#!/usr/bin/env bash
# Read-only HTTP surface probe. GET only, no authentication, no payloads.
# Usage: collect-web.sh https://example.com
set -uo pipefail
[ $# -ge 1 ] || { echo "usage: collect-web.sh https://example.com [https://sub.example.com ...]"; exit 1; }
sec() { printf '\n=== %s ===\n' "$1"; }

# Every vhost is its own surface. Pass each subdomain collect-dns.sh found:
# an admin dashboard usually lives on one of them, not on the apex.
if [ $# -gt 1 ]; then
  echo "### $# hosts to probe: $*"
  for h in "$@"; do
    printf '\n\n##################### %s #####################\n' "$h"
    "$0" "$h"
  done
  exit 0
fi

BASE="${1%/}"
probe() { curl -sS -o /dev/null -w "%{http_code} %{content_type} %{size_download}\n" --max-time 12 "$1" 2>&1; }

sec "SECURITY HEADERS"
curl -sSI --max-time 12 "$BASE/" | grep -iE \
  'strict-transport|content-security-policy|x-content-type|x-frame|referrer-policy|permissions-policy|^server|x-powered-by' \
  || echo "(none of the expected headers found)"

sec "BASELINE (every 200 below is compared against this automatically)"
BASE_LINE=$(curl -sS -o /dev/null -w "%{content_type}|%{size_download}" --max-time 12 "$BASE/" 2>/dev/null)
BASE_TYPE="${BASE_LINE%%|*}"; BASE_SIZE="${BASE_LINE##*|}"
printf 'GET /            %s %s\n' "$BASE_TYPE" "$BASE_SIZE"
echo "A 200 whose content_type AND size match this is the SPA fallback serving"
echo "index.html, not a served file. Those are tagged SPA-FALLBACK below."

# Re-defined now that the baseline is known: annotate instead of leaving the
# comparison to the reader. Six paths on the first real run of this script
# answered 200 with the baseline body; reported raw they read as six leaks.
probe() {
  local out type size
  out=$(curl -sS -o /dev/null -w "%{http_code}|%{content_type}|%{size_download}" --max-time 12 "$1" 2>&1)
  local code="${out%%|*}"; local rest="${out#*|}"
  type="${rest%%|*}"; size="${rest##*|}"
  local tag=""
  if [ "$code" = "200" ]; then
    if [ "$type" = "$BASE_TYPE" ] && [ "$size" = "$BASE_SIZE" ]; then
      tag="   <- SPA-FALLBACK (same body as /, not a real endpoint)"
    else
      tag="   <- REAL RESPONSE, differs from / : look at it"
    fi
  fi
  printf '%s %s %s%s\n' "$code" "$type" "$size" "$tag"
}

sec "PATHS THAT SHOULD NOT BE PUBLIC"
for p in /.env /.git/config /config.json /secrets.json /credentials.json \
         /backup.sql /dump.sql /server-status /actuator/health /metrics \
         /debug /admin /.well-known/security.txt; do
  printf 'GET %-28s ' "$p"; probe "$BASE$p"
done

sec "COMMON ADMIN / DASHBOARD SURFACES"
for p in /login /admin/login /dashboard /wp-login.php /phpmyadmin; do
  printf 'GET %-28s ' "$p"; probe "$BASE$p"
done

sec "BURST BEHAVIOUR (is anything throttling? 10 sequential requests)"
for _ in $(seq 10); do curl -sS -o /dev/null -w '%{http_code} ' --max-time 8 "$BASE/wp-login.php"; done
echo
echo "All identical => no rate limiting and no fail2ban web jail on this path."

sec "SOURCE MAPS AND BUILD ARTEFACTS"
for p in /assets /static /sitemap.xml /robots.txt; do
  printf 'GET %-28s ' "$p"; probe "$BASE$p"
done
curl -sS --max-time 12 "$BASE/robots.txt" 2>/dev/null | head -20

sec "TLS"
echo | openssl s_client -connect "${BASE#https://}:443" -servername "${BASE#https://}" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates 2>/dev/null || echo "(openssl unavailable)"
