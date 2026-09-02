#!/usr/bin/env bash
# Read-only DNS and mail-identity inventory. Queries public DNS only.
# Usage: collect-dns.sh example.com
set -uo pipefail
D="${1:?usage: collect-dns.sh example.com}"
sec() { printf '\n=== %s ===\n' "$1"; }
command -v dig >/dev/null || { echo "dig not installed (bind-utils / dnsutils)"; exit 1; }

sec "APEX RECORDS"
for t in A AAAA MX NS TXT CAA; do printf '%-5s ' "$t"; dig +short "$t" "$D" | tr '\n' ' '; echo; done

sec "REGISTRAR AND EXPIRY"
command -v whois >/dev/null && whois "$D" 2>/dev/null \
  | grep -iE 'registrar:|expiry|expiration|status:' | head -10 || echo "(whois not installed)"
echo "Check for a registrar lock (clientTransferProhibited) in the status lines."

sec "MAIL IDENTITY"
printf 'SPF    '; dig +short TXT "$D" | grep -i 'v=spf1' || echo "(none - anyone can send as this domain)"
printf 'DMARC  '; dig +short TXT "_dmarc.$D" || echo "(none)"
echo "A DMARC policy of p=none monitors but enforces nothing."
for s in default google resend selector1 selector2 k1 mail; do
  r=$(dig +short TXT "$s._domainkey.$D" 2>/dev/null)
  [ -n "$r" ] && printf 'DKIM %-10s present\n' "$s"
done

sec "SUBDOMAINS FOUND IN CERTIFICATE TRANSPARENCY"
command -v curl >/dev/null && curl -sS --max-time 20 "https://crt.sh/?q=%25.$D&output=json" 2>/dev/null \
  | tr ',' '\n' | grep -oE '"[a-z0-9._*-]+\.'"$D"'"' | tr -d '"' | sort -u | head -40 \
  || echo "(crt.sh unavailable)"

sec "DANGLING CNAME CANDIDATES (subdomain takeover)"
echo "For each subdomain above, a CNAME whose target no longer resolves is a takeover risk."
crt=$(curl -sS --max-time 20 "https://crt.sh/?q=%25.$D&output=json" 2>/dev/null \
  | tr ',' '\n' | grep -oE '"[a-z0-9._-]+\.'"$D"'"' | tr -d '"' | sort -u | head -40)
while read -r sub; do
  [ -z "$sub" ] && continue
  cname=$(dig +short CNAME "$sub" 2>/dev/null)
  [ -z "$cname" ] && continue
  target=$(dig +short A "${cname%.}" 2>/dev/null)
  if [ -z "$target" ]; then
    printf 'DANGLING? %-40s -> %s (target does not resolve)\n' "$sub" "$cname"
  else
    printf 'ok        %-40s -> %s\n' "$sub" "$cname"
  fi
done <<< "$crt"

sec "NEXT STEP: PROBE EVERY SUBDOMAIN FOUND"
subs=$(curl -sS --max-time 20 "https://crt.sh/?q=%25.$D&output=json" 2>/dev/null \
  | tr ',' '\n' | grep -oE '"[a-z0-9._-]+\.'"$D"'"' | tr -d '"' | sort -u | head -20)
if [ -n "$subs" ]; then
  cmd="collect-web.sh"
  while read -r s; do [ -n "$s" ] && cmd="$cmd https://$s"; done <<< "$subs"
  echo "$cmd"
  echo
  echo "A subdomain that resolves but serves nothing is a loose end: the record"
  echo "still advertises the service to anyone enumerating DNS or certificate logs."
fi

sec "TLS CERTIFICATE"
echo | openssl s_client -connect "$D:443" -servername "$D" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null \
  || echo "(no TLS on 443, or openssl unavailable)"
