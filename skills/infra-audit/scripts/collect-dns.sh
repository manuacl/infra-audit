#!/usr/bin/env bash
# Read-only DNS and mail-identity inventory. Queries public DNS only.
# Usage: collect-dns.sh example.com
set -uo pipefail
D="${1:?usage: collect-dns.sh example.com}"
sec() { printf '\n=== %s ===\n' "$1"; }
command -v dig >/dev/null || { echo "dig not installed (bind-utils / dnsutils)"; exit 1; }

# Every lookup below goes to the zone's own nameserver, never to whatever
# resolver this machine happens to use. A recursive resolver answers from its
# cache until the TTL expires - 3362 s was observed on a record deleted minutes
# earlier - so a bare `dig` reports a deleted record as still published, and
# the audit ships a finding that was fixed before it was written.
NS=$(dig +short NS "$D" 2>/dev/null | head -1)
if [ -n "$NS" ]; then
  AT="@${NS%.}"
  echo "authoritative nameserver: ${NS%.}  (all lookups below are sent there)"
else
  AT=""
  echo "WARNING: no NS record found for $D. Falling back to this machine's"
  echo "resolver, which answers from cache: a record deleted in the last few"
  echo "minutes may still show up below. Re-check anything you act on."
fi

sec "APEX RECORDS"
for t in A AAAA MX NS TXT CAA; do printf '%-5s ' "$t"; dig +short $AT "$t" "$D" | tr '\n' ' '; echo; done

sec "REGISTRAR AND EXPIRY"
command -v whois >/dev/null && whois "$D" 2>/dev/null \
  | grep -iE 'registrar:|expiry|expiration|status:' | head -10 || echo "(whois not installed)"
echo "Check for a registrar lock (clientTransferProhibited) in the status lines."

sec "MAIL IDENTITY"
printf 'SPF    '; dig +short $AT TXT "$D" | grep -i 'v=spf1' || echo "(none - anyone can send as this domain)"
printf 'DMARC  '; dig +short $AT TXT "_dmarc.$D" || echo "(none)"
echo "A DMARC policy of p=none monitors but enforces nothing."
for s in default google resend selector1 selector2 k1 mail; do
  r=$(dig +short $AT TXT "$s._domainkey.$D" 2>/dev/null)
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
  cname=$(dig +short $AT CNAME "$sub" 2>/dev/null)
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
  echo
  echo "To confirm a record is really gone after deleting it, ask the nameserver"
  echo "above and not this machine: an empty answer there is the deletion, while"
  echo "a local resolver keeps serving the old one until the TTL runs out."
fi

sec "TLS CERTIFICATE"
echo | openssl s_client -connect "$D:443" -servername "$D" 2>/dev/null \
  | openssl x509 -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null \
  || echo "(no TLS on 443, or openssl unavailable)"
