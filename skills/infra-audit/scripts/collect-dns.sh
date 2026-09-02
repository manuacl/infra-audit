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

sec "CERTIFICATE ISSUANCE (CAA)"
caa=$(dig +short $AT CAA "$D" 2>/dev/null)
if [ -z "$caa" ]; then
  echo "FLAG: no CAA record. Any certificate authority in the world may issue"
  echo "      for this domain. A CAA record names the ones allowed to."
else
  echo "$caa"
fi

sec "MAIL IDENTITY"
spf=$(dig +short $AT TXT "$D" 2>/dev/null | grep -i 'v=spf1')
if [ -z "$spf" ]; then
  echo "FLAG: no SPF record. Anyone can send mail as this domain."
else
  echo "SPF    $spf"
  case "$spf" in
    *"-all"*) : ;;
    *"~all"*) echo "FLAG: SPF ends in ~all (softfail). A forged message is marked, not rejected." ;;
    *"?all"*|*"+all"*) echo "FLAG: SPF ends in ?all or +all, which authorizes anyone. Use -all." ;;
    *) echo "FLAG: SPF has no all-qualifier, so it constrains nothing at the end." ;;
  esac
fi

dmarc=$(dig +short $AT TXT "_dmarc.$D" 2>/dev/null)
if [ -z "$dmarc" ]; then
  echo "FLAG: no DMARC record. Receivers have no instruction for a message that fails SPF/DKIM."
else
  echo "DMARC  $dmarc"
  case "$dmarc" in
    *"p=none"*) echo "FLAG: DMARC p=none. The policy observes and enforces nothing:" \
                     "a forged message is still delivered." ;;
    *"p=quarantine"*) echo "note: DMARC p=quarantine. Partial enforcement, mail lands in spam." ;;
  esac
  case "$dmarc" in
    *"rua="*) : ;;
    *) echo "FLAG: DMARC has no rua= address, so no aggregate report is ever received." \
            "Nobody learns that the domain is being forged." ;;
  esac
fi

dkim_found=0
for s in default google resend selector1 selector2 k1 mail mandrill zoho s1 s2; do
  r=$(dig +short $AT TXT "$s._domainkey.$D" 2>/dev/null)
  if [ -n "$r" ]; then printf 'DKIM %-10s present\n' "$s"; dkim_found=1; fi
done
if [ "$dkim_found" = 0 ]; then
  echo "note: no DKIM selector found among the common names. The domain may still"
  echo "      sign with a custom selector, which cannot be enumerated from outside."
fi

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
