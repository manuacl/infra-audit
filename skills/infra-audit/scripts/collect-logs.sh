#!/usr/bin/env bash
# Read-only look at what the server's own logs already witnessed. Every other
# collector describes the surface that COULD be attacked; this one reads what
# is actually being tried, which is what separates a theoretical finding from
# an urgent one.
#
# Aggregation happens on the remote host and only counts come back. Access logs
# carry client IPs, user agents and request paths, so pulling them to the
# auditor's machine would copy someone's visitor data onto a third box for no
# analytical gain.
#
# Usage: collect-logs.sh user@host [lines]      (default: last 50000 lines)
set -uo pipefail
TARGET="${1:?usage: collect-logs.sh user@host [lines]}"
LINES="${2:-50000}"

ssh -o ConnectTimeout=10 -o BatchMode=yes "$TARGET" "LINES='$LINES' bash -s" <<'REMOTE'
sec() { printf '\n=== %s ===\n' "$1"; }

sec "LOG INVENTORY"
# Uncompressed access logs only: a rotated .gz is history, not the live picture.
LOGS=$(ls -1 /var/log/caddy/*.log /var/log/nginx/*access*.log \
              /var/log/apache2/*access*.log /var/log/httpd/*access*.log \
              /var/log/lighttpd/*access*.log 2>/dev/null | grep -v '\.gz$')
if [ -z "$LOGS" ]; then
  echo "FLAG: no web access log found in the usual locations."
  echo "      Without one there is no way to tell whether anything has been"
  echo "      tried, and no evidence at all if something succeeds later."
else
  now=$(date +%s)
  while read -r f; do
    [ -z "$f" ] && continue
    age=$(( (now - $(stat -c %Y "$f" 2>/dev/null || echo "$now")) / 60 ))
    printf '%-45s %10s  last write %s min ago\n' "$f" "$(du -h "$f" 2>/dev/null | cut -f1)" "$age"
    # A log that stopped is either a retired vhost or a log someone silenced.
    # Both matter, and only the owner knows which - so say it, do not judge it.
    [ "$age" -gt 1440 ] && echo "  FLAG: no write in over 24 h. Retired service, or logging stopped."
  done <<< "$LOGS"
fi

# Container logs land in journald when the compose logging driver says so, in
# which case `docker logs` returns nothing and people conclude there are none.
sec "CONTAINER AND SERVICE LOGS"
if command -v journalctl >/dev/null; then
  journalctl --disk-usage 2>/dev/null
  echo "--- units with the most entries in the last 24 h ---"
  journalctl --since '24 hours ago' -o json 2>/dev/null \
    | grep -o '"_SYSTEMD_UNIT":"[^"]*"' | cut -d'"' -f4 | sort | uniq -c | sort -rn | head -8 \
    || echo "(journal not readable as this user)"
  echo "--- container tags seen (docker journald driver) ---"
  journalctl --since '24 hours ago' 2>/dev/null | grep -oE '^\S+ \S+ \S+ [a-z0-9_.-]+\[' \
    | awk '{print $4}' | tr -d '[' | sort | uniq -c | sort -rn | head -8 || true
else
  echo "journalctl: not present"
fi

[ -z "$LOGS" ] && exit 0

# One awk pass per file, over the tail. Handles Caddy JSON and the common
# combined format; anything else falls through and is reported as unparsed.
analyse() {
  tail -n "$LINES" "$1" 2>/dev/null | awk '
    function jnum(k,   m) { m = match($0, "\"" k "\":[0-9]+"); return m ? substr($0, RSTART+length(k)+3, RLENGTH-length(k)-3) : "" }
    function jstr(k,   m) { m = match($0, "\"" k "\":\"[^\"]*\""); return m ? substr($0, RSTART+length(k)+4, RLENGTH-length(k)-5) : "" }
    function respctype(   r, s, m) {
      r = index($0, "\"resp_headers\""); if (!r) return ""
      s = substr($0, r)
      m = match(s, "\"Content-Type\":\\[\"[^\"]*\"")
      return m ? substr(s, RSTART+17, RLENGTH-18) : ""
    }
    {
      if (substr($0,1,1) == "{") {
        status = jnum("status"); size = jnum("size"); uri = jstr("uri")
        ip = jstr("remote_ip"); if (ip == "") ip = jstr("client_ip")
        ua = jstr("User-Agent"); ctype = respctype()
      } else if (NF >= 9 && $6 ~ /^"/) {
        status = $9; size = $10; uri = $7; ip = $1; ua = ""; ctype = ""
        for (i = 12; i <= NF; i++) ua = ua " " $i
      } else { unparsed++; next }
      if (status == "") { unparsed++; next }
      total++
      # Strip the query string: /x?a=1 and /x?a=2 are one path being probed.
      sub(/\?.*/, "", uri)
      code[substr(status,1,1) "xx"]++
      if (status ~ /^[45]/) { bad[uri]++; badip[ip]++ }
      if (status ~ /^5/) five[uri]++
      byip[ip]++
      if (uri ~ /login|signin|auth|admin|wp-|token|password|session/) authhit[uri "  " status]++
      if (ua ~ /nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wpscan|curl\/|python-requests|Go-http/) scanua[ua]++
      # The SPA trap: a client-routed app answers 200 with index.html for any
      # unmatched path, so a 200 alone proves nothing was served. Identical
      # response sizes on odd paths are that fallback, not a leak.
      if (status == 200 && size != "") sizecount[size]++
      if (status == 200 && uri ~ /\.(env|sql|bak|old|yml|yaml|ini|conf|log|php|json|key|pem)$|\/\.|config|secret|credential/) {
        if (ctype != "") {
          if (ctype ~ /text\/html/) fallback_hit[uri]++          # the SPA page, not the file
          else served[uri "  " ctype "  " size " B"]++
        } else susp_noct[uri "  size=" size]++                    # no content type logged
      }
    }
    END {
      printf "parsed %d lines", total
      if (unparsed) printf ", %d unparsed (unknown format)", unparsed
      printf "\n\nstatus classes:\n"
      for (c in code) printf "  %-5s %8d\n", c, code[c]
      # The same fallback body is logged at several sizes, because the proxy
      # records the ENCODED length and a gzip/zstd client gets a different
      # number than a bare curl. Comparing against a single modal size was
      # tested against a live server and flagged the home page as a leak.
      # So: collect the sizes that dominate the 200s, and treat every one of
      # them as a fallback candidate.
      cover = 0; nf = 0
      for (rounds = 0; rounds < 4; rounds++) {
        m = 0; ms = ""
        for (s in sizecount) if (!(s in picked) && sizecount[s] > m) { m = sizecount[s]; ms = s }
        if (ms == "" || m < total * 0.05) break
        picked[ms] = 1; cover += m; nf++
        fallback[nf] = ms; fallcount[nf] = m
      }
      if (nf) {
        printf "\ncommon 200 response sizes (the same body appears at several sizes:\n"
        printf "the proxy logs the ENCODED length, so gzip and identity differ):\n"
        for (i = 1; i <= nf; i++) printf "  %8s bytes on %d responses\n", fallback[i], fallcount[i]
        printf "  these %d sizes cover %.0f%% of all 200s\n", nf, cover * 100 / total
      }
      printf "\ntop probed paths answering 4xx/5xx:\n"
      n = 0; for (u in bad) { printf "  %6d  %s\n", bad[u], u | "sort -rn | head -15"; n++ }
      close("sort -rn | head -15")
      printf "\nhits on authentication and admin paths:\n"
      n = 0; for (k in authhit) { printf "  %6d  %s\n", authhit[k], k | "sort -rn | head -12"; n++ }
      close("sort -rn | head -12")
      if (n == 0) printf "  (none)\n"
      printf "\ntop source addresses:\n"
      for (i in byip) printf "  %6d  %s\n", byip[i], i | "sort -rn | head -10"
      close("sort -rn | head -10")
      printf "\nsources whose traffic is mostly errors (probing shape):\n"
      for (i in badip) if (byip[i] >= 20 && badip[i] > byip[i] * 0.8) printf "  %6d/%-6d  %s\n", badip[i], byip[i], i
      printf "\n5xx by path (the app failing, sometimes under a payload):\n"
      n = 0; for (u in five) { printf "  %6d  %s\n", five[u], u | "sort -rn | head -8"; n++ }
      close("sort -rn | head -8")
      if (n == 0) printf "  (none)\n"
      printf "\nscanner-shaped user agents:\n"
      n = 0; for (a in scanua) { printf "  %6d  %s\n", scanua[a], substr(a,1,80) | "sort -rn | head -8"; n++ }
      close("sort -rn | head -8")
      if (n == 0) printf "  (none)\n"
      if (length(served)) {
        printf "\nFLAG: 200 on a sensitive-looking path, answered with a NON-HTML content\n"
        printf "type. This is the shape that matters: the app did not fall through to\n"
        printf "its router page, something else answered.\n"
        for (u in served) printf "  %6d  %s\n", served[u], u | "sort -rn | head -12"
        close("sort -rn | head -12")
        printf "Still not proof. Re-issue each request and read the first bytes.\n"
      }
      if (length(susp_noct)) {
        printf "\n200 on a sensitive-looking path, no response content type in this log\n"
        printf "format. Size alone cannot separate a served file from the router page,\n"
        printf "because the proxy logs the encoded length. Re-issue these by hand:\n"
        for (u in susp_noct) printf "  %6d  %s\n", susp_noct[u], u | "sort -rn | head -12"
        close("sort -rn | head -12")
      }
      if (length(fallback_hit)) {
        n = 0; for (u in fallback_hit) n += fallback_hit[u]
        printf "\n%d probe(s) of sensitive-looking paths got a text/html 200: the router\n", n
        printf "page answered, nothing was served. Noise, not a finding.\n"
      }
    }' LINES="$LINES"
}

while read -r f; do
  [ -z "$f" ] && continue
  sec "TRAFFIC: $f (last $LINES lines)"
  LINES="$LINES" analyse "$f"
done <<< "$LOGS"

sec "READING THESE NUMBERS"
cat <<'NOTE'
Probe traffic is constant background noise on any public address, so volume
alone is not a finding. What is:
  - a 200 on a path that should not exist, whose size differs from the modal
    fallback size (that one really was served)
  - sustained hits on a login or admin path, especially one this audit found
    reachable without a quota
  - a single source producing thousands of requests with no throttling visible
  - 5xx concentrated on one endpoint: the app failing where someone is pushing
  - a log that stopped writing while its service still runs
Cross these against the exposed surface: an endpoint that is both reachable
and actively probed outranks one that is merely reachable.
NOTE
REMOTE
