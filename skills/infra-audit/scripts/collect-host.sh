#!/usr/bin/env bash
# Read-only production host state over SSH. Status commands only: nothing is
# started, stopped, written or authenticated against.
# Usage: collect-host.sh root@203.0.113.10
set -uo pipefail
TARGET="${1:?usage: collect-host.sh user@host}"

ssh -o ConnectTimeout=10 -o BatchMode=yes "$TARGET" 'bash -s' <<'REMOTE'
set -uo pipefail
sec() { printf '\n=== %s ===\n' "$1"; }

sec "SYSTEM"
. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME"
uptime

sec "PENDING SECURITY UPDATES"
if command -v apt-get >/dev/null; then
  apt-get -s upgrade 2>/dev/null | grep -c -i security
  systemctl is-enabled unattended-upgrades 2>/dev/null || echo "unattended-upgrades: NOT enabled"
elif command -v dnf >/dev/null; then
  dnf -q updateinfo list security 2>/dev/null | wc -l
fi

sec "FIREWALL"
if command -v ufw >/dev/null; then ufw status verbose; else nft list ruleset 2>/dev/null | head -30; fi

sec "LISTENING ON NON-LOOPBACK (the real exposed surface)"
ss -tlnp 2>/dev/null | grep -v '127.0.0.1\|::1'

sec "SSH EFFECTIVE CONFIG"
sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|kbdinteractiveauthentication|permitemptypasswords|maxauthtries|x11forwarding)'

sec "FAIL2BAN (which layers are actually covered?)"
if command -v fail2ban-client >/dev/null; then
  fail2ban-client status
  for j in $(fail2ban-client status 2>/dev/null | sed -n 's/.*Jail list:\s*//p' | tr ',' ' '); do
    printf -- '--- %s ---\n' "$j"; fail2ban-client status "$j" 2>/dev/null | grep -E 'Total failed|Currently banned|Total banned'
  done
else
  echo "fail2ban: not installed"
fi

sec "CONTAINERS AND IMAGE TAGS"
command -v docker >/dev/null && docker ps --format '{{.Names}}\t{{.Image}}\t{{.Status}}'

sec "PUBLISHED CONTAINER PORTS (anything not on 127.0.0.1 bypasses the firewall)"
command -v docker >/dev/null && docker ps --format '{{.Names}}\t{{.Ports}}'

sec "DATASTORE IDENTITIES (how many roles, and who shares one?)"
# The highest-impact finding on a small deployment hides here: one role, often
# a superuser, shared by every service on the box. Read-only catalog queries.
if command -v docker >/dev/null; then
  for c in $(docker ps --format '{{.Names}}' 2>/dev/null); do
    img=$(docker inspect "$c" --format '{{.Config.Image}}' 2>/dev/null)
    case "$img" in
      *postgres*)
        u=$(docker inspect "$c" --format '{{range .Config.Env}}{{println .}}{{end}}' 2>/dev/null \
            | sed -n 's/^POSTGRES_USER=//p' | head -1); u=${u:-postgres}
        printf -- '--- %s (%s), connecting as %s ---\n' "$c" "$img" "$u"
        echo "roles (usesuper=t means superuser):"
        docker exec "$c" psql -U "$u" -d postgres -tAc \
          "select usename, usesuper, usecreatedb from pg_user" 2>/dev/null || echo "  (query refused)"
        echo "databases:"
        docker exec "$c" psql -U "$u" -d postgres -tAc \
          "select datname from pg_database where not datistemplate" 2>/dev/null || echo "  (query refused)"
        echo "listen_addresses:"
        docker exec "$c" psql -U "$u" -d postgres -tAc "show listen_addresses" 2>/dev/null
        ;;
      *mysql*|*mariadb*)
        printf -- '--- %s (%s) ---\n' "$c" "$img"
        docker exec "$c" sh -c 'mysql -u root -p"$MYSQL_ROOT_PASSWORD" -N -e \
          "select user, host from mysql.user"' 2>/dev/null || echo "  (query refused)"
        ;;
    esac
  done
  echo
  echo "One role for several databases, or usesuper=t on the application role,"
  echo "means a vulnerability in ANY service that connects reaches all the others."
fi
# Same question for a datastore installed straight on the host, which is the
# common case outside container setups.
if command -v psql >/dev/null; then
  echo "--- postgres on the host ---"
  su - postgres -c "psql -tAc \"select usename, usesuper from pg_user\"" 2>/dev/null \
    || sudo -n -u postgres psql -tAc "select usename, usesuper from pg_user" 2>/dev/null \
    || echo "  (no passwordless local access; run it yourself as the db admin)"
fi
if command -v mysql >/dev/null; then
  echo "--- mysql/mariadb on the host ---"
  mysql -N -e "select user, host from mysql.user" 2>/dev/null \
    || echo "  (no passwordless local access; run it yourself as the db admin)"
fi
command -v docker >/dev/null || command -v psql >/dev/null || command -v mysql >/dev/null \
  || echo "(no datastore client found; list the roles by hand on whatever it runs)"

sec "PROXIED PATHS (candidates for the per-request cost question)"
# An unauthenticated endpoint that sends mail or an SMS, calls an LLM, or runs
# an expensive query is where a missing quota actually hurts.
for f in /etc/caddy/Caddyfile /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf \
         /etc/nginx/sites-enabled/* /etc/apache2/sites-enabled/* /etc/httpd/conf.d/*.conf \
         /etc/haproxy/haproxy.cfg /etc/traefik/*.y*ml /etc/lighttpd/lighttpd.conf; do
  [ -f "$f" ] || continue
  printf -- '--- %s ---\n' "$f"
  grep -nE '^\s*(location|reverse_proxy|proxy_pass|handle|ProxyPass|<Location|backend |server |rule =|Host\()' "$f" 2>/dev/null | head -25
done
echo
echo "DO NOT send a burst at these to test for a quota: one of them may actually"
echo "send email or spend money per call. List them, read the application code"
echo "behind each, and ask what one request costs the owner."

sec "SECRET FILE PERMISSIONS"
find /opt /srv /root /home -maxdepth 4 -name '.env' -exec ls -l {} \; 2>/dev/null | head

sec "WEB SERVER CONFIG PRESENT ON HOST (diff against the repo copy)"
ls -l /etc/caddy/Caddyfile /etc/nginx/sites-enabled/ 2>/dev/null

sec "RECENT AUTH FAILURES"
journalctl -u ssh -u sshd --since '7 days ago' 2>/dev/null | grep -ci 'failed password' || echo 0
REMOTE
