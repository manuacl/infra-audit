#!/usr/bin/env bash
# Read-only compromise triage over SSH. Collects leads, proves nothing:
# a compromised host's own binaries and logs may be untrustworthy.
# Writes nothing, kills nothing, changes nothing.
# Usage: collect-compromise.sh user@host [YYYY-MM-DD suspected date]
set -uo pipefail
TARGET="${1:?usage: collect-compromise.sh user@host [YYYY-MM-DD]}"
SINCE="${2:-}"

ssh -o ConnectTimeout=10 "$TARGET" "SINCE='$SINCE' bash -s" <<'REMOTE'
set -uo pipefail
sec() { printf '\n=== %s ===\n' "$1"; }
echo "NOTE: leads only. On a rooted host these commands can lie."

sec "ACCOUNTS WITH A SHELL"
grep -vE '/(nologin|false|sync)$' /etc/passwd 2>/dev/null

sec "UID 0 (should be root alone)"
awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null

sec "EMPTY PASSWORD FIELDS"
sudo -n awk -F: '$2==""' /etc/shadow 2>/dev/null || echo "(needs root, skipped)"

sec "RECENTLY MODIFIED ACCOUNT FILES"
ls -l --time-style=long-iso /etc/passwd /etc/shadow /etc/group /etc/sudoers 2>/dev/null

sec "EVERY authorized_keys ON THE BOX"
find / -name authorized_keys -not -path '*/proc/*' 2>/dev/null | while read -r f; do
  printf -- '--- %s ---\n' "$f"; ls -l --time-style=long-iso "$f"; cat "$f" 2>/dev/null
done

sec "CRON (user, system, cron.d)"
for u in $(cut -d: -f1 /etc/passwd); do
  c=$(crontab -l -u "$u" 2>/dev/null) && [ -n "$c" ] && printf -- '--- %s ---\n%s\n' "$u" "$c"
done
cat /etc/crontab 2>/dev/null
ls -l --time-style=long-iso /etc/cron.d/ /etc/cron.*/ 2>/dev/null | head -40
command -v atq >/dev/null && atq 2>/dev/null

sec "SYSTEMD UNITS AND TIMERS, NEWEST FIRST"
ls -lt --time-style=long-iso /etc/systemd/system/ /lib/systemd/system/ 2>/dev/null | head -25
systemctl list-timers --all --no-pager 2>/dev/null | head -20

sec "PRELOAD AND KERNEL MODULES"
cat /etc/ld.so.preload 2>/dev/null || echo "(no ld.so.preload - good)"
grep -rIn 'LD_PRELOAD' /etc/environment /etc/profile /etc/profile.d/ ~/.bashrc ~/.profile 2>/dev/null
lsmod 2>/dev/null | head -25

sec "SUID BINARIES OUTSIDE THE USUAL PLACES"
find / -perm -4000 -type f -not -path '*/proc/*' 2>/dev/null | grep -vE '^/(usr/bin|usr/sbin|bin|sbin|usr/lib|usr/libexec)/' | head -20

sec "PROCESSES RUNNING FROM TEMP OR WITH A DELETED BINARY"
ls -l /proc/*/exe 2>/dev/null | grep -E 'deleted|/tmp/|/dev/shm|/var/tmp' | head -20

sec "EXECUTABLES IN WORLD-WRITABLE TEMP DIRECTORIES"
find /tmp /dev/shm /var/tmp -type f -perm -u+x 2>/dev/null | head -20

sec "LISTENING SOCKETS WITH PROCESSES"
ss -tulnp 2>/dev/null

sec "ESTABLISHED OUTBOUND CONNECTIONS"
ss -tnp state established 2>/dev/null | head -30

sec "PACKAGE INTEGRITY (lead only, slow)"
if command -v debsums >/dev/null; then debsums -c 2>/dev/null | head -20
elif command -v rpm >/dev/null; then rpm -Va 2>/dev/null | grep '^..5' | head -20
else echo "(no integrity tool installed)"; fi

sec "AUTH FAILURES AND SUCCESSFUL LOGINS"
command -v lastb >/dev/null && lastb -n 15 2>/dev/null
last -n 20 2>/dev/null

sec "LOG COVERAGE (a gap is a lead)"
ls -l --time-style=long-iso /var/log/ 2>/dev/null | head -25
journalctl --disk-usage 2>/dev/null

sec "CONTAINERS AND IMAGES"
command -v docker >/dev/null && docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Command}}' 2>/dev/null
command -v docker >/dev/null && docker images --format '{{.Repository}}:{{.Tag}}\t{{.CreatedSince}}' 2>/dev/null | head -20

if [ -n "${SINCE:-}" ]; then
  sec "FILES MODIFIED SINCE $SINCE (system paths)"
  find /etc /usr/bin /usr/sbin /usr/local /root /var/www /srv /opt \
    -newermt "$SINCE" -type f -not -path '*/proc/*' 2>/dev/null | head -60
fi
REMOTE
