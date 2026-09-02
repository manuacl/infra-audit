#!/usr/bin/env bash
# Compare versioned infrastructure config against what is actually deployed.
# Read-only on both sides: diffs only, writes nothing.
# Usage: collect-drift.sh user@host [extra:local:remote pairs...]
set -uo pipefail
TARGET="${1:?usage: collect-drift.sh user@host [local:remote ...]}"; shift || true
sec() { printf '\n=== %s ===\n' "$1"; }

# Common pairs, skipped when the local file is absent. Add your own as arguments.
PAIRS=(
  "caddy/Caddyfile:/etc/caddy/Caddyfile"
  "nginx/default.conf:/etc/nginx/conf.d/default.conf"
  "nginx/nginx.conf:/etc/nginx/nginx.conf"
  "docker-compose.yml:/opt/*/docker-compose.yml"
  "$@"
)

sec "VERSIONED CONFIG VS DEPLOYED"
for pair in "${PAIRS[@]}"; do
  [ -z "$pair" ] && continue
  local_f="${pair%%:*}"; remote_f="${pair#*:}"
  [ -f "$local_f" ] || continue
  printf -- '--- %s vs %s ---\n' "$local_f" "$remote_f"
  if remote=$(ssh -o ConnectTimeout=10 "$TARGET" "cat $remote_f" 2>/dev/null); then
    if diff -u <(cat "$local_f") <(printf '%s\n' "$remote") > /tmp/.drift.$$ 2>&1; then
      echo "identical"
    else
      head -40 /tmp/.drift.$$
      echo "^ DRIFT: the deployed file differs from the versioned one."
    fi
    rm -f /tmp/.drift.$$
  else
    echo "(not readable on the host, or absent)"
  fi
done

sec "DECLARED IMAGE TAGS VS RUNNING IMAGES"
echo "--- declared locally ---"
grep -rhE '^\s*image:' docker-compose*.y*ml 2>/dev/null | sed 's/^\s*image:\s*//' | sort -u
echo "--- running on the host ---"
ssh -o ConnectTimeout=10 "$TARGET" 'command -v docker >/dev/null && docker ps --format "{{.Image}}"' 2>/dev/null | sort -u
echo
echo "A tag present on both sides still proves nothing when it is floating:"
echo "compare image digests to know whether the same bits are running."

sec "UNCOMMITTED LOCAL CHANGES TO INFRA FILES"
git status --short -- caddy nginx docker-compose*.y*ml .github 2>/dev/null || echo "(not a git repository)"
