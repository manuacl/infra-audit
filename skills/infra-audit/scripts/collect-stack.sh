#!/usr/bin/env bash
# Read-only inventory of the declared stack, from the repository side.
# Writes nothing. Run from the project root; every block degrades if absent.
set -uo pipefail
sec() { printf '\n=== %s ===\n' "$1"; }

sec "CONTAINER IMAGES DECLARED (floating tags are a finding)"
grep -rnE '^\s*(image|FROM)[: ]' --include='docker-compose*.y*ml' --include='Dockerfile*' \
  --include='*.yaml' . 2>/dev/null | grep -v node_modules | head -30
echo
echo "Floating if the tag is latest/stable/edge/community/main, or absent."

sec "PORT BINDINGS DECLARED (anything not on 127.0.0.1 bypasses the firewall)"
grep -rnE "^\s*-\s*['\"]?[0-9]" --include='docker-compose*.y*ml' . 2>/dev/null \
  | grep -v node_modules | grep -E ':[0-9]+' | head -25

sec "DOCKER SOCKET MOUNTS AND PRIVILEGE (direct host root if present)"
grep -rnE 'docker\.sock|privileged:\s*true|network_mode:\s*host|user:\s*root|cap_add' \
  --include='docker-compose*.y*ml' . 2>/dev/null | grep -v node_modules || echo "(none declared - good)"

sec "SECRET-BEARING FILES ON DISK"
find . -maxdepth 3 \( -name '.env*' -o -name '*.pem' -o -name '*.key' -o -name 'id_rsa*' \) \
  -not -path '*/node_modules/*' -exec ls -l {} \; 2>/dev/null

sec "SECRETS TRACKED IN VERSION CONTROL (should be empty)"
git ls-files 2>/dev/null | grep -E '(^|/)\.env($|\.)|\.pem$|\.key$|credentials' | head -10 \
  || echo "(none / not a git repository)"
grep -nE '^\s*\.env' .gitignore 2>/dev/null || echo "WARNING: .env not in .gitignore"

sec "PROXIED ROUTES DECLARED IN THE REPO"
# The reverse-proxy config is often baked into a container image rather than
# left on the host, so read it from the repository too.
grep -rnE '^\s*(location|reverse_proxy|proxy_pass)' \
  nginx/ caddy/ Caddyfile* 2>/dev/null | head -25 || echo "(no proxy config in the repo)"

sec "ENDPOINTS THAT COST THE OWNER PER CALL (candidates, not verdicts)"
# A missing quota only hurts where a request spends money or reputation.
# Find the code that spends, then check whether its route needs credentials.
echo "--- code that sends mail / SMS / spends per call ---"
SRC_ROOTS=$(ls -d server/src src app api lib pkg internal cmd routes controllers \
  handlers services 2>/dev/null | tr '\n' ' '); SRC_ROOTS=${SRC_ROOTS:-.}
grep -rnE '(resend|sendgrid|mailgun|postmark|nodemailer|smtplib|sendmail|mailer|boto3.*ses|twilio|vonage|nexmo|stripe|paypal|openai|anthropic|gemini|bedrock)' \
  --include='*.ts' --include='*.js' --include='*.mjs' --include='*.py' --include='*.go' \
  --include='*.rb' --include='*.php' --include='*.java' --include='*.cs' --include='*.rs' \
  $SRC_ROOTS 2>/dev/null | grep -viE 'test|spec|\.d\.ts|vendor/|node_modules' | head -12
echo
echo "--- routes reachable WITHOUT authentication ---"
echo "(a route file with no requireAuth / authenticate / middleware guard)"
for f in $(grep -rlE '\.(post|get|put|patch|delete)\(|@(app|router|blueprint)\.route|@(Get|Post|Put|Delete)Mapping|Route::|http\.HandleFunc' \
    --include='*.ts' --include='*.js' --include='*.py' --include='*.go' --include='*.rb' \
    --include='*.php' --include='*.java' $SRC_ROOTS 2>/dev/null \
    | grep -viE 'test|spec|node_modules|vendor/' | head -25); do
  grep -qiE 'requireAuth|requireUser|authenticate|isAuthenticated|login_required|before_action|@auth|IsAuthenticated|middleware.*auth|authorize' "$f" \
    || echo "  no auth guard seen in: $f"
done
echo
echo "Cross the two lists: an endpoint that appears in BOTH spends the owner's"
echo "money on an anonymous request. DO NOT send a burst to test it - you would"
echo "actually send the mail. Read the handler and look for a quota instead."

sec "DEPENDENCY ADVISORIES"
for dir in . server backend api web frontend; do
  [ -f "$dir/package.json" ] || continue
  printf -- '--- npm audit in %s ---\n' "$dir"
  (cd "$dir" && npm audit --audit-level=moderate 2>&1 | tail -12)
done
[ -f requirements.txt ] && { command -v pip-audit >/dev/null && pip-audit 2>&1 | tail -12 || echo "(pip-audit not installed)"; }
[ -f go.mod ] && { command -v govulncheck >/dev/null && govulncheck ./... 2>&1 | tail -12 || echo "(govulncheck not installed)"; }
[ -f Cargo.toml ] && { command -v cargo-audit >/dev/null && cargo audit 2>&1 | tail -12 || echo "(cargo-audit not installed)"; }
echo
echo "Rank each advisory by which side of the build it sits on: a devDependency"
echo "is toolchain, not shipped."
