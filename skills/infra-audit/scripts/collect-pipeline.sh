#!/usr/bin/env bash
# Read-only review of the deployment pipeline definition. Run from the repo root.
# Reads workflow files; runs nothing, triggers nothing.
set -uo pipefail
sec() { printf '\n=== %s ===\n' "$1"; }

WF=.github/workflows
[ -d "$WF" ] || { echo "no $WF (not GitHub Actions - review the equivalent by hand)"; }

sec "WORKFLOWS PRESENT"
ls -1 "$WF" 2>/dev/null || true
ls -1 .gitlab-ci.yml Jenkinsfile .circleci/config.yml 2>/dev/null || true

sec "TRIGGERS THAT RUN UNTRUSTED CODE WITH SECRETS IN SCOPE"
grep -rn 'pull_request_target\|workflow_run\|issue_comment' "$WF" 2>/dev/null \
  || echo "(none - good)"
echo "pull_request_target runs in the base repo's context WITH secrets while checking out"
echo "the fork's code: the pwn-request pattern. If present, verify it never checks out"
echo "and executes the PR head."

sec "THIRD-PARTY ACTIONS NOT PINNED TO A COMMIT SHA"
grep -rn 'uses:' "$WF" 2>/dev/null | grep -v 'uses: \./' \
  | grep -vE '@[0-9a-f]{40}' || echo "(all pinned to a SHA - good)"
echo "A mutable tag can be force-pushed: in March 2026, 75 of 76 trivy-action tags were"
echo "overwritten this way and exfiltrated secrets from every pipeline that used them."

sec "TOKEN PERMISSIONS"
grep -rn -A3 'permissions:' "$WF" 2>/dev/null | head -30 \
  || echo "WARNING: no explicit permissions block - the default token may be write-scoped"

sec "RUNNERS"
grep -rn 'runs-on:' "$WF" 2>/dev/null | sort -u
echo "self-hosted runners keep cached credentials, shell history and internal network"
echo "access between jobs; a mounted docker socket on one is host root."

sec "SECRETS REFERENCED"
grep -rnoE 'secrets\.[A-Z_]+' "$WF" 2>/dev/null | sort -u | head -25

sec "SECRETS REFERENCED BUT NEVER SET (a workflow running on an empty credential)"
# An unset secret expands to the empty string. The step then runs with no
# credential at all, and unless it checks its own exit status it stays green
# while doing nothing. This is class 12 of the taxonomy, and it is invisible
# from the workflow file alone: the name is right there, it just has no value.
if command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
  referenced=$(grep -rhoE 'secrets\.[A-Z_]+' "$WF" 2>/dev/null \
    | sed 's/^secrets\.//' | sort -u | grep -v '^GITHUB_TOKEN$')
  present=$(gh secret list --json name --jq '.[].name' 2>/dev/null | sort -u)
  missing=""
  while read -r name; do
    [ -z "$name" ] && continue
    printf '%s\n' "$present" | grep -qx "$name" || missing="$missing $name"
  done <<< "$referenced"
  if [ -n "$missing" ]; then
    echo "FLAG: referenced by a workflow but absent from the repository secrets:"
    for m in $missing; do echo "      $m"; done
    echo "      Each expands to an empty string at run time. Read the step that uses it:"
    echo "      if it does not check its own status, that job is green and doing nothing."
    echo "      (Environment- and organisation-level secrets are not listed by this"
    echo "      command, so confirm before reporting one as a finding.)"
  else
    echo "(every referenced secret exists at repository level)"
  fi
else
  echo "(gh not installed or not authenticated: compare the names above against the"
  echo " repository's configured secrets by hand. An unset secret expands to an empty"
  echo " string and the step usually stays green.)"
fi

sec "REPORTING CALLS THAT CANNOT FAIL (class 12)"
# A job whose whole purpose is to report somewhere, and whose transport call
# never checks a status code, cannot distinguish "nothing to report" from
# "reported nowhere". curl is silent by default: no -f, no captured
# %{http_code}, no `set -e`-visible exit means a refused POST reads as success.
reporting=$(grep -rnE 'curl[^|]*(-X *POST|--data|-d )' "$WF" 2>/dev/null \
  | grep -vE '[-][-]fail|[-]f |[-]fsS|[-][-]fail-with-body|http_code|[-][-]retry-all-errors')
if [ -n "$reporting" ]; then
  echo "FLAG: POST without -f and without a checked status code:"
  printf '%s\n' "$reporting" | head -10
  echo "      Verify at the DESTINATION that the report actually arrives, not in the"
  echo "      run log. A green run proves the step ended, not that anyone was told."
else
  echo "(no unchecked reporting call found)"
fi

sec "SCHEDULED JOBS: WHAT PROVES THEY STILL RUN?"
grep -rn -B2 -A2 'schedule:' "$WF" 2>/dev/null | head -20 || echo "(no scheduled workflow)"
echo "For each: does it alert only on events? Then its silence is unfalsifiable -"
echo "a dead job and a quiet system are the same observation. A heartbeat to an"
echo "external service is what makes the silence mean something."

sec "COMMANDS RUN AGAINST PRODUCTION"
grep -rnE 'ssh |scp |rsync |docker (compose )?(up|push)|kubectl|terraform apply' "$WF" 2>/dev/null | head -15
echo "Each of these implies a long-lived credential in the pipeline: check its scope."
