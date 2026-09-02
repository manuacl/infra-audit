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

sec "COMMANDS RUN AGAINST PRODUCTION"
grep -rnE 'ssh |scp |rsync |docker (compose )?(up|push)|kubectl|terraform apply' "$WF" 2>/dev/null | head -15
echo "Each of these implies a long-lived credential in the pipeline: check its scope."
