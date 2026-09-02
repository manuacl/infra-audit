# Attack classes on the deployed assembly

Code-level vulnerability classes (injection, XSS, SSRF in application code,
deserialization, IDOR) are **not** here: the `claude-security` plugin covers
them from the repository. This file covers what only a look at the running
system can reveal.

## Read this before using the list

**This list is a floor, not a ceiling, and it is not the lens.** A checklist
finds what is on it and blinds you to everything else, which is how an audit
misses the thing that was actually wrong. The lens is SKILL.md phase 2a:
derive the surface from the system in front of you, component by component,
and ask the generative questions of each one. Only then come back here, as a
net, to catch what the derivation missed.

Three consequences:

- **A finding that fits no category is still a finding.** Write it up, then
  add the category to this file. A list that never grows stopped describing
  reality some time ago.
- **The list ages.** The campaign names, CVEs and figures below were true when
  written and will not stay true. When an audit matters, search afresh for the
  actual components of the stack rather than trusting this file's recall.
- **Empty categories are information.** Sweep every one explicitly. Three
  findings in one category and nothing elsewhere usually means the others were
  never looked at, not that they are clean.

Each category gives the attack, the read-only check, and how to rank it.

---

## 1. Compartmentation and privileges

**Attack.** One credential, or one privilege, covering more than its job.
A single database role shared by every service; a superuser where an owner
would do; a container running as root; `/var/run/docker.sock` mounted into a
container, which is a direct line to root on the host, letting a compromised
container spawn privileged containers and escape; a `privileged: true`
container. Industry breakdown of container misconfigurations: containers
running as root ~28%, exposed Docker sockets ~18%, excessive privileges ~10%.

**Check.**
```bash
psql -tAc "select usename, usesuper from pg_user"      # how many identities?
psql -tAc "select datname from pg_database"            # how many share one?
docker inspect <c> --format '{{.HostConfig.Privileged}} {{.Config.User}}'
docker inspect <c> --format '{{range .Mounts}}{{.Source}} {{end}}' | grep docker.sock
```

**Ranking.** Usually the highest-impact finding on a small deployment, and the
one that looks like nothing while you read it. It is not a vulnerability by
itself: it is what turns any future third-party vulnerability into total
compromise. Rank on the blast radius it removes.

---

## 2. Unnecessary exposed surface

**Attack.** Admin panels, dashboards, metrics and debug endpoints reachable
from the internet. Management interfaces are the primary initial-access
vector, ahead of exploits: panels shipped with factory credentials, login
portals under permanent automated credential-stuffing, bots scanning IP ranges
continuously. Also: internal files under the web root, source maps, dumps.

**Check.** For every vhost and every published port, ask what in the product
needs it to be public. A dashboard only its owner uses does not.
`scripts/collect-web.sh` probes the paths; the judgement is yours.

**Ranking.** P2 by default. P1 when the panel has no rate limiting *and* a
password login, since that combination is what the bots are built for. The
correction is almost never "a better password": it is removing the panel from
the internet (VPN, tailnet, IP allowlist).

---

## 3. Datastore exposed or weakly bound

**Attack.** A database listening beyond loopback. Over 650,000 PostgreSQL
instances are internet-facing, 99% of them on the default 5432. Automated
scanners spray credentials against the `postgres` superuser and, on success,
drop a miner through `COPY ... FROM PROGRAM` or PL/Python. Publicly reachable
instances have been compromised within seven minutes of exposure, tables
dropped and a ransom note left.

**Check.**
```bash
ss -tlnp | grep -E '5432|3306|27017|6379'      # bound to 0.0.0.0 or 127.0.0.1?
docker ps --format '{{.Names}}\t{{.Ports}}'    # a published port bypasses ufw
```
A port published as `0.0.0.0:5432->5432` is exposed **even with a perfect
firewall**, because Docker inserts its own rules ahead of it.

**Ranking.** P1 if reachable from outside, no argument.

---

## 4. Reverse proxy correctness and header trust

**Attack.** The proxy and the origin disagree about the same request.
Parser-mismatch and desync attacks (request smuggling) weaponize differing
treatment of `Content-Length` versus `Transfer-Encoding` or chunking between
front-end and origin, letting an attacker slip a second request in or poison
a cache. Alias traversal from a missing trailing slash in an `alias`
directive. h2c smuggling through mishandled `Upgrade` / `Connection` headers,
reaching internal endpoints. Host-header spoofing where no default server
absorbs unmatched hosts. SSRF when the proxy derives the backend address from
something the client sent. In Caddy, `templates` evaluates anything in curly
braces, including untrusted input, and exposes `readFile`.

**Related: trusting client-supplied headers.** `X-Forwarded-For`,
`X-Real-IP` and `CF-Connecting-IP` are attacker-controlled unless the peer is
verified to be your own proxy. Anything keyed on them (rate limits, geo, audit
logs, allowlists) is bypassable when the check is missing.

**Check.** Read the proxy config as configuration, not prose: every `alias`,
every `proxy_pass` whose target contains a variable, every `location` regex,
whether a `default_server` exists, and where the real client IP is resolved.
Confirm the app only trusts forwarding headers when the peer is local.

**Ranking.** P1 for anything reaching an internal endpoint or poisoning a
shared cache; P3 for a spoofable rate-limit key.

---

## 5. Missing quota at the edge

**Attack.** Unauthenticated endpoints that cost the owner something per call:
sending an email or an SMS, an LLM call, an expensive query, a row insert.
Rank by what the attacker spends versus what the owner spends. An endpoint
that mails an arbitrary third party on demand is worse than one that burns
CPU: it damages a sending domain's reputation, which is slow to repair.

**Check.** Send a burst and watch for a change in status code or latency
(`collect-web.sh` does ten). Then **read the code before concluding**: the
quota may exist one layer away.

**Ranking.** P3 normally. P2 when the endpoint spends money or reputation.

---

## 6. Supply chain and the deployment pipeline

**Attack.** The pipeline is a machine with credentials, and in 2026 it is
actively farmed. Mutable action tags: 75 of 76 `trivy-action` version tags
were overwritten by force-push in March 2026, exfiltrating secrets from every
pipeline that ran the scan. The MEGALODON_CI campaign poisoned workflows to
harvest cloud credentials, OIDC tokens and SSH keys, 3,500+ repositories
confirmed by May 2026; a related run pushed 5,718 malicious commits across
5,561 repositories in about six hours. "Pwn requests" through
`pull_request_target` give an external contributor's code access to repository
secrets and write permissions. Self-hosted runners are worse than ephemeral
ones: cached credentials, shell history, internal network access, and a
mounted Docker socket turns a job into host root.

**Check.**
```bash
grep -rn 'pull_request_target\|workflow_run' .github/workflows/
grep -rn 'uses:' .github/workflows/ | grep -v '@[0-9a-f]\{40\}'   # unpinned
grep -rn 'permissions:' .github/workflows/                        # least privilege?
grep -rn 'runs-on:.*self-hosted' .github/workflows/
```

**Ranking.** P1 for a `pull_request_target` workflow that checks out and runs
untrusted code with secrets in scope. P2 for third-party actions pinned to a
mutable tag rather than a commit SHA.

---

## 7. Domain, DNS and mail identity

**Attack.** A dangling DNS record pointing at a third-party resource you no
longer control is a subdomain takeover: an attacker claims the resource and
serves their content from your name, with your TLS and your cookies in reach.
Domain and DNS hijacking plus subdomain takeover ranked as the top threats
organizations experienced in 2025. For a domain that sends transactional mail,
missing or permissive SPF/DKIM/DMARC lets anyone send as you.

**Check.** Enumerate every record and, for each `CNAME`, verify the target
still resolves and is still yours. Then `dig TXT` for SPF, the DKIM selector,
and `_dmarc`. Ordering rule for any later cleanup: **delete the DNS record
first, wait for the TTL, then delete the resource.**

**Ranking.** P1 for a live dangling CNAME. P3 for a `p=none` DMARC policy on a
domain that sends mail.

---

## 8. Secrets and credential material

**Attack.** Secrets readable by more than the process that needs them: file
permissions on disk, secrets baked into image layers (~12% of container
misconfigurations), credentials in CI logs or error responses, long-lived
tokens where short-lived would do.

**Check.** `ls -l` every `.env` on the host; `docker history` for build-time
secrets; grep deployment logs for values that look like keys. Rotate-ability
matters as much as exposure: ask what breaks if this one has to change today.

**Ranking.** P1 if reachable by an unprivileged local process or present in a
published artefact; P3 for over-broad but locally-scoped permissions.

---

## 9. Host hardening

**Attack.** The unglamorous baseline that automated scanning exists to find:
password SSH, permissive root login, no firewall default-deny, unpatched
packages, services listening that nobody remembers starting.

**Check.** `collect-host.sh` covers it. Read fail2ban's jail list against the
services actually exposed: an SSH-only jail on a box whose real surface is
HTTP means the web layer costs an attacker nothing to probe.

**Ranking.** P3 mostly, since these are defence-in-depth. P1 for password SSH
or a missing default-deny.

---

## 10. Backups and recovery

**Attack.** Ransomware's leverage is the backup, not the data. Backups
reachable with the same credentials as production get encrypted alongside it.

**Check.** Do backups exist, are they pulled rather than pushed (so the
production host holds no credential for the backup store), is the storage
versioned or immutable so a compromised admin account cannot rewrite history,
and **has a restore actually been tested**. An untested backup is a
hypothesis.

**Ranking.** P2 when backups exist but share credentials with production. P1
when there are none.

---

## 11. Drift between the repository and production

**Attack.** Not an attack: the condition that makes every other category
unauditable. Config living only on the server cannot be reviewed, and a
hand-edited file diverges silently from the version everyone reads.

**Check.** Diff each versioned infrastructure file against its deployed
counterpart, and compare declared image tags against the images actually
running.

**Ranking.** P4 on its own, but a finding here downgrades your confidence in
every other finding: say so in the report's limits section.

---

## Severity rubric

Rank on blast radius and reachability, never on cleverness.

- **P1** - compromise of data or code execution, or removal of the containment
  that would keep a future third-party vulnerability local. Reachable without
  credentials, or by any authenticated user.
- **P2** - avoidable attack surface, or a bounded auth weakness. Fixable
  without a data migration.
- **P3** - abuse, cost, defence in depth. Nothing is compromised today; an
  attacker pays nothing to keep trying.
- **P4** - hygiene and traceability. Real and cheap, but nobody should lose a
  night over it.

A finding that requires an attacker to already hold a valid session, physical
access, or a compromised developer machine drops one level unless it
escalates privileges.

## False-positive killers

1. **Grep for the protection before claiming it is missing.** Quotas,
   validation and checks often live one layer away: middleware, route body,
   proxy config, database constraint.
2. **A published port on `127.0.0.1` is not exposed.** Read the binding, not
   just the port number. Conversely a `0.0.0.0` binding *is* exposed despite a
   clean `ufw status`.
3. **`200` from an SPA is not a served file.** Compare `content_type` and
   `size_download` against a known page.
4. **A bare `curl` cannot observe browser-gated behaviour.** Cookies, JS,
   geo-redirects and consent walls answer differently.
5. **CORS restrains browsers only.** Never cite it as access control.
6. **A CNAME is only dangling if the target is gone.** Resolve it before
   calling it a takeover.
7. **Check which side of the build a vulnerable dependency sits on.** Dev
   toolchain advisories are not production findings.
8. **Read the project's own rules before flagging a convention.** What looks
   sloppy may be a documented trade-off; what looks fine may violate a rule
   the project wrote for itself, which makes it a finding rather than taste.
9. **A DNS answer from a local resolver is not the zone's answer.** A
   recursive resolver keeps serving what it cached until the TTL expires:
   3362 s was observed on a record deleted minutes earlier. Ask the zone's own
   nameserver, taken from its `NS` record - an empty answer there is the
   deletion, and a non-empty local answer afterwards is propagation, not
   failure. `collect-dns.sh` resolves the nameserver and routes every lookup
   to it; a lookup you type by hand needs the `@ns` yourself. The same trap
   runs backwards, and that is the costly direction: reporting a record as
   still published when the owner already removed it sends them chasing a
   finding that no longer exists.

## Writing a finding

1. **Title** - the defect, not the fix
2. **Evidence** - command plus verbatim output, or `file:line`. Mandatory.
3. **Why it matters here** - the concrete path from this to harm, on this
   deployment. If the sentence needs hedging, it is P4 or it is not a finding.
4. **Correction** - concretely what to change
5. **Cost and risk of the correction** - especially whether it is a migration
6. **Constraint not to break** - the property the current setup already has
   that a careless fix would remove

## Sources

Every figure and campaign named above comes from one of these, consulted
2026-09-02. **Re-check before quoting any of it in a report: these age, and a
stale number in an audit is worse than no number.**

Containers and privileges
- <https://www.redfoxsec.com/blog/escaping-docker-container-in-2026>
- <https://www.aikido.dev/blog/docker-container-security-vulnerabilities>
- <https://www.securityscientist.net/blog/12-questions-and-answers-about-docker-socket-exposure-misconfiguration/>
- <https://resources.infosecinstitute.com/topics/general-security/common-container-misconfigurations-and-how-to-prevent-them/>

Exposed panels and datastores
- <https://www.threatngsecurity.com/glossary/exposed-admin-panels>
- <https://www.imperva.com/blog/postgresql-database-ransomware-analysis/>
- <https://www.hunters.security/en/blog/protecting-postgres>
- <https://tuxcare.com/blog/postgresql-security/>

Reverse proxy and request handling
- <https://gixy.getpagespeed.com/nginx-hardening-guide/>
- <https://swisskyrepo.github.io/PayloadsAllTheThings/Reverse%20Proxy%20Misconfigurations/>
- <https://www.invicti.com/web-application-vulnerabilities/request-smuggling>
- <https://www.invicti.com/blog/web-security/ssrf-vulnerabilities-caused-by-sni-proxy-misconfigurations>

Supply chain and CI/CD
- <https://www.wiz.io/blog/github-actions-security-guide>
- <https://phoenix.security/megalodon-ci-github-actions-workflow-poisoning-credential-harvesting/>
- <https://appsecbrief.com/articles/github-actions-pwn-request-pull-request-target-secrets-exfiltration-2026/>
- <https://github.com/step-security/github-actions-goat/blob/main/docs/Vulnerabilities/ExfiltratingCICDSecrets.md>

Domain and DNS
- <https://aws.amazon.com/blogs/security/threat-tactic-spotlight-subdomain-takeover/>
- <https://www.cscdbs.com/blog/why-domain-and-dns-hijacking-remain-a-critical-ciso-risk-in-2026/>

Standing references, worth preferring over any blog when they cover the point:
the CIS Benchmarks (Docker, Ubuntu, nginx, PostgreSQL), the OWASP Cheat Sheet
Series, and each component's own hardening documentation.
