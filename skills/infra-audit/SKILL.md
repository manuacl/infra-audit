---
name: infra-audit
description: Read-only security audit of a deployed server - host hardening, firewall, reverse proxy, containers, datastore exposure, DNS, deployment pipeline, and the HTTP surface as actually served - producing an evidence-backed report and a prioritized fix plan, without modifying anything. Includes a distinct mode for a host that may already be compromised. Stack-agnostic. Use when someone asks to audit a server, a deployment or an infrastructure, "audite mon serveur", "sécurise mon VPS", "/infra-audit". For a full audit of a project, run this for the deployed half and hand the code half to the `claude-security` plugin.
---

# infra-audit

An audit of what is **deployed**, run read-only, ending in a report and a list
of fixes. Works on any Linux server; assumes no particular stack.

## Before anything: is the host healthy or already compromised?

Ask, and do not assume. **If there is any sign of a successful intrusion, stop
and switch to `references/compromised-host.md`.** The two jobs are different:

| | healthy host | compromised host |
|---|---|---|
| goal | reduce future risk | contain now, then rebuild |
| trust in commands | commands tell the truth | **binaries and logs may lie** |
| first move | collect and rank | preserve evidence, rotate credentials |
| outcome | a prioritized fix plan | a clean rebuild, then this audit on it |

Signs that switch modes: unexplained outbound traffic, unknown processes or
users, log gaps, files nobody wrote, a provider abuse notice, a defacement,
crypto-mining load, or the owner simply saying attacks "got through".

## Scope, and what covers the rest

Anthropic's `claude-security` plugin hunts vulnerabilities in repository code
with multi-agent research and adversarial verification. It is better at that
than anything here, and this skill does not compete with it. What it cannot do
is connect to the server: it cannot see that three services share one database
superuser, that a dashboard answers `200` from the public internet, or that
the running image is not the one the repo declares.

| | covers | reads |
|---|---|---|
| `claude-security` (plugin) | repository code, in depth | the repository |
| **`infra-audit`** | **the deployed assembly** | **the running host and site** |

**When asked for a full audit of a project**, say it splits in two, run this
for the deployed half, and hand the code half to `/claude-security`.

## The one rule that makes this skill work

**Read-only by construction.** Every command reads state. Nothing writes,
nothing authenticates, nothing exploits.

- allowed: reading files, `curl` on public paths, status commands
  (`ufw status`, `sshd -T`, `ss -tlnp`, `docker ps`), `SELECT` on system
  catalogs
- never: login attempts, even against the owner's own dashboard; payload
  injection; writing to any database; restarting services; editing config

If a finding can only be confirmed by writing or authenticating, **report it
as a hypothesis and say what would confirm it**. Do not run it.

Confirm the target belongs to the person asking, or that they are authorized
to audit it. Get that in words before the first command, especially when
auditing on behalf of someone else.

## Where to run it

Run it **from the project's development directory** when the project has one.
Three collectors read the repository and phase 0 reads the project's own
conventions, so the audit is meaningfully weaker without it:

| collector | needs the repo? |
|---|---|
| `collect-stack.sh` | **yes** - compose files, Dockerfiles, lockfiles |
| `collect-pipeline.sh` | **yes** - `.github/workflows` |
| `collect-drift.sh` | **yes** - it diffs the versioned config against the deployed one |
| `collect-host.sh`, `collect-web.sh`, `collect-dns.sh`, `collect-logs.sh`, `collect-compromise.sh` | no - SSH and network only |

**Auditing a server with no repository at hand** (someone else's box, a
machine whose code you do not have) works: the repo-side collectors report
what is absent and the audit narrows to host, web and DNS. Say so in the
report's "not covered" section rather than letting the gap pass silently -
without the repo you cannot see config drift, pipeline credentials, or
whether a quota exists one layer inside the application.

The skill itself lives wherever skills live on the machine; only the *working
directory* matters, and only for those three.

## Phase 0 - framing

1. Get the production URL(s) and the SSH target.
2. Ask what the machine actually runs, and what the owner already knows is
   weak. Their answer is a lead, not a boundary.
3. Read whatever conventions exist: `CLAUDE.md`, `AGENTS.md`, `docs/`, any
   runbook. Findings that violate a rule the project wrote for itself land
   harder than findings that violate your preference.
4. Note which infrastructure files are versioned and which are deployed by
   hand. Every hand-deployed file is a drift candidate.

## Phase 1 - collection

Scripts print raw state and decide nothing. Each degrades gracefully when a
component is absent, so they run on any stack.

```bash
scripts/collect-host.sh       root@host     # os, updates, firewall, ssh, listeners, containers
scripts/collect-web.sh        https://site  # headers, public paths, burst behaviour, TLS
scripts/collect-stack.sh                    # declared images/tags, port bindings, socket mounts, advisories
scripts/collect-dns.sh        example.com   # records, dangling CNAME candidates, SPF/DKIM/DMARC
scripts/collect-pipeline.sh                 # CI triggers, unpinned actions, runner type, prod credentials
scripts/collect-drift.sh      root@host     # versioned config vs what is deployed
scripts/collect-logs.sh       root@host [lines] # what the logs already witnessed: probes, auth hits, sources
scripts/collect-compromise.sh root@host [date]   # only in compromised-host mode
```

**Show the owner what will run before running it on their machine.** The
scripts are short and readable on purpose: a read-only guarantee they can
check beats one they have to take on faith.

## Phase 2a - derive the surface from the system (the lens)

**Do this before opening the category list.** A checklist finds only what is
on it; the categories are a completeness net, run afterwards.

Enumerate what actually exists, then interrogate each item:

- every **listening port**, every **vhost**, every **container**, every
  **scheduled job**, every **credential**, every **inbound path**
- and then read what the logs say was already **tried** against each of them:
  `collect-logs.sh` aggregates that on the host and returns counts only, never
  log lines. Probe traffic is constant background noise on any public address,
  so volume is not a finding. What raises a finding's rank is the crossing:
  an endpoint that is both reachable AND actively hit outranks one that is
  merely reachable, and an auth path being hammered with no quota in front of
  it is a different item from the same path sitting quiet.
- for each one, ask:
  - who can reach this **without credentials**?
  - what credential does it hold, and **what does that credential reach**?
  - what does it **trust**, and can the trusted thing be forged?
  - if it were **fully compromised**, what else falls with it?
  - what does it **cost the owner per request**, and who pays to trigger it?
  - **why is this here at all**, and who remembers putting it there?
  - if I wanted in, **what would I try first**?

The last question finds what no list contains. Answer it honestly before
consulting anything.

**Then search for the actual components.** A static list cannot know about
last month's CVE. For each significant component and its version, look up
current advisories and known misconfigurations, and note the date you looked.

## Phase 2b - sweep the categories, then qualify

`references/taxonomy.md` is the net: eleven attack classes, each with a
read-only check and a ranking note. Sweep them all and say which came back
empty. **A finding that fits no category is still a finding**: write it up and
add the category to the file.

Two rules dominate qualification.

**Evidence or it does not ship.** Every finding carries a command with its
verbatim output, or a `file:line`. A finding you inferred but did not observe
is labelled a hypothesis, in those words. A fabricated finding costs more than
a missed one: it sends someone rebuilding what already worked.

**Verify the absence before claiming it.** The commonest false positive is
"there is no rate limit / no check" when there is one, one layer away,
implemented differently than expected. This mistake was made in the session
that produced this skill: an anonymous endpoint was reported as unthrottled
while it already had a honeypot, an hourly per-identity quota and a
fail-closed branch.

Severity is **blast radius**, not cleverness. A shared database superuser is
not a vulnerability by itself; it is what turns any future third-party
vulnerability into total compromise. That outranks a missing header.

## Phase 3 - the living report

The report is a **state file plus a generator**, never hand-written HTML.

1. Write `findings.json` next to where the owner keeps documents. Schema and a
   worked example: `references/findings.example.json`. Per finding: `id`,
   `order`, `severity` (P1-P4), `category`, `status`, `title`, `evidence`,
   `impact`, `correction`, `cost`, `constraint`, `notes`. Plus `meta`,
   `already_in_place`, `accepted_risks`, `not_covered`.
2. Render and open it:
   ```bash
   python3 scripts/render-report.py <path>/findings.json
   ```
   It writes the HTML beside the JSON, opens it in the browser, and prints the
   progress line.

**The action list runs most urgent first, and settled findings go last.**
`order` drives it, and the section is titled "de la plus urgente a la moins",
so the plan has to mean it. The worst open finding opens the list even when
its fix is a migration: needing a window and a backup is a reason to schedule
it, not a reason to bury it under P4s. Nothing downstream waits on it either,
so the quick surface reductions below can still be taken as they come. Closed
findings are archives, not actions: rank them below every open one.

Deviating from that is allowed, but it must be argued in `meta.order_note`,
which the generator renders in the report. An unexplained plan reads as a
sorting bug - that is exactly how the first one was reported, by an owner
looking at a P1 sitting at rank #10. `render-report.py` warns on both shapes:
the list not opening on the worst open finding, and settled work ranked among
live work.

**`already_in_place` is not padding.** It is what stops the owner
re-investing where the work is done, and it is what makes the findings
credible. Fill it.

**The header card shows exposure, not progress.** Those are two different
signals and conflating them misleads: eight items closed out of ten still
reads critical while a P1 stands. The generator derives one of five levels
from the severity of whatever is *not* fixed - `EXPOSITION CRITIQUE`, `RISQUE
ELEVE`, `RISQUE MODERE`, `RISQUE FAIBLE`, `AUCUN RISQUE OUVERT` - each with
its own colour, and prints the progress underneath as a separate line.

One rule inside that: **accepting a P1 never turns the header green.** An
accepted risk counts toward the level exactly like an open one, the tag is
marked `(ACCEPTE)`, and a callout says the level is carried by a decision
rather than an oversight. A knowingly retained exposure is still an exposure,
and a report that hides that behind a green banner is worse than no report.

Two more rules the generator enforces: **no score out of 100** (the number is
invented and fakes measurement) and **an explicit "not covered" list** (an
audit constates what was examined on a date; it never proves absence of
vulnerability).

### Re-auditing: completing an existing report

Never start a second pass from a blank file. Write the new pass to its own
`findings-<date>.json`, then merge:

```bash
python3 scripts/merge-findings.py <existing>.json <new-pass>.json
python3 scripts/render-report.py  <existing>.json
```

The merge keeps `status`, `notes` and `order` from the existing report and
refreshes the observed facts (evidence, impact) from the new pass. Findings
are matched on an explicit `key` field when present, otherwise on a slug of
the title - give a finding a stable `key` when its wording is likely to change
between passes.

Three outcomes deserve attention, and the script names each:

- **REGRESSION** - a finding previously marked `fixed` that shows up again.
  It reverts to `todo` with the old follow-up preserved underneath. This
  outranks a new finding: something that was closed came back, which means
  either the fix did not hold or it was undone. Investigate why before
  re-applying the same correction.
- **new** - added as `todo`, tagged with the pass date.
- **not observed this pass** - kept as-is with a note. **Never auto-close
  these.** Absence from one pass is not proof of a fix: a collector may have
  failed, a service may have been down, credentials may have changed. Only a
  deliberate re-check closes a finding.

A finding already `fixed` or `accepted` and absent from the new pass stays
settled and silent - that is the normal case, not a signal.

## Phase 4 - remediation, one at a time

Only after the owner has read the report, and only with their go. The audit
was read-only; this phase is not, so it is explicitly separate.

For each item, in `order`:

1. **Restate what it is and what the fix will do**, including whether it is
   reversible and whether it interrupts service. Wait for a go on that one
   item. Never batch several fixes behind one approval.
2. Set `status` to `in_progress` in `findings.json`, re-render. The owner sees
   what is being worked on.
3. Apply the fix. Respect the `constraint` field: it names the property the
   current setup already has that a careless fix would remove.
4. **Verify it from outside**, with the same command that produced the
   evidence. A fix nobody re-measured is a hypothesis.
5. Set `status` to `fixed` and write in `notes` what was actually done and how
   it was verified. Re-render, and show the new progress line.
6. If it cannot be done now: `blocked` with the reason, or `accepted` with the
   rationale. Both are legitimate outcomes and both keep the report honest.

Stop after each item and let the owner decide whether to continue. A security
session that runs six changes in a row on a production host is how an audit
turns into an outage.

## Why scripts, and where judgment stays

Deterministic steps live in `scripts/`; judgment lives here. The split is not
cosmetic:

- a script **cannot hallucinate** a firewall rule or a DNS record, and its
  output is comparable from one run to the next
- a collector's **annotations must be conditional**: a hint printed on every
  run is noise, and noise gets scrolled past. `collect-dns.sh` printed "a
  DMARC policy of p=none monitors but enforces nothing" whatever the real
  policy was, and a real `p=none` went unreported for it. Print a `FLAG:` line
  only when its condition actually holds, so that seeing one means something
- the owner can **read it before allowing it near their server**, and re-run
  it later **without any AI at all**
- but a script **only finds what was coded into it**, which is exactly the
  blind spot phase 2a exists to cover

So: collection, rendering and diffing are scripted. Deriving the surface,
judging reachability and blast radius, writing the finding, ranking, and
carrying out each fix are not, and must not be. Adding a category to the
taxonomy is how a lesson gets kept; adding a check to a collector is how it
gets automated. Do both, in that order.

## Auditing for someone else

- Get explicit authorization in words, and keep to read-only regardless.
- Their machine, their vocabulary: do not assume Docker, systemd, Ubuntu,
  nginx or a git repository. Ask, or let the scripts report what is absent.
- Rank by what **they** would lose, not by what is interesting.
- Say plainly what you did not look at. Someone acting on a partial audit
  believing it complete is worse off than before.
- Hand over the report and the commands, not just conclusions: they need to be
  able to re-run this without you.

## Delegation

Security qualification is not delegable: judging what is reachable and how far
it reaches is the work. Keep it in the main session. A read-only collection
sweep can be delegated when its output would flood context, but a subagent
returns what it saw, never a verdict.

## Traps

- **A change to an `image:` tag is a production migration**, not a config
  edit: it ships whatever schema migrations the new image runs. Pinning a
  floating tag to the version *already running* is the one safe exception.
- **Never edit deployed config during an audit.** When a fix later touches a
  hand-deployed file, port it into the repo in the same session and diff the
  two. Config living only in production is how an outage gets built.
- **A `200` in an access log is not proof a file was served.** SPA fallbacks
  answer `200` with `index.html` for any unmatched path. Compare
  `content_type` and `size_download` against a known page.
- **A negative `curl` is not proof a feature is off.** Anything gated on a
  real browser answers differently to a bare request.
- **CORS is not access control.** It restrains browsers; `curl` ignores it.
- **Docker bypasses the host firewall.** A perfect `ufw status` says nothing
  about a container publishing on `0.0.0.0`. Read both.
- **Dev-only advisories are not production findings.** Say which side of the
  build the package sits on before ranking it.
- **The absence of a WAF or CDN is a decision, not a finding**, at small
  scale. Put it in "risques acceptés" rather than inflating the list.
