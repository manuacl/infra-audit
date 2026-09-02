# infra-audit

A read-only security audit of a **deployed** server, as a Claude Code skill.
It looks at the running host, the reverse proxy, the containers, the datastore
roles, the DNS, the deployment pipeline, and the HTTP surface as actually
served. It produces an evidence-backed HTML report with an ordered action list,
then walks the fixes one at a time, updating the report as it goes.

It is aimed at the person who runs a small production server and wants to know
what is exposed, without buying a scanner.

## Read this first

**Audit only infrastructure you own, or that you have written authorization to
audit.** The collectors SSH into a host and query a public site. That is
trivially legitimate on your own machine and trivially illegitimate on someone
else's. The skill asks for that authorization in words before the first
command; do not route around it.

**Never commit the findings file or the rendered report.** A `findings.json`
is a map of a live system's weaknesses and the HTML is the same map with the
fixes spelled out. The bundled `.gitignore` blocks the usual names; keep them
wherever you keep documents, not in a repository.

## What it does, and what it deliberately does not

| | covers | reads |
|---|---|---|
| [`claude-security`](https://github.com/anthropics/claude-plugins-official) (Anthropic) | repository code, in depth | the repository |
| **`infra-audit`** | **the deployed assembly** | **the running host and site** |

`claude-security` hunts vulnerabilities in source code with multi-agent
research and adversarial verification. It is better at that than anything
here. What it cannot do is connect to the server: it will not see that three
services share one database superuser, that an admin dashboard answers `200`
from the public internet, or that the running image is not the one the repo
declares. That gap is what this skill fills. Use both.

## Install

As a plugin (recommended - it updates in place):

```
/plugin marketplace add manuacl/infra-audit
/plugin install infra-audit@infra-audit
```

Or as a plain skill, no plugin machinery:

```bash
git clone https://github.com/manuacl/infra-audit ~/src/infra-audit
ln -s ~/src/infra-audit/skills/infra-audit ~/.claude/skills/infra-audit
```

Then, in Claude Code: *"audit my server"* / *"audite mon serveur"*, or
`/infra-audit`.

Run it **from the project's development directory** when the project has one:
three of the collectors read the repository. Auditing a server with no
repository at hand works too - the audit narrows to host, web and DNS, and the
report says so.

Nothing is installed on the audited host, and nothing runs on a schedule. The
skill acts only inside a session you started.

## The design, in four rules

**Read-only by construction.** Every collector reads state: no login attempts
(not even against your own dashboard), no payload injection, no writes, no
service restarts. A finding that could only be confirmed by writing or
authenticating is reported as a hypothesis, with what would confirm it. The
scripts are short on purpose - you can read what will run on your server
before it runs, and re-run them later without any AI at all.

**Derivation first, checklist second.** A checklist finds what is on it and
blinds you to everything else. The skill enumerates what actually exists -
every port, vhost, container, credential, scheduled job - and interrogates
each one ("what does this trust, and can it be forged?", "if I wanted in, what
would I try first?"). Only then does it sweep the eleven attack classes in
`references/taxonomy.md` as a completeness net. A finding that fits no
category is still a finding, and the file says to add the category.

**Evidence or it does not ship.** Every finding carries a command with its
verbatim output, or a `file:line`. A fabricated finding costs more than a
missed one: it sends someone rebuilding what already worked.

**No score out of 100.** The number is always invented and it fakes
measurement. The report says what was examined, what was found, and - always -
what was *not* covered.

## The report

`findings.json` is the state; `render-report.py` generates the HTML and opens
it. The header shows **exposure**, derived from the severity of whatever is
not fixed, separately from progress: eight items closed out of ten still reads
critical while a P1 stands. Accepting a P1 never turns the header green - a
knowingly retained risk is still a live exposure, and it is labelled as one.

Re-auditing merges into the existing report rather than replacing it:

```bash
python3 scripts/merge-findings.py report.json new-pass.json
python3 scripts/render-report.py  report.json
```

Status and notes survive; a finding previously marked fixed that reappears is
flagged as a **regression**, which outranks a new finding. Findings absent
from a new pass are never auto-closed - absence in one run is not proof of a
fix.

## Already compromised?

Different job, and the skill says so before anything else. On a host where an
intrusion succeeded, its own binaries and logs may lie, so the order becomes
contain, preserve evidence, find the entry vector, **rebuild rather than
clean**, rotate every secret the machine could see, and only then audit.
`references/compromised-host.md` carries the procedure, including the part
that is not technical: in the EU, a personal-data breach is notifiable within
72 hours.

## What is tested, and what is not

Exercised end to end against Ubuntu 24.04 with Docker Compose, Caddy, nginx,
PostgreSQL and GitHub Actions.

The code paths for **Apache, HAProxy, Traefik, lighttpd, `dnf`-based distros,
a datastore installed directly on the host, and non-Node stacks** (Python, Go,
Ruby, PHP, Java) are written but **not yet exercised**. They degrade to "not
found" rather than failing, but treat their silence as untested rather than as
a clean result. Reports of what they get wrong are welcome.

The attack-class figures in `references/taxonomy.md` are sourced and dated;
they age, and the file says to re-check before quoting them.

## Layout

```
.claude-plugin/plugin.json         plugin manifest
.claude-plugin/marketplace.json    lets this repo be added as a marketplace
skills/infra-audit/
  SKILL.md                         method: phases, guard-rails, traps
  references/taxonomy.md           11 attack classes, severity rubric, false-positive killers
  references/compromised-host.md   incident-response mode
  references/findings.example.json report schema, worked example
  scripts/collect-host.sh          os, updates, firewall, ssh, listeners, containers, db roles
  scripts/collect-web.sh           headers, public paths, burst behaviour, TLS (multi-host)
  scripts/collect-stack.sh         images/tags, port bindings, socket mounts, cost-bearing endpoints
  scripts/collect-dns.sh           records, dangling CNAMEs, SPF/DKIM/DMARC, certificate transparency
  scripts/collect-pipeline.sh      CI triggers, unpinned actions, runner type, production credentials
  scripts/collect-drift.sh         versioned config vs what is actually deployed
  scripts/collect-compromise.sh    read-only intrusion triage
  scripts/render-report.py         findings.json -> HTML
  scripts/merge-findings.py        merge a new pass, keep the follow-up, flag regressions
```

## Contributing

The two things most worth sending: a stack where a collector reported nothing
and should have reported something, and an attack class the taxonomy misses.
Both are the same bug - a blind spot - and the second one is the harder to
find alone.

Please do not attach a real `findings.json` or a rendered report to an issue.
Paste the collector output you need to show, with hostnames and addresses
removed.

MIT licensed.
