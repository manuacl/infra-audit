# When the host may already be compromised

A different job from hardening. Hardening reduces future risk; this reduces
present damage. Doing them in the wrong order wastes both.

## First principle

**A compromised host lies.** Its `ps`, `ls`, `netstat` and `find` may be
replaced, its logs edited, its timestamps rewritten. Everything collected from
inside the running system is a lead, never a proof of absence. "The triage
found nothing" does not mean the machine is clean.

The reliable observations come from outside it: network flow logs at the
provider, an out-of-band snapshot of the disk inspected from a rescue system,
backups taken before the intrusion, and logs already shipped off the box.

## Order of operations

Do not reorder these. Each step protects the next.

1. **Decide containment with the owner** before touching anything.
   - Isolating the network stops ongoing damage and exfiltration, and it also
     tips off an attacker who is watching.
   - Powering off preserves the disk but destroys memory, and some persistence
     only exists in memory.
   - Snapshotting the disk at the provider, while the machine runs, is usually
     the best first move: it costs nothing and it is reversible.
   Whatever is chosen, the owner chooses it, knowingly.

2. **Preserve evidence.** Take the provider snapshot. Copy logs off the box
   (`/var/log`, web server logs, shell histories, container logs) to somewhere
   the attacker cannot reach. Do this before any cleanup, and before a reboot
   that might rotate or truncate them.

3. **Triage, read-only**, with `scripts/collect-compromise.sh`. Its job is to
   find the entry vector and the persistence, not to prove cleanliness.

4. **Find the entry vector.** This step is not optional: rebuilding without it
   rebuilds the same hole. In practice the answer is nearly always one of a
   small set - an exposed admin panel with a weak or default password, an
   unpatched internet-facing service, a leaked credential, an exposed
   datastore, or a poisoned dependency or CI pipeline. If it cannot be
   established, assume the most exposed candidate and close all of them.

5. **Rebuild rather than clean.** On a fresh machine, from known-good sources.
   Cleaning a rooted host means proving a negative on a system whose tools
   cannot be trusted; a rebuild takes less time and produces a machine you can
   reason about. **Restore data, never binaries**, and restore from a point
   before the earliest evidence of intrusion, which is usually earlier than
   the first symptom.

6. **Rotate every secret the machine could see.** Not the ones you think
   leaked: all of them. SSH keys and `authorized_keys` everywhere the host
   could reach, database passwords, API tokens, OAuth client secrets, mail
   provider keys, CI deploy keys and runner tokens, cloud credentials, and the
   session-signing secret - rotating that last one invalidates every live user
   session, which is the point.

7. **Then run the normal audit** from SKILL.md against the clean host, so the
   rebuild does not silently reproduce the original weaknesses.

## Obligations that are not technical

If personal data may have been accessed, there are deadlines. In the EU, a
personal-data breach is notifiable to the supervisory authority (in France,
the CNIL) **within 72 hours** of becoming aware of it, and affected people
must be informed when the risk to them is high. Say this plainly to the owner
early; it is not the auditor's decision to make for them, and a missed
deadline is a second problem stacked on the first.

Where money, customer data, or a legal exposure is involved, say plainly that
professional incident response is warranted. Being useful here includes
knowing the edge of what a remote read-only triage can establish.

## What not to do

- **Do not "clean and continue".** Deleting the miner and moving on leaves the
  access that installed it.
- **Do not reboot before capturing evidence.** It can erase memory-only
  persistence and rotate the logs that would have named the entry point.
- **Do not trust the box's own package manager or antivirus** to certify
  itself.
- **Do not log in with new credentials until you know how the old ones went.**
  If a keylogger or a trojaned `sshd` is in play, you are handing over the
  replacement.
- **Do not let the audit become the response.** If damage is ongoing, stop
  auditing and contain first.

## What the triage looks for

`collect-compromise.sh` sweeps, read-only:

- **accounts**: users with a shell, UID 0 duplicates, recently added accounts,
  empty passwords, every `authorized_keys` on the box
- **persistence**: cron (user, system, `cron.d`), `at` jobs, systemd units and
  timers (especially recently written ones), shell profile files,
  `/etc/ld.so.preload` and `LD_PRELOAD`, loaded kernel modules, SUID binaries
  outside the usual set
- **execution**: processes whose binary is deleted or lives in `/tmp`,
  `/dev/shm` or `/var/tmp`; unexpected listening sockets; established outbound
  connections; unknown containers and images
- **tampering**: package integrity (`debsums`, `rpm -Va`) as a lead only;
  files modified around the suspected date; gaps or truncation in logs;
  `lastb` failure volume; web-accessible directories containing scripts that
  should not be there
- **exposure**: what was reachable, so the entry vector has candidates

Every one of these is a lead to investigate, not a verdict. Absence proves
nothing; presence is worth chasing.
