# INC-002 — Rogue local account added to the sudo group

| Field | Value |
|---|---|
| Severity | High |
| Status | Closed — escalated |
| Source | Custom 100121; stock 5901/5902; FIM 550; audit 80792 |
| Host | soc-victim (Debian 12) |
| Account created | `svc-ops` (uid 1003, gid 1003) |
| Actor | `analyst` (uid 1000) via `sudo`, from 10.0.2.2 |
| Detected (UTC) | 2026-10-31 04:30:48 |
| Contained (UTC) | 2026-10-31 04:32:07 |
| Time to triage | ~3 minutes (exercise conditions) |

## What fired

1. **100121** (custom, level 12) — `Privilege assignment: user added to the sudo group (svc-ops)`
   at 04:30:48.390. Audit execve: `usermod -aG sudo svc-ops`.
2. **5902** (level 8) — `New user added to the system`, `dstuser=svc-ops`, uid 1003.
3. **5901** (level 8) — `New group added to the system`.
4. **FIM 550** — `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` modified.
5. **Audit 80792** — `useradd`, `chpasswd`, `usermod`; **80781** write access to
   `/etc/passwd` and `/etc/group`.

Raw command trail:

```text
04:30:46Z  sudo useradd -m -s /bin/bash svc-ops
04:30:46Z  useradd -m -s /bin/bash svc-ops
04:30:46Z  sudo chpasswd
04:30:47Z  sudo usermod -aG sudo svc-ops
04:30:47Z  usermod -aG sudo svc-ops
04:30:47Z  id svc-ops
```

## Investigation

- The account was created with an interactive shell (`/bin/bash`) and a home
  directory, then immediately added to the `sudo` group.
- `getent group sudo` after the action:

```text
sudo:x:27:analyst,debian,svc-ops
```

  `analyst` and `debian` are the expected members. `svc-ops` is not.
- No change request, no maintenance window, and no naming convention that justifies
  a service account in `sudo`.
- The account did not execute `sudo` during the window. Membership alone grants the
  capability, which is what makes this a privilege-assignment finding rather than a
  simple new user.
- No SSH key or cron persistence was observed before containment.

## Severity rationale

**High.** A newly created account with a known password was granted membership of the
`sudo` group, which is effectively root capability. It is not Critical because no
privileged command was executed by the account before it was removed, and the actor was
an authenticated administrator account rather than an external attacker.

## Action taken

1. Removed the account from the `sudo` group.
2. Deleted the account and its home directory at 04:32:07.
3. Verified the group membership returned to `analyst,debian`.
4. Preserved the alert JSON, journal, audit command trail, and membership snapshot.
5. Escalated for a change-control review.

## Escalation note

> A local account `svc-ops` (uid 1003) was created at 04:30:46 UTC and added to the
> `sudo` group at 04:30:47 by `analyst` via sudo. No change request was found. The
> account had an interactive shell and a password. It was removed from sudo and
> deleted at 04:32:07. Requesting: confirmation that `analyst` was authorised, a review
> of sudo-group membership across the estate, and a check for the same account name on
> other hosts.

## Detection gap this exposed

Stock rule 5902 reports a new account at **level 8**, in a window that also produced
237 alerts, most of them audit command events and FIM changes. Nothing in the stock set
says "this account was given root capability." The custom rule 100121 supplies exactly
that context:

```xml
<rule id="100121" level="12">
  <if_sid>80792</if_sid>
  <field name="audit.exe">/usr/sbin/usermod</field>
  <field name="audit.execve.a2">sudo</field>
  <description>Privilege assignment: user added to the sudo group ($(audit.execve.a3))</description>
  <mitre>
    <id>T1098</id>
    <id>T1548.003</id>
  </mitre>
  <group>audit_command,privilege_escalation,</group>
</rule>
```

It matches the `usermod` binary and the `sudo` argument, rather than relying on file
diffs or a hard-coded username.

## MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| Create local account | T1136.001 | `useradd -m -s /bin/bash svc-ops` |
| Account manipulation | T1098 | `usermod -aG sudo svc-ops` |
| Abuse elevation control: sudo | T1548.003 | Membership in group `sudo` |
| Valid accounts | T1078 | Actor `analyst` using sudo |

## Evidence

- `docs/evidence/INC-002-alerts.json` — 237 alerts in the window
- `docs/evidence/INC-002-account.log` — journal excerpt with sudo/audit lines
- `docs/evidence/INC-002-account-commands.txt` — decoded command trail
- `docs/evidence/INC-002-membership.txt` — `sudo` group and account record

## Lessons

- A new account is not the finding; **the privilege assignment is**. 5902 alone is easy
  to scroll past.
- Service-account conventions must include "never in sudo." `svc-ops` looked plausible
  and was still wrong.
- File integrity monitoring told us *that* `/etc/group` changed; the audit argument told
  us *who* and *to which group*. Correlate them.
- Change-control integration is the real control. Detection caught it in seconds; only a
  ticket lookup can say whether it was allowed.
