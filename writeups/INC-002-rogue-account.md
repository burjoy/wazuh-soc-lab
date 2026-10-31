# The account nobody asked for

### Catching a rogue sudo user in Wazuh, when the stock rule only says "new user"

A lab write-up. Local VM, synthetic accounts, no production data.

---

## Summary

At 04:30:46 UTC, a local account was created on the endpoint and added to the `sudo`
group one second later. The account had an interactive shell, a password, and a home
directory. It was not requested by any change process.

Stock Wazuh noticed part of it: rule **5902** reported a new user at **level 8**, and
FIM reported `/etc/passwd`, `/etc/group`, `/etc/shadow`, and `/etc/gshadow` as modified.
None of that says "this account can become root."

A custom rule, **100121**, did say it:

```text
Privilege assignment: user added to the sudo group (svc-ops)
```

It fired on the `usermod` process, using the audit argument vector. That is the
difference between a low-priority identity event and a privilege-escalation finding.

---

## The environment

| Component | Detail |
|---|---|
| SIEM | Wazuh 4.14.7 |
| Endpoint | Debian 12 VM, agent 4.14.7 |
| Telemetry | auditd execve (`audit-wazuh-c`), file watches (`audit-wazuh-w`), FIM realtime on `/etc` and `/home` |
| Actor | `analyst` (uid 1000), the lab administrator, via `sudo` |
| Noise | Routine logins, `sudo`, web requests, full execve auditing |

The actor being an administrator is deliberate. This models the two cases that look
identical in the log: a compromised admin session, or an insider creating a backdoor
account. The investigation can separate them only with change-control evidence.

---

## What the noise looked like

The window produced **237 alerts** in about 80 seconds:

| Rule | Description | Count |
|---|---|---|
| 80792 | Audit: command executed | majority |
| 550 | FIM: integrity checksum changed | 16 |
| 554 | FIM: file added | 10 |
| 5501 / 5502 | PAM session opened / closed | 13 / 10 |
| 553 | FIM: file deleted | 7 |
| **100121** | **sudo group assignment** | **1** |
| **5902** | **new user** | **1** |
| **5901** | **new group** | **1** |

The 5901/5902 pair sits at level 8. In a queue dominated by audit commands, that is
easy to defer. The custom rule puts the escalation at level 12 and names the account.

---

## Timeline

| Time (UTC) | Event |
|---|---|
| 04:30:46 | `sudo useradd -m -s /bin/bash svc-ops` |
| 04:30:46 | `chpasswd` sets the account password |
| 04:30:47 | `sudo usermod -aG sudo svc-ops` |
| 04:30:47 | `id svc-ops` → `groups=1003(svc-ops),27(sudo)` |
| 04:30:46–47 | FIM: `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow` modified |
| 04:30:48 | **100121** fires with the `usermod` argument vector |
| 04:30:48 | **5901** and **5902** fire |
| 04:32:07 | Account removed from `sudo`, then deleted |

The audit alert timestamps lag the journal by about a second because of event grouping;
the journal is the authoritative time source for the actions.

---

## The rule

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

Why this shape:

- **`if_sid 80792`** anchors on Wazuh's decoded audit command rule, so the fields are
  already parsed.
- **`audit.exe`** restricts it to the `usermod` binary. `useradd` and `chpasswd` have
  their own meaning and should not match.
- **`audit.execve.a2`** is the group name argument in `usermod -aG sudo <user>`. Matching
  `sudo` covers both `-aG` (append) and `-G` (replace); both are privilege assignment.
- **`$(audit.execve.a3)`** puts the affected account in the alert title, which saves the
  analyst a pivot.

Limitations:

- It matches the `sudo` group name. A site that uses a custom privileged group
  (`wheel`, `admin`, `ops-root`) needs that group added to the rule or a list lookup.
- It relies on auditd and the `audit-wazuh-c` key. Hosts without auditd get nothing.
- It is a *privilege assignment* rule, not an authorization rule. Legitimate admin
  onboarding will fire it; that is intended, because the ticket should ask "was this
  approved?"

A broader alternative is to alert on any `usermod` writing `/etc/group`, which catches
every group change but loses the specific "sudo" signal. I preferred the narrow rule and
a second, lower-severity rule for general group changes if the estate needs it.

---

## Triage

Five questions, in order:

1. **Who created the account?** `analyst`, uid 1000, via sudo from 10.0.2.2.
2. **Was it authorised?** No change request, no window, no naming convention that puts a
   service account in `sudo`.
3. **What can it do?** Membership in `sudo` is root capability on this host.
4. **Has it been used?** No privileged command by `svc-ops` in the window, and no SSH
   login as the account.
5. **What else was added?** Check `authorized_keys`, cron, systemd units, and the
   account's home directory before deleting it.

The containment order matters:

1. Remove from `sudo` (`gpasswd -d svc-ops sudo`).
2. Lock or delete the account (`userdel -r`).
3. Check for persistence the account may have installed.
4. Preserve the membership snapshot and the audit trail.
5. Escalate for the authorization question.

Deleting the account before checking for keys or cron would destroy evidence and miss a
second foothold.

---

## What this scenario teaches

- **New user ≠ new risk.** The risk is the group assignment. Rules should name the
  privilege, not just the object.
- **FIM tells you what changed; audit tells you who and how.** Correlate them in the
  ticket, even if the rule only uses one.
- **Level 8 is not a priority.** In a noisy queue, a medium identity event will wait.
  The custom rule raises the signal without suppressing the underlying event.
- **The actor matters.** An admin account creating a sudo user is either a process
  failure or an insider. Only change-control data can tell you which.
- **Service-account naming is not a control.** `svc-ops` sounded legitimate. It was
  still an interactive, password-authenticated, sudo-capable account.

---

## Reproduce it

```bash
# on the victim, as the admin account
sudo useradd -m -s /bin/bash svc-ops
echo 'svc-ops:Summer2026!' | sudo chpasswd
sudo usermod -aG sudo svc-ops

# expected detections
#   100121  privilege assignment (custom)
#   5902    new user
#   5901    new group
#   550     /etc/passwd, /etc/group, /etc/shadow, /etc/gshadow
#   80792   useradd, chpasswd, usermod

# cleanup
sudo gpasswd -d svc-ops sudo
sudo userdel -r svc-ops
```

---

## Caveats

- The actor is the lab administrator. No real insider or compromised session was
  involved.
- The account name, password, and UID are synthetic.
- The QEMU gateway (`10.0.2.2`) is the source for all sessions, so source IP does not
  distinguish the actor from routine admin activity.
- The rule was validated against a repeat of the `usermod` command; the clean evidence
  run is the one quoted above.
