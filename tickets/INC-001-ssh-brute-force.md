# INC-001: SSH brute force, successful login, authorized_keys persistence

| Field | Value |
|---|---|
| Severity | High |
| Status | Closed, escalated to L2 |
| Source | Wazuh 5763 to 40112. Custom 100120 |
| Host | soc-victim (Debian 12) |
| Account | svc-backup (uid 1002) |
| Source address | 10.0.2.2 (lab gateway, see caveat) |
| Detected (UTC) | 2026-10-30 15:22:01 |
| Confirmed (UTC) | 2026-10-30 15:22:21 |
| Time to triage | ~4 minutes (exercise conditions) |

## What fired

1. 20 × 5760, `sshd: authentication failed` for `svc-backup`, 15:21:51–15:22:19.
2. 5763, `sshd: brute force trying to get access to the system`, 15:22:01.
3. 40112, `Multiple authentication failures followed by a success`, 15:22:21.
   The same rule also fired on six alerts from four routine `analyst` sessions in the
   same window.
4. 100120, `FIM: SSH authorized_keys added or modified`, 15:22:22.

Raw line:

```text
Oct 30 15:22:21 soc-victim sshd[10847]: Accepted password for svc-backup from 10.0.2.2 port 52318 ssh2
```

## Investigation

- **Volume and timing**  
  20 failures in 31 seconds, one account, one source. Not a
  user mistyping a password.
- **Success**  
  Password authentication for `svc-backup` succeeded at 15:22:21.
- Post-login activity (auditd):
  `id`, `whoami`, `uname -a`, `head -1`, `sudo -n -l`, `mkdir -p ~/.ssh`,
  `bash -c` (key append), `curl http://10.0.2.2:8080/`.
- **Privilege escalation**  
  `sudo -n -l` returned "a password is required". No root
  session, no new account, no sudoers change.
- **Persistence**  
  `/home/svc-backup/.ssh/authorized_keys` added, realtime FIM.
- **Lateral movement**  
  No evidence in this host. One outbound HTTP request to the
  lab gateway returned 200.

## Findings

| Item | Value |
|---|---|
| File | `/home/svc-backup/.ssh/authorized_keys` |
| Event | added (realtime) |
| Owner | `svc-backup` (1002) |
| SHA-256 | `61954205be034570c75bdd6db67b3fbd3410ac1d4bebb08b65d117667965c5e8` |
| Attempts | 20 failed passwords, 1 success |
| Root obtained | No |
| Accounts created | None |

## Severity rationale

**High**

Valid account compromised plus persistence. Not Critical: unprivileged
account, `sudo` failed, no lateral movement observed. Not Medium: the key survives a
password reset, so the attacker retains a route back in.

## Action taken

1. Host isolated (VM snapshot preserved. Network is host-only).
2. `svc-backup` disabled and password expired.
3. Unauthorised key removed. File hash recorded before and after.
4. Evidence preserved: alert JSON, journal, audit records, decoded command list.
5. Escalated with the timeline and hash.

## Escalation note

> `svc-backup` compromised via SSH password brute force at 15:22:21 UTC. Attacker
> added an SSH key at 15:22:22 (SHA-256 above) and ran discovery. `sudo` failed.
> Host isolated, account disabled, key removed. Requesting an estate-wide check for
> the key fingerprint and a review of password authentication on service accounts.

## Lessons

- The account had password auth enabled and a password that appeared in a 20-entry
  list. Neither should be true for a service account.
- No lockout: 20 attempts were allowed.
- Stock 40112 is account-blind and source-IP-only. In this lab every session shares
  the gateway, so it produced six false-positive alerts. Tune it rather than duplicating
  it.
- Full execve auditing produced 292 alerts in 150 seconds. Filter by the account or
  session under investigation.

## Evidence

- `docs/evidence/INC-001-alerts.json`, 400 alerts in the incident window
- `docs/evidence/INC-001-auth.log`, sshd journal
- `docs/evidence/INC-001-audit.log`, audit records for the session
- `docs/evidence/INC-001-postex-commands.txt`, decoded command line
- `writeups/INC-001-ssh-brute-force.md`, full narrative