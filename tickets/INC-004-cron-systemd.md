# INC-004 — Cron and systemd persistence

| Field | Value |
|---|---|
| Severity | Critical |
| Status | Closed — escalated |
| Source | 100129 (cron), 100130 (systemd), audit 80792, sudo 5402 |
| Host | soc-victim (Debian 12) |
| Cron | `/etc/cron.d/updates` — every minute as root |
| systemd | `updates.service` + `updates.timer` — root oneshot |
| Execution | `uid=0(root)` for both |
| Detected (UTC) | 2026-10-31 23:17:25 |
| Contained (UTC) | 2026-10-31 23:19 |
| Time to triage | ~4 minutes (exercise conditions) |

## What fired

1. **100129** (level 12) — `/etc/cron.d/updates` added at 23:17:25.115.
2. **100130** (level 10) — `/etc/systemd/system/updates.service` added at 23:17:28.122.
3. **100130** — `/etc/systemd/system/updates.timer` added at 23:17:28.128.
4. **100130** — `timers.target.wants/updates.timer` symlink at 23:17:31.309.
5. **80792** — `tee` into each path, `systemctl daemon-reload`,
   `systemctl enable --now updates.timer`.
6. **5402** — sudo command attributed to `analyst`.

Proof files:

```text
cron:    uid=0(root) gid=0(root) groups=0(root)
systemd: uid=0(root) gid=0(root) groups=0(root)
```

## False-positive baseline

Run before the attack, on the same host:

| Legitimate action | Result |
|---|---|
| Create `/etc/cron.d/apt-maintenance` | 100129 |
| Modify the same cron file | 100129 |
| `systemctl enable cron` | 100130 (enable symlink) |
| `systemctl disable cron` | silent (553) |

Baseline: **2× 100129, 1× 100130**. Both rules are change monitors; they need a
change-ticket check before escalation.

## Timeline

| Time (UTC) | Event |
|---|---|
| 23:16:58 | Legit `cron.service` enable symlink → 100130 |
| 23:17:01 | Legit cron file added → 100129 |
| 23:17:05 | Legit cron file modified → 100129 |
| 23:17:25 | Malicious cron file added → 100129 |
| 23:17:25 | Audit `tee /etc/cron.d/updates` |
| 23:17:28 | Service and timer added → 100130 ×2 |
| 23:17:31 | Timer enabled → 100130 (symlink) |
| 23:17:31 | Audit `systemctl daemon-reload` / `enable --now` |
| 23:18:01 | Cron and systemd execute as root |
| 23:19 | Timer disabled, units and cron file removed |

## Severity rationale

**Critical.** Both mechanisms execute as root and survive a reboot. The only mitigating
fact is that the actor already had sudo; no privilege escalation was required. If this
were an unprivileged compromise, it would still be Critical because of the root
persistence.

## Action taken

1. Hashed the cron file, service, and timer before deletion.
2. Disabled `updates.timer`.
3. Removed both unit files and ran `systemctl daemon-reload`.
4. Removed `/etc/cron.d/updates`.
5. Preserved alerts, audit commands, sudo records, and proof files.
6. Escalated for a change-control and sudo-access review.

## Detection gaps

| Gap | Consequence |
|---|---|
| `/var/spool/cron/crontabs` not monitored | User cron persistence is invisible |
| Deletion (553) not covered | Removing persistence is silent |
| 100130 fires on enable symlinks | High false-positive volume |
| No write → enable → execute sequence | The analyst joins the dots manually |
| No allow-list of approved units | Legit and malicious units look identical |

## Recommendations

| # | Action |
|---|---|
| 1 | Route 100129/100130 to change-aware triage |
| 2 | Split 100130 into unit body (12) and enable link (5) |
| 3 | Add `/var/spool/cron/crontabs` coverage |
| 4 | Add deletion rules for persistence paths |
| 5 | Allow-list approved units and cron jobs |
| 6 | Review sudo access for the actor |
| 7 | Manage units/cron through configuration management |
| 8 | Alert on unexpected `systemctl enable` |

## MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| Scheduled task/job: cron | T1053.003 | `/etc/cron.d/updates` |
| Create/modify system process: systemd | T1543.002 | `updates.service`/`updates.timer` |
| Abuse elevation control: sudo | T1548.003 | `sudo tee`, `sudo systemctl` |
| Valid accounts | T1078 | Actor `analyst` |

## Evidence

- `docs/evidence/INC-004-alerts.json` — 279 alerts in the window
- `docs/evidence/INC-004-commands.txt` — decoded `tee`/`systemctl`/`id`
- `docs/evidence/INC-004-hashes.txt` — three SHA-256 values
- `docs/evidence/INC-004-proof.txt` — root execution proof
- `docs/evidence/INC-004-files.txt` — unit and cron file contents
- `writeups/INC-004/` — four-document package
- `rules/inc-004-rules.md` — rule rationale and test matrix
