# INC-006 — Authorized Change Triage

<!-- subtitle: Four persistence alerts, one approved change, no incident -->
<!--meta
id: INC-006
incident: INC-006 — Authorized change triage
severity: None (authorized change)
-->

| | |
|---|---|
| **Case** | INC-006 — Authorized change triage |
| **Classification** | Lab exercise, sanitized for publication |
| **Activity date** | 2026-10-31 / 2026-11-01 |
| **Report date** | 2026-11-01 |
| **Author** | SOC L1 portfolio lab |
| **Decision** | Closed — authorized change, no incident |
| **Severity** | None (the alerts were correct; the activity was approved) |
| **Related** | `tickets/INC-006-authorized-change.md`, `docs/evidence/INC-006-*` |

---

## 1. Executive summary

At 23:35:51 UTC, four persistence alerts fired:

| Rule | Path |
|---|---|
| **100129** | `/etc/cron.d/log-maintenance` |
| **100130** | `/etc/systemd/system/logrotate-check.service` |
| **100130** | `/etc/systemd/system/logrotate-check.timer` |
| **100130** | `/etc/systemd/system/timers.target.wants/logrotate-check.timer` |

They matched an approved change, **CHG-2026-1101-01**, requested by `analyst` and approved
by the lab change manager. The change record listed the three files and their SHA-256
values; every deployed file matched. The timer was active. The cron job was a benign
log-cleanup task. No authentication, process, or network anomaly followed.

**Decision: closed as an authorized change, not an incident.**

This is not a false positive. The alerts correctly reported that files changed. The
context — an approved change with matching hashes — made the activity benign. Calling it
a false positive would mislabel a working detection and hide the fact that the control
worked.

---

## 2. Scope and method

### 2.1 Scope

| In scope | Out of scope |
|---|---|
| One Debian 12 VM (`soc-victim`, 10.0.2.15) | Production systems |
| Change CHG-2026-1101-01 | Real business changes |
| Rules 100129/100130 | New detection rules |
| Evidence verification | Exploitation |

### 2.2 Method

1. Write a change record with scope, files, hashes, approver, and rollback.
2. Deploy the cron file and systemd service/timer exactly as recorded.
3. Collect the four alerts.
4. Verify the change record, hashes, file contents, timer state, and absence of
   follow-on anomalies.
5. Close the case with a written rationale.

### 2.3 Limitations

- The change manager and approval are synthetic.
- One host; no CMDB or ticketing integration.
- The cron job runs daily at 02:15; it did not execute during the 15-minute triage
  window. The timer is scheduled daily at midnight.

---

## 3. The change

**CHG-2026-1101-01 — Nightly log maintenance**

| Field | Value |
|---|---|
| Status | Approved |
| Requester | analyst |
| Approver | lab-change-manager |
| Window | 2026-11-01 06:30 UTC |
| Purpose | Remove rotated logs older than 7 days; add a logrotate health check |
| Risk | Low |

Files and hashes:

| Path | SHA-256 |
|---|---|
| `/etc/cron.d/log-maintenance` | `58acf8face227878d58765d32cebe4b82b562996b9e77b02d7011e7533835437` |
| `/etc/systemd/system/logrotate-check.service` | `6a0555d9e6831f2dcf2b208e7f7bf4da9473f145b4d31b46ebde76def3a50f19` |
| `/etc/systemd/system/logrotate-check.timer` | `83d683d881cc93e29c2f56f6925756b60d53c84f4234e2bbdeac060d87658cd8` |

The cron file:

```cron
# Nightly cleanup of rotated logs older than 7 days
15 2 * * * root /usr/bin/find /var/log -type f -name '*.gz' -mtime +7 -delete
```

The service runs `/usr/bin/true`; the timer triggers it daily. Neither does anything
destructive.

---

## 4. Timeline

| Time (UTC) | Event |
|---|---|
| 23:35:45 | Triage window starts; change record staged |
| 23:35:51 | Cron file, service, and timer written |
| 23:35:51.674 | **100129** `/etc/cron.d/log-maintenance` added |
| 23:35:51.685 | **100130** `logrotate-check.service` added |
| 23:35:51.692 | **100130** `logrotate-check.timer` added |
| 23:35:51.883 | **100130** enable symlink added |
| 23:35:52 | Timer active |
| 23:36 | Hashes verified against the change record |
| 23:36 | No authentication or process anomalies |
| 23:37 | Case closed as authorized change |

---

## 5. Alerts

| Rule | Level | Path | Assessment |
|---|---|---|---|
| 100129 | 12 | `/etc/cron.d/log-maintenance` | Expected by CHG |
| 100130 | 10 | `logrotate-check.service` | Expected by CHG |
| 100130 | 10 | `logrotate-check.timer` | Expected by CHG |
| 100130 | 10 | `timers.target.wants/...` | Expected side effect of `enable` |

Supporting evidence:

- audit `80792` `tee` / `cp` commands into the three paths;
- sudo `5402` attribution to `analyst`;
- FIM 554 events for the change record under `/home/analyst/changes`;
- `systemctl cat` matching the recorded content;
- `systemctl list-timers` showing the next run;
- no failed logins, invalid users, or authentication failures in the window.

---

## 6. Investigation

### 6.1 Authorization

A change record exists, names the requester and approver, lists the exact files, and
gives the rollback. The deployment time falls inside the approved window.

### 6.2 Integrity

All three deployed files match the hashes in the change record. No extra file was
written under `/etc/cron.d` or `/etc/systemd/system` during the window.

### 6.3 Behaviour

- The cron job deletes only `*.gz` files older than seven days under `/var/log`.
- The service runs `/usr/bin/true`; it has no side effect.
- The timer is enabled for daily execution and has not run during triage.

### 6.4 Follow-on activity

No authentication failures, new accounts, unusual processes, or outbound connections
appeared after the change. The host's normal telemetry continued.

---

## 7. Why this is not a false positive

A false positive is an alert that should not have fired: the rule misread the event, or
the event did not happen.

Here, the rule read the event correctly:

- a cron file **did** appear;
- a service and timer **did** appear;
- an enable symlink **did** appear.

The analyst's job was not to dispute the alert. It was to establish whether the change
was authorized. The change record and matching hashes did that.

The correct label is **benign true positive** or **authorized change**. The distinction
matters:

| Term | Meaning | Action |
|---|---|---|
| False positive | The detection was wrong | Fix the rule |
| Benign true positive | The detection was right; the activity is allowed | Close with evidence; tune context |
| True positive | The detection was right; the activity is malicious | Incident response |

Closing this as a "false positive" would have created pressure to suppress 100129/100130,
which would hide the next unauthorized cron file.

---

## 8. Decision

**Closed — authorized change, no incident.**

- No containment.
- No rule change.
- Change record retained.
- Hashes and alert set preserved.
- The detection remains enabled.

---

## 9. What would change the decision

| Condition | Outcome |
|---|---|
| No change record | Escalate as unapproved persistence |
| Hash mismatch | Escalate; the deployed file is not the approved one |
| Deployment outside the window | Escalate; ask the approver |
| Unexpected command in the cron/service | Escalate; the content is not the approved content |
| Authentication failure or new account | Escalate; possible compromise |
| Outbound connection after the change | Escalate; possible payload |

---

## 10. Recommendations

| # | Action |
|---|---|
| 1 | Enrich 100129/100130 with the change ID when one exists |
| 2 | Route approved changes to a queue that expects them |
| 3 | Keep the rules enabled; do not suppress on busy change days |
| 4 | Store file hashes in the change record |
| 5 | Add an allow-list of approved unit names, not a blanket suppression |
| 6 | Review the change after the first scheduled run |

---

## 11. Lessons learned

- **A correct alert is not a false positive.** Context decides benign vs malicious.
- **Change control is the control.** FIM proved the files appeared; the change record
  proved they were allowed.
- **Hashes make the decision auditable.** "Looks fine" is not evidence.
- **Do not suppress the rule.** Suppression would hide the next unauthorized change.
- **Write the "no incident" ticket as carefully as the incident ticket.** It is the
  hardest L1 skill to demonstrate.

---

## Appendix A — Change record

```markdown
# CHG-2026-1101-01 — Nightly log maintenance

| Field | Value |
|---|---|
| Status | Approved |
| Requester | analyst |
| Approver | lab-change-manager |
| Window | 2026-11-01 06:30 UTC |
| Purpose | Remove rotated logs older than 7 days; add a logrotate health check |
| Risk | Low |

Files and SHA-256 values are recorded in the change record and verified above.
Rollback: disable the timer, remove the units and cron file, daemon-reload.
```

## Appendix B — MITRE ATT&CK

The alerts map to persistence techniques:

| Technique | ID | Note |
|---|---|---|
| Scheduled task/job: cron | T1053.003 | Authorized maintenance |
| Create/modify system process: systemd | T1543.002 | Authorized timer |

The mapping is why the rules exist. It does not make an approved change malicious.

## Appendix C — Evidence index

| File | Contents |
|---|---|
| `docs/evidence/INC-006-alerts.json` | 162 alerts in the triage window |
| `docs/evidence/INC-006-change-record.md` | Approved change with hashes |
| `docs/evidence/INC-006-triage.txt` | Unit contents, hashes, timer state |
| `tickets/INC-006-authorized-change.md` | The closure decision |

## Appendix D — Glossary

| Term | Meaning |
|---|---|
| Benign true positive | Correct alert, allowed activity |
| False positive | Incorrect alert |
| Change record | Documented approval, scope, hashes, rollback |
| FIM | File integrity monitoring |
