# INC-006: Authorized change (cron/systemd)

| Field | Value |
|---|---|
| Decision | Closed, authorized change, no incident |
| Classification | Benign true positive |
| Change | CHG-2026-1101-01 (approved) |
| Host | soc-victim (Debian 12) |
| Alerts | 1× 100129, 3× 100130 |
| Hash match | 3/3 |
| Follow-on activity | none |
| Detected (UTC) | 2026-10-31 23:35:51 |
| Closed (UTC) | 2026-10-31 23:37 |

## What fired

| Rule | Path |
|---|---|
| 100129 | `/etc/cron.d/log-maintenance` |
| 100130 | `/etc/systemd/system/logrotate-check.service` |
| 100130 | `/etc/systemd/system/logrotate-check.timer` |
| 100130 | `/etc/systemd/system/timers.target.wants/logrotate-check.timer` |

Supporting: audit `80792` writes, sudo `5402` attribution, FIM 554 for the change record.

## Change evidence

| Field | Value |
|---|---|
| Change ID | CHG-2026-1101-01 |
| Requester | analyst |
| Approver | lab-change-manager |
| Window | 2026-11-01 06:30 UTC |
| Purpose | Log cleanup and a logrotate health check |
| Rollback | Disable timer, remove units, daemon-reload, remove cron file |

Hashes:

```text
58acf8face227878d58765d32cebe4b82b562996b9e77b02d7011e7533835437  cron
6a0555d9e6831f2dcf2b208e7f7bf4da9473f145b4d31b46ebde76def3a50f19  service
83d683d881cc93e29c2f56f6925756b60d53c84f4234e2bbdeac060d87658cd8  timer
```

## Verification

| Check | Result |
|---|---|
| Change approved and in window | yes |
| File paths match the record | 3/3 |
| SHA-256 match the record | 3/3 |
| Content matches the purpose | log cleanup / `/usr/bin/true` |
| Timer active | yes |
| Auth failures or new accounts | none |
| Unexpected process or egress | none |

## Why this is not a false positive

The files really did change, and the rules correctly reported it. The activity was
authorized. The correct label is benign true positive / authorized change.

A false positive would mean the detection was wrong. It was not. Closing this as a false
positive would create pressure to suppress 100129/100130 and hide the next unauthorized
cron file.

## What would change the decision

| Condition | Outcome |
|---|---|
| No change record | Escalate as unapproved persistence |
| Hash mismatch | Escalate. Deployed file is not the approved one |
| Outside the window | Escalate. Ask the approver |
| Unexpected content | Escalate |
| Follow-on anomaly | Escalate as possible compromise |

## Action taken

- No containment.
- No rule change or suppression.
- Change record, hashes, alerts, and verification output preserved.
- Detection left enabled.

## Recommendations

| # | Action |
|---|---|
| 1 | Enrich persistence alerts with the change ID when one exists |
| 2 | Route approved changes to a change-aware queue |
| 3 | Keep the hashes in the change record |
| 4 | Review after the first scheduled run |
| 5 | Do not suppress the rule on busy change days |

## Evidence

- `docs/evidence/INC-006-alerts.json`, 162 alerts in the triage window
- `docs/evidence/INC-006-change-record.md`, approved change with hashes
- `docs/evidence/INC-006-triage.txt`, unit contents, hashes, timer state, auth check
- `writeups/INC-006/`, four-document package
