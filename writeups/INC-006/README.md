# INC-006 Document Package

Four documents covering the authorized-change triage: what happened, how to rebuild the
change, how to verify and close it, and how the change was staged.

The scenario is deliberately benign. The skill being demonstrated is the closure,
not an attack.

---

## Documents

| # | Document | Audience | What it answers |
|---|---|---|---|
| 1 | [Findings report](01-findings-report.md) · [PDF](01-findings-report.pdf) | Anyone | What fired, what the change record proved, why this is not an incident |
| 2 | [Reproduction guide](02-reproduction-guide.md) · [PDF](02-reproduction-guide.pdf) | You, rebuilding the case | How to create the change package, deploy, triage, and close |
| 3 | [Detection, mitigation, triage](03-detection-mitigation-triage.md) · [PDF](03-detection-mitigation-triage.pdf) | L1/L2 analysts | How to verify authorization, integrity, behaviour, and follow-on activity |
| 4 | [Change setup](04-change-setup.md) · [PDF](04-change-setup.pdf) | Detection testers | How the legitimate change was staged, with variations |

The ticket is [../../tickets/INC-006-authorized-change.md](../../tickets/INC-006-authorized-change.md).

---

## Key facts

| | |
|---|---|
| Date | 2026-10-31, 23:35 UTC |
| Change | CHG-2026-1101-01, approved |
| Files | cron log cleanup. Systemd no-op health check |
| Alerts | 1× 100129, 3× 100130 |
| Hash match | 3/3 |
| Follow-on activity | none |
| Decision | Closed, authorized change, no incident |
| Term | Benign true positive, not a false positive |

---

## Why the distinction matters

| Term | Alert | Activity | Action |
|---|---|---|---|
| False positive | wrong | irrelevant | fix the rule |
| Benign true positive | right | allowed | close with evidence |
| True positive | right | malicious | incident response |

Calling this a false positive would put pressure on 100129/100130 to be suppressed. The
alerts were correct. The change record made them benign.

---

## Evidence

| File | Contents |
|---|---|
| [`../../docs/evidence/INC-006-alerts.json`](../../docs/evidence/INC-006-alerts.json) | 162 alerts in the triage window |
| [`../../docs/evidence/INC-006-change-record.md`](../../docs/evidence/INC-006-change-record.md) | Approved change with hashes |
| [`../../docs/evidence/INC-006-triage.txt`](../../docs/evidence/INC-006-triage.txt) | Unit contents, hashes, timer state, auth check |

---

## Rebuild the PDFs

```bash
python3 tools/md2pdf.py \
  writeups/INC-006/01-findings-report.md \
  writeups/INC-006/02-reproduction-guide.md \
  writeups/INC-006/03-detection-mitigation-triage.md \
  writeups/INC-006/04-change-setup.md
```

Requirements: Python 3, `markdown`, `pygments`, and Chrome at
`/opt/google/chrome/chrome`.

---

## Scope and disclaimer

Independent portfolio lab. The change, approver, hashes, and host are synthetic. The
files only clean old compressed logs and run `/usr/bin/true`. There is no attack payload.
