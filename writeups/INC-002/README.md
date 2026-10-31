# INC-002 Document Package

Four documents covering the rogue-account incident: what happened, how to rebuild the
lab, how to detect and triage the change, and how the action was staged.

All activity was local, against a VM created for the exercise. No production systems,
client data, or real credentials are included.

---

## Documents

| # | Document | Audience | What it answers |
|---|---|---|---|
| 1 | [Findings report](01-findings-report.md) · [PDF](01-findings-report.pdf) | Anyone | What happened, what the evidence shows, why the severity is High, what to fix |
| 2 | [Reproduction guide](02-reproduction-guide.md) · [PDF](02-reproduction-guide.pdf) | You, rebuilding the run | How to deploy the rule, validate it, and reproduce the evidence |
| 3 | [Detection, mitigation, triage](03-detection-mitigation-triage.md) · [PDF](03-detection-mitigation-triage.pdf) | L1/L2 analysts | How the rules behave, how to triage the change, how to contain and harden |
| 4 | [Attack setup](04-attack-setup.md) · [PDF](04-attack-setup.pdf) | Detection testers | How the action was staged, phase by phase, with variations |

The shorter narrative is [../INC-002-rogue-account.md](../INC-002-rogue-account.md).
The ticket is [../../tickets/INC-002-rogue-account.md](../../tickets/INC-002-rogue-account.md).

---


## Detection rules

- [Rules paper](../../rules/inc-002-rules.md) · [PDF](../../rules/inc-002-rules.pdf) — 100121 and the variant rules (100122–100126), with the test matrix
- [Deployed rules](../../rules/local_rules.xml)

## Reading order

- **Hiring manager / interviewer:** document 1, then the narrative.
- **Analyst:** document 3, then document 1 §6–7.
- **Rebuilding it:** document 2, then 4.
- **Detection engineering:** document 3 §2–3, plus `../../rules/tuning-notes.md`.

---

## Key facts

| | |
|---|---|
| Date | 2026-10-31, 04:30–04:32 UTC |
| Host | Debian 12 VM `soc-victim`, 10.0.2.15 |
| Account | `svc-ops` (uid 1003), `/bin/bash`, password, group `sudo` |
| Actor | `analyst` (uid 1000) via `sudo`, source 10.0.2.2 |
| Detection | **100121** (custom, level 12), 5901/5902, FIM 550 |
| Noise | 237 alerts in the window, 160 audit command events |
| Containment | Removed from `sudo`, account deleted at 04:32:07 |
| Privileged use | None observed |
| Custom rule | 100121 — `usermod` with `a2=sudo` |

---

## Evidence

| File | Contents |
|---|---|
| [`../../docs/evidence/INC-002-alerts.json`](../../docs/evidence/INC-002-alerts.json) | 237 alerts from the incident window |
| [`../../docs/evidence/INC-002-account.log`](../../docs/evidence/INC-002-account.log) | Journal excerpt with sudo and audit lines |
| [`../../docs/evidence/INC-002-account-commands.txt`](../../docs/evidence/INC-002-account-commands.txt) | Decoded command trail |
| [`../../docs/evidence/INC-002-membership.txt`](../../docs/evidence/INC-002-membership.txt) | `sudo` group and account record before cleanup |

---

## Rebuild the PDFs

```bash
python3 tools/md2pdf.py \
  writeups/INC-002/01-findings-report.md \
  writeups/INC-002/02-reproduction-guide.md \
  writeups/INC-002/03-detection-mitigation-triage.md \
  writeups/INC-002/04-attack-setup.md
```

Requirements: Python 3, `markdown`, `pygments`, and Chrome at
`/opt/google/chrome/chrome`.

---

## Scope and disclaimer

Independent portfolio lab. Not affiliated with any employer or client. The account,
password, and UID are fictitious. The action was performed on an isolated VM by the lab
administrator to test detection and response.
