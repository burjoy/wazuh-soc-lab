# INC-001 Document Package

Four documents covering one incident from four angles: what happened, how to rebuild the
lab, how to detect and triage it, and how the attack was staged.

All activity was local, against a VM created for the exercise. No production systems,
client data, or real credentials are included.

---

## Documents

| # | Document | Audience | What it answers |
|---|---|---|---|
| 1 | [Findings report](01-findings-report.md) · [PDF](01-findings-report.pdf) | Anyone | What happened, what the evidence shows, why the severity is High, what to fix |
| 2 | [Reproduction guide](02-reproduction-guide.md) · [PDF](02-reproduction-guide.pdf) | You, rebuilding the lab | How to go from a bare host to a working Wazuh + VM + rule setup |
| 3 | [Detection, mitigation, triage](03-detection-mitigation-triage.md) · [PDF](03-detection-mitigation-triage.pdf) | L1/L2 analysts | How the rules behave, how to triage this alert, how to contain and harden |
| 4 | [Attack setup](04-attack-setup.md) · [PDF](04-attack-setup.pdf) | Detection testers | How the incident was staged, phase by phase, safely |

The shorter narrative version is [../INC-001-ssh-brute-force.md](../INC-001-ssh-brute-force.md).
The ticket is [../../tickets/INC-001-ssh-brute-force.md](../../tickets/INC-001-ssh-brute-force.md).

---

## Reading order

- **Hiring manager / interviewer**  
  Document 1, then the narrative.
- **Analyst**  
  Document 3, then document 1 §6–7.
- **Rebuilding it**  
  Document 2, then 4.
- **Detection engineering**  
  Document 3 §2–3, plus `../../rules/tuning-notes.md`.

---

## Key facts

| | |
|---|---|
| Date | 2026-10-30, 15:21–15:23 UTC |
| Host | Debian 12 VM `soc-victim`, 10.0.2.15 |
| Account | `svc-backup` (uid 1002), password auth enabled |
| Attack | 20 passwords, 34 s from launch to login |
| Persistence | `authorized_keys` added at 15:22:22 |
| Privilege escalation | Attempted, failed (`sudo` required a password) |
| Severity | High |
| Detection | 5763 to 40112 to 100120 |
| Noise | 400 alerts in 150 s, 292 of them audit execve |
| Custom rule | 100120, FIM on `authorized_keys` |
| Key file SHA-256 | `61954205be034570c75bdd6db67b3fbd3410ac1d4bebb08b65d117667965c5e8` |

---

## Evidence

| File | Contents |
|---|---|
| [`../../docs/evidence/INC-001-alerts.json`](../../docs/evidence/INC-001-alerts.json) | 400 alerts from the incident window |
| [`../../docs/evidence/INC-001-auth.log`](../../docs/evidence/INC-001-auth.log) | sshd journal excerpt |
| [`../../docs/evidence/INC-001-audit.log`](../../docs/evidence/INC-001-audit.log) | audit records for the compromised session |
| [`../../docs/evidence/INC-001-postex-commands.txt`](../../docs/evidence/INC-001-postex-commands.txt) | Decoded command line |

---

## Rebuild the PDFs

PDFs are generated from the Markdown with headless Chrome:

```bash
python3 tools/md2pdf.py \
  writeups/INC-001/01-findings-report.md \
  writeups/INC-001/02-reproduction-guide.md \
  writeups/INC-001/03-detection-mitigation-triage.md \
  writeups/INC-001/04-attack-setup.md
```

Requirements: Python 3, `markdown`, `pygments`, and Chrome at
`/opt/google/chrome/chrome`.

---

## Scope and disclaimer

This is an independent portfolio lab. It is not affiliated with any employer or client.
The attack is a controlled simulation on an isolated VM. The account, password, and key
are fictitious. The authorized assessment work mentioned in the wider portfolio is
described generically and is not reproduced here.