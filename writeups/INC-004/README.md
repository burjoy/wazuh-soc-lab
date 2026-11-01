# INC-004 Document Package

Five documents covering the root-persistence incident: what happened, how to rebuild the
run, how to detect and triage the change, and how the action was staged.

All activity was local, against a VM created for the exercise. No production systems,
client data, or real credentials are included.

---

## Documents

| # | Document | Audience | What it answers |
|---|---|---|---|
| 1 | [Findings report](01-findings-report.md) · [PDF](01-findings-report.pdf) | Anyone | What happened, what the evidence shows, why Critical, what to fix |
| 2 | [Reproduction guide](02-reproduction-guide.md) · [PDF](02-reproduction-guide.pdf) | You, rebuilding the run | How to install cron, deploy the rules, run the baseline, and reproduce the evidence |
| 3 | [Detection, mitigation, triage](03-detection-mitigation-triage.md) · [PDF](03-detection-mitigation-triage.pdf) | L1/L2 analysts | How the rules behave, how to triage persistence, how to contain and harden |
| 4 | [Attack setup](04-attack-setup.md) · [PDF](04-attack-setup.pdf) | Detection testers | How the cron and systemd payloads were staged, with variations |
| 5 | [Evidence walkthrough](05-evidence-walkthrough.pdf) | Interviewer or reviewer | Annotated screenshots of the dashboard, the evidence, the capture steps, and the investigation guide |

The ticket is [../../tickets/INC-004-cron-systemd.md](../../tickets/INC-004-cron-systemd.md).
The rules paper is [../../rules/inc-004-rules.md](../../rules/inc-004-rules.md).

---

## Reading order

- **Hiring manager / interviewer**  
  Document 1.
- **Analyst**  
  Document 3, then document 1 §7–9.
- **Rebuilding it**  
  Document 2, then 4.
- **Detection engineering**  
  Document 3 §2–3, plus the rules paper.

---

## Key facts

| | |
|---|---|
| Date | 2026-10-31, 23:17 UTC |
| Host | Debian 12 VM `soc-victim`, 10.0.2.15 |
| Cron | `/etc/cron.d/updates`, every minute as root |
| systemd | `updates.service` + `updates.timer`, root oneshot |
| Execution | `uid=0(root)` for both |
| Detection | 100129 (cron), 100130 (systemd), 80792, 5402 |
| Severity | Critical, root persistence |

### File hashes

```text
991523eaf5c220a6217557fafc3be04d13f5e496c85f1944641efd71fca05651  cron
1674fae2cbf55c8e5cbb3bb8889409b951811e5a1c26c3e8f35c9efc6760c574  service
b58a06d878ddb229f8bfed5eaebf1d32341ee345d0897b765868f7d16c6f0129  timer
```

---

## False-positive baseline

Run before the attack, on the same host:

| Legitimate action | Result |
|---|---|
| Create `/etc/cron.d/apt-maintenance` | 100129 |
| Modify the same cron file | 100129 |
| `systemctl enable cron` | 100130 (enable symlink) |
| `systemctl disable cron` | silent (deletion is 553) |

The baseline is 2× 100129 and 1× 100130. Both rules report change, not intent.
Route them to a change-aware queue. Do not suppress them.

---

## Evidence

| File | Contents |
|---|---|
| [`../../docs/evidence/INC-004-alerts.json`](../../docs/evidence/INC-004-alerts.json) | 279 alerts in the window |
| [`../../docs/evidence/INC-004-commands.txt`](../../docs/evidence/INC-004-commands.txt) | Decoded `tee`/`systemctl`/`id` commands |
| [`../../docs/evidence/INC-004-hashes.txt`](../../docs/evidence/INC-004-hashes.txt) | SHA-256 for the three files |
| [`../../docs/evidence/INC-004-proof.txt`](../../docs/evidence/INC-004-proof.txt) | Root execution proof |
| [`../../docs/evidence/INC-004-files.txt`](../../docs/evidence/INC-004-files.txt) | Unit and cron file contents |

---

## Rebuild the PDFs

```bash
python3 tools/md2pdf.py \
  writeups/INC-004/01-findings-report.md \
  writeups/INC-004/02-reproduction-guide.md \
  writeups/INC-004/03-detection-mitigation-triage.md \
  writeups/INC-004/04-attack-setup.md
```

Requirements: Python 3, `markdown`, `pygments`, and Chrome at
`/opt/google/chrome/chrome`.

---

## Scope and disclaimer

Independent portfolio lab. Not affiliated with any employer or client. The payload is
`/usr/bin/id` writing to `/tmp`. No external C2. The host, hashes, and unit names are
synthetic. The action was performed on an isolated VM by the lab administrator.
