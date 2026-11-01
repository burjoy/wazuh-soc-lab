# INC-003 Document Package

Four documents covering the web-shell incident: what happened, how to rebuild the run,
how to detect and triage it, and how the action was staged.

All activity was local, against a VM created for the exercise. No production systems,
client data, or real credentials are included.

---

## Documents

| # | Document | Audience | What it answers |
|---|---|---|---|
| 1 | [Findings report](01-findings-report.md) · [PDF](01-findings-report.pdf) | Anyone | What happened, what the evidence shows, why the severity is High, what to fix |
| 2 | [Reproduction guide](02-reproduction-guide.md) · [PDF](02-reproduction-guide.pdf) | You, rebuilding the run | How to configure PHP, deploy the rules, reproduce the evidence |
| 3 | [Detection, mitigation, triage](03-detection-mitigation-triage.md) · [PDF](03-detection-mitigation-triage.pdf) | L1/L2 analysts | How the rules behave, how to triage a web shell, how to contain and harden |
| 4 | [Attack setup](04-attack-setup.md) · [PDF](04-attack-setup.pdf) | Detection testers | How the shell was dropped and used, with variations |

The shorter narrative is [../INC-003-web-shell.md](../INC-003-web-shell.md).
The ticket is [../../tickets/INC-003-web-shell.md](../../tickets/INC-003-web-shell.md).

---

## Reading order

- **Hiring manager / interviewer**  
  Document 1, then the narrative.
- **Analyst**  
  Document 3, then document 1 §6–8.
- **Rebuilding it**  
  Document 2, then 4.
- **Detection engineering**  
  Document 3 §2–3, plus [the rules paper](../../rules/inc-003-rules.md) · [PDF](../../rules/inc-003-rules.pdf).

---

## Key facts

| | |
|---|---|
| Date | 2026-10-31, 22:12 UTC |
| Host | Debian 12 VM `soc-victim`, 10.0.2.15 |
| Shell | `/var/www/html/updates2.php` |
| SHA-256 | `50e626c8e31a460af48991b83dfd98c0b24f3a9d9e6eb906e961e77a2aecf15d` |
| Execution | `www-data` (uid 33) via PHP-FPM |
| Detection | 100128 (FIM), 100127 (web), 80790/80792, 5402 |
| Clean-window alerts | 67 |
| Missing stock signal | successful `200` on `.php?cmd=` |

---

## False-positive test

Legitimate PHP deployment and parameter usage were tested on 2026-10-31 at 23:01–23:02:

| Behaviour | Result |
|---|---|
| Legit `index.php` deploy/update | 100128 fires (expected. Needs a change ticket) |
| `GET /index.php?page=1` | silent |
| `GET /index.php?cmd=status` | 100127 fires (false positive) |
| `GET /index.php?foo=1&cmd=id` | no 100127 (parameter-order gap) |
| `app.phtml` | no 100128 (extension gap) |
| `legacy.php5` | 100128 fires (`.php` substring) |
| `/home/analyst/notes/app.php` | 100128 fires (outside webroot) |
| `style.css` | silent |
| Staging copy `/home/analyst/deploy/index.php` | 100128 fires |
| `index.php.bak` / `.tmp` | 100128 fires |
| Referer/UA containing `.php?cmd=` | no 100127 (scoped to request path) |

Full analysis: document 1 §8 and document 3 §5.

---

## Evidence

| File | Contents |
|---|---|
| [`../../docs/evidence/INC-003-alerts.json`](../../docs/evidence/INC-003-alerts.json) | 67 alerts from the clean window |
| [`../../docs/evidence/INC-003-web.log`](../../docs/evidence/INC-003-web.log) | nginx access lines for the shell requests |
| [`../../docs/evidence/INC-003-commands.txt`](../../docs/evidence/INC-003-commands.txt) | Decoded audit commands |

---

## Rebuild the PDFs

```bash
python3 tools/md2pdf.py \
  writeups/INC-003/01-findings-report.md \
  writeups/INC-003/02-reproduction-guide.md \
  writeups/INC-003/03-detection-mitigation-triage.md \
  writeups/INC-003/04-attack-setup.md
```

Requirements: Python 3, `markdown`, `pygments`, and Chrome at
`/opt/google/chrome/chrome`.

---

## Scope and disclaimer

Independent portfolio lab. Not affiliated with any employer or client. The shell is a
three-line test file. The account, host, and hash are synthetic. The action was
performed on an isolated VM by the lab administrator to test detection and response.