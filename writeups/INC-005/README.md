# INC-005 Document Package

Four documents covering the outbound port scan: what happened, how to rebuild the run,
how to detect and triage it, and how the scan was staged.

All activity was local, against a VM created for the exercise. No production systems,
client data, or real targets are included.

---

## Documents

| # | Document | Audience | What it answers |
|---|---|---|---|
| 1 | [Findings report](01-findings-report.md) · [PDF](01-findings-report.pdf) | Anyone | What happened, what the evidence shows, why Medium, what to fix |
| 2 | [Reproduction guide](02-reproduction-guide.md) · [PDF](02-reproduction-guide.pdf) | You, rebuilding the run | How to add the Suricata rule, measure false positives, and run the scan |
| 3 | [Detection, mitigation, triage](03-detection-mitigation-triage.md) · [PDF](03-detection-mitigation-triage.pdf) | L1/L2 analysts | How the rule behaves, how to triage a scan, how to contain and harden |
| 4 | [Attack setup](04-attack-setup.md) · [PDF](04-attack-setup.pdf) | Detection testers | How the scan and the false-positive bursts were staged |

The ticket is [../../tickets/INC-005-port-scan.md](../../tickets/INC-005-port-scan.md).
The rules paper is [../../rules/inc-005-rules.md](../../rules/inc-005-rules.md).

---

## Key facts

| | |
|---|---|
| Date | 2026-10-31, 23:26 UTC |
| Source | `soc-victim` 10.0.2.15 |
| Destination | QEMU gateway 10.0.2.2 |
| Scan | `nmap -sS --top-ports 200 --min-rate 500` |
| Rule | Suricata sid 1000001, `LAB SCAN outbound SYN sweep` |
| Threshold | 50 SYNs / 5 s, track by source |
| Alerts | 144 scan events, Wazuh 86601 |
| Severity | Medium — reconnaissance, no follow-on |

---

## False-positive baseline

| Legitimate activity | Alerts |
|---|---|
| Normal `apt` + `curl` | 0 |
| 40 requests in a burst | 0 |
| 60 requests in a burst | **10** (false positive) |

The 50/5 s threshold is the boundary. A load test or busy health checker can cross it;
the detection guide covers tuning and correlation.

---

## Evidence

| File | Contents |
|---|---|
| [`../../docs/evidence/INC-005-alerts.json`](../../docs/evidence/INC-005-alerts.json) | Wazuh alerts in the window |
| [`../../docs/evidence/INC-005-suricata.json`](../../docs/evidence/INC-005-suricata.json) | Suricata `LAB SCAN` events |
| [`../../docs/evidence/INC-005-scan.txt`](../../docs/evidence/INC-005-scan.txt) | nmap output |
| [`../../docs/evidence/INC-005-fp.txt`](../../docs/evidence/INC-005-fp.txt) | False-positive baseline |
| [`../../docs/evidence/INC-005-rule.txt`](../../docs/evidence/INC-005-rule.txt) | The local rule |

---

## Rebuild the PDFs

```bash
python3 tools/md2pdf.py \
  writeups/INC-005/01-findings-report.md \
  writeups/INC-005/02-reproduction-guide.md \
  writeups/INC-005/03-detection-mitigation-triage.md \
  writeups/INC-005/04-attack-setup.md
```

Requirements: Python 3, `markdown`, `pygments`, and Chrome at
`/opt/google/chrome/chrome`.

---

## Scope and disclaimer

Independent portfolio lab. Not affiliated with any employer or client. The scan is
limited to the VM's QEMU gateway. The host, addresses, and timestamps are synthetic. The
action was performed on an isolated VM by the lab administrator.
