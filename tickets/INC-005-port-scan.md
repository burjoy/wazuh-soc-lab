# INC-005 — Outbound port scan

| Field | Value |
|---|---|
| Severity | Medium (reconnaissance) |
| Status | Closed — escalated for verification |
| Source | Suricata sid 1000001 → Wazuh 86601 |
| Source host | `soc-victim` 10.0.2.15 |
| Destination | QEMU gateway 10.0.2.2 |
| Scan | `nmap -sS --top-ports 200 --min-rate 500` |
| Alerts | 144 scan events (first run) |
| Detected (UTC) | 2026-10-31 23:26:35 |
| Follow-on activity | None observed |

## What fired

- **Suricata sid 1000001** — `LAB SCAN outbound SYN sweep`.
- **Wazuh 86601** — `Suricata: Alert - LAB SCAN outbound SYN sweep`.
- 144 alerts in two seconds: 5 at 23:26:35, 139 at 23:26:36.
- Destination ports included 1074, 808, 2121, and many others.

No authentication, file change, process execution, or egress followed the scan.

## False-positive baseline

Run before the scan:

| Legitimate activity | Alerts |
|---|---|
| Normal `apt` + `curl` | 0 |
| 40 requests in a burst | 0 |
| 60 requests in a burst | 10 |

The rule counts 50 SYNs per 5 seconds from one source. The 60-request burst crosses the
threshold; that is a documented false-positive boundary, not a hidden bug.

## Timeline

| Time (UTC) | Event |
|---|---|
| 23:26:26 | Normal traffic, 0 alerts |
| 23:26:28 | 60-request legit burst, 10 alerts (FP) |
| 23:26:35 | nmap starts |
| 23:26:35–36 | 144 scan alerts |
| 23:26:40 | Scan ends |
| 23:27 | Evidence exported |

## Investigation

- Confirmed the source was the lab VM and the destination was its gateway.
- Checked authentication logs (5715/5760/5763) for the source: no follow-on attempts.
- Checked FIM and audit for new files/processes: none.
- Checked for outbound connections: none beyond normal traffic.
- Confirmed the scan was not an approved inventory run.

## Severity rationale

**Medium.** Reconnaissance only, one source, one destination, no exploitation or
session. Raise to High if authentication failures or exploit attempts follow within the
hour; Critical if a session or payload follows.

## Action taken

1. Preserved the Suricata events, Wazuh alerts, and nmap output.
2. Confirmed no follow-on host activity.
3. Escalated for scanner-schedule and host-owner verification.
4. Did not isolate the host: a scan alone does not justify containment.

## Detection gaps

| Gap | Consequence |
|---|---|
| Outbound-only rule | An inbound scan of the VM is not covered |
| Packet-count threshold | Legit bursts false-positive; slow scans evade |
| One destination | A subnet sweep is not represented |
| No follow-on correlation | Scan and exploit are separate alerts |

## Recommendations

| # | Action |
|---|---|
| 1 | Maintain a scanner inventory and schedule |
| 2 | Baseline load tests/monitoring bursts |
| 3 | Correlate scan → auth failures → exploit attempts |
| 4 | Add the inbound rule if the sensor sees inbound traffic |
| 5 | Deploy the bridge upgrade if an inbound lab scenario is needed |
| 6 | Review the 50/5 s threshold against the estate |

## MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| Network service discovery | T1046 | SYN sweep across 200 ports |
| Active scanning | T1595 | nmap from the victim |

## Evidence

- `docs/evidence/INC-005-alerts.json` — Wazuh alerts in the window
- `docs/evidence/INC-005-suricata.json` — Suricata `LAB SCAN` events
- `docs/evidence/INC-005-scan.txt` — nmap output
- `docs/evidence/INC-005-fp.txt` — false-positive baseline
- `docs/evidence/INC-005-rule.txt` — the local Suricata rule
- `writeups/INC-005/` — four-document package
- `rules/inc-005-rules.md` — rule rationale and test matrix
