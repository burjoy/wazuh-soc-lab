# SOC L1 Lab — Wazuh Triage Portfolio

A small, reproducible detection-and-triage lab built to demonstrate entry-level SOC
Analyst work: alerts generated, investigated, ticketed, escalated, and documented.

**Status:** build in progress. See `docs/build-log.md` for what actually runs.

---

## What this is

| | |
|---|---|
| **Role target** | SOC Analyst Level 1 — monitoring, first-line triage, ticketing, escalation |
| **SIEM** | Wazuh 4.14.7, single-node, Docker |
| **Endpoint** | Ubuntu 24.04 Server VM, Wazuh agent, `auditd`, nginx, `sshd` |
| **Network sensor** | Suricata, inside the endpoint VM, trimmed ET Open ruleset |
| **Ticketing** | Jira (free tier) |
| **Attacker** | Host shell — `nmap`, `hydra`, `curl`, `ssh` |

Everything runs on one laptop, on an isolated host-only network. No internet-facing
targets, no real malware, no employer data.

---

## Architecture

```
Host (CachyOS, 7.5 GB RAM)
┌──────────────────────────────────────────────────────────┐
│  Docker: wazuh-manager / indexer / dashboard              │
│  Attacker shell                                            │
└───────────────┬──────────────────────────────────────────┘
                │ isolated host-only network
┌───────────────┴──────────────────────────────────────────┐
│  Victim VM — Ubuntu 24.04 Server, 1.5 GB                  │
│  sshd · nginx · auditd · wazuh-agent · suricata           │
│  suricata -i eth0 → /var/log/suricata/eve.json            │
└──────────────────────────────────────────────────────────┘
```

The Wazuh agent forwards three streams from the victim: authentication logs,
`auditd` execve records, and file-integrity events. Suricata's `eve.json` is
forwarded through the same agent.

---

## Scenarios

| # | Scenario | MITRE | Primary telemetry |
|---|---|---|---|
| 1 | SSH brute force → successful login | T1110.001, T1078 | sshd, auditd |
| 2 | Rogue local account + sudo group | T1136.001, T1548.003 | auditd, FIM |
| 3 | Web shell dropped and used | T1505.003, T1105 | FIM, nginx, Suricata |
| 4 | Cron persistence | T1053.003 | FIM, auditd |
| 5 | Port scan + service enumeration | T1046, T1595 | Suricata |
| 6 | Benign change closed as false positive | — | FIM, auditd |

Each case has a ticket in `tickets/` with severity, timeline, evidence, containment
and escalation note, plus the runbook used.

---

## Repository layout

```
.
├── README.md
├── SCOPE.md                  # what this lab may and may not touch
├── windows-parity.md         # Windows event IDs ↔ Linux telemetry
├── docs/
│   ├── architecture.md
│   ├── build-log.md          # command history, including failures
│   └── screenshots/
├── lab/
│   ├── wazuh/                # pinned stack setup
│   ├── vm/                   # cloud-init and launch scripts
│   └── suricata/             # config, rules, tuning notes
├── rules/                    # custom Wazuh rules + suppressions
├── runbooks/                 # analyst procedures
└── tickets/                  # incident write-ups
```

---

## Evidence standard

Every ticket must contain:

- severity and the reason for it
- UTC timeline with timestamps from the actual logs
- SHA-256 of any file artifact
- screenshots of the alert, the raw log line, and the ticket
- a containment or escalation decision, stated as an action
- time-to-triage

---

## Scope

See `SCOPE.md`. In short: RFC1918 addresses only, local VM only, no scanning of
external hosts, no real malicious binaries.

## Disclaimer

Independent lab. Not affiliated with any employer. No production or government data
is included; work history is described generically and under NDA.
