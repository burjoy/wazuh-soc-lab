# Build report: Wazuh triage lab

**Status**

Days 0–1 complete. Infrastructure verified end to end. Scenario work not
started yet.
**Date**

30 October 2026

This report is the readable summary. The raw command history, including failures, is in
`build-log.md`. The design is in `architecture.md`.

---

## 1. Purpose

Build a small, reproducible lab that produces the evidence an L1 SOC interviewer asks
about: a real alert, a real log line, a severity call, a containment decision, and a
ticket that someone else could act on.

The target role is SOC Analyst Level 1, monitoring, first-line triage, ticketing,
escalation. The lab is not trying to demonstrate exploitation or detection engineering.

---

## 2. What exists now

```
Host (CachyOS, 12 cores, 7.5 GB RAM)
┌────────────────────────────────────────────────────────────┐
│  Docker                                                     │
│    wazuh.indexer    1 GB heap                               │
│    wazuh.manager    decoders, rules, agent management       │
│    wazuh.dashboard  https://localhost (localhost only)      │
│                                                             │
│  Attacker shell: ssh, curl, nmap                            │
└──────────────┬─────────────────────────────────────────────┘
               │ QEMU user network: host 10.0.2.2, guest 10.0.2.15
               │ forwarded ports 2222: 22, 8080: 80
┌──────────────┴─────────────────────────────────────────────┐
│  Victim VM: Debian 12, 1.5 GB, no swap                     │
│    sshd · nginx · auditd · suricata · wazuh-agent           │
│    auditd: identity, cron.d, webroot, execve rules          │
│    suricata: 8,234 ET Open rules on ens3                    │
└─────────────────────────────────────────────────────────────┘
```

Telemetry reaching the manager:

| Source | Path | Format |
|---|---|---|
| Authentication | journald / `auth.log` | syslog |
| Audit | `/var/log/audit/audit.log` | auditd |
| File integrity | agent `syscheck` | Wazuh FIM events |
| Web | `/var/log/nginx/access.log` | apache |
| Network | `/var/log/suricata/wazuh.json` | JSON, alerts/http/dns only |

`eve.json` is filtered before forwarding. Sending every flow record to the manager
would be a self-inflicted ingestion problem.

---

## 3. What was done

### Day 0: SIEM stack

- Confirmed the existing Wazuh 4.14.7 checkout and existing `single-node_*` volumes.
- Docker became reachable through a socket ACL rather than group membership.
- Dashboard returns `302`, manager API returns `200`. Three containers healthy.
- Bound every published port to `127.0.0.1` (dashboard, indexer API, manager API,
  agent ports, syslog). The upstream compose exposes them on `0.0.0.0`.
- Recorded the known vulnerability-scanner feed error as out of scope. It does not
  affect the stack.

### Day 1: endpoint, sensor, and the first real alerts

- Built a Debian 12 cloud-image VM with cloud-init: `analyst` user, SSH key only,
  nginx, auditd, jq.
- Installed Suricata 7.0.10 from `bookworm-backports`.
- Installed the Wazuh agent 4.14.7 and enrolled it as `001 soc-victim`, Active.
- Loaded audit rules for identity files, `/etc/cron.d`, `/var/www/html`, and execve.
- Added realtime FIM for `/etc` and `/var/www/html`. The stock config only scans every
  12 hours.
- Narrowed Suricata from the full 53k ET set to 8,234 rules covering scan, web and DNS.
- Took snapshot `clean-baseline` after removing the test artefacts.

---

## 4. Decisions

| Decision | Why | Cost if wrong |
|---|---|---|
| Debian 12 instead of Ubuntu 24.04 | Ubuntu cloud mirror delivered 0–370 KB/s. Debian ~1 MB/s, ~350 MB | Suricata is 7.0.10 from backports rather than a distro default |
| VM, not container, for the victim | `auditd` is per-kernel. A container cannot produce per-container execve telemetry | ~1.4 GB RAM (Plan B in the project plan covers container-only) |
| Suricata inside the VM | Correct packet direction, snapshot-able, no host capture quirks | Sensor dies with the endpoint, which is acceptable here |
| 8,234 ET rules, not 53,299 | Full set used 1.1 GB in a 1.5 GB VM and OOM-killed the agent | A scenario outside scan/web/dns needs a rule group added |
| `HOME_NET = 10.0.2.15/32` | With the whole subnet as home, gateway traffic is internal to internal and directional rules never fire | A second victim on the same segment would be misclassified |
| Scenario 5 defaults to outbound scan | QEMU user networking cannot expose arbitrary guest ports | Inbound scan needs the documented tap/bridge upgrade |
| All ports bound to `127.0.0.1` | The lab should not be reachable from the LAN | None. The browser and forwarded ports still work |

---

## 5. Evidence collected so far

These are smoke tests that prove the pipeline, not incident tickets.

| Test | Result |
|---|---|
| 5 invalid SSH users from the host | rule 5710 "Attempt to login using a non-existent user". `srcip`, `srcuser`, MITRE T1110.001 / T1021.004 |
| Successful key login | rule 5715 "authentication success" |
| `sudo tee /etc/cron.d/...` | rule 5402 "Successful sudo to ROOT executed", full command captured |
| File created in `/etc/cron.d` | FIM: 2 alerts (added, deleted) |
| `sqlmap/1.7` user-agent | Suricata: `ET SCAN Sqlmap SQL Injection Scan` |

Indexed alerts: 692 in `wazuh-alerts-*` at the end of Day 1.

What this demonstrates, in role terms:

- agent deployment and enrolment
- onboarding five log sources into a SIEM
- reading a raw log line and matching it to a rule
- MITRE ATT&CK mapping arriving with the alert
- file-integrity monitoring with realtime coverage
- a network IDS producing a signature hit
- troubleshooting a lab that failed twice before it worked

---

## 6. Incidents during the build

These matter more than the successes. They are the material for interview answers.

1. **Docker socket unreachable**  
  User was not in the `docker` group. Resolved via a
   socket ACL (`user:luqman:rw-`). `sg` is not installed on this system. `newgrp -c`
   is the equivalent.
2. **Root-owned TLS cert directory**  
  Left from an earlier `sudo` run. Cert files were
   owned by the container UIDs (1000/999) and correct. The stack was healthy, so it was
   left untouched rather than "fixed" into a broken state.
3. **Ubuntu image download stalled**  
  0–370 KB/s. Switched base image instead of
   waiting hours. Ruling recorded.
4. cloud-init failed with exit 100. Suricata lives in `bookworm-backports`. Apt
   resolved the backports package against stable `libhtp2`. Installed with
   `-t bookworm-backports` explicitly.
5. **Suricata OOM-killed the Wazuh agent**  
  53,299 rules = 1.1 GB RSS, no swap in the
   guest. Trimmed to 8,234 rules at ~80 MB.
6. **ET Open renamed its web rule files**  
  `emerging-web-application-attack.rules` no
   longer exists. The current names use underscores (`emerging-web_specific_apps.rules`).
   The symptom was `Enabled 0 rules`.
7. **Directional rules never fired**  
  `HOME_NET` covered the gateway as well as the
   victim. Narrowed to the victim `/32`.
8. **Duplicate Suricata log block**  
  The Debian `ossec.conf` has two
   `<ossec_config>` sections. A Python `replace()` inserted into both, producing a
   "log file is duplicated" warning and queue pressure.

---

## 7. What is not done

- Scenarios 1–6 and their tickets. Current alerts are smoke tests.
- Runbook for any scenario.
- Custom rule plus a deliberate suppression with rationale.
- Jira board and exported tickets.
- One-page summary for a hiring manager.
- CV and application. This is the highest-value remaining item and does not depend on
  the lab.
- Optional bridge upgrade to make scenario 5 an inbound scan.

---

## 8. Next

1. Scenario 1 (SSH brute force to success) and scenario 2 (rogue account + sudo).
2. Scenario 3 (web shell + FIM + nginx) and scenario 4 (cron persistence).
3. Scenario 5 (scan) and scenario 6 (benign change closed as false positive).
4. Runbook, tuning note, MITRE and Windows parity tables.
5. Publish, then rehearse the walk-through in English.

---

## 9. Reproducing it

```bash
# SIEM
cd lab/wazuh && ./setup.sh

# Victim
cd lab/vm && ./launch.sh
scp -i keys/id_ed25519 -P 2222 provision-agent.sh analyst@127.0.0.1:/tmp/
ssh -i keys/id_ed25519 -p 2222 analyst@127.0.0.1 'sudo bash /tmp/provision-agent.sh'

# Baseline
./snapshot.sh save clean-baseline
```

Credentials: Wazuh dashboard `admin` / `SecretPassword` on `https://localhost`. Local
lab only. Change before exposing anything.

---

## 10. Caveats

- The attacker is the QEMU gateway (`10.0.2.2`). A ticket will show that as the source.
  the README states it plainly rather than inventing a cleaner address.
- Host has 2.4 GB free with the stack and VM running. Close heavy applications during
  a scenario. There is no swap in the guest.
- No employer, agency, or client material is present. The authorised assessment work
  from the day job is described generically and never reproduced here.