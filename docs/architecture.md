# Architecture

## Components

| Component | Role | Where |
|---|---|---|
| `wazuh-manager` | Alert decoding, rule matching, agent management | Docker, host |
| `wazuh-indexer` | Event storage, 1 GB heap | Docker, host |
| `wazuh-dashboard` | Analyst UI on `https://localhost` | Docker, host |
| Victim VM | Endpoint under observation | QEMU/KVM, 1.5 GB |
| `wazuh-agent` | Forwards auth, auditd, FIM, Suricata events | Victim VM |
| Suricata | Network IDS on the VM's `ens3` | Victim VM |

## Data flow

```
attack (host) ──► victim eth0 ──► sshd / nginx / auditd / FIM
                        │
                        └──► suricata ──► /var/log/suricata/eve.json
                                              │
wazuh-agent ── reads auth.log, audit.log, eve.json, syscheck
      │
      └──► manager :1514 ──► indexer ──► dashboard
```

## Network

- QEMU user-mode networking, no bridge, no tap, no route to the LAN.
- Guest sees the host as `10.0.2.2`; the host reaches the guest through forwarded
  ports (`127.0.0.1:2222` → `22`, `127.0.0.1:8080` → `80`).
- The manager listens on `1514/1515`, published by Docker on the host.

## Log sources

| Source | Path | Format |
|---|---|---|
| Authentication | `/var/log/auth.log` | syslog |
| Audit | `/var/log/audit/audit.log` | auditd |
| Web | `/var/log/nginx/access.log` | combined |
| File integrity | agent `syscheck` | JSON |
| Network | `/var/log/suricata/wazuh.json` | JSON, alerts + http + dns only (filtered from `eve.json`) |

## Constraints

- 1.5 GB for the VM, ~3 GB for the Wazuh stack; browser closed during attack windows.
- Suricata runs ~8,200 ET Open rules (scan, web, dns), which keeps it under ~150 MB.
  The full 53k set needs ~1.1 GB and OOM-kills the agent in this VM.
- Wazuh version pinned at 4.14.7. No upgrades during the build.
- `eve.json` is filtered to `alert`, `http`, `dns`. Forwarding flow events would
  flood the manager.
