# Suricata

Runs **inside the victim VM**, on `eth0`. Network telemetry only — no inline IPS,
no blocking.

## Configuration

- `HOME_NET: "[10.0.2.0/24]"` (QEMU user network)
- `EXTERNAL_NET: "!$HOME_NET"`
- `interface: eth0`

## Rule categories

Enable only these to keep noise proportional to the lab:

- `scan`
- `web-application-attack`
- `web-server`
- `dns`

`suricata-update` pulls ET Open. Do not enable every category; suppressing
thousands of irrelevant alerts is not the skill being demonstrated.

## Logging

`eve-log` emits **only** `alert`, `http`, and `dns`. Flow events are excluded on
purpose — forwarding them would flood the manager and is a real ingestion-cost
problem, noted in the write-up.

The agent forwards the file:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```

## Verification

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v   # config test
sudo tail -f /var/log/suricata/eve.json | jq -c 'select(.event_type=="alert")'
```

## Scan scenario direction

QEMU user networking forwards individual ports only, so the host cannot scan the
guest's full port range. The scan scenario is therefore **outbound**: `nmap` runs
inside the victim against the gateway `10.0.2.2`, which is the more common L1 alert
anyway — an internal host performing reconnaissance, possibly compromised.

Suricata still sees the traffic on `eth0`; the ET `scan` rules fire on the source.
Triage asks whether it is an authorised scanner, a misconfigured asset, or malware
doing discovery.
