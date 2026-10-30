# Suricata

Runs **inside the victim VM**, on `ens3` (predictable interface name on the Debian
cloud image). Network telemetry only — no inline IPS, no blocking.

## Configuration

- `HOME_NET: "[10.0.2.15/32]"` — the victim only. If the whole `10.0.2.0/24` is
  home, traffic from the QEMU gateway is classified internal→internal and the
  directional ET rules never match.
- `EXTERNAL_NET: "!$HOME_NET"`
- `interface: ens3`

## Rule set

ET Open, narrowed by file:

`/etc/suricata/disable.conf`

```
re:.*
```

`/etc/suricata/enable.conf`

```
group:emerging-scan.rules
group:emerging-web-server.rules
group:emerging-web_specific_apps.rules
group:emerging-web_client.rules
group:emerging-dns.rules
```

Result: ~8,200 active rules, ~80–150 MB RSS.

**Do not enable the full 53k set on a 1.5 GB VM.** It uses ~1.1 GB, leaves no
headroom, and the OOM killer takes the Wazuh agent with it. This happened once;
see `docs/build-log.md`.

Rule file names change between ET Open releases. If `suricata-update` reports
`Enabled 0 rules`, list the tarball and check the names:

```bash
sudo tar tzf /var/lib/suricata/update/cache/*emerging.rules.tar.gz \
  | grep -E 'scan|web|dns'
```

## Logging

`eve.json` is filtered to `alert`, `http`, `dns` by
`/usr/local/bin/suricata-wazuh-filter.sh`, a systemd unit that appends to
`/var/log/suricata/wazuh.json`. Forwarding raw `eve.json` would send every flow
record to the manager.

The agent forwards the filtered file:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/wazuh.json</location>
</localfile>
```

## Verification

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml -v
sudo systemctl status suricata
sudo grep -c '^alert' /var/lib/suricata/rules/suricata.rules
sudo jq -r 'select(.event_type=="alert") | .alert.signature' \
  /var/log/suricata/wazuh.json | tail
```

Proven triggers used during the build:

- `sqlmap/1.7` user-agent against nginx → `ET SCAN Sqlmap SQL Injection Scan`
- DNS NXDOMAIN lookups → `ET DNS Standard query response, Name Error`

## Scan scenario direction

QEMU user networking forwards individual ports only. An inbound port scan of the
guest is not possible without the tap/bridge upgrade in `lab/vm/README.md`. The
default scenario is therefore an **outbound** scan from the victim against
`10.0.2.2`; Suricata sees it on `ens3`. Note that many ET SCAN rules are written
`$EXTERNAL_NET -> $HOME_NET`, so an outbound scan may not produce a signature —
which is why the bridge upgrade is the better version of this scenario.
