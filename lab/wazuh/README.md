# Wazuh stack

Pinned at 4.14.7 (`v4.14.7` tag of `wazuh/wazuh-docker`).

## Start

```bash
./setup.sh
```

Expected: containers `wazuh.indexer`, `wazuh.manager`, `wazuh.dashboard` running.
dashboard answering on `https://localhost`.

## Default credentials

The upstream single-node compose ships `admin` / `SecretPassword`. This is a local
lab only. If the dashboard is ever exposed beyond `localhost`, change it first.

## Checks

```bash
docker compose ps
curl -ks https://localhost -o /dev/null -w '%{http_code}\n'   # expect 200
docker compose logs -f wazuh.manager
```

## Notes

- Indexer heap is capped at 1 GB. Do not raise it. The host has 7.5 GB total.
- Certificate generation writes to `single-node/config/wazuh_indexer_ssl_certs`.
  If that directory is root-owned from an earlier run, fix ownership before
  starting, or run compose as the same user that created it.
