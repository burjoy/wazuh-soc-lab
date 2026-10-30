# Build log

Chronological record of what was actually run, including what failed. Newest
entries at the bottom.

---

## 2026-10-30 — Pre-flight

Checked the machine and the existing Wazuh checkout.

```
$ uname -srm
Linux 7.2.2-1-cachyos x86_64

$ nproc && free -h && df -h /
12
Mem: 7.5Gi total, 3.2Gi available
/dev/nvme0n1p2  477G  56G avail (89% used)

$ docker --version
Docker version 29.7.2

$ systemctl is-active docker
active        # started manually before this session

$ ls /home/luqman/wazuh-docker/single-node
docker-compose.yml  config/  ...
```

Findings:

- Existing `wazuh-docker` checkout at **4.14.7**, upstream remote intact.
- Indexer heap already capped: `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g`.
- `single-node/config/wazuh_indexer_ssl_certs` is `root:root 500` — left over from a
  previous run under `sudo`. Needs ownership fixed before compose can read it.
- Current user is **not** in the `docker` group; the daemon socket is unreachable
  from this shell.

## 2026-10-30 — Repository scaffold

Created the repo, README, scope statement, Windows parity table and directory
layout. No lab components started yet.

**Blocked on:** `docker` group membership and ownership of the TLS cert directory.
