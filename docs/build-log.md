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

## 2026-10-30 — VM provisioning scripts

Wrote `lab/vm/launch.sh`, `snapshot.sh`, `provision-agent.sh` and the cloud-init
seed. QEMU user-mode networking keeps the VM unprivileged: the guest reaches the
host at `10.0.2.2`, the host reaches the guest only through forwarded ports
`2222` (ssh) and `8080` (http).

**Ruling:** scenario 5 changes direction — from "host scans victim" to "victim
scans its gateway". QEMU user networking forwards individual ports, so the host
cannot scan the guest's full port range without a privileged tap or bridge.
An outbound scan is the more common L1 alert anyway (internal host doing
reconnaissance), and Suricata still sees it on `eth0`. Cost if wrong: one
scenario has to be re-shot if a tap/bridge is added later.

**Note:** `sg` is not installed on this system; `newgrp docker -c '<command>'` is
the working equivalent once group membership is in place.
