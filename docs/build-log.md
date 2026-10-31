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

## 2026-10-30 — Day 0: stack verified

Docker became reachable through a socket ACL (`user:luqman:rw-` on
`/var/run/docker.sock`), so group membership was not needed after all.

```
$ docker compose ps
single-node-wazuh.dashboard-1   running   Up 27 minutes
single-node-wazuh.indexer-1     running   Up 27 minutes
single-node-wazuh.manager-1     running   Up 27 minutes

$ curl -ks -o /dev/null -w '%{http_code}' https://localhost
302

$ curl -ks -u 'wazuh-wui:…' -o /dev/null -w '%{http_code}' \
    https://localhost:55000/security/user/authenticate
200
```

The stack had already been started when the socket was fixed; existing
`single-node_*` volumes from the September run were reused rather than wiped.
Non-destructive choice: if indexer state interferes with the lab, rebuild the
volumes then.

Notes:

- `config/wazuh_indexer_ssl_certs` is `root:root 400`. Certificate files inside are
  owned by uid 1000/999 with mode 400, which is what the containers expect. A
  `chmod` from a root container did not change the directory mode; left as-is
  because the stack is healthy. Host-side `ls` of that directory fails.
- Manager logs a vulnerability-scanner feed error:
  `[json.exception.out_of_range.403] key 'other' not found`. Upstream feed schema
  problem, not a stack failure. Vulnerability detection is out of scope for this
  lab; noted, not fixed.
- 3.2 GB RAM available, with two unrelated containers (`php2shell-*`) running.
  They are not part of this lab and were left alone.

## 2026-10-30 — Port bindings tightened

The upstream compose publishes the dashboard, indexer API, manager API and agent
ports on `0.0.0.0`. Changed all of them to bind `127.0.0.1` only, consistent with
`SCOPE.md`. Original file kept as `docker-compose.yml.bak`.

## 2026-10-30 — Base image switched to Debian 12

**Ruling:** Ubuntu 24.04 → Debian 12 genericcloud. The Ubuntu cloud-image mirror
was delivering 0–370 KB/s, which put a ~600 MB download at hours; the Debian
image is ~350 MB at ~1 MB/s. Wazuh publishes agent packages for Debian 12, and
the scenario set is distro-agnostic. Cost if wrong: Suricata is 6.0.x rather than
7.x, so a few rule/category names may differ; noted when the sensor is configured.



## 2026-10-30 — Day 1: victim VM, agent, sensor

Base image: Debian 12 genericcloud, ~350 MB at ~1 MB/s. Overlay disk 20 GB thin.
QEMU user networking; guest `ens3` = `10.0.2.15`, host = `10.0.2.2`, forwarded
ports `2222` (ssh) and `8080` (http). No sudo needed to run the VM.

```
$ cloud-init status --long
status: error
detail: package-update-upgrade-install ... apt-get install nginx auditd suricata jq ...
Exit code: 100
```

Cause: `suricata` only exists in `bookworm-backports`, and apt will not cross
suites on its own — it tried to resolve the backports suricata against the stable
`libhtp2`. Installed explicitly:

```
$ sudo apt-get install -y -t bookworm-backports suricata suricata-update
$ suricata --build-info | head -1
This is Suricata version 7.0.10 RELEASE
```

Wazuh agent 4.14.7 installed from `packages.wazuh.com/4.x/apt`, enrolled as agent
`001` (`soc-victim`), status **Active**. auditd rules loaded (identity, cron.d,
webroot, execve).

### Suricata sizing

First attempt used the full ET Open set: 53,299 active rules, **1.1 GB RSS** in a
1.5 GB VM with no swap. The OOM killer took the Wazuh agent; `systemctl` showed
the unit inactive while the processes had been running.

Narrowed by file with `disable.conf` (`re:.*`) plus `enable.conf`:

```
group:emerging-scan.rules
group:emerging-web-server.rules
group:emerging-web_specific_apps.rules
group:emerging-web_client.rules
group:emerging-dns.rules
```

8,234 active rules, ~80 MB RSS, 900 MB free in the guest.

**Ruling:** narrow rule set over full ET Open — the lab needs scan, web and DNS
coverage, not malware/trojan signatures. Cost if wrong: a scenario needing a
category outside this set has to add a group and restart Suricata.

**Ruling:** `HOME_NET` is the victim only (`10.0.2.15/32`), not `10.0.2.0/24`.
With the subnet as home, traffic from the QEMU gateway is internal→internal and
the directional ET rules never fire. Cost if wrong: a second victim on the same
segment would be misclassified as external; there is only one.

### Other fixes

- ET Open renamed its web rule files. `emerging-web-application-attack.rules`
  does not exist any more; the current names are `emerging-web_server.rules`,
  `emerging-web_specific_apps.rules` and `emerging-web_client.rules`. The first
  update reported `Enabled 0 rules` for that group, which is how it was caught.
- The agent config ended up with the Suricata `<localfile>` block twice, because
  the Debian `ossec.conf` contains two `<ossec_config>` sections and the Python
  insert replaced both closing tags. Removed one; the `log file is duplicated`
  warning stopped.
- Added realtime FIM for `/etc` and `/var/www/html`. The stock config has a 12-hour
  frequency, which is useless for scenario work.
- `suricata-update` writes 69,264 lines to `suricata.rules`; disabled rules are
  commented out with `# `. `grep -c '^alert'` is the reliable active-rule count.

### Evidence that the pipeline works

| Event | Rule | Detail |
|---|---|---|
| Invalid SSH user ×5 | 5710 | `srcip=10.0.2.2`, `srcuser=baduserN`, MITRE T1110.001 |
| Successful SSH login | 5715 | `analyst` from `10.0.2.2` |
| sudo to root | 5402 | command `/usr/bin/tee /etc/cron.d/soc-lab-test` |
| File created in `/etc/cron.d` | FIM | 2 alerts for `soc-lab-test` (added, then deleted) |
| sqlmap user-agent | Suricata | `ET SCAN Sqlmap SQL Injection Scan` |

Indexer count after the tests: `wazuh-alerts-*` → **675** documents.

Snapshot `clean-baseline` taken after removing the test cron file:

```
$ qemu-img info disk.qcow2   # (monitor: info snapshots)
clean-baseline   1.37 GiB
```

Host memory at the end of Day 1: 1.6 GB available with the Wazuh stack, the VM,
and two unrelated `php2shell-*` containers running. Tight but stable.

## 2026-10-30 — Dashboard reachability from the browser

`localhost` resolves to `::1` before `127.0.0.1`, and the dashboard was published on
IPv4 only, so the browser's first connection attempt was refused. Added a second
mapping:

```yaml
- 127.0.0.1:443:5601
- "[::1]:443:5601"
```

Both families now return `302`, and the login page returns `200` with title
`Wazuh`.

The remaining browser warning is the certificate, not the network: the upstream
dashboard cert is `CN=wazuh.dashboard` with `SAN DNS:wazuh.dashboard` only. There is
no `localhost` or `127.0.0.1` SAN, so Chrome reports
`ERR_CERT_COMMON_NAME_INVALID`. Expected for a self-signed lab; bypass once via
Advanced → Proceed.

## 2026-10-30 — INC-001 scenario run

Goal: one coherent incident, with legitimate activity mixed in, so the detection
has to be separated from noise.

### First attempt (15:12 UTC) — failed evidence

- The brute force targeted a **valid** account, `svc-backup`, so sshd produced
  `5760` (authentication failed), not `5710` (non-existent user). The custom
  correlation rule was keyed to `5710` and never fired.
- `auditd` alerts were absent entirely. Wazuh's audit rules use a CDB list
  (`/var/ossec/etc/lists/audit-keys`) and only recognise the keys
  `audit-wazuh-w`, `audit-wazuh-r`, `audit-wazuh-a`, `audit-wazuh-x`,
  `audit-wazuh-c`. The lab had been using descriptive keys (`identity`, `exec`,
  `persistence`, `webroot`), so every event was decoded but no rule matched.
- The `crontab` binary is not installed in the Debian cloud image, so the intended
  cron persistence failed. The SSH-key persistence still worked.

### Fixes before the second attempt

- audit rules rewritten to `audit-wazuh-w` for writable files and `audit-wazuh-c`
  for execve.
- `<same_user />` tested and rejected: Wazuh compares `srcuser` on 5760 with
  `dstuser` on 5715 and does not bridge them.
- Correlation rule keyed to `5763` was also rejected: stock `40112` matches the
  success event first, so the local sibling never fires. Recorded in
  `rules/tuning-notes.md`.
- The single-file bind mount for `local_rules.xml` stopped reflecting edits when the
  editor replaced the inode. Switched to mounting the whole `rules/` directory.
- Custom rule **100120** written against FIM instead: `authorized_keys` added or
  modified, level 12. Validated by writing the file and observing the alert.

### Second attempt (15:21–15:23 UTC) — clean evidence

- 15:21:47 legitimate `svc-backup` login (baseline).
- 15:21:50–15:22:19: 20 failed passwords.
- 15:22:01: **5763** brute force.
- 15:22:21: successful password login for `svc-backup`; **40112**.
- 15:22:22: **100120**, `/home/svc-backup/.ssh/authorized_keys` added,
  SHA-256 `61954205be034570c75bdd6db67b3fbd3410ac1d4bebb08b65d117667965c5e8`.
- 15:22:23: audit trail of `id`, `whoami`, `uname -a`, `head`, `sudo -n -l`
  (failed), `mkdir`, key write, `curl`.
- Four additional **40112** alerts fired on legitimate `analyst` logins in the same
  window. They share the QEMU gateway source `10.0.2.2`, which is the lab's
  source-attribution limitation.

Window totals: 400 alerts in 150 seconds; 292 were audit command events, 20 were
authentication failures, 8 were 40112, 1 was 100120.

Evidence written to `docs/evidence/`; narrative in
`writeups/INC-001-ssh-brute-force.md`; ticket in
`tickets/INC-001-ssh-brute-force.md`.

## 2026-10-31 — INC-002 scenario run

Scenario: a local account created and added to the `sudo` group, with routine admin
activity around it.

### Detection

The first account (`svc-support`) was used to confirm which rules fire. Stock output:

- **5902** new user, level 8, `dstuser=svc-support`, uid 1003;
- **5901** new group, level 8;
- FIM **550** on `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/gshadow`;
- audit **80792** `useradd`, `chpasswd`, `usermod`, and **80781** write access to
  `/etc/group`.

Nothing named the privilege assignment. The audit record for `usermod` did contain the
full argument vector (`a1=-aG`, `a2=sudo`, `a3=svc-support`), unlike the earlier
`bash -c` event where `a2` was dropped. Rule **100121** was written against
`audit.exe=/usr/sbin/usermod` and `audit.execve.a2=sudo`.

### Clean run

Removed `svc-support`, then created `svc-ops` in a fresh window:

- 04:30:46 `useradd -m -s /bin/bash svc-ops`, `chpasswd`;
- 04:30:47 `usermod -aG sudo svc-ops`;
- 04:30:48 **100121** (level 12) names `svc-ops`;
- 04:30:48 **5901/5902** (level 8);
- FIM 550 on the identity files.

Window total: 237 alerts, dominated by audit command and FIM events.

Cleanup at 04:32:07: removed from `sudo`, account deleted, home removed. Group membership
returned to `analyst,debian`.

Evidence: `docs/evidence/INC-002-alerts.json`, `INC-002-account.log`,
`INC-002-account-commands.txt`, `INC-002-membership.txt`.
