# The 200 that nobody alerts on

### Dropping and using a web shell, and finding the gap between "file added" and "command executed"

A lab write-up. Local VM, synthetic shell, no production data.

---

## Summary

At 22:12:20 UTC, a PHP file appeared in the nginx webroot. One second later, auditd
recorded its creation. Four seconds after that, an HTTP request returned
`uid=33(www-data)`.

Wazuh caught the drop:

- 100128, FIM: PHP file added under a monitored path
- 80790, Audit: Created `/var/www/html/updates2.php`
- 80792, `cp /tmp/updates2.php /var/www/html/updates2.php`
- 5402, `sudo cp` by the administrator account

It did not catch the use. A normal `200` response to
`/updates2.php?cmd=id` produced no stock alert. The web ruleset alerts on 4xx/5xx
errors and on known attack user-agents. A successful command execution through a
custom PHP file is just a 200.

Two custom rules close the gap:

- 100127, a `.php?cmd=` request
- 100128, a `.php` file added under a monitored path

---

## Setup

| Component | Detail |
|---|---|
| Web server | nginx 1.22.1 |
| PHP | PHP-FPM 8.2 |
| SIEM | Wazuh 4.14.7 |
| Endpoint | Debian 12 VM |
| FIM | realtime on `/var/www/html` |
| Audit | execve (`audit-wazuh-c`) and file watches |
| Attacker | host shell, HTTP over the forwarded port |

The first attempt served the PHP source because PHP was not configured. That is a
useful reminder that "web shell" is a property of the deployment, not just the file.
After installing `php-fpm` and adding the standard location block, the same file
executed as `www-data`.

---

## What the first run looked like

The shell was copied into the webroot at 22:07:18:

```bash
sudo cp /tmp/updates.php /var/www/html/updates.php
```

Wazuh produced:

| Rule | Description | Time |
|---|---|---|
| 554 | File added | 22:07:18.951 |
| 80790 | Audit: Created `/var/www/html/updates.php` | 22:07:19.105 |
| 80792 | `cp` | 22:07:19.103 |
| 5402 | `sudo cp ...` | 22:07:19.801 |

When the shell was requested with `?cmd=id`, the only web alert was:

```text
31101  Web server 400 error code
```

,  and that was for an unrelated `/does-not-exist` request. The successful `200` on the
shell produced nothing.

Suricata did fire `ET SCAN Sqlmap SQL Injection Scan` when the request used a
`sqlmap/1.7` user-agent. That is a useful signal, but it detects the tool, not the
shell. A plain `curl` request would have been invisible.

---

## The rules

### 100128: FIM on PHP files

```xml
<rule id="100128" level="12">
  <if_sid>550,554</if_sid>
  <match>.php</match>
  <description>FIM: PHP file added under a monitored path (possible web shell)</description>
  <mitre>
    <id>T1505.003</id>
  </mitre>
  <group>syscheck,web,persistence,</group>
</rule>
```

It fires on the FIM "file added" event for any `.php` file in a monitored path. It is
deliberately broad: a legitimate deployment also fires it, and the ticket should ask
whether the change was approved.

### 100127: a `.php?cmd=` request

```xml
<rule id="100127" level="12">
  <if_sid>31100</if_sid>
  <match>.php?cmd=</match>
  <description>Web: command parameter in a PHP request (possible web shell)</description>
  <mitre>
    <id>T1505.003</id>
    <id>T1059.004</id>
  </mitre>
  <group>web,attack,</group>
</rule>
```

The parent is stock rule 31100, the level-0 grouping rule for access logs. The
match is a literal `.php?cmd=`.

Two implementation lessons came out of this:

- **Wazuh uses one `<match>` per rule**  
  Adding `<match>.php</match>` and
  `<match>cmd=</match>` did not AND them. The rule did not fire. A single literal is
  the reliable form.
- **OS_Regex was not usable here**  
  `\.php.*cmd=`, `authorized_keys[^.]`, and similar
  patterns did not match the log. The literal substring did.

Limitations:

- `?foo=1&cmd=id` does not match. The parameter must be first.
- A legitimate PHP application using a first-position `cmd` parameter will fire it.
- The rule detects a naming pattern, not malicious intent.

---

## Timeline, clean run

| Time (UTC) | Event |
|---|---|
| 22:12:20.956 | 100128, `updates2.php` added |
| 22:12:21.160 | 80790, audit created file |
| 22:12:24 | `GET /updates2.php?cmd=id` to `uid=33(www-data)` |
| 22:12:25.031 | 100127, first request |
| 22:12:25.031 | 100127, second request (`uname -a`) |
| 22:12:28 | sqlmap user-agent request to 100127 |
| 22:13 | Files removed, evidence preserved |

---

## Triage

1. What is the file? Path, hash, owner, size, and whether it matches a deployment.
2. What did it do? Audit execve under the web user: `id`, `uname`, `curl`, etc.
3. What context? `www-data` is not root. Check for privilege escalation and
   outbound connections.
4. Is it still there? Check the webroot for other `.php` files and recent changes.
5. Was it deployed? Compare against the change pipeline. A legitimate deploy is a
   false positive for 100128, not for 100127.
6. **Contain**  
  Remove the file, preserve the hash and logs, verify no second shell.

The response order matters: hash the file before deleting it. A shell is evidence.

---

## Lessons

- **FIM tells you a file appeared. It does not tell you it was used**  
  Pair file
  monitoring with an access-layer rule.
- **A 200 is not a benign event**  
  Stock web rules are biased toward errors and known
  attack tools. Custom application behaviour needs custom rules.
- One `<match>` per rule is a Wazuh implementation detail worth knowing before
  writing a compound condition.
- **The webroot is a write target**  
  If the deployment path can write PHP, the web
  user can execute it. Read-only deployment and disabled functions are the controls.

---

## Reproduce it

```bash
# prerequisites: nginx + php-fpm, FIM realtime on /var/www/html
sudo cp /tmp/updates.php /var/www/html/updates.php
curl 'http://127.0.0.1:8080/updates.php?cmd=id'

# expected detections
#   100128  PHP file added
#   80790   audit created file
#   80792   cp
#   100127  .php?cmd= request
#   5402    sudo cp

sudo rm -f /var/www/html/updates.php
```

---

## Caveats

- The shell is a three-line test file. No real malware or external infrastructure.
- The source address is the QEMU gateway for every session.
- PHP-FPM was installed for the exercise. A production host's configuration will
  differ.
- 100127 is intentionally narrow and will miss parameter orders other than
  `.php?cmd=`.