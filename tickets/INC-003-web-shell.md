# INC-003: Web shell dropped and executed

| Field | Value |
|---|---|
| Severity | High |
| Status | Closed, escalated |
| Source | 100128 (FIM), 100127 (web access), audit 80790/80792 |
| Host | soc-victim (Debian 12) |
| Path | `/var/www/html/updates2.php` (clean run). `updates.php` (first run) |
| SHA-256 | `50e626c8e31a460af48991b83dfd98c0b24f3a9d9e6eb906e961e77a2aecf15d` |
| Execution context | `www-data` (uid 33) via PHP-FPM |
| Detected (UTC) | 2026-10-31 22:12:20 |
| Contained (UTC) | 2026-10-31 22:13 |
| Time to triage | ~4 minutes (exercise conditions) |

## What fired

1. 100128 (custom, level 12), `FIM: PHP file added under a monitored path`
   at 22:12:20.956, `syscheck.path=/var/www/html/updates2.php`.
2. 100127 (custom, level 12), `Web: command parameter in a PHP request`
   at 22:12:25 and 22:12:25 (two requests), plus the sqlmap request at 22:12:28.
3. 80790, `Audit: Created: /var/www/html/updates2.php` at 22:12:21.160.
4. 80792, `cp /tmp/updates2.php /var/www/html/updates2.php`, then
   `sh -c id`, `id`, `sh -c uname -a`, `uname -a` at 22:12:24–22:12:28.
5. 5402, `sudo cp /tmp/updates2.php /var/www/html/updates2.php` by `analyst`.

The first run, before 100127/100128 existed, produced no stock alert for the
successful `cmd=id` request. It did produce FIM 554, audit 80790, and a Suricata
`ET SCAN Sqlmap SQL Injection Scan` on the sqlmap user-agent. The gap was the
successful web-shell request itself.

## Timeline

| Time (UTC) | Event |
|---|---|
| 22:07:18 | First shell `updates.php` copied into the webroot (FIM 554) |
| 22:07:19 | Audit 80790 created file. Sudo command recorded |
| 22:07:51 | Suricata `ET SCAN Sqlmap SQL Injection Scan` |
| 22:08:42 | First successful execution as `www-data` (PHP-FPM configured) |
| 22:12:20 | Clean run: `updates2.php` added. 100128 fires |
| 22:12:21 | Audit 80790 created file |
| 22:12:24 | `GET /updates2.php?cmd=id` to `uid=33(www-data)` |
| 22:12:25 | 100127 fires on the request |
| 22:12:28 | sqlmap user-agent request to 100127 again |
| 22:13 | Files removed. Evidence preserved |

## Investigation

- The file was owned by `root:root` (copied with `sudo`) and was world-readable.
- PHP-FPM executed it as `www-data`, not root. The command output confirms:
  `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.
- Commands executed through the shell: `id`, `uname -a`. No file download, no
  privilege escalation, no new account, no cron/systemd persistence.
- The webroot contained only the original `index.nginx-debian.html` after cleanup.
- Nginx access logs show repeated `200` responses to `.php?cmd=` requests from
  `10.0.2.2`, plus one request from `127.0.0.1` (the host's guest-side test).
- The source address is the QEMU gateway, as in the other lab scenarios.

## Severity rationale

**High**

Remote code execution as the web user, with command output returned over
HTTP. It is not Critical because the process was `www-data`, not root, and no
privilege escalation or persistence was observed. It is not Medium because a web
shell is an interactive foothold and the webroot was writable by the deployment path.

## Action taken

1. Removed `updates.php` and `updates2.php` from `/var/www/html`.
2. Preserved the file hash, FIM alert, nginx log lines, and audit commands.
3. Verified no other PHP files remained in the webroot.
4. Reviewed the PHP/nginx configuration and confirmed execution was as `www-data`.
5. Escalated for a webroot write-permission and deployment review.

## Detection gap and rules added

| Gap | Rule |
|---|---|
| No stock alert for a successful `.php?cmd=` request | 100127 (level 12) |
| FIM reported the file but not as a web-shell risk | 100128 (level 12) |

```xml
<rule id="100127" level="12">
  <if_sid>31100</if_sid>
  <match>.php?cmd=</match>
  <description>Web: command parameter in a PHP request (possible web shell)</description>
  <mitre><id>T1505.003</id><id>T1059.004</id></mitre>
  <group>web,attack,</group>
</rule>

<rule id="100128" level="12">
  <if_sid>550,554</if_sid>
  <match>.php</match>
  <description>FIM: PHP file added under a monitored path (possible web shell)</description>
  <mitre><id>T1505.003</id></mitre>
  <group>syscheck,web,persistence,</group>
</rule>
```

Limitations, stated plainly:

- 100127 matches the literal `.php?cmd=`. It misses `?foo=1&cmd=` and other
  parameter orders. It can false-positive on a legitimate PHP application that uses a
  `cmd` parameter first.
- 100128 matches any `.php` file added in a monitored path, not only the webroot.
  Legitimate PHP deployments will fire it and should be matched to a change ticket.

## Recommendations

| # | Action |
|---|---|
| 1 | Make the webroot read-only to the web user. Deploy through a pipeline |
| 2 | Disable PHP execution in directories that do not need it |
| 3 | Set `disable_functions` (`system`, `exec`, `shell_exec`, `passthru`, `popen`) |
| 4 | Add `open_basedir` for the application |
| 5 | Put a WAF or reverse proxy in front of the app |
| 6 | Alert on any new `.php` file and any `.php?cmd=` request |
| 7 | Review file ownership and write permissions on `/var/www/html` |
| 8 | Restrict outbound traffic from the web tier |

## MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| Server software component: web shell | T1505.003 | `updates2.php` with `system($_GET['cmd'])` |
| Unix shell | T1059.004 | `sh -c id`, `sh -c uname -a` |
| System information discovery | T1082 | `uname -a` |
| System owner/user discovery | T1033 | `id` |

## Evidence

- `docs/evidence/INC-003-alerts.json`, 67 alerts in the clean-run window
- `docs/evidence/INC-003-web.log`, nginx access lines for the shell requests
- `docs/evidence/INC-003-commands.txt`, decoded audit commands
- `writeups/INC-003-web-shell.md`, narrative
- `rules/inc-003-rules.md`, rule rationale and test matrix
