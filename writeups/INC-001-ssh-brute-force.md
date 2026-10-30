# Finding the attack in 400 alerts

### Triaging an SSH brute force in Wazuh, with real noise around it

A lab write-up. Everything here ran on one laptop against a local VM. No production
systems, no client data, no real malware.

---

## TL;DR

At 15:21:47 UTC a password spray against a Debian endpoint began. Twenty guesses
later, the `svc-backup` account was compromised. The attacker added an SSH key and
ran discovery commands. Total time from first failure to persistence: **32 seconds**.

The detection was not the hard part. The hard part was that the SIEM produced **400
alerts in 150 seconds**, and the stock "failures followed by a success" rule fired
on six alerts from routine analyst sessions as well as the attacker. This is the story of
separating the two.

| | |
|---|---|
| **Verdict** | True positive, confirmed compromise |
| **Severity** | High |
| **Entry** | SSH password authentication, weak service-account password |
| **Persistence** | SSH `authorized_keys` added |
| **Privilege escalation** | Attempted, failed (`sudo` required a password) |
| **MITRE** | T1110.001, T1078, T1098.004, T1059.004, T1082, T1033 |

---

## The environment

| Component | Detail |
|---|---|
| SIEM | Wazuh 4.14.7, single-node Docker |
| Endpoint | Debian 12, 1.5 GB VM, Wazuh agent 4.14.7 |
| Telemetry | journald, `auditd` (execve + file watches), FIM on `/etc`, `/home`, `/var/www/html` |
| Network | Suricata 7.0.10, 8,234 ET Open rules (scan/web/DNS) |
| Attacker | `hydra` from the host, 20-password list |
| Time | All timestamps UTC |

One lab artefact matters for the analysis: QEMU user networking makes the attacker
and every legitimate session appear as **10.0.2.2**, the virtual gateway. In a real
estate the attacker's source address would be distinct. That limitation is exactly
what produced the false positives below.

---

## What the noise looked like

While the attack ran, the environment generated normal activity:

- an analyst logging in over SSH every 30 seconds and running `uptime` and
  `systemctl status`
- routine `sudo` calls
- HTTP requests to the local nginx
- full `execve` auditing, which turns every command on the box into an alert

Counts for the incident window (15:21:00–15:23:30):

| Rule | Description | Count |
|---|---|---|
| 80792 | Audit: command executed | 292 |
| 5501 / 5502 | PAM session opened / closed | 27 / 23 |
| 5760 | sshd authentication failed | 20 |
| 40112 | Multiple auth failures followed by a success | 8 |
| 5715 | sshd authentication success | 6 |
| 5763 | sshd brute force | 1 |
| **100120** | **FIM: authorized_keys added or modified** | **1** |

Four hundred alerts. One of them is the compromise. Four of the eight `40112`
alerts are benign.

---

## The timeline

| Time (UTC) | Event |
|---|---|
| 15:21:47 | Legitimate login by `svc-backup` from 10.0.2.2 (baseline activity) |
| 15:21:50 | First failed password for `svc-backup` |
| 15:22:01 | Rule **5763** — sshd brute force |
| 15:22:03 | Rule **40112** fires on an **analyst** login (false positive) |
| 15:22:05 | Rule **40112** fires on another analyst login (false positive) |
| 15:22:21 | `Accepted password for svc-backup` — the successful guess |
| 15:22:21 | Rule **40112** on `svc-backup` |
| 15:22:22 | Rule **100120** — `/home/svc-backup/.ssh/authorized_keys` added |
| 15:22:23 | `id`, `whoami`, `uname -a`, `head`, `sudo -n -l` (failed), `mkdir ~/.ssh`, key write, `curl` |
| 15:22:23 | Two in-flight guesses still arriving (another 5760, another 40112) |
| 15:22:35 onward | Two more `40112` on analyst logins |

The two extra failures after success are worth noticing: `hydra` had parallel
workers in flight. A real attacker would not stop the instant one guess worked
either.

---

## The investigation

### 1. Is this real?

Twenty failures in 31 seconds, all for `svc-backup`, all from 10.0.2.2, followed
immediately by a success on the same account. That is not a mistyped password.

```text
Oct 30 15:21:50 soc-victim sshd[10779]: Failed password for svc-backup from 10.0.2.2 port 49856 ssh2
...
Oct 30 15:22:21 soc-victim sshd[10847]: Accepted password for svc-backup from 10.0.2.2 port 52318 ssh2
```

**True positive.**

### 2. What did the successful session do?

`auditd` had the process trail:

```text
15:22:21Z  bash -c <script>
15:22:21Z  id
15:22:21Z  whoami
15:22:21Z  uname -a
15:22:21Z  head -1
15:22:21Z  sudo -n -l
15:22:21Z  mkdir -p /home/svc-backup/.ssh
15:22:21Z  curl -s -o /dev/null -w outbound_http=%{http_code} http://10.0.2.2:8080/
```

The `bash -c` argument decoded to the full script: discovery, a `sudo` check, the
key append, and an outbound request. The `sudo` attempt failed with "a password is
required", which is a useful fact: **no privilege escalation occurred.**

### 3. Persistence

The FIM alert is the one that matters:

```json
{
  "rule": { "id": "100120", "level": 12,
            "description": "FIM: SSH authorized_keys added or modified (possible persistence)" },
  "syscheck": {
    "path": "/home/svc-backup/.ssh/authorized_keys",
    "mode": "realtime",
    "event": "added",
    "uid_after": "1002",
    "sha256_after": "61954205be034570c75bdd6db67b3fbd3410ac1d4bebb08b65d117667965c5e8"
  }
}
```

An added key file, owned by the compromised account, in realtime. That survives a
password reset, which is why it changes the response: removing the key is not
optional.

### 4. The false positives

Four `40112` alerts were legitimate analyst sessions:

| Time | User | Why benign |
|---|---|---|
| 15:22:03 | analyst | key-based login, known admin, routine command |
| 15:22:05 | analyst | same |
| 15:22:35 | analyst | same |
| 15:23:05 | analyst | same |

They matched because `40112` correlates **any** authentication failure with **any**
success from the same source, and in this lab every session shares the gateway
address. The separation came from three details, not from the rule:

1. **Username** — the failures and the success were both for `svc-backup`.
2. **Authentication method** — the analyst used a key; the attacker used a password.
3. **Timing and volume** — 20 failures in 31 seconds immediately before the success.

This is exactly the kind of judgement an L1 analyst is paid for. The rule gives you a
candidate; the ticket has to prove it.

---

## Severity and response

**High.** A valid account was compromised and persistence was established. It is not
Critical because the account was unprivileged, `sudo` failed, and no lateral
movement was observed. It is not Medium because an attacker with a working key can
return after the password is reset.

Containment, in order:

1. **Isolate the host** (in this lab, snapshot and disconnect; in production, EDR
   network containment).
2. **Disable `svc-backup`** and expire its password.
3. **Remove the unauthorised key** and compare the file against the last known-good
   hash.
4. **Preserve evidence** before changing anything: the FIM record, `auditd` records,
   the `authorized_keys` file and its SHA-256.
5. **Check for reuse** of the same key or account on other hosts.
6. **Review the authentication policy** that allowed this: password auth on a service
   account, no lockout, a password that appeared in a 20-entry list.

Escalation note to L2:

> `svc-backup` was compromised via SSH password brute force at 15:22:21 UTC. The
> account added an SSH key at 15:22:22 (SHA-256 above) and ran discovery commands.
> `sudo` failed. Host isolated, account disabled, key removed. Requesting: scope
> check for the same key fingerprint across the estate, and a review of password
> authentication on service accounts.

---

## Detection engineering

### The custom rule that survived

```xml
<rule id="100120" level="12">
  <if_sid>550,554</if_sid>
  <match>authorized_keys</match>
  <description>FIM: SSH authorized_keys added or modified (possible persistence)</description>
  <mitre>
    <id>T1098.004</id>
    <id>T1078</id>
  </mitre>
  <group>syscheck,persistence,</group>
</rule>
```

Why FIM and not command matching: I first tried to alert on the `auditd` execve
record. Wazuh's audit decoder exposed `a0` and `a1` for the `bash -c` event but
**dropped `a2`**, which is where the command string lives. The raw audit log had it;
the decoded alert did not. FIM gave a stable, high-fidelity signal instead: a path, an
event type, a user, and hashes.

Limitations, stated plainly:

- It matches the file name for any user, so legitimate key rotation will fire it.
- An attacker who writes the file with an editor, or uses a different path spelling,
  still lands in FIM but may not match this rule.
- The right follow-up is an allow-list of expected keys or a baseline of key
  fingerprints per account.

### The rule I did not keep

I wrote a second rule intended to alert when a successful login follows a
brute-force alert, anchored on `5763`. It never fired. Stock rule `40112` matched the
same success event and won the evaluation, because local rules are evaluated after
the stock set and `40112` is a closer match for the success rule.

I also tried `<same_user />` to tie the failure and the success to the same account.
Wazuh compares `srcuser` on the failure (5710/5760) with `dstuser` on the success
(5715), so the fields do not line up.

The honest conclusion: **do not duplicate `40112`; tune it.** Narrow it to sshd
authentication groups, raise the failure threshold, and make the account part of the
condition if the field model allows. A duplicate rule that never fires is worse than
no rule at all, because it creates false confidence.

---

## What I would change next time

| Gap | Fix |
|---|---|
| Password auth enabled on a service account | Key-only, or `nologin` for accounts that never log in |
| No lockout after 20 failures | `pam_faillock`, plus a shorter detection threshold |
| 292 execve alerts in 150 seconds | Audit only the command patterns that matter, or aggregate per session |
| Shared gateway IP hides the attacker | Bridge/tap networking, or a second attacker VM with its own address |
| `40112` is account-blind | Tune it, do not clone it |
| Legitimate key rotation would trip 100120 | Baseline expected fingerprints per account |

---

## MITRE ATT&CK

| Technique | ID | Evidence |
|---|---|---|
| Brute force: password guessing | T1110.001 | 20 × 5760, then 5763 |
| Valid accounts | T1078 | Successful password login |
| Account manipulation: SSH authorized keys | T1098.004 | FIM on `authorized_keys` |
| Unix shell | T1059.004 | `bash -c` with the persistence script |
| System information discovery | T1082 | `uname -a` |
| System owner/user discovery | T1033 | `id`, `whoami` |
| Remote services: SSH | T1021.004 | Session from 10.0.2.2 |

---

## Reproduce it

```bash
# target account and password auth (lab only)
sudo useradd -m -s /bin/bash svc-backup
echo 'svc-backup:Summer2026!' | sudo chpasswd
printf 'PasswordAuthentication yes\n' | sudo tee /etc/ssh/sshd_config.d/00-lab-password.conf
sudo systemctl restart ssh

# brute force
hydra -l svc-backup -P passwords.txt -s 2222 -t 2 -V 127.0.0.1 ssh

# detection is in rules/local_rules.xml; evidence in docs/evidence/
```

---

## Caveats

- The attack came from the virtual gateway because of QEMU user networking. That is
  why source-IP correlation produced false positives; a real network would not have
  this exact problem.
- `svc-backup` was created for the exercise, with password authentication
  deliberately enabled. That is the misconfiguration being demonstrated.
- No real malware, external infrastructure, or employer data was involved.

---

*Lab repository: `soc-l1-lab`. Evidence and the rule are included. The write-up is
published for portfolio and discussion purposes.*
