# INC-004 Detection Rules

<!-- subtitle: Two rules for root persistence, and the legitimate admin work they also catch -->
<!--meta
id: INC-004
incident: INC-004 — Cron and systemd persistence rules
severity: Critical
-->

These are the two Wazuh rules added for INC-004. Both were loaded in 4.14.7 and tested
against legitimate cron/systemd administration and a live root persistence run on
2026-10-31.

The deployed file is `rules/local_rules.xml`.

---

## 1. Inventory

| ID | Trigger | Level | MITRE |
|---|---|---|---|
| **100129** | FIM: file added/modified under `/etc/cron.d/` | 12 | T1053.003 |
| **100130** | FIM: file added/modified under `/etc/systemd/system/` | 10 | T1543.002 |

---

## 2. The rules

```xml
<group name="local,syscheck,">

  <rule id="100129" level="12">
    <if_sid>550,554</if_sid>
    <match>/etc/cron.d/</match>
    <description>FIM: cron file added or modified (possible persistence)</description>
    <mitre>
      <id>T1053.003</id>
    </mitre>
    <group>syscheck,persistence,</group>
  </rule>

  <rule id="100130" level="10">
    <if_sid>550,554</if_sid>
    <match>/etc/systemd/system/</match>
    <description>FIM: systemd unit or enable-link changed (possible persistence)</description>
    <mitre>
      <id>T1543.002</id>
    </mitre>
    <group>syscheck,persistence,</group>
  </rule>

</group>
```

---

## 3. Rule-by-rule

### 100129 — cron file added or modified

- **Parents:** 550 (modified) and 554 (added).
- **Match:** the `/etc/cron.d/` path substring.
- **Tested:** 23:17:25.115 on `/etc/cron.d/updates`.
- **False positives:** every legitimate cron job. The baseline produced two hits for
  one legitimate file (add and modify).
- **Gap:** user crontabs in `/var/spool/cron/crontabs` are not covered.

### 100130 — systemd unit or enable-link changed

- **Parents:** 550 and 554.
- **Match:** the `/etc/systemd/system/` path substring.
- **Tested:** 23:17:28.122 (`updates.service`), 23:17:28.128 (`updates.timer`),
  23:17:31.309 (`timers.target.wants/updates.timer`).
- **False positive:** every `systemctl enable`, because it creates a symlink under
  `*.wants/`. The baseline produced one hit for enabling cron.
- **Why level 10:** enable events are frequent. The rule cannot distinguish a symlink
  from a new unit body with one `<match>`, so a lower level is the safer default.

---

## 4. Test matrix

| Action | Expected |
|---|---|
| Legit `/etc/cron.d/apt-maintenance` added | **100129** |
| Same file modified | **100129** |
| `systemctl disable cron` | silent (553) |
| `systemctl enable cron` | **100130** on the enable symlink |
| Attack `/etc/cron.d/updates` | **100129** |
| `updates.service` written | **100130** |
| `updates.timer` written | **100130** |
| `systemctl enable --now updates.timer` | **100130** on the enable symlink |
| `tee`, `systemctl`, `id` | 80792 command trail |
| `sudo` writes | 5402 |

Baseline counts: **2× 100129, 1× 100130**. Attack counts: **1× 100129, 3× 100130**.

---

## 5. Coverage gaps

- **User crontabs.** `/var/spool/cron/crontabs` is not monitored. A user-level job is
  invisible to 100129.
- **Package units.** Units in `/lib/systemd/system` are outside the FIM path; only the
  `/etc` overrides and enable links are covered.
- **Deletion.** 100129/100130 use 550/554. A deletion is 553, so removing persistence
  is silent.
- **Symlink vs body.** 100130 cannot distinguish a legit `enable` link from a new unit
  file. Both are level 10.
- **Intent.** Neither rule knows whether a change was approved. Change control is the
  only discriminator.
- **Execution.** Neither rule proves the job or service ran. Audit and the proof file do.

---

## 6. Tuning

### 6.1 Split 100130

Best next step:

- level 12 for a new `.service`/`.timer` **body**;
- level 5 for a `*.wants/` enable link;
- correlate the body + enable + execution for a Critical sequence.

This requires two rules with different matches (one on `.service`, one on `.timer`, or
a path allow-list) and a way to exclude `*.wants/`. Since `<match>` is a substring and
only one match per rule is reliable, use separate rules and test the precedence.

### 6.2 Cover user crontabs

Add FIM/audit for `/var/spool/cron/crontabs` and the `crontab` command. Keep the rule at
level 12 for changes, with a change-ticket check.

### 6.3 Deletion rules

Add `if_sid 553` rules for the same paths. Removing a unit or cron file is
anti-forensics; it should not be silent.

### 6.4 Change-control integration

Match every hit to an approved change, a package transaction, or a configuration
management run. Do not suppress the rule; suppress the *known* deployment ID.

---

## 7. Deployment

```bash
cd "$HOME/wazuh-docker/single-node"
docker compose up -d wazuh.manager
sleep 20

for id in 100129 100130; do
  printf '%s: ' "$id"
  docker exec single-node-wazuh.manager-1 \
    grep -c "id=\"$id\"" /var/ossec/etc/rules/local_rules.xml
done
```

Validate 100129 with a disposable cron file and 100130 with a `systemctl enable` action.
Run the legitimate baseline before any attack so the false positives are recorded.

---

## 8. MITRE ATT&CK

| Technique | ID | Rule |
|---|---|---|
| Scheduled task/job: cron | T1053.003 | 100129 |
| Create or modify system process: systemd service | T1543.002 | 100130 |
| Abuse elevation control: sudo | T1548.003 | context (80792/5402) |
| Valid accounts | T1078 | context (actor) |

---

## 9. Caveats

- Tested on Debian 12, systemd 252, cron 3.0, Wazuh 4.14.7.
- `/etc` must be in FIM realtime.
- A host using another init system needs different coverage.
- The rules detect file change, not execution or authorization.
