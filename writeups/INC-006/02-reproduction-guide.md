# Reproduction Guide: INC-006 Lab

<!-- subtitle: Creating an approved change, tripping the rules, and closing the case with evidence -->
<!--meta
id: INC-006
incident: INC-006, Authorized change triage
severity: None (authorized change)
-->

This guide reproduces the authorized-change triage on the existing lab. It assumes the
Wazuh stack, the Debian endpoint, and rules 100129/100130 from INC-004 are running.

**Time**

15–20 minutes.
**Result**

Four persistence alerts, a matching change record, a written closure, and a
rollback path.

---

## 1. Prerequisites

| Requirement | Check |
|---|---|
| Wazuh stack | `docker compose ps` |
| Agent active | `agent_control -l` shows `001 soc-victim Active` |
| Rules 100129/100130 | `grep -c` in the container |
| FIM realtime on `/etc` | `grep -n 'realtime.*etc'` |
| Admin sudo | `analyst` can run `sudo -n true` |

```bash
export LAB="$HOME/Documents/Eterna/soc-l1-lab"
export VMKEY="$LAB/lab/vm/keys/id_ed25519"
export VM="analyst@127.0.0.1"
export VMPORT=2222
```

---

## 2. Part A: Build the change package

Create the files locally, compute hashes, and write the change record before
deploying.

```bash
mkdir -p /tmp/inc006
cat > /tmp/inc006/log-maintenance <<'EOF'
# Nightly cleanup of rotated logs older than 7 days
15 2 * * * root /usr/bin/find /var/log -type f -name '*.gz' -mtime +7 -delete
EOF

cat > /tmp/inc006/logrotate-check.service <<'EOF'
[Unit]
Description=Logrotate health check

[Service]
Type=oneshot
ExecStart=/usr/bin/true
EOF

cat > /tmp/inc006/logrotate-check.timer <<'EOF'
[Unit]
Description=Daily logrotate health check

[Timer]
OnCalendar=daily
Persistent=true
Unit=logrotate-check.service

[Install]
WantedBy=timers.target
EOF

sha256sum /tmp/inc006/log-maintenance \
          /tmp/inc006/logrotate-check.service \
          /tmp/inc006/logrotate-check.timer
```

Write the change record with the hashes, the approver, the window, and the rollback.
A template is in `04-change-setup.md`.

---

## 3. Part B: Deploy

```bash
scp -q -i "$VMKEY" -P "$VMPORT" \
  /tmp/inc006/CHG-2026-1101-01.md \
  /tmp/inc006/log-maintenance \
  /tmp/inc006/logrotate-check.service \
  /tmp/inc006/logrotate-check.timer \
  "$VM":/tmp/

ssh -i "$VMKEY" -p "$VMPORT" "$VM" '
mkdir -p ~/changes
cp /tmp/CHG-2026-1101-01.md ~/changes/
sudo cp /tmp/log-maintenance /etc/cron.d/log-maintenance
sudo cp /tmp/logrotate-check.service /etc/systemd/system/logrotate-check.service
sudo cp /tmp/logrotate-check.timer /etc/systemd/system/logrotate-check.timer
sudo chmod 644 /etc/cron.d/log-maintenance
sudo systemctl daemon-reload
sudo systemctl enable --now logrotate-check.timer
systemctl is-active logrotate-check.timer
sudo sha256sum /etc/cron.d/log-maintenance \
  /etc/systemd/system/logrotate-check.service \
  /etc/systemd/system/logrotate-check.timer'
```

Expected:

- timer `active`.
- three hashes matching the change record.
- an enable symlink under `/etc/systemd/system/timers.target.wants/`.

---

## 4. Part C: Collect the alerts

```bash
sleep 8
docker exec single-node-wazuh.manager-1 sh -c \
  'grep -E "\"id\":\"100129\"|\"id\":\"100130\"" /var/ossec/logs/alerts/alerts.json | tail -6' \
  | jq -r '[.timestamp,.rule.id,.syscheck.path] | @tsv'
```

Expected:

```text
100129  /etc/cron.d/log-maintenance
100130  /etc/systemd/system/logrotate-check.service
100130  /etc/systemd/system/logrotate-check.timer
100130  /etc/systemd/system/timers.target.wants/logrotate-check.timer
```

There may be duplicate or batched events. The four paths above are the signal.

---

## 5. Part D: Triage

### 5.1 Authorization

```bash
ssh -i "$VMKEY" -p "$VMPORT" "$VM" 'cat ~/changes/CHG-2026-1101-01.md'
```

Check:

- status is Approved.
- the requester and approver are named.
- the window includes the deployment time.
- the file list matches what appeared.
- the hashes match.

### 5.2 Integrity

```bash
ssh -i "$VMKEY" -p "$VMPORT" "$VM" '
sudo sha256sum /etc/cron.d/log-maintenance \
  /etc/systemd/system/logrotate-check.service \
  /etc/systemd/system/logrotate-check.timer'
```

Compare every hash to the record. A mismatch is an escalation, not a closure.

### 5.3 Behaviour

```bash
ssh -i "$VMKEY" -p "$VMPORT" "$VM" '
cat /etc/cron.d/log-maintenance
systemctl cat logrotate-check.service
systemctl cat logrotate-check.timer
systemctl list-timers logrotate-check.timer --no-pager'
```

Check that the contents are what the change says: a log cleanup and a no-op health
check. Look for an unexpected `ExecStart`, a network call, or a new account.

### 5.4 Follow-on activity

```bash
ssh -i "$VMKEY" -p "$VMPORT" "$VM" \
  'sudo journalctl --since "2026-10-31 23:35:45" --until "2026-10-31 23:37:00" \
   --no-pager | grep -Ei "failed password|invalid user|authentication failure"'
```

Expected: no output.

Also check FIM/audit for unexpected files or processes in the same window.

---

## 6. Part E: Close

Write the ticket with:

- the change ID and approver.
- the four alert paths.
- the hash comparison result.
- the file contents summary.
- the absence of follow-on activity.
- the decision: authorized change, no incident.
- the note that this is not a false positive.

No containment. No rule change. Keep the detection enabled.

---

## 7. Part F: Rollback (optional)

The change is a lab artifact. To remove it:

```bash
ssh -i "$VMKEY" -p "$VMPORT" "$VM" '
sudo systemctl disable --now logrotate-check.timer
sudo rm -f /etc/systemd/system/logrotate-check.service \
           /etc/systemd/system/logrotate-check.timer
sudo systemctl daemon-reload
sudo rm -f /etc/cron.d/log-maintenance
systemctl list-timers --all | grep -i logrotate || echo "timer gone"'
```

If you roll back, record the rollback in the change record. Do not remove it silently.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| No 100129 | `/etc` not FIM realtime | Verify syscheck. Restart agent |
| No 100130 | Unit written outside `/etc/systemd/system` | Use the recorded path |
| Hash mismatch | File changed after the record | Stop. Escalate. Do not close |
| Timer inactive | `enable --now` not run | `systemctl enable --now logrotate-check.timer` |
| Timer runs immediately | `OnCalendar=daily` semantics | Check `systemctl list-timers`. Adjust if needed |
| Alert missing in Wazuh | Manager queue/filter | Check agent and manager logs |
| Legit change looks like an incident | No change record or no hashes | Escalate. The evidence is missing |

---

## 9. Checklist

- [ ] Agent active
- [ ] Rules 100129/100130 loaded
- [ ] Change record written with hashes before deploy
- [ ] Cron file, service, timer deployed
- [ ] Timer active
- [ ] Hashes match the record
- [ ] Four alert paths collected
- [ ] No authentication/process anomalies
- [ ] Decision documented as authorized change
- [ ] Rollback path recorded
