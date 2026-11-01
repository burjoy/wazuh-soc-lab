# CHG-2026-1101-01: Nightly log maintenance

| Field | Value |
|---|---|
| Status | Approved |
| Requester | analyst |
| Approver | lab-change-manager |
| Window | 2026-11-01 06:30 UTC |
| Purpose | Remove rotated logs older than 7 days. Add a logrotate health check |
| Risk | Low |

## Files

| Path | SHA-256 |
|---|---|
| /etc/cron.d/log-maintenance | 58acf8face227878d58765d32cebe4b82b562996b9e77b02d7011e7533835437 |
| /etc/systemd/system/logrotate-check.service | 6a0555d9e6831f2dcf2b208e7f7bf4da9473f145b4d31b46ebde76def3a50f19 |
| /etc/systemd/system/logrotate-check.timer | 83d683d881cc93e29c2f56f6925756b60d53c84f4234e2bbdeac060d87658cd8 |

## Rollback

```bash
sudo systemctl disable --now logrotate-check.timer
sudo rm -f /etc/systemd/system/logrotate-check.service /etc/systemd/system/logrotate-check.timer
sudo systemctl daemon-reload
sudo rm -f /etc/cron.d/log-maintenance
```
