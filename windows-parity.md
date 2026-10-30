# Windows ↔ Linux telemetry parity

**This is a mapping, not executed evidence.** The lab runs on Linux. Windows event
IDs are listed so the same triage reasoning can be applied to the Windows estate
used in this role.

| Activity | Windows | Linux telemetry used here |
|---|---|---|
| Successful logon | 4624 | `sshd` "Accepted publickey/password", PAM session opened |
| Failed logon | 4625 | `sshd` "Failed password" / "Invalid user" |
| Explicit credentials | 4648 | `sudo` / `su` in `auth.log` |
| Special privileges assigned | 4672 | `usermod -aG sudo`, `/etc/group` change |
| Process creation | 4688, Sysmon 1 | `auditd` `execve` (command line, parent, UID) |
| Account created | 4720 | `useradd`, `/etc/passwd` FIM event |
| Account added to group | 4732 | `usermod -aG`, `/etc/group` FIM event |
| Service installed | 7045 | systemd unit file creation, FIM |
| Scheduled task created | 4698, Sysmon 1 | `/etc/cron.d` file creation, FIM |
| File created by process | Sysmon 11 | FIM `added` event |
| Network connection | Sysmon 3, 5156 | Suricata flow/alert, `ss -tunap` |
| DNS query | Sysmon 22 | Suricata `dns` event |

## How this is used

In an interview or a ticket, the answer is: "I ran this on Linux; on Windows the
equivalent evidence is 4624/4625 for logon, Sysmon 1 for process creation, and
Sysmon 11 for file writes. The triage questions are identical."

No claim is made that Windows scenarios were executed in this lab.
