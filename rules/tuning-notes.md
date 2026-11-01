# Detection tuning notes

## 100120: FIM on `authorized_keys`

**What fired**

FIM reported `/home/svc-backup/.ssh/authorized_keys` as `added`
(realtime), extending the parent rule with a level-12 alert.

**Why it matters**

After a password compromise, an SSH key is the cheapest
persistence. It survives a password reset, so the response must remove it, not just
change the password.

**Narrowest condition that still catches the behaviour**

File name match on
`authorized_keys`, under the existing realtime FIM coverage of `/home`. It does not
try to parse the command that wrote it.

**Known false positives**

Legitimate key rotation, onboarding a new admin, or a
user adding a second device. These should be handled with an allow-list of expected
fingerprints or a change window, not by suppressing the rule.

**What would make this wrong**

An attacker who writes the file under a different
name, or uses a tool that bypasses FIM (for example, a write the agent does not see).
Pair with authentication logs and key fingerprints.

**Tested 2026-10-31**

Lookalike filenames (`authorized_keys.txt`,
`authorized_keys.bak`) also trigger the rule because the match is a substring. Exact
path matching was not achievable with `<match>` or `<regex>` against the FIM log, and
`<field name="syscheck.path">` is not evaluated. Mitigate by naming and by a key
baseline. See `inc-002-rules.md` §5.2.

## 40112: not duplicated

Stock rule 40112 already correlates "multiple authentication failures followed by a
success". Two variants were attempted and discarded:

1. A sibling rule anchored on 5763. It never fired because 40112 matched the success
   event first. Local rules are evaluated after the stock set.
2. `<same_user />` on the success rule. Wazuh compares `srcuser` on the failed-login
   rules with `dstuser` on the success rule, so the fields do not align.

**Recommendation**

Tune 40112 itself. Scope it to sshd authentication groups, raise
the failure threshold, and make the account part of the condition if a decoder can
expose it consistently. A duplicate rule that never fires is worse than no rule: it
looks like coverage.

## 100121: user added to the sudo group

**What fired**

Audit execve of `/usr/sbin/usermod` with `a2=sudo`, raised to level 12.
INC-002 produced it at 04:30:48, naming the affected account (`svc-ops`) in the alert.

**Why it matters**

Stock 5902 reports a new user at level 8, without saying the account
can become root. In a window with 237 alerts, level 8 is easy to defer.

**Narrowest condition that still catches the behaviour**

The `usermod` binary plus the
group argument `sudo`. It works for both `-aG` (append) and `-G` (replace), because the
group name is still `a2`.

**Known false positives**

Legitimate administrator onboarding, automated account
provisioning, and configuration management that grants sudo. These should be matched
against a change ticket, not suppressed.

**What would make this wrong**

A site that uses a different privileged group (`wheel`,
`admin`), a host without auditd, or an attacker who edits `/etc/group` directly instead
of using `usermod`. Pair with FIM on `/etc/group` and a group-membership baseline.
