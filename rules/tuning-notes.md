# Detection tuning notes

## 100120 — FIM on `authorized_keys`

**What fired:** FIM reported `/home/svc-backup/.ssh/authorized_keys` as `added`
(realtime), extending the parent rule with a level-12 alert.

**Why it matters:** after a password compromise, an SSH key is the cheapest
persistence. It survives a password reset, so the response must remove it, not just
change the password.

**Narrowest condition that still catches the behaviour:** file name match on
`authorized_keys`, under the existing realtime FIM coverage of `/home`. It does not
try to parse the command that wrote it.

**Known false positives:** legitimate key rotation, onboarding a new admin, or a
user adding a second device. These should be handled with an allow-list of expected
fingerprints or a change window, not by suppressing the rule.

**What would make this wrong:** an attacker who writes the file under a different
name, or uses a tool that bypasses FIM (for example, a write the agent does not see).
Pair with authentication logs and key fingerprints.

## 40112 — not duplicated

Stock rule 40112 already correlates "multiple authentication failures followed by a
success". Two variants were attempted and discarded:

1. A sibling rule anchored on 5763. It never fired because 40112 matched the success
   event first; local rules are evaluated after the stock set.
2. `<same_user />` on the success rule. Wazuh compares `srcuser` on the failed-login
   rules with `dstuser` on the success rule, so the fields do not align.

**Recommendation:** tune 40112 itself. Scope it to sshd authentication groups, raise
the failure threshold, and make the account part of the condition if a decoder can
expose it consistently. A duplicate rule that never fires is worse than no rule: it
looks like coverage.
