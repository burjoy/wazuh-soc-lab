# Runbooks

One file per scenario, written so a colleague on the next shift can follow it
without asking me anything.

Structure:

1. **Trigger** — the alert or condition this runbook starts from.
2. **Verify** — how to confirm it is real, and what a false positive looks like.
3. **Enrich** — what context to pull (asset owner, account, reputation, recent changes).
4. **Decide** — severity and the threshold for escalation.
5. **Contain** — the exact action, and who is authorised to take it.
6. **Record** — the ticket fields that must be filled before closing.
7. **Escalate** — what L2 receives.

Runbooks are living documents. Any ticket that required a step not listed here
gets that step added.
