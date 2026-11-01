# Ticket template

Copy this file for each incident. Keep the shape identical every time, consistency
is part of what this repository is demonstrating.

```markdown
# INC-00N: <one-line summary>

| Field | Value |
|---|---|
| Severity | Critical / High / Medium / Low |
| Status | Closed / Escalated |
| Source | Wazuh rule <id>: <description> |
| Host | soc-victim |
| User | <account> |
| MITRE | T####.###: <technique> |
| Detected (UTC) | YYYY-MM-DD HH:MM:SS |
| Triaged (UTC) | YYYY-MM-DD HH:MM:SS |
| Time to triage | N minutes |

## What fired

The alert text, plus the single raw log line that proves it. No paraphrase.

## Investigation

What I checked, in order, and what each check ruled in or out.

## Findings

Facts only. Hashes, paths, command lines, source addresses, counts.

## Severity rationale

Why this severity and not the one above or below it.

## Action taken

Containment or escalation, stated as an action with a timestamp.

## Escalation note

What L2 needs to know that is not already in the ticket, and what I would do next.

## Lessons

What the runbook should say next time.
```

## Rules

- All timestamps in UTC, taken from the log, not from memory.
- Every file artefact gets a SHA-256.
- Screenshots go in `docs/screenshots/` and are linked, not pasted.
- "Closed as false positive" is a valid outcome, but the reasoning must be written.
