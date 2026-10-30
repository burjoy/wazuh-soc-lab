# Detection rules

Custom rules and suppressions, each with a written reason.

## What belongs here

- Rules that close a genuine gap in the stock ruleset, with the log sample that
  motivated them.
- Suppressions for known-benign activity, with the scope narrowed as much as
  possible (never a blanket `if_sid` with no condition).

## Naming

`100100`–`100199` reserved for custom rules. Each file gets a comment header:

```
<!--
  Rule: 1001xx
  Gap:   <what stock Wazuh missed>
  Sample: <one raw log line>
  Tuning: <known false positives and how they are excluded>
-->
```

## Tuning notes

Every suppression gets an entry in `tuning-notes.md` answering:

- What fired?
- Why is it benign here?
- What is the narrowest condition that still suppresses it?
- What would make this suppression wrong, and how would I notice?
