# Templates

## `.cavet/design/threat-model.md`

Keep it short and current. Overwrite sections; do not append history (the log has
history).

```markdown
# Threat model — <system/feature>
Updated: <date> · Reviewed against: <design doc / commit>

## Assets
| asset | sensitivity | where it lives |
|-------|-------------|----------------|

## Trust boundaries
| boundary | untrusted side | what crosses | control |
|----------|----------------|--------------|---------|

## Threats considered
| # | threat | likelihood | impact | mitigation | decision |
|---|--------|------------|--------|------------|----------|

## Accepted risks
| # | risk | why accepted | revisit when |
|---|------|--------------|--------------|

## Open
See `cavet items`.
```

## `.cavet/design/decisions/NNNN-<slug>.md`

ADR-shaped. One decision per file. Numbered, never edited after acceptance —
supersede with a new file.

```markdown
# NNNN — <decision in one line>
Status: accepted | superseded by NNNN
Date: <date>
Related items: <cavet item ids>

## Context
Two or three sentences: what was being decided and why security bears on it.

## Decision
What was chosen.

## Consequences
What this protects against; what it costs; what it does not protect against.

## Alternatives considered
One line each, with why not.
```
