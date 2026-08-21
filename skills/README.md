# cavet skills — draft set

Six skills, hard cap (spec §11). Each is a directory: `SKILL.md` (thin, always
loaded when triggered) plus `references/` (loaded on demand). Prefix `cavet-`
everywhere; the prefix carries the security signal, names do not repeat it.

```
cavet-design/          conversational, design phase
cavet-design-review/   checkpoint, design → build
cavet-triage/          scan results, subagent + parent reconciliation
cavet-secure-coding/   preventive, parent thread, fires on any code
cavet-supply-chain/    dependencies
cavet-deployment/      IaC, secrets, runtime config
```

The `cavet-security` subagent definition lives in `../subagents/`; the
agent-instruction snippet, allowlists, and CLI contract these skills depend on are
in `../docs/install-notes.md`.

## Contract with the CLI

Skills reference **command names only**, never flags (spec §2.1). Flags are what
`cavet <cmd> --help` and the CLI's `next:` hints answer at the moment of need. The
commands these drafts depend on are listed in `../docs/install-notes.md`; if a command is
renamed or removed, that list is the change surface.

## Style rules applied

- Frontmatter descriptions are deliberately "pushy" and describe *activity*, not
  security vocabulary — skills undertrigger by default.
- Bodies say *why*, briefly, rather than stacking MUSTs.
- Nothing in a skill body duplicates what the CLI prints.
- Every skill tells the agent what to do when it is unsure: raise, don't guess.
