# cavet skills — draft set

Seven skills: six trigger-contract skills under the spec §11 cap, plus one
bootstrap skill outside it. Each is a directory: `SKILL.md` (thin, always
loaded when triggered) plus `references/` (loaded on demand). Prefix `cavet-`
everywhere; the prefix carries the security signal, names do not repeat it.

```
cavet-design/          conversational, design phase
cavet-design-review/   checkpoint, design → build
cavet-triage/          scan results, subagent + parent reconciliation
cavet-secure-coding/   preventive, parent thread, fires on any code
cavet-supply-chain/    dependencies
cavet-deployment/      IaC, secrets, runtime config
cavet-install/         bootstrap: installs the CLI when a skill finds it missing
```

`cavet-install` is a different class from the six above. The six are
trigger-contract skills: their descriptions are long and pushy because they
must fire on activity that never mentions security. `cavet-install`'s trigger
is mechanical (the `cavet` binary is not on PATH), so its description is two
short lines and it is exempt from the trigger-contract description
conventions. That exemption is what keeps its resident cost near zero, and why
it carries no `references/` directory: a bootstrap skill stays a single file.

The `cavet-security` subagent definition lives in `../subagents/`; the
agent-instruction snippet, allowlists, and CLI contract these skills depend on
lived in `docs/install-notes.md`, now hosted at
<https://migatchev.co.za/projects/cavet>.

## Contract with the CLI

Skills reference **command names only**, never flags (spec §2.1). Flags are what
`cavet <cmd> --help` and the CLI's `next:` hints answer at the moment of need. The
commands these drafts depend on are listed in the CLI contract (hosted at
<https://migatchev.co.za/projects/cavet>); if a command is
renamed or removed, that list is the change surface.

## Style rules applied

- Frontmatter descriptions are deliberately "pushy" and describe *activity*, not
  security vocabulary — skills undertrigger by default.
- Bodies say *why*, briefly, rather than stacking MUSTs.
- Nothing in a skill body duplicates what the CLI prints.
- Every skill tells the agent what to do when it is unsure: raise, don't guess.
