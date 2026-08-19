# Install notes for the skill set

## Agent instruction file snippet

The one place resident tokens are spent (spec §11.1). Paste into `CLAUDE.md`,
`AGENTS.md`, or the harness equivalent:

```
Security is part of design, not a phase after it. When we discuss architecture,
features, integrations, data flows, auth, or third-party services, surface security
implications alongside functional ones — one line, at the decision point, via the
cavet-design skill. When code is written, apply cavet-secure-coding. Before commit
or on request, run cavet-triage. Never write to .cavet/ directly; the cavet CLI is
the only author of its log.
```

## Placement

Skills go as loose directories under the harness's skills path, flat namespace,
`cavet-*` prefix intact. Uninstall = delete `cavet-*`.

## Subagent

`subagent/cavet-security.md` → the harness's subagent format. Tool allowlist:
Read + shell scoped to `cavet`. Nothing else.

## Trigger

`cavet init --hooks` installs the pre-commit hook; hook output landing in the agent's
context is what makes `cavet-triage`'s "hook output is a scan result" line work.

## CLI contract these skills depend on

Command names only. If any of these change, grep the skills for the name.

| Command | Used by |
|---|---|
| `cavet items` | design, design-review |
| `cavet raise` (kinds: design, verification) | design, design-review, triage, supply-chain, deployment |
| `cavet resolve` | design, design-review, triage |
| `cavet scan` | triage |
| `cavet triage` | triage |
| `cavet lookup` | triage, supply-chain |
| `cavet defer` | triage (verdicts reference) |
| `cavet finding`, `cavet log` | reached via CLI `next:` hints, not named in skills |
| `config.yaml` keys: Checkov enable, container image scanning | deployment (by description only) |

Behavioural assumptions:
- CLI output is markdown tables with an aggregate line and `next:` hints (§4).
- `engine shell` refuses without a TTY (§5), so `cavet *` is a safe allowlist.
- Default scanners: Opengrep, Gitleaks, Trivy; Checkov opt-in (§7.2).
- The CLI de-duplicates already-triaged fingerprints; skills never re-triage.

## What to revisit after real use

- `cavet-design` trigger calibration — the false-flag rate is the metric that
  matters. Keep a list of flags the operator found noisy; they become negative
  examples in `references/decision-points.md`.
- `cavet-secure-coding/references/` — add stacks as encountered; keep each file
  under ~80 lines.
- Verification-hint frequency — if the subagent raises many, either the verdicts
  reference needs more cases or the parent context passed at dispatch is too thin.
