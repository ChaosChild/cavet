# cavet

From *caveat*, "let him beware". A warning, not a prohibition.

A toolbox that lets a willing operator enable their coding agent to think about
security while it works, and to deal with the results efficiently — without
prompting for it every time.

`cavet` makes security review **repeatable**: the same checks, the same phases, the
same output shape, the same audit trail, session after session.

**Nothing blocks.** Everything advises. The agent or the operator chooses to
remediate, defer, or dismiss. Teams that need enforcement build it themselves
around these tools.

**Status: design complete, nothing built.** The CLI does not exist yet. What is in
this repository today is the specification and the draft skill set.

## Layout

```
docs/          SPECIFICATION.md — the design of record; install notes
skills/        the six cavet-* agent skills (SKILL.md + references/)
subagents/     the cavet-security subagent definition, harness-agnostic
```

The Go CLI, the engine image, and the harness installers land here as they are
built.

## Reading order

1. [`docs/SPECIFICATION.md`](docs/SPECIFICATION.md) — what this is and why it is
   shaped this way.
2. [`docs/spike-2026-08-21-scanner-baseline.md`](docs/spike-2026-08-21-scanner-baseline.md)
   — measured scanner behaviour, and the five things it proved the specification had
   wrong.
3. [`skills/README.md`](skills/README.md) — the six skills and the contract they
   hold with the CLI.
4. [`docs/install-notes.md`](docs/install-notes.md) — placement, allowlists, and
   the CLI commands the skills depend on.

## Licence

`cavet` itself is MIT. See [LICENSE](LICENSE).

**The engine image is not uniformly MIT**, and the difference matters if you intend
to sell something built on this:

| Component | Licence |
|---|---|
| `cavet` CLI, skills, subagent, installers | MIT |
| Gitleaks | MIT |
| Trivy | Apache-2.0 |
| Opengrep engine | LGPL-2.1 |
| **Opengrep rule corpus** | **LGPL-2.1 + Commons Clause** |

The Opengrep rules are the `semgrep-rules` corpus, licensed by Semgrep, Inc. under
LGPL-2.1 with a Commons Clause condition: you may not *sell* a product or service
whose value derives entirely or substantially from them. Using `cavet`, distributing
it, and building on it are all unaffected. Selling a hosted service whose value comes
substantially from those rules is not.

The rules are only loaded by the deep scan tier. The fast tier — secrets and
dependency scanning, which is what the pre-commit hook and staged scans use — is
entirely MIT and Apache-2.0, and Opengrep can be disabled outright in `config.yaml`.
