# Comparison with other tools

Verified 2026-09-08. Star counts and last-push dates are re-verified at each
release, so the page ages honestly rather than silently.

Written for an engineer deciding what to run, not for outreach. Facts with
sources where they are checkable; where a vendor does not document something,
that is stated rather than guessed.

## The field

| | cavet | `/security-review` | Aikido plugin | Semgrep Guardian | Snyk |
|---|---|---|---|---|---|
| What it is | Go CLI, seven skills, one subagent | Prose slash command plus a GitHub Action | Marketplace plugin over the Aikido MCP server | MCP server, hooks, skills | CLI and MCP over a cloud platform |
| Detection | Deterministic scanners; the model triages and advises | Model reads the diff | Aikido engines: SAST, secrets, IaC | Semgrep Code, Supply Chain, Secrets | Snyk engines: Open Source, Code, Container, IaC |
| Lifecycle | Design, code, dependencies, deploy, triage | One branch diff | Files changed in the session, up to 50 per request | File edit and end of agent loop | Dev, CI, production |
| Verdicts persist | Append-only log in the repository, with reason and actor | No; false-positive filtering re-runs each time | Not documented | Not documented | Cloud project history |
| Where code goes | Container at `NetworkMode: none`; `lookup` takes identifiers only | Diff to the Anthropic API | Account required; local or cloud not documented | Claude Code default is Semgrep's hosted server | Snyk cloud; `SNYK_TOKEN` required |
| Agents | 7 harness installers, 70 agents via `npx skills add` | Claude Code | Claude Code | Claude Code, Codex, Cursor, Copilot, Windsurf, Kiro | Claude Code, Cursor, Devin, Codex |
| Posture | Advises, never blocks (stated non-goal, [SPECIFICATION.md §1.1](SPECIFICATION.md)) | Advises | Re-scans up to three times until clean | Re-prompts the agent until clean or dismissed | Enforcement and policy gates |
| Cost | MIT, free, no account | Free, plus Anthropic API usage | Commercial, account | Commercial, account; Semgrep Teams starting at $30/contributor/month, free tier to 10 contributors and 10 private repos | Commercial, account |

### `/security-review` in detail

Anthropic's `/security-review` is a prose slash command plus a GitHub Action.
The command file declares `allowed-tools: git diff, Read, Glob, Grep`; there is
no scanner anywhere in the repository. It reviews a branch diff, filters false
positives with a second model call per run, and retains nothing between runs.
It is model judgement over a diff, which is a different category of thing from
deterministic scanners, useful for what it is. Repository:
[anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review),
6.2k stars, last pushed 2026-02-11.

## Engine lineage: Opengrep and Semgrep

cavet's deep-scan engine is Opengrep, a fork of Semgrep v1.100.0 under
LGPL-2.1, created in January 2025 after Semgrep moved cross-function taint
analysis behind a commercial licence. Semgrep CE, the free tier, is
intraprocedural only; Opengrep kept the cross-function taint engine open.

That is the whole statement, in both directions. Semgrep's paid tiers still
hold two things Opengrep does not have: cross-file (interfile) analysis on
eight languages, and the Pro ruleset. cavet makes no claim to better rules
than Semgrep; it bundles the `semgrep-rules` corpus it is licensed to bundle
(LGPL-2.1 + Commons Clause, see the README licence table), and the fast scan
tier does not touch it at all.

Aikido is one of the five AppSec companies in the Opengrep consortium, with
Amplify, Endor Labs, Kodem and Orca Security. Aikido's plugin and cavet
therefore run engines with shared lineage; this is a common ancestry, not a
rivalry, and it means engine-level arguments between them are mostly arguments
about configuration.

## Auto-remediation loops

The Aikido plugin applies remediation guidance and re-scans up to three times
until the result is clean. Semgrep Guardian re-prompts the agent to regenerate
until the scanner returns clean or a human dismisses the prompt. These are
design choices, made deliberately, with a cost worth naming: under a
goal-directed agent, "until clean" is a forced-upgrade loop, and the pinned
dependency it forces an upgrade on was pinned for reasons the agent cannot see.
Sometimes the right answer to a finding is to accept it and reduce the surface
elsewhere; a loop until clean removes that answer.

cavet does not gate, and this is a stated non-goal
([SPECIFICATION.md §1.1](SPECIFICATION.md): "Not a gate. Nothing blocks."),
not an unfinished feature. The reasoning is the mirror image of the above: a
tool that records every verdict, deferral and suppression makes enforcement
trivial to build on top (CI can read the log), while unpicking enforcement from
a tool that assumes it is not. Teams that need gates build them around the
record.

## Where code goes

cavet's own infrastructure cannot carry source out. Scans run in a container
created with `NetworkMode: none`, enforced in `internal/engineclient/client.go`
and pinned by CI tests; no scanner tier needs network egress. `cavet lookup`
accepts identifiers only: CVE, GHSA and OSV ids, package coordinates, rule
ids, CWE references. A command whose only parameters are identifiers
structurally cannot carry a code snippet, a file path, or a secret; the
constraint is structural, not policy.

What the operator's own agent does with the code afterwards is outside cavet's
mandate, and cavet does not claim otherwise.

For comparison: `/security-review` sends the diff to the Anthropic API.
Guardian on Claude Code defaults to Semgrep's hosted server. Snyk requires
`SNYK_TOKEN` and its cloud. Aikido's documentation does not state whether
scanning is local or cloud, nor whether anything persists between sessions.

## Accounts

Aikido, Semgrep and Snyk require an account. cavet does not. For a team under
Semgrep's free thresholds (10 contributors, 10 private repos) or one that
already pays for Snyk seats, the account question matters less than it sounds;
stated as a fact, not as a verdict.

## A different axis: securing the agent

[snyk/agent-scan](https://github.com/snyk/agent-scan) and
[cc-safety-net](https://github.com/kenryu42/cc-safety-net) are not competitors
on the axis this table measures. They secure the agent itself: prompt
injection, tool poisoning, malicious skills, destructive commands before they
run. cavet secures the code the agent writes and does nothing in that space.
The two are complementary, and an operator running both is not double-paying
for one job.

## Scope, stated plainly

cavet today is single-repository and single-operator oriented. Teams, multiple
repositories, and an org-controlled central engine are roadmap items, not
absent features nobody noticed.

## Repository metrics

Verified 2026-09-08 against the GitHub API; re-verified at each release.

| Repository | Stars | Last push |
|---|---|---|
| [anthropics/claude-code-security-review](https://github.com/anthropics/claude-code-security-review) | 6,182 | 2026-02-11 |
| [semgrep/guardian](https://github.com/semgrep/guardian) | 12 | 2026-09-03 |
| [semgrep/semgrep](https://github.com/semgrep/semgrep) | 16,543 | 2026-09-04 |
| [opengrep/opengrep](https://github.com/opengrep/opengrep) | 3,057 | 2026-09-07 |
| [snyk/agent-scan](https://github.com/snyk/agent-scan) | 3,016 | 2026-09-08 |
| [kenryu42/cc-safety-net](https://github.com/kenryu42/cc-safety-net) | 1,528 | 2026-09-08 |

cavet's engine image is not a repository with a star count; it is
`ghcr.io/chaoschild/cavet-engine`, signed and digest-pinned.
