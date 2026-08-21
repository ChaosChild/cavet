# Spike: scanner baseline

**Date:** 2026-08-21 · **Status:** complete · **Output:** findings + SARIF fixtures

Purpose: capture real SARIF from Opengrep, Gitleaks and Trivy before building the
projection layer, so `internal/finding` is written against observed output rather
than the spec's assumption. Five findings materially affect the specification; all
planted vulnerabilities were detected.

Method: `debian:bookworm-slim` + Opengrep 1.27.1, Gitleaks 8.30.1, Trivy 0.74.0,
scanning a 5-file fixture repository with planted SQL injection, `os.system`
interpolation, MD5 token derivation, a hardcoded credential, four vulnerable pinned
Python dependencies, and two AWS Terraform misconfigurations. Fixtures and captured
SARIF are in `internal/finding/testdata/`; §7 records how the planted credential was
changed before commit and what that cost.

## 1. Opengrep's rules are Commons Clause, not LGPL

**Contradicts §7.2 directly.** The spec justifies Opengrep over Semgrep CE on the
grounds that "Semgrep's registry rules sit under a licence restricting use in
commercial and competing products. Opengrep's consortium governance and LGPL rules
are the safer foundation for an MIT project."

`opengrep-rules/LICENSE` reads:

```
"Commons Clause" License Condition v1.0
... the License does not grant to you, the right to Sell the Software.
Software: semgrep-rules (https://github.com/semgrep/semgrep-rules)
License: LGPL 2.1
Licensor: Semgrep, Inc.
```

The rules are the *same* semgrep-rules corpus under the *same* Commons Clause. The
engine binary is genuinely LGPL-2.1; the rules are not. The licensing rationale in
§7.2 is void and needs rewriting — the argument for Opengrep has to rest on
governance and the absence of a paid tier, not on rule licensing.

Consequence for an MIT project: distributing the rules inside the engine image is
permitted; selling a product or service whose value derives substantially from them
is not. This must be stated in the README and the image's licence notice.

## 2. The ≤10s staged budget is unreachable with the community ruleset

Opengrep's cost is **rule parsing, fixed per invocation, independent of file count**:

| Rules | Files | Time |
|---|---|---|
| 2 | 3 | 2.9s |
| 368 (python) | 1 | 10.8s |
| 368 (python) | 5 | 12.6s |
| 962 (all langs) | 1 | 48.4s |
| 962 (all langs) | 5 | 49.1s |

One file and five files cost the same. Warming the container does not help
(11.5s → 11.2s across repeated `docker exec`). The floor is ~2.2s of Opengrep's own
startup; above that it is roughly 26–48ms per rule, degrading superlinearly.

Budget arithmetic, warm: Gitleaks 0.6s + Trivy 1.2s leaves ~8s, which buys about
**150–250 rules** out of a 962-rule corpus.

Two ways out: curate the ruleset down to fit the budget, or move the budget.
**The decision was to move it** — SAST leaves the fast path, and `--staged` runs
Gitleaks and Trivy only, at ~1.8s. Curating would have traded coverage for a latency
number and created permanent rule-selection work, which is a poor bargain when the
alternative costs one flag. See "What this changed" below.

An `opengrep lsp` persistent server exists and would amortise rule loading across
scans, which is the route to full-corpus SAST inside a budget if that is ever wanted.
Not v0.1 work.

## 3. §7.1's long-lived container is right, but for Trivy, not Opengrep

Repeated `docker exec` into one warm container:

| Scanner | First | Subsequent |
|---|---|---|
| Trivy | 24.0s | **1.2s** |
| Gitleaks | 0.7s | 0.6s |
| Opengrep (368 rules) | 11.5s | 11.2s |

Trivy is the entire justification for the long-lived container — a 20× improvement.
Opengrep gains nothing, because its cost is per-invocation rule parsing rather than
process or cache warm-up. §7.1's reasoning ("cold `docker run` costs 0.5–2s") is
correct but understates the real number by an order of magnitude.

## 4. Trivy is not offline by default, which breaks §3.4 determinism

With networking disabled and default flags, Trivy **fatals**:

```
FATAL run error: init error: DB error: failed to download vulnerability DB
```

It attempts to refresh the baked database. This defeats §3.4 — if Trivy silently
updates its vulnerability data at runtime, the engine digest no longer pins the
scan's inputs and the delta stops being reproducible.

`--skip-db-update --skip-check-update --offline-scan` fixes both: the scan runs
offline in 1.8s and reports all 39 findings. **These flags are mandatory, not
optional**, and the reason is determinism before it is offline support. §7.5 should
say so.

The misconfiguration policy bundle is also not baked (`/opt/trivy-cache/policy`
missing); Trivy falls back to embedded checks and still finds everything, but the
bundle should be baked for a clean offline path.

## 5. SARIF bloat is worse than §4 assumes — which validates §4

Opengrep, python+terraform scope, 7 findings:

- **889,143 bytes** of `tool.driver.rules` metadata
- **5,555 bytes** of actual `results`

**99.4% of the SARIF is rule definitions for rules that did not match.** Gitleaks
emits 49,856 bytes and 222 embedded rule descriptors for a single finding. The
all-language Opengrep run produced 2.6MB for 10 findings.

§4's "raw SARIF never reaches the model" is not an optimisation, it is the only
workable design. The projection layer must read `results[]` and ignore
`tool.driver.rules` except to resolve the matched `ruleId`.

## 6. Incidental findings

- **Locale.** Opengrep crashes with `UnicodeDecodeError: 'ascii' codec` unless
  `LANG`/`LC_ALL` are set to a UTF-8 locale. The image must set them.
- **Rule curation is mandatory.** Pointing `--config` at a clone of opengrep-rules
  fails: the repo contains its own `.pre-commit-config.yaml` and `*.test.yaml`
  fixtures, which Opengrep tries to parse as rules and aborts on. The image must
  build a curated bundle (language directories only, test fixtures stripped:
  2031 YAML files → 1818).
- **Image size: 4.49GB**, of which Trivy's databases are 2.7GB (1.3GB vuln,
  **1.5GB java-db**). The java DB is only needed for JARs lacking a pom and should
  be excluded by default. Binaries are 226MB, curated rules 20MB. Excluding java-db
  gives roughly 3.0GB; excluding all baked DBs gives ~370MB, but that trades away
  §7.5 and §3.4.
- **Scanner overlap is real.** Trivy's secret scanner and Gitleaks both flagged the
  same Slack token under different rule ids (`slack-access-token` /
  `slack-bot-token`), and neither carries a CWE. §3.3's fingerprint falls back to
  the scanner rule id here, so the same secret becomes two findings. Cross-scanner
  deduplication needs a decision the spec does not currently make.
  **See §7 — the committed fixture no longer reproduces this**, though the
  measurement stands and the §3.3 decision rests on it.
- **Multi-arch is free.** All three scanners ship prebuilt linux x86_64 and arm64
  binaries, confirming §7.2's "build-matrix concern rather than per-tool porting".
- **Exit codes match §4** — Gitleaks exits 1 when leaks are found, 0 when clean.

## 7. Fixture sanitisation, and what it cost

The fixture originally planted a Slack bot token, which both Gitleaks and Trivy
detected — the collision recorded in §6. That token cannot be committed to a public
repository: GitHub's push protection matches known provider patterns and would block
the push, and the literal value appears in `gitleaks.sarif` as the detected snippet,
not only in the source file.

Candidate replacements were measured against both scanners:

| Planted secret | Gitleaks | Trivy | GitHub push protection |
|---|---|---|---|
| Generic high-entropy key | `generic-api-key` | — | safe |
| Keyword + high entropy (`DATABASE_PASSWORD`) | `generic-api-key` | — | safe |
| JWT-shaped token | `generic-api-key` | — | safe |
| Stripe-shaped `sk_live_…` | `stripe-access-token` | `stripe-secret-token` | **blocks** |
| Slack `xoxb-…` (original) | `slack-bot-token` | `slack-access-token` | **blocks** |

**Trivy's secret scanner has no generic rule** — it fires only on provider-specific
patterns. Every secret both scanners detect is therefore, by construction, exactly the
kind of pattern GitHub blocks. Keeping the cross-scanner collision in the fixture and
keeping the repository pushable are mutually exclusive.

Coverage was chosen over the collision. The fixture now plants a high-entropy generic
key, which Gitleaks reports as `generic-api-key` at `config.py:9`; `gitleaks.sarif`
and `trivy.sarif` were regenerated from it. Trivy's result count drops 39 → 38 and it
reports no secrets. `opengrep.sarif` is unchanged — Opengrep never matched `config.py`.

AWS's published example keys (`AKIAIOSFODNN7EXAMPLE`) are retained deliberately. Both
GitHub and Gitleaks allowlist them, and a fixture demonstrating the allowlist is worth
having.

**Consequence to carry forward.** The secret-deduplication logic required by §3.3 has
no fixture that exercises it. When that code is written it needs a hand-built pair of
minimal SARIF documents reporting one secret under two scanner rule ids — a few lines
of test data, not a scanner run. This is a note for the implementer, not an open design
question: the decision is made and the evidence for it is §6.

## What this changed

Decisions taken on these findings, recorded in the specification:

| Spec section | Change made |
|---|---|
| §7.2 | Opengrep-vs-Semgrep rationale rewritten — rests on governance, not licensing, because the licensing claim was false |
| §5.2 | Retitled "Scan tiers and latency". **The budget was not met by curating rules; it was moved.** SAST left the fast path entirely: `--staged` runs Gitleaks + Trivy in ~1.8s, `--full` and `--deep` add Opengrep at ~50s |
| §7.1 | Long-lived container rejustified on Trivy 24s→1.2s; notes Opengrep gains nothing from it |
| §7.5 | Trivy offline flags documented as mandatory, framed as determinism before offline support |
| §7.2.1 | java-db excluded by default; UTF-8 locale, rule curation and policy bundle recorded as hard build requirements |
| §3.1, §3.3 | `remediated` gated on the originating scanner having run; secrets collapsed pre-fingerprint on `sha256(span + path)` with `also_detected_by[]` |
| §4, §4.1 | Bloat measurement recorded; result header now names the scanners that ran |
| §5.1 | Baseline scan pinned to the deep tier |
| §9 | Pre-commit hook inherits the fast path |

The one finding that did **not** drive a change: §2's suggestion of a curated
150–250 rule default set. That option was considered and rejected — curating the
corpus trades coverage for a latency number and creates permanent selection work.
Moving SAST off the fast path costs nothing but an explicit flag.

### 7.1 A free false positive

Scanning the `cavet` repository itself with the sanitised fixtures in place returns
two Gitleaks findings:

```
generic-api-key            internal/finding/testdata/fixture/config.py:9
sourcegraph-access-token   internal/finding/testdata/gitleaks.sarif:1372
```

The first is the planted credential, working as intended. The second is a **false
positive on a git commit SHA** — `54e12fd9…`, recorded in the captured SARIF's own
`commitSha` field. Sourcegraph access tokens are 40 hex characters, so the rule
matches every commit hash it sees.

It is harmless for publication: GitHub's Sourcegraph pattern requires an `sgp_`
prefix, so push protection ignores it.

Keep it. A fixture with a real, reasoned false positive is more useful than one
without — it exercises the dismissal path in §6 of the specification with a case whose
correct verdict is unambiguous and whose reason ("40-hex match on a commit SHA, not a
credential") is exactly the kind of thing the `triaged` event must record.
