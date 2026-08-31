---
name: cavet-secure-coding
description: Secure-by-default construction while writing or modifying any code — functions, endpoints, queries, file and path handling, shell calls, serialisation, auth, tokens, config, scripts, tests, migrations. Use on every code-writing or code-editing task, regardless of whether it appears security-relevant; recognising what is security-relevant is exactly what this skill supplies, so it cannot be gated on that recognition.
---

# cavet-secure-coding

Preventive, not detective. Runs in your own context while you write, because the
pattern has to be present at the moment the line is written. A finding avoided here
never has to be detected, triaged, surfaced, or fixed.

## How to use this

Write the code the secure way by default and say nothing about it. Mention security
only when the secure form costs something the operator will notice — a new
dependency, a behavioural change, a migration — and then in one line. Do not annotate
ordinary code with security commentary; the goal is that secure is the unremarkable
default.

When working in a specific stack, read the matching file under `references/` once
per session and apply its idioms. The table below is the cross-language core.

## The contrast table

| Insecure | Secure | Why |
|---|---|---|
| Untrusted value concatenated into SQL / NoSQL query | Parameterised query or query builder; value validated against expected shape | Separates data from statement; escaping is not a substitute |
| Shell command assembled by string interpolation | Argument vector, no shell; or no subprocess at all | Removes the shell's parsing stage entirely |
| User-supplied path joined onto a base directory | Resolve, then check the result is still under the base; or map ids to files | `..` and absolute paths escape naive joins |
| Deserialising untrusted input with a general-purpose (un)pickler / YAML full loader / Java native serialisation | Data-only formats (JSON), safe loaders, explicit schemas | General deserialisers execute code |
| MD5 / SHA-1 / plain SHA-256 for passwords | argon2id, scrypt, or bcrypt with sane parameters | Password hashes must be slow and salted |
| Predictable or fast-hash tokens / ids used for auth | CSPRNG-generated tokens of ≥128 bits | Guessable tokens are no tokens |
| `==` on secrets, MACs, tokens | Constant-time comparison | Timing leaks the prefix |
| Redirect target from the request | Allowlist of destinations, or relative paths only | Open redirect is a phishing and token-leak primitive |
| Server fetches a user-supplied URL as given | Allowlist hosts/schemes; resolve and block private/metadata ranges | SSRF into internal networks and cloud metadata |
| HTML built by string concatenation with user data | Auto-escaping template; context-appropriate encoding | XSS |
| Credential in source, config in VCS, build arg, or client bundle | Injected at runtime from environment or platform secret store | Version control has no forgetting; bundles are public |
| TLS verification disabled "for now" | Fix the trust store; never ship `verify=false` | It is never re-enabled |
| Detailed exception text returned to the client | Generic message to client, full detail to logs with a correlation id | Stack traces are a map for attackers |
| Request bodies, tokens, or PII written to logs | Log ids and outcomes; redact fields at the logger | Logs travel further than the app |
| `Math.random()` / `random` for anything security-related | The platform CSPRNG | Non-cryptographic PRNGs are predictable |
| Regex with nested quantifiers on untrusted input | Bounded patterns, input length limits, or a linear-time engine | ReDoS |
| Model bound directly from request body | Explicit allowlist of settable fields (DTO) | Mass assignment of privileged fields |
| JWT accepted with any algorithm / unverified | Pin the algorithm, verify signature and claims (exp, aud, iss) | `alg:none` and key confusion |
| CORS `*` with credentials, or reflecting Origin | Explicit origin allowlist | Cross-site credentialed requests |
| Uploaded file trusted by extension, stored under web root | Validate type by content, cap size, rename, store outside web root, serve with fixed content type | Upload-to-execute and content sniffing |
| Object fetched by id with no ownership check | Scope the query by the caller (tenant/user) at the data layer | IDOR — one request to exploit |
| LLM prompt concatenating instructions with untrusted text; model output executed or trusted | Separate instruction and data roles; treat output as untrusted input; minimum tools | Prompt injection |

Illustrative, not the full set. Stack-specific idioms, framework helpers, and
gotchas are one level down:

- `references/python.md` — Django, Flask/FastAPI, subprocess, pickle/yaml, crypto libs
- `references/javascript.md` — Node, Express/Next, browser, npm ecosystem specifics
- `references/go.md` — database/sql, os/exec, net/http, crypto, templates
- Working in a stack with no file here? Propose the addition to the operator
  instead — new stacks arrive as reviewed contributions, keeping the same shape.

## Relationship to the scanners

This is preventive; the SAST rules in the engine are detective. The overlap is
deliberate: the pattern applied at write time and the rule that would have caught it
are two independent chances at the same outcome. Do not skip the pattern because "the
scanner will catch it", and do not dismiss a scanner finding because "I applied the
pattern" — read the code.

## Working with the cavet CLI

The repo's pre-commit hook is advisory: a shallow staged scan (secrets and
dependencies only) that never blocks. For security-relevant changes, run
`cavet scan --staged --deep` before committing. Check a new dependency with
`cavet lookup` on its purl (`pkg:pypi/reportlab@5.0.1`, `pkg:npm/lodash@4.17.4`)
before pinning. Never re-triage findings the CLI already deduplicates, and never
write to `.cavet/` directly — the CLI is the only author of its log.
