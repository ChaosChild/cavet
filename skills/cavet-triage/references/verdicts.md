# Verdicts by finding category

What a defensible dismissal looks like, per category, and what is never a reason.

## SAST (Opengrep / Semgrep rules)
An SAST match is a pattern match, not a vulnerability. Read the code.

Legitimate dismissals (say which):
- **Fixture / test / example** — path is under a test or docs tree and the code is
  not imported by production modules. Confidence high.
- **Input is trusted, and here is why** — the tainted value originates from config,
  a constant, or a value already validated at a named line. Confidence high only if
  the origin is in the file or a direct import you read.
- **Unreachable** — dead code, disabled feature flag, or a branch that cannot be
  taken. Confidence per how certain that is.
- **Sanitised upstream** — name the function and line that neutralises it. If you
  cannot name it, confidence low or confirm.

Not a reason: "framework probably handles it", "internal service", "unlikely",
"low severity" (severity is not a verdict), "would be caught in review".

## Secrets (Gitleaks)
- **Placeholder / example** — obviously synthetic (`sk-xxxx`, `changeme`, matches a
  documented dummy format). Confidence high.
- **Public by nature** — a publishable key type documented as safe to expose.
  Confidence high, cite the doc in the reason.
- **Revoked** — only if the operator has said so; you cannot verify. Confirm with a
  note otherwise: it is in history regardless.
- High-entropy string that is a hash, UUID, or checksum, not a credential — read
  context and state what it is. Confidence high only if you can account for where
  the value came from; otherwise confidence low or confirm.

Not a reason: "it's in .env.example" if the value is real; "it's an old commit".

## SCA / dependencies (Trivy)
Run `cavet lookup` first. Then:
- **Not in affected range** — installed version is outside the range from the
  advisory. Confidence high, cite.
- **Fixed version already installed** — cite.
- **Vulnerable function not called** — dismiss only with confidence low unless you
  read the dependency's call sites and can name them; otherwise confirm and note it
  as a remediation hint.
- **Dev-only dependency** — lowers urgency, does not dismiss. Confirm, note scope.
- Known-exploited (KEV) or high EPSS → never dismiss on reachability arguments alone.
  The default bar for "high EPSS" is ≥10%, or any KEV listing; the operator may set
  a different threshold — this one applies when none is given.

## IaC / misconfiguration (Trivy, optional Checkov)
- **Intentional and documented** — a public bucket that is a static site, a
  permissive rule in a dev-only module named as such. Confidence high only if the
  intent is stated in code, a decision record, or an open item.
- **Environment-scoped** — module or overlay is unambiguously non-production and the
  finding is about production hardening. Confidence per how verifiable the scoping is.

Not a reason: "it's just staging" without evidence of scoping; "we'll lock it down
before launch" (that is a deferral, not a dismissal — use `cavet defer`).

## Container images (only if enabled)
Treat as SCA plus base-image freshness. "We'll rebuild later" is a deferral.

## Always
- Every verdict has a reason a stranger could evaluate.
- Prefer confirm-low over dismiss-low when uncertain: uncertainty should be visible
  to the operator, not hidden in a dismissal.
- A dismissal can still leave an operator-only question (for example, whether a
  hash-like string is also the production credential). Raising a verification item
  for that question is correct even though the finding itself is dismissed; reference
  the raised item in the dismissal reason.
- Duplicate of an already-triaged fingerprint: the CLI handles it; do not re-triage.
