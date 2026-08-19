# CI / CD

## Permissions and identity
- Workflow-level `permissions:` minimal (`contents: read` default), elevate per job.
- Cloud access via OIDC federation with a scoped trust policy; no long-lived cloud
  keys as CI secrets if the platform supports federation.
- Separate deploy credentials per environment; production deploy requires a
  protected environment / manual approval where the risk warrants.

## Third-party steps
- Pin actions/orbs/plugins to a full commit SHA. Review what a new step does before
  adopting; it runs with the job's token.
- `pull_request_target` and equivalents that run with secrets on fork code: avoid,
  or never check out and execute the PR head in that context.

## Secrets in pipelines
- Secrets are masked in logs only if the platform knows them — do not derive and
  echo values. Never write secrets to artifacts, caches, or build outputs.
- Fork PRs do not receive secrets; design the pipeline so that is fine.

## Supply chain in the pipeline
- Install from lockfiles (`npm ci`, `--require-hashes`, `go mod verify`).
- Build once, promote the same artifact/digest across environments; do not rebuild
  per environment.
- Generate an SBOM if the platform makes it cheap; sign artifacts where possible.

## Deploy scripts
- Idempotent; fail loudly (`set -euo pipefail`); no interactive prompts; no
  credentials in arguments (visible in process lists) — env or files with tight perms.
- Rollback path scripted or documented next to the deploy step.

## Scanning in CI
- `cavet` writes SARIF to `.cavet/reports/`; upload it to code scanning if the
  platform supports it. Advisory, not gating, unless the operator builds gating.
