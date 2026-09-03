## Summary

<!-- What changes and why, in one or two sentences. Link the issue. -->

Fixes #

## Docs ride along

- [ ] User-visible change: README (or site docs) updated in this same PR
- [ ] Design change: docs/SPECIFICATION.md updated in this same PR
- [ ] Neither applies

## Verification

Phase boundary gate, run before opening:

- [ ] `go build ./...`
- [ ] `go vet ./...`
- [ ] `go test ./...`
- [ ] `golangci-lint run --timeout=5m` (pinned v1.64.8, v1 module path)

Test evidence (commands + result; note engineclient integration tests need
Docker up):

## Constraints checked

- [ ] `.cavet/log/` untouched by hand – the CLI is its only author; any
      finding this PR introduces is triaged in the log before merge
      (remediated, deferred as debt, or dismissed with a recorded reason) –
      no new untriaged entries
- [ ] No `.env` or other gitignored local artefacts committed
- [ ] If golangci-lint moved: upgraded everywhere at once (local, CI, config format)
- [ ] Windows still works – primary dev platform, pwsh-compatible

For agent-authored PRs: a human has reviewed the full diff and owns this change.
