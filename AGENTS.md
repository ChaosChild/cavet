# Agent instructions for cavet

## Tracking

- `docs/implementation-plan.md` is the working plan. As each step/task completes,
  flip its checkbox (`- [ ]` → `- [x]`) and include the change in the commit that
  completes the work.
- Commit messages: conventional commits (`feat:`, `test:`, `chore:`, `docs:`),
  scoped where useful (e.g. `feat(events): …`).

## Build and verify

- Go toolchain directive lives in `go.mod`; CI reads `go-version-file: go.mod`.
- Phase boundary gate: `go build ./...`, `go vet ./...`, `go test ./...`,
  then `golangci-lint run --timeout=5m` (config: `.golangci.yml`, v1 format).
- Pinned tooling — upgrade everywhere at once: golangci-lint **v1.64.8** from
  the v1 module path
  (`go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8`)
  on the dev machine AND in `.github/workflows/ci.yml`; `.golangci.yml` is v1
  format, so a v2 binary requires migrating the config in the same change,
  and binaries built with a Go older than `go.mod`'s directive refuse to load
  the module.
- Windows is the primary dev platform; keep shell commands pwsh-compatible.
- On this machine Go lives at `C:\Program Files\Go\bin` and golangci-lint at
  `%USERPROFILE%\go\bin` — prepend to `Path` in shell sessions that need them.

## Secrets

- `.env` and `.lavish/` are gitignored. Never commit keys or session artefacts.

## Spec sources

- Design of record: `docs/SPECIFICATION.md` + annexes (`artefacts-spec.md`,
  `cli-spec.md`, `engine-spec.md`, `skills-spec.md`). Deviations get a numbered
  entry in the relevant annex's deviations section, not silent drift.
- The implementation plan's inline code is a design sketch: adapt it, don't
  transcribe it; behaviour in the annexes wins over sketch code.
