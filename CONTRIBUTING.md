# Contributing to cavet

Thanks for considering a contribution. cavet advises, never blocks, and
records every judgement. Patches that keep that shape predictable land
fastest, so this guide is short on ceremony and firm on its gates.

## Ground rules

- **A human reviews and owns every PR.** Agent-authored contributions are
  welcome and expected – this repository is itself built agent-first – but a
  person reads the full diff before it merges. Agents, and operators directing
  them, follow [AGENTS.md](AGENTS.md).
- **One behaviour change per PR**, kept small, linked to an issue where one
  exists.
- **User-visible commands ship with docs in the same PR.** README updates ride
  along; they do not follow later.
- **Design changes update [docs/SPECIFICATION.md](docs/SPECIFICATION.md)** –
  the design of record – in the same PR.
- **Never hand-edit `.cavet/log/`**, including in tests and fixtures: the CLI
  is the only author of the audit trail. A PR that introduces a finding
  triages it in the log before merge – remediated, deferred as debt, or
  dismissed with a recorded reason; no new untriaged entries.
- **Never commit secrets or local artefacts** (`.env`, scratch and session
  directories). They are gitignored; keep it that way.

## Development setup

- **Go 1.26** – the directive in `go.mod` is the source of truth; CI reads
  `go-version-file: go.mod`.
- **Docker**, daemon running: the engineclient integration tests execute
  against it rather than skip.
- **golangci-lint v1.64.8**, from the v1 module path:

  ```sh
  go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.64.8
  ```

  `.golangci.yml` is v1 format, so a v2 binary needs a config migration in the
  same change, and the version moves everywhere at once: dev machine, CI
  workflow, config format.
- **Windows is the primary development platform** – keep shell snippets and
  scripts pwsh-compatible.

## The gate

CI runs exactly this; run it before opening the PR:

```sh
go build ./...
go vet ./...
go test ./...
golangci-lint run --timeout=5m
```

All four must pass. A red PR is not reviewed further until it is green.

## Reporting issues

Bug reports and feature proposals use the issue templates. Security
vulnerabilities do not go through issues – see [SECURITY.md](SECURITY.md)
for private reporting.

## Licence

cavet is MIT (see [LICENSE](LICENSE)); by contributing you agree that your
contributions are licensed MIT. Bundled scanner rules carry their own
licences – the Opengrep `semgrep-rules` corpus in particular; see the licence
table in the [README](README.md#licence).
