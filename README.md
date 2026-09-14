# cavet

[![Release](https://img.shields.io/github/v/release/ChaosChild/cavet)](https://github.com/ChaosChild/cavet/releases/latest)
[![CI](https://github.com/ChaosChild/cavet/actions/workflows/ci.yml/badge.svg)](https://github.com/ChaosChild/cavet/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/ChaosChild/cavet.svg)](https://pkg.go.dev/github.com/ChaosChild/cavet)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/ChaosChild/cavet/blob/main/LICENSE)

From *caveat*, "let him beware". A warning, not a prohibition.

Most of the code landing in repositories now is written by coding agents –
sometimes eager to please the operator, and happy to skip the boring parts. At
the same time, the agentic workflows doing the writing are themselves a rising
attack surface. Put the two together and the direction is set: as agent-written
code accelerates, the attack surface of the products being shipped has to
shrink, not grow.

Security scanning already exists – most CI stacks run the same scanners cavet
wraps – but it runs after the agent is done, and a finding that arrives after
the change is complete arrives too late to shape it. Prose goes further: a
paragraph in the system prompt, a section in the agent instructions, a skill. Any
of these can tell an agent to be security-aware while it designs and
builds. It works, in the sense that it sometimes fires. But prose is advice,
not a guarantee: it does not behave the same way twice, and it evaporates
between sessions.

And when CI does flag something, the findings land in a new agent session that
has none of the context that produced them: what the previous session decided
during design, why it decided it, and which of these findings are pre-existing
baseline debt versus newly introduced by the change. The same false positive
gets rediscovered and re-argued from first principles, session after session.

cavet is one operator's answer, in toolkit form: security at the same speed as
everything else – operators and their agents producing more secure products,
more often, with repeatable efficiency. The audit trail and the recorded
baseline carry the context between sessions; the skills advise at the moments
where judgement is actually needed; the CLI records every judgement – verdict,
reason, actor – and is the only author of that record. The same checks, the
same phases, the same output shape, the same audit trail, session after
session. **Nothing blocks.** Everything advises. The agent or the operator
chooses to remediate, defer, or dismiss. Teams that need enforcement build it
themselves around these tools.

**Status:** v0.1.2. The CLI, the multi-arch engine image, installers for seven
harnesses, and CI are all here and working;
[SPECIFICATION.md](docs/SPECIFICATION.md) remains the design of record.

<p><img src="docs/scan-demo.gif" alt="cavet staged scan finds a planted key, the finding is dismissed with a recorded reason, and the audit trail shows every event" width="840"></p>
<p>
  <img src="docs/harness-claude.png" alt="Claude Code loads the cavet-triage skill, dispatches the cavet-security subagent, and reconciles the verdict for the operator" width="840">
</p>
<p>
  <img src="docs/harness-opencode.png" alt="OpenCode runs the same flow: skill, subagent scan, verification item resolved with cavet, reconciliation and coverage caveat" width="840">
</p>

## Network posture

Two properties, both structural rather than promised:

- **Scanning runs with the network off.** The engine container is created with
  `NetworkMode: none`, enforced in `internal/engineclient/client.go` and pinned
  by CI tests; no scanner tier needs egress.
- **`cavet lookup` accepts identifiers only** – CVE, GHSA and OSV ids, package
  coordinates, rule ids, CWE references. A command whose only parameters are
  identifiers structurally cannot carry a code snippet, a file path, or a secret.

What your agent does with your code afterwards is outside cavet's mandate.

## How this differs from /security-review, Aikido and Semgrep Guardian

`/security-review` is prose plus a model reading the diff. Aikido's plugin and
Semgrep Guardian are commercial scanners wired into the agent loop. cavet is
deterministic scanners plus advisory skills, with verdicts recorded in a log
the repository owns. [docs/COMPARISON.md](docs/COMPARISON.md) carries the full
comparison: what each tool is, which scanners run, where code goes, what
persists between sessions, what it costs.

## Installation

### Prerequisites

1. **Docker**, with a running daemon – `cavet init` probes it first and tells you
   if it is unreachable. Image scanning additionally uses the `docker` CLI's
   `buildx` plugin (bundled with Docker Desktop) to build images.
2. **A `cavet` binary** – the one-liner below installs it, or any channel in
   [Advanced: other install channels](#advanced-other-install-channels).
3. **A git repository you want covered.**

### Install

One line per platform – checksum-verified download, binary on your `PATH`:

```sh
curl -fsSL https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/binary.sh | bash
```

Installs the latest release for your OS/arch (darwin/linux × amd64/arm64)
into `~/.local/bin` – override with `--dir <path>` or `CAVET_INSTALL_DIR`, pin
a version with `bash -s -- --version <x.y.z>`. Windows (pwsh, canonical
two-step form – a piped script cannot bind `param()`):

```pwsh
irm https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/binary.ps1 -OutFile binary.ps1
pwsh -NoProfile -File binary.ps1
```

Installs into `$HOME\.local\bin` and adds that directory to your user `PATH`
(override with `-InstallDir`). Every download is verified against the release
`checksums.txt`, and against the Sigstore signature too when
[cosign](https://docs.sigstore.dev/cosign/system_config/installation/) is
installed. Other channels – manual download, `go install`, Homebrew, Scoop –
are in [Advanced: other install channels](#advanced-other-install-channels).

### Upgrade

`cavet update` is the in-place upgrade path: it resolves the latest release,
verifies it exactly like the installers (checksum, plus the Sigstore bundle
when cosign is installed), and swaps the running binary at its real install
location. That location is the reason it exists: re-running an installer
defaults to `~/.local/bin` (or `$HOME\.local\bin`) regardless of where cavet
actually lives, so a Homebrew, Scoop, `go install` or manual install can end
up shadowed by a stale copy. `cavet update --check` only reports whether an
update exists. Development builds (`go install`, `go build`) refuse and point
back at their own channel.

### Engine image

Nothing to install by hand: `cavet init` pulls the engine image,
`ghcr.io/chaoschild/cavet-engine` – public, multi-arch (`linux/amd64`,
`linux/arm64`), and digest-pinned into `.cavet/config.yaml` on first run.

- Two variants: **core** (default – secrets, dependencies, SAST) and **full**
  (adds Trivy's Java vulnerability database); set `engine.variant` in
  `config.yaml`.
- `CAVET_ENGINE_IMAGE` overrides the image reference entirely – local builds,
  mirrors, pinning.
- **Image scanning** via `scan.container_images`: `false` (default), `true`
  (every `Dockerfile*` at the repository root), or an explicit list of
  Dockerfile paths, nested ones included (`engine/Dockerfile`). A list entry
  may also be a map with a build target: `{dockerfile: engine/Dockerfile,
  target: final-core}` – multi-stage Dockerfiles default to the last stage,
  and the stage you actually ship is usually the one worth scanning. `cavet
  image add <path> --target <stage>` writes that form. `cavet image
  add/remove/list` manages the list, so the file never needs hand-editing.
  `cavet scan --image` scans just the configured images: each one is built
  host-side via `docker buildx build` (build progress streams to your
  terminal), handed to the engine as a tar, and scanned offline by Trivy. A
  `--full` scan includes the image phase whenever images are configured, and a
  staged scan (including the pre-commit hook) includes it when one of the
  configured Dockerfiles is itself staged. Mind the pre-commit latency: the
  first build of a changed image takes minutes, and the phase fires only when
  the Dockerfile itself changed.

The image bundles Opengrep, Gitleaks, Trivy and Checkov. Trivy alone already
covers dependencies, IaC misconfiguration and containers from one binary;
Checkov is an optional, off-by-default second IaC scanner for operators who
want its broader IaC rule set, enabled per repository with
`scanners.checkov: true` in `config.yaml`. The Opengrep rule corpus is
LGPL-2.1 + Commons Clause: using cavet is fine, selling a service whose value
derives from those rules is not – see the [licence table](#licence).

### `cavet init`

Run it in the repository you want covered:

```sh
cd your-repo
cavet init             # add --hooks to also install the advisory pre-commit hook
```

It scaffolds `.cavet/`, pulls and starts the engine container, and runs a full
baseline scan that records every pre-existing finding as debt (work through it
later with `cavet debt`). The engine container is per-repository and long-lived:
cavet restarts it when stopped and creates a new one only when absent. Repositories
that get deleted or moved leave their containers behind; `cavet engine prune`
removes those, and `--all` removes every cavet container except the current
repository's.

| Path | Commit? |
|---|---|
| `log/` | yes – the append-only audit trail (`.gitattributes` sets `merge=union` on it) |
| `config.yaml` | yes – engine variant + digest pin |
| `design/` | yes – design decisions |
| `state/`, `cache/`, `reports/` | no – derived; `cavet rebuild` regenerates them |

The scaffolded `.gitignore` already excludes the derived directories. Never
edit `log/` by hand – the CLI is its only author.

### Harness setup

**Skills, any agent, one line.** `npx skills add ChaosChild/cavet` installs the
seven cavet skills into any of 70 supported agents (Claude Code, Codex, OpenCode,
Pi, Hermes, zcode, Cursor, Copilot, Gemini CLI, Windsurf and more). The skills
will walk you through installing the CLI and engine on first use: `cavet-install`
prints the exact command, what it does, and waits for your explicit yes before
running anything. Skills alone are enough to evaluate cavet and how it advises;
the binary and engine are needed to actually scan.

The per-harness routes below copy the six phase skills and add what that line
does not carry: the `cavet-security` subagent and the agent-instruction
snippet, placed where the harness reads them. The binary from the install step
above is still required on either path – the skills drive the CLI, they do not
replace it.

**Claude Code** (plugin, no clone needed):

```
/plugin marketplace add ChaosChild/cavet
/plugin install cavet@cavet
```

**Every other harness** – codex, opencode, pi, hermes, zcode, deepseek – one
line, no clone needed:

```sh
curl -fsSL https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/fetch.sh | bash -s -- --harness codex
```

pwsh (canonical two-step form – a piped script cannot bind `param()`):

```pwsh
irm https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/fetch.ps1 -OutFile fetch.ps1
pwsh -NoProfile -File fetch.ps1 -Harness codex
```

Or from a clone: `bash installers/<harness>.sh` / `pwsh installers/<harness>.ps1`
for any of the seven harnesses. What lands where, per harness:
[installers/README.md](installers/README.md).

### First scan

```sh
git add -A
cavet scan --staged
```

Exit codes are informational, never gating: `0` clean (or nothing staged),
`1` findings present, `2` error. `cavet --help` lists everything;
`cavet describe --json` emits the machine contract for tooling that wants it.

### Advanced: other install channels

<details>
<summary>GitHub Releases manual download · go install · Homebrew · Scoop</summary>

#### GitHub Releases

Pick your OS/arch archive from
<https://github.com/ChaosChild/cavet/releases/latest>, and download
`checksums.txt` and `checksums.txt.sigstore.json` alongside it. cavet is a
security tool: verify before trusting the download. Both the signature and the
checksums are produced by the repo's own release workflow, so pin the
certificate identity to it (no cosign yet?
[Install it](https://docs.sigstore.dev/cosign/system_config/installation/)):

```sh
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github\.com/ChaosChild/cavet/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

sha256sum --check --ignore-missing checksums.txt   # macOS/Linux
# Windows: compare (Get-FileHash cavet_0.1.0_windows_amd64.zip).Hash against checksums.txt
```

Each archive holds the binary (`cavet`, or `cavet.exe` on Windows), `LICENSE`
and `README.md` at its root – `./cavet` runs straight from the extraction
folder, no install step needed. To put it on your `PATH`:

```sh
tar -xzf cavet_0.1.0_linux_amd64.tar.gz   # or: unzip cavet_0.1.0_windows_amd64.zip
sudo install -m 0755 cavet /usr/local/bin/cavet
```

#### go install

```sh
go install github.com/ChaosChild/cavet/cmd/cavet@latest
```

The binary lands in `$GOPATH/bin/cavet` (or `$GOBIN/cavet` if set) – a
directory Ubuntu does not put on your `PATH` by default. Fix:

```sh
echo 'export PATH="$PATH:$(go env GOPATH)/bin"' >> ~/.profile
```

then log out and back in.

#### Homebrew (macOS, Linux)

```sh
brew install --cask chaoschild/tap/cavet
```

#### Scoop (Windows)

```pwsh
scoop bucket add chaoschild https://github.com/ChaosChild/scoop-bucket
scoop install cavet
```

</details>

## What it does

| Command | |
|---|---|
| `init` | Scaffold `.cavet/`, start the engine, record existing debt as baseline |
| `scan` | Run scanners for a scope (`--staged`, `--diff`, `--full`, `--image`) and fold the delta |
| `image` | Manage the Dockerfiles cavet scans as container images: `add`, `remove`, `list` |
| `finding` | Show one finding: row, locations, verdict |
| `debt` | The pre-existing baseline, on demand only |
| `triage` | Record a confirm or dismiss verdict with reason and confidence |
| `suppress` | Silence a finding deliberately, with a reason |
| `defer` | Acknowledge a finding, act later |
| `log` | Read the audit trail, newest first |
| `items` | List open items: design concerns and verification requests |
| `raise` | Open an item: a design concern or a verification request |
| `resolve` | Close an open item with the decision or answer |
| `lookup` | Advisory, package, and rule lookup – identifiers only, by design |
| `engine` | Control the long-lived scanner container; `prune` removes containers whose repository is gone |
| `rebaseline` | After a deliberate engine change: regenerate the baseline |
| `rebuild` | Regenerate `state/` from the log (the source of truth) |
| `describe` | Machine contract for third-party installers |
| `update` | Update the cavet binary in place from GitHub releases, checksum and Sigstore verified |

Judgement lives in the skills: `cavet-design`, `cavet-design-review`,
`cavet-secure-coding`, `cavet-triage`, `cavet-supply-chain`, `cavet-deployment`,
plus the `cavet-install` bootstrap skill that offers the binary install when a
skill cannot find the CLI, and the `cavet-security` subagent that does focused
review with nothing but Read and a cavet-only shell. The skills advise; the CLI
is the only author of `.cavet/` artefacts – every verdict, deferral, and
suppression lands in the log with a reason and an actor.

## Documentation

- [SPECIFICATION.md](docs/SPECIFICATION.md) – what this is and why it is shaped
  this way. The design story, kept in the repo.
- [docs/COMPARISON.md](docs/COMPARISON.md) – how cavet compares with
  `/security-review`, the Aikido plugin, Semgrep Guardian, Snyk, and the
  agent-security tools on a different axis.
- Build and development documentation – implementation history, the spec
  annexes, the scanner spike, the distribution plan, install internals – lives
  at <https://migatchev.co.za/projects/cavet>.

## Licence

`cavet` itself is MIT. See [LICENSE](LICENSE).

**The engine image is not uniformly MIT**, and the difference matters if you intend
to sell something built on this:

| Component | Licence |
|---|---|
| `cavet` CLI, skills, subagent, installers | MIT |
| Gitleaks | MIT |
| Trivy | Apache-2.0 |
| Checkov *(optional, off by default)* | Apache-2.0 |
| git (in the engine image) | GPL-2.0 |
| Opengrep engine | LGPL-2.1 |
| **Opengrep rule corpus** | **LGPL-2.1 + Commons Clause** |

The Opengrep rules are the `semgrep-rules` corpus, licensed by Semgrep, Inc. under
LGPL-2.1 with a Commons Clause condition: you may not *sell* a product or service
whose value derives entirely or substantially from them. Using `cavet`, distributing
it, and building on it are all unaffected. Selling a hosted service whose value comes
substantially from those rules is not.

The rules are only loaded by the deep scan tier. The fast tier – secrets and
dependency scanning, which is what the pre-commit hook and staged scans use – is
entirely MIT and Apache-2.0, and Opengrep can be disabled outright in `config.yaml`.
