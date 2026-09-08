---
name: cavet-install
description: Install the cavet CLI when a cavet skill needs it and the binary is missing. Does nothing when cavet already works.
---

# cavet-install

Bootstrap skill. A cavet skill tried to run `cavet` and could not, or you were
asked to set cavet up. Your job is to get the binary installed with the
operator's explicit consent, then hand back to whichever skill triggered.

Do not run an install unasked, and do not treat a general "help me set up cavet"
as consent to pipe a remote script into a shell. cavet's argument is that
security actions are visible and confirmed rather than automatic, and the
install is the first one.

## Sequence

1. **Diagnose.** Run bare `cavet` and read the failure; the table below maps the
   usual failures to actions. If the binary answers at all, you were invoked by
   mistake: say so and stop.
2. **Propose.** Print the exact install command for the platform (below), what it
   will do: download the release archive for the OS/arch from GitHub Releases,
   verify it against the release `checksums.txt` (and against the Sigstore
   signature when cosign is on PATH), write one binary into `~/.local/bin`
   (macOS, Linux) or `$HOME\.local\bin` plus a user `PATH` entry (Windows).
   Nothing else is written.
3. **Ask** for an explicit yes, in that turn.
4. **Run** only on a clear yes. On anything else, leave the command printed for
   the operator and stop.
5. **Verify.** `cavet describe --json` must answer. Then `cavet init` in the
   repository (offer `--hooks` for the advisory pre-commit hook); it scaffolds
   `.cavet/` and pulls the engine image, digest-pinned.
6. **Return** to whichever skill originally triggered and resume it.

## Diagnostics

| Symptom | Cause | Action |
|---|---|---|
| `cavet: command not found` | no binary | offer the platform install command, confirm, run |
| daemon unreachable | Docker not running | ask the operator to start Docker, then `cavet init` |
| no `.cavet/` in the repo | not initialised | `cavet init`, `--hooks` for the advisory pre-commit hook |
| engine image absent | first run | `cavet init` pulls `ghcr.io/chaoschild/cavet-engine`, digest-pinned into `.cavet/config.yaml` |
| binary present but stale | old install | `cavet update`, `--check` to report only; it swaps at the real install location, so a Homebrew or Scoop copy is not left shadowing |

## Install commands

```sh
# macOS / Linux, installs into ~/.local/bin
curl -fsSL https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/binary.sh | bash
```

```pwsh
# Windows, two steps because a piped script cannot bind param()
irm https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/binary.ps1 -OutFile binary.ps1
pwsh -NoProfile -File binary.ps1
```

Other channels (manual download, `go install`, Homebrew, Scoop) are in the repo
README; the two commands above are the ones the binary installers document.
