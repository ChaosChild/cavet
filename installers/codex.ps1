# cavet installer - Codex CLI
# Copies the six cavet-* skills, writes the cavet-security subagent, and
# appends the instruction snippet to the global instruction file. Idempotent.
# Uninstall: delete cavet-* from the skills dir, the subagent file, and the
# snippet from the instruction file.
#
# Paths (verified 2026-08, sources in installers/README.md):
#   skills        ~/.agents/skills/                      (user level, flat)
#   subagent      $CODEX_HOME/agents/cavet-security.toml (TOML, default ~/.codex)
#   instructions  $CODEX_HOME/AGENTS.md                  (global guidance)
# assumption: Codex custom agents have no per-agent tool allowlist key. The
# closest native restriction is sandbox_mode = "read-only"; the cavet-only
# shell rule is additionally stated in developer_instructions.
#
# -Target <dir> (or env CAVET_INSTALL_TARGET) redirects ALL writes under
# <dir> instead of the real harness home, for testing.

param([string]$Target = "")

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$skillNames = @('cavet-deployment', 'cavet-design', 'cavet-design-review',
                'cavet-secure-coding', 'cavet-supply-chain', 'cavet-triage')
$utf8 = [Text.UTF8Encoding]::new($false)
$marker = 'Never write to .cavet/ directly'
$snippet = @'
Security is part of design, not a phase after it. When we discuss architecture,
features, integrations, data flows, auth, or third-party services, surface security
implications alongside functional ones — one line, at the decision point, via the
cavet-design skill. When code is written, apply cavet-secure-coding. Before commit
or on request, run cavet-triage. Never write to .cavet/ directly; the cavet CLI is
the only author of its log.
'@

# 1. resolve roots: real harness home, or the test target
$target = if ($Target) { $Target } else { $env:CAVET_INSTALL_TARGET }
$codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
$skillsRoot = if ($target) { $target } else { Join-Path $HOME '.agents' }
$agentsRoot = if ($target) { $target } else { $codexHome }
$instrRoot = if ($target) { $target } else { $codexHome }
$skillsDir = Join-Path $skillsRoot 'skills'
$agentsDir = Join-Path $agentsRoot 'agents'
$instrFile = Join-Path $instrRoot 'AGENTS.md'

# 2. copy the six skills (overwrite = remove then copy; uninstall = delete cavet-*)
New-Item -ItemType Directory -Force -Path $skillsDir | Out-Null
foreach ($name in $skillNames) {
    $src = Join-Path (Join-Path $repo 'skills') $name
    if (-not (Test-Path $src)) { throw "missing skill source: $src" }
    $dst = Join-Path $skillsDir $name
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    Copy-Item -Recurse $src $dst
}

# 3. write the subagent in harness format
New-Item -ItemType Directory -Force -Path $agentsDir | Out-Null
$subagent = @'
# cavet-security subagent, translated from subagents/cavet-security.md.
# Tool surface: read-only sandbox (filesystem reads only). Codex has no
# per-agent command allowlist, so the cavet-only shell rule below is
# instruction-enforced.
name = "cavet-security"
description = "Runs a cavet security scan for the given scope and phase, triages every finding, and returns the CLI's structured output verbatim. Use for review-time scans and pre-commit triage."
sandbox_mode = "read-only"
developer_instructions = """
You are the cavet security subagent. You have read access to the repository and
the `cavet` command, and nothing else — by design. Your job is triage and
deduplication, not narration and not remediation. Run the scan for the scope and
phase you were given. For each finding, read the code, decide confirmed or
dismissed, and record it with `cavet triage` with a specific reason and a
confidence. For dependency findings, `cavet lookup` the identifiers first and cite
them in your reason. If a finding turns on a question you cannot answer from code
or advisories, mark it confirmed with low confidence, raise a verification item
with `cavet raise`, and include the question in a `verify` block. Reply with the
CLI's aggregate line, table, next-step hints, and verify block, verbatim. Nothing
else. Follow the `cavet-triage` skill's subagent section.

Shell restriction: only commands that invoke the `cavet` binary. No file writes,
no web, nothing else.

Input (from parent):

    scope: staged | diff <ref> | full | path <p>
    phase: build | test | deploy
    context: <optional, a few lines: files not to touch, prior decisions, intent>

Output (to parent) — exactly this, nothing else:

    <CLI aggregate line>
    <CLI findings table — confirmed only>
    <CLI next: hints>
    verify[n]{id,question}:        # only if any raised
      <id>,<question>
"""
'@
$subagentFile = Join-Path $agentsDir 'cavet-security.toml'
[IO.File]::WriteAllText($subagentFile, $subagent, $utf8)

# 4. append the instruction snippet, idempotently
if ((Test-Path $instrFile) -and (Select-String -SimpleMatch -Quiet $marker $instrFile)) {
    $instrAction = 'already present'
} else {
    [IO.File]::AppendAllText($instrFile, "`n$snippet`n", $utf8)
    $instrAction = 'appended'
}

# 5. summary
Write-Host 'cavet -> Codex'
Write-Host "  skills       : $skillsDir ($($skillNames.Count) cavet-* dirs)"
Write-Host "  subagent     : $subagentFile"
Write-Host "  instructions : $instrFile ($instrAction)"
