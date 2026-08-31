# cavet installer - DeepSeek Harness (dsh)
# Copies the six cavet-* skills, writes the translated cavet-security
# definition, and appends the instruction snippet to the user-global
# instruction file. Idempotent. Uninstall: delete cavet-* from the skills dir,
# the definition file, and the snippet from the instruction file.
#
# Paths (verified 2026-08, sources in installers/README.md):
#   skills        $DSH_HOME/skills/                   (user root, flat; default ~/.dsh)
#   subagent      $DSH_HOME/cavet-security.md         (documented file, see note)
#   instructions  $DSH_HOME/AGENTS.md                 (user-global instruction file)
# limitation: dsh subagents are created at call time (delegation via the
# subagent tool), not by files; tool restriction is a per-request `toolFilter`
# on the delegation. The translated definition is a documented file; paste its
# body into the delegation and restrict the child's tools there to Read +
# shell scoped to `cavet`.
# note: dsh also scans ~/.agents/skills (after $DSH_HOME/skills), so cavet
# skills installed for codex/pi are discoverable too; this installer writes the
# dsh-native root, which dsh scans first.
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
$dshHome = if ($env:DSH_HOME) { $env:DSH_HOME } else { Join-Path $HOME '.dsh' }
$harnessHome = if ($target) { $target } else { $dshHome }
$skillsDir = Join-Path $harnessHome 'skills'
$instrFile = Join-Path $harnessHome 'AGENTS.md'

# 2. copy the six skills (overwrite = remove then copy; uninstall = delete cavet-*)
New-Item -ItemType Directory -Force -Path $skillsDir | Out-Null
foreach ($name in $skillNames) {
    $src = Join-Path (Join-Path $repo 'skills') $name
    if (-not (Test-Path $src)) { throw "missing skill source: $src" }
    $dst = Join-Path $skillsDir $name
    if (Test-Path $dst) { Remove-Item -Recurse -Force $dst }
    Copy-Item -Recurse $src $dst
}

# 3. write the subagent definition as a documented file
New-Item -ItemType Directory -Force -Path $harnessHome | Out-Null
$subagent = @'
# cavet-security subagent definition
# (translated from the "Subagent role" section of skills/cavet-triage/SKILL.md)

dsh subagents are created at call time via delegation; there is no definition
file format (verified 2026-08). Tool restriction is a per-request `toolFilter`
on the delegation. This file is the documented source for the subagent prompt.
To use it, paste the body below into the delegation request and set the child's
toolFilter to Read (repository files) + shell scoped to the `cavet` binary.
Nothing else.

---

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
'@
$subagentFile = Join-Path $harnessHome 'cavet-security.md'
[IO.File]::WriteAllText($subagentFile, $subagent, $utf8)

# 4. append the instruction snippet, idempotently
if ((Test-Path $instrFile) -and (Select-String -SimpleMatch -Quiet $marker $instrFile)) {
    $instrAction = 'already present'
} else {
    [IO.File]::AppendAllText($instrFile, "`n$snippet`n", $utf8)
    $instrAction = 'appended'
}

# 5. summary
Write-Host 'cavet -> DeepSeek Harness (dsh)'
Write-Host "  skills       : $skillsDir ($($skillNames.Count) cavet-* dirs)"
Write-Host "  subagent     : $subagentFile (documented file; dsh subagents are call-time)"
Write-Host "  instructions : $instrFile ($instrAction)"
