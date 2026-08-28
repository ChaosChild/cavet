# cavet end-to-end smoke (implementation-plan Task 21).
# Builds the CLI, drives init/scan/triage/log/items against the spike fixture
# in a throwaway git repo, and asserts the artefacts landed. Needs Docker and
# a local engine image (default cavet-engine:dev, override -EngineImage).

param([string]$EngineImage = "cavet-engine:dev")

$ErrorActionPreference = 'Stop'
$env:CAVET_ENGINE_IMAGE = $EngineImage

# --- helpers ---

function Assert-True([bool]$Cond, [string]$What) {
    if (-not $Cond) { throw "assertion failed: $What" }
}

function Invoke-Exe([string]$FilePath, [string[]]$Arguments, [string]$WorkingDirectory) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $FilePath
    foreach ($a in $Arguments) { [void]$psi.ArgumentList.Add($a) }
    $psi.WorkingDirectory = $WorkingDirectory
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.UseShellExecute = $false
    $p = [System.Diagnostics.Process]::Start($psi)
    $out = $p.StandardOutput.ReadToEnd()
    $err = $p.StandardError.ReadToEnd()
    $p.WaitForExit()
    [pscustomobject]@{ Code = $p.ExitCode; Out = $out; Err = $err }
}

# High-entropy alnum key, deliberately distinct from the fixture's SERVICE_API_KEY,
# shaped so gitleaks' generic-api-key rule flags the staged content.
$SmokeKey = 'Xk49Wq7Rt2ZhB8VyNc3Jm6LpQd4FsGwKr5TwYb2HnUeA7xDc'

# --- build ---

if (-not (Get-Command go -ErrorAction SilentlyContinue) -and $IsWindows) {
    $env:Path = "C:\Program Files\Go\bin;$env:Path" # AGENTS.md: Go lives here on dev machines
}
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "go toolchain not on PATH" }

$Base = Join-Path ([IO.Path]::GetTempPath()) ("cavet-smoke-" + [guid]::NewGuid().ToString('N').Substring(0, 12))
$Repo = Join-Path $Base 'repo'
$Exe = Join-Path $Base $(if ($IsWindows) { 'cavet.exe' } else { 'cavet' })
$RepoRoot = Split-Path $PSScriptRoot -Parent
$Fixture = Join-Path $RepoRoot 'internal/finding/testdata/fixture'

function Cavet([string[]]$Arguments) { Invoke-Exe $Exe $Arguments $Repo }
function Git([string[]]$Arguments) { Invoke-Exe 'git' $Arguments $Repo }

try {
    [void](New-Item -ItemType Directory -Path $Base)
    Write-Host "1. build binary"
    $go = Invoke-Exe (Get-Command go).Source @('build', '-o', $Exe, './cmd/cavet') $RepoRoot
    Assert-True ($go.Code -eq 0) "go build failed: $($go.Err)"

    Write-Host "2. fixture temp repo"
    Copy-Item -Recurse $Fixture $Repo
    [void](Git @('init'))
    [void](Git @('add', '-A'))
    [void](Git @('-c', 'user.name=smoke', '-c', 'user.email=smoke@test', 'commit', '-qm', 'fixture'))

    Write-Host "3. cavet init (baseline scan, ~1 min)"
    $r = Cavet @('init')
    Assert-True ($r.Code -eq 0 -and $r.Out -match 'initialised\.') "init failed (exit $($r.Code)): $($r.Err)"

    Write-Host "4. baseline covers planted findings"
    $r = Cavet @('debt')
    Assert-True ($r.Code -eq 0) "debt failed: $($r.Err)"
    Assert-True ($r.Out -match 'baseline: (\d+) findings') "debt output has no baseline count"
    $BaselineCount = [int]$Matches[1]
    Assert-True ($BaselineCount -ge 5) "baseline $BaselineCount < 5 planted findings"

    Write-Host "5. staged scan finds the new secret (exit 1)"
    Add-Content -Path (Join-Path $Repo 'api/users.py') -Value "`n# smoke marker`nSMOKE_TEST_KEY = `"$SmokeKey`""
    [void](Git @('add', 'api/users.py'))
    $r = Cavet @('scan', '--staged')
    Assert-True ($r.Code -eq 1) "scan --staged exit $($r.Code), want 1"
    Assert-True ($r.Out -match 'generic-api-key') "scan output lacks the secret finding"
    Assert-True ($r.Out -match '\|\s*([0-9a-f]{6})\s*\|[^\r\n]*generic-api-key') "no display id next to the finding"
    $FindingId = $Matches[1]

    Write-Host "6. triage dismiss ($FindingId)"
    $r = Cavet @('triage', $FindingId, '--dismiss', '--reason', 'fixture', '--confidence', 'high')
    Assert-True ($r.Code -eq 0) "triage failed: $($r.Err)"

    Write-Host "7. log shows detected + triaged"
    $r = Cavet @('log', '--fingerprint', $FindingId)
    Assert-True ($r.Code -eq 0) "log failed: $($r.Err)"
    Assert-True ($r.Out -match 'detected') "log lacks a detected event"
    Assert-True ($r.Out -match 'triaged') "log lacks a triaged event"

    Write-Host "8. raise / items / resolve round-trip"
    $r = Cavet @('raise', '--kind', 'design', '--question', 'smoke: is the fixture representative?')
    Assert-True ($r.Code -eq 0 -and $r.Out -match '(it-[0-9a-f]{8})') "raise failed: $($r.Out)$($r.Err)"
    $ItemId = $Matches[1]
    $r = Cavet @('items')
    Assert-True ($r.Code -eq 0 -and $r.Out -match [regex]::Escape($ItemId)) "items does not list $ItemId"
    $r = Cavet @('resolve', $ItemId, '--answer', 'yes, by design')
    Assert-True ($r.Code -eq 0) "resolve failed: $($r.Err)"
    $r = Cavet @('items')
    Assert-True ($r.Code -eq 0 -and $r.Out -notmatch [regex]::Escape($ItemId)) "items still lists $ItemId"

    Write-Host "9. clean staged scan (exit 0, 0 new findings)"
    [void](Git @('-c', 'user.name=smoke', '-c', 'user.email=smoke@test', 'commit', '-qm', 'smoke key'))
    Set-Content -Path (Join-Path $Repo 'README.md') -Value '# smoke', 'benign documentation change'
    [void](Git @('add', 'README.md'))
    $r = Cavet @('scan', '--staged')
    Assert-True ($r.Code -eq 0) "clean scan exit $($r.Code), want 0: $($r.Out)$($r.Err)"
    Assert-True ($r.Out -match '0 new findings') "clean scan did not report 0 new findings"

    Write-Host "10. reports/latest.sarif exists"
    $Sarif = Join-Path $Repo '.cavet/reports/latest.sarif'
    Assert-True (Test-Path $Sarif) "missing $Sarif"
    Assert-True ((Get-Item $Sarif).Length -gt 0) "latest.sarif is empty"

    Write-Host "SMOKE OK"
}
finally {
    if (Test-Path (Join-Path $Repo '.cavet')) {
        [void](Cavet @('engine', 'stop')) # release the bind mount before deleting
    }
    foreach ($attempt in 1..2) { # Windows file locks clear slowly
        try { Remove-Item -Recurse -Force $Base -ErrorAction Stop; break } catch { Start-Sleep -Seconds 2 }
    }
}
