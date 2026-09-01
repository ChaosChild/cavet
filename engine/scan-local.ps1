# cavet engine image local scan (the dev-machine half of the image security
# process; release.yml holds the release-time CI gate and image-posture.yml
# the weekly shipped-image alarm).
#
# Principle: engine images are immutable per release, so they are scanned when
# built, on the dev machine, with findings logged and fixed before any release.
# Each variant is built via engine/build.ps1's no-Push path (reuse, not
# duplication), then trivy is run FROM the just-built image against the image
# itself through the docker socket: the same trivy binary and baked DB the
# engine ships with examines its own image.
#
# Logging: the full table report is printed and written to
# engine/scan-reports/scan-<variant>-<yyyyMMdd-HHmmss>.txt (local history,
# gitignored) and, when the repo has a .cavet scaffold, best-effort to
# .cavet/reports/image-scan-<variant>.txt (skipped silently when .cavet is not
# initialised).
#
# Gate: any CRITICAL fails with exit 1 - fix before release; do not ship past
# unresolved criticals. HIGH is reported but never fails.
#
# Usage:
#   pwsh engine/scan-local.ps1                    # build + scan core, full
#   pwsh engine/scan-local.ps1 -SkipBuild         # scan existing local tags
#   pwsh engine/scan-local.ps1 -Variants core
#   pwsh engine/scan-local.ps1 -Severity CRITICAL

param(
    [string[]]$Variants = @('core', 'full'),
    [switch]$SkipBuild,
    [string[]]$Severity = @('HIGH', 'CRITICAL'),
    [string]$EngineImage = 'cavet-engine' # repo prefix; :<variant> is appended (local tags, NOT the dev alias)
)

$ErrorActionPreference = 'Stop'
$RepoRoot = Split-Path $PSScriptRoot -Parent

$Variants = @($Variants | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() })
$Severity = @($Severity | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToUpperInvariant() })
foreach ($v in $Variants) {
    if ($v -notin 'core', 'full') { throw "unknown variant '$v' (want: core, full)" }
}

# Reuse the existing local-build path rather than re-implementing it.
if (-not $SkipBuild) {
    & (Join-Path $PSScriptRoot 'build.ps1') -Variants $Variants
}

$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$ScanDir = Join-Path $PSScriptRoot 'scan-reports'
[void](New-Item -ItemType Directory -Path $ScanDir -Force)
$CavetReports = Join-Path $RepoRoot '.cavet/reports'

$TotalCritical = 0
$TotalHigh = 0
foreach ($v in $Variants) {
    $ref = '{0}:{1}' -f $EngineImage, $v
    if ($SkipBuild) {
        & docker image inspect $ref *> $null
        if ($LASTEXITCODE -ne 0) { throw "no local image $ref; drop -SkipBuild or run engine/build.ps1 first" }
    }

    Write-Host ''
    Write-Host "scan $ref (trivy from the image itself, via the docker socket)"
    # --quiet: table only - keeps console and stored reports free of DB-download
    # progress noise; trivy errors still print (and fail the run below).
    $scanArgs = @('run', '--rm', '-v', '/var/run/docker.sock:/var/run/docker.sock',
        $ref, 'trivy', 'image', '--quiet', '--severity', ($Severity -join ','), '--ignore-unfixed', $ref)
    $report = (& docker @scanArgs 2>&1) -join "`n"
    if ($LASTEXITCODE -ne 0) { throw "trivy scan of $ref failed (exit $LASTEXITCODE)`n$report" }
    Write-Host $report

    # Tally from trivy's per-target "Total: N (…)" summary lines; severities
    # trivy omits (zero count) stay 0.
    $critical = 0
    $high = 0
    foreach ($m in [regex]::Matches($report, 'Total:\s*\d+\s*\(([^)]*)\)')) {
        foreach ($p in [regex]::Matches($m.Groups[1].Value, '(CRITICAL|HIGH):\s*(\d+)')) {
            if ($p.Groups[1].Value -eq 'CRITICAL') { $critical += [int]$p.Groups[2].Value }
            else { $high += [int]$p.Groups[2].Value }
        }
    }
    $TotalCritical += $critical
    $TotalHigh += $high

    $scanReport = Join-Path $ScanDir ('scan-{0}-{1}.txt' -f $v, $Stamp)
    Set-Content -Path $scanReport -Value $report
    if (Test-Path $CavetReports) { # best-effort cavet-native copy; silent skip when not initialised
        Set-Content -Path (Join-Path $CavetReports ('image-scan-{0}.txt' -f $v)) -Value $report
    }

    Write-Host ''
    Write-Host "report: $scanReport"
    Write-Host "TALLY $v`: CRITICAL $critical, HIGH $high"
}

if (($TotalCritical + $TotalHigh) -gt 0) {
    Write-Host ''
    Write-Host 'Accepted-risk trail: for each finding you accept rather than fix, record the'
    Write-Host 'decision with: cavet raise --kind verification --question "<finding and why it is accepted>",'
    Write-Host 'then close it later with: cavet resolve <item> --answer "<judgement>".'
    Write-Host 'Findings live in the report; judgements live in the audit trail.'
}

Write-Host ''
if ($TotalCritical -gt 0) {
    Write-Host "GATE FAILED: $TotalCritical CRITICAL finding(s) - fix before release; do not ship past unresolved criticals."
    exit 1
}
Write-Host 'gate passed: no CRITICAL findings'
exit 0
