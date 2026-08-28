# cavet engine image build/publish (implementation-plan Task 23; engine-spec §9).
#
# Default (no -Push): local single-platform build of each requested variant,
# tagged cavet-engine:<variant> via --load. Nothing is pushed, nothing recorded.
#
# -Push: multi-arch manifest per variant pushed to -Registry as :<variant>,
# plus the :<variant>-<digest8> alias retag (engine-spec §1), then each
# variant's manifest digest is written to engine/digest.txt.
#
# digest.txt format: one line per variant, "<variant> <manifest-digest>"
# (e.g. "core sha256:abcd…"); '#' lines are comments. Committed after each
# release as the reviewable record of what shipped (engine-spec §9.3).

param(
    [string]$Registry = 'ghcr.io/chaoschild/cavet-engine',
    [string[]]$Variants = @('core', 'full'),
    [string[]]$Platforms = @('linux/amd64', 'linux/arm64'),
    [switch]$Push
)

$ErrorActionPreference = 'Stop'

# Variant tag -> Dockerfile final stage (engine-spec §1: differ only in Trivy java-db).
$Targets = @{ core = 'final-core'; full = 'final-full' }
$Variants = @($Variants | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() })
$Platforms = @($Platforms | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() })
foreach ($v in $Variants) {
    if (-not $Targets.ContainsKey($v)) { throw "unknown variant '$v' (want: core, full)" }
}

function Invoke-Docker([string[]]$Arguments) {
    & docker @Arguments
    if ($LASTEXITCODE -ne 0) { throw "docker $($Arguments -join ' ') failed (exit $LASTEXITCODE)" }
}

# Multi-arch --push needs a container-driver builder; the default docker driver
# refuses it. Created once, reused after.
if ($Push) {
    if (((& docker buildx ls) -join "`n") -notmatch 'cavet-multiarch') {
        Invoke-Docker @('buildx', 'create', '--name', 'cavet-multiarch', '--bootstrap')
    }
    Invoke-Docker @('buildx', 'use', 'cavet-multiarch')
}

$Dockerfile = Join-Path $PSScriptRoot 'Dockerfile'
$DigestFile = Join-Path $PSScriptRoot 'digest.txt'
$DigestLines = @()

foreach ($v in $Variants) {
    if ($Push) {
        $ref = '{0}:{1}' -f $Registry, $v
        Write-Host "build + push $ref ($($Platforms -join ', '))"
        $meta = Join-Path ([IO.Path]::GetTempPath()) "cavet-engine-$v.json"
        Invoke-Docker @('buildx', 'build',
            "--platform=$($Platforms -join ',')", "--tag=$ref",
            "--target=$($Targets[$v])", '--push', "--metadata-file=$meta",
            '-f', $Dockerfile, $PSScriptRoot)
        $digest = (Get-Content -Raw $meta | ConvertFrom-Json).'containerimage.digest'
        $d8 = $digest -replace '^sha256:', ''
        $d8 = $d8.Substring(0, 8)
        Invoke-Docker @('buildx', 'imagetools', 'create', '-t', ('{0}:{1}-{2}' -f $Registry, $v, $d8), $ref)
        $DigestLines += "$v $digest"
        Write-Host "pushed $ref @ $digest (alias tag $v-$d8)"
    }
    else {
        $plat = $Platforms[0]
        if ($Platforms.Count -gt 1) { Write-Host "local build is single-platform; using $plat (-Push for multi-arch)" }
        $ref = 'cavet-engine:{0}' -f $v
        Write-Host "build $ref ($plat, local --load)"
        Invoke-Docker @('buildx', 'build',
            "--platform=$plat", "--tag=$ref",
            "--target=$($Targets[$v])", '--load',
            '-f', $Dockerfile, $PSScriptRoot)
        Write-Host "built $ref locally (no push, no digest recorded)"
    }
}

if ($Push) {
    Set-Content -Path $DigestFile -Value (@(
        '# cavet engine published digests - format: "<variant> <manifest-digest>", one line per variant.'
        '# Record of what shipped; committed after each release (engine-spec §9.3).'
    ) + $DigestLines)
    Write-Host "wrote $DigestFile"
}
