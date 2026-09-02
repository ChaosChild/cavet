# cavet binary installer (pwsh, Windows) - resolves a GitHub release
# (default: latest), downloads the windows/arch archive, verifies it against
# checksums.txt (and the Sigstore bundle when cosign is installed), installs
# cavet.exe, and puts the install directory on the user PATH.
#
# Usage (canonical two-step form - a piped script cannot bind param()):
#   irm https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/binary.ps1 -OutFile binary.ps1
#   pwsh -NoProfile -File binary.ps1
# Pipe-safe one-liner (scriptblock invocation binds named params):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/binary.ps1))) -Version 0.1.0
#
# -Version <x.y.z|latest>  release to install (default: latest)
# -InstallDir <path>       install directory (default: $HOME\.local\bin)

param([string]$Version = 'latest', [string]$InstallDir = '')

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # Invoke-WebRequest is 10x slower with the progress bar

if (-not $InstallDir) {
    $InstallDir = if ($env:CAVET_INSTALL_DIR) { $env:CAVET_INSTALL_DIR } else { Join-Path $HOME '.local\bin' }
}

$platform = $PSVersionTable.Platform
if ($platform -and $platform -ne 'Win32NT') {
    throw "unsupported platform '$platform' - this installer is for Windows; on macOS/Linux use installers/binary.sh"
}
$arch = $env:PROCESSOR_ARCHITECTURE
switch ($arch) {
    'AMD64' { $arch = 'amd64' }
    'ARM64' { $arch = 'arm64' }
    default { throw "unsupported architecture '$arch' (`$env:PROCESSOR_ARCHITECTURE); supported: AMD64, ARM64" }
}

if ($Version -eq 'latest') {
    $Version = (Invoke-RestMethod 'https://api.github.com/repos/ChaosChild/cavet/releases/latest').tag_name
    if (-not $Version) { throw 'could not resolve latest release from the GitHub API' }
}
$v = $Version.TrimStart('v')
$base = "https://github.com/ChaosChild/cavet/releases/download/v$v"
$archive = "cavet_${v}_windows_${arch}.zip"

$tmp = $null
try {
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ("cavet-binary-" + [guid]::NewGuid().ToString('N').Substring(0, 12))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    Write-Host "installing cavet $v for windows/$arch into $InstallDir"
    $checksums = Join-Path $tmp 'checksums.txt'
    Invoke-WebRequest -Uri "$base/checksums.txt" -OutFile $checksums
    $archivePath = Join-Path $tmp $archive
    Invoke-WebRequest -Uri "$base/$archive" -OutFile $archivePath

    # 1. checksum (Get-FileHash is uppercase hex; -eq compares case-insensitively)
    $actual = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash
    $expected = Get-Content $checksums | Where-Object { $_ -match "  $([regex]::Escape($archive))`$" } | ForEach-Object { ($_ -split '\s+')[0] }
    if (-not $expected) { throw "checksums.txt has no entry for $archive" }
    if ($actual -ne $expected) { throw "checksum mismatch for $archive - nothing installed" }

    # 2. signature: verified only when cosign is on PATH (hard error on failure)
    if (Get-Command cosign -ErrorAction SilentlyContinue) {
        $bundle = Join-Path $tmp 'checksums.txt.sigstore.json'
        Invoke-WebRequest -Uri "$base/checksums.txt.sigstore.json" -OutFile $bundle
        & cosign verify-blob --bundle $bundle `
            --certificate-identity-regexp '^https://github\.com/ChaosChild/cavet/\.github/workflows/release\.yml@' `
            --certificate-oidc-issuer https://token.actions.githubusercontent.com `
            $checksums
        if ($LASTEXITCODE -ne 0) { throw 'signature verification failed - nothing installed' }
    } else {
        Write-Host 'checksum verified; signature not verified (cosign not installed)'
    }

    # 3. install + user PATH
    Expand-Archive -Path $archivePath -DestinationPath $tmp
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    $dest = Join-Path $InstallDir 'cavet.exe'
    Copy-Item -LiteralPath (Join-Path $tmp 'cavet.exe') -Destination $dest -Force

    $dirs = @([Environment]::GetEnvironmentVariable('Path', 'User') -split ';' | Where-Object { $_ })
    if ($dirs -notcontains $InstallDir) {
        [Environment]::SetEnvironmentVariable('Path', (($dirs + $InstallDir) -join ';'), 'User')
        Write-Host "added $InstallDir to the user PATH - open a new terminal for it to take effect"
    }

    Write-Host "installed : $dest"
    $versionOut = & $dest --version
    if ($LASTEXITCODE -eq 0 -and $versionOut) { Write-Host "version   : $versionOut" }
} finally {
    if ($tmp) { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}
