# cavet fetch-installer (pwsh) - installs a cavet harness installer without a
# local clone: resolves the requested release (default: latest), downloads the
# tag tarball from GitHub, extracts it to a temp dir, and runs
# installers/<harness>.ps1 from there. -Target (or CAVET_INSTALL_TARGET) is
# forwarded to that installer.
#
# Usage (canonical two-step form - a piped script cannot bind param()):
#   irm https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/fetch.ps1 -OutFile fetch.ps1
#   pwsh -NoProfile -File fetch.ps1 -Harness claude-code
# Pipe-safe one-liner (scriptblock invocation binds params; -Harness may also
# arrive positionally or via $args):
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/ChaosChild/cavet/main/installers/fetch.ps1))) -Harness claude-code
#
# CAVET_FETCH_SOURCE=<dir> (test hook): use <dir> as the already-extracted
# source tree instead of downloading anything.

param([string]$Harness = "", [string]$Version = "latest", [string]$Target = "")

$ErrorActionPreference = 'Stop'

# Pipe fallback: accept the harness/version/target tokens via $args when
# param() did not bind them.
if (($Harness -eq '') -and $args) {
    $rest = @($args)
    for ($i = 0; $i -lt $rest.Count; $i++) {
        switch -Regex ($rest[$i]) {
            '^-+harness$' { $Harness = $rest[++$i] }
            '^-+version$' { $Version = $rest[++$i] }
            '^-+target$'  { $Target = $rest[++$i] }
            default       { if (($Harness -eq '') -and ($rest[$i] -notmatch '^-')) { $Harness = $rest[$i] } }
        }
    }
}

$harnesses = 'claude-code', 'codex', 'opencode', 'pi', 'hermes', 'zcode', 'deepseek'
if ($Harness -eq '') { throw "usage: fetch.ps1 -Harness <name> [-Version <x.y.z|latest>] [-Target <dir>] (harnesses: $($harnesses -join ', '))" }
if ($harnesses -notcontains $Harness) { throw "unknown harness '$Harness' (want one of: $($harnesses -join ', '))" }

$tmp = $null
try {
    if ($env:CAVET_FETCH_SOURCE) {
        $src = $env:CAVET_FETCH_SOURCE
    } else {
        if ($Version -eq 'latest') {
            $Version = (Invoke-RestMethod 'https://api.github.com/repos/ChaosChild/cavet/releases/latest').tag_name
            if (-not $Version) { throw 'could not resolve latest release from the GitHub API' }
        }
        $Version = $Version.TrimStart('v')
        Write-Host "fetching cavet $Version"
        $tmp = Join-Path ([IO.Path]::GetTempPath()) ("cavet-fetch-" + [guid]::NewGuid().ToString('N').Substring(0, 12))
        New-Item -ItemType Directory -Path $tmp | Out-Null
        $tgz = Join-Path $tmp 'src.tar.gz'
        Invoke-WebRequest -Uri "https://github.com/ChaosChild/cavet/archive/refs/tags/v$Version.tar.gz" -OutFile $tgz
        tar -xzf $tgz -C $tmp # tar.exe ships with Windows 10+ and macOS
        $src = Get-ChildItem -Directory -Path $tmp -Filter 'cavet-*' | Select-Object -First 1
        if (-not $src) { throw 'archive did not extract a cavet-* directory' }
    }

    $installer = Join-Path $src "installers/$Harness.ps1"
    if (-not (Test-Path $installer)) { throw "installer not found: $installer" }
    if ($Target) { & $installer -Target $Target } else { & $installer }
} finally {
    if ($tmp) { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
}
