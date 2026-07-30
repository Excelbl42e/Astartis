# npcap_verify_helper build script
#
# Prerequisites:
#   - Visual Studio 2019/2022 (any edition) installed
#   - Npcap SDK installed (auto-detected from common locations)
#
# Usage (from bridge/npcap_verify_helper/ directory):
#   .\build.ps1
#
# Output: npcap_verify_helper.exe (copied to ..\..\dashboard\ for auto-discovery)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# 1. Auto-detect Npcap SDK
# ---------------------------------------------------------------------------
$NpcapCandidates = @(
    'C:\npcap-sdk',
    'C:\Program Files\Npcap',
    'C:\Program Files (x86)\Npcap',
    "$env:LOCALAPPDATA\Npcap"
)

$NpcapSDK = $null
foreach ($candidate in $NpcapCandidates) {
    if (Test-Path "$candidate\Include\pcap.h") {
        $NpcapSDK = $candidate
        break
    }
}

if (-not $NpcapSDK) {
    Write-Error @"
Npcap SDK not found. Searched:
  $($NpcapCandidates -join "`n  ")

Install the Npcap SDK from https://npcap.com/#download
and re-run this script.
"@
    exit 1
}

$NpcapInc = "$NpcapSDK\Include"
$NpcapLib = "$NpcapSDK\Lib\x64"

if (-not (Test-Path "$NpcapLib\wpcap.lib")) {
    Write-Error "wpcap.lib not found at $NpcapLib. Check SDK install."
    exit 1
}

Write-Host "[npcap_verify_helper] Npcap SDK: $NpcapSDK"

# ---------------------------------------------------------------------------
# 2. Bootstrap MSVC environment (cl.exe / mt.exe) if not already in PATH
# ---------------------------------------------------------------------------
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    Write-Host "[npcap_verify_helper] cl.exe not in PATH - searching for MSVC..."

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (-not (Test-Path $vswhere)) {
        # VS 2022+ installs vswhere under ProgramFiles, not ProgramFiles(x86)
        $vswhere = "$env:ProgramFiles\Microsoft Visual Studio\Installer\vswhere.exe"
    }

    if (-not (Test-Path $vswhere)) {
        Write-Error "vswhere.exe not found. Install Visual Studio 2019 or 2022 (any edition including Build Tools)."
        exit 1
    }

    $vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2>$null
    if (-not $vsPath) {
        # Fallback: any VS install
        $vsPath = & $vswhere -latest -products * -property installationPath 2>$null
    }

    if (-not $vsPath) {
        Write-Error "No Visual Studio installation found. Install VS 2019/2022 with C++ workload."
        exit 1
    }

    Write-Host "[npcap_verify_helper] Visual Studio: $vsPath"

    # Find vcvars64.bat
    $vcvars = "$vsPath\VC\Auxiliary\Build\vcvars64.bat"
    if (-not (Test-Path $vcvars)) {
        Write-Error "vcvars64.bat not found at $vcvars"
        exit 1
    }

    Write-Host "[npcap_verify_helper] Loading MSVC environment from vcvars64.bat..."

    # Execute vcvars64.bat and capture the resulting environment variables into this PS session
    $envDump = cmd.exe /c "`"$vcvars`" >nul 2>&1 && set"
    foreach ($line in $envDump) {
        if ($line -match '^([^=]+)=(.*)$') {
            [System.Environment]::SetEnvironmentVariable($Matches[1], $Matches[2], 'Process')
        }
    }

    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
        Write-Error "cl.exe still not found after loading vcvars64.bat. Check VS C++ workload is installed."
        exit 1
    }

    Write-Host "[npcap_verify_helper] MSVC environment loaded."
}

$clVer = $null
try {
    $clOut = $null
    $ErrorActionPreference = 'Continue'
    $clOut = & cl.exe 2>&1
    $ErrorActionPreference = 'Stop'
    $clVer = ($clOut | Select-Object -First 1).ToString().Trim()
} catch { $clVer = 'unknown' }
Write-Host "[npcap_verify_helper] Compiler: $clVer"

# ---------------------------------------------------------------------------
# 3. Compile
# ---------------------------------------------------------------------------
$src  = "npcap_verify_helper.cpp"
$out  = "npcap_verify_helper.exe"
$mfst = "npcap_verify_helper.manifest"

if (-not (Test-Path $src)) {
    Write-Error "Source file not found: $src. Run this script from the bridge\npcap_verify_helper\ directory."
    exit 1
}

Write-Host "[npcap_verify_helper] Compiling $src..."

& cl.exe /nologo /W3 /O2 /EHsc /std:c++17 `
    "/I$NpcapInc" `
    $src `
    /link `
    "/LIBPATH:$NpcapLib" `
    wpcap.lib ws2_32.lib `
    "/OUT:$out" `
    /SUBSYSTEM:CONSOLE

if ($LASTEXITCODE -ne 0) {
    Write-Error "[npcap_verify_helper] Compilation FAILED (exit $LASTEXITCODE)"
    exit 1
}

Write-Host "[npcap_verify_helper] Compilation succeeded."

# ---------------------------------------------------------------------------
# 4. Embed UAC manifest (requireAdministrator)
# ---------------------------------------------------------------------------
if (Test-Path $mfst) {
    $mtCmd = Get-Command mt.exe -ErrorAction SilentlyContinue
    if ($mtCmd) {
        Write-Host "[npcap_verify_helper] Embedding manifest (requireAdministrator)..."
        & mt.exe -nologo -manifest $mfst "-outputresource:${out};1"
        if ($LASTEXITCODE -eq 0) {
            Write-Host "[npcap_verify_helper] Manifest embedded successfully."
        } else {
            Write-Warning "[npcap_verify_helper] mt.exe failed (exit $LASTEXITCODE) - manifest not embedded."
            Write-Warning "  The runas verb in DashboardServer still forces UAC on every run."
        }
    } else {
        Write-Warning "[npcap_verify_helper] mt.exe not found - manifest not embedded."
        Write-Warning "  The runas verb in DashboardServer still forces UAC on every run."
    }
} else {
    Write-Warning "[npcap_verify_helper] $mfst not found - skipping manifest embed."
}

# ---------------------------------------------------------------------------
# 5. Copy to dashboard directory for auto-discovery
# ---------------------------------------------------------------------------
$dashDir = Resolve-Path "..\..\dashboard" -ErrorAction SilentlyContinue
if ($dashDir -and (Test-Path $dashDir)) {
    Copy-Item $out "$dashDir\$out" -Force
    Write-Host "[npcap_verify_helper] Copied to $dashDir\$out"
} else {
    Write-Warning "[npcap_verify_helper] Dashboard dir not found at ..\..\dashboard - skipping copy."
}

# ---------------------------------------------------------------------------
# Done
# ---------------------------------------------------------------------------
Write-Host ""
Write-Host "[npcap_verify_helper] Build complete: $out"
Write-Host ""
Write-Host "When the dashboard Verify Npcap button is clicked:"
Write-Host "  1. DashboardServer calls ShellExecuteEx with verb runas"
Write-Host "  2. Windows shows a UAC elevation prompt (EVERY time)"
Write-Host "  3. This helper captures 10 real packets via Npcap"
Write-Host "  4. Result JSON is written and served on /npcap_verify_result.json"
Write-Host "  5. Dashboard displays result immediately"
