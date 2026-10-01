param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

# Builds VERSION.dll (kevlar_hook) and kevlar_inject.exe -- plain usermode MSBuild, no
# WDK. Kept out of KEVLAR.sln deliberately (docs/bridge.md SS4.7): a DLL injected into
# someone else's process is not part of the emulator, and building the emulator should
# not build it. It does link Zydis out of vcpkg_installed, so build KEVLAR at least
# once first. The hook is named VERSION.dll for side-by-side proxy load beside cod.exe /
# bootstrapper.exe and is deployed to both Call of Duty locations.

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"

if (-not (Test-Path $vswhere)) {
    throw "Visual Studio Installer was not found."
}

$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) {
    throw "Visual Studio 2022 C++ build tools were not found."
}

$msbuild = Join-Path $vsPath "MSBuild\Current\Bin\amd64\MSBuild.exe"

& $msbuild "$root\kevlar_hook.vcxproj" -m "/p:Configuration=$Configuration" "/p:Platform=x64"
if ($LASTEXITCODE) { throw "MSBuild failed building VERSION.dll with exit code $LASTEXITCODE" }

& $msbuild "$root\kevlar_inject.vcxproj" -m "/p:Configuration=$Configuration" "/p:Platform=x64"
if ($LASTEXITCODE) { throw "MSBuild failed building kevlar_inject.exe with exit code $LASTEXITCODE" }

Write-Host "Built: $root\builds\$Configuration\VERSION.dll"
Write-Host "Built: $root\builds\$Configuration\kevlar_inject.exe"

# Deploy VERSION.dll to both Call of Duty locations. Requires elevation for
# Program Files / ProgramData; failures are warned but do not fail the build.
$builtDll = Join-Path $root "builds\$Configuration\VERSION.dll"
$deployTargets = @(
    "C:\Program Files (x86)\Steam\steamapps\common\Call of Duty HQ\VERSION.dll",
    "C:\ProgramData\Activision\Call of Duty\VERSION.dll"
)

foreach ($target in $deployTargets) {
    $targetDir = Split-Path $target -Parent
    try {
        if (-not (Test-Path $targetDir)) {
            New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
            Write-Host "Created: $targetDir"
        }
        Copy-Item -LiteralPath $builtDll -Destination $target -Force -ErrorAction Stop
        Write-Host "Deployed: $target"
    } catch {
        Write-Warning "Failed to deploy to $target : $($_.Exception.Message) (run elevated if needed)"
    }
}
