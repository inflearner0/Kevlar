param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

# Builds kevlar_hook.dll and kevlar_inject.exe -- plain usermode MSBuild, no WDK, but
# kept out of KEVLAR.sln for the same reason as kevlar_proxy (kevlar_proxy/README.md
# SS4.6 / SS6): a hook DLL for redirecting a client's device I/O isn't part of the
# emulator itself.

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
if ($LASTEXITCODE) { throw "MSBuild failed building kevlar_hook.dll with exit code $LASTEXITCODE" }

& $msbuild "$root\kevlar_inject.vcxproj" -m "/p:Configuration=$Configuration" "/p:Platform=x64"
if ($LASTEXITCODE) { throw "MSBuild failed building kevlar_inject.exe with exit code $LASTEXITCODE" }

$solutionRoot = Split-Path $root -Parent
Write-Host "Built: $solutionRoot\builds\$Configuration\kevlar_hook.dll"
Write-Host "Built: $solutionRoot\builds\$Configuration\kevlar_inject.exe"
