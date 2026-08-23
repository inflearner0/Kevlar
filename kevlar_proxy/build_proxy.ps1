param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release"
)

# Builds kevlarproxy.sys directly via MSBuild -- deliberately not part of KEVLAR.sln
# (kevlar_proxy/README.md SS4.6): this is a WDK driver project, not a usermode C++
# app, and shouldn't make the host build (build.ps1) depend on the WDK being
# installed.

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

& $msbuild "$root\kevlar_proxy.vcxproj" -m "/p:Configuration=$Configuration" "/p:Platform=x64"
if ($LASTEXITCODE) { throw "MSBuild failed with exit code $LASTEXITCODE" }

$solutionRoot = Split-Path $root -Parent
Write-Host "Built: $solutionRoot\builds\$Configuration\kevlarproxy.sys"
