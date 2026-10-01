param(
    [ValidateSet("Debug", "Release")]
    [string]$Configuration = "Release",
    [switch]$SkipBuild,
    [switch]$KeepLogs
)

# End-to-end test of the bridge: a real driver running inside KEVLAR, answering a real
# client that thinks it installed and started a kernel service.
#
#   bridge_client.exe -> kevlar_hook.dll -> \\.\pipe\kevlar-KevlarBridgeTest
#       -> IoManager::Dispatch* -> bridge_driver.sys under Unicorn
#
# Every value the client checks is one only the driver could have produced -- a magic
# number, a byte transform, counters kept between requests -- so a pass means the guest
# code ran, not that the relay copied buffers around.
#
# Needs the WDK headers and ntoskrnl.lib for the driver half. Without them the test skips
# rather than failing: tests\smoke.ps1 stays the check that runs anywhere.

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$outDir = Join-Path $root "builds\$Configuration\bridge_test"
$kevlar = Join-Path $root "builds\$Configuration\KEVLAR.exe"
$injector = Join-Path $root "kevlar_hook\builds\$Configuration\kevlar_inject.exe"
$hookDll = Join-Path $root "kevlar_hook\builds\$Configuration\VERSION.dll"
$driverSys = Join-Path $outDir "bridge_driver.sys"
$clientExe = Join-Path $outDir "bridge_client.exe"
$serveName = "bridge"       # Bridge::kDefaultChannelA -- both ends compile it in

function Fail($message) {
    Write-Host "BRIDGE FAIL - $message" -ForegroundColor Red
    exit 1
}

function Skip($message) {
    Write-Host "BRIDGE SKIP - $message" -ForegroundColor Yellow
    exit 0
}

# ---- toolchain ------------------------------------------------------------------

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path $vswhere)) { Fail "Visual Studio Installer was not found" }
$vsPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsPath) { Fail "Visual Studio 2022 C++ build tools were not found" }
$vcvars = Join-Path $vsPath "VC\Auxiliary\Build\vcvars64.bat"
if (-not (Test-Path $vcvars)) { Fail "vcvars64.bat was not found under $vsPath" }

# Newest WDK that ships both the km headers and ntoskrnl.lib for x64.
$kitRoot = "${env:ProgramFiles(x86)}\Windows Kits\10"
$wdkVersion = $null
if (Test-Path "$kitRoot\Include") {
    $wdkVersion = Get-ChildItem "$kitRoot\Include" -Directory |
        Where-Object { (Test-Path "$kitRoot\Include\$($_.Name)\km\ntddk.h") -and
                       (Test-Path "$kitRoot\Lib\$($_.Name)\km\x64\ntoskrnl.lib") } |
        Sort-Object Name | Select-Object -Last 1 -ExpandProperty Name
}
if (-not $wdkVersion) { Skip "no WDK with km headers + ntoskrnl.lib found under $kitRoot" }
Write-Host "Using WDK $wdkVersion"

# ---- build the emulator and the hook ---------------------------------------------

if (-not $SkipBuild) {
    & (Join-Path $root "build.ps1") $Configuration | Out-Host
    if ($LASTEXITCODE) { Fail "building KEVLAR failed" }
    & (Join-Path $root "kevlar_hook\build_hook.ps1") $Configuration | Out-Host
    if ($LASTEXITCODE) { Fail "building kevlar_hook failed" }
}
foreach ($required in @($kevlar, $injector, $hookDll)) {
    if (-not (Test-Path $required)) { Fail "$required not found - run without -SkipBuild" }
}

New-Item -ItemType Directory -Force $outDir | Out-Null

# ---- build the test driver and the test client -----------------------------------
#
# The driver is compiled and linked directly rather than through a WDK vcxproj: it needs
# no INF, no signing and no WDK VS integration, only the km headers and ntoskrnl.lib.
# It is linked with relocations (no /FIXED) because UnicornEmu::MapDriverImage relocates
# the image to DRIVER_BASE_UC when it maps it.

$driverCompile = @(
    'cl.exe /c /nologo /W3 /O2 /GS- /Gy /Zl /DNDEBUG /D_AMD64_ /DAMD64 /D_WIN64',
    '/D_KERNEL_MODE /DNTDDI_VERSION=0x0A000007 /D_WIN32_WINNT=0x0A00',
    "/I`"$kitRoot\Include\$wdkVersion\km`" /I`"$kitRoot\Include\$wdkVersion\shared`"",
    "/Fo`"$outDir\bridge_driver.obj`" `"$PSScriptRoot\bridge_driver.c`""
) -join ' '

$driverLink = @(
    'link.exe /nologo /DRIVER /SUBSYSTEM:NATIVE /ENTRY:DriverEntry /NODEFAULTLIB',
    '/MACHINE:X64 /RELEASE /OPT:REF /OPT:ICF',
    "/LIBPATH:`"$kitRoot\Lib\$wdkVersion\km\x64`" ntoskrnl.lib",
    "/OUT:`"$driverSys`" `"$outDir\bridge_driver.obj`""
) -join ' '

$clientCompile = @(
    'cl.exe /nologo /W3 /O2 /MT',
    "/Fo`"$outDir\bridge_client.obj`" /Fe`"$clientExe`"",
    "`"$PSScriptRoot\bridge_client.c`" /link advapi32.lib"
) -join ' '

Write-Host "Compiling bridge_driver.sys and bridge_client.exe..."
$buildLog = & cmd /c "call `"$vcvars`" >nul 2>&1 && $driverCompile && $driverLink && $clientCompile" 2>&1
if ($LASTEXITCODE -ne 0) {
    $buildLog | Out-Host
    Fail "compiling the test driver/client failed"
}
if (-not (Test-Path $driverSys)) { Fail "bridge_driver.sys was not produced" }
if (-not (Test-Path $clientExe)) { Fail "bridge_client.exe was not produced" }

# ---- control case: the client on its own -----------------------------------------
#
# Establishes that a pass below is the hook working, not the machine happening to have
# a real KevlarBridgeTest device present.

$controlOut = & $clientExe 2>&1 | Out-String
if ($controlOut -match "RESULT: PASS") {
    Fail "the client passed WITHOUT the hook - something real is answering for that device"
}
Write-Host "Control run (no hook): fails as expected"

# ---- run ---------------------------------------------------------------------------

$kevlarLog = Join-Path $outDir "kevlar.log"
$hookLog = Join-Path $outDir "kevlar_hook.log"
Remove-Item $kevlarLog, $hookLog -ErrorAction SilentlyContinue
$env:KEVLAR_HOOK_LOG = $hookLog

$emulator = Start-Process $kevlar `
    -ArgumentList $driverSys, "--serve", "--no-pause" `
    -WorkingDirectory $root -RedirectStandardOutput $kevlarLog -PassThru -WindowStyle Hidden

try {
    # DriverEntry has to reach IoCreateDevice and the server has to be listening before
    # the client opens anything.
    $listening = $false
    foreach ($attempt in 1..120) {
        Start-Sleep -Milliseconds 500
        if ($emulator.HasExited) { break }
        if ((Test-Path $kevlarLog) -and
            (Select-String -Path $kevlarLog -Pattern "Usermode bridge listening" -Quiet)) {
            $listening = $true
            break
        }
    }
    if (-not $listening) {
        Get-Content $kevlarLog -Tail 30 -ErrorAction SilentlyContinue | Out-Host
        Fail "the emulator never reported the bridge listening"
    }

    # The readiness grep can match before the rest of that line has been flushed, so the
    # device count is reported when available rather than assumed present.
    $deviceLine = Select-String -Path $kevlarLog -Pattern "device\(s\) registered" | Select-Object -First 1
    if ($deviceLine) {
        Write-Host "Emulator ready: $($deviceLine.Line.Trim())"
    } else {
        Write-Host "Emulator ready (device count not flushed yet)"
    }

    Write-Host "Running bridge_client.exe under kevlar_inject..."
    $clientOut = & $injector --wait $clientExe 2>&1 | Out-String
    $clientOut | Out-Host
}
finally {
    if (-not $emulator.HasExited) { Stop-Process -Id $emulator.Id -Force }
    Remove-Item Env:\KEVLAR_HOOK_LOG -ErrorAction SilentlyContinue
}

# ---- assertions ---------------------------------------------------------------------

$problems = @()

# The client's own checks are the real evidence: a magic value, a byte transform and
# counters kept between requests can only have come from the driver executing.
if ($clientOut -notmatch "RESULT: PASS") { $problems += "the client did not report PASS" }

# Per-request assertions read the hook log, not the emulator's. The emulator's stdout is
# redirected here, so the CRT buffers it in blocks, and stopping the process discards
# whatever had not filled a block -- the tail of that log is routinely truncated mid-line.
# kevlar_hook writes each line with WriteFile, so its log is always complete.
$hookText = Get-Content $hookLog -Raw -ErrorAction SilentlyContinue
if ($hookText -notmatch "CreateService faked") { $problems += "the hook did not intercept CreateService" }
if ($hookText -notmatch "StartService faked") { $problems += "the hook did not intercept StartService" }
if ($hookText -notmatch "MATCH open") { $problems += "the hook did not redirect the device open" }
foreach ($ioctl in @("0x00222000", "0x00222004", "0x00222008")) {
    if ($hookText -notmatch "IOCTL $ioctl .* status=0x00000000") {
        $problems += "IOCTL $ioctl was not relayed successfully"
    }
}
if ($hookText -notmatch "WRITE 26 -> status=0x00000000") { $problems += "the write was not relayed" }
if ($hookText -notmatch "READ .* information=26") { $problems += "the read did not return the written bytes" }

# Child propagation: the parent's CreateProcess hook injected this DLL into the process
# it spawned, and that child reached the driver on its own connection.
if ($hookText -notmatch "Child inject: hooked") { $problems += "the hook did not follow into the child process" }
# Both processes must land on the same fixed channel with no configuration at all --
# note the client installs the driver under "UnrelatedServiceName", so anything deriving
# the pipe from the service name would miss.
if ($hookText -notmatch "attached to pid .*kevlar-$serveName \(default\)") {
    $problems += "a process did not use the default fixed channel"
}
if ($hookText -notmatch "CreateService faked: name=UnrelatedServiceName") {
    $problems += "the client's service name was not the decoupled one the test expects"
}
if (([regex]::Matches($hookText, "kevlar_hook attached to pid")).Count -lt 2) {
    $problems += "expected two attaches (parent and child)"
}

# One check against the emulator's own log, early enough to always be flushed: the IRP
# path really ran in the guest rather than being answered short of it.
$emulatorText = Get-Content $kevlarLog -Raw -ErrorAction SilentlyContinue
if ($emulatorText -notmatch "IoManager::DispatchIoctl IOCTL=0x00222000") {
    $problems += "no IOCTL reached the emulated driver's dispatch routine"
}

if ($problems.Count) {
    Write-Host "BRIDGE FAIL:" -ForegroundColor Red
    $problems | ForEach-Object { Write-Host "  - $_" -ForegroundColor Red }
    Write-Host "  emulator log: $kevlarLog"
    Write-Host "  hook log:     $hookLog"
    exit 1
}

if (-not $KeepLogs) { Remove-Item $kevlarLog, $hookLog -ErrorAction SilentlyContinue }
Write-Host "BRIDGE PASS - service install, start, open, IOCTL, read/write all served by the emulated driver" -ForegroundColor Green
exit 0
