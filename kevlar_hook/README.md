# kevlar_hook

A usermode DLL that makes an unmodified client believe it installed, started and is
talking to a kernel driver, while the driver actually runs inside the KEVLAR emulator.

Nothing here loads a driver, writes a service key, or needs test signing. The design
rationale and the limits live in [`docs/bridge.md`](../docs/bridge.md) §4; this file is
how to use it.

## Build

```powershell
.\build.ps1 Release                     # emulator first: this also populates vcpkg_installed
.\kevlar_hook\build_hook.ps1 Release    # kevlar_hook.dll + kevlar_inject.exe
```

Output lands in `kevlar_hook\builds\<Configuration>\`. The DLL links Zydis statically out
of `vcpkg_installed\x64-windows-static`, and is built with the static CRT so it does not
need a redistributable present in whatever process it lands in.

## Run

Start the emulator serving the driver, then launch the client with the DLL injected:

```powershell
.\builds\Release\KEVLAR.exe driver.sys --serve --no-pause
```

```powershell
.\kevlar_hook\builds\Release\kevlar_inject.exe client.exe [args...]
```

`kevlar_inject` launches the target suspended and injects before it runs any of its own
code, so the service install cannot be missed. It hands the child its own stdin/stdout/
stderr, so redirecting or piping the injector captures the client's output. `--wait` blocks
until the target exits and returns its exit code, which is what makes it scriptable:

```powershell
.\kevlar_hook\builds\Release\kevlar_inject.exe --wait client.exe
```

To attach to a client that is already up — which races anything it has already done:

```powershell
.\kevlar_hook\builds\Release\kevlar_inject.exe --pid 1234
```

Both ends compile in the same channel name, so nothing has to be matched up by hand. The
client may install the driver under any service name, or none at all; the only thing that
has to correspond is the device the emulated driver creates and the device the client
opens.

## Test

`tests\bridge_smoke.ps1` runs this DLL against a real driver executing in the emulator and
a real client that knows nothing about KEVLAR, and asserts on values only the driver could
have produced. Run it after changing anything here:

```powershell
.\tests\bridge_smoke.ps1 -SkipBuild
```

## Configuration

Environment variables, read at attach. The launched client inherits the injector's
environment, so set them before running `kevlar_inject`.

| Variable | Default | Meaning |
|---|---|---|
| `KEVLAR_HOOK_PIPE` | `\\.\pipe\kevlar-bridge` | only needed to run several emulators side by side; must match the server's `--serve=<name>` |
| `KEVLAR_HOOK_SERVICE` | every kernel/filesystem driver service | fake only this one service name |
| `KEVLAR_HOOK_DEVICE` | discovered by enumerating the bridge | device name to open, for a client that never creates the service |
| `KEVLAR_HOOK_MATCH` | none | substring override for device-path matching |
| `KEVLAR_HOOK_LOG` | `%TEMP%\kevlar_hook.log` | log file path |

## Reading the log

Every decision is one line, and the log is the product of a run. A healthy sequence looks
like this:

```
kevlar_hook attached to pid 24288: pipe=\\.\pipe\kevlar-bridge (default) ...
HOOKED NtCreateFile at 00007FFF1AEE0E10 (displaced 16 bytes, trampoline ...)
HOOKED QueryServiceStatusEx via its pointer slot 00007FFF19116930 (was ...)
CreateService faked: name=WhateverTheClientCallsIt type=0x1 image=... -> handle 0x...
StartService faked: name=WhateverTheClientCallsIt now SERVICE_RUNNING (no driver was loaded)
Connected to \\.\pipe\kevlar-bridge
Emulated device: \Device\MyDriver (symlink \DosDevices\MyDriver, type 0x22)
MATCH open \??\MyDriver -> bridge OPEN \Device\MyDriver
OPEN ok -> handle 0000000000000174 (session 1)
IOCTL 0x00222004 in=16 out=64 -> status=0x00000000 information=16
Child inject: hooked D:\Games\Example\client.exe (pid 4321)
```

Two lines worth recognising:

- `<name>: body not patchable -- ...` is not a failure on its own; the next line is either
  `HOOKED <name> via its pointer slot` or nothing. Only the second case leaves the function
  unhooked, and a client calling it with a faked handle is then a real hazard.
- `WARN: ... is not answering` after `StartService` means the emulator is not listening on
  that pipe. The client's device open will fail and it will read that as "my driver did not
  start".

## Files

| File | Contents |
|---|---|
| `dllmain.cpp` | attach, install all three layers |
| `service_hooks.cpp` | the fake SCM: create / start / query / control / delete, plus `NtLoadDriver` |
| `process_hooks.cpp` | follows the hook into child processes via `CreateProcess*` |
| `device_hooks.cpp` | open / IOCTL / read / write / close redirected to the bridge |
| `bridge_client.cpp` | the pipe transport and device matching |
| `hook_engine.cpp` | inline patching, trampolines, relocation, the pointer-slot fallback |
| `kevlar_hook.cpp` | logging, environment configuration, device-path helpers |
| `inject.cpp` | `kevlar_inject.exe` |
