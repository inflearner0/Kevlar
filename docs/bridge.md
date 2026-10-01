# KEVLAR Usermode Bridge — Design & Status

**Status:** implemented, in two pieces.

- **`KEVLAR.exe --serve`** (`KEVLAR/host/bridge/`) exposes the emulated driver's IRP
  dispatch over a named pipe.
- **`kevlar_hook.dll`** (`kevlar_hook/`) is injected into an unmodified client so that
  installing a driver service, starting it, opening the device and talking to it all
  resolve to that pipe instead of to the kernel.

**Goal:** let a usermode program on the host issue `CreateService` / `StartService` /
`CreateFile` / `DeviceIoControl` / `ReadFile` / `WriteFile` against a driver running
inside the KEVLAR emulator, without the driver ever being loaded by Windows.

A third piece used to exist: `kevlarproxy.sys`, a WDM proxy driver that captured real
IRPs on real device objects and relayed them up, plus a namespace shadow that patched
`ntoskrnl` so a real driver could not claim the names the proxy owned. **Both are
removed.** They required test signing, a reboot, and an unsigned driver on the machine
to reach clients that the hook DLL reaches with none of that (§2, §4).

This document is self-contained — it assumes no context beyond the KEVLAR repo itself.

---

## 1. Background: what already existed

### 1.1 The dispatch layer

`IoManager::Dispatch{Create,Close,Cleanup,Read,Write,DeviceIoControl}` — declared in
`KEVLAR/core/io/io_manager.h`, implemented in `irp_ioctl.cpp` / `irp_readwrite.cpp` —
was complete and had **zero callers** before the bridge was written. It already:

- takes **host** pointers in and out
  (`void* InputBuffer, ULONG InputLength, void* OutputBuffer, ULONG OutputLength, ULONG* BytesReturned`)
  — i.e. it is already shaped exactly like a `DeviceIoControl` call;
- handles all four buffer methods (BUFFERED / IN_DIRECT / OUT_DIRECT / NEITHER),
  allocating guest-side buffers and copying in both directions;
- builds the `_IRP` + `_IO_STACK_LOCATION` and reads the real dispatch routine out of
  the guest `DRIVER_OBJECT`;
- spawns a guest thread via `UnicornThread::CreateEx(DispatchAddr, DeviceObj, Irp, 0, 0, nullptr)`;
- waits on a completion event signalled by `h_IofCompleteRequest` via
  `IoManager::SignalCompletion` (`KEVLAR/api/io/io_device.cpp`), 30 s timeout;
- is wrapped in `__try/__except`.

**So this was never "implement IOCTL support". It was "build a host transport and call
the function that already exists."**

### 1.2 Device naming

`DeviceTracker` (`KEVLAR/api/io/io_device.h`) records every emulated device:

```cpp
struct DeviceInfo {
    uint64_t     UcAddr;
    std::wstring DeviceName;    // set by h_IoCreateDevice
    std::wstring SymLinkName;   // set by h_IoCreateSymbolicLink
    ULONG        DeviceType;
};
```

`FindByName()` matches against **either** `DeviceName` or `SymLinkName`, by full name.
`GetByIndex()` / `GetCount()` allow enumeration, which is what the `ENUM` opcode returns.

### 1.3 Why nothing can open the device directly

`h_IoCreateDevice` does exactly three things: `AllocateVariable` in guest memory, `memset`
a `_DEVICE_OBJECT`, `push_back` onto a vector. `h_IoCreateSymbolicLink` only records a
string.

**Nothing touches the real Object Manager.** There is no `\Device\Foo`, no `\??\Foo`. An
unmodified `CreateFileW` on `\\.\Foo` goes `NtCreateFile` → real Object Manager →
`\GLOBAL??\Foo` → `STATUS_OBJECT_NAME_NOT_FOUND`. That lookup happens entirely inside the
real kernel; a device object cannot be fabricated from usermode. This is the fact the
whole design works around: rather than making the name exist, §4 intercepts the open.

### 1.4 Process lifetime

After `DriverEntry`, `main` enters an idle loop (`KEVLAR/host/main/kevlar.cpp`) that exits
once spawned guest threads go idle, or after 5 s under `--no-pause`. Under `--serve` those
exit conditions are suppressed: the process exists to answer relayed requests.

---

## 2. Reality check — read this before pointing it at a defended target

If the intended client is a **protected / anticheat usermode process**, this architecture
will **not** achieve transparent substitution. Ranked by detection speed:

1. **Test signing.** One call: `NtQuerySystemInformation(SystemCodeIntegrityInformation)`
   → `CODEINTEGRITY_OPTION_TESTSIGN`. Checked at init by essentially every AC. (This one
   no longer applies to KEVLAR itself now that the proxy driver is gone — nothing here
   needs test signing any more — but it still applies to whatever else is on the machine.)
2. **Hook and injection detection.** `kevlar_hook.dll` patches ntdll and sechost in the
   target and shows up in the module list. A client that checksums its own imports, or
   compares `NtCreateFile`'s prologue against a clean copy from disk, sees it immediately.
3. **The AC's own driver-integrity handshake.** Usually fatal. AC usermode modules verify
   their kernel component via a secret established at driver load, a challenge-response,
   an image-hash/signature check, or a session key only the real driver holds. An emulated
   driver that never ran the real init sequence has none of it.
4. **Latency.** Real IOCTL round trip: single-digit microseconds. This path is
   client → hooked ntdll → named pipe → *spawn a fresh Unicorn thread* → emulate → back.
   Milliseconds. 100–1000× off, trivially measured with an `rdtsc` pair.

**Scope boundary.** The relay itself — transport, session model, hook engine, buffer
handling — is ordinary engineering and is in scope. Defeating the checks above (hiding the
hooks, normalising timing, forging driver identity) is out of scope; it has no analysis
value.

Both pieces remain worth having for any **unprotected** client, which is the overwhelming
majority of drivers.

---

## 3. The pipe bridge (`--serve`)

`KEVLAR/host/bridge/bridge_server.cpp`, gated behind `--serve[=name]` so default behaviour
is unchanged.

### 3.1 Transport

Message-mode named pipe. Message mode means one write equals one request — no framing
logic needed.

The channel name is a **constant compiled into both ends** (`Bridge::kDefaultPipeNameW`,
`\\.\pipe\kevlar-bridge`), so a run lines up with no configuration. It used to be derived
— the server from the `.sys` filename, the hook from whatever service name the client
passed to `CreateService` — which meant two unrelated strings had to coincide before
anything could connect, and a client that installed the driver under a different service
name silently never found the bridge. What identifies the driver is the device it creates;
the transport does not need to.

`--serve=<name>` and `KEVLAR_HOOK_PIPE` still override it, for running several emulators
side by side.

### 3.2 Protocol

`KEVLAR/host/bridge/bridge_protocol.h`, shared verbatim with the hook DLL:

```
request  { magic, version, opcode, session, ioctl, inLen, outLen } + payload
response { status, information, session, outLen }                 + payload
```

Opcodes: `ENUM` (list devices from `DeviceTracker`), `OPEN`, `IOCTL`, `READ`, `WRITE`,
`CLOSE`.

### 3.3 Session model

- `OPEN` → `IoManager::AllocateFileObject(engine, DeviceObjUc)` + `DispatchCreate`,
  returns a session id
- `CLOSE` → `DispatchCleanup` + `DispatchClose` + `FreeFileObject`
- All sessions are torn down on pipe disconnect, so a client crash cannot leak guest
  FILE_OBJECTs

This is not optional detail: drivers routinely key per-handle state off the FileObject,
and many perform their access check in `IRP_MJ_CREATE`. Jumping straight to IOCTL fails
against real targets.

### 3.4 Constraints

- **Concurrent clients, serialised guest work.** The listener accepts each connection onto
  its own thread, so a launcher and the process it spawns can both hold the pipe — but
  every dispatch still goes through one global mutex (`IoManager::DispatchMutex`), so
  there is one in-flight IRP at a time. `UnicornMem::AllocateVariable` and the shared UC
  memory are not safe against concurrent dispatch threads. Genuine parallel IRPs remain a
  later problem.
- **Sessions belong to a connection.** They used to live in one global table, which meant
  any client disconnecting tore down every other client's FILE_OBJECTs. With a process
  tree on the pipe that is no longer a theoretical problem, so each connection owns its
  own session table and closes only its own.
- **Bounds.** `inLen` / `outLen` are capped at 1 MB (`Bridge::kMaxPayload`), bounding the
  guest allocation a client can drive per request.
- **Lifetime.** Under `--serve` the idle loop must not exit when guest threads go idle.

### 3.5 RequestorMode

`IRP->RequestorMode` used to be hardcoded to UserMode while the buffers came from
`AllocateVariable` at kernel-range addresses — so any guest driver calling `ProbeForRead` /
`ProbeForWrite` on a METHOD_NEITHER buffer would raise. It is now a per-dispatch parameter
(`IoManager::Dispatch*`, defaulting to KernelMode) and the bridge passes KernelMode
deliberately. A usermode-range allocator for NEITHER buffers would let this be honest
rather than merely consistent; until then, a driver that inspects the buffer address range
itself will notice.

---

## 4. The client-side shim (`kevlar_hook`)

`kevlar_hook.dll`, injected by `kevlar_inject.exe`. This is the "client is unmodified but
injectable" path: no unsigned driver, no test signing, no reboot, no kernel attack surface.

### 4.1 What the client sees

The sequence a driver client performs, and what answers each step:

| Client call | Answered by | Result |
|---|---|---|
| `OpenSCManager` | real SCM if it succeeds, otherwise a fake manager handle | works unelevated |
| `CreateService(… SERVICE_KERNEL_DRIVER …)` | fake service database | no service key, no driver load |
| `StartService` | fake service database | state becomes `SERVICE_RUNNING` |
| `QueryServiceStatus[Ex]`, `QueryServiceConfig` | fake service database | reports the config it was given |
| `NtLoadDriver` | fake service database | `STATUS_SUCCESS`, nothing loaded |
| `CreateFile("\\\\.\\Foo")` | bridge `ENUM` + `OPEN` | a real handle backed by a bridge session |
| `DeviceIoControl` / `ReadFile` / `WriteFile` | bridge `IOCTL` / `READ` / `WRITE` | the emulated driver's dispatch routine runs |
| `CloseHandle`, `ControlService(STOP)`, `DeleteService` | both layers | session closed, state reset |

Nothing in that table depends on the service name. The client can install the driver under
any name it likes — or never install it at all — because the bridge is found on a fixed
channel (§3.1) and the device is matched by the name the emulated driver actually created.
The only thing that has to correspond is **device created ↔ device opened**.

### 4.2 Hook engine (`hook_engine.cpp`)

Inline patching, with instruction boundaries from Zydis (already vendored for the
emulator):

- The patch is `jmp qword ptr [rip+0]` + an 8-byte destination — 14 bytes, and it clobbers
  no register. The shorter `mov rax, imm64 ; jmp rax` cannot be used: the trampoline for an
  ntdll syscall stub runs between `mov eax, <syscall number>` and the `syscall`, so
  clobbering RAX there issues an arbitrary system call.
- Export entries are followed through thunks — `jmp rel32`, and `jmp [rip+disp]`, which is
  what most sechost service exports look like once advapi32's forwarder is resolved.
- Displaced instructions with a rip-relative operand are relocated: the trampoline is
  allocated within signed-32-bit range of the function so the displacement can be
  rewritten to address the same global.
- A prologue containing a relative *branch* is not displaced (widening a rel8 would change
  the layout the rest of the copy depends on). When the export was reached through a
  pointer thunk, the fallback is to overwrite that pointer instead — one word, no code
  patching, and every caller reaching the function through the export is intercepted.
  `QueryServiceStatusEx` is currently the one function that takes this path.

### 4.3 Service database (`service_hooks.cpp`)

A fake SCM: a name-keyed record table plus handle tables, none of which touch the real
service database.

- **Handles** are addresses inside a page the DLL owns, so their values cannot collide
  with a real `SC_HANDLE` the same process holds.
- **`OpenSCManager` prefers the real thing.** Only when the real open fails — which is what
  happens unelevated, the case where faking the install is most useful — is a fake manager
  handed back. Everything else in the process keeps working against the real SCM.
- **Interception policy.** By default every service create whose type includes
  `SERVICE_KERNEL_DRIVER` or `SERVICE_FILE_SYSTEM_DRIVER` is faked, because letting one
  actually load defeats the point of emulating it. Ordinary Win32 services pass through.
  `KEVLAR_HOOK_SERVICE` narrows this to a single name.
- **`OpenService` carries no type**, so the name has to identify it: one already faked, the
  one named by `KEVLAR_HOOK_SERVICE`, or one matching a device the emulator reports.
  Anything else passes through.

### 4.4 Device I/O (`device_hooks.cpp`)

Hooks on `NtCreateFile`, `NtOpenFile`, `NtDeviceIoControlFile`, `NtReadFile`,
`NtWriteFile`, `NtClose` and `NtDuplicateObject` — at the ntdll layer, so the Win32 entry
points and direct `Nt*` callers are covered by one set.

- **Matching** is driven by the bridge's `ENUM` result, not by a hardcoded name and not
  by anything the client did with the SCM: the leaf of the requested path is compared
  against the leaf of each emulated `DeviceName` and `SymLinkName`, so `\??\Foo`,
  `\Device\Foo` and `\DosDevices\Foo` all resolve. Because the channel is fixed, this
  works on the very first open, in a process that never installed anything. The
  `OPEN` then sends the exact `DeviceName`, which is what `DeviceTracker::FindByName`
  matches. The device list is cached; while the emulator is not answering, a re-enumerate
  is attempted at most every two seconds so a client opening files in a loop pays nothing.
- **The handle handed back is a real kernel handle** on `\Device\Null`, not a fabricated
  value, so handle operations this DLL does not hook — waits, `NtQueryInformationFile`,
  validity checks, appearing in a handle snapshot — behave like a handle rather than
  failing. Duplicates are tracked and the bridge session closes with the last handle.
- **Completion** sets the `IO_STATUS_BLOCK`, signals the event, and queues the APC to the
  issuing thread when the client passed one — what the I/O manager would have done, so an
  alertable-wait client still gets its callback. The relay itself is synchronous.
- **Re-entrancy** is guarded per-thread: the transport is a named pipe, i.e. file I/O
  through the very functions being hooked.

### 4.5 Following the process tree (`process_hooks.cpp`)

The process you inject into is often not the one that opens the device — a launcher starts
the program that does. `CreateProcessW`/`A` and `CreateProcessAsUserW`/`A` are hooked so
the child is created suspended, this same DLL is injected into it, and only then is it
resumed (or left suspended, if that is what the caller asked for). The child is therefore
hooked before it runs any of its own code, exactly as if `kevlar_inject` had launched it.

Two details that matter:

- **The pipe name is published into the environment** before the child is created, so a
  child that never creates the service still knows which pipe to use. A caller that
  supplies its own environment block is left alone — rewriting someone else's block is not
  worth the failure modes — and the DLL logs that the child will not inherit it.
- **A failed injection still resumes the child.** The target has to keep working even when
  this DLL cannot follow it; the failure is a log line, not a hang. A 32-bit child is
  skipped outright and logged, since a 64-bit DLL cannot be loaded into it.

### 4.6 What this does not cover

- **Overlapped I/O is completed synchronously.** A client that waits on the *file handle*
  rather than on an event or the APC will not be woken; nothing has been observed doing so.
- **Unhooked SCM APIs are a hazard, not a no-op.** The ~20 functions a driver loader
  realistically calls are hooked; if a client calls some other `SC_HANDLE`-taking function
  with a fake handle, sechost dereferences a pointer that is not its own structure. Add the
  hook rather than hoping.
- **No registry service key is created.** A client that reads
  `HKLM\SYSTEM\CurrentControlSet\Services\<name>` directly, instead of asking the SCM,
  sees nothing there.
- **32-bit clients need a separate 32-bit shim**, and a 32-bit child is skipped rather
  than injected.
- **A handle duplicated into another process** stops reaching the emulator.

### 4.7 Build and run

`kevlar_hook/build_hook.ps1` is deliberately outside `KEVLAR.sln`: a DLL injected into
someone else's process is not part of the emulator, and building the emulator should not
build it. It does link Zydis out of `vcpkg_installed`, so build KEVLAR at least once first.

```powershell
.\build.ps1 Release                     # emulator, and vcpkg_installed for Zydis
.\kevlar_hook\build_hook.ps1 Release    # kevlar_hook.dll + kevlar_inject.exe

.\builds\Release\KEVLAR.exe driver.sys --serve=MyDriver --no-pause
.\kevlar_hook\builds\Release\kevlar_inject.exe client.exe
.\kevlar_hook\builds\Release\kevlar_inject.exe --wait client.exe   # block, return its exit code
.\kevlar_hook\builds\Release\kevlar_inject.exe --pid 1234          # already-running client
```

The injector hands its own stdin/stdout/stderr to the child, so a redirected or piped run
captures the client's output.

### 4.8 The end-to-end test

`tests\bridge_smoke.ps1` exercises the whole path against code in this repo:
`tests\bridge_driver.c` is a real WDM driver running under `--serve`, and
`tests\bridge_client.c` is an ordinary client that installs a kernel service, starts it,
opens `\\.\KevlarBridgeTest` and talks to it — knowing nothing about KEVLAR.

Every value the client checks is one only the driver could have produced: a magic constant
from `IOCTL_KEVLAR_PING`, a byte transform from `IOCTL_KEVLAR_ECHO` (the driver upper-cases
the input, so a copy would not pass), bytes stored by a write and handed back by a later
read, and counters the driver kept across all of it. An echo test would have proved only
that the relay copies buffers.

The script runs the client **without** the hook first and requires that run to fail, so a
pass cannot come from something real answering for that device name. It needs the WDK km
headers and `ntoskrnl.lib`, and skips rather than fails without them.

The test driver is linked with relocations (no `/FIXED`) because
`UnicornEmu::MapDriverImage` relocates the image to `DRIVER_BASE_UC`, and it avoids
`memcpy` entirely: `memcpy` is not registered in `ntoskrnl_provider.cpp`, so a
compiler-emitted call would resolve through the unimplemented-stub path and silently
corrupt the result.

Configuration is environment variables, inherited by the launched client:
`KEVLAR_HOOK_PIPE`, `KEVLAR_HOOK_SERVICE`, `KEVLAR_HOOK_DEVICE`, `KEVLAR_HOOK_MATCH`,
`KEVLAR_HOOK_LOG`. Every decision the DLL makes is one line in the log; when something
does not get intercepted, the log says which step declined and why.

---

## 5. Recommended alternative if the goal is the protocol

Given §2, transparent substitution will not survive a defended anticheat. If the research
objective is the usermode↔kernel protocol, **capture instead of substitute**:

run the real driver and real usermode module together in a VM, log the IOCTL stream at the
kernel level, then replay that stream into KEVLAR through the pipe server. Full protocol,
reproducible, no arms race — and it fits the existing `--trace` / `--check` deterministic
replay design.

---

## 6. Unrelated bug found while surveying

`h_IoDeleteSymbolicLink` (`KEVLAR/api/io/io_device.cpp`) called the **real**
`ZwOpenSymbolicLinkObject` + `ZwMakeTemporaryObject` while `h_IoCreateSymbolicLink` was a
no-op stub — so an emulated driver deleting a symlink name that happened to exist on the
host would try to make the host's real one temporary. **Fixed**: deletion now operates on
`DeviceTracker` state, matching creation.
