# KEVLAR Usermode Bridge — Design & Implementation Plan

**Status:** design, not started. Nothing in this directory is implemented yet.

**Goal:** let usermode programs on the host issue `CreateFile` / `DeviceIoControl` /
`ReadFile` / `WriteFile` against a driver running inside the KEVLAR emulator.

This document is self-contained — it assumes no context beyond the KEVLAR repo itself.

---

## 1. Background: what already exists

### 1.1 The dispatch layer is written and unreachable

`IoManager::Dispatch{Create,Close,Cleanup,Read,Write,DeviceIoControl}` — declared in
`KEVLAR/core/io/io_manager.h`, implemented in `irp_ioctl.cpp` / `irp_readwrite.cpp` —
is **complete and has zero callers anywhere outside `core/io/`**. It is dead code.

`IoManager::DispatchDeviceIoControl` already:

- takes **host** pointers in and out
  (`void* InputBuffer, ULONG InputLength, void* OutputBuffer, ULONG OutputLength, ULONG* BytesReturned`)
  — i.e. it is already shaped exactly like a `DeviceIoControl` call;
- handles all four buffer methods (BUFFERED / IN_DIRECT / OUT_DIRECT / NEITHER),
  allocating guest-side buffers and copying in both directions;
- builds the `_IRP` + `_IO_STACK_LOCATION` and reads the real dispatch routine out of
  the guest `DRIVER_OBJECT`;
- spawns a guest thread via `UnicornThread::CreateEx(DispatchAddr, DeviceObj, Irp, 0, 0, nullptr)`;
- waits on a completion event signalled by `h_IofCompleteRequest` via
  `IoManager::SignalCompletion` (`KEVLAR/api/io/io_device.cpp:293`), 30 s timeout
  (`irp_ioctl.cpp:169`);
- is wrapped in `__try/__except`.

**Implication: this project is not "implement IOCTL support". It is "build a host
transport and call the function that already exists."**

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

`FindByName()` matches against **either** `DeviceName` or `SymLinkName`.
`GetByIndex()` / `GetCount()` allow enumeration.

### 1.3 Why nothing can open the device today

`h_IoCreateDevice` (`KEVLAR/api/io/io_device.cpp:42`) does exactly three things:
`AllocateVariable` in guest memory, `memset` a `_DEVICE_OBJECT`, `push_back` onto a
vector. `h_IoCreateSymbolicLink` is marked `//todo impl` and only records a string.

**Nothing touches the real Object Manager.** There is no `\Device\Foo`, no `\??\Foo`.
An unmodified `CreateFileW` on `\\.\Foo` goes `NtCreateFile` → real Object Manager →
`\GLOBAL??\Foo` → `STATUS_OBJECT_NAME_NOT_FOUND`. That lookup happens entirely inside
the real kernel; a device object cannot be fabricated from usermode.

### 1.4 Process lifetime

After `DriverEntry`, `main` enters an idle loop (`KEVLAR/host/main/kevlar.cpp:567`)
that exits once spawned guest threads go idle, or after 5 s under `--no-pause`
(`kevlar.cpp:619`). A server has to keep this alive.

---

## 2. Reality check — read before building Phase 2

If the intended client is a **protected / anticheat usermode process**, this
architecture will **not** achieve transparent substitution. Ranked by detection speed:

1. **Test signing.** One call: `NtQuerySystemInformation(SystemCodeIntegrityInformation)`
   → `CODEINTEGRITY_OPTION_TESTSIGN`. Checked at init by essentially every AC.
2. **Driver enumeration.** `SystemModuleInformation` lists `kevlarproxy.sys` by name.
   The existing VM-module filtering (commit `92c543b`) operates on the *emulated*
   module list and does not help — this check runs on the real host.
3. **The AC's own driver-integrity handshake.** Usually fatal. AC usermode modules
   verify their kernel component via a secret established at driver load, a
   challenge-response, an image-hash/signature check, or a session key only the real
   driver holds. An emulated driver that never ran the real init sequence has none of
   it. (The BCrypt passthrough on `feat/cng-bcrypt-passthrough` supplies crypto
   primitives, not the secret.)
4. **Latency.** Real IOCTL round trip: single-digit microseconds. This path is
   user → kernel → pend → usermode → *spawn a fresh Unicorn thread* → emulate → back
   down. Milliseconds. 100–1000× off, trivially measured with an `rdtsc` pair.

**Scope boundary.** The relay itself — transport, inverted call, buffer capture, ACLs —
is ordinary driver engineering and is in scope. Defeating the four checks above (hiding
the driver from enumeration, normalising timing against latency probes, forging driver
identity to pass an integrity check) is out of scope; it has no analysis value.

Phases 1 and 2 remain worth building for any **unprotected** client, which is the
overwhelming majority of drivers.

---

## 3. Phase 1 — in-process IOCTL server

Required by every downstream option. New code under `KEVLAR/host/bridge/`.
Gated behind a `--serve [name]` flag so default behaviour is unchanged.

### 3.1 Transport

Message-mode named pipe, `\\.\pipe\kevlar-<drivername>`. Message mode means one write
equals one request — no framing logic needed.

### 3.2 Protocol

```
request  { magic, version, opcode, session, ioctl, inLen, outLen } + payload
response { status, information, outLen }                          + payload
```

Opcodes: `ENUM` (list devices from `DeviceTracker`), `OPEN`, `IOCTL`, `READ`, `WRITE`, `CLOSE`.

### 3.3 Session model

- `OPEN` → `IoManager::AllocateFileObject(engine, DeviceObjUc)` + `DispatchCreate`,
  returns a session id
- `CLOSE` → `DispatchCleanup` + `DispatchClose` + `FreeFileObject`
- Tear down all sessions on pipe disconnect so a client crash cannot leak guest
  FILE_OBJECTs

This is not optional detail: drivers routinely key per-handle state off the FileObject,
and many perform their access check in `IRP_MJ_CREATE`. Jumping straight to IOCTL will
fail against real targets.

### 3.4 Constraints

- **Serialisation.** One global dispatch mutex; one in-flight IRP at a time.
  `UnicornMem::AllocateVariable` and the shared UC memory are not safe against
  concurrent dispatch threads. Genuine parallel IRPs are a later problem — document
  the limit.
- **Bounds.** Cap `inLen` / `outLen` at ~1 MB. Otherwise a buggy client can drive
  unbounded guest allocation.
- **Lifetime.** Under `--serve`, the idle loop at `kevlar.cpp:567` must not exit when
  guest threads go idle.

### 3.5 Known issue to fix during Phase 1

`IrpHost->RequestorMode = 1` (UserMode) is hardcoded at:

- `KEVLAR/core/io/irp_ioctl.cpp:137`
- `KEVLAR/core/io/irp_readwrite.cpp:86`
- `KEVLAR/core/io/irp_readwrite.cpp:253`

…but the buffers come from `AllocateVariable` at kernel-range addresses. Any guest
driver calling `ProbeForRead` / `ProbeForWrite` on a METHOD_NEITHER buffer will raise.
Needs a per-request knob, and probably a usermode-range allocator for NEITHER buffers.

---

## 4. Phase 2 — proxy driver (`kevlarproxy.sys`)

Only required when the client is unmodified **and** uses `DeviceIoControl`.
See §6 for the two cases where it is not required.

**Build and run this in a VM, not on the host.** An unsigned driver relaying arbitrary
IRPs into a usermode emulator is exactly what a snapshot-able lab VM is for, and when
the relay faults you will want a kernel debugger already attached.

### 4.1 Shape

Plain WDM plus `IoCsq` (cancel-safe queue). No KMDF dependency needed.

- **Control device** `\Device\KevlarProxyCtl` — SDDL `D:P(A;;GA;;;SY)(A;;GA;;;BA)`
  (SYSTEM + Administrators). Record the `FILE_OBJECT` of the first opener; reject all
  subsequent openers. One control-channel owner, ever.
- **Exposed devices** created on demand by control IOCTL, named from `DeviceTracker`.

### 4.2 Inverted-call flow

1. KEVLAR runs emulated `DriverEntry`; `DeviceTracker::Devices` now holds `\Device\Foo`
   plus its symlink.
2. KEVLAR opens `\\.\KevlarProxyCtl` and sends
   `IOCTL_KVP_CREATE_DEVICE {name, symlink, deviceType, sddl}`.
3. Driver calls `IoCreateDeviceSecure` + `IoCreateSymbolicLink`.
4. KEVLAR posts a pool of ~8 pending `IOCTL_KVP_GET_REQUEST` IRPs — the inverted-call
   channel.
5. Client opens `\\.\Foo` → proxy `IRP_MJ_CREATE` → capture, assign `RequestId`, park on
   the CSQ, `IoMarkIrpPending`, return `STATUS_PENDING`. Complete one `GET_REQUEST`
   upward carrying the request descriptor.
6. KEVLAR calls the existing `IoManager::DispatchCreate`, then sends
   `IOCTL_KVP_COMPLETE_REQUEST {RequestId, status, information, outData}`.
7. Driver pulls the IRP off the CSQ by id, copies output, calls `IoCompleteRequest`.

### 4.3 Buffer capture — the part that actually breaks

| Method | Handling |
|---|---|
| **BUFFERED** | `AssociatedIrp.SystemBuffer` is already a kernel copy. memcpy up and back. Trivial. |
| **IN/OUT_DIRECT** | Input in SystemBuffer; output via `Irp->MdlAddress` → `MmGetSystemAddressForMdlSafe`. Valid from any context once the MDL is held, so this may happen after pending. |
| **NEITHER** | `Parameters.DeviceIoControl.Type3InputBuffer` and `Irp->UserBuffer` are raw usermode VAs **valid only in the caller's context**. `ProbeForRead`/`ProbeForWrite` inside `__try/__except` **in the dispatch routine, before pending**, and copy input to pool there. For output, `IoAllocateMdl` + `MmProbeAndLockPages` at the same point so the completion path can write back later. |

Getting NEITHER wrong means dereferencing another process's addresses from a worker
thread. (`ObReferenceObject` on the caller plus `KeStackAttachProcess` at completion
time also works, but is strictly worse than locking an MDL up front.)

### 4.4 Cancellation and teardown

- The CSQ handles cancellation. KEVLAR must treat "complete a `RequestId` that no
  longer exists" as a normal, expected outcome — not an error.
- Register cleanup on the control device's `FILE_OBJECT`: **if KEVLAR.exe dies,
  complete every pended IRP with an error status.** Otherwise clients hang forever and
  the device cannot be deleted.

### 4.5 Security

A driver that accepts IOCTLs from any process and forwards them to a usermode program
is a local privilege-escalation primitive if the ACL is wrong.

- Control device: SYSTEM + Administrators only, single owner (§4.1).
- Exposed device: default to Administrators-only. Widening it is precisely how this
  becomes a working LPE — widen deliberately or not at all.
- Validate every `RequestId` and every length field arriving from usermode.

### 4.6 Build and deploy

- Separate `.vcxproj` under `kevlar_proxy/`, WDK toolchain, x64, matching host arch.
- `bcdedit /set testsigning on` plus reboot, or a KMCS/EV cert. Note that Microsoft
  attestation signing for a driver whose stated purpose is relaying arbitrary IRPs to
  usermode is a plausible rejection.
- Load with `sc create kevlarproxy type= kernel binPath= ...` then `sc start`, or via
  OSR Loader.

---

## 5. Rough schedule

| Step | Estimate |
|---|---|
| Phase 1 server: transport, sessions, dispatch mutex, `RequestorMode` knob | ~2 days |
| Driver skeleton + control channel + BUFFERED only | ~3 days |
| DIRECT / NEITHER capture | ~3 days |
| Cancellation + teardown hardening | ~2 days |

---

## 6. When the proxy driver is NOT needed

**Client can be recompiled** → Phase 1 plus a client library is the entire job.
Ship `kevlarctl.exe --list` / `--ioctl 0x22e004 --in f.bin --outlen 256`, and a
`KevlarOpenDevice` / `KevlarDeviceIoControl` / `KevlarCloseDevice` export set.

**Client is unmodified but injectable** → hook `NtCreateFile` / `NtDeviceIoControlFile` /
`NtReadFile` / `NtWriteFile` / `NtClose` in the target; match the device path, forward
over the Phase 1 pipe, pass everything else through. Return the pipe's own handle as
the pseudo-handle so unrelated handle operations still behave. No signing, no reboot,
no kernel attack surface. Caveats: hook and injection detection, overlapped I/O needs a
real async path, 32-bit clients need a separate 32-bit shim.

**Driver's interface is Read/Write rather than IOCTL** → no driver needed at all.
As Administrator:

```c
DefineDosDeviceW(DDD_RAW_TARGET_PATH, L"Foo", L"\\Device\\NamedPipe\\kevlar-Foo");
```

`CreateFileW` on `\\.\Foo` then opens your pipe, and `ReadFile`/`WriteFile` work
transparently against `DispatchRead`/`DispatchWrite`. **This does not extend to
`DeviceIoControl`** — that IRP goes to npfs, which handles pipe FSCTLs and rejects
arbitrary control codes with `STATUS_INVALID_DEVICE_REQUEST`.

---

## 7. Recommended alternative if the goal is the protocol

Given §2, transparent substitution will not survive a defended anticheat. If the
research objective is the usermode↔kernel protocol, **capture instead of substitute**:

run the real driver and real usermode module together in a VM, log the IOCTL stream at
the kernel level, then replay that stream into KEVLAR through the Phase 1 server. Full
protocol, reproducible, no arms race, no unsigned driver on the machine — and it fits
the existing `--trace` / `--check` deterministic replay design. Strictly less work than
Phase 2.

---

## 8. Unrelated bug found while surveying

`h_IoDeleteSymbolicLink` (`KEVLAR/api/io/io_device.cpp:142`) calls the **real**
`ZwOpenSymbolicLinkObject` + `ZwMakeTemporaryObject`, while `h_IoCreateSymbolicLink` is
a no-op stub. Create is emulated, delete reaches into the host Object Manager — so an
emulated driver deleting a symlink name that happens to exist on the host will try to
make the host's real one temporary. Independent of this project; worth fixing.
