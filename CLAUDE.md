# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

KEVLAR maps an x64 Windows kernel driver into a synthetic kernel address space and runs
`DriverEntry` (and anything it spawns) inside Unicorn, on the host, without loading it into
the real kernel. Kernel imports resolve to host C++ implementations. `README.md` documents
user-facing behavior, flags and the roadmap; this file covers the internals.

## Build & test

```powershell
.\build.ps1 Release          # vswhere -> vcpkg (x64-windows-static) -> MSBuild KEVLAR.sln
.\build.ps1 Debug            # separate output dir; Debug and Release do not overwrite

.\tests\smoke.ps1            # build + generate a minimal .sys + run + assert + --selftest
.\tests\smoke.ps1 -SkipBuild # reuse the existing build (the fast inner loop)

.\builds\Release\KEVLAR.exe --selftest              # IRQL/APC/DPC/timer self-test only, no driver
.\builds\Release\KEVLAR.exe path\to\drv.sys --diag --no-pause
.\tools\pdb_layout.ps1                              # regenerate generated\kernel_layout.h from the ntoskrnl PDB
.\kevlar_proxy\build_proxy.ps1                      # kevlarproxy.sys (WDK; deliberately outside KEVLAR.sln)
```

There is no unit-test framework. The two automated checks are `tests\smoke.ps1` (PE mapping +
emulator init end-to-end) and `--selftest` (IRQL/APC/DPC/timer semantics, implemented in
`host/main/kevlar.cpp`). Both assert on log text: changing a line that `smoke.ps1` greps for
breaks the test.

`--trace <file>` / `--check <file>` give deterministic record/replay for regression work on a
specific driver: record on a known-good build, replay after a change, first divergence is reported.

**The .vcxproj does not glob.** A new `.cpp` must be added by hand to `KEVLAR/KEVLAR.vcxproj`
(`<ClCompile Include="..."/>`) and to `KEVLAR.vcxproj.filters`, or it is silently not compiled.

## Architecture

### Two address worlds — the single most important invariant

Everything the emulated driver sees is a **guest (UC) address**; host implementations run as
native code with **host pointers**. They are not the same memory. `UnicornMem` (`core/memory/`)
keeps the `UcToHostMap` / `HostToUcMap` mapping.

Every pointer argument arriving in a host implementation is a guest address and must be
translated before dereference, using the helpers in `KEVLAR/include/common.h`:

- `UcPtr(p)` — map guest→host, returns the original pointer if it is already host-resident.
- `UcPtrSafe(p, LocalBuf)` — same, but falls back to `uc_mem_read` into a caller-owned buffer.
- `TranslateObjAttr` / `RewriteSystemRootPath` — for `OBJECT_ATTRIBUTES` passed on to real Nt* calls.

Forgetting `UcPtr` is the recurring bug class here: it reads host memory at a kernel-range
address and either faults inside the hook or silently returns garbage. `api/cng/cng.cpp` is the
cleanest example of the pattern (every buffer wrapped before handing off to real BCrypt).

Guest allocation goes through `UnicornMem::AllocatePool` / `AllocateVariable` /
`AllocateUsermode`; the fixed guest address map (`DRIVER_BASE_UC`, `KPCR_BASE_UC`,
`POOL_BASE_UC`, `SENTINEL_BASE_UC`, …) lives at the top of `core/exec/unicorn_engine.h`.

### How an emulated kernel call reaches host code

1. `PEFile::ResolveImport` + `UnicornEmu::BuildSentinelIat` rewrite the driver's IAT so each
   import points at a unique **sentinel address** in `SENTINEL_BASE_UC`, recorded in `SentinelMap`.
2. The driver calls it; the code hook `UnicornEmu::Hooks::OnSentinelExec`
   (`core/exec/unicorn_hooks.cpp`) fires instead of anything executing.
3. That hook reads RCX/RDX/R8/R9 plus 12 stack args from `[RSP+0x28]`, invokes the host function
   through `CallHookSafe` (SEH-wrapped; a crashing hook is logged with the last 16 hook names and
   is not fatal), writes the result to RAX and returns.

So a host implementation is an ordinary `__fastcall`-shaped C++ function taking up to 16
integer-width args. It never sees a real thread context — only registers.

### Adding or changing a kernel API

1. Write `h_<ExportName>` (or `k_<ExportName>`) in the matching `KEVLAR/api/<subsystem>/` file
   (`ke/`, `ex/`, `mm/`, `io/`, `nt/`, `ob/`, `ps/`, `rtl/`, `cng/`); translate every pointer arg.
2. Register it in `KEVLAR/host/providers/ntoskrnl_provider.cpp` with
   `Provider::AddFuncImpl("ExportName", h_ExportName);` — ~370 entries; that file is the API index.
3. Add any new `.cpp` to the `.vcxproj` and `.filters`.

**Exported *data*** is different: declare a `MONITOR` global in
`host/providers/static_export_provider.h` (the `MONITOR` macro places it in a dedicated
`hookaccess` section) and register it in `InitializeExport()` with `Provider::AddDataImpl`.
`AddDataImpl` copies the value into guest memory once the engine exists, so registrations made
before `UnicornEmu::Initialize` behave differently from later ones.

**Unregistered exports** fall through `Provider::FindFuncImpl`: PE export or PDB symbol lookup →
registered provider → cached ntdll passthrough (`GetProcAddress(ntdll, name)`) → `unimplemented_stub`,
which returns `0`, or `STATUS_NOT_IMPLEMENTED` under `--strict-exports`. A driver appearing to work
may therefore mean an ntdll function ran with kernel semantics — check the log before believing a result.

### Emulation core (`core/exec/`)

`unicorn_engine.cpp` owns engine creation, GDT/IDT/CR/MSR setup and region mapping. Hooks are
split by concern: `unicorn_hooks.cpp` (sentinel dispatch + unmapped memory),
`unicorn_hooks_insn.cpp` (CPUID/RDTSC/RDMSR/WRMSR/syscall/port I/O, branch provenance),
`unicorn_hooks_exception.cpp`, `unicorn_hooks_monitor.cpp` (read hooks on DRIVER_OBJECT, KUSD,
module list), `unicorn_hooks_install.cpp` (which hooks get installed when).
`instruction_emulator.cpp` plus `insn_avx*.cpp` / `insn_crypto.cpp` implement instructions Unicorn
does not support, dispatched from the unsupported-instruction path.

Unmapped-memory hooks are load-bearing, not diagnostics: they lazily map tracked allocations,
route faults into `SehDispatch::DispatchException`, and stop runaway execution.

The CPU surface presented to the guest (`core/exec/cpu_profile.h`, timing in `timing_spoof.cpp`)
is a **coherent bare-metal Intel profile** — leaf `0x1` with the hypervisor bit clear, empty
`0x40000000`, VMX pre-conditions advertised in MSRs. Changing one value in isolation breaks that
coherence, which is exactly what earlier versions got wrong; see the FACEIT section of `README.md`.

### Kernel structures and PDB-generated layouts

`include/ntoskrnl_struct.h` holds hand-written struct definitions (largely Win10 21H2 x64).
`tools/pdb_layout.ps1` emits `generated/kernel_layout.h` (`GEN_<STRUCT>_<FIELD>` offsets) from the
cached ntoskrnl PDB, and `include/kernel_layout_consume.h` turns those into the accessors the
harness actually uses, plus `static_assert`s that fail the build when a hardcoded struct drifts.

When touching ETHREAD/KTHREAD/KPCR/KPRCB/EPROCESS: go through `kernel_layout_consume.h`
accessors, never a fresh magic offset. `_EPROCESS`/`_KPROCESS` bodies are known to predate the
target build — fields outside the `GEN_` accessors are not PDB-accurate.

### Threads, I/O and the relays

Each synthetic guest thread (`core/process/unicorn_threading.cpp`) gets its **own `uc_engine`**,
ETHREAD, KPCR and stack, plus a `WakeEvent` used to deliver kernel APCs to a wait-blocked thread.
`UnicornThread::GetCurrentEngine()` is thread-local — a host implementation must use it rather
than `UnicornEmu::PrimaryEngine` whenever it can run on a spawned thread.

`core/io/io_manager.{h,cpp}` plus `irp_ioctl.cpp` / `irp_readwrite.cpp` are the only IRP entry
point: `IoManager::Dispatch{Create,Close,Cleanup,Read,Write,DeviceIoControl}` take **host**
buffers, build the `_IRP`/`_IO_STACK_LOCATION`, spawn a guest thread on the driver's dispatch
routine, and block on a completion event signalled by `h_IofCompleteRequest`.
`IoManager::DispatchMutex` serializes all of this and every relay must hold it — guest allocation
is not concurrency-safe.

Two relays sit on top, both off by default:

- `--serve[=name]` → `host/bridge/bridge_server.cpp`, a message-mode named pipe
  `\\.\pipe\kevlar-<name>` speaking the protocol in `bridge_protocol.h`
  (ENUM/OPEN/IOCTL/READ/WRITE/CLOSE).
- `--proxy` → `host/bridge/proxy_relay.cpp` talking to `kevlarproxy.sys` (`kevlar_proxy/`, plain
  WDM, wire protocol in `kevlar_proxy/kvp_protocol.h`), which captures real client IRPs on real
  device objects and hands them up via an inverted call. Requires test signing; run it in a VM.

Either flag also keeps the process alive past the idle-thread exit condition in `kevlar.cpp`.

`kevlar_proxy/README.md` is the design document for both relays, and code comments cite it by
section (`kevlar_proxy/README.md SS3.5`). Its status header saying "not started" is stale — the
rationale, constraints and the RequestorMode caveat in it are still current.

### State isolation

Each driver gets its own on-disk virtual filesystem and registry under
`builds/<Config>/<driver>/{vfs,vreg}` (`core/registry/virtual_fs.cpp`); `kevlar.cpp` seeds the
service key (`ImagePath`, `Start`, `Type`, …) before `DriverEntry`. Deleting that directory resets
a target's persisted state.

## Conventions

- `h_` prefix = host implementation of a kernel export; `k_` appears on a few. Locals and
  parameters are PascalCase, matching the NT style of the surrounding code.
- `// ponytail:` marks a deliberately bounded model with a note on when to extend it (IOMMU
  register set, APC queue, timer clamping, CPU profile). Treat these as scope markers, not TODOs
  to clear: models here are extended when a real driver is observed exercising the path, not
  speculatively.
- Logging is `Logger::Log` with inline `{RED}`/`{GRN}`/`{GRY}`/`{RESET}` color tags. Much of the
  log output is the actual product of a run — be conservative about deleting or rewording lines.
- Diagnostic-only work belongs behind `UnicornEmu::DiagnosticHooksEnabled` (`--diag`) or
  `core/diagnostics/diag_center.cpp`; the default path stays fast.
- Commit subjects are `feat:` / `fix:` / `docs:` / `chore:`, imperative, one behavioral change each.
- `core/` and `host/` code deliberately avoids depending on `include/nt_define.h` and declares the
  few NTSTATUS literals it needs locally.

## Claims and evidence

This is a research harness, and the surrounding docs are careful about what has actually been
observed. Reaching the end of `DriverEntry` does not mean initialization succeeded, and a returned
`NTSTATUS` may have come from a stub. When reporting on target compatibility, say what the log
shows and what was inferred, and keep unvalidated models labeled as such (see the FACEIT baseline
and the ACPI/PCI/IOMMU notes in `README.md` for the expected tone).
