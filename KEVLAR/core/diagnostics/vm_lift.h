#pragma once

#include <unicorn/unicorn.h>
#include <cstdint>
#include <string>

// ---------------------------------------------------------------------------
// VM lifting support (--devirt).
//
// Randgrid.sys and drivers protected the same way execute almost nothing
// natively: DriverEntry hands control to a direct-threaded bytecode interpreter
// whose handler bodies are the only real code in the image. A hot-block profile
// of such a driver is degenerate - a few hundred handler blocks executed tens of
// millions of times - so the usual "which code ran" question has to be asked one
// level down, about the *virtual* instruction pointer rather than RIP.
//
// This module records that lower level. Every guest basic block is sampled for
// the pair (native block, VIP), which is enough to recover the executed virtual
// program once the handler bodies have been classified statically, and dumps the
// driver image as the guest actually sees it - decrypted .data, the handler
// table and the bytecode included.
// ---------------------------------------------------------------------------
namespace VmLift {

// Byte offsets into the interpreter's context structure, discovered from the
// handler bodies (see docs/devirt.md). RBP holds the context pointer for the
// whole run, so these are read straight out of host memory once the context has
// been identified.
constexpr uint64_t kCtxVipOffset = 0xB4;
constexpr uint64_t kCtxHandlerTableOffset = 0xDC;

extern bool Enabled;
// false => image dumping only, no UC_HOOK_BLOCK tracer (much faster; set by
// --dump). The post-DriverEntry image does not depend on the tracer.
extern bool TracerEnabled;
extern std::string OutDir;

// Latched once a stable driver-resident RBP has been observed. Zero until then.
uint64_t GetContextUc();

void InstallTracer(uc_engine* Uc, uint64_t DriverBase, uint64_t DriverSize);

// Install on an engine created later. Each guest thread gets its own uc_engine,
// and IoManager dispatches every IRP on one of those - so without this the
// entire dispatch surface executes untraced, which looks exactly like a driver
// that never handles an IRP. No-op until InstallTracer has set the bounds.
void InstallTracerOnEngine(uc_engine* Uc);

// Writes <OutDir>/image.bin - DriverSize bytes read out of the guest starting at
// DriverBase, unmapped pages zero-filled - plus a small text sidecar recording
// where the context and handler table ended up.
void DumpImage(const char* Reason, uint64_t DriverBase, uint64_t DriverSize);

// Writes <OutDir>/trace.bin (sequential u32 pairs: block RVA, VIP RVA) and
// <OutDir>/blocks.txt (per-block execution counts and first observed VIP).
void DumpTrace(const char* Reason);

}
