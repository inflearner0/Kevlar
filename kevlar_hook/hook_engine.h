#pragma once

// Inline hook installer for kevlar_hook.dll.
//
// The service-control APIs this DLL has to intercept live in sechost.dll / advapi32.dll
// and are ordinary compiled functions, not the short straight-line syscall stubs in
// ntdll -- so a prologue cannot be measured by scanning for the first `ret`. Instruction
// boundaries come from Zydis, which the KEVLAR tree already vendors.

#include <windows.h>

namespace HookEngine {

// Resolves an export, following the forwarder chain (advapi32's service exports forward
// to sechost on Win8+). Returns nullptr if the module is not loaded or the name is absent.
void* Resolve(const wchar_t* Module, const char* Name);

// Patches a 12-byte `mov rax, Detour; jmp rax` over Target's prologue and returns, in
// *Original, a trampoline that runs the displaced instructions and jumps back. *Original
// is written before the patch goes in, so a detour that fires immediately never sees a
// null original.
//
// Returns false and leaves Target untouched when the prologue cannot be relocated. That
// covers any displaced instruction with a relative operand: relocating rip-relative and
// rel32 operands into the trampoline is possible, but every prologue observed on these
// targets is register/stack setup, so the failure is logged rather than engineered around.
// ponytail: extend to rewrite relative displacements if a real target ever needs it.
bool Install(const char* Name, void* Target, void* Detour, void** Original);

} // namespace HookEngine
