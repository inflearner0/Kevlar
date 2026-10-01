#include "hook_engine.h"
#include "kevlar_hook.h"

#include <Zydis/Zydis.h>

#include <cstdint>
#include <mutex>
#include <vector>

using KevlarHook::Log;

namespace HookEngine {

namespace {

// jmp qword ptr [rip+0] followed by the 8-byte destination.
//
// The obvious `mov rax, imm64 ; jmp rax` is two bytes shorter but clobbers RAX, and the
// trampoline for an ntdll syscall stub runs between `mov eax, <syscall number>` and the
// `syscall` itself -- clobbering RAX there issues an arbitrary system call. This form
// touches no register, so it is safe at both ends.
constexpr size_t kPatchSize = 14;

// How far a rip-relative displacement can still reach: a relocated instruction has to
// address the same global from the trampoline, so the trampoline has to land within
// signed 32-bit range of it. Leave headroom for the instruction's own length.
constexpr uint64_t kRelativeReach = 0x7FFF0000ull;

std::once_flag g_DecoderOnce;
ZydisDecoder g_Decoder;

const ZydisDecoder& Decoder() {
    std::call_once(g_DecoderOnce, [] {
        ZydisDecoderInit(&g_Decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    });
    return g_Decoder;
}

void WriteAbsoluteJump(uint8_t* At, const void* Destination) {
    At[0] = 0xFF; At[1] = 0x25;                                  // jmp qword ptr [rip+0]
    *reinterpret_cast<uint32_t*>(At + 2) = 0;
    *reinterpret_cast<uint64_t*>(At + 6) = (uint64_t)Destination;
}

// An export can land on a thunk rather than on the function body: `jmp rel32` from
// incremental linking or ICF, or `jmp [rip+disp]` through a pointer, which is what most
// of sechost's service exports look like once advapi32's forwarder has been resolved.
// Patching a thunk would work for calls that go through it, but the body is also
// reachable directly from inside the owning module, so follow the chain and hook the body.
// PointerSlot, when the chain went through a `jmp [rip+disp]`, receives the address of
// the pointer it read. That slot is the fallback hook site: overwriting one function
// pointer intercepts every caller that reaches the function through the export, and needs
// no code patching at all.
void* FollowThunks(const char* Name, void* Target, void*** PointerSlot) {
    *PointerSlot = nullptr;
    for (int Hop = 0; Hop < 4; Hop++) {
        ZydisDecodedInstruction Insn;
        ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder(), Target, 32, &Insn, Operands)))
            return Target;
        if (Insn.mnemonic != ZYDIS_MNEMONIC_JMP || Insn.operand_count_visible != 1)
            return Target;

        ZyanU64 Absolute = 0;
        if (!ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&Insn, &Operands[0], (ZyanU64)Target, &Absolute)))
            return Target;

        void* Next = nullptr;
        if (Operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && Operands[0].imm.is_relative) {
            Next = (void*)Absolute;
        } else if (Operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                   Operands[0].mem.base == ZYDIS_REGISTER_RIP) {
            // The pointer is resolved already: the owning module is loaded.
            *PointerSlot = (void**)Absolute;
            Next = **PointerSlot;
        } else {
            return Target;
        }
        if (!Next)
            return Target;

        Log("%s: entry is a thunk, following %p -> %p", Name, Target, Next);
        Target = Next;
    }
    return Target;
}

struct DisplacedInsn {
    size_t Offset;                 // from the start of the function
    ZydisDecodedInstruction Insn;
    ZydisDecodedOperand Operands[ZYDIS_MAX_OPERAND_COUNT];
    bool RipRelative;
    ZyanU64 RipTarget;             // absolute address the operand refers to
};

// Decodes the whole instructions a kPatchSize patch would overwrite.
//
// A relative *branch* in that range is refused: re-encoding a rel8 into the trampoline
// needs a wider instruction, which changes the layout the rest of the copy depends on.
// None of the targets here start with one -- these are function entries, not jump tables.
// ponytail: widen rel8/rel32 branches too if a target ever needs it.
bool DecodePrologue(const char* Name, const uint8_t* Code, std::vector<DisplacedInsn>& Out,
    size_t& Total) {
    Total = 0;
    while (Total < kPatchSize) {
        DisplacedInsn Entry{};
        Entry.Offset = Total;
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&Decoder(), Code + Total, 32, &Entry.Insn,
                Entry.Operands))) {
            Log("%s: body not patchable -- cannot decode prologue at +%zu", Name, Total);
            return false;
        }

        for (ZyanU8 I = 0; I < Entry.Insn.operand_count; I++) {
            const ZydisDecodedOperand& Operand = Entry.Operands[I];
            if (Operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && Operand.imm.is_relative) {
                Log("%s: body not patchable -- relative branch at +%zu cannot be displaced", Name, Total);
                return false;
            }
            if (Operand.type == ZYDIS_OPERAND_TYPE_MEMORY &&
                    Operand.mem.base == ZYDIS_REGISTER_RIP) {
                if (Entry.Insn.raw.disp.size != 32) {
                    Log("%s: body not patchable -- rip-relative operand at +%zu has a %u-bit displacement",
                        Name, Total, Entry.Insn.raw.disp.size);
                    return false;
                }
                ZydisCalcAbsoluteAddress(&Entry.Insn, &Operand, (ZyanU64)(Code + Total),
                    &Entry.RipTarget);
                Entry.RipRelative = true;
            }
        }

        Total += Entry.Insn.length;
        Out.push_back(Entry);
    }
    return true;
}

// Trampolines for a prologue containing a rip-relative operand have to live within
// signed 32-bit range of what that operand addresses, or the displacement cannot be
// rewritten. Walk outward from the function in allocation-granularity steps.
uint8_t* AllocateNear(void* Anchor, size_t Size) {
    SYSTEM_INFO Info{};
    GetSystemInfo(&Info);
    const uint64_t Granularity = Info.dwAllocationGranularity;
    const uint64_t Base = (uint64_t)Anchor & ~(Granularity - 1);

    for (uint64_t Delta = Granularity; Delta < kRelativeReach; Delta += Granularity) {
        for (int Direction = 0; Direction < 2; Direction++) {
            uint64_t Candidate = Direction ? Base + Delta : Base - Delta;
            if (Candidate < Granularity || Candidate > 0x7FFFFFFF0000ull)
                continue;
            auto* Memory = (uint8_t*)VirtualAlloc((void*)Candidate, Size,
                MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (Memory)
                return Memory;
        }
    }
    return nullptr;
}

// Copies the displaced instructions into the trampoline, rewriting every rip-relative
// displacement so it still addresses the same global from its new location.
bool CopyAndRelocate(const char* Name, const std::vector<DisplacedInsn>& Insns,
    const uint8_t* Code, uint8_t* Trampoline) {
    for (const DisplacedInsn& Entry : Insns) {
        uint8_t* Destination = Trampoline + Entry.Offset;
        memcpy(Destination, Code + Entry.Offset, Entry.Insn.length);
        if (!Entry.RipRelative)
            continue;

        int64_t NewDisplacement = (int64_t)Entry.RipTarget -
            (int64_t)(uintptr_t)(Destination + Entry.Insn.length);
        if (NewDisplacement < INT32_MIN || NewDisplacement > INT32_MAX) {
            Log("%s: body not patchable -- relocated displacement at +%zu is out of range", Name, Entry.Offset);
            return false;
        }
        *reinterpret_cast<int32_t*>(Destination + Entry.Insn.raw.disp.offset) =
            (int32_t)NewDisplacement;
    }
    return true;
}

// Fallback when the function body cannot be patched: redirect the pointer the export's
// thunk reads. Nothing is displaced, so no prologue has to be relocatable. The limit is
// that a caller inside the owning module which reaches the body directly is not
// intercepted -- for these service APIs the client goes through the export.
bool HookPointerSlot(const char* Name, void** Slot, void* Detour, void** Original) {
    DWORD OldProtect = 0;
    if (!VirtualProtect(Slot, sizeof(void*), PAGE_READWRITE, &OldProtect)) {
        Log("SKIP %s: pointer slot %p is not writable, gle=%lu", Name, (void*)Slot,
            GetLastError());
        return false;
    }
    void* Previous = *Slot;
    if (Original)
        *Original = Previous;
    *Slot = Detour;
    VirtualProtect(Slot, sizeof(void*), OldProtect, &OldProtect);

    Log("HOOKED %s via its pointer slot %p (was %p)", Name, (void*)Slot, Previous);
    return true;
}

} // namespace

void* Resolve(const wchar_t* Module, const char* Name) {
    HMODULE Handle = GetModuleHandleW(Module);
    if (!Handle)
        return nullptr;
    return (void*)GetProcAddress(Handle, Name);
}

bool Install(const char* Name, void* Target, void* Detour, void** Original) {
    if (Original)
        *Original = nullptr;
    if (!Target) {
        Log("SKIP %s: target not found", Name);
        return false;
    }

    void** PointerSlot = nullptr;
    Target = FollowThunks(Name, Target, &PointerSlot);
    auto* Code = (uint8_t*)Target;

    // Anything that gives up on patching the body can still fall back to the pointer the
    // export's thunk reads, when there was one.
    auto Fallback = [&]() {
        return PointerSlot && HookPointerSlot(Name, PointerSlot, Detour, Original);
    };

    std::vector<DisplacedInsn> Insns;
    size_t Displaced = 0;
    if (!DecodePrologue(Name, Code, Insns, Displaced))
        return Fallback();

    bool NeedsNear = false;
    for (const DisplacedInsn& Entry : Insns)
        NeedsNear |= Entry.RipRelative;

    const size_t TrampolineSize = Displaced + kPatchSize;
    uint8_t* Trampoline = NeedsNear ? AllocateNear(Target, TrampolineSize) : nullptr;
    if (!Trampoline && !NeedsNear)
        Trampoline = (uint8_t*)VirtualAlloc(nullptr, TrampolineSize, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
    if (!Trampoline) {
        Log("%s: body not patchable -- no trampoline could be allocated%s", Name,
            NeedsNear ? " within reach of the prologue's rip-relative operand" : "");
        return Fallback();
    }

    if (!CopyAndRelocate(Name, Insns, Code, Trampoline)) {
        VirtualFree(Trampoline, 0, MEM_RELEASE);
        return Fallback();
    }
    WriteAbsoluteJump(Trampoline + Displaced, Code + Displaced);
    FlushInstructionCache(GetCurrentProcess(), Trampoline, TrampolineSize);

    // Publish the trampoline before the patch: from the instant the patch lands, another
    // thread already inside the process can enter the detour.
    if (Original)
        *Original = Trampoline;

    DWORD OldProtect = 0;
    if (!VirtualProtect(Target, Displaced, PAGE_EXECUTE_READWRITE, &OldProtect)) {
        Log("%s: body not patchable -- VirtualProtect failed, gle=%lu", Name, GetLastError());
        if (Original)
            *Original = nullptr;
        VirtualFree(Trampoline, 0, MEM_RELEASE);
        return Fallback();
    }

    uint8_t Patch[kPatchSize];
    WriteAbsoluteJump(Patch, Detour);
    memcpy(Target, Patch, kPatchSize);
    for (size_t I = kPatchSize; I < Displaced; I++)
        Code[I] = 0x90;

    VirtualProtect(Target, Displaced, OldProtect, &OldProtect);
    FlushInstructionCache(GetCurrentProcess(), Target, Displaced);

    Log("HOOKED %s at %p (displaced %zu bytes%s, trampoline %p)", Name, Target, Displaced,
        NeedsNear ? ", relocated" : "", (void*)Trampoline);
    return true;
}

} // namespace HookEngine
