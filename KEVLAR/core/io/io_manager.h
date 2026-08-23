#pragma once

#include <windows.h>
#include <cstdint>
#include <unicorn/unicorn.h>
#include <unordered_map>
#include <mutex>

namespace IoManager {

// Serializes every Dispatch*/AllocateFileObject call across every host-side relay
// (KEVLAR/host/bridge/bridge_server.cpp, proxy_relay.cpp): UnicornMem::AllocateVariable
// and the shared UC memory are not safe under concurrent dispatch threads, and this
// is the one lock all relays must share so they can't race each other either.
extern std::mutex DispatchMutex;

struct IrpCompletionInfo {
    HANDLE Event;
    NTSTATUS Status;
    ULONG_PTR Information;
    bool Completed;
};

void Initialize();
void Shutdown();

void SignalCompletion(uint64_t IrpUcAddr, NTSTATUS Status, ULONG_PTR Information);

uint64_t AllocateIrp(uc_engine* Uc, CCHAR StackSize);
void FreeIrp(uint64_t IrpUcAddr);

uint64_t AllocateFileObject(uc_engine* Uc, uint64_t DeviceObjUcAddr);
void FreeFileObject(uint64_t FileObjUcAddr);

struct DispatchResult {
    NTSTATUS Status;
    ULONG_PTR Information;
    bool TimedOut;
};

// RequestorMode: 0 = KernelMode, 1 = UserMode (written to IRP->RequestorMode).
// Buffers for these dispatches come from AllocateVariable in the kernel-range UC
// pool, so passing UserMode here is only safe against a driver that never inspects
// the address range itself (see kevlar_proxy/README.md SS3.5). Callers relaying a
// real usermode request should still pass KernelMode unless/until a usermode-range
// allocator backs these buffers.
DispatchResult DispatchCreate(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr, CHAR RequestorMode = 0);
DispatchResult DispatchClose(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr, CHAR RequestorMode = 0);
DispatchResult DispatchCleanup(uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr, CHAR RequestorMode = 0);
DispatchResult DispatchDeviceIoControl(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    ULONG IoControlCode,
    void* InputBuffer, ULONG InputLength,
    void* OutputBuffer, ULONG OutputLength,
    ULONG* BytesReturned,
    CHAR RequestorMode = 0);
DispatchResult DispatchWrite(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* WriteBuffer, ULONG WriteLength,
    ULONG WriteOffset, ULONG* BytesWritten,
    CHAR RequestorMode = 0);
DispatchResult DispatchRead(
    uint64_t DeviceObjUcAddr, uint64_t FileObjUcAddr,
    void* ReadBuffer, ULONG ReadLength,
    ULONG ReadOffset, ULONG* BytesRead,
    CHAR RequestorMode = 0);

}
