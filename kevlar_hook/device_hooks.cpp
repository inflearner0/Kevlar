#include "device_hooks.h"
#include "bridge_client.h"
#include "hook_engine.h"
#include "kevlar_hook.h"
#include "reentry.h"

#include <windows.h>
#include <winternl.h>

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

using KevlarHook::Log;

typedef LONG NTSTATUS;

namespace {

constexpr NTSTATUS kStatusSuccess = 0;
constexpr NTSTATUS kStatusUnsuccessful = (NTSTATUS)0xC0000001;

// winternl.h stops short of the ntddk file-open constants.
constexpr ULONG kObjCaseInsensitive = 0x00000040;
constexpr ULONG kFileOpen = 0x00000001;
constexpr ULONG kFileSynchronousIoNonAlert = 0x00000020;
constexpr ULONG_PTR kFileOpened = 1;  // IoStatusBlock.Information for a successful open

typedef void (NTAPI* PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG Reserved);

typedef NTSTATUS(NTAPI* PFN_NtCreateFile)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer,
    ULONG EaLength);

typedef NTSTATUS(NTAPI* PFN_NtOpenFile)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);

typedef NTSTATUS(NTAPI* PFN_NtDeviceIoControlFile)(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer,
    ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);

typedef NTSTATUS(NTAPI* PFN_NtReadWriteFile)(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset,
    PULONG Key);

typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE Handle);

typedef NTSTATUS(NTAPI* PFN_NtDuplicateObject)(
    HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
    PHANDLE TargetHandle, ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

PFN_NtCreateFile Orig_NtCreateFile;
PFN_NtOpenFile Orig_NtOpenFile;
PFN_NtDeviceIoControlFile Orig_NtDeviceIoControlFile;
PFN_NtReadWriteFile Orig_NtReadFile;
PFN_NtReadWriteFile Orig_NtWriteFile;
PFN_NtClose Orig_NtClose;
PFN_NtDuplicateObject Orig_NtDuplicateObject;

// ---- session table ---------------------------------------------------------------
//
// A handle handed back to the client is a real kernel handle on \Device\Null rather
// than a fabricated value, so every handle operation this DLL does *not* hook -- waits,
// NtQueryInformationFile, handle-validity checks, the handle showing up in a snapshot --
// behaves like a handle instead of failing with STATUS_INVALID_HANDLE.
// ponytail: \Device\Null answers NtQueryObject with its own name, and a client that
// waits on the file handle itself rather than an event will not be woken. Neither has
// been observed on a real target; a dedicated backing object is the fix if one is.

struct SessionState {
    std::mutex Lock;
    std::unordered_map<HANDLE, uint64_t> HandleToSession;
    std::unordered_map<uint64_t, int> SessionRefs;   // handles sharing one bridge session
};

// Never destroyed: NtClose keeps arriving here while the process tears down.
SessionState& Sessions() { return KevlarHook::Immortal<SessionState>(); }

bool LookupSession(HANDLE Handle, uint64_t& Session) {
    SessionState& State = Sessions();
    std::lock_guard<std::mutex> Guard(State.Lock);
    auto It = State.HandleToSession.find(Handle);
    if (It == State.HandleToSession.end())
        return false;
    Session = It->second;
    return true;
}

void TrackHandle(HANDLE Handle, uint64_t Session) {
    SessionState& State = Sessions();
    std::lock_guard<std::mutex> Guard(State.Lock);
    State.HandleToSession[Handle] = Session;
    State.SessionRefs[Session]++;
}

// Drops one reference; reports whether this was the last handle on the session, i.e.
// whether the bridge session should be closed.
bool ReleaseHandle(HANDLE Handle, uint64_t& Session) {
    SessionState& State = Sessions();
    std::lock_guard<std::mutex> Guard(State.Lock);
    auto It = State.HandleToSession.find(Handle);
    if (It == State.HandleToSession.end())
        return false;
    Session = It->second;
    State.HandleToSession.erase(It);
    auto RefIt = State.SessionRefs.find(Session);
    if (RefIt == State.SessionRefs.end())
        return true;
    if (--RefIt->second > 0)
        return false;
    State.SessionRefs.erase(RefIt);
    return true;
}

// A real handle for the client to hold. \Device\Null accepts any access and never
// blocks, and the open goes through the trampoline so it is not intercepted here.
HANDLE OpenBackingHandle() {
    if (!Orig_NtCreateFile)
        return nullptr;

    wchar_t NullName[] = L"\\Device\\Null";
    UNICODE_STRING Name{};
    Name.Buffer = NullName;
    Name.Length = (USHORT)(wcslen(NullName) * sizeof(wchar_t));
    Name.MaximumLength = (USHORT)(Name.Length + sizeof(wchar_t));

    OBJECT_ATTRIBUTES Attributes{};
    Attributes.Length = sizeof(Attributes);
    Attributes.ObjectName = &Name;
    Attributes.Attributes = kObjCaseInsensitive;

    HANDLE Handle = nullptr;
    IO_STATUS_BLOCK Iosb{};
    NTSTATUS Status = Orig_NtCreateFile(&Handle, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
        &Attributes, &Iosb, nullptr, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE, kFileOpen, kFileSynchronousIoNonAlert,
        nullptr, 0);
    if (Status < 0) {
        Log("Backing handle open failed, status=0x%08x", (unsigned)Status);
        return nullptr;
    }
    return Handle;
}

// ---- completion ------------------------------------------------------------------

struct PendingApc {
    PIO_APC_ROUTINE Routine;
    PVOID Context;
    PIO_STATUS_BLOCK IoStatusBlock;
};

void NTAPI DeliverApc(ULONG_PTR Parameter) {
    auto* Pending = reinterpret_cast<PendingApc*>(Parameter);
    Pending->Routine(Pending->Context, Pending->IoStatusBlock, 0);
    delete Pending;
}

// The relay completes synchronously, but a client that passed an APC routine or an event
// is entitled to both. Queueing the APC to the issuing thread is what the I/O manager
// would have done, so an alertable-wait client still gets its completion callback.
void Complete(NTSTATUS Status, ULONG_PTR Information, PIO_STATUS_BLOCK IoStatusBlock,
    HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext) {
    if (IoStatusBlock) {
        IoStatusBlock->Status = Status;
        IoStatusBlock->Information = Information;
    }
    if (Event)
        SetEvent(Event);
    if (ApcRoutine)
        QueueUserAPC(&DeliverApc, GetCurrentThread(),
            (ULONG_PTR)new PendingApc{ ApcRoutine, ApcContext, IoStatusBlock });
}

std::wstring ObjectPath(POBJECT_ATTRIBUTES Attributes) {
    if (!Attributes || !Attributes->ObjectName || !Attributes->ObjectName->Buffer ||
            !Attributes->ObjectName->Length)
        return {};
    // A relative open (RootDirectory set) is never a device-namespace open of ours.
    if (Attributes->RootDirectory)
        return {};
    return std::wstring(Attributes->ObjectName->Buffer,
        Attributes->ObjectName->Length / sizeof(wchar_t));
}

// Shared by the NtCreateFile and NtOpenFile detours: decides whether the path is the
// Shared by the NtCreateFile and NtOpenFile detours: decides whether the path is the
// emulated driver's device and, if so, opens a bridge session for it.
// Returns false when the caller should fall through to the real function.
bool TryOpenEmulatedDevice(POBJECT_ATTRIBUTES Attributes, PHANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock, NTSTATUS& Result) {
    std::wstring Requested = ObjectPath(Attributes);
    if (Requested.empty())
        return false;

    // The channel is a fixed constant, so the device list can be enumerated on the very
    // first open regardless of whether this process ever installed a service. Matching
    // is therefore purely "is the device being opened one the emulated driver created" --
    // no dependency on service names, image paths or install order.
    std::wstring DeviceName = BridgeClient::MatchDevice(Requested);
    if (DeviceName.empty())
        return false;

    Log("MATCH open %ls -> bridge OPEN %ls", Requested.c_str(), DeviceName.c_str());

    Bridge::ResponseHeader Response{};
    uint32_t OutLen = 0;
    if (!BridgeClient::SendRecv(Bridge::Opcode::Open, 0, 0, DeviceName.data(),
            (uint32_t)(DeviceName.size() * sizeof(wchar_t)), nullptr, 0, Response, OutLen)) {
        Log("OPEN transport failed -- falling through to the real object namespace");
        return false;
    }

    if (Response.Status < 0) {
        Log("OPEN rejected by the driver's IRP_MJ_CREATE, status=0x%08x",
            (unsigned)Response.Status);
        if (IoStatusBlock) {
            IoStatusBlock->Status = Response.Status;
            IoStatusBlock->Information = 0;
        }
        Result = Response.Status;
        return true;
    }

    HANDLE Backing = OpenBackingHandle();
    if (!Backing) {
        // The session exists on the server; close it rather than leaking a FILE_OBJECT.
        Bridge::ResponseHeader Discard{};
        uint32_t DiscardLen = 0;
        BridgeClient::SendRecv(Bridge::Opcode::Close, Response.Session, 0, nullptr, 0,
            nullptr, 0, Discard, DiscardLen);
        Result = kStatusUnsuccessful;
        return true;
    }

    TrackHandle(Backing, Response.Session);
    *FileHandle = Backing;
    if (IoStatusBlock) {
        IoStatusBlock->Status = kStatusSuccess;
        IoStatusBlock->Information = kFileOpened;
    }
    Log("OPEN ok -> handle %p (session %llu)", Backing, (unsigned long long)Response.Session);
    Result = kStatusSuccess;
    return true;
}

// ---- detours ----------------------------------------------------------------------

NTSTATUS NTAPI Hk_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    if (!KevlarHook::ReentryActive() && FileHandle) {
        KevlarHook::ReentryGuard Guard;
        NTSTATUS Result = kStatusSuccess;
        if (TryOpenEmulatedDevice(ObjectAttributes, FileHandle, IoStatusBlock, Result))
            return Result;
    }
    return Orig_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        AllocationSize, FileAttributes, ShareAccess, CreateDisposition, CreateOptions,
        EaBuffer, EaLength);
}

NTSTATUS NTAPI Hk_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess,
    ULONG OpenOptions) {
    if (!KevlarHook::ReentryActive() && FileHandle) {
        KevlarHook::ReentryGuard Guard;
        NTSTATUS Result = kStatusSuccess;
        if (TryOpenEmulatedDevice(ObjectAttributes, FileHandle, IoStatusBlock, Result))
            return Result;
    }
    return Orig_NtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
        ShareAccess, OpenOptions);
}

NTSTATUS NTAPI Hk_NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
    ULONG OutputBufferLength) {
    uint64_t Session = 0;
    if (!KevlarHook::ReentryActive() && LookupSession(FileHandle, Session)) {
        KevlarHook::ReentryGuard Guard;
        Bridge::ResponseHeader Response{};
        uint32_t OutLen = 0;
        bool Ok = BridgeClient::SendRecv(Bridge::Opcode::Ioctl, Session, IoControlCode,
            InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength, Response, OutLen);
        NTSTATUS Status = Ok ? (NTSTATUS)Response.Status : kStatusUnsuccessful;
        Log("IOCTL 0x%08x in=%lu out=%lu -> status=0x%08x information=%llu", IoControlCode,
            InputBufferLength, OutputBufferLength, (unsigned)Status,
            Ok ? (unsigned long long)Response.Information : 0ull);
        Complete(Status, Ok ? (ULONG_PTR)Response.Information : 0, IoStatusBlock, Event,
            ApcRoutine, ApcContext);
        return Status;
    }
    return Orig_NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
        IoControlCode, InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

NTSTATUS NTAPI Hk_NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key) {
    uint64_t Session = 0;
    if (!KevlarHook::ReentryActive() && LookupSession(FileHandle, Session)) {
        KevlarHook::ReentryGuard Guard;
        Bridge::ResponseHeader Response{};
        uint32_t OutLen = 0;
        bool Ok = BridgeClient::SendRecv(Bridge::Opcode::Read, Session, 0, nullptr, 0,
            Buffer, Length, Response, OutLen);
        NTSTATUS Status = Ok ? (NTSTATUS)Response.Status : kStatusUnsuccessful;
        Log("READ %lu -> status=0x%08x information=%llu", Length, (unsigned)Status,
            Ok ? (unsigned long long)Response.Information : 0ull);
        Complete(Status, Ok ? (ULONG_PTR)Response.Information : 0, IoStatusBlock, Event,
            ApcRoutine, ApcContext);
        return Status;
    }
    return Orig_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer,
        Length, ByteOffset, Key);
}

NTSTATUS NTAPI Hk_NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length,
    PLARGE_INTEGER ByteOffset, PULONG Key) {
    uint64_t Session = 0;
    if (!KevlarHook::ReentryActive() && LookupSession(FileHandle, Session)) {
        KevlarHook::ReentryGuard Guard;
        Bridge::ResponseHeader Response{};
        uint32_t OutLen = 0;
        bool Ok = BridgeClient::SendRecv(Bridge::Opcode::Write, Session, 0, Buffer, Length,
            nullptr, 0, Response, OutLen);
        NTSTATUS Status = Ok ? (NTSTATUS)Response.Status : kStatusUnsuccessful;
        Log("WRITE %lu -> status=0x%08x information=%llu", Length, (unsigned)Status,
            Ok ? (unsigned long long)Response.Information : 0ull);
        Complete(Status, Ok ? (ULONG_PTR)Response.Information : 0, IoStatusBlock, Event,
            ApcRoutine, ApcContext);
        return Status;
    }
    return Orig_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer,
        Length, ByteOffset, Key);
}

NTSTATUS NTAPI Hk_NtClose(HANDLE Handle) {
    uint64_t Session = 0;
    if (!KevlarHook::ReentryActive() && ReleaseHandle(Handle, Session)) {
        KevlarHook::ReentryGuard Guard;
        Bridge::ResponseHeader Response{};
        uint32_t OutLen = 0;
        BridgeClient::SendRecv(Bridge::Opcode::Close, Session, 0, nullptr, 0, nullptr, 0,
            Response, OutLen);
        Log("CLOSE handle %p (session %llu)", Handle, (unsigned long long)Session);
    }
    return Orig_NtClose(Handle);
}

NTSTATUS NTAPI Hk_NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Options) {
    uint64_t Session = 0;
    bool IsOurs = !KevlarHook::ReentryActive() && LookupSession(SourceHandle, Session);

    NTSTATUS Status = Orig_NtDuplicateObject(SourceProcessHandle, SourceHandle,
        TargetProcessHandle, TargetHandle, DesiredAccess, HandleAttributes, Options);

    // A duplicate in this process refers to the same file object, so it must reach the
    // same bridge session -- and the session only closes when the last handle does.
    if (IsOurs && Status >= 0 && TargetHandle && *TargetHandle &&
            TargetProcessHandle == GetCurrentProcess()) {
        TrackHandle(*TargetHandle, Session);
        Log("DUP handle %p -> %p (session %llu)", SourceHandle, *TargetHandle,
            (unsigned long long)Session);
    } else if (IsOurs && Status >= 0) {
        Log("WARN: relayed handle %p duplicated out of this process; I/O on the duplicate "
            "will not reach the emulator", SourceHandle);
    }
    return Status;
}

} // namespace

namespace DeviceHooks {

void Install() {
    struct { const char* Name; void* Detour; void** Original; } Sites[] = {
        { "NtCreateFile", (void*)&Hk_NtCreateFile, (void**)&Orig_NtCreateFile },
        { "NtOpenFile", (void*)&Hk_NtOpenFile, (void**)&Orig_NtOpenFile },
        { "NtDeviceIoControlFile", (void*)&Hk_NtDeviceIoControlFile, (void**)&Orig_NtDeviceIoControlFile },
        { "NtReadFile", (void*)&Hk_NtReadFile, (void**)&Orig_NtReadFile },
        { "NtWriteFile", (void*)&Hk_NtWriteFile, (void**)&Orig_NtWriteFile },
        { "NtClose", (void*)&Hk_NtClose, (void**)&Orig_NtClose },
        { "NtDuplicateObject", (void*)&Hk_NtDuplicateObject, (void**)&Orig_NtDuplicateObject },
    };

    for (auto& Site : Sites) {
        void* Target = HookEngine::Resolve(L"ntdll.dll", Site.Name);
        if (!HookEngine::Install(Site.Name, Target, Site.Detour, Site.Original))
            *Site.Original = Target;  // unhooked: call the real one directly
    }
}

} // namespace DeviceHooks
