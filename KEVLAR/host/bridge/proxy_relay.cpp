#include "host/bridge/proxy_relay.h"

#include "core/io/io_manager.h"
#include "core/exec/unicorn_engine.h"
#include "api/io/io_device.h"

#include <Logger/Logger.h>

#include <windows.h>
#include <atomic>
#include <cstring>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

// After windows.h: kvp_protocol.h needs NTSTATUS/WCHAR/ULONG/UINT64 and CTL_CODE
// already visible (see kvp_protocol.h's own note on why it doesn't self-include).
#include "kvp_protocol.h"

// Raw NTSTATUS literals follow this codebase's existing convention (see
// core/io/irp_ioctl.cpp) of not depending on include/nt_define.h from host code.
namespace {
constexpr int32_t kStatusSuccess = 0;
constexpr int32_t kStatusInvalidHandle = (int32_t)0xC0000008;
constexpr int32_t kStatusObjectNameNotFound = (int32_t)0xC0000034;
constexpr int32_t kStatusInsufficientResources = (int32_t)0xC000009A;

// Requests arrive from a real kernel IRP relayed by kevlarproxy.sys, not from
// literal usermode memory in this process; buffers live in the kernel-range UC
// pool. KernelMode here matches bridge_server.cpp's Phase 1 choice for the same
// reason (kevlar_proxy/README.md SS3.5).
constexpr CHAR kProxyRequestorMode = 0; // KernelMode

constexpr int kWorkerCount = 8; // matches the inverted-call channel depth in README SS4.2
constexpr DWORD kRegistrarPollMs = 250;      // how often to re-scan DeviceTracker for new devices
constexpr int kSymLinkGraceRetries = 10;     // ~500ms total: give IoCreateSymbolicLink a moment to follow IoCreateDevice

// The control handle is shared by every worker thread (kevlarproxy.sys enforces a
// single owner per README SS4.1, so there is exactly one handle to go around).
// Plain synchronous DeviceIoControl relies on a completion event owned by the
// handle's FILE_OBJECT itself; two threads blocking on it concurrently race over
// that single event and can hang or wake the wrong caller. Opening the handle
// FILE_FLAG_OVERLAPPED and giving every call its own OVERLAPPED+event (this
// helper) makes concurrent calls on the shared handle actually independent.
BOOL SyncDeviceIoControl(HANDLE Device, DWORD IoControlCode,
    LPVOID InBuffer, DWORD InSize, LPVOID OutBuffer, DWORD OutSize, LPDWORD BytesReturned) {
    OVERLAPPED Ov{};
    Ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!Ov.hEvent)
        return FALSE;

    BOOL Ok = DeviceIoControl(Device, IoControlCode, InBuffer, InSize, OutBuffer, OutSize, BytesReturned, &Ov);
    if (!Ok && GetLastError() == ERROR_IO_PENDING)
        Ok = GetOverlappedResult(Device, &Ov, BytesReturned, TRUE /* wait */);

    CloseHandle(Ov.hEvent);
    return Ok;
}

struct SessionInfo {
    uint64_t DeviceObjUcAddr;
    uint64_t FileObjUcAddr;
};

std::atomic<bool> Active{ false };
std::atomic<bool> StopRequested{ false };
HANDLE g_CtrlHandle = INVALID_HANDLE_VALUE;
std::vector<std::thread> g_Workers;
std::thread g_RegistrarThread;

// How far into DeviceTracker RegisterNewDevices has already scanned. Only the
// registrar thread (and Start()'s initial synchronous call, before that thread
// exists) touches this -- single writer, so no lock needed for the index itself.
std::atomic<size_t> g_NextDeviceTrackerIndex{ 0 };

// Written by the registrar thread as new devices appear post-DriverEntry (a driver
// spawning a worker thread/deferred init that calls IoCreateDevice later), read by
// every GET_REQUEST worker thread in HandleCreate -- needs a lock now that it is no
// longer a one-shot snapshot built before the workers start.
std::mutex g_DeviceIndexLock;
std::unordered_map<ULONG, uint64_t> g_DeviceIndexMap; // driver DeviceIndex -> DeviceObjUcAddr

std::mutex g_SessionLock;
std::unordered_map<UINT64, SessionInfo> g_Sessions; // driver FileId -> emulated session

bool LookupSession(UINT64 FileId, SessionInfo& Out) {
    std::lock_guard<std::mutex> Guard(g_SessionLock);
    auto It = g_Sessions.find(FileId);
    if (It == g_Sessions.end())
        return false;
    Out = It->second;
    return true;
}

bool TakeSession(UINT64 FileId, SessionInfo& Out) {
    std::lock_guard<std::mutex> Guard(g_SessionLock);
    auto It = g_Sessions.find(FileId);
    if (It == g_Sessions.end())
        return false;
    Out = It->second;
    g_Sessions.erase(It);
    return true;
}

void CopyNameTruncated(WCHAR (&Dest)[KVP_MAX_NAME_CHARS], const std::wstring& Src) {
    size_t CopyChars = Src.size();
    if (CopyChars > KVP_MAX_NAME_CHARS - 1)
        CopyChars = KVP_MAX_NAME_CHARS - 1;
    memcpy(Dest, Src.data(), CopyChars * sizeof(WCHAR));
    Dest[CopyChars] = L'\0';
}

// Registers whatever DeviceTracker entries have appeared since the last call
// (tracked by g_NextDeviceTrackerIndex), then advances that index. Called once
// synchronously in Start() for the common case (device already exists by the time
// DriverEntry returns) and repeatedly by the registrar thread afterward, so a
// driver that creates its device from a worker thread / deferred init *after*
// DriverEntry returns still gets picked up -- this is the actual name registered
// with kevlarproxy.sys: whatever the emulated driver itself called IoCreateDevice
// with, read straight out of DeviceTracker, never hardcoded.
int RegisterNewDevices(HANDLE Ctrl) {
    int Registered = 0;
    size_t Count = DeviceTracker::GetCount();
    size_t Start = g_NextDeviceTrackerIndex.load();

    for (size_t I = Start; I < Count; I++) {
        auto* Dev = DeviceTracker::GetByIndex(I);
        if (!Dev || Dev->DeviceName.empty())
            continue;

        // IoCreateDevice and IoCreateSymbolicLink are two separate emulated calls;
        // a driver observed between them would otherwise get registered with no
        // symlink. Give it a brief window to finish the pair before registering.
        for (int Retry = 0; Dev->SymLinkName.empty() && Retry < kSymLinkGraceRetries && !StopRequested.load(); Retry++) {
            Sleep(50);
            Dev = DeviceTracker::GetByIndex(I);
            if (!Dev)
                break;
        }
        if (!Dev)
            continue;

        KVP_CREATE_DEVICE_IN In;
        memset(&In, 0, sizeof(In));
        CopyNameTruncated(In.DeviceName, Dev->DeviceName);
        CopyNameTruncated(In.SymLinkName, Dev->SymLinkName);
        In.DeviceType = Dev->DeviceType;

        KVP_CREATE_DEVICE_OUT Out{};
        DWORD BytesReturned = 0;
        BOOL Ok = SyncDeviceIoControl(Ctrl, IOCTL_KVP_CREATE_DEVICE,
            &In, sizeof(In), &Out, sizeof(Out), &BytesReturned);

        if (!Ok) {
            Logger::Log("{RED}ProxyRelay: IOCTL_KVP_CREATE_DEVICE transport failed for %ls (err=%lu){RESET}\n",
                Dev->DeviceName.c_str(), GetLastError());
            continue;
        }
        if (Out.Status != kStatusSuccess) {
            Logger::Log("{RED}ProxyRelay: kevlarproxy rejected %ls (status=0x%08x){RESET}\n",
                Dev->DeviceName.c_str(), Out.Status);
            continue;
        }

        {
            std::lock_guard<std::mutex> Guard(g_DeviceIndexLock);
            g_DeviceIndexMap[Out.DeviceIndex] = Dev->UcAddr;
        }
        Registered++;
        Logger::Log("{GRN}ProxyRelay: registered %ls (symlink=%ls) -> proxy slot %u{RESET}\n",
            Dev->DeviceName.c_str(), Dev->SymLinkName.empty() ? L"(none)" : Dev->SymLinkName.c_str(),
            Out.DeviceIndex);
        if (!Dev->SymLinkName.empty() && Out.SymLinkStatus != kStatusSuccess) {
            Logger::Log("{YEL}ProxyRelay: symlink %ls (len=%zu) -> %ls failed (status=0x%08x, sentinel=%s); "
                "device is still reachable via \\\\.\\GLOBALROOT\\Device path{RESET}\n",
                Dev->SymLinkName.c_str(), Dev->SymLinkName.size(), Dev->DeviceName.c_str(), Out.SymLinkStatus,
                Out.SymLinkStatus == (int32_t)0x7FFFFFFF ? "true (never attempted)" : "false");
        }
    }

    g_NextDeviceTrackerIndex.store(Count);
    return Registered;
}

void RegistrarLoop(HANDLE Ctrl) {
    while (!StopRequested.load()) {
        RegisterNewDevices(Ctrl);
        for (int I = 0; I < 5 && !StopRequested.load(); I++)
            Sleep(kRegistrarPollMs / 5);
    }
}

void HandleCreate(const KVP_REQUEST_HEADER& Hdr, KVP_COMPLETE_HEADER& Resp, std::vector<uint8_t>&) {
    uint64_t DeviceObjUcAddr;
    {
        std::lock_guard<std::mutex> Guard(g_DeviceIndexLock);
        auto It = g_DeviceIndexMap.find(Hdr.DeviceIndex);
        if (It == g_DeviceIndexMap.end()) {
            Resp.Status = kStatusObjectNameNotFound;
            return;
        }
        DeviceObjUcAddr = It->second;
    }

    uint64_t FileObjUcAddr;
    IoManager::DispatchResult Result;
    {
        std::lock_guard<std::mutex> Guard(IoManager::DispatchMutex);
        FileObjUcAddr = IoManager::AllocateFileObject(UnicornEmu::PrimaryEngine, DeviceObjUcAddr);
        if (!FileObjUcAddr) {
            Resp.Status = kStatusInsufficientResources;
            return;
        }
        Result = IoManager::DispatchCreate(DeviceObjUcAddr, FileObjUcAddr, kProxyRequestorMode);
        if (Result.Status < 0)
            IoManager::FreeFileObject(FileObjUcAddr);
    }

    if (Result.Status >= 0) {
        std::lock_guard<std::mutex> Guard(g_SessionLock);
        g_Sessions[Hdr.FileId] = { DeviceObjUcAddr, FileObjUcAddr };
    }

    Resp.Status = Result.Status;
    Resp.Information = Result.Information;
}

void HandleClose(const KVP_REQUEST_HEADER& Hdr, KVP_COMPLETE_HEADER& Resp, std::vector<uint8_t>&) {
    SessionInfo Sess;
    if (!TakeSession(Hdr.FileId, Sess)) {
        // A CREATE that the emulated driver rejected still gets a real MJ_CLOSE
        // (standard WDM contract) with nothing on our side to close -- benign.
        Resp.Status = kStatusSuccess;
        return;
    }

    IoManager::DispatchResult Result;
    {
        std::lock_guard<std::mutex> Guard(IoManager::DispatchMutex);
        Result = IoManager::DispatchClose(Sess.DeviceObjUcAddr, Sess.FileObjUcAddr, kProxyRequestorMode);
        IoManager::FreeFileObject(Sess.FileObjUcAddr);
    }
    Resp.Status = Result.Status;
    Resp.Information = Result.Information;
}

void HandleCleanup(const KVP_REQUEST_HEADER& Hdr, KVP_COMPLETE_HEADER& Resp, std::vector<uint8_t>&) {
    SessionInfo Sess;
    if (!LookupSession(Hdr.FileId, Sess)) {
        Resp.Status = kStatusSuccess;
        return;
    }
    std::lock_guard<std::mutex> Guard(IoManager::DispatchMutex);
    IoManager::DispatchResult Result = IoManager::DispatchCleanup(Sess.DeviceObjUcAddr, Sess.FileObjUcAddr, kProxyRequestorMode);
    Resp.Status = Result.Status;
    Resp.Information = Result.Information;
}

void HandleDeviceControl(const KVP_REQUEST_HEADER& Hdr, const uint8_t* InPayload,
    KVP_COMPLETE_HEADER& Resp, std::vector<uint8_t>& OutPayload) {
    SessionInfo Sess;
    if (!LookupSession(Hdr.FileId, Sess)) {
        Resp.Status = kStatusInvalidHandle;
        return;
    }

    OutPayload.resize(Hdr.OutCap);
    ULONG BytesReturned = 0;
    IoManager::DispatchResult Result;
    {
        std::lock_guard<std::mutex> Guard(IoManager::DispatchMutex);
        Result = IoManager::DispatchDeviceIoControl(
            Sess.DeviceObjUcAddr, Sess.FileObjUcAddr,
            Hdr.IoControlCode,
            const_cast<uint8_t*>(InPayload), Hdr.InLen,
            OutPayload.empty() ? nullptr : OutPayload.data(), Hdr.OutCap,
            &BytesReturned, kProxyRequestorMode);
    }

    Resp.Status = Result.Status;
    Resp.Information = Result.Information;
    ULONG CopyLen = (BytesReturned < Hdr.OutCap) ? BytesReturned : Hdr.OutCap;
    OutPayload.resize(CopyLen);
}

void HandleRead(const KVP_REQUEST_HEADER& Hdr, KVP_COMPLETE_HEADER& Resp, std::vector<uint8_t>& OutPayload) {
    SessionInfo Sess;
    if (!LookupSession(Hdr.FileId, Sess)) {
        Resp.Status = kStatusInvalidHandle;
        return;
    }

    OutPayload.resize(Hdr.OutCap);
    ULONG BytesRead = 0;
    IoManager::DispatchResult Result;
    {
        std::lock_guard<std::mutex> Guard(IoManager::DispatchMutex);
        Result = IoManager::DispatchRead(
            Sess.DeviceObjUcAddr, Sess.FileObjUcAddr,
            OutPayload.empty() ? nullptr : OutPayload.data(), Hdr.OutCap,
            0, &BytesRead, kProxyRequestorMode);
    }

    Resp.Status = Result.Status;
    Resp.Information = Result.Information;
    ULONG CopyLen = (BytesRead < Hdr.OutCap) ? BytesRead : Hdr.OutCap;
    OutPayload.resize(CopyLen);
}

void HandleWrite(const KVP_REQUEST_HEADER& Hdr, const uint8_t* InPayload,
    KVP_COMPLETE_HEADER& Resp, std::vector<uint8_t>&) {
    SessionInfo Sess;
    if (!LookupSession(Hdr.FileId, Sess)) {
        Resp.Status = kStatusInvalidHandle;
        return;
    }

    ULONG BytesWritten = 0;
    IoManager::DispatchResult Result;
    {
        std::lock_guard<std::mutex> Guard(IoManager::DispatchMutex);
        Result = IoManager::DispatchWrite(
            Sess.DeviceObjUcAddr, Sess.FileObjUcAddr,
            const_cast<uint8_t*>(InPayload), Hdr.InLen,
            0, &BytesWritten, kProxyRequestorMode);
    }
    Resp.Status = Result.Status;
    Resp.Information = Result.Information;
}

void WorkerLoop(HANDLE Ctrl) {
    std::vector<uint8_t> GetBuf(sizeof(KVP_REQUEST_HEADER) + KVP_MAX_PAYLOAD);

    while (!StopRequested.load()) {
        DWORD BytesReturned = 0;
        BOOL Ok = SyncDeviceIoControl(Ctrl, IOCTL_KVP_GET_REQUEST,
            nullptr, 0, GetBuf.data(), (DWORD)GetBuf.size(), &BytesReturned);

        if (!Ok) {
            // Canceled (Stop()) or the driver tore everything down because the
            // control handle went away -- either way, nothing more to serve.
            break;
        }
        if (BytesReturned < sizeof(KVP_REQUEST_HEADER))
            continue;

        KVP_REQUEST_HEADER Hdr;
        memcpy(&Hdr, GetBuf.data(), sizeof(Hdr));
        const uint8_t* InPayload = GetBuf.data() + sizeof(Hdr);

        KVP_COMPLETE_HEADER Resp{};
        Resp.RequestId = Hdr.RequestId;
        Resp.Status = kStatusSuccess;
        std::vector<uint8_t> OutPayload;

        switch ((KVP_MAJOR_OP)Hdr.Op) {
        case KvpOpCreate:        HandleCreate(Hdr, Resp, OutPayload); break;
        case KvpOpClose:         HandleClose(Hdr, Resp, OutPayload); break;
        case KvpOpCleanup:       HandleCleanup(Hdr, Resp, OutPayload); break;
        case KvpOpDeviceControl: HandleDeviceControl(Hdr, InPayload, Resp, OutPayload); break;
        case KvpOpRead:          HandleRead(Hdr, Resp, OutPayload); break;
        case KvpOpWrite:         HandleWrite(Hdr, InPayload, Resp, OutPayload); break;
        default:
            Resp.Status = kStatusInvalidHandle;
            break;
        }

        Resp.OutLen = (ULONG)OutPayload.size();

        std::vector<uint8_t> CompleteBuf(sizeof(Resp) + OutPayload.size());
        memcpy(CompleteBuf.data(), &Resp, sizeof(Resp));
        if (!OutPayload.empty())
            memcpy(CompleteBuf.data() + sizeof(Resp), OutPayload.data(), OutPayload.size());

        SyncDeviceIoControl(Ctrl, IOCTL_KVP_COMPLETE_REQUEST,
            CompleteBuf.data(), (DWORD)CompleteBuf.size(), nullptr, 0, &BytesReturned);
    }
}

} // namespace

namespace ProxyRelay {

bool Start() {
    if (Active.load())
        return false;

    HANDLE Ctrl = CreateFileW(L"\\\\.\\KevlarProxyCtl",
        GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
    if (Ctrl == INVALID_HANDLE_VALUE) {
        Logger::Log("{RED}ProxyRelay: failed to open \\\\.\\KevlarProxyCtl (err=%lu) -- "
            "is kevlarproxy.sys loaded, and is this the only instance?{RESET}\n", GetLastError());
        return false;
    }

    {
        std::lock_guard<std::mutex> Guard(g_DeviceIndexLock);
        g_DeviceIndexMap.clear();
    }
    g_NextDeviceTrackerIndex.store(0);

    // Registers whatever DeviceTracker already has (the common case: DriverEntry
    // created its device directly). Not a failure if this finds nothing yet --
    // the registrar thread below keeps watching for devices a driver creates later
    // from a worker thread or deferred init.
    int Registered = RegisterNewDevices(Ctrl);
    Logger::Log("{CYN}ProxyRelay: %d device(s) registered at startup; watching for more{RESET}\n", Registered);

    g_CtrlHandle = Ctrl;
    StopRequested = false;
    Active = true;

    g_Workers.clear();
    g_Workers.reserve(kWorkerCount);
    for (int I = 0; I < kWorkerCount; I++)
        g_Workers.emplace_back(WorkerLoop, Ctrl);

    g_RegistrarThread = std::thread(RegistrarLoop, Ctrl);

    return true;
}

void Stop() {
    if (!Active.load())
        return;

    StopRequested = true;
    // Unblocks every worker's in-flight IOCTL_KVP_GET_REQUEST: kevlarproxy.sys's
    // cancel routine completes them with STATUS_CANCELLED.
    CancelIoEx(g_CtrlHandle, nullptr);

    for (auto& T : g_Workers) {
        if (T.joinable())
            T.join();
    }
    g_Workers.clear();

    // The registrar thread wakes from its Sleep loop and exits on its own once it
    // observes StopRequested; its own SyncDeviceIoControl calls (if any are briefly
    // in flight) share the same CancelIoEx above.
    if (g_RegistrarThread.joinable())
        g_RegistrarThread.join();

    // Closing the control handle fires kevlarproxy.sys's own cleanup, which fails
    // any request that arrived after CancelIoEx and deletes every exposed device
    // (kevlar_proxy/README.md SS4.4).
    CloseHandle(g_CtrlHandle);
    g_CtrlHandle = INVALID_HANDLE_VALUE;

    {
        std::lock_guard<std::mutex> Guard(g_SessionLock);
        g_Sessions.clear();
    }
    {
        std::lock_guard<std::mutex> Guard(g_DeviceIndexLock);
        g_DeviceIndexMap.clear();
    }

    Active = false;
}

bool IsActive() {
    return Active.load();
}

} // namespace ProxyRelay
