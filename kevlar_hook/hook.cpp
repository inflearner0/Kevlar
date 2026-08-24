// kevlar_hook.dll -- injected into an unmodified client so its device I/O against a
// matched device path is redirected to the KEVLAR --serve bridge pipe instead of the
// real kernel driver. This is the "client is unmodified but injectable" path from
// kevlar_proxy/README.md SS6: no unsigned driver, no reboot, no kernel attack surface.
//
// Offline analysis only. It does not, and cannot, defeat test-signing detection, driver
// enumeration, or a real integrity handshake -- see kevlar_proxy/README.md SS2.

#include <windows.h>
#include <winternl.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <algorithm>

#include "../KEVLAR/host/bridge/bridge_protocol.h"

typedef LONG NTSTATUS;

typedef void (NTAPI *PIO_APC_ROUTINE)(PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG Reserved);

typedef NTSTATUS(NTAPI* PFN_NtCreateFile)(
    PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

typedef NTSTATUS(NTAPI* PFN_NtDeviceIoControlFile)(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength);

typedef NTSTATUS(NTAPI* PFN_NtReadWriteFile)(
    HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

typedef NTSTATUS(NTAPI* PFN_NtClose)(HANDLE Handle);

namespace {

// ---- logging -------------------------------------------------------------

std::mutex g_LogLock;
FILE* g_LogFile = nullptr;

void LogInit() {
    wchar_t path[MAX_PATH];
    DWORD n = GetEnvironmentVariableW(L"KEVLAR_HOOK_LOG", path, MAX_PATH);
    if (!n || n >= MAX_PATH) {
        wchar_t tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, tmp);
        swprintf_s(path, L"%skevlar_hook.log", tmp);
    }
    _wfopen_s(&g_LogFile, path, L"a, ccs=UTF-8");
}

void Log(const char* fmt, ...) {
    std::lock_guard<std::mutex> guard(g_LogLock);
    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    OutputDebugStringA(buf);
    if (g_LogFile) {
        fprintf(g_LogFile, "[%lu] %s\n", GetCurrentThreadId(), buf);
        fflush(g_LogFile);
    }
}

// ---- configuration --------------------------------------------------------

std::wstring g_PipeName = L"\\\\.\\pipe\\kevlar-EasyAntiCheat_EOS";
std::wstring g_DeviceName = L"\\Device\\EasyAntiCheat_EOS";
std::wstring g_MatchSubstr = L"EASYANTICHEAT";

std::wstring EnvOr(const wchar_t* name, const std::wstring& fallback) {
    wchar_t buf[512];
    DWORD n = GetEnvironmentVariableW(name, buf, 512);
    if (n && n < 512) return std::wstring(buf, n);
    return fallback;
}

std::wstring ToUpper(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towupper);
    return s;
}

bool PathMatches(POBJECT_ATTRIBUTES oa) {
    if (!oa || !oa->ObjectName || !oa->ObjectName->Buffer || !oa->ObjectName->Length)
        return false;
    std::wstring path(oa->ObjectName->Buffer, oa->ObjectName->Length / sizeof(wchar_t));
    return ToUpper(path).find(g_MatchSubstr) != std::wstring::npos;
}

// ---- transport: one bridge pipe connection, request/response is one message each ----

std::mutex g_PipeLock;
HANDLE g_Pipe = INVALID_HANDLE_VALUE;

bool EnsurePipeConnected() {
    std::lock_guard<std::mutex> guard(g_PipeLock);
    if (g_Pipe != INVALID_HANDLE_VALUE)
        return true;
    for (int attempt = 0; attempt < 5; attempt++) {
        HANDLE h = CreateFileW(g_PipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
            OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            DWORD mode = PIPE_READMODE_MESSAGE;
            SetNamedPipeHandleState(h, &mode, nullptr, nullptr);
            g_Pipe = h;
            Log("Connected to %ls", g_PipeName.c_str());
            return true;
        }
        if (GetLastError() != ERROR_PIPE_BUSY) {
            Log("CreateFile(%ls) failed, gle=%lu", g_PipeName.c_str(), GetLastError());
            break;
        }
        WaitNamedPipeW(g_PipeName.c_str(), 2000);
    }
    return false;
}

// Serializes the whole request/response exchange -- the server side dispatches one IRP
// at a time anyway (KEVLAR/core/io/io_manager.h DispatchMutex), so there is no
// concurrency to gain by pipelining multiple in-flight requests here.
bool SendRecv(Bridge::Opcode op, uint64_t session, uint32_t ioctl,
    const void* inBuf, uint32_t inLen, void* outBuf, uint32_t outCap,
    Bridge::ResponseHeader& outHdr, uint32_t& outLen) {
    if (!EnsurePipeConnected())
        return false;

    std::vector<uint8_t> req(sizeof(Bridge::RequestHeader) + inLen);
    auto* hdr = reinterpret_cast<Bridge::RequestHeader*>(req.data());
    hdr->Magic = Bridge::kMagic;
    hdr->Version = Bridge::kVersion;
    hdr->Opcode = static_cast<uint16_t>(op);
    hdr->Session = session;
    hdr->IoControlCode = ioctl;
    hdr->InLen = inLen;
    hdr->OutLen = outCap;
    if (inLen && inBuf)
        memcpy(req.data() + sizeof(*hdr), inBuf, inLen);

    std::lock_guard<std::mutex> guard(g_PipeLock);
    bool ok = true;
    DWORD written = 0;
    if (!WriteFile(g_Pipe, req.data(), (DWORD)req.size(), &written, nullptr) || written != req.size())
        ok = false;

    std::vector<uint8_t> resp;
    if (ok) {
        resp.resize(sizeof(Bridge::ResponseHeader) + (size_t)outCap);
        DWORD got = 0;
        if (!ReadFile(g_Pipe, resp.data(), (DWORD)resp.size(), &got, nullptr))
            ok = false;
        else if (got < sizeof(Bridge::ResponseHeader))
            ok = false;
        else {
            memcpy(&outHdr, resp.data(), sizeof(outHdr));
            outLen = (std::min)(outHdr.OutLen, (uint32_t)(got - sizeof(outHdr)));
            if (outBuf && outLen)
                memcpy(outBuf, resp.data() + sizeof(outHdr), (std::min)(outLen, outCap));
        }
    }

    if (!ok) {
        Log("Transport error on opcode %u, gle=%lu -- dropping connection", (unsigned)op, GetLastError());
        CloseHandle(g_Pipe);
        g_Pipe = INVALID_HANDLE_VALUE;
    }
    return ok;
}

// ---- pseudo-handle table: real client HANDLEs the kernel never issued -----------

std::mutex g_HandleLock;
std::unordered_map<HANDLE, uint64_t> g_Sessions;
volatile LONG64 g_NextHandle = 0x0EAC0004;

HANDLE AllocPseudoHandle(uint64_t session) {
    HANDLE h = (HANDLE)(uintptr_t)InterlockedAdd64(&g_NextHandle, 4);
    std::lock_guard<std::mutex> guard(g_HandleLock);
    g_Sessions[h] = session;
    return h;
}

bool LookupSession(HANDLE h, uint64_t& session) {
    std::lock_guard<std::mutex> guard(g_HandleLock);
    auto it = g_Sessions.find(h);
    if (it == g_Sessions.end())
        return false;
    session = it->second;
    return true;
}

void RemoveSession(HANDLE h) {
    std::lock_guard<std::mutex> guard(g_HandleLock);
    g_Sessions.erase(h);
}

// ---- inline hooking ---------------------------------------------------------------
//
// ntdll x64 syscall stubs are a short straight-line sequence ending in a single `ret`
// (mov r10,rcx; mov eax,imm32; syscall; ret -- 12 bytes on a normal desktop build).
// Scanning for the first 0xC3 gives the stub length without a real disassembler. This
// does not handle the rare hypervisor-only stub shape with a secondary int-2e tail
// (SharedUserData+0x308 branch); that path is not reachable on bare-metal Windows.
size_t FindStubLength(const uint8_t* code) {
    for (size_t i = 0; i < 31; i++) {
        if (code[i] == 0xC3)
            return i + 1;
    }
    return 0;
}

struct HookSite {
    const char* Name;
    void* Target;
    void* Trampoline;
    void* Detour;
};

bool InstallHook(HookSite& site) {
    size_t len = FindStubLength((const uint8_t*)site.Target);
    if (len < 12) {
        Log("SKIP %s: stub length %zu < 12, not hooking", site.Name, len);
        return false;
    }

    site.Trampoline = VirtualAlloc(nullptr, len + 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!site.Trampoline) {
        Log("SKIP %s: VirtualAlloc failed", site.Name);
        return false;
    }
    memcpy(site.Trampoline, site.Target, len);
    uint8_t* tj = (uint8_t*)site.Trampoline + len;
    tj[0] = 0x48; tj[1] = 0xB8;
    *(uint64_t*)&tj[2] = (uint64_t)((uint8_t*)site.Target + len);
    tj[10] = 0xFF; tj[11] = 0xE0; // jmp rax

    DWORD oldProt;
    if (!VirtualProtect(site.Target, len, PAGE_EXECUTE_READWRITE, &oldProt)) {
        Log("SKIP %s: VirtualProtect failed", site.Name);
        return false;
    }
    uint8_t patch[12];
    patch[0] = 0x48; patch[1] = 0xB8;
    *(uint64_t*)&patch[2] = (uint64_t)site.Detour;
    patch[10] = 0xFF; patch[11] = 0xE0;
    memcpy(site.Target, patch, 12);
    for (size_t i = 12; i < len; i++)
        ((uint8_t*)site.Target)[i] = 0x90;
    VirtualProtect(site.Target, len, oldProt, &oldProt);
    FlushInstructionCache(GetCurrentProcess(), site.Target, len);

    Log("HOOKED %s (stub len=%zu)", site.Name, len);
    return true;
}

// ---- detours ----------------------------------------------------------------------

PFN_NtCreateFile Orig_NtCreateFile;
PFN_NtDeviceIoControlFile Orig_NtDeviceIoControlFile;
PFN_NtReadWriteFile Orig_NtReadFile;
PFN_NtReadWriteFile Orig_NtWriteFile;
PFN_NtClose Orig_NtClose;

NTSTATUS NTAPI Hk_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    if (PathMatches(ObjectAttributes)) {
        std::wstring reqPath(ObjectAttributes->ObjectName->Buffer, ObjectAttributes->ObjectName->Length / sizeof(wchar_t));
        Log("MATCH NtCreateFile %ls -> Open(%ls)", reqPath.c_str(), g_DeviceName.c_str());

        Bridge::ResponseHeader resp{};
        uint32_t outLen = 0;
        if (!SendRecv(Bridge::Opcode::Open, 0, 0, g_DeviceName.data(),
                (uint32_t)(g_DeviceName.size() * sizeof(wchar_t)), nullptr, 0, resp, outLen)) {
            Log("Open transport failed, falling back to real NtCreateFile");
        } else {
            if (IoStatusBlock) {
                IoStatusBlock->Status = resp.Status;
                IoStatusBlock->Information = resp.Status >= 0 ? (resp.Information ? resp.Information : 1) : 0;
            }
            if (resp.Status >= 0) {
                HANDLE h = AllocPseudoHandle(resp.Session);
                *FileHandle = h;
                Log("Open OK -> pseudo handle %p (session=%llu)", h, (unsigned long long)resp.Session);
            } else {
                Log("Open rejected by bridge, status=0x%08x", (unsigned)resp.Status);
            }
            return (NTSTATUS)resp.Status;
        }
    }
    return Orig_NtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize,
        FileAttributes, ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}

NTSTATUS NTAPI Hk_NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength) {
    uint64_t session;
    if (LookupSession(FileHandle, session)) {
        if (ApcRoutine)
            Log("WARN: NEITHER/APC-completion IOCTL 0x%x on pseudo handle, completing synchronously anyway", IoControlCode);

        Bridge::ResponseHeader resp{};
        uint32_t outLen = 0;
        bool ok = SendRecv(Bridge::Opcode::Ioctl, session, IoControlCode, InputBuffer, InputBufferLength,
            OutputBuffer, OutputBufferLength, resp, outLen);
        NTSTATUS status = ok ? (NTSTATUS)resp.Status : (NTSTATUS)0xC0000001; // STATUS_UNSUCCESSFUL
        if (IoStatusBlock) {
            IoStatusBlock->Status = status;
            IoStatusBlock->Information = ok ? resp.Information : 0;
        }
        if (Event) SetEvent(Event);
        return status;
    }
    return Orig_NtDeviceIoControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, IoControlCode,
        InputBuffer, InputBufferLength, OutputBuffer, OutputBufferLength);
}

NTSTATUS NTAPI Hk_NtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    uint64_t session;
    if (LookupSession(FileHandle, session)) {
        Bridge::ResponseHeader resp{};
        uint32_t outLen = 0;
        bool ok = SendRecv(Bridge::Opcode::Read, session, 0, nullptr, 0, Buffer, Length, resp, outLen);
        NTSTATUS status = ok ? (NTSTATUS)resp.Status : (NTSTATUS)0xC0000001;
        if (IoStatusBlock) {
            IoStatusBlock->Status = status;
            IoStatusBlock->Information = ok ? resp.Information : 0;
        }
        if (Event) SetEvent(Event);
        return status;
    }
    return Orig_NtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS NTAPI Hk_NtWriteFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    uint64_t session;
    if (LookupSession(FileHandle, session)) {
        Bridge::ResponseHeader resp{};
        uint32_t outLen = 0;
        bool ok = SendRecv(Bridge::Opcode::Write, session, 0, Buffer, Length, nullptr, 0, resp, outLen);
        NTSTATUS status = ok ? (NTSTATUS)resp.Status : (NTSTATUS)0xC0000001;
        if (IoStatusBlock) {
            IoStatusBlock->Status = status;
            IoStatusBlock->Information = ok ? resp.Information : 0;
        }
        if (Event) SetEvent(Event);
        return status;
    }
    return Orig_NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
}

NTSTATUS NTAPI Hk_NtClose(HANDLE Handle) {
    uint64_t session;
    if (LookupSession(Handle, session)) {
        Bridge::ResponseHeader resp{};
        uint32_t outLen = 0;
        SendRecv(Bridge::Opcode::Close, session, 0, nullptr, 0, nullptr, 0, resp, outLen);
        RemoveSession(Handle);
        Log("Close pseudo handle %p (session=%llu)", Handle, (unsigned long long)session);
        return 0; // STATUS_SUCCESS
    }
    return Orig_NtClose(Handle);
}

void InstallAllHooks() {
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");

    HookSite sites[] = {
        { "NtCreateFile", GetProcAddress(ntdll, "NtCreateFile"), nullptr, (void*)&Hk_NtCreateFile },
        { "NtDeviceIoControlFile", GetProcAddress(ntdll, "NtDeviceIoControlFile"), nullptr, (void*)&Hk_NtDeviceIoControlFile },
        { "NtReadFile", GetProcAddress(ntdll, "NtReadFile"), nullptr, (void*)&Hk_NtReadFile },
        { "NtWriteFile", GetProcAddress(ntdll, "NtWriteFile"), nullptr, (void*)&Hk_NtWriteFile },
        { "NtClose", GetProcAddress(ntdll, "NtClose"), nullptr, (void*)&Hk_NtClose },
    };

    for (auto& s : sites) {
        if (!s.Target) { Log("SKIP %s: not found in ntdll", s.Name); continue; }
        InstallHook(s);
    }

    Orig_NtCreateFile = (PFN_NtCreateFile)(sites[0].Trampoline ? sites[0].Trampoline : sites[0].Target);
    Orig_NtDeviceIoControlFile = (PFN_NtDeviceIoControlFile)(sites[1].Trampoline ? sites[1].Trampoline : sites[1].Target);
    Orig_NtReadFile = (PFN_NtReadWriteFile)(sites[2].Trampoline ? sites[2].Trampoline : sites[2].Target);
    Orig_NtWriteFile = (PFN_NtReadWriteFile)(sites[3].Trampoline ? sites[3].Trampoline : sites[3].Target);
    Orig_NtClose = (PFN_NtClose)(sites[4].Trampoline ? sites[4].Trampoline : sites[4].Target);
}

} // namespace

BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        LogInit();
        g_PipeName = EnvOr(L"KEVLAR_HOOK_PIPE", g_PipeName);
        g_DeviceName = EnvOr(L"KEVLAR_HOOK_DEVICE", g_DeviceName);
        g_MatchSubstr = ToUpper(EnvOr(L"KEVLAR_HOOK_MATCH", g_MatchSubstr));
        Log("kevlar_hook attached: pipe=%ls device=%ls match=%ls",
            g_PipeName.c_str(), g_DeviceName.c_str(), g_MatchSubstr.c_str());
        InstallAllHooks();
    }
    return TRUE;
}
