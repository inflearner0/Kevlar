#include "service_hooks.h"
#include "bridge_client.h"
#include "hook_engine.h"
#include "kevlar_hook.h"
#include "process_hooks.h"
#include "reentry.h"

#include <windows.h>
#include <winsvc.h>
#include <winternl.h>

#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using KevlarHook::EnvOr;
using KevlarHook::IEquals;
using KevlarHook::Log;
using KevlarHook::ToUpper;

typedef LONG NTSTATUS;

namespace {

constexpr NTSTATUS kStatusSuccess = 0;

// ---- the service database this DLL pretends to be -------------------------------

struct ServiceRecord {
    std::wstring Name;
    std::wstring DisplayName;
    std::wstring BinaryPath;
    DWORD ServiceType = SERVICE_KERNEL_DRIVER;
    DWORD StartType = SERVICE_DEMAND_START;
    DWORD ErrorControl = SERVICE_ERROR_NORMAL;
    DWORD CurrentState = SERVICE_STOPPED;
    bool Deleted = false;
};

struct ServiceState {
    std::mutex Lock;
    std::unordered_map<std::wstring, ServiceRecord> Services;  // keyed on the upper-cased name
    std::unordered_map<SC_HANDLE, std::wstring> ServiceHandles;
    std::unordered_set<SC_HANDLE> ManagerHandles;

    // Fake SC_HANDLEs are addresses inside a page this DLL owns, so their values can never
    // collide with a real SCM handle the same process is holding. Handing back a small
    // integer would work right up until something compared it against a real one.
    uint8_t* HandlePage = nullptr;
    size_t HandleCapacity = 4096;
    size_t NextSlot = 0;
    std::vector<size_t> FreeSlots;
};

// Deliberately never destroyed (KevlarHook::Immortal): CloseServiceHandle can arrive
// during process teardown. These are references rather than accessor calls only so the
// code below reads the way it would with plain globals; a reference has no destructor.
ServiceState& StateRef = KevlarHook::Immortal<ServiceState>();
std::mutex& g_Lock = StateRef.Lock;
auto& g_Services = StateRef.Services;
auto& g_ServiceHandles = StateRef.ServiceHandles;
auto& g_ManagerHandles = StateRef.ManagerHandles;

constexpr size_t kHandleStride = 16;

SC_HANDLE AllocFakeHandleLocked() {
    if (!StateRef.HandlePage) {
        StateRef.HandlePage = (uint8_t*)VirtualAlloc(nullptr, StateRef.HandleCapacity * kHandleStride,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!StateRef.HandlePage)
            return nullptr;
    }
    size_t Slot = 0;
    if (!StateRef.FreeSlots.empty()) {
        Slot = StateRef.FreeSlots.back();
        StateRef.FreeSlots.pop_back();
    } else if (StateRef.NextSlot < StateRef.HandleCapacity) {
        Slot = StateRef.NextSlot++;
    } else {
        Log("Out of fake service handles (%zu in use)", StateRef.HandleCapacity);
        return nullptr;
    }
    return (SC_HANDLE)(StateRef.HandlePage + (Slot * kHandleStride));
}

bool IsFakeManager(SC_HANDLE Handle) {
    std::lock_guard<std::mutex> Guard(g_Lock);
    return g_ManagerHandles.count(Handle) != 0;
}

// Copies out the record a fake service handle refers to. Returns false for a real
// handle, which the caller then passes through untouched.
bool LookupService(SC_HANDLE Handle, ServiceRecord& Out) {
    std::lock_guard<std::mutex> Guard(g_Lock);
    auto HandleIt = g_ServiceHandles.find(Handle);
    if (HandleIt == g_ServiceHandles.end())
        return false;
    auto ServiceIt = g_Services.find(HandleIt->second);
    if (ServiceIt == g_Services.end())
        return false;
    Out = ServiceIt->second;
    return true;
}

template <typename Fn>
bool UpdateService(SC_HANDLE Handle, Fn&& Mutate) {
    std::lock_guard<std::mutex> Guard(g_Lock);
    auto HandleIt = g_ServiceHandles.find(Handle);
    if (HandleIt == g_ServiceHandles.end())
        return false;
    auto ServiceIt = g_Services.find(HandleIt->second);
    if (ServiceIt == g_Services.end())
        return false;
    Mutate(ServiceIt->second);
    return true;
}

std::wstring Widen(const char* Narrow) {
    if (!Narrow)
        return {};
    int Chars = MultiByteToWideChar(CP_ACP, 0, Narrow, -1, nullptr, 0);
    if (Chars <= 1)
        return {};
    std::wstring Wide(Chars - 1, L'\0');
    MultiByteToWideChar(CP_ACP, 0, Narrow, -1, Wide.data(), Chars);
    return Wide;
}

// ---- interception policy ---------------------------------------------------------
//
// Default: every kernel/file-system driver service the client tries to install is faked,
// because letting one of them actually load defeats the point of emulating it. Ordinary
// Win32 services are passed through untouched. KEVLAR_HOOK_SERVICE narrows this to a
// single name for a client that legitimately installs more than one driver.

bool NameIsRestricted(const std::wstring& Name) {
    std::wstring Only = EnvOr(L"KEVLAR_HOOK_SERVICE", L"");
    return !Only.empty() && !IEquals(Only, Name);
}

bool ShouldFakeCreate(const std::wstring& Name, DWORD ServiceType) {
    if (!(ServiceType & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)))
        return false;
    return !NameIsRestricted(Name);
}

// A known name can be handled without touching the real SCM. Unknown names are opened
// normally and inspected below: kernel/file-system drivers are converted to fake handles,
// while ordinary Win32 services keep their real handles.
bool ShouldFakeOpen(const std::wstring& Name) {
    {
        std::lock_guard<std::mutex> Guard(g_Lock);
        if (g_Services.count(ToUpper(Name)))
            return true;
    }
    if (IEquals(EnvOr(L"KEVLAR_HOOK_SERVICE", L""), Name))
        return true;

    std::wstring Leaf = KevlarHook::DeviceLeaf(Name);
    for (const auto& Device : BridgeClient::Devices()) {
        if (KevlarHook::DeviceLeaf(Device.DeviceName) == Leaf ||
                (!Device.SymLinkName.empty() && KevlarHook::DeviceLeaf(Device.SymLinkName) == Leaf))
            return true;
    }
    return false;
}

// ---- shared implementations ------------------------------------------------------

SC_HANDLE FakeCreate(const std::wstring& Name, const std::wstring& DisplayName,
    const std::wstring& BinaryPath, DWORD ServiceType, DWORD StartType, DWORD ErrorControl) {
    std::lock_guard<std::mutex> Guard(g_Lock);
    SC_HANDLE Handle = AllocFakeHandleLocked();
    if (!Handle) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }

    ServiceRecord& Record = g_Services[ToUpper(Name)];
    Record.Name = Name;
    Record.DisplayName = DisplayName.empty() ? Name : DisplayName;
    Record.BinaryPath = BinaryPath;
    Record.ServiceType = ServiceType;
    Record.StartType = StartType;
    Record.ErrorControl = ErrorControl;
    Record.CurrentState = SERVICE_STOPPED;
    Record.Deleted = false;
    g_ServiceHandles[Handle] = ToUpper(Name);

    Log("CreateService faked: name=%ls type=0x%x start=%u image=%ls -> handle %p",
        Name.c_str(), ServiceType, StartType, BinaryPath.c_str(), (void*)Handle);
    SetLastError(ERROR_SUCCESS);
    return Handle;
}

SC_HANDLE FakeOpen(const std::wstring& Name, const ServiceRecord* Seed = nullptr) {
    std::lock_guard<std::mutex> Guard(g_Lock);
    SC_HANDLE Handle = AllocFakeHandleLocked();
    if (!Handle) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return nullptr;
    }

    std::wstring Key = ToUpper(Name);
    auto It = g_Services.find(Key);
    if (It == g_Services.end()) {
        ServiceRecord& Record = g_Services[Key];
        Record.Name = Name;
        Record.DisplayName = Name;
        if (Seed) {
            Record.DisplayName = Seed->DisplayName.empty() ? Name : Seed->DisplayName;
            Record.BinaryPath = Seed->BinaryPath;
            Record.ServiceType = Seed->ServiceType;
            Record.StartType = Seed->StartType;
            Record.ErrorControl = Seed->ErrorControl;
        }
    } else if (It->second.Deleted) {
        // A deleted service is gone until it is created again.
        SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
        return nullptr;
    }
    g_ServiceHandles[Handle] = Key;

    Log("OpenService faked: name=%ls -> handle %p", Name.c_str(), (void*)Handle);
    SetLastError(ERROR_SUCCESS);
    return Handle;
}

BOOL FakeStart(SC_HANDLE Handle) {
    ServiceRecord Record{};
    if (!UpdateService(Handle, [](ServiceRecord& R) { R.CurrentState = SERVICE_RUNNING; }))
        return FALSE;
    LookupService(Handle, Record);

    Log("StartService faked: name=%ls now SERVICE_RUNNING (no driver was loaded)",
        Record.Name.c_str());

    // The client's next move is to open the device. If the emulator is not listening,
    // that open fails with a status the client will read as "my driver did not start",
    // which is worth saying plainly here rather than leaving it to be inferred.
    if (BridgeClient::Devices().empty())
        Log("WARN: %ls is not answering. Start KEVLAR.exe <driver.sys> --serve before the "
            "client opens the device, or the open will fail.",
            KevlarHook::PipeName().empty() ? L"<no pipe name known>" : KevlarHook::PipeName().c_str());

    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

void FillStatus(const ServiceRecord& Record, SERVICE_STATUS& Status) {
    Status.dwServiceType = Record.ServiceType;
    Status.dwCurrentState = Record.CurrentState;
    Status.dwControlsAccepted = Record.CurrentState == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
    Status.dwWin32ExitCode = ERROR_SUCCESS;
    Status.dwServiceSpecificExitCode = 0;
    Status.dwCheckPoint = 0;
    Status.dwWaitHint = 0;
}

// QUERY_SERVICE_CONFIG is a header followed by its strings in the same buffer.
template <typename ConfigT, typename CharT>
BOOL FillConfig(const ServiceRecord& Record, ConfigT* Config, DWORD BufSize, LPDWORD Needed,
    const std::basic_string<CharT>& BinaryPath, const std::basic_string<CharT>& DisplayName) {
    // Empty group / dependencies / account: a driver service has no logon account, and
    // the dependency list is a double-NUL-terminated block.
    size_t Strings = (BinaryPath.size() + 1) + 1 /* group */ + 2 /* dependencies */ +
        1 /* start name */ + (DisplayName.size() + 1);
    DWORD Required = (DWORD)(sizeof(ConfigT) + Strings * sizeof(CharT));
    if (Needed)
        *Needed = Required;
    if (!Config || BufSize < Required) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    CharT* Tail = (CharT*)((uint8_t*)Config + sizeof(ConfigT));
    auto Append = [&Tail](const std::basic_string<CharT>& Text) {
        CharT* Start = Tail;
        if (!Text.empty()) {
            memcpy(Tail, Text.c_str(), Text.size() * sizeof(CharT));
            Tail += Text.size();
        }
        *Tail++ = (CharT)0;
        return Start;
    };
    const std::basic_string<CharT> Empty;

    Config->dwServiceType = Record.ServiceType;
    Config->dwStartType = Record.StartType;
    Config->dwErrorControl = Record.ErrorControl;
    Config->lpBinaryPathName = Append(BinaryPath);
    Config->lpLoadOrderGroup = Append(Empty);
    Config->dwTagId = 0;
    Config->lpDependencies = Append(Empty);
    *Tail++ = (CharT)0;  // second terminator of the dependency block
    Config->lpServiceStartName = Append(Empty);
    Config->lpDisplayName = Append(DisplayName);

    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

// ---- originals -------------------------------------------------------------------

typedef SC_HANDLE(WINAPI* PFN_OpenSCManagerW)(LPCWSTR, LPCWSTR, DWORD);
typedef SC_HANDLE(WINAPI* PFN_OpenSCManagerA)(LPCSTR, LPCSTR, DWORD);
typedef SC_HANDLE(WINAPI* PFN_CreateServiceW)(SC_HANDLE, LPCWSTR, LPCWSTR, DWORD, DWORD,
    DWORD, DWORD, LPCWSTR, LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR);
typedef SC_HANDLE(WINAPI* PFN_CreateServiceA)(SC_HANDLE, LPCSTR, LPCSTR, DWORD, DWORD,
    DWORD, DWORD, LPCSTR, LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR);
typedef SC_HANDLE(WINAPI* PFN_OpenServiceW)(SC_HANDLE, LPCWSTR, DWORD);
typedef SC_HANDLE(WINAPI* PFN_OpenServiceA)(SC_HANDLE, LPCSTR, DWORD);
typedef BOOL(WINAPI* PFN_StartServiceW)(SC_HANDLE, DWORD, LPCWSTR*);
typedef BOOL(WINAPI* PFN_StartServiceA)(SC_HANDLE, DWORD, LPCSTR*);
typedef BOOL(WINAPI* PFN_ControlService)(SC_HANDLE, DWORD, LPSERVICE_STATUS);
typedef BOOL(WINAPI* PFN_ControlServiceExW)(SC_HANDLE, DWORD, DWORD, PVOID);
typedef BOOL(WINAPI* PFN_ControlServiceExA)(SC_HANDLE, DWORD, DWORD, PVOID);
typedef BOOL(WINAPI* PFN_QueryServiceStatus)(SC_HANDLE, LPSERVICE_STATUS);
typedef BOOL(WINAPI* PFN_QueryServiceStatusEx)(SC_HANDLE, SC_STATUS_TYPE, LPBYTE, DWORD, LPDWORD);
typedef BOOL(WINAPI* PFN_QueryServiceConfigW)(SC_HANDLE, LPQUERY_SERVICE_CONFIGW, DWORD, LPDWORD);
typedef BOOL(WINAPI* PFN_QueryServiceConfigA)(SC_HANDLE, LPQUERY_SERVICE_CONFIGA, DWORD, LPDWORD);
typedef BOOL(WINAPI* PFN_ChangeServiceConfigW)(SC_HANDLE, DWORD, DWORD, DWORD, LPCWSTR,
    LPCWSTR, LPDWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR);
typedef BOOL(WINAPI* PFN_ChangeServiceConfigA)(SC_HANDLE, DWORD, DWORD, DWORD, LPCSTR,
    LPCSTR, LPDWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR);
typedef BOOL(WINAPI* PFN_DeleteService)(SC_HANDLE);
typedef BOOL(WINAPI* PFN_CloseServiceHandle)(SC_HANDLE);
typedef NTSTATUS(NTAPI* PFN_NtLoadDriver)(PVOID);

PFN_OpenSCManagerW Orig_OpenSCManagerW;
PFN_OpenSCManagerA Orig_OpenSCManagerA;
PFN_CreateServiceW Orig_CreateServiceW;
PFN_CreateServiceA Orig_CreateServiceA;
PFN_OpenServiceW Orig_OpenServiceW;
PFN_OpenServiceA Orig_OpenServiceA;
PFN_StartServiceW Orig_StartServiceW;
PFN_StartServiceA Orig_StartServiceA;
PFN_ControlService Orig_ControlService;
PFN_ControlServiceExW Orig_ControlServiceExW;
PFN_ControlServiceExA Orig_ControlServiceExA;
PFN_QueryServiceStatus Orig_QueryServiceStatus;
PFN_QueryServiceStatusEx Orig_QueryServiceStatusEx;
PFN_QueryServiceConfigW Orig_QueryServiceConfigW;
PFN_QueryServiceConfigA Orig_QueryServiceConfigA;
PFN_ChangeServiceConfigW Orig_ChangeServiceConfigW;
PFN_ChangeServiceConfigA Orig_ChangeServiceConfigA;
PFN_DeleteService Orig_DeleteService;
PFN_CloseServiceHandle Orig_CloseServiceHandle;
PFN_NtLoadDriver Orig_NtLoadDriver;
PFN_NtLoadDriver Orig_NtUnloadDriver;

bool IsDriverServiceType(DWORD ServiceType) {
    return (ServiceType & (SERVICE_KERNEL_DRIVER | SERVICE_FILE_SYSTEM_DRIVER)) != 0;
}

bool QueryRealServiceType(SC_HANDLE Service, DWORD& ServiceType) {
    if (!Orig_QueryServiceStatusEx)
        return false;

    SERVICE_STATUS_PROCESS Status{};
    DWORD Needed = 0;
    if (!Orig_QueryServiceStatusEx(Service, SC_STATUS_PROCESS_INFO,
            reinterpret_cast<LPBYTE>(&Status), sizeof(Status), &Needed))
        return false;

    ServiceType = Status.dwServiceType;
    return true;
}

bool QueryRealServiceConfigW(SC_HANDLE Service, ServiceRecord& Record) {
    if (!Orig_QueryServiceConfigW)
        return false;

    DWORD Needed = 0;
    Orig_QueryServiceConfigW(Service, nullptr, 0, &Needed);
    if (!Needed)
        return false;

    std::vector<BYTE> Storage(Needed);
    auto* Config = reinterpret_cast<LPQUERY_SERVICE_CONFIGW>(Storage.data());
    if (!Orig_QueryServiceConfigW(Service, Config, Needed, &Needed))
        return false;

    Record.DisplayName = Config->lpDisplayName ? Config->lpDisplayName : L"";
    Record.BinaryPath = Config->lpBinaryPathName ? Config->lpBinaryPathName : L"";
    Record.ServiceType = Config->dwServiceType;
    Record.StartType = Config->dwStartType;
    Record.ErrorControl = Config->dwErrorControl;
    return true;
}

bool QueryRealServiceConfigA(SC_HANDLE Service, ServiceRecord& Record) {
    if (!Orig_QueryServiceConfigA)
        return false;

    DWORD Needed = 0;
    Orig_QueryServiceConfigA(Service, nullptr, 0, &Needed);
    if (!Needed)
        return false;

    std::vector<BYTE> Storage(Needed);
    auto* Config = reinterpret_cast<LPQUERY_SERVICE_CONFIGA>(Storage.data());
    if (!Orig_QueryServiceConfigA(Service, Config, Needed, &Needed))
        return false;

    Record.DisplayName = Widen(Config->lpDisplayName);
    Record.BinaryPath = Widen(Config->lpBinaryPathName);
    Record.ServiceType = Config->dwServiceType;
    Record.StartType = Config->dwStartType;
    Record.ErrorControl = Config->dwErrorControl;
    return true;
}

SC_HANDLE ConvertDriverHandle(const std::wstring& Name, SC_HANDLE RealHandle,
    const ServiceRecord& Record) {
    if (!RealHandle || NameIsRestricted(Name) || !IsDriverServiceType(Record.ServiceType))
        return RealHandle;

    bool IsEmulated = !BridgeClient::Devices().empty() || !EnvOr(L"KEVLAR_HOOK_SERVICE", L"").empty();
    if (!IsEmulated)
        return RealHandle;

    Log("OpenService identified existing driver: name=%ls type=0x%x; replacing real handle %p",
        Name.c_str(), Record.ServiceType, (void*)RealHandle);
    Orig_CloseServiceHandle(RealHandle);
    return FakeOpen(Name, &Record);
}

// ---- detours ---------------------------------------------------------------------

// A real SCM handle is preferred whenever the process can get one: it keeps every
// unrelated service call working normally. The fake manager only appears when the real
// open fails, which is what happens in a client running without administrator rights --
// exactly the case where faking the install is most useful.
SC_HANDLE WINAPI Hk_OpenSCManagerW(LPCWSTR MachineName, LPCWSTR DatabaseName, DWORD Access) {
    SC_HANDLE Real = Orig_OpenSCManagerW(MachineName, DatabaseName, Access);
    if (Real)
        return Real;

    DWORD Error = GetLastError();
    std::lock_guard<std::mutex> Guard(g_Lock);
    SC_HANDLE Handle = AllocFakeHandleLocked();
    if (!Handle) {
        SetLastError(Error);
        return nullptr;
    }
    g_ManagerHandles.insert(Handle);
    Log("OpenSCManager failed for real (gle=%lu); handing back fake manager %p",
        Error, (void*)Handle);
    SetLastError(ERROR_SUCCESS);
    return Handle;
}

SC_HANDLE WINAPI Hk_OpenSCManagerA(LPCSTR MachineName, LPCSTR DatabaseName, DWORD Access) {
    SC_HANDLE Real = Orig_OpenSCManagerA(MachineName, DatabaseName, Access);
    if (Real)
        return Real;

    DWORD Error = GetLastError();
    std::lock_guard<std::mutex> Guard(g_Lock);
    SC_HANDLE Handle = AllocFakeHandleLocked();
    if (!Handle) {
        SetLastError(Error);
        return nullptr;
    }
    g_ManagerHandles.insert(Handle);
    Log("OpenSCManagerA failed for real (gle=%lu); handing back fake manager %p",
        Error, (void*)Handle);
    SetLastError(ERROR_SUCCESS);
    return Handle;
}

SC_HANDLE WINAPI Hk_CreateServiceW(SC_HANDLE Manager, LPCWSTR ServiceName,
    LPCWSTR DisplayName, DWORD Access, DWORD ServiceType, DWORD StartType,
    DWORD ErrorControl, LPCWSTR BinaryPath, LPCWSTR LoadOrderGroup, LPDWORD TagId,
    LPCWSTR Dependencies, LPCWSTR StartName, LPCWSTR Password) {
    std::wstring Name = ServiceName ? ServiceName : L"";
    if (!Name.empty() && ShouldFakeCreate(Name, ServiceType)) {
        if (TagId)
            *TagId = 0;
        return FakeCreate(Name, DisplayName ? DisplayName : L"",
            BinaryPath ? BinaryPath : L"", ServiceType, StartType, ErrorControl);
    }
    if (IsFakeManager(Manager)) {
        Log("CreateService(%ls, type=0x%x) not faked and the manager handle is not real",
            Name.c_str(), ServiceType);
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    return Orig_CreateServiceW(Manager, ServiceName, DisplayName, Access, ServiceType,
        StartType, ErrorControl, BinaryPath, LoadOrderGroup, TagId, Dependencies, StartName,
        Password);
}

SC_HANDLE WINAPI Hk_CreateServiceA(SC_HANDLE Manager, LPCSTR ServiceName, LPCSTR DisplayName,
    DWORD Access, DWORD ServiceType, DWORD StartType, DWORD ErrorControl, LPCSTR BinaryPath,
    LPCSTR LoadOrderGroup, LPDWORD TagId, LPCSTR Dependencies, LPCSTR StartName,
    LPCSTR Password) {
    std::wstring Name = Widen(ServiceName);
    if (!Name.empty() && ShouldFakeCreate(Name, ServiceType)) {
        if (TagId)
            *TagId = 0;
        return FakeCreate(Name, Widen(DisplayName), Widen(BinaryPath), ServiceType, StartType,
            ErrorControl);
    }
    if (IsFakeManager(Manager)) {
        SetLastError(ERROR_ACCESS_DENIED);
        return nullptr;
    }
    return Orig_CreateServiceA(Manager, ServiceName, DisplayName, Access, ServiceType,
        StartType, ErrorControl, BinaryPath, LoadOrderGroup, TagId, Dependencies, StartName,
        Password);
}

SC_HANDLE WINAPI Hk_OpenServiceW(SC_HANDLE Manager, LPCWSTR ServiceName, DWORD Access) {
    std::wstring Name = ServiceName ? ServiceName : L"";
    if (!Name.empty() && ShouldFakeOpen(Name))
        return FakeOpen(Name);
    if (IsFakeManager(Manager)) {
        SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
        return nullptr;
    }
    SC_HANDLE RealHandle = Orig_OpenServiceW(Manager, ServiceName, Access);
    if (!RealHandle || Name.empty() || NameIsRestricted(Name))
        return RealHandle;

    ServiceRecord Record{};
    if (QueryRealServiceConfigW(RealHandle, Record))
        return ConvertDriverHandle(Name, RealHandle, Record);
    if (QueryRealServiceType(RealHandle, Record.ServiceType))
        return ConvertDriverHandle(Name, RealHandle, Record);

    // Probe with short-lived handles when the caller did not request either query right.
    // A real driver's configuration is retained so validation of its image path succeeds.
    SC_HANDLE Probe = Orig_OpenServiceW(Manager, ServiceName, SERVICE_QUERY_CONFIG);
    if (Probe) {
        bool Queried = QueryRealServiceConfigW(Probe, Record);
        Orig_CloseServiceHandle(Probe);
        if (Queried)
            return ConvertDriverHandle(Name, RealHandle, Record);
    }
    Probe = Orig_OpenServiceW(Manager, ServiceName, SERVICE_QUERY_STATUS);
    if (Probe) {
        bool Queried = QueryRealServiceType(Probe, Record.ServiceType);
        Orig_CloseServiceHandle(Probe);
        if (Queried)
            return ConvertDriverHandle(Name, RealHandle, Record);
    }
    return RealHandle;
}

SC_HANDLE WINAPI Hk_OpenServiceA(SC_HANDLE Manager, LPCSTR ServiceName, DWORD Access) {
    std::wstring Name = Widen(ServiceName);
    if (!Name.empty() && ShouldFakeOpen(Name))
        return FakeOpen(Name);
    if (IsFakeManager(Manager)) {
        SetLastError(ERROR_SERVICE_DOES_NOT_EXIST);
        return nullptr;
    }
    SC_HANDLE RealHandle = Orig_OpenServiceA(Manager, ServiceName, Access);
    if (!RealHandle || Name.empty() || NameIsRestricted(Name))
        return RealHandle;

    ServiceRecord Record{};
    if (QueryRealServiceConfigA(RealHandle, Record))
        return ConvertDriverHandle(Name, RealHandle, Record);
    if (QueryRealServiceType(RealHandle, Record.ServiceType))
        return ConvertDriverHandle(Name, RealHandle, Record);

    SC_HANDLE Probe = Orig_OpenServiceA(Manager, ServiceName, SERVICE_QUERY_CONFIG);
    if (Probe) {
        bool Queried = QueryRealServiceConfigA(Probe, Record);
        Orig_CloseServiceHandle(Probe);
        if (Queried)
            return ConvertDriverHandle(Name, RealHandle, Record);
    }
    Probe = Orig_OpenServiceA(Manager, ServiceName, SERVICE_QUERY_STATUS);
    if (Probe) {
        bool Queried = QueryRealServiceType(Probe, Record.ServiceType);
        Orig_CloseServiceHandle(Probe);
        if (Queried)
            return ConvertDriverHandle(Name, RealHandle, Record);
    }
    return RealHandle;
}

BOOL WINAPI Hk_StartServiceW(SC_HANDLE Service, DWORD ArgCount, LPCWSTR* Args) {
    ServiceRecord Record{};
    if (LookupService(Service, Record))
        return FakeStart(Service);
    return Orig_StartServiceW(Service, ArgCount, Args);
}

BOOL WINAPI Hk_StartServiceA(SC_HANDLE Service, DWORD ArgCount, LPCSTR* Args) {
    ServiceRecord Record{};
    if (LookupService(Service, Record))
        return FakeStart(Service);
    return Orig_StartServiceA(Service, ArgCount, Args);
}

BOOL WINAPI Hk_ControlService(SC_HANDLE Service, DWORD Control, LPSERVICE_STATUS Status) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_ControlService(Service, Control, Status);

    if (Control == SERVICE_CONTROL_STOP) {
        UpdateService(Service, [](ServiceRecord& R) { R.CurrentState = SERVICE_STOPPED; });
        Record.CurrentState = SERVICE_STOPPED;
        Log("ControlService(STOP) faked for %ls", Record.Name.c_str());
    } else {
        Log("ControlService(0x%x) faked for %ls (state unchanged)", Control, Record.Name.c_str());
    }
    if (Status)
        FillStatus(Record, *Status);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI Hk_ControlServiceExW(SC_HANDLE Service, DWORD Control, DWORD InfoLevel, PVOID Info) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_ControlServiceExW(Service, Control, InfoLevel, Info);
    if (Control == SERVICE_CONTROL_STOP)
        UpdateService(Service, [](ServiceRecord& R) { R.CurrentState = SERVICE_STOPPED; });
    Log("ControlServiceEx(0x%x) faked for %ls", Control, Record.Name.c_str());
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI Hk_ControlServiceExA(SC_HANDLE Service, DWORD Control, DWORD InfoLevel, PVOID Info) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_ControlServiceExA(Service, Control, InfoLevel, Info);
    if (Control == SERVICE_CONTROL_STOP)
        UpdateService(Service, [](ServiceRecord& R) { R.CurrentState = SERVICE_STOPPED; });
    Log("ControlServiceExA(0x%x) faked for %ls", Control, Record.Name.c_str());
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI Hk_QueryServiceStatus(SC_HANDLE Service, LPSERVICE_STATUS Status) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_QueryServiceStatus(Service, Status);
    if (!Status) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    FillStatus(Record, *Status);
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI Hk_QueryServiceStatusEx(SC_HANDLE Service, SC_STATUS_TYPE InfoLevel, LPBYTE Buffer,
    DWORD BufSize, LPDWORD Needed) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_QueryServiceStatusEx(Service, InfoLevel, Buffer, BufSize, Needed);

    if (InfoLevel != SC_STATUS_PROCESS_INFO) {
        SetLastError(ERROR_INVALID_LEVEL);
        return FALSE;
    }
    if (Needed)
        *Needed = sizeof(SERVICE_STATUS_PROCESS);
    if (!Buffer || BufSize < sizeof(SERVICE_STATUS_PROCESS)) {
        SetLastError(ERROR_INSUFFICIENT_BUFFER);
        return FALSE;
    }

    SERVICE_STATUS Plain{};
    FillStatus(Record, Plain);

    auto* Status = (LPSERVICE_STATUS_PROCESS)Buffer;
    Status->dwServiceType = Plain.dwServiceType;
    Status->dwCurrentState = Plain.dwCurrentState;
    Status->dwControlsAccepted = Plain.dwControlsAccepted;
    Status->dwWin32ExitCode = Plain.dwWin32ExitCode;
    Status->dwServiceSpecificExitCode = Plain.dwServiceSpecificExitCode;
    Status->dwCheckPoint = Plain.dwCheckPoint;
    Status->dwWaitHint = Plain.dwWaitHint;
    Status->dwProcessId = 0;      // a driver service has no host process
    Status->dwServiceFlags = 0;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI Hk_QueryServiceConfigW(SC_HANDLE Service, LPQUERY_SERVICE_CONFIGW Config,
    DWORD BufSize, LPDWORD Needed) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_QueryServiceConfigW(Service, Config, BufSize, Needed);
    return FillConfig<QUERY_SERVICE_CONFIGW, wchar_t>(Record, Config, BufSize, Needed,
        Record.BinaryPath, Record.DisplayName);
}

BOOL WINAPI Hk_QueryServiceConfigA(SC_HANDLE Service, LPQUERY_SERVICE_CONFIGA Config,
    DWORD BufSize, LPDWORD Needed) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_QueryServiceConfigA(Service, Config, BufSize, Needed);

    auto Narrow = [](const std::wstring& Wide) {
        if (Wide.empty())
            return std::string();
        int Bytes = WideCharToMultiByte(CP_ACP, 0, Wide.c_str(), (int)Wide.size(), nullptr, 0,
            nullptr, nullptr);
        std::string Out((size_t)Bytes, '\0');
        WideCharToMultiByte(CP_ACP, 0, Wide.c_str(), (int)Wide.size(), Out.data(), Bytes,
            nullptr, nullptr);
        return Out;
    };
    return FillConfig<QUERY_SERVICE_CONFIGA, char>(Record, Config, BufSize, Needed,
        Narrow(Record.BinaryPath), Narrow(Record.DisplayName));
}

BOOL WINAPI Hk_ChangeServiceConfigW(SC_HANDLE Service, DWORD ServiceType, DWORD StartType,
    DWORD ErrorControl, LPCWSTR BinaryPath, LPCWSTR LoadOrderGroup, LPDWORD TagId,
    LPCWSTR Dependencies, LPCWSTR StartName, LPCWSTR Password, LPCWSTR DisplayName) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_ChangeServiceConfigW(Service, ServiceType, StartType, ErrorControl,
            BinaryPath, LoadOrderGroup, TagId, Dependencies, StartName, Password, DisplayName);

    UpdateService(Service, [&](ServiceRecord& R) {
        if (ServiceType != SERVICE_NO_CHANGE) R.ServiceType = ServiceType;
        if (StartType != SERVICE_NO_CHANGE) R.StartType = StartType;
        if (ErrorControl != SERVICE_NO_CHANGE) R.ErrorControl = ErrorControl;
        if (BinaryPath) R.BinaryPath = BinaryPath;
        if (DisplayName) R.DisplayName = DisplayName;
    });
    if (TagId)
        *TagId = 0;
    Log("ChangeServiceConfig faked for %ls", Record.Name.c_str());
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI Hk_ChangeServiceConfigA(SC_HANDLE Service, DWORD ServiceType, DWORD StartType,
    DWORD ErrorControl, LPCSTR BinaryPath, LPCSTR LoadOrderGroup, LPDWORD TagId,
    LPCSTR Dependencies, LPCSTR StartName, LPCSTR Password, LPCSTR DisplayName) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_ChangeServiceConfigA(Service, ServiceType, StartType, ErrorControl,
            BinaryPath, LoadOrderGroup, TagId, Dependencies, StartName, Password, DisplayName);

    UpdateService(Service, [&](ServiceRecord& R) {
        if (ServiceType != SERVICE_NO_CHANGE) R.ServiceType = ServiceType;
        if (StartType != SERVICE_NO_CHANGE) R.StartType = StartType;
        if (ErrorControl != SERVICE_NO_CHANGE) R.ErrorControl = ErrorControl;
        if (BinaryPath) R.BinaryPath = Widen(BinaryPath);
        if (DisplayName) R.DisplayName = Widen(DisplayName);
    });
    if (TagId)
        *TagId = 0;
    Log("ChangeServiceConfigA faked for %ls", Record.Name.c_str());
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI Hk_DeleteService(SC_HANDLE Service) {
    ServiceRecord Record{};
    if (!LookupService(Service, Record))
        return Orig_DeleteService(Service);
    UpdateService(Service, [](ServiceRecord& R) {
        R.Deleted = true;
        R.CurrentState = SERVICE_STOPPED;
    });
    Log("DeleteService faked for %ls", Record.Name.c_str());
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI Hk_CloseServiceHandle(SC_HANDLE Handle) {
    {
        std::lock_guard<std::mutex> Guard(g_Lock);
        // The record itself outlives the handle: a client that closes and reopens the
        // service must find the state it left behind.
        bool ErasedService = g_ServiceHandles.erase(Handle) != 0;
        bool ErasedManager = g_ManagerHandles.erase(Handle) != 0;
        if (ErasedService || ErasedManager) {
            if (StateRef.HandlePage && (uint8_t*)Handle >= StateRef.HandlePage) {
                size_t Offset = (uint8_t*)Handle - StateRef.HandlePage;
                if (Offset < StateRef.HandleCapacity * kHandleStride && (Offset % kHandleStride == 0)) {
                    StateRef.FreeSlots.push_back(Offset / kHandleStride);
                }
            }
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }
    }
    return Orig_CloseServiceHandle(Handle);
}

// Loaders that write the service key themselves and skip the SCM entirely call this
// with \Registry\Machine\System\CurrentControlSet\Services\<name>.
NTSTATUS NTAPI Hk_NtLoadDriver(PVOID RegistryPath) {
    auto* Path = (UNICODE_STRING*)RegistryPath;
    std::wstring Name;
    if (Path && Path->Buffer && Path->Length) {
        std::wstring Full(Path->Buffer, Path->Length / sizeof(wchar_t));
        Name = Full.substr(Full.find_last_of(L'\\') + 1);
    }
    if (!Name.empty() && (ShouldFakeCreate(Name, SERVICE_KERNEL_DRIVER) || ShouldFakeOpen(Name))) {
        {
            std::lock_guard<std::mutex> Guard(g_Lock);
            ServiceRecord& Record = g_Services[ToUpper(Name)];
            Record.Name = Name;
            Record.ServiceType = SERVICE_KERNEL_DRIVER;
            Record.CurrentState = SERVICE_RUNNING;
        }
        Log("NtLoadDriver faked for %ls (no driver was loaded)", Name.c_str());
        return kStatusSuccess;
    }
    return Orig_NtLoadDriver(RegistryPath);
}

NTSTATUS NTAPI Hk_NtUnloadDriver(PVOID RegistryPath) {
    auto* Path = (UNICODE_STRING*)RegistryPath;
    std::wstring Name;
    if (Path && Path->Buffer && Path->Length) {
        std::wstring Full(Path->Buffer, Path->Length / sizeof(wchar_t));
        Name = Full.substr(Full.find_last_of(L'\\') + 1);
    }
    std::lock_guard<std::mutex> Guard(g_Lock);
    auto It = g_Services.find(ToUpper(Name));
    if (It != g_Services.end()) {
        It->second.CurrentState = SERVICE_STOPPED;
        Log("NtUnloadDriver faked for %ls", Name.c_str());
        return kStatusSuccess;
    }
    return Orig_NtUnloadDriver(RegistryPath);
}

// ---- installation ----------------------------------------------------------------

struct Site {
    const wchar_t* Module;
    const char* Name;
    void* Detour;
    void** Original;
};

const Site kSites[] = {
    // OpenService uses these originals while deciding whether a real handle represents
    // a driver, so install them before the OpenService detours become reachable.
    { L"advapi32.dll", "QueryServiceStatusEx", (void*)&Hk_QueryServiceStatusEx, (void**)&Orig_QueryServiceStatusEx },
    { L"advapi32.dll", "QueryServiceConfigW", (void*)&Hk_QueryServiceConfigW, (void**)&Orig_QueryServiceConfigW },
    { L"advapi32.dll", "QueryServiceConfigA", (void*)&Hk_QueryServiceConfigA, (void**)&Orig_QueryServiceConfigA },
    { L"advapi32.dll", "CloseServiceHandle", (void*)&Hk_CloseServiceHandle, (void**)&Orig_CloseServiceHandle },
    { L"advapi32.dll", "OpenSCManagerW", (void*)&Hk_OpenSCManagerW, (void**)&Orig_OpenSCManagerW },
    { L"advapi32.dll", "OpenSCManagerA", (void*)&Hk_OpenSCManagerA, (void**)&Orig_OpenSCManagerA },
    { L"advapi32.dll", "CreateServiceW", (void*)&Hk_CreateServiceW, (void**)&Orig_CreateServiceW },
    { L"advapi32.dll", "CreateServiceA", (void*)&Hk_CreateServiceA, (void**)&Orig_CreateServiceA },
    { L"advapi32.dll", "OpenServiceW", (void*)&Hk_OpenServiceW, (void**)&Orig_OpenServiceW },
    { L"advapi32.dll", "OpenServiceA", (void*)&Hk_OpenServiceA, (void**)&Orig_OpenServiceA },
    { L"advapi32.dll", "StartServiceW", (void*)&Hk_StartServiceW, (void**)&Orig_StartServiceW },
    { L"advapi32.dll", "StartServiceA", (void*)&Hk_StartServiceA, (void**)&Orig_StartServiceA },
    { L"advapi32.dll", "ControlService", (void*)&Hk_ControlService, (void**)&Orig_ControlService },
    { L"advapi32.dll", "ControlServiceExW", (void*)&Hk_ControlServiceExW, (void**)&Orig_ControlServiceExW },
    { L"advapi32.dll", "ControlServiceExA", (void*)&Hk_ControlServiceExA, (void**)&Orig_ControlServiceExA },
    { L"advapi32.dll", "QueryServiceStatus", (void*)&Hk_QueryServiceStatus, (void**)&Orig_QueryServiceStatus },
    { L"advapi32.dll", "ChangeServiceConfigW", (void*)&Hk_ChangeServiceConfigW, (void**)&Orig_ChangeServiceConfigW },
    { L"advapi32.dll", "ChangeServiceConfigA", (void*)&Hk_ChangeServiceConfigA, (void**)&Orig_ChangeServiceConfigA },
    { L"advapi32.dll", "DeleteService", (void*)&Hk_DeleteService, (void**)&Orig_DeleteService },
    { L"ntdll.dll", "NtLoadDriver", (void*)&Hk_NtLoadDriver, (void**)&Orig_NtLoadDriver },
    { L"ntdll.dll", "NtUnloadDriver", (void*)&Hk_NtUnloadDriver, (void**)&Orig_NtUnloadDriver },
};

void InstallAll() {
    for (const Site& Entry : kSites) {
        void* Target = HookEngine::Resolve(Entry.Module, Entry.Name);
        if (!HookEngine::Install(Entry.Name, Target, Entry.Detour, Entry.Original))
            *Entry.Original = Target;
    }
}

DWORD WINAPI WaitAndInstall(LPVOID) {
    // Outside the loader lock now, so waiting for -- and if necessary forcing -- the
    // service DLLs to map is safe.
    for (int Attempt = 0; Attempt < 400; Attempt++) {   // ~10s
        if (GetModuleHandleW(L"advapi32.dll")) {
            InstallAll();
            ProcessHooks::InstallDelayed();
            return 0;
        }
        Sleep(25);
    }
    if (LoadLibraryW(L"advapi32.dll")) {
        Log("advapi32 never loaded on its own; forced it in to install the SCM hooks");
        InstallAll();
        ProcessHooks::InstallDelayed();
    } else {
        Log("advapi32 could not be loaded; SCM hooks are not installed");
    }
    return 0;
}

} // namespace

namespace ServiceHooks {

void InstallDeferred() {
    if (GetModuleHandleW(L"advapi32.dll")) {
        InstallAll();
        ProcessHooks::InstallDelayed();
        return;
    }
    Log("advapi32 not mapped yet; deferring the SCM hooks to a worker thread");
    HANDLE Thread = CreateThread(nullptr, 0, &WaitAndInstall, nullptr, 0, nullptr);
    if (Thread)
        CloseHandle(Thread);
}

} // namespace ServiceHooks
