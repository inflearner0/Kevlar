// kevlar_hook.dll -- injected into an unmodified client so that installing, starting and
// then talking to a kernel driver all resolve to a driver running inside KEVLAR instead
// of one running in the kernel. Two layers, both usermode:
//
//   service_hooks.cpp  CreateService / StartService / QueryServiceStatus and friends are
//                      answered from a fake service database. No driver is loaded, no
//                      service key is written, and the client sees SERVICE_RUNNING.
//   device_hooks.cpp   the open of \??\<name> that follows is redirected to the KEVLAR
//                      --serve pipe, and IOCTL / read / write on that handle are relayed
//                      to the emulated driver's dispatch routines.
//
// This is the "client is unmodified but injectable" path from docs/bridge.md SS4.
// Offline analysis only: it does not, and cannot, defeat test-signing detection, driver
// enumeration, latency probes or a real driver-integrity handshake -- see docs/bridge.md SS2.

#include "device_hooks.h"
#include "kevlar_hook.h"
#include "process_hooks.h"
#include "service_hooks.h"

#include <windows.h>

BOOL APIENTRY DllMain(HMODULE Module, DWORD Reason, LPVOID) {
    if (Reason == DLL_PROCESS_ATTACH) {
        wchar_t ProcessPath[MAX_PATH];
        DWORD ProcessPathLength = GetModuleFileNameW(nullptr, ProcessPath, ARRAYSIZE(ProcessPath));
        if (!ProcessPathLength || ProcessPathLength >= ARRAYSIZE(ProcessPath))
            return TRUE;

        const wchar_t* ProcessName = wcsrchr(ProcessPath, L'\\');
        ProcessName = ProcessName ? ProcessName + 1 : ProcessPath;
        const bool IsBroker = lstrcmpiW(ProcessName, L"CODBrokerService.exe") == 0;
        const bool IsTestClient = lstrcmpiW(ProcessName, L"bridge_client.exe") == 0 ||
                                 lstrcmpiW(ProcessName, L"client.exe") == 0;
        if (lstrcmpiW(ProcessName, L"cod.exe") != 0 &&
            lstrcmpiW(ProcessName, L"bootstrapper.exe") != 0 &&
            !IsBroker && !IsTestClient)
            return TRUE;

        if (true || GetEnvironmentVariableW(L"KEVLAR_HOOK_CONSOLE", nullptr, 0)) {
            AllocConsole();
            SetConsoleTitleW(L"kevlar_hook attached");
            const wchar_t ConsoleMessage[] = L"kevlar_hook.dll: DLL_PROCESS_ATTACH\r\n";
            DWORD ConsoleCharsWritten = 0;
            WriteConsoleW(GetStdHandle(STD_OUTPUT_HANDLE), ConsoleMessage,
                ARRAYSIZE(ConsoleMessage) - 1, &ConsoleCharsWritten, nullptr);
        }

        DisableThreadLibraryCalls(Module);

        // Pinned: the detours below live in this module, and the patched bytes in ntdll
        // and sechost outlive any FreeLibrary. Unloading would leave every hooked
        // function jumping into freed memory, so unloading must not be possible.
        HMODULE Pinned = nullptr;
        GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_PIN | GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
            (LPCWSTR)Module, &Pinned);

        KevlarHook::SetSelfModule(Module);

        // LocalSystem's default %TEMP% log is not readable by the interactive user who
        // runs the emulator. Keep the broker trace beside the proxy so the same operator
        // can inspect the service-side device open and IOCTL sequence.
        if (IsBroker && !GetEnvironmentVariableW(L"KEVLAR_HOOK_LOG", nullptr, 0)) {
            wchar_t BrokerLog[MAX_PATH];
            wcsncpy_s(BrokerLog, ProcessPath, _TRUNCATE);
            wchar_t* FileName = wcsrchr(BrokerLog, L'\\');
            if (FileName)
                wcscpy_s(FileName + 1, ARRAYSIZE(BrokerLog) - (FileName + 1 - BrokerLog),
                    L"kevlar_hook_service.log");
            SetEnvironmentVariableW(L"KEVLAR_HOOK_LOG", BrokerLog);
        }
        KevlarHook::LogInit();

        std::wstring Pipe = KevlarHook::PipeName();
        KevlarHook::Log("kevlar_hook attached to pid %lu (%ls): pipe=%ls%ls service=%ls device=%ls match=%ls",
            GetCurrentProcessId(), ProcessName, Pipe.c_str(),
            KevlarHook::PipeNameOverridden() ? L" (KEVLAR_HOOK_PIPE)" : L" (default)",
            KevlarHook::EnvOr(L"KEVLAR_HOOK_SERVICE", L"<any kernel driver>").c_str(),
            KevlarHook::EnvOr(L"KEVLAR_HOOK_DEVICE", L"<from bridge enumeration>").c_str(),
            KevlarHook::EnvOr(L"KEVLAR_HOOK_MATCH", L"<none>").c_str());

        // ntdll and kernel32 are mapped in every process, so those hooks are safe under
        // the loader lock. The service hooks, and the CreateProcessAsUser variants that
        // live beside them, may have to wait for advapi32 and go in from a worker.
        DeviceHooks::Install();
        ProcessHooks::Install();
        ServiceHooks::InstallDeferred();
    }
    // No detach path on purpose. The module is pinned, so the only DLL_PROCESS_DETACH
    // that can arrive is process exit, where every other thread is already gone and pipe
    // I/O from here would only risk hanging teardown. Sessions left open are torn down by
    // the server when the pipe drops (docs/bridge.md SS3.3).
    return TRUE;
}
