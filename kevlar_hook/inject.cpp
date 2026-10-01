// kevlar_inject.exe -- puts kevlar_hook.dll (found next to this exe) into a target
// process via the classic CreateRemoteThread + LoadLibraryW pattern, either by launching
// the target suspended or by attaching to one that is already running.
//
// Launching suspended is the one to prefer: the hooks are in before the process runs a
// single instruction of its own code, so the service install cannot be missed. Attaching
// to a running process is for a client that is already up, and races anything it has
// already done.
//
// The child inherits this process's environment, so KEVLAR_HOOK_* configuration set
// before running the injector reaches the hook DLL.

#include <windows.h>
#include <string>
#include <vector>
#include <cstdio>

namespace {

std::wstring HookDllPath() {
    wchar_t SelfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, SelfPath, MAX_PATH);
    std::wstring Directory(SelfPath);
    Directory = Directory.substr(0, Directory.find_last_of(L"\\/"));
    std::wstring VersionPath = Directory + L"\\VERSION.dll";
    if (GetFileAttributesW(VersionPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        return VersionPath;
    std::wstring LegacyPath = Directory + L"\\kevlar_hook.dll";
    if (GetFileAttributesW(LegacyPath.c_str()) != INVALID_FILE_ATTRIBUTES)
        return LegacyPath;
    return VersionPath;
}

// Writes the DLL path into the target and runs LoadLibraryW on it there. The thread's
// exit code is the module base, or zero if the load failed.
bool InjectInto(HANDLE Process, const std::wstring& DllPath) {
    SIZE_T Bytes = (DllPath.size() + 1) * sizeof(wchar_t);
    LPVOID Remote = VirtualAllocEx(Process, nullptr, Bytes, MEM_COMMIT, PAGE_READWRITE);
    if (!Remote) {
        wprintf(L"VirtualAllocEx failed, gle=%lu\n", GetLastError());
        return false;
    }
    if (!WriteProcessMemory(Process, Remote, DllPath.c_str(), Bytes, nullptr)) {
        wprintf(L"WriteProcessMemory failed, gle=%lu\n", GetLastError());
        VirtualFreeEx(Process, Remote, 0, MEM_RELEASE);
        return false;
    }

    auto LoadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    HANDLE Thread = CreateRemoteThread(Process, nullptr, 0, LoadLibraryAddress, Remote, 0,
        nullptr);
    if (!Thread) {
        wprintf(L"CreateRemoteThread failed, gle=%lu\n", GetLastError());
        VirtualFreeEx(Process, Remote, 0, MEM_RELEASE);
        return false;
    }

    WaitForSingleObject(Thread, 10000);
    DWORD ExitCode = 0;
    GetExitCodeThread(Thread, &ExitCode);
    CloseHandle(Thread);
    VirtualFreeEx(Process, Remote, 0, MEM_RELEASE);

    if (!ExitCode) {
        wprintf(L"LoadLibraryW returned NULL -- the hook DLL did not load\n");
        return false;
    }
    wprintf(L"%ls injected (module base 0x%p)\n", DllPath.c_str(), (void*)(uintptr_t)ExitCode);
    return true;
}

int AttachToPid(DWORD Pid, const std::wstring& DllPath) {
    HANDLE Process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, Pid);
    if (!Process) {
        wprintf(L"OpenProcess(%lu) failed, gle=%lu\n", Pid, GetLastError());
        return 1;
    }
    wprintf(L"Attaching to PID %lu (anything it already did is not intercepted)\n", Pid);
    bool Ok = InjectInto(Process, DllPath);
    CloseHandle(Process);
    return Ok ? 0 : 1;
}

// Hands this process's stdin/stdout/stderr to the child so a redirected or piped
// injector run captures the target's output. Without this the child inherits the console
// but not a redirection, and an automated run sees nothing.
void ShareStandardHandles(STARTUPINFOW& StartupInfo) {
    const DWORD Ids[] = { STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, STD_ERROR_HANDLE };
    HANDLE* Slots[] = { &StartupInfo.hStdInput, &StartupInfo.hStdOutput, &StartupInfo.hStdError };
    for (int I = 0; I < 3; I++) {
        HANDLE Handle = GetStdHandle(Ids[I]);
        if (Handle && Handle != INVALID_HANDLE_VALUE)
            SetHandleInformation(Handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        *Slots[I] = Handle;
    }
    StartupInfo.dwFlags |= STARTF_USESTDHANDLES;
}

int LaunchSuspended(const std::wstring& ExePath, const std::wstring& CommandLine,
    const std::wstring& DllPath, bool Wait) {
    STARTUPINFOW StartupInfo{};
    StartupInfo.cb = sizeof(StartupInfo);
    ShareStandardHandles(StartupInfo);
    PROCESS_INFORMATION ProcessInfo{};
    std::vector<wchar_t> CommandBuffer(CommandLine.begin(), CommandLine.end());
    CommandBuffer.push_back(0);

    if (!CreateProcessW(ExePath.c_str(), CommandBuffer.data(), nullptr, nullptr, TRUE,
            CREATE_SUSPENDED, nullptr, nullptr, &StartupInfo, &ProcessInfo)) {
        wprintf(L"CreateProcess failed, gle=%lu\n", GetLastError());
        return 1;
    }

    if (!InjectInto(ProcessInfo.hProcess, DllPath)) {
        TerminateProcess(ProcessInfo.hProcess, 1);
        CloseHandle(ProcessInfo.hThread);
        CloseHandle(ProcessInfo.hProcess);
        return 1;
    }

    ResumeThread(ProcessInfo.hThread);
    wprintf(L"Resumed target, PID %lu\n", ProcessInfo.dwProcessId);
    CloseHandle(ProcessInfo.hThread);

    DWORD ExitCode = 0;
    if (Wait) {
        WaitForSingleObject(ProcessInfo.hProcess, INFINITE);
        GetExitCodeProcess(ProcessInfo.hProcess, &ExitCode);
        wprintf(L"Target exited with %lu\n", ExitCode);
    }
    CloseHandle(ProcessInfo.hProcess);
    return Wait ? (int)ExitCode : 0;
}

std::wstring Widen(const char* Narrow) {
    wchar_t Wide[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, Narrow, -1, Wide, MAX_PATH);
    return Wide;
}

} // namespace

int main(int Argc, char** Argv) {
    if (Argc < 2) {
        printf("Usage: kevlar_inject.exe [--wait] <target.exe> [args...]\n");
        printf("       kevlar_inject.exe --pid <pid>\n");
        printf("  --wait  block until the target exits and return its exit code\n");
        return 1;
    }

    std::wstring DllPath = HookDllPath();
    if (GetFileAttributesW(DllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"VERSION.dll (or kevlar_hook.dll) not found next to the injector: %ls\n", DllPath.c_str());
        return 1;
    }

    int First = 1;
    bool Wait = false;
    if (!strcmp(Argv[First], "--wait")) {
        Wait = true;
        First++;
    }
    if (First >= Argc) {
        printf("--wait requires a target\n");
        return 1;
    }

    if (!strcmp(Argv[First], "--pid")) {
        if (First + 1 >= Argc) {
            printf("--pid requires a process id\n");
            return 1;
        }
        return AttachToPid((DWORD)strtoul(Argv[First + 1], nullptr, 10), DllPath);
    }

    std::wstring ExePath = Widen(Argv[First]);
    std::wstring CommandLine = L"\"" + ExePath + L"\"";
    for (int I = First + 1; I < Argc; I++)
        CommandLine += L" " + Widen(Argv[I]);

    return LaunchSuspended(ExePath, CommandLine, DllPath, Wait);
}
