#include "process_hooks.h"
#include "hook_engine.h"
#include "kevlar_hook.h"
#include "reentry.h"

#include <windows.h>

#include <string>

using KevlarHook::Log;

namespace {

typedef BOOL(WINAPI* PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW,
    LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* PFN_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
    LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA,
    LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* PFN_CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR,
    LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL(WINAPI* PFN_CreateProcessAsUserA)(HANDLE, LPCSTR, LPSTR,
    LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR,
    LPSTARTUPINFOA, LPPROCESS_INFORMATION);

PFN_CreateProcessW Orig_CreateProcessW;
PFN_CreateProcessA Orig_CreateProcessA;
PFN_CreateProcessAsUserW Orig_CreateProcessAsUserW;
PFN_CreateProcessAsUserA Orig_CreateProcessAsUserA;

// A 32-bit child has a different kernel32, so the LoadLibraryW address resolved here
// does not apply to it. Rather than inject something that would fault, say so and let
// the child run unhooked.
bool ChildIsSameArchitecture(HANDLE Process) {
    USHORT ProcessMachine = 0, NativeMachine = 0;
    auto IsWow64Process2Fn = (decltype(&IsWow64Process2))GetProcAddress(
        GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2");
    if (!IsWow64Process2Fn)
        return true;   // pre-1709: assume it matches, as it almost always does
    if (!IsWow64Process2Fn(Process, &ProcessMachine, &NativeMachine))
        return true;
    return ProcessMachine == IMAGE_FILE_MACHINE_UNKNOWN;  // not running under WOW64
}

// Same technique kevlar_inject uses, aimed at a child this process just created.
bool InjectSelfInto(HANDLE Process) {
    std::wstring DllPath = KevlarHook::SelfModulePath();
    if (DllPath.empty()) {
        Log("Child inject: this module's own path is unknown");
        return false;
    }

    SIZE_T Bytes = (DllPath.size() + 1) * sizeof(wchar_t);
    LPVOID Remote = VirtualAllocEx(Process, nullptr, Bytes, MEM_COMMIT, PAGE_READWRITE);
    if (!Remote) {
        Log("Child inject: VirtualAllocEx failed, gle=%lu", GetLastError());
        return false;
    }

    bool Ok = false;
    if (WriteProcessMemory(Process, Remote, DllPath.c_str(), Bytes, nullptr)) {
        auto LoadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
        HANDLE Thread = CreateRemoteThread(Process, nullptr, 0, LoadLibraryAddress, Remote,
            0, nullptr);
        if (Thread) {
            WaitForSingleObject(Thread, 10000);
            DWORD ExitCode = 0;
            GetExitCodeThread(Thread, &ExitCode);
            CloseHandle(Thread);
            Ok = ExitCode != 0;
            if (!Ok)
                Log("Child inject: LoadLibraryW returned NULL in the child");
        } else {
            Log("Child inject: CreateRemoteThread failed, gle=%lu", GetLastError());
        }
    } else {
        Log("Child inject: WriteProcessMemory failed, gle=%lu", GetLastError());
    }

    VirtualFreeEx(Process, Remote, 0, MEM_RELEASE);
    return Ok;
}

// A child on the default channel needs nothing propagated -- it compiles in the same
// constant. Only a non-default channel has to be carried down, and the child inherits
// this process's environment unless the caller supplies its own block, which is left
// alone: rewriting someone else's environment is not worth the failure modes.
void PublishPipeNameForChild(LPVOID CallerEnvironment) {
    if (!KevlarHook::PipeNameOverridden())
        return;

    std::wstring Pipe = KevlarHook::PipeName();
    if (CallerEnvironment) {
        Log("Child inject: caller supplied its own environment; the child will fall back "
            "to the default channel instead of KEVLAR_HOOK_PIPE=%ls", Pipe.c_str());
        return;
    }
    SetEnvironmentVariableW(L"KEVLAR_HOOK_PIPE", Pipe.c_str());
}

// Shared tail: the child exists and is suspended. Inject, then honour whatever the
// caller originally asked for. A failed injection still resumes the child -- the target
// must keep working even when this DLL cannot follow it.
void HookChildAndResume(const wchar_t* What, BOOL Created, BOOL CallerWantedSuspended,
    LPPROCESS_INFORMATION ProcessInformation) {
    if (!Created || !ProcessInformation || !ProcessInformation->hProcess)
        return;

    if (ChildIsSameArchitecture(ProcessInformation->hProcess)) {
        if (InjectSelfInto(ProcessInformation->hProcess))
            Log("Child inject: hooked %ls (pid %lu)", What, ProcessInformation->dwProcessId);
        else
            Log("Child inject: FAILED for %ls (pid %lu); it will run unhooked", What,
                ProcessInformation->dwProcessId);
    } else {
        Log("Child inject: %ls (pid %lu) is 32-bit; this DLL is 64-bit, leaving it alone",
            What, ProcessInformation->dwProcessId);
    }

    if (!CallerWantedSuspended)
        ResumeThread(ProcessInformation->hThread);
}

const wchar_t* DescribeW(LPCWSTR ApplicationName, LPWSTR CommandLine) {
    if (ApplicationName && *ApplicationName)
        return ApplicationName;
    if (CommandLine && *CommandLine)
        return CommandLine;
    return L"<unnamed child>";
}

BOOL WINAPI Hk_CreateProcessW(LPCWSTR ApplicationName, LPWSTR CommandLine,
    LPSECURITY_ATTRIBUTES ProcessAttributes, LPSECURITY_ATTRIBUTES ThreadAttributes,
    BOOL InheritHandles, DWORD CreationFlags, LPVOID Environment,
    LPCWSTR CurrentDirectory, LPSTARTUPINFOW StartupInfo,
    LPPROCESS_INFORMATION ProcessInformation) {
    if (KevlarHook::ReentryActive())
        return Orig_CreateProcessW(ApplicationName, CommandLine, ProcessAttributes,
            ThreadAttributes, InheritHandles, CreationFlags, Environment, CurrentDirectory,
            StartupInfo, ProcessInformation);

    KevlarHook::ReentryGuard Guard;
    BOOL CallerWantedSuspended = (CreationFlags & CREATE_SUSPENDED) != 0;
    PublishPipeNameForChild(Environment);

    BOOL Created = Orig_CreateProcessW(ApplicationName, CommandLine, ProcessAttributes,
        ThreadAttributes, InheritHandles, CreationFlags | CREATE_SUSPENDED, Environment,
        CurrentDirectory, StartupInfo, ProcessInformation);
    HookChildAndResume(DescribeW(ApplicationName, CommandLine), Created,
        CallerWantedSuspended, ProcessInformation);
    return Created;
}

BOOL WINAPI Hk_CreateProcessA(LPCSTR ApplicationName, LPSTR CommandLine,
    LPSECURITY_ATTRIBUTES ProcessAttributes, LPSECURITY_ATTRIBUTES ThreadAttributes,
    BOOL InheritHandles, DWORD CreationFlags, LPVOID Environment,
    LPCSTR CurrentDirectory, LPSTARTUPINFOA StartupInfo,
    LPPROCESS_INFORMATION ProcessInformation) {
    if (KevlarHook::ReentryActive())
        return Orig_CreateProcessA(ApplicationName, CommandLine, ProcessAttributes,
            ThreadAttributes, InheritHandles, CreationFlags, Environment, CurrentDirectory,
            StartupInfo, ProcessInformation);

    KevlarHook::ReentryGuard Guard;
    BOOL CallerWantedSuspended = (CreationFlags & CREATE_SUSPENDED) != 0;
    PublishPipeNameForChild(Environment);

    BOOL Created = Orig_CreateProcessA(ApplicationName, CommandLine, ProcessAttributes,
        ThreadAttributes, InheritHandles, CreationFlags | CREATE_SUSPENDED, Environment,
        CurrentDirectory, StartupInfo, ProcessInformation);
    HookChildAndResume(L"<ANSI child>", Created, CallerWantedSuspended, ProcessInformation);
    return Created;
}

BOOL WINAPI Hk_CreateProcessAsUserW(HANDLE Token, LPCWSTR ApplicationName,
    LPWSTR CommandLine, LPSECURITY_ATTRIBUTES ProcessAttributes,
    LPSECURITY_ATTRIBUTES ThreadAttributes, BOOL InheritHandles, DWORD CreationFlags,
    LPVOID Environment, LPCWSTR CurrentDirectory, LPSTARTUPINFOW StartupInfo,
    LPPROCESS_INFORMATION ProcessInformation) {
    if (KevlarHook::ReentryActive())
        return Orig_CreateProcessAsUserW(Token, ApplicationName, CommandLine,
            ProcessAttributes, ThreadAttributes, InheritHandles, CreationFlags, Environment,
            CurrentDirectory, StartupInfo, ProcessInformation);

    KevlarHook::ReentryGuard Guard;
    BOOL CallerWantedSuspended = (CreationFlags & CREATE_SUSPENDED) != 0;
    PublishPipeNameForChild(Environment);

    BOOL Created = Orig_CreateProcessAsUserW(Token, ApplicationName, CommandLine,
        ProcessAttributes, ThreadAttributes, InheritHandles,
        CreationFlags | CREATE_SUSPENDED, Environment, CurrentDirectory, StartupInfo,
        ProcessInformation);
    HookChildAndResume(DescribeW(ApplicationName, CommandLine), Created,
        CallerWantedSuspended, ProcessInformation);
    return Created;
}

BOOL WINAPI Hk_CreateProcessAsUserA(HANDLE Token, LPCSTR ApplicationName,
    LPSTR CommandLine, LPSECURITY_ATTRIBUTES ProcessAttributes,
    LPSECURITY_ATTRIBUTES ThreadAttributes, BOOL InheritHandles, DWORD CreationFlags,
    LPVOID Environment, LPCSTR CurrentDirectory, LPSTARTUPINFOA StartupInfo,
    LPPROCESS_INFORMATION ProcessInformation) {
    if (KevlarHook::ReentryActive())
        return Orig_CreateProcessAsUserA(Token, ApplicationName, CommandLine,
            ProcessAttributes, ThreadAttributes, InheritHandles, CreationFlags, Environment,
            CurrentDirectory, StartupInfo, ProcessInformation);

    KevlarHook::ReentryGuard Guard;
    BOOL CallerWantedSuspended = (CreationFlags & CREATE_SUSPENDED) != 0;
    PublishPipeNameForChild(Environment);

    BOOL Created = Orig_CreateProcessAsUserA(Token, ApplicationName, CommandLine,
        ProcessAttributes, ThreadAttributes, InheritHandles,
        CreationFlags | CREATE_SUSPENDED, Environment, CurrentDirectory, StartupInfo,
        ProcessInformation);
    HookChildAndResume(L"<ANSI child>", Created, CallerWantedSuspended, ProcessInformation);
    return Created;
}

} // namespace

namespace ProcessHooks {

void Install() {
    struct { const wchar_t* Module; const char* Name; void* Detour; void** Original; } Sites[] = {
        { L"kernel32.dll", "CreateProcessW", (void*)&Hk_CreateProcessW, (void**)&Orig_CreateProcessW },
        { L"kernel32.dll", "CreateProcessA", (void*)&Hk_CreateProcessA, (void**)&Orig_CreateProcessA },
    };
    for (auto& Site : Sites) {
        void* Target = HookEngine::Resolve(Site.Module, Site.Name);
        if (!HookEngine::Install(Site.Name, Target, Site.Detour, Site.Original))
            *Site.Original = Target;
    }
}

void InstallDelayed() {
    struct { const wchar_t* Module; const char* Name; void* Detour; void** Original; } Sites[] = {
        { L"advapi32.dll", "CreateProcessAsUserW", (void*)&Hk_CreateProcessAsUserW, (void**)&Orig_CreateProcessAsUserW },
        { L"advapi32.dll", "CreateProcessAsUserA", (void*)&Hk_CreateProcessAsUserA, (void**)&Orig_CreateProcessAsUserA },
    };
    for (auto& Site : Sites) {
        void* Target = HookEngine::Resolve(Site.Module, Site.Name);
        if (!HookEngine::Install(Site.Name, Target, Site.Detour, Site.Original))
            *Site.Original = Target;
    }
}

} // namespace ProcessHooks
