// kevlar_inject.exe -- launches a target process suspended, injects kevlar_hook.dll
// (found next to this exe) via the classic CreateRemoteThread + LoadLibraryW pattern,
// then resumes the main thread. Standard, well-understood technique; here it targets a
// process the operator owns for offline analysis against the KEVLAR --serve bridge.

#include <windows.h>
#include <string>
#include <vector>
#include <cstdio>

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: kevlar_inject.exe <target.exe> [args...]\n");
        return 1;
    }

    wchar_t exePath[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, exePath, MAX_PATH);

    std::wstring cmdLine = L"\"" + std::wstring(exePath) + L"\"";
    for (int i = 2; i < argc; i++) {
        wchar_t arg[MAX_PATH];
        MultiByteToWideChar(CP_UTF8, 0, argv[i], -1, arg, MAX_PATH);
        cmdLine += L" ";
        cmdLine += arg;
    }

    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    std::wstring dir(selfPath);
    dir = dir.substr(0, dir.find_last_of(L"\\/"));
    std::wstring hookDll = dir + L"\\kevlar_hook.dll";
    if (GetFileAttributesW(hookDll.c_str()) == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"kevlar_hook.dll not found next to injector: %ls\n", hookDll.c_str());
        return 1;
    }

    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
    cmdBuf.push_back(0);

    if (!CreateProcessW(exePath, cmdBuf.data(), nullptr, nullptr, FALSE,
            CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        wprintf(L"CreateProcess failed, gle=%lu\n", GetLastError());
        return 1;
    }

    SIZE_T sz = (hookDll.size() + 1) * sizeof(wchar_t);
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, nullptr, sz, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        wprintf(L"VirtualAllocEx failed, gle=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    WriteProcessMemory(pi.hProcess, remoteMem, hookDll.c_str(), sz, nullptr);

    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    auto loadLibW = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    HANDLE hThread = CreateRemoteThread(pi.hProcess, nullptr, 0, loadLibW, remoteMem, 0, nullptr);
    if (!hThread) {
        wprintf(L"CreateRemoteThread failed, gle=%lu\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        return 1;
    }
    WaitForSingleObject(hThread, 10000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);
    VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);

    if (exitCode == 0)
        wprintf(L"WARNING: LoadLibraryW returned NULL -- hook DLL may not have loaded\n");
    else
        wprintf(L"kevlar_hook.dll injected (module base 0x%p)\n", (void*)(uintptr_t)exitCode);

    ResumeThread(pi.hThread);
    wprintf(L"Resumed target, PID %lu\n", pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
