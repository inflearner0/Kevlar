#include "kevlar_hook.h"

#include "../KEVLAR/host/bridge/bridge_protocol.h"

#include <algorithm>
#include <cstdarg>
#include <cstdio>
#include <mutex>

namespace KevlarHook {

namespace {

// Raw Win32 file I/O rather than the CRT's stdio: the CRT closes every open stream during
// process exit, and the hooks keep logging after that. Writing to a closed FILE* reaches
// the invalid-parameter handler, which is __fastfail -- the client would die on its way
// out, in this DLL, for a log line.
struct LogState {
    std::mutex Lock;
    HANDLE File = INVALID_HANDLE_VALUE;
};

struct ConfigState {
    std::mutex Lock;
    std::wstring PipeName;   // set once at attach, never re-derived
    bool PipeNameFromEnv = false;
    std::wstring SelfPath;
};

LogState& Logs() { return Immortal<LogState>(); }
ConfigState& Config() { return Immortal<ConfigState>(); }

} // namespace

void LogInit() {
    wchar_t Path[MAX_PATH];
    DWORD N = GetEnvironmentVariableW(L"KEVLAR_HOOK_LOG", Path, MAX_PATH);
    if (!N || N >= MAX_PATH) {
        wchar_t Tmp[MAX_PATH];
        GetTempPathW(MAX_PATH, Tmp);
        swprintf_s(Path, L"%skevlar_hook.log", Tmp);
    }

    LogState& State = Logs();
    {
        std::lock_guard<std::mutex> Guard(State.Lock);
        State.File = CreateFileW(Path, FILE_APPEND_DATA, FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    }

    // The channel is known before anything is intercepted: it is the constant compiled
    // into both ends (Bridge::kDefaultPipeNameW), not something derived from a service
    // name the client may never use. That is what lets a device open be matched purely
    // on the device name, with no dependency on how the driver was installed.
    ConfigState& Cfg = Config();
    std::lock_guard<std::mutex> ConfigGuard(Cfg.Lock);
    std::wstring FromEnv = EnvOr(L"KEVLAR_HOOK_PIPE", L"");
    Cfg.PipeName = FromEnv.empty() ? Bridge::kDefaultPipeNameW : FromEnv;
    Cfg.PipeNameFromEnv = !FromEnv.empty();
}

void Log(const char* Fmt, ...) {
    char Line[1200];
    int Prefix = _snprintf_s(Line, sizeof(Line), _TRUNCATE, "[%lu] ", GetCurrentThreadId());
    if (Prefix < 0)
        Prefix = 0;

    va_list Args;
    va_start(Args, Fmt);
    int Body = _vsnprintf_s(Line + Prefix, sizeof(Line) - Prefix, _TRUNCATE, Fmt, Args);
    va_end(Args);
    if (Body < 0)
        Body = (int)strlen(Line + Prefix);

    size_t Length = (size_t)Prefix + (size_t)Body;
    if (Length + 2 < sizeof(Line)) {
        Line[Length++] = '\r';
        Line[Length++] = '\n';
    }

    OutputDebugStringA(Line);

    HANDLE Console = GetStdHandle(STD_OUTPUT_HANDLE);
    if (Console && Console != INVALID_HANDLE_VALUE) {
        DWORD ConsoleCharsWritten = 0;
        WriteConsoleA(Console, Line, (DWORD)Length, &ConsoleCharsWritten, nullptr);
    }

    LogState& State = Logs();
    std::lock_guard<std::mutex> Guard(State.Lock);
    if (State.File != INVALID_HANDLE_VALUE) {
        DWORD Written = 0;
        WriteFile(State.File, Line, (DWORD)Length, &Written, nullptr);
    }
}

std::wstring EnvOr(const wchar_t* Name, const std::wstring& Fallback) {
    wchar_t Buf[512];
    DWORD N = GetEnvironmentVariableW(Name, Buf, 512);
    if (N && N < 512)
        return std::wstring(Buf, N);
    return Fallback;
}

std::wstring ToUpper(std::wstring S) {
    std::transform(S.begin(), S.end(), S.begin(), ::towupper);
    return S;
}

bool IEquals(const std::wstring& A, const std::wstring& B) {
    return A.size() == B.size() && ToUpper(A) == ToUpper(B);
}

std::wstring DeviceLeaf(const std::wstring& Path) {
    std::wstring Upper = ToUpper(Path);

    // Strip any of the namespace prefixes a client can reach the same device through.
    static const wchar_t* Prefixes[] = {
        L"\\??\\", L"\\DOSDEVICES\\", L"\\DEVICE\\", L"\\GLOBAL??\\", L"\\\\.\\", L"\\\\?\\",
    };
    for (const wchar_t* Prefix : Prefixes) {
        size_t Len = wcslen(Prefix);
        if (Upper.size() > Len && Upper.compare(0, Len, Prefix) == 0) {
            Upper.erase(0, Len);
            break;
        }
    }

    // A device open can carry a trailing path ("\Device\Foo\Bar"); the leaf is the first
    // component, which is the name the device object was created under.
    size_t Slash = Upper.find(L'\\');
    if (Slash != std::wstring::npos)
        Upper.erase(Slash);
    return Upper;
}

std::wstring PipeName() {
    ConfigState& Cfg = Config();
    std::lock_guard<std::mutex> Guard(Cfg.Lock);
    return Cfg.PipeName;
}

bool PipeNameOverridden() {
    ConfigState& Cfg = Config();
    std::lock_guard<std::mutex> Guard(Cfg.Lock);
    return Cfg.PipeNameFromEnv;
}

void SetSelfModule(HMODULE Module) {
    wchar_t Path[MAX_PATH];
    DWORD N = GetModuleFileNameW(Module, Path, MAX_PATH);
    if (!N || N >= MAX_PATH)
        return;
    ConfigState& Cfg = Config();
    std::lock_guard<std::mutex> Guard(Cfg.Lock);
    Cfg.SelfPath.assign(Path, N);
}

std::wstring SelfModulePath() {
    ConfigState& Cfg = Config();
    std::lock_guard<std::mutex> Guard(Cfg.Lock);
    return Cfg.SelfPath;
}

} // namespace KevlarHook
