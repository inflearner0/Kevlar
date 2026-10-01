#pragma once

// Shared plumbing for kevlar_hook.dll -- logging, environment configuration and the
// device-path helpers used by both the SCM hooks and the device-I/O hooks.
//
// See docs/bridge.md SS4 for what this DLL is and SS2 for what it deliberately does not do.

#include <windows.h>
#include <string>

namespace KevlarHook {

// Any state a detour can reach must outlive static destruction. A hooked NtClose or
// NtWriteFile keeps firing while the host process tears itself down, long after this
// DLL's own globals would have been destroyed -- touching a destroyed std::unordered_map
// from there kills the process on its way out. Everything reachable from a detour is
// therefore allocated once and deliberately never freed.
template <typename T>
T& Immortal() {
    static T* Instance = new T();
    return *Instance;
}

// ---- logging ----
// Appends to %KEVLAR_HOOK_LOG% (default %TEMP%\kevlar_hook.log) and mirrors to the
// debugger. Every hooked decision logs one line: the log is the product of a run.
void LogInit();
void Log(const char* Fmt, ...);

// ---- configuration ----
// KEVLAR_HOOK_PIPE     full pipe path; default derives from the intercepted service name
// KEVLAR_HOOK_SERVICE  only fake this one service name (default: every kernel driver)
// KEVLAR_HOOK_DEVICE   device name to Open on the bridge when enumeration is unavailable
// KEVLAR_HOOK_MATCH    substring override for device-path matching
// KEVLAR_HOOK_LOG      log file path
std::wstring EnvOr(const wchar_t* Name, const std::wstring& Fallback);
std::wstring ToUpper(std::wstring S);
bool IEquals(const std::wstring& A, const std::wstring& B);

// Leaf of a device path, upper-cased: "\??\Foo", "\Device\Foo", "\DosDevices\Foo",
// "\\.\Foo" and "Foo" all reduce to "FOO". The bridge's DeviceTracker::FindByName
// matches the full name, so this is only used to decide *whether* a path is ours.
std::wstring DeviceLeaf(const std::wstring& Path);

// The bridge channel. Fixed at attach from Bridge::kDefaultPipeNameW, or from
// KEVLAR_HOOK_PIPE when several emulators are running side by side. Never derived from
// a service name: what identifies the driver is the device it creates.
std::wstring PipeName();
bool PipeNameOverridden();

// This DLL's own path on disk, recorded at attach. The process hooks need it to inject
// the same DLL into a child.
void SetSelfModule(HMODULE Module);
std::wstring SelfModulePath();

} // namespace KevlarHook
