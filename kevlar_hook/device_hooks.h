#pragma once

// Redirects the client's device I/O -- open, IOCTL, read, write, close -- from the
// kernel object namespace to the KEVLAR bridge pipe. Hooks sit on the ntdll syscall
// stubs, so both the Win32 entry points (CreateFileW / DeviceIoControl / ReadFile /
// WriteFile) and direct Nt* callers are covered by one set of hooks.

namespace DeviceHooks {

// ntdll is always mapped, so this is safe to call from DllMain.
void Install();

} // namespace DeviceHooks
