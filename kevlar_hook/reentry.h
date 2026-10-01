#pragma once

// Re-entrancy guard.
//
// The device hooks sit on NtCreateFile / NtReadFile / NtWriteFile / NtClose, and this
// DLL's own transport is a named pipe -- i.e. file I/O through exactly those functions.
// Without a guard, one relayed IOCTL would re-enter its own transport forever. The SCM
// hooks need it for the same reason: sechost reaches the service database over ALPC.
//
// Per-thread rather than global: an unrelated thread issuing real I/O while a relay is
// in flight must still be intercepted normally.

namespace KevlarHook {

inline thread_local int TlsReentryDepth = 0;

inline bool ReentryActive() { return TlsReentryDepth > 0; }

struct ReentryGuard {
    ReentryGuard() { TlsReentryDepth++; }
    ~ReentryGuard() { TlsReentryDepth--; }
    ReentryGuard(const ReentryGuard&) = delete;
    ReentryGuard& operator=(const ReentryGuard&) = delete;
};

} // namespace KevlarHook
