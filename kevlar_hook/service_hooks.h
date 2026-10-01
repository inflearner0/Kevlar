#pragma once

// Makes the client believe it installed and started a kernel service.
//
// The service-control APIs live in sechost.dll on Win8+, with advapi32 forwarding to
// them, so hooking the address GetProcAddress resolves covers both import paths.
//
// Nothing here loads a driver, writes a service key, or needs the real SCM: the whole
// point is that no unsigned driver reaches the kernel while the client still walks its
// normal install -> start -> open sequence, which then lands on the device hooks.

namespace ServiceHooks {

// Installs immediately if the service APIs are already mapped -- they are, for any
// client that imports advapi32, by the time an injected DLL runs. Otherwise starts a
// worker that waits for the module and installs then, because LoadLibrary must not be
// called under the loader lock.
void InstallDeferred();

} // namespace ServiceHooks
