#pragma once

// Follows the hook down the process tree.
//
// A driver client is often not the process you launch: a launcher starts the program
// that actually opens the device. Without this, injecting into the launcher covers
// nothing that matters. CreateProcess* here forces the child suspended, injects this
// same DLL into it, and only then lets it run -- so the child is hooked before it
// executes any of its own code, exactly as if kevlar_inject had launched it.

namespace ProcessHooks {

// kernel32's CreateProcessW/A. Safe from DllMain: kernel32 is mapped in every process.
void Install();

// advapi32's CreateProcessAsUserW/A, which cannot be resolved until advapi32 is mapped.
// Called by the service hooks' worker once it has waited for that module.
void InstallDelayed();

} // namespace ProcessHooks
