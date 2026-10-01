#pragma once

#include <string>

// In-process IOCTL server (docs/bridge.md SS3). Exposes DeviceTracker's
// emulated devices to host usermode clients over a message-mode named pipe by
// calling the existing (previously dead) IoManager::Dispatch* entry points.
// Opt-in: only active when the host passes --serve.
namespace BridgeServer {

// Starts the pipe server on \\.\pipe\kevlar-<Name> on a background thread.
// Returns false if a server is already running.
bool Start(const std::string& Name);

// Signals the server thread to stop, unblocks a pending accept, and joins it.
void Stop();

bool IsActive();

// Randgrid and drivers like it deny IRP_MJ_CREATE from an unauthorised caller,
// which leaves the whole dispatch surface unreachable from a harness: no
// session, so no IOCTL, so the callback and dispatch code never executes and
// never appears in a trace.
//
// With this set the CREATE handler still runs and its status is still reported
// - the denial itself is a result worth having - but the session is kept anyway
// so the IRP paths behind it can be driven. It changes what the harness does
// with the answer, not what the driver computes.
extern bool ForceOpenEnabled;

} // namespace BridgeServer
