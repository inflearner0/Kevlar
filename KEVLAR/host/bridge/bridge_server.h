#pragma once

#include <string>

// In-process IOCTL server (kevlar_proxy/README.md SS3). Exposes DeviceTracker's
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

} // namespace BridgeServer
