#pragma once

// Client side of the KEVLAR --serve pipe (docs/bridge.md SS3): one message-mode
// named-pipe write per request, one read per response, one exchange at a time.

#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

#include "../KEVLAR/host/bridge/bridge_protocol.h"

namespace BridgeClient {

struct DeviceEntry {
    std::wstring DeviceName;   // as passed to IoCreateDevice, e.g. "\Device\Foo"
    std::wstring SymLinkName;  // as passed to IoCreateSymbolicLink, may be empty
    uint32_t DeviceType;
};

// Serializes the whole request/response exchange -- the server dispatches one IRP at a
// time anyway (KEVLAR/core/io/io_manager.h DispatchMutex), so there is nothing to gain
// by keeping several requests in flight.
bool SendRecv(Bridge::Opcode Op, uint64_t Session, uint32_t IoControlCode,
    const void* InBuf, uint32_t InLen, void* OutBuf, uint32_t OutCap,
    Bridge::ResponseHeader& OutHdr, uint32_t& OutLen);

// True once the emulator has been reached at least once on the current pipe name.
bool Reachable();

// Devices the emulated driver registered, from the ENUM opcode. Cached after the first
// success; retried at most every couple of seconds while the emulator is not answering.
std::vector<DeviceEntry> Devices();

// Decides whether an NT path a client is opening belongs to the emulated driver, and
// returns the exact device name to send in an OPEN (the server matches it against
// DeviceTracker by full name). Empty means "not ours, pass it through".
std::wstring MatchDevice(const std::wstring& NtPath);

void Disconnect();

} // namespace BridgeClient
