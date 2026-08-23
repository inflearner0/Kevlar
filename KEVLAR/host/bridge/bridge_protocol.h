#pragma once

// Wire protocol for the Phase 1 usermode bridge (kevlar_proxy/README.md SS3).
// One message-mode named-pipe write == one request; one write == one response.
// Fixed-size headers below are read/written as raw bytes (no marshalling library),
// so keep them POD and explicitly packed.

#include <cstdint>

namespace Bridge {

// 'KVLB' -- distinguishes a real client from a stray connection on the pipe.
constexpr uint32_t kMagic = 0x4B564C42;
constexpr uint16_t kVersion = 1;

// Cap on InLen/OutLen (kevlar_proxy/README.md SS3.4): bounds guest-side allocation
// a client can trigger per request.
constexpr uint32_t kMaxPayload = 1 * 1024 * 1024;

enum class Opcode : uint16_t {
    Enum = 1,   // -> device list, no request payload
    Open = 2,   // request payload = device/symlink name (UTF-16LE, no NUL required)
    Ioctl = 3,  // request payload = input buffer; OutLen = requested output size
    Read = 4,   // no request payload; OutLen = requested read size
    Write = 5,  // request payload = write buffer
    Close = 6,  // no request payload
};

#pragma pack(push, 1)

struct RequestHeader {
    uint32_t Magic;
    uint16_t Version;
    uint16_t Opcode;
    uint64_t Session;   // 0 for Enum/Open; the session id returned by Open otherwise
    uint32_t IoControlCode;
    uint32_t InLen;     // bytes of request payload following this header
    uint32_t OutLen;    // requested output size (Ioctl/Read); ignored otherwise
};

struct ResponseHeader {
    int32_t Status;        // NTSTATUS
    uint64_t Information;  // IoStatus.Information / bytes returned
    uint64_t Session;      // echoed back; for Open, the newly assigned session id
    uint32_t OutLen;       // bytes of response payload following this header
};

#pragma pack(pop)

} // namespace Bridge
