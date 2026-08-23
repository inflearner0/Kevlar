#pragma once

// KEVLAR Usermode Bridge, Phase 2 wire protocol (kevlar_proxy/README.md SS4).
// Shared verbatim between the kernel driver (kevlarproxy.sys, plain C) and the
// host relay (KEVLAR/host/bridge/proxy_relay.cpp, C++). Plain-C POD only: fixed
// width types, no STL, no C++ features.
//
// Deliberately does not include ntdef.h/ntddk.h/windows.h itself: ntdef.h requires
// a target-architecture macro that only the kernel toolset defines, which breaks a
// usermode build. NTSTATUS/WCHAR/ULONG/UINT64 must already be visible from the
// includer -- ntddk.h in kevlarproxy.c, windows.h in proxy_relay.cpp -- before this
// header is included.

#define KVP_DEVICE_TYPE 0x8000u

// All control-channel IOCTLs are METHOD_BUFFERED: the payloads here are small
// (fixed headers) or, for GET_REQUEST/COMPLETE_REQUEST, bounded by KVP_MAX_PAYLOAD
// and a buffered copy is simplest to reason about on the control channel itself.
// (The *relayed* IOCTLs against exposed devices still get real BUFFERED/DIRECT/
// NEITHER handling -- see kevlarproxy.c.)
#define IOCTL_KVP_CREATE_DEVICE    CTL_CODE(KVP_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KVP_GET_REQUEST      CTL_CODE(KVP_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KVP_COMPLETE_REQUEST CTL_CODE(KVP_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

// Mirrors kevlar_proxy/README.md SS3.4's Phase 1 bound: caps pool allocation a
// captured request can drive, and how large a GET_REQUEST/COMPLETE_REQUEST buffer
// the host ever needs to provision.
#define KVP_MAX_PAYLOAD (1u * 1024u * 1024u)

#define KVP_MAX_NAME_CHARS 256u   // wchar_t count including a NUL terminator
#define KVP_MAX_DEVICES 64u       // fixed-size device slot table in the driver

#pragma pack(push, 1)

typedef enum _KVP_MAJOR_OP {
    KvpOpCreate = 0,
    KvpOpClose = 1,
    KvpOpCleanup = 2,
    KvpOpDeviceControl = 3,
    KvpOpRead = 4,
    KvpOpWrite = 5,
} KVP_MAJOR_OP;

// IOCTL_KVP_CREATE_DEVICE input. Always creates an Administrators-only device
// (kevlar_proxy/README.md SS4.5) -- there is deliberately no knob to widen the ACL.
typedef struct _KVP_CREATE_DEVICE_IN {
    WCHAR DeviceName[KVP_MAX_NAME_CHARS];    // e.g. L"\Device\Foo"
    WCHAR SymLinkName[KVP_MAX_NAME_CHARS];   // e.g. L"\DosDevices\Foo"; empty = no symlink
    ULONG DeviceType;
} KVP_CREATE_DEVICE_IN, *PKVP_CREATE_DEVICE_IN;

typedef struct _KVP_CREATE_DEVICE_OUT {
    NTSTATUS Status;
    ULONG DeviceIndex;   // driver-assigned slot; echoed back on every relayed request for this device
    // A symlink failure does not fail the whole call (the device is still reachable
    // by its NT path either way) but is not silently discarded either: 0 if no
    // symlink was requested, otherwise the real NTSTATUS from IoCreateSymbolicLink.
    LONG SymLinkStatus;
} KVP_CREATE_DEVICE_OUT, *PKVP_CREATE_DEVICE_OUT;

// IOCTL_KVP_GET_REQUEST output: one relayed request, header followed by InLen
// bytes of captured input. The host must provision an output buffer of at least
// sizeof(KVP_REQUEST_HEADER) + KVP_MAX_PAYLOAD; capture already enforces InLen <=
// KVP_MAX_PAYLOAD so this always fits.
typedef struct _KVP_REQUEST_HEADER {
    UINT64 RequestId;      // matched by a later IOCTL_KVP_COMPLETE_REQUEST
    ULONG DeviceIndex;
    UINT64 FileId;         // stable per real FILE_OBJECT (its pointer value; opaque to the host)
    ULONG Op;              // KVP_MAJOR_OP
    ULONG IoControlCode;   // valid for KvpOpDeviceControl only
    ULONG InLen;           // bytes of captured input following this header
    ULONG OutCap;          // max output the real client's request can accept
} KVP_REQUEST_HEADER, *PKVP_REQUEST_HEADER;

// IOCTL_KVP_COMPLETE_REQUEST input: header followed by OutLen bytes of output
// payload (OutLen <= the OutCap from the matching KVP_REQUEST_HEADER).
typedef struct _KVP_COMPLETE_HEADER {
    UINT64 RequestId;
    LONG Status;      // NTSTATUS
    UINT64 Information;
    ULONG OutLen;
} KVP_COMPLETE_HEADER, *PKVP_COMPLETE_HEADER;

#pragma pack(pop)
