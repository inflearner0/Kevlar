#include "bridge_client.h"
#include "kevlar_hook.h"
#include "reentry.h"

#include <algorithm>
#include <mutex>

using KevlarHook::DeviceLeaf;
using KevlarHook::EnvOr;
using KevlarHook::Log;
using KevlarHook::ToUpper;

namespace BridgeClient {

namespace {

// Reached from the device detours, so never destroyed -- see KevlarHook::Immortal.
struct PipeState {
    std::mutex Lock;
    HANDLE Pipe = INVALID_HANDLE_VALUE;
    bool EverReachable = false;
};

struct DeviceState {
    std::mutex Lock;
    std::vector<DeviceEntry> Devices;
    bool Valid = false;
    ULONGLONG LastEnumAttemptMs = 0;
};

PipeState& Pipe() { return KevlarHook::Immortal<PipeState>(); }
DeviceState& Cache() { return KevlarHook::Immortal<DeviceState>(); }

// While the emulator is not up, a client that opens files in a loop must not pay a
// pipe-connect attempt per open.
constexpr ULONGLONG kEnumRetryIntervalMs = 2000;

// Called with PipeState::Lock held.
bool EnsurePipeConnected() {
    PipeState& State = Pipe();
    if (State.Pipe != INVALID_HANDLE_VALUE)
        return true;

    std::wstring Name = KevlarHook::PipeName();
    if (Name.empty())
        return false;

    HANDLE Handle = CreateFileW(Name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
        OPEN_EXISTING, 0, nullptr);
    if (Handle == INVALID_HANDLE_VALUE) {
        if (GetLastError() == ERROR_PIPE_BUSY && WaitNamedPipeW(Name.c_str(), 2000)) {
            Handle = CreateFileW(Name.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                OPEN_EXISTING, 0, nullptr);
        }
    }
    if (Handle == INVALID_HANDLE_VALUE) {
        Log("Bridge pipe %ls not available, gle=%lu", Name.c_str(), GetLastError());
        return false;
    }

    DWORD Mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(Handle, &Mode, nullptr, nullptr);
    State.Pipe = Handle;
    State.EverReachable = true;
    Log("Connected to %ls", Name.c_str());
    return true;
}

void DropConnectionLocked() {
    PipeState& State = Pipe();
    if (State.Pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(State.Pipe);
        State.Pipe = INVALID_HANDLE_VALUE;
    }
}

bool ReadU32(const uint8_t* Buf, uint32_t Len, uint32_t& Offset, uint32_t& Out) {
    if (Offset + sizeof(uint32_t) > Len)
        return false;
    memcpy(&Out, Buf + Offset, sizeof(uint32_t));
    Offset += sizeof(uint32_t);
    return true;
}

bool ReadString(const uint8_t* Buf, uint32_t Len, uint32_t& Offset, std::wstring& Out) {
    uint32_t Bytes = 0;
    if (!ReadU32(Buf, Len, Offset, Bytes))
        return false;
    if (Bytes % sizeof(wchar_t) || Offset + Bytes > Len)
        return false;
    Out.assign((const wchar_t*)(Buf + Offset), Bytes / sizeof(wchar_t));
    Offset += Bytes;
    return true;
}

// HandleEnum in bridge_server.cpp writes: count, then per device
// {nameBytes, name, symBytes, symlink, deviceType}.
bool ParseEnum(const uint8_t* Payload, uint32_t Len, std::vector<DeviceEntry>& Out) {
    uint32_t Offset = 0;
    uint32_t Count = 0;
    if (!ReadU32(Payload, Len, Offset, Count))
        return false;
    for (uint32_t I = 0; I < Count; I++) {
        DeviceEntry Entry{};
        if (!ReadString(Payload, Len, Offset, Entry.DeviceName))
            return false;
        if (!ReadString(Payload, Len, Offset, Entry.SymLinkName))
            return false;
        if (!ReadU32(Payload, Len, Offset, Entry.DeviceType))
            return false;
        Out.push_back(std::move(Entry));
    }
    return true;
}

// Refreshes the device cache at most once per kEnumRetryIntervalMs while the emulator
// is unreachable. Returns a copy so callers never hold g_DeviceLock across a match.
std::vector<DeviceEntry> DevicesLocked() {
    DeviceState& State = Cache();
    {
        std::lock_guard<std::mutex> Guard(State.Lock);
        if (State.Valid)
            return State.Devices;
        ULONGLONG Now = GetTickCount64();
        if (State.LastEnumAttemptMs && Now - State.LastEnumAttemptMs < kEnumRetryIntervalMs)
            return {};
        State.LastEnumAttemptMs = Now;
    }

    std::vector<uint8_t> Payload(Bridge::kMaxPayload);
    Bridge::ResponseHeader Resp{};
    uint32_t OutLen = 0;
    if (!SendRecv(Bridge::Opcode::Enum, 0, 0, nullptr, 0, Payload.data(),
            (uint32_t)Payload.size(), Resp, OutLen))
        return {};
    if (Resp.Status < 0) {
        Log("ENUM failed, status=0x%08x", (unsigned)Resp.Status);
        return {};
    }

    std::vector<DeviceEntry> Parsed;
    if (!ParseEnum(Payload.data(), OutLen, Parsed)) {
        Log("ENUM response malformed (%u bytes)", OutLen);
        return {};
    }

    std::lock_guard<std::mutex> Guard(State.Lock);
    State.Devices = Parsed;
    State.Valid = true;
    for (const auto& Entry : State.Devices)
        Log("Emulated device: %ls (symlink %ls, type 0x%x)", Entry.DeviceName.c_str(),
            Entry.SymLinkName.empty() ? L"<none>" : Entry.SymLinkName.c_str(), Entry.DeviceType);
    return State.Devices;
}

} // namespace

bool SendRecv(Bridge::Opcode Op, uint64_t Session, uint32_t IoControlCode,
    const void* InBuf, uint32_t InLen, void* OutBuf, uint32_t OutCap,
    Bridge::ResponseHeader& OutHdr, uint32_t& OutLen) {
    // Everything below issues real file I/O on the pipe; without this the device hooks
    // would re-enter themselves through their own transport.
    KevlarHook::ReentryGuard Guard;

    if (InLen > Bridge::kMaxPayload || OutCap > Bridge::kMaxPayload) {
        Log("Request rejected locally: InLen=%u OutLen=%u exceeds the %u byte cap",
            InLen, OutCap, Bridge::kMaxPayload);
        return false;
    }

    std::vector<uint8_t> Request(sizeof(Bridge::RequestHeader) + InLen);
    auto* Header = reinterpret_cast<Bridge::RequestHeader*>(Request.data());
    Header->Magic = Bridge::kMagic;
    Header->Version = Bridge::kVersion;
    Header->Opcode = (uint16_t)Op;
    Header->Session = Session;
    Header->IoControlCode = IoControlCode;
    Header->InLen = InLen;
    Header->OutLen = OutCap;
    if (InLen && InBuf)
        memcpy(Request.data() + sizeof(*Header), InBuf, InLen);

    PipeState& State = Pipe();
    std::lock_guard<std::mutex> PipeGuard(State.Lock);
    if (!EnsurePipeConnected())
        return false;

    bool Ok = true;
    DWORD Written = 0;
    if (!WriteFile(State.Pipe, Request.data(), (DWORD)Request.size(), &Written, nullptr) ||
            Written != Request.size())
        Ok = false;

    if (Ok) {
        std::vector<uint8_t> Response(sizeof(Bridge::ResponseHeader) + (size_t)OutCap);
        DWORD Got = 0;
        if (!ReadFile(State.Pipe, Response.data(), (DWORD)Response.size(), &Got, nullptr))
            Ok = false;
        else if (Got < sizeof(Bridge::ResponseHeader))
            Ok = false;
        else {
            memcpy(&OutHdr, Response.data(), sizeof(OutHdr));
            OutLen = (std::min)(OutHdr.OutLen, (uint32_t)(Got - sizeof(OutHdr)));
            OutLen = (std::min)(OutLen, OutCap);
            if (OutBuf && OutLen)
                memcpy(OutBuf, Response.data() + sizeof(OutHdr), OutLen);
        }
    }

    if (!Ok) {
        Log("Transport error on opcode %u, gle=%lu -- dropping connection", (unsigned)Op,
            GetLastError());
        DropConnectionLocked();
        DeviceState& Devices = Cache();
        std::lock_guard<std::mutex> DeviceGuard(Devices.Lock);
        Devices.Valid = false;
    }
    return Ok;
}

bool Reachable() {
    PipeState& State = Pipe();
    std::lock_guard<std::mutex> Guard(State.Lock);
    return State.EverReachable;
}

std::vector<DeviceEntry> Devices() {
    return DevicesLocked();
}

std::wstring MatchDevice(const std::wstring& NtPath) {
    if (NtPath.empty())
        return {};

    std::wstring Leaf = DeviceLeaf(NtPath);
    if (Leaf.empty() || Leaf.find(L':') != std::wstring::npos)
        return {};  // drive-letter and file-system opens are never ours

    // An explicit substring override skips enumeration entirely: it exists for the case
    // where the emulator is not up yet but the operator already knows both names.
    std::wstring Override = ToUpper(EnvOr(L"KEVLAR_HOOK_MATCH", L""));
    if (!Override.empty() && ToUpper(NtPath).find(Override) != std::wstring::npos) {
        std::wstring Configured = EnvOr(L"KEVLAR_HOOK_DEVICE", L"");
        if (!Configured.empty())
            return Configured;
        auto Enumerated = DevicesLocked();
        if (!Enumerated.empty())
            return Enumerated.front().DeviceName;
        return L"\\Device\\" + NtPath.substr(NtPath.find_last_of(L'\\') + 1);
    }

    for (const auto& Entry : DevicesLocked()) {
        if (DeviceLeaf(Entry.DeviceName) == Leaf ||
                (!Entry.SymLinkName.empty() && DeviceLeaf(Entry.SymLinkName) == Leaf))
            return Entry.DeviceName;
    }

    // Enumeration unavailable (emulator not up, or the driver registered its device
    // after we last asked) but the operator named the device explicitly.
    std::wstring Configured = EnvOr(L"KEVLAR_HOOK_DEVICE", L"");
    if (!Configured.empty() && DeviceLeaf(Configured) == Leaf)
        return Configured;

    return {};
}

void Disconnect() {
    PipeState& State = Pipe();
    std::lock_guard<std::mutex> Guard(State.Lock);
    DropConnectionLocked();
}

} // namespace BridgeClient
