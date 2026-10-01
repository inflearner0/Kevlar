#include "host/bridge/bridge_server.h"
#include "host/bridge/bridge_protocol.h"

#include "core/io/io_manager.h"
#include "core/exec/unicorn_engine.h"
#include "api/io/io_device.h"

#include <Logger/Logger.h>

#include <windows.h>
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <thread>
#include <unordered_map>
#include <vector>

// Raw NTSTATUS literals below follow this codebase's existing convention
// (see core/io/irp_ioctl.cpp) of not depending on include/nt_define.h from core/host code.
bool BridgeServer::ForceOpenEnabled = false;

namespace {
constexpr int32_t kStatusSuccess = 0;
constexpr int32_t kStatusUnsuccessful = (int32_t)0xC0000001;
constexpr int32_t kStatusInvalidHandle = (int32_t)0xC0000008;
constexpr int32_t kStatusInvalidParameter = (int32_t)0xC000000D;
constexpr int32_t kStatusBufferTooSmall = (int32_t)0xC0000023;
constexpr int32_t kStatusObjectNameNotFound = (int32_t)0xC0000034;
constexpr int32_t kStatusInsufficientResources = (int32_t)0xC000009A;
constexpr int32_t kStatusNotSupported = (int32_t)0xC00000BB;

// Requests relayed through this bridge originate from a remote client, not from
// literal usermode memory in this process; the buffers backing them come from
// AllocateVariable in the kernel-range UC pool. Passing KernelMode here keeps
// ProbeForRead/ProbeForWrite (and any driver's own previous-mode checks) from
// rejecting them -- see docs/bridge.md SS3.5 and io_manager.h.
constexpr CHAR kBridgeRequestorMode = 0; // KernelMode

struct SessionInfo {
    uint64_t DeviceObjUcAddr;
    uint64_t FileObjUcAddr;
};

std::atomic<bool> Active{ false };
std::atomic<bool> StopRequested{ false };
std::thread ServerThread;
std::wstring PipeName;

// Sessions belong to the connection that opened them. A launcher and the process it
// spawns are two clients on this pipe at once, so a single global table would have
// either one's exit tear down the other's FILE_OBJECTs.
struct ClientState {
    std::mutex Lock;
    std::unordered_map<uint64_t, SessionInfo> Sessions;
};

// Ids stay unique across clients: a stray id from one connection then cannot name
// another's session, and the log is unambiguous about which session is which.
std::atomic<uint64_t> NextSessionId{ 1 };

void AppendBytes(std::vector<uint8_t>& Buf, const void* Data, size_t Len) {
    auto P = (const uint8_t*)Data;
    Buf.insert(Buf.end(), P, P + Len);
}

void SendResponse(HANDLE Pipe, int32_t Status, uint64_t Information, uint64_t Session,
    const void* PayloadData, uint32_t PayloadLen) {
    std::vector<uint8_t> Buf(sizeof(Bridge::ResponseHeader) + PayloadLen);
    Bridge::ResponseHeader Resp{};
    Resp.Status = Status;
    Resp.Information = Information;
    Resp.Session = Session;
    Resp.OutLen = PayloadLen;
    memcpy(Buf.data(), &Resp, sizeof(Resp));
    if (PayloadLen && PayloadData)
        memcpy(Buf.data() + sizeof(Resp), PayloadData, PayloadLen);

    DWORD Written = 0;
    WriteFile(Pipe, Buf.data(), (DWORD)Buf.size(), &Written, nullptr);
}

bool LookupSession(ClientState& Client, uint64_t SessionId, SessionInfo& Out) {
    std::lock_guard<std::mutex> Guard(Client.Lock);
    auto It = Client.Sessions.find(SessionId);
    if (It == Client.Sessions.end())
        return false;
    Out = It->second;
    return true;
}

// Tears down every session still open on this connection (docs/bridge.md
// SS3.3): a crashed or sloppy client must not leak guest FILE_OBJECTs.
void CloseAllSessions(ClientState& Client) {
    std::vector<std::pair<uint64_t, SessionInfo>> ToClose;
    {
        std::lock_guard<std::mutex> Guard(Client.Lock);
        ToClose.assign(Client.Sessions.begin(), Client.Sessions.end());
        Client.Sessions.clear();
    }
    for (auto& [Id, Sess] : ToClose) {
        std::lock_guard<std::mutex> DispatchGuard(IoManager::DispatchMutex);
        IoManager::DispatchCleanup(Sess.DeviceObjUcAddr, Sess.FileObjUcAddr, kBridgeRequestorMode);
        IoManager::DispatchClose(Sess.DeviceObjUcAddr, Sess.FileObjUcAddr, kBridgeRequestorMode);
        IoManager::FreeFileObject(Sess.FileObjUcAddr);
    }
}

void HandleEnum(HANDLE Pipe, const Bridge::RequestHeader& Req) {
    std::vector<uint8_t> Payload;
    uint32_t Count = (uint32_t)DeviceTracker::GetCount();
    AppendBytes(Payload, &Count, sizeof(Count));

    for (uint32_t I = 0; I < Count; I++) {
        auto* Dev = DeviceTracker::GetByIndex(I);
        if (!Dev)
            break;
        uint32_t NameBytes = (uint32_t)(Dev->DeviceName.size() * sizeof(wchar_t));
        AppendBytes(Payload, &NameBytes, sizeof(NameBytes));
        AppendBytes(Payload, Dev->DeviceName.data(), NameBytes);
        uint32_t SymBytes = (uint32_t)(Dev->SymLinkName.size() * sizeof(wchar_t));
        AppendBytes(Payload, &SymBytes, sizeof(SymBytes));
        AppendBytes(Payload, Dev->SymLinkName.data(), SymBytes);
        uint32_t DevType = Dev->DeviceType;
        AppendBytes(Payload, &DevType, sizeof(DevType));
    }

    if (Payload.size() > Bridge::kMaxPayload) {
        SendResponse(Pipe, kStatusBufferTooSmall, 0, Req.Session, nullptr, 0);
        return;
    }
    SendResponse(Pipe, kStatusSuccess, Payload.size(), Req.Session, Payload.data(), (uint32_t)Payload.size());
}

void HandleOpen(ClientState& Client, HANDLE Pipe, const Bridge::RequestHeader& Req, const uint8_t* Payload) {
    if (Req.InLen == 0 || (Req.InLen % sizeof(wchar_t)) != 0) {
        SendResponse(Pipe, kStatusInvalidParameter, 0, 0, nullptr, 0);
        return;
    }
    std::wstring Name((const wchar_t*)Payload, Req.InLen / sizeof(wchar_t));

    uint64_t DeviceObjUcAddr = DeviceTracker::FindByName(Name);
    if (!DeviceObjUcAddr) {
        SendResponse(Pipe, kStatusObjectNameNotFound, 0, 0, nullptr, 0);
        return;
    }

    uint64_t FileObjUcAddr;
    IoManager::DispatchResult CreateResult;
    {
        std::lock_guard<std::mutex> DispatchGuard(IoManager::DispatchMutex);
        FileObjUcAddr = IoManager::AllocateFileObject(UnicornEmu::PrimaryEngine, DeviceObjUcAddr);
        if (!FileObjUcAddr) {
            SendResponse(Pipe, kStatusInsufficientResources, 0, 0, nullptr, 0);
            return;
        }
        CreateResult = IoManager::DispatchCreate(DeviceObjUcAddr, FileObjUcAddr, kBridgeRequestorMode);
        if (CreateResult.Status < 0 && !BridgeServer::ForceOpenEnabled)
            IoManager::FreeFileObject(FileObjUcAddr);
    }

    if (CreateResult.Status < 0) {
        if (!BridgeServer::ForceOpenEnabled) {
            SendResponse(Pipe, CreateResult.Status, 0, 0, nullptr, 0);
            return;
        }
        Logger::Log("{YEL}BridgeServer: CREATE denied %ls (0x%08X) - keeping the session "
            "anyway (--force-open){RESET}\n", Name.c_str(), (unsigned)CreateResult.Status);
    }

    uint64_t SessionId = NextSessionId.fetch_add(1);
    {
        std::lock_guard<std::mutex> Guard(Client.Lock);
        Client.Sessions[SessionId] = { DeviceObjUcAddr, FileObjUcAddr };
    }

    Logger::Log("{GRN}BridgeServer: OPEN %ls -> session %llu{RESET}\n", Name.c_str(), SessionId);
    SendResponse(Pipe, CreateResult.Status, CreateResult.Information, SessionId, nullptr, 0);
}

void HandleIoctl(ClientState& Client, HANDLE Pipe, const Bridge::RequestHeader& Req, const uint8_t* Payload) {
    SessionInfo Sess;
    if (!LookupSession(Client, Req.Session, Sess)) {
        SendResponse(Pipe, kStatusInvalidHandle, 0, Req.Session, nullptr, 0);
        return;
    }

    std::vector<uint8_t> OutBuf(Req.OutLen);
    ULONG BytesReturned = 0;
    IoManager::DispatchResult Result;
    {
        std::lock_guard<std::mutex> DispatchGuard(IoManager::DispatchMutex);
        Result = IoManager::DispatchDeviceIoControl(
            Sess.DeviceObjUcAddr, Sess.FileObjUcAddr,
            Req.IoControlCode,
            const_cast<uint8_t*>(Payload), Req.InLen,
            OutBuf.empty() ? nullptr : OutBuf.data(), Req.OutLen,
            &BytesReturned,
            kBridgeRequestorMode);
    }

    uint32_t CopyLen = (BytesReturned < Req.OutLen) ? (uint32_t)BytesReturned : Req.OutLen;
    SendResponse(Pipe, Result.Status, Result.Information, Req.Session, OutBuf.data(), CopyLen);
}

// Offset is always 0: this bridge exposes sequential read/write, not a seekable
// file position. A driver that requires ByteOffset-based access needs the
// protocol extended with an explicit offset field.
void HandleRead(ClientState& Client, HANDLE Pipe, const Bridge::RequestHeader& Req) {
    SessionInfo Sess;
    if (!LookupSession(Client, Req.Session, Sess)) {
        SendResponse(Pipe, kStatusInvalidHandle, 0, Req.Session, nullptr, 0);
        return;
    }

    std::vector<uint8_t> OutBuf(Req.OutLen);
    ULONG BytesRead = 0;
    IoManager::DispatchResult Result;
    {
        std::lock_guard<std::mutex> DispatchGuard(IoManager::DispatchMutex);
        Result = IoManager::DispatchRead(
            Sess.DeviceObjUcAddr, Sess.FileObjUcAddr,
            OutBuf.empty() ? nullptr : OutBuf.data(), Req.OutLen,
            0, &BytesRead, kBridgeRequestorMode);
    }

    uint32_t CopyLen = (BytesRead < Req.OutLen) ? (uint32_t)BytesRead : Req.OutLen;
    SendResponse(Pipe, Result.Status, Result.Information, Req.Session, OutBuf.data(), CopyLen);
}

void HandleWrite(ClientState& Client, HANDLE Pipe, const Bridge::RequestHeader& Req, const uint8_t* Payload) {
    SessionInfo Sess;
    if (!LookupSession(Client, Req.Session, Sess)) {
        SendResponse(Pipe, kStatusInvalidHandle, 0, Req.Session, nullptr, 0);
        return;
    }

    ULONG BytesWritten = 0;
    IoManager::DispatchResult Result;
    {
        std::lock_guard<std::mutex> DispatchGuard(IoManager::DispatchMutex);
        Result = IoManager::DispatchWrite(
            Sess.DeviceObjUcAddr, Sess.FileObjUcAddr,
            const_cast<uint8_t*>(Payload), Req.InLen,
            0, &BytesWritten, kBridgeRequestorMode);
    }

    SendResponse(Pipe, Result.Status, Result.Information, Req.Session, nullptr, 0);
}

void HandleClose(ClientState& Client, HANDLE Pipe, const Bridge::RequestHeader& Req) {
    SessionInfo Sess;
    bool Found;
    {
        std::lock_guard<std::mutex> Guard(Client.Lock);
        auto It = Client.Sessions.find(Req.Session);
        Found = It != Client.Sessions.end();
        if (Found) {
            Sess = It->second;
            Client.Sessions.erase(It);
        }
    }
    if (!Found) {
        SendResponse(Pipe, kStatusInvalidHandle, 0, Req.Session, nullptr, 0);
        return;
    }

    IoManager::DispatchResult Result;
    {
        std::lock_guard<std::mutex> DispatchGuard(IoManager::DispatchMutex);
        IoManager::DispatchCleanup(Sess.DeviceObjUcAddr, Sess.FileObjUcAddr, kBridgeRequestorMode);
        Result = IoManager::DispatchClose(Sess.DeviceObjUcAddr, Sess.FileObjUcAddr, kBridgeRequestorMode);
        IoManager::FreeFileObject(Sess.FileObjUcAddr);
    }

    SendResponse(Pipe, Result.Status, Result.Information, Req.Session, nullptr, 0);
}

// Reads one full message off a message-mode pipe into Buf, growing up to MaxBytes.
// Returns false on disconnect/error, or if the message exceeds MaxBytes (in which
// case the rest of that oversized message is drained off the wire first so the
// pipe isn't left mid-message before the caller disconnects the client).
bool ReadMessage(HANDLE Pipe, std::vector<uint8_t>& Buf, size_t MaxBytes) {
    Buf.clear();
    uint8_t Chunk[8192];

    for (;;) {
        DWORD BytesRead = 0;
        BOOL Ok = ReadFile(Pipe, Chunk, sizeof(Chunk), &BytesRead, nullptr);
        if (!Ok && GetLastError() != ERROR_MORE_DATA)
            return false;

        if (Buf.size() + BytesRead > MaxBytes) {
            while (!Ok) {
                Ok = ReadFile(Pipe, Chunk, sizeof(Chunk), &BytesRead, nullptr);
                if (!Ok && GetLastError() != ERROR_MORE_DATA)
                    break;
            }
            return false;
        }

        Buf.insert(Buf.end(), Chunk, Chunk + BytesRead);
        if (Ok)
            break; // last read for this message had no ERROR_MORE_DATA
    }
    return true;
}

void ServeClient(HANDLE Pipe) {
    ClientState Client;
    std::vector<uint8_t> Buf;
    const size_t MaxMsg = sizeof(Bridge::RequestHeader) + Bridge::kMaxPayload;

    while (!StopRequested.load()) {
        if (!ReadMessage(Pipe, Buf, MaxMsg))
            break;
        if (Buf.size() < sizeof(Bridge::RequestHeader))
            break;

        Bridge::RequestHeader Req;
        memcpy(&Req, Buf.data(), sizeof(Req));

        if (Req.Magic != Bridge::kMagic || Req.Version != Bridge::kVersion) {
            SendResponse(Pipe, kStatusInvalidParameter, 0, Req.Session, nullptr, 0);
            continue;
        }
        if (Req.InLen > Bridge::kMaxPayload || Req.OutLen > Bridge::kMaxPayload ||
            (size_t)Req.InLen > Buf.size() - sizeof(Req)) {
            SendResponse(Pipe, kStatusInvalidParameter, 0, Req.Session, nullptr, 0);
            continue;
        }

        const uint8_t* Payload = Buf.data() + sizeof(Req);

        switch ((Bridge::Opcode)Req.Opcode) {
        case Bridge::Opcode::Enum:  HandleEnum(Pipe, Req); break;
        case Bridge::Opcode::Open:  HandleOpen(Client, Pipe, Req, Payload); break;
        case Bridge::Opcode::Ioctl: HandleIoctl(Client, Pipe, Req, Payload); break;
        case Bridge::Opcode::Read:  HandleRead(Client, Pipe, Req); break;
        case Bridge::Opcode::Write: HandleWrite(Client, Pipe, Req, Payload); break;
        case Bridge::Opcode::Close: HandleClose(Client, Pipe, Req); break;
        default:
            SendResponse(Pipe, kStatusNotSupported, 0, Req.Session, nullptr, 0);
            break;
        }
    }

    CloseAllSessions(Client);
    FlushFileBuffers(Pipe);
    DisconnectNamedPipe(Pipe);
}

// One thread per accepted connection, so a client that sits on its pipe does not lock
// every other client out. Guest work stays serialised regardless: every dispatch below
// still goes through IoManager::DispatchMutex.
struct Connection {
    HANDLE Pipe = INVALID_HANDLE_VALUE;
    std::atomic<bool> Finished{ false };
    std::thread Worker;
};

std::mutex ConnectionLock;
std::vector<std::unique_ptr<Connection>> Connections;

// Joins and closes connections whose worker has already returned. Called from the accept
// loop so a long-lived server does not accumulate dead threads.
void ReapFinishedConnections() {
    std::lock_guard<std::mutex> Guard(ConnectionLock);
    for (size_t I = 0; I < Connections.size();) {
        if (Connections[I]->Finished.load()) {
            if (Connections[I]->Worker.joinable())
                Connections[I]->Worker.join();
            CloseHandle(Connections[I]->Pipe);
            Connections.erase(Connections.begin() + I);
        } else {
            I++;
        }
    }
}

// Unblocks every client thread and waits for it. A worker parked in ReadFile does not
// see StopRequested on its own, so cancel its I/O and drop the connection first.
void StopAllConnections() {
    std::vector<std::unique_ptr<Connection>> ToStop;
    {
        std::lock_guard<std::mutex> Guard(ConnectionLock);
        ToStop.swap(Connections);
    }
    for (auto& Conn : ToStop) {
        CancelIoEx(Conn->Pipe, nullptr);
        DisconnectNamedPipe(Conn->Pipe);
        if (Conn->Worker.joinable())
            Conn->Worker.join();
        CloseHandle(Conn->Pipe);
    }
}

void ServerLoop() {
    Logger::Log("{CYN}BridgeServer: listening on %ls{RESET}\n", PipeName.c_str());

    while (!StopRequested.load()) {
        HANDLE Pipe = CreateNamedPipeW(
            PipeName.c_str(),
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            (DWORD)(sizeof(Bridge::ResponseHeader) + Bridge::kMaxPayload),
            (DWORD)(sizeof(Bridge::RequestHeader) + Bridge::kMaxPayload),
            0, nullptr);

        if (Pipe == INVALID_HANDLE_VALUE) {
            Logger::Log("{RED}BridgeServer: CreateNamedPipeW failed (%lu){RESET}\n", GetLastError());
            break;
        }

        BOOL Connected = ConnectNamedPipe(Pipe, nullptr) ? TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

        if (StopRequested.load()) {
            CloseHandle(Pipe);
            break;
        }
        if (!Connected) {
            CloseHandle(Pipe);
            continue;
        }

        ReapFinishedConnections();

        auto Conn = std::make_unique<Connection>();
        Conn->Pipe = Pipe;
        Connection* Raw = Conn.get();
        Conn->Worker = std::thread([Raw] {
            Logger::Log("{GRN}BridgeServer: client connected{RESET}\n");
            ServeClient(Raw->Pipe);
            Logger::Log("{GRY}BridgeServer: client disconnected{RESET}\n");
            Raw->Finished = true;
        });

        std::lock_guard<std::mutex> Guard(ConnectionLock);
        Connections.push_back(std::move(Conn));
    }

    StopAllConnections();
    Logger::Log("{CYN}BridgeServer: stopped{RESET}\n");
}

} // namespace

namespace BridgeServer {

bool Start(const std::string& Name) {
    if (Active.load())
        return false;

    std::string PipeNameA = std::string(Bridge::kPipePrefixA) + Name;
    PipeName.assign(PipeNameA.begin(), PipeNameA.end());
    StopRequested = false;
    Active = true;
    ServerThread = std::thread(ServerLoop);
    return true;
}

void Stop() {
    if (!Active.load())
        return;

    StopRequested = true;
    // ConnectNamedPipe blocks in the server thread; connecting a throwaway client
    // completes that wait so the loop can observe StopRequested and exit.
    HANDLE Dummy = CreateFileW(PipeName.c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Dummy != INVALID_HANDLE_VALUE)
        CloseHandle(Dummy);

    if (ServerThread.joinable())
        ServerThread.join();
    Active = false;
}

bool IsActive() {
    return Active.load();
}

} // namespace BridgeServer
