#include "se_token.h"
#include "core/memory/unicorn_memory.h"
#include "core/process/unicorn_threading.h"
#include <cstddef>

TOKEN_PRIVILEGES kernelToken[31] = { 0 };

namespace {
    constexpr ULONG kSeGroupIntegrity = 0x20;
    constexpr ULONG kSeGroupIntegrityEnabled = 0x40;

    uint64_t AllocateTokenInfo(size_t Size, const char* Name) {
        return UnicornMem::AllocateVariable(
            UnicornThread::GetCurrentEngine(), (Size + 0xF) & ~size_t(0xF), Name);
    }

    PSID WriteSid(uint8_t* HostBase, uint64_t GuestBase, size_t Offset,
        SID_IDENTIFIER_AUTHORITY Authority, ULONG Rid) {
        auto Sid = (SID*)(HostBase + Offset);
        memset(Sid, 0, sizeof(SID));
        Sid->Revision = SID_REVISION;
        Sid->SubAuthorityCount = 1;
        Sid->IdentifierAuthority = Authority;
        Sid->SubAuthority[0] = Rid;
        return (PSID)(GuestBase + Offset);
    }
}

NTSTATUS h_SeQueryInformationToken(PACCESS_TOKEN Token, TOKEN_INFORMATION_CLASS TokenInformationClass, PVOID* TokenInformation) {
    auto HostTokenInfo = UcPtr(TokenInformation);
    Logger::Log("{CYN}\tToken : %llx - Class : %d{RESET}\n", (const void*)Token, (int)TokenInformationClass);

    if (!HostTokenInfo)
        return STATUS_INVALID_PARAMETER;

    if (TokenInformationClass == TokenPrivileges) {
        static constexpr DWORD PrivilegeLuids[] = {
            2, 3, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 22, 23, 28, 29, 30, 31, 33, 35
        };
        constexpr ULONG PrivilegeCount = (ULONG)(sizeof(PrivilegeLuids) / sizeof(PrivilegeLuids[0]));
        const ULONG AllocSize = (ULONG)offsetof(TOKEN_PRIVILEGES, Privileges) +
            PrivilegeCount * (ULONG)sizeof(LUID_AND_ATTRIBUTES);
        uint64_t PrivBuf = AllocateTokenInfo(AllocSize, "TokenPrivileges");
        auto HostPriv = (TOKEN_PRIVILEGES*)UnicornMem::UcToHost(PrivBuf);
        memset(HostPriv, 0, AllocSize);
        HostPriv->PrivilegeCount = PrivilegeCount;
        for (ULONG Index = 0; Index < PrivilegeCount; ++Index) {
            HostPriv->Privileges[Index].Luid.LowPart = PrivilegeLuids[Index];
            HostPriv->Privileges[Index].Luid.HighPart = 0;
            HostPriv->Privileges[Index].Attributes =
                SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
        }
        *HostTokenInfo = (PVOID)PrivBuf;
        return STATUS_SUCCESS;
    } else if (TokenInformationClass == TokenUser) {
        const size_t SidOffset = (sizeof(TOKEN_USER) + 7) & ~size_t(7);
        const size_t AllocSize = SidOffset + sizeof(SID);
        uint64_t UserBuf = AllocateTokenInfo(AllocSize, "TokenUser");
        auto HostUser = (uint8_t*)UnicornMem::UcToHost(UserBuf);
        memset(HostUser, 0, AllocSize);
        auto User = (TOKEN_USER*)HostUser;
        SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
        User->User.Sid = WriteSid(HostUser, UserBuf, SidOffset, NtAuthority, SECURITY_LOCAL_SYSTEM_RID);
        User->User.Attributes = 0;
        *HostTokenInfo = (PVOID)UserBuf;
        return STATUS_SUCCESS;
    } else if (TokenInformationClass == TokenIntegrityLevel) {
        const size_t SidOffset = (sizeof(TOKEN_MANDATORY_LABEL) + 7) & ~size_t(7);
        const size_t AllocSize = SidOffset + sizeof(SID);
        uint64_t IntBuf = AllocateTokenInfo(AllocSize, "TokenIntegrityLevel");
        auto HostInt = (uint8_t*)UnicornMem::UcToHost(IntBuf);
        memset(HostInt, 0, AllocSize);
        auto Label = (TOKEN_MANDATORY_LABEL*)HostInt;
        SID_IDENTIFIER_AUTHORITY MandatoryAuthority = SECURITY_MANDATORY_LABEL_AUTHORITY;
        Label->Label.Sid = WriteSid(HostInt, IntBuf, SidOffset, MandatoryAuthority,
            SECURITY_MANDATORY_SYSTEM_RID);
        Label->Label.Attributes = kSeGroupIntegrity | kSeGroupIntegrityEnabled;
        *HostTokenInfo = (PVOID)IntBuf;
        return STATUS_SUCCESS;
    } else if (TokenInformationClass == TokenOrigin) {
        uint64_t OriginBuf = AllocateTokenInfo(sizeof(TOKEN_ORIGIN), "TokenOrigin");
        auto Origin = (TOKEN_ORIGIN*)UnicornMem::UcToHost(OriginBuf);
        memset(Origin, 0, sizeof(*Origin));
        Origin->OriginatingLogonSession.LowPart = 0x3e7;
        *HostTokenInfo = (PVOID)OriginBuf;
        return STATUS_SUCCESS;
    }

    *HostTokenInfo = nullptr;
    return STATUS_INVALID_INFO_CLASS;
}
