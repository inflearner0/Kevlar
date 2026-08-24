#include "host/providers/ntoskrnl_provider.h"
#include "host/providers/provider.h"

#include "api/ps/ps_process.h"
#include "api/ob/ob_object.h"
#include "api/ke/ke_event.h"
#include "api/ke/ke_timer.h"
#include "api/ke/ke_sync.h"
#include "api/ke/ke_misc.h"
#include "api/ex/ex_pool.h"
#include "api/ex/ex_sync.h"
#include "api/ex/ex_pushlock.h"
#include "api/ex/ex_misc.h"
#include "api/mm/mm_pool.h"
#include "api/mm/mm_mdl.h"
#include "api/mm/mm_virtual.h"
#include "api/io/io_device.h"
#include "api/nt/nt_query.h"
#include "api/nt/nt_file.h"
#include "api/nt/nt_registry.h"
#include "api/nt/nt_memory.h"
#include "api/rtl/rtl_string.h"
#include "api/rtl/rtl_misc.h"
#include "api/rtl/rtl_registry.h"
#include "api/ps/se_token.h"
#include "api/ob/cm_callback.h"
#include "core/debug/dbg_misc.h"
#include "core/debug/dbg_bugcheck.h"
#include "api/io/flt_filter.h"
#include "api/rtl/crt_string.h"
#include "api/cng/cng.h"
#include "core/debug/dbg_print.h"

// Bounded ACPI/PCI/IOMMU model: synthetic PCI config space + a guest-resident
// VT-d DMAR table describing one DRHD unit at 0xFED90000 (mapped in MmMapIoSpaceEx).
// ponytail: shaped from the general shape of IOMMU-oriented drivers, not from a
// captured FACEIT_IOMMU trace; re-validate against a real trace when one is available.
static uint64_t h_HalGetBusDataByOffset(uint64_t BusDataType, uint64_t BusNumber, uint64_t SlotNumber, PVOID Buffer, uint64_t Offset, uint64_t Length) {
    if (BusDataType != 5)   // PCIConfiguration
        return 0;

    auto HostBuffer = UcPtr(Buffer);
    if (!HostBuffer || Length == 0) return 0;

    uint8_t Config[256] = { 0 };
    uint8_t Device = (uint8_t)((SlotNumber >> 3) & 0x1F);
    uint8_t Function = (uint8_t)(SlotNumber & 0x7);

    if (Device == 0 && Function == 0) {
        // Intel host bridge (vendor 0x8086)
        Config[0x00] = 0x86; Config[0x01] = 0x80;        // VendorID
        Config[0x02] = 0x1F; Config[0x03] = 0x3E;        // DeviceID 0x3E1F
        Config[0x08] = 0x00; Config[0x09] = 0x00;        // Revision
        Config[0x0A] = 0x06; Config[0x0B] = 0x00;        // Class: Host Bridge
        Config[0x0E] = 0x00; Config[0x0F] = 0x00;        // HeaderType 0
    } else if (Device == 0 && Function == 2) {
        // Intel VT-d IOMMU (Raptor Lake 0x4612)
        Config[0x00] = 0x86; Config[0x01] = 0x80;        // VendorID
        Config[0x02] = 0x12; Config[0x03] = 0x46;        // DeviceID 0x4612
        Config[0x08] = 0x10; Config[0x09] = 0x00;        // Revision
        Config[0x0A] = 0x08; Config[0x0B] = 0x00;        // Class: System Peripheral
        Config[0x0E] = 0x00; Config[0x0F] = 0x00;        // HeaderType 0
    } else {
        return 0;   // no synthetic config for other device/function slots
    }

    if (Offset >= sizeof(Config)) return 0;
    size_t CopyLen = (size_t)Length;
    if (Offset + CopyLen > sizeof(Config))
        CopyLen = sizeof(Config) - (size_t)Offset;
    memcpy(HostBuffer, Config + Offset, CopyLen);
    return CopyLen;
}

// HalAcpiGetTableEx is undocumented, but the Windows implementation uses this
// four-argument contract:
//   PVOID HalAcpiGetTableEx(PVOID Context, ULONG Signature,
//                           const char* OemId, const char* OemTableId);
// It returns an ACPI table pointer (or NULL), not an NTSTATUS and out parameters.
#pragma pack(push, 1)
struct KvlAcpiHeader {
    uint32_t Signature;
    uint32_t Length;
    uint8_t Revision;
    uint8_t Checksum;
    uint8_t OemId[6];
    uint8_t OemTableId[8];
    uint32_t OemRevision;
    uint32_t CreatorId;
    uint32_t CreatorRevision;
};

struct KvlDmarTable {
    KvlAcpiHeader Header;
    uint8_t HostAddressWidth;
    uint8_t Flags;
    uint8_t Reserved[10];
};

struct KvlDmarDrhd {
    uint16_t Type;
    uint16_t Length;
    uint8_t Flags;
    uint8_t Reserved;
    uint16_t SegmentNumber;
    uint64_t RegisterBaseAddress;
};

struct KvlMadtTable {
    KvlAcpiHeader Header;
    uint32_t LocalApicAddress;
    uint32_t Flags;
};
#pragma pack(pop)

static void KvlFinalizeAcpiChecksum(uint8_t* Table, size_t Size) {
    auto* Header = (KvlAcpiHeader*)Table;
    Header->Checksum = 0;
    uint8_t Sum = 0;
    for (size_t I = 0; I < Size; I++) Sum = (uint8_t)(Sum + Table[I]);
    Header->Checksum = (uint8_t)(0u - Sum);
}

static uint64_t KvlCopyAcpiTableToGuest(const uint8_t* Table, size_t Size, const char* Name) {
    if (!Table || Size < sizeof(KvlAcpiHeader) || Size > 0x100000)
        return 0;

    uint64_t TableUcAddr = UnicornMem::AllocateVariable(
        UnicornThread::GetCurrentEngine(), Size, Name);
    void* HostTable = UnicornMem::UcToHost(TableUcAddr);
    if (!TableUcAddr || !HostTable)
        return 0;

    memcpy(HostTable, Table, Size);
    return TableUcAddr;
}

static bool KvlAcpiTableMatchesFilters(
    const KvlAcpiHeader* Header, uint64_t OemId, uint64_t OemTableId) {
    if (OemId) {
        auto HostOemId = (const uint8_t*)UnicornMem::UcToHost(OemId);
        if (!HostOemId || memcmp(Header->OemId, HostOemId, sizeof(Header->OemId)) != 0)
            return false;
    }
    if (OemTableId) {
        auto HostOemTableId = (const uint8_t*)UnicornMem::UcToHost(OemTableId);
        if (!HostOemTableId || memcmp(Header->OemTableId, HostOemTableId, sizeof(Header->OemTableId)) != 0)
            return false;
    }
    return true;
}

static uint64_t h_HalAcpiGetTableEx(
    uint64_t Context, uint64_t Signature, uint64_t OemId, uint64_t OemTableId) {
    uint32_t Sig = (uint32_t)Signature;
    char SigText[5] = {
        (char)(Sig & 0xFF), (char)((Sig >> 8) & 0xFF),
        (char)((Sig >> 16) & 0xFF), (char)((Sig >> 24) & 0xFF), 0
    };
    Logger::Log(
        "{GRY}\tHalAcpiGetTableEx: context=0x%llx sig=0x%08x (%s) oemId=0x%llx oemTableId=0x%llx{RESET}\n",
        Context, Sig, SigText, OemId, OemTableId);

    // Prefer the host's real ACPI table. This gives the guest the same table a
    // native driver on this machine would receive.
    constexpr uint32_t AcpiProvider = 0x41435049; // 'ACPI'
    UINT HostSize = GetSystemFirmwareTable(AcpiProvider, Sig, nullptr, 0);
    if (HostSize >= sizeof(KvlAcpiHeader) && HostSize <= 0x100000) {
        std::vector<uint8_t> HostTable(HostSize);
        UINT Written = GetSystemFirmwareTable(AcpiProvider, Sig, HostTable.data(), HostSize);
        if (Written == HostSize) {
            auto* Header = (const KvlAcpiHeader*)HostTable.data();
            if (Header->Signature == Sig &&
                Header->Length >= sizeof(KvlAcpiHeader) &&
                Header->Length <= HostSize &&
                KvlAcpiTableMatchesFilters(Header, OemId, OemTableId)) {
                uint64_t Result = KvlCopyAcpiTableToGuest(
                    HostTable.data(), Header->Length, SigText);
                Logger::Log("{GRY}\tHalAcpiGetTableEx: host table -> 0x%llx (%u bytes){RESET}\n",
                    Result, Header->Length);
                return Result;
            }
        }
    }

    if (Sig == 0x52414D44) { // 'DMAR'
        // The emulated PCI model advertises Intel VT-d, so provide a coherent
        // DMAR table even when the host itself uses a different IOMMU format.
        uint8_t Bytes[sizeof(KvlDmarTable) + sizeof(KvlDmarDrhd)] = {};
        auto* Table = (KvlDmarTable*)Bytes;
        Table->Header.Signature = Sig;
        Table->Header.Length = sizeof(Bytes);
        Table->Header.Revision = 1;
        memcpy(Table->Header.OemId, "KEVLAR", 6);
        memcpy(Table->Header.OemTableId, "KVLRIOMM", 8);
        Table->Header.OemRevision = 1;
        Table->Header.CreatorId = 0x524C564B; // 'KVLR'
        Table->Header.CreatorRevision = 1;
        Table->HostAddressWidth = 0x2F; // 48-bit physical addresses, encoded as N-1

        auto* Drhd = (KvlDmarDrhd*)(Bytes + sizeof(KvlDmarTable));
        Drhd->Type = 0;
        Drhd->Length = sizeof(KvlDmarDrhd);
        Drhd->Flags = 1; // INCLUDE_PCI_ALL
        Drhd->SegmentNumber = 0;
        Drhd->RegisterBaseAddress = 0xFED90000;
        KvlFinalizeAcpiChecksum(Bytes, sizeof(Bytes));

        if (!KvlAcpiTableMatchesFilters(&Table->Header, OemId, OemTableId))
            return 0;
        uint64_t Result = KvlCopyAcpiTableToGuest(Bytes, sizeof(Bytes), "DMAR");
        Logger::Log("{GRY}\tHalAcpiGetTableEx: synthetic DMAR -> 0x%llx (%zu bytes){RESET}\n",
            Result, sizeof(Bytes));
        return Result;
    }

    if (Sig == 0x43495041) { // 'APIC'; fallback for hosts that deny firmware access
        KvlMadtTable Table = {};
        Table.Header.Signature = Sig;
        Table.Header.Length = sizeof(Table);
        Table.Header.Revision = 5;
        memcpy(Table.Header.OemId, "KEVLAR", 6);
        memcpy(Table.Header.OemTableId, "KVLRAPIC", 8);
        Table.Header.OemRevision = 1;
        Table.Header.CreatorId = 0x524C564B;
        Table.Header.CreatorRevision = 1;
        Table.LocalApicAddress = 0xFEE00000;
        Table.Flags = 1; // dual 8259 PICs are present
        KvlFinalizeAcpiChecksum((uint8_t*)&Table, sizeof(Table));

        if (!KvlAcpiTableMatchesFilters(&Table.Header, OemId, OemTableId))
            return 0;
        uint64_t Result = KvlCopyAcpiTableToGuest((const uint8_t*)&Table, sizeof(Table), "APIC");
        Logger::Log("{GRY}\tHalAcpiGetTableEx: synthetic APIC -> 0x%llx (%zu bytes){RESET}\n",
            Result, sizeof(Table));
        return Result;
    }

    // WAET and unknown/absent tables correctly return NULL. Returning an
    // NTSTATUS here is what previously made the guest dereference C0000225.
    Logger::Log("{GRY}\tHalAcpiGetTableEx: table absent -> NULL{RESET}\n");
    return 0;
}

static uint64_t h_DbgSetDebugPrintCallback(uint64_t Callback, uint64_t Enable) {
    Logger::Log("{GRY}\tDbgSetDebugPrintCallback: callback=0x%llx enable=%llu{RESET}\n", Callback, Enable);
    return 0;
}

static uint64_t h_FsRtlNumberOfRunsInBaseMcb(uint64_t Mcb) {
    return 0;
}

static void h_RtlGetDefaultCodePage(PUSHORT AnsiCodePage, PUSHORT OemCodePage) {
    auto HostAnsi = UcPtr(AnsiCodePage);
    auto HostOem = UcPtr(OemCodePage);
    if (HostAnsi) *HostAnsi = 1252;
    if (HostOem) *HostOem = 437;
}

static uint64_t h_PsReferenceProcessFilePointer(uint64_t Process, uint64_t OutFilePointer) {
    auto HostOut = UcPtr((PVOID*)OutFilePointer);
    if (HostOut) {
        uint64_t FakeFileObj = UnicornMem::AllocateVariable(
            UnicornThread::GetCurrentEngine(), 0x100, "FakeFileObject");
        auto HostFile = (uint8_t*)UnicornMem::UcToHost(FakeFileObj);
        if (HostFile) {
            memset(HostFile, 0, 0x100);
            *(uint16_t*)(HostFile + 0) = 5;
            *(uint16_t*)(HostFile + 2) = 0xD8;
        }
        *HostOut = (PVOID)FakeFileObj;
    }
    return 0;
}

static uint64_t h_ObGetObjectType(uint64_t Object) {
    return (uint64_t)PsProcessType;
}

void ntoskrnl_provider::Initialize() {
    Provider::AddFuncImpl("ExAcquireSpinLockShared", h_ExAcquireSpinLockShared);
    Provider::AddFuncImpl("ExReleaseSpinLockShared", h_ExReleaseSpinLockShared);
    Provider::AddFuncImpl("ExAcquireSpinLockExclusive", h_ExAcquireSpinLockExclusive);
    Provider::AddFuncImpl("ExReleaseSpinLockExclusive", h_ExReleaseSpinLockExclusive);
    Provider::AddFuncImpl("MmMapIoSpaceEx", k_MmMapIoSpaceEx);
    Provider::AddFuncImpl("MmCopyMemory", h_MmCopyMemory);
    Provider::AddFuncImpl("IoGetDeviceInterfaces", h_IoGetDeviceInterfaces);
    Provider::AddFuncImpl("ZwDeviceIoControlFile", h_ZwDeviceIoControlFile);
    Provider::AddFuncImpl("NtDeviceIoControlFile", h_ZwDeviceIoControlFile);
    Provider::AddFuncImpl("ExGetFirmwareEnvironmentVariable", h_ExGetFirmwareEnvironmentVariable);
    Provider::AddFuncImpl("ExGetFirmwareType", h_ExGetFirmwareType);
    Provider::AddFuncImpl("KeReadStateTimer", h_KeReadStateTimer);
    Provider::AddFuncImpl("KeClearEvent", h_KeClearEvent);
    Provider::AddFuncImpl("KeWaitForMutexObject", h_KeWaitForMutextObject);
    Provider::AddFuncImpl("ExRegisterCallback", h_ExRegisterCallback);
    Provider::AddFuncImpl("KeWaitForMultipleObjects", h_KeWaitForMultipleObjects);
    Provider::AddFuncImpl("KeInitializeGuardedMutex", h_KeInitializeGuardedMutex);
    Provider::AddFuncImpl("IoAllocateMdl", h_IoAllocateMdl);
    Provider::AddFuncImpl("MmAllocateContiguousMemorySpecifyCache", h_MmAllocateContiguousMemorySpecifyCache);
    Provider::AddFuncImpl("MmGetPhysicalMemoryRanges", h_MmGetPhysicalMemoryRanges);
    Provider::AddFuncImpl("MmGetPhysicalAddress", h_MmGetPhysicalAddress);
    Provider::AddFuncImpl("_vsnwprintf", h__vsnwprintf);
    Provider::AddFuncImpl("_vsnprintf", h__vsnprintf);
    Provider::AddFuncImpl("ZwOpenSection", h_ZwOpenSection);
    Provider::AddFuncImpl("MmGetSystemRoutineAddress", h_MmGetSystemRoutineAddress);
    Provider::AddFuncImpl("IoDeleteSymbolicLink", h_IoDeleteSymbolicLink);
    Provider::AddFuncImpl("PsRemoveLoadImageNotifyRoutine", h_PsRemoveLoadImageNotifyRoutine);
    Provider::AddFuncImpl("PsSetCreateProcessNotifyRoutineEx", h_PsSetCreateProcessNotifyRoutineEx);
    Provider::AddFuncImpl("PsSetCreateProcessNotifyRoutine", h_PsSetCreateProcessNotifyRoutineEx);
    Provider::AddFuncImpl("KeAcquireSpinLockRaiseToDpc", h_KeAcquireSpinLockRaiseToDpc);
    Provider::AddFuncImpl("PsRemoveCreateThreadNotifyRoutine", h_PsRemoveLoadImageNotifyRoutine);
    Provider::AddFuncImpl("KeReleaseSpinLock", h_KeReleaseSpinLock);
    Provider::AddFuncImpl("ExpInterlockedPopEntrySList", h_ExpInterlockedPopEntrySList);
    Provider::AddFuncImpl("KeDelayExecutionThread", h_KeDelayExecutionThread);
    Provider::AddFuncImpl("ExWaitForRundownProtectionRelease", h_ExWaitForRundownProtectionRelease);
    Provider::AddFuncImpl("KeCancelTimer", h_KeCancelTimer);
    Provider::AddFuncImpl("KeSetEvent", h_KeSetEvent);
    Provider::AddFuncImpl("KeSetTimer", h_KeSetTimer);
    Provider::AddFuncImpl("ExCreateCallback", h_ExCreateCallback);
    Provider::AddFuncImpl("IoCreateFileEx", h_IoCreateFileEx);
    Provider::AddFuncImpl("RtlDuplicateUnicodeString", h_RtlDuplicateUnicodeString);
    Provider::AddFuncImpl("IoDeleteController", h_IoDeleteController);
    Provider::AddFuncImpl("SeQueryInformationToken", h_SeQueryInformationToken);
    Provider::AddFuncImpl("PsReferencePrimaryToken", h_PsReferencePrimaryToken);
    Provider::AddFuncImpl("PsIsProtectedProcess", h_PsIsProtectedProcess);
    Provider::AddFuncImpl("NtQueryInformationProcess", h_NtQueryInformationProcess);
    Provider::AddFuncImpl("PsGetCurrentThreadProcessId", h_PsGetCurrentThreadProcessId);
    Provider::AddFuncImpl("IoGetCurrentThreadProcessId", h_PsGetCurrentThreadProcessId);
    Provider::AddFuncImpl("PsGetCurrentThreadId", h_PsGetCurrentThreadId);
    Provider::AddFuncImpl("IoGetCurrentThreadId", h_PsGetCurrentThreadId);
    Provider::AddFuncImpl("PsGetCurrentProcess", h_PsGetCurrentProcess);
    Provider::AddFuncImpl("IoGetCurrentProcess", h_PsGetCurrentProcess);
    Provider::AddFuncImpl("PsGetProcessId", h_PsGetProcessId);
    Provider::AddFuncImpl("PsGetProcessWow64Process", h_PsGetProcessWow64Process);
    Provider::AddFuncImpl("PsLookupProcessByProcessId", h_PsLookupProcessByProcessId);
    Provider::AddFuncImpl("RtlCompareString", h_RtlCompareString);
    Provider::AddFuncImpl("PsGetProcessCreateTimeQuadPart", h_PsGetProcessCreateTimeQuadPart);
    Provider::AddFuncImpl("ObfReferenceObject", h_ObfReferenceObject);
    Provider::AddFuncImpl("ObReferenceObject", h_ObfReferenceObject);
    Provider::AddFuncImpl("ExAcquireFastMutex", h_ExAcquireFastMutex);
    Provider::AddFuncImpl("ExReleaseFastMutex", h_ExReleaseFastMutex);
    Provider::AddFuncImpl("ZwQueryFullAttributesFile", h_ZwQueryFullAttributesFile);
    Provider::AddFuncImpl("NtQueryFullAttributesFile", h_ZwQueryFullAttributesFile);
    Provider::AddFuncImpl("RtlWriteRegistryValue", h_RtlWriteRegistryValue);
    Provider::AddFuncImpl("RtlInitUnicodeString", h_RtlInitUnicodeString);
    Provider::AddFuncImpl("ZwOpenKey", h_ZwOpenKey);
    Provider::AddFuncImpl("NtOpenKey", h_ZwOpenKey);
    Provider::AddFuncImpl("ZwFlushKey", h_ZwFlushKey);
    Provider::AddFuncImpl("NtFlushKey", h_ZwFlushKey);
    Provider::AddFuncImpl("ZwClose", h_ZwClose);
    Provider::AddFuncImpl("NtClose", h_ZwClose);
    Provider::AddFuncImpl("ZwQueryDirectoryFile", h_NtQueryDirectoryFile);
    Provider::AddFuncImpl("NtQueryDirectoryFile", h_NtQueryDirectoryFile);
    Provider::AddFuncImpl("ZwOpenDirectoryObject", h_NtOpenDirectoryObject);
    Provider::AddFuncImpl("NtOpenDirectoryObject", h_NtOpenDirectoryObject);
    Provider::AddFuncImpl("ZwQuerySystemInformation", h_NtQuerySystemInformation);
    Provider::AddFuncImpl("NtQuerySystemInformation", h_NtQuerySystemInformation);
    Provider::AddFuncImpl("ExAllocatePoolWithTag", hM_AllocPoolTag);
    Provider::AddFuncImpl("ExAllocatePool", hM_AllocPool);
    Provider::AddFuncImpl("ExFreePoolWithTag", h_DeAllocPoolTag);
    Provider::AddFuncImpl("ExFreePool", h_DeAllocPool);
    Provider::AddFuncImpl("RtlRandomEx", h_RtlRandomEx);
    Provider::AddFuncImpl("IoCreateDevice", h_IoCreateDevice);
    Provider::AddFuncImpl("IoCreateDeviceSecure", h_IoCreateDeviceSecure);
    Provider::AddFuncImpl("IoValidateDeviceIoControlAccess", h_IoValidateDeviceIoControlAccess);
    Provider::AddFuncImpl("IoIsSystemThread", h_IoIsSystemThread);
    Provider::AddFuncImpl("KeInitializeEvent", h_KeInitializeEvent);
    Provider::AddFuncImpl("RtlGetVersion", h_RtlGetVersion);
    Provider::AddFuncImpl("DbgPrintEx", h_DbgPrintEx);
    Provider::AddFuncImpl("DbgPrint", h_DbgPrint);
    Provider::AddFuncImpl("__C_specific_handler", _c_exception);
    Provider::AddFuncImpl("RtlMultiByteToUnicodeN", h_RtlMultiByteToUnicodeN);
    Provider::AddFuncImpl("KeAreAllApcsDisabled", h_KeAreAllApcsDisabled);
    Provider::AddFuncImpl("KeAreApcsDisabled", h_KeAreApcsDisabled);
    Provider::AddFuncImpl("ZwCreateFile", h_NtCreateFile);
    Provider::AddFuncImpl("NtCreateFile", h_NtCreateFile);
    Provider::AddFuncImpl("ZwQueryInformationFile", h_NtQueryInformationFile);
    Provider::AddFuncImpl("NtQueryInformationFile", h_NtQueryInformationFile);
    Provider::AddFuncImpl("ZwReadFile", h_NtReadFile);
    Provider::AddFuncImpl("NtReadFile", h_NtReadFile);
    Provider::AddFuncImpl("ZwWriteFile", h_NtWriteFile);
    Provider::AddFuncImpl("NtWriteFile", h_NtWriteFile);
    Provider::AddFuncImpl("ZwFlushBuffersFile", h_ZwFlushBuffersFile);
    Provider::AddFuncImpl("NtFlushBuffersFile", h_ZwFlushBuffersFile);
    Provider::AddFuncImpl("ZwQueryValueKey", h_ZwQueryValueKey);
    Provider::AddFuncImpl("NtQueryValueKey", h_ZwQueryValueKey);
    Provider::AddFuncImpl("ZwQueryKey", h_ZwQueryKey);
    Provider::AddFuncImpl("NtQueryKey", h_ZwQueryKey);
    Provider::AddFuncImpl("IoWMIOpenBlock", h_IoWMIOpenBlock);
    Provider::AddFuncImpl("IoWMIQueryAllData", h_IoWMIQueryAllData);
    Provider::AddFuncImpl("ObfDereferenceObject", h_ObfDereferenceObject);
    Provider::AddFuncImpl("ObDereferenceObject", h_ObfDereferenceObject);
    Provider::AddFuncImpl("PsLookupThreadByThreadId", h_PsLookupThreadByThreadId);
    Provider::AddFuncImpl("RtlDuplicateUnicodeString", h_RtlDuplicateUnicodeString);
    Provider::AddFuncImpl("ExSystemTimeToLocalTime", h_ExSystemTimeToLocalTime);
    Provider::AddFuncImpl("ProbeForRead", h_ProbeForRead);
    Provider::AddFuncImpl("ProbeForWrite", h_ProbeForWrite);
    Provider::AddFuncImpl("RtlTimeToTimeFields", h_RtlTimeToTimeFields);
    Provider::AddFuncImpl("RtlTimeFieldsToTime", h_RtlTimeFieldsToTime);
    Provider::AddFuncImpl("KeInitializeMutex", h_KeInitializeMutex);
    Provider::AddFuncImpl("RtlInitAnsiString", h_RtlInitAnsiString);
    Provider::AddFuncImpl("RtlFreeAnsiString", h_RtlFreeAnsiString);
    Provider::AddFuncImpl("KeReleaseMutex", h_KeReleaseMutex);
    Provider::AddFuncImpl("KeWaitForSingleObject", h_KeWaitForSingleObject);
    Provider::AddFuncImpl("PsCreateSystemThread", h_PsCreateSystemThread);
    Provider::AddFuncImpl("PsTerminateSystemThread", h_PsTerminateSystemThread);
    Provider::AddFuncImpl("IofCompleteRequest", h_IofCompleteRequest);
    Provider::AddFuncImpl("IoCreateSymbolicLink", h_IoCreateSymbolicLink);
    Provider::AddFuncImpl("IoDeleteDevice", h_IoDeleteDevice);
    Provider::AddFuncImpl("IoGetTopLevelIrp", h_IoGetTopLevelIrp);
    Provider::AddFuncImpl("ObReferenceObjectByHandle", h_ObReferenceObjectByHandle);
    Provider::AddFuncImpl("ObRegisterCallbacks", h_ObRegisterCallbacks);
    Provider::AddFuncImpl("ObUnRegisterCallbacks", h_ObUnRegisterCallbacks);
    Provider::AddFuncImpl("ObGetFilterVersion", h_ObGetFilterVersion); // undoc func
    Provider::AddFuncImpl("MmIsAddressValid", h_MmIsAddressValid);
    Provider::AddFuncImpl("PsSetCreateThreadNotifyRoutine", h_PsSetCreateThreadNotifyRoutine);
    Provider::AddFuncImpl("PsSetLoadImageNotifyRoutine", h_PsSetLoadImageNotifyRoutine);
    Provider::AddFuncImpl("PsGetCurrentProcessId", h_PsGetCurrentThreadProcessId);
    Provider::AddFuncImpl("PsGetThreadId", h_PsGetThreadId);
    Provider::AddFuncImpl("PsGetThreadProcessId", h_PsGetThreadProcessId);
    Provider::AddFuncImpl("PsGetThreadProcess", h_PsGetThreadProcess);
    Provider::AddFuncImpl("PsAcquireProcessExitSynchronization", h_PsAcquireProcessExitSynchronization);
    Provider::AddFuncImpl("PsReleaseProcessExitSynchronization", h_PsReleaseProcessExitSynchronization);
    Provider::AddFuncImpl("IoQueryFileDosDeviceName", h_IoQueryFileDosDeviceName);
    Provider::AddFuncImpl("ObOpenObjectByPointer", h_ObOpenObjectByPointer);
    Provider::AddFuncImpl("ObQueryNameString", h_ObQueryNameString);
    Provider::AddFuncImpl("PsGetProcessInheritedFromUniqueProcessId", h_PsGetProcessInheritedFromUniqueProcessId);
    Provider::AddFuncImpl("PsGetProcessPeb", h_PsGetProcessPeb);
    Provider::AddFuncImpl("KeQueryTimeIncrement", h_KeQueryTimeIncrement);
    Provider::AddFuncImpl("ExAcquireResourceExclusiveLite", h_ExAcquireResourceExclusiveLite);
    Provider::AddFuncImpl("vswprintf_s", h_vswprintf_s);
    Provider::AddFuncImpl("swprintf_s", h_swprintf_s);
    Provider::AddFuncImpl("wcscpy_s", h_wcscpy_s);
    Provider::AddFuncImpl("wcscat_s", h_wcscat_s);
    Provider::AddFuncImpl("KeIpiGenericCall", h_KeIpiGenericCall);
    Provider::AddFuncImpl("KeInitializeTimer", h_KeInitializeTimer);
    Provider::AddFuncImpl("DbgPrompt", h_DbgPrompt);
    Provider::AddFuncImpl("FsRtlNumberOfRunsInBaseMcb", h_FsRtlNumberOfRunsInBaseMcb);
    Provider::AddFuncImpl("RtlGetDefaultCodePage", h_RtlGetDefaultCodePage);
    Provider::AddFuncImpl("PsReferenceProcessFilePointer", h_PsReferenceProcessFilePointer);
    Provider::AddFuncImpl("ObGetObjectType", h_ObGetObjectType);
    Provider::AddFuncImpl("KdChangeOption", h_KdChangeOption);
    Provider::AddFuncImpl("KdSystemDebugControl", h_KdSystemDebugControl);

    Provider::AddFuncImpl("BCryptOpenAlgorithmProvider", h_BCryptOpenAlgorithmProvider);
    Provider::AddFuncImpl("BCryptCloseAlgorithmProvider", h_BCryptCloseAlgorithmProvider);
    Provider::AddFuncImpl("BCryptCreateHash", h_BCryptCreateHash);
    Provider::AddFuncImpl("BCryptHashData", h_BCryptHashData);
    Provider::AddFuncImpl("BCryptFinishHash", h_BCryptFinishHash);
    Provider::AddFuncImpl("BCryptDestroyHash", h_BCryptDestroyHash);
    Provider::AddFuncImpl("BCryptGetProperty", h_BCryptGetProperty);
    Provider::AddFuncImpl("BCryptSetProperty", h_BCryptSetProperty);
    Provider::AddFuncImpl("BCryptGenRandom", h_BCryptGenRandom);
    Provider::AddFuncImpl("BCryptGenerateSymmetricKey", h_BCryptGenerateSymmetricKey);
    Provider::AddFuncImpl("BCryptEncrypt", h_BCryptEncrypt);
    Provider::AddFuncImpl("BCryptDecrypt", h_BCryptDecrypt);
    Provider::AddFuncImpl("BCryptImportKeyPair", h_BCryptImportKeyPair);
    Provider::AddFuncImpl("BCryptExportKey", h_BCryptExportKey);
    Provider::AddFuncImpl("BCryptVerifySignature", h_BCryptVerifySignature);
    Provider::AddFuncImpl("BCryptSignHash", h_BCryptSignHash);
    Provider::AddFuncImpl("BCryptDeriveKeyPBKDF2", h_BCryptDeriveKeyPBKDF2);
    Provider::AddFuncImpl("BCryptDestroyKey", h_BCryptDestroyKey);
    Provider::AddFuncImpl("BCryptDuplicateHash", h_BCryptDuplicateHash);
    Provider::AddFuncImpl("BCryptHash", h_BCryptHash);
    Logger::Log("{GRN}BCrypt passthrough: registered 20 functions{RESET}\n");

    Provider::AddFuncImpl("FltRegisterFilter", h_FltRegisterFilter);
    Provider::AddFuncImpl("FltStartFiltering", h_FltStartFiltering);
    Provider::AddFuncImpl("FltUnregisterFilter", h_FltUnregisterFilter);
    Provider::AddFuncImpl("FltObjectDereference", h_FltObjectDereference);
    Provider::AddFuncImpl("FltGetFilterInformation", h_FltGetFilterInformation);
    Provider::AddFuncImpl("FltGetRoutineAddress", h_FltGetRoutineAddress);
    Provider::AddFuncImpl("FltSetCallbackDataDirty", h_FltSetCallbackDataDirty);
    Provider::AddFuncImpl("FltGetDiskDeviceObject", h_FltGetDiskDeviceObject);
    Provider::AddFuncImpl("FltGetVolumeFromInstance", h_FltGetVolumeFromInstance);
    Provider::AddFuncImpl("FltAllocateCallbackData", h_FltAllocateCallbackData);
    Provider::AddFuncImpl("FltFreeCallbackData", h_FltFreeCallbackData);
    Provider::AddFuncImpl("FltPerformSynchronousIo", h_FltPerformSynchronousIo);
    Provider::AddFuncImpl("FltCancellableWaitForSingleObject", h_FltCancellableWaitForSingleObject);
    Provider::AddFuncImpl("FltCancellableWaitForMultipleObjects", h_FltCancellableWaitForMultipleObjects);
    Provider::AddFuncImpl("FltClose", h_FltClose);
    Provider::AddFuncImpl("FltCreateFile", h_FltCreateFile);
    Provider::AddFuncImpl("FltGetVolumeProperties", h_FltGetVolumeProperties);

    Provider::AddFuncImpl("KeEnterCriticalRegion", h_KeEnterCriticalRegion);
    Provider::AddFuncImpl("KeLeaveCriticalRegion", h_KeLeaveCriticalRegion);
    Provider::AddFuncImpl("KeEnterGuardedRegion", h_KeEnterGuardedRegion);
    Provider::AddFuncImpl("KeLeaveGuardedRegion", h_KeLeaveGuardedRegion);
    Provider::AddFuncImpl("KeGetCurrentIrql", h_KeGetCurrentIrql);
    Provider::AddFuncImpl("KeRaiseIrqlToDpcLevel", h_KeRaiseIrqlToDpcLevel);
    Provider::AddFuncImpl("KeBugCheckEx", h_KeBugCheckEx);
    Provider::AddFuncImpl("KeBugCheck", h_KeBugCheck);
    Provider::AddFuncImpl("__security_check_cookie", h___security_check_cookie);
    Provider::AddFuncImpl("__report_gsbufferoverrun", h___report_gsbufferoverrun);
    Provider::AddFuncImpl("KeRegisterBugCheckReasonCallback", h_KeRegisterBugCheckReasonCallback);
    Provider::AddFuncImpl("KeDeregisterBugCheckReasonCallback", h_KeDeregisterBugCheckReasonCallback);
    Provider::AddFuncImpl("KfRaiseIrql", h_KfRaiseIrql);
    Provider::AddFuncImpl("KeRaiseIrql", h_KeRaiseIrql);
    Provider::AddFuncImpl("KeLowerIrql", h_KeLowerIrql);
    Provider::AddFuncImpl("KfLowerIrql", h_KfLowerIrql);
    Provider::AddFuncImpl("ExAllocatePool2", h_ExAllocatePool2);
    Provider::AddFuncImpl("ExAllocatePool3", h_ExAllocatePool3);
    Provider::AddFuncImpl("KeQueryPerformanceCounter", h_KeQueryPerformanceCounter);
    Provider::AddFuncImpl("RtlLookupFunctionEntry", h_RtlLookupFunctionEntry);
    Provider::AddFuncImpl("RtlVirtualUnwind", h_RtlVirtualUnwind);
    Provider::AddFuncImpl("RtlCaptureContext", h_RtlCaptureContext);
    Provider::AddFuncImpl("CmRegisterCallbackEx", h_CmRegisterCallbackEx);
    Provider::AddFuncImpl("CmUnRegisterCallback", h_CmUnRegisterCallback);
    Provider::AddFuncImpl("CmRegisterCallback", h_CmRegisterCallback);
    Provider::AddFuncImpl("RtlCopyUnicodeString", h_RtlCopyUnicodeString);
    Provider::AddFuncImpl("RtlEqualUnicodeString", h_RtlEqualUnicodeString);
    Provider::AddFuncImpl("RtlCompareUnicodeString", h_RtlCompareUnicodeString);
    Provider::AddFuncImpl("RtlFreeUnicodeString", h_RtlFreeUnicodeString);
    Provider::AddFuncImpl("RtlAnsiStringToUnicodeString", h_RtlAnsiStringToUnicodeString);
    Provider::AddFuncImpl("RtlUnicodeStringToAnsiString", h_RtlUnicodeStringToAnsiString);
    Provider::AddFuncImpl("ZwOpenFile", h_ZwOpenFile);
    Provider::AddFuncImpl("NtOpenFile", h_ZwOpenFile);
    Provider::AddFuncImpl("ZwSetInformationFile", h_ZwSetInformationFile);
    Provider::AddFuncImpl("NtSetInformationFile", h_ZwSetInformationFile);
    Provider::AddFuncImpl("PsGetProcessImageFileName", h_PsGetProcessImageFileName);
    Provider::AddFuncImpl("PsIsSystemThread", h_PsIsSystemThread);
    Provider::AddFuncImpl("KeInitializeSpinLock", h_KeInitializeSpinLock);
    Provider::AddFuncImpl("ExAcquireResourceSharedLite", h_ExAcquireResourceSharedLite);
    Provider::AddFuncImpl("ExReleaseResourceLite", h_ExReleaseResourceLite);
    Provider::AddFuncImpl("ExInitializeResourceLite", h_ExInitializeResourceLite);
    Provider::AddFuncImpl("ExDeleteResourceLite", h_ExDeleteResourceLite);
    Provider::AddFuncImpl("IoFreeMdl", h_IoFreeMdl);
    Provider::AddFuncImpl("MmProbeAndLockPages", h_MmProbeAndLockPages);
    Provider::AddFuncImpl("MmUnlockPages", h_MmUnlockPages);
    Provider::AddFuncImpl("MmBuildMdlForNonPagedPool", h_MmBuildMdlForNonPagedPool);
    Provider::AddFuncImpl("RtlImageNtHeader", h_RtlImageNtHeader);
    Provider::AddFuncImpl("IoCreateNotificationEvent", h_IoCreateNotificationEvent);
    Provider::AddFuncImpl("KeInitializeDpc", h_KeInitializeDpc);
    Provider::AddFuncImpl("KeInsertQueueDpc", h_KeInsertQueueDpc);
    Provider::AddFuncImpl("KeRemoveQueueDpc", h_KeRemoveQueueDpc);
    Provider::AddFuncImpl("KeFlushQueuedDpcs", h_KeFlushQueuedDpcs);
    Provider::AddFuncImpl("ObDereferenceObjectDeferDelete", h_ObDereferenceObjectDeferDelete);
    Provider::AddFuncImpl("MmMapLockedPagesSpecifyCache", h_MmMapLockedPagesSpecifyCache);
    Provider::AddFuncImpl("MmUnmapLockedPages", h_MmUnmapLockedPages);
    Provider::AddFuncImpl("KeInitializeTimerEx", h_KeInitializeTimerEx);
    Provider::AddFuncImpl("KeSetTimerEx", h_KeSetTimerEx);
    Provider::AddFuncImpl("MmGetSystemAddressForMdlSafe", h_MmGetSystemAddressForMdlSafe);
    Provider::AddFuncImpl("ZwSetValueKey", h_ZwSetValueKey);
    Provider::AddFuncImpl("NtSetValueKey", h_ZwSetValueKey);
    Provider::AddFuncImpl("ZwDeleteKey", h_ZwDeleteKey);
    Provider::AddFuncImpl("NtDeleteKey", h_ZwDeleteKey);
    Provider::AddFuncImpl("ZwEnumerateKey", h_ZwEnumerateKey);
    Provider::AddFuncImpl("NtEnumerateKey", h_ZwEnumerateKey);
    Provider::AddFuncImpl("ZwEnumerateValueKey", h_ZwEnumerateValueKey);
    Provider::AddFuncImpl("NtEnumerateValueKey", h_ZwEnumerateValueKey);
    Provider::AddFuncImpl("RtlDeleteRegistryValue", h_RtlDeleteRegistryValue);
    Provider::AddFuncImpl("ZwDeleteValueKey", h_ZwDeleteValueKey);
    Provider::AddFuncImpl("NtDeleteValueKey", h_ZwDeleteValueKey);
    Provider::AddFuncImpl("ZwCreateKey", h_ZwCreateKey);
    Provider::AddFuncImpl("NtCreateKey", h_ZwCreateKey);
    Provider::AddFuncImpl("ZwOpenKeyEx", h_ZwOpenKeyEx);
    Provider::AddFuncImpl("NtOpenKeyEx", h_ZwOpenKeyEx);
    Provider::AddFuncImpl("RtlQueryRegistryValues", h_RtlQueryRegistryValues);
    Provider::AddFuncImpl("IoGetAttachedDeviceReference", h_IoGetAttachedDeviceReference);
    Provider::AddFuncImpl("ObDereferenceObjectWithTag", h_ObDereferenceObjectWithTag);
    Provider::AddFuncImpl("PsSetCreateProcessNotifyRoutineEx2", h_PsSetCreateProcessNotifyRoutineEx2);
    Provider::AddFuncImpl("IoRegisterPlugPlayNotification", h_IoRegisterPlugPlayNotification);
    Provider::AddFuncImpl("IoRegisterShutdownNotification", h_IoRegisterShutdownNotification);
    Provider::AddFuncImpl("IoUnregisterPlugPlayNotificationEx", h_IoUnregisterPlugPlayNotificationEx);
    Provider::AddFuncImpl("ExIsResourceAcquiredSharedLite", h_ExIsResourceAcquiredSharedLite);
    Provider::AddFuncImpl("ExIsResourceAcquiredExclusiveLite", h_ExIsResourceAcquiredExclusiveLite);
    Provider::AddFuncImpl("RtlGUIDFromString", h_RtlGUIDFromString);
    Provider::AddFuncImpl("RtlStringFromGUID", h_RtlStringFromGUID);
    Provider::AddFuncImpl("ExInitializeRundownProtection", h_ExInitializeRundownProtection);
    Provider::AddFuncImpl("ExAcquireRundownProtection", h_ExAcquireRundownProtection);
    Provider::AddFuncImpl("ExReleaseRundownProtection", h_ExReleaseRundownProtection);
    Provider::AddFuncImpl("KeAcquireSpinLockAtDpcLevel", h_KeAcquireSpinLockAtDpcLevel);
    Provider::AddFuncImpl("KeReleaseSpinLockFromDpcLevel", h_KeReleaseSpinLockFromDpcLevel);
    Provider::AddFuncImpl("ExAllocatePoolZero", h_ExAllocatePoolZero);
    Provider::AddFuncImpl("KeGetCurrentThread", h_KeGetCurrentThread);
    Provider::AddFuncImpl("ExfUnblockPushLock", h_ExfUnblockPushLock);
    Provider::AddFuncImpl("ExpUnblockPushLock", h_ExpUnblockPushLock);
    Provider::AddFuncImpl("ExEnumHandleTable", h_ExEnumHandleTable);
    Provider::AddFuncImpl("KeLeaveCriticalRegionThread", h_KeLeaveCriticalRegionThread);
    Provider::AddFuncImpl("ObOpenObjectByName", h_ObOpenObjectByName);
    Provider::AddFuncImpl("ObReferenceObjectByName", h_ObReferenceObjectByName);
    Provider::AddFuncImpl("KeStackAttachProcess", h_KeStackAttachProcess);
    Provider::AddFuncImpl("KeUnstackDetachProcess", h_KeUnstackDetachProcess);
    Provider::AddFuncImpl("KeInitializeApc", h_KeInitializeApc);
    Provider::AddFuncImpl("KeInsertQueueApc", h_KeInsertQueueApc);
    Provider::AddFuncImpl("KeRemoveQueueApc", h_KeRemoveQueueApc);
    Provider::AddFuncImpl("KeTestAlertThread", h_KeTestAlertThread);
    Provider::AddFuncImpl("MmUnmapViewOfSection", h_MmUnmapViewOfSection);
    Provider::AddFuncImpl("PsSuspendProcess", h_PsSuspendProcess);
    Provider::AddFuncImpl("PsResumeProcess", h_PsResumeProcess);
    Provider::AddFuncImpl("MmCopyVirtualMemory", h_MmCopyVirtualMemory);
    Provider::AddFuncImpl("MmGetVirtualForPhysical", h_MmGetVirtualForPhysical);
    Provider::AddFuncImpl("MmAllocateContiguousNodeMemory", h_MmAllocateContiguousNodeMemory);
    Provider::AddFuncImpl("PsGetProcessSectionBaseAddress", h_PsGetProcessSectionBaseAddress);
    Provider::AddFuncImpl("PsGetProcessExitStatus", h_PsGetProcessExitStatus);
    Provider::AddFuncImpl("KeAlertThread", h_KeAlertThread);
    Provider::AddFuncImpl("ObOpenObjectByPointerWithTag", h_ObOpenObjectByPointerWithTag);
    Provider::AddFuncImpl("PsGetProcessWin32Process", h_PsGetProcessWin32Process);
    Provider::AddFuncImpl("ZwQueryVirtualMemory", h_ZwQueryVirtualMemory);
    Provider::AddFuncImpl("KeQueryActiveProcessorCountEx", h_KeQueryActiveProcessorCountEx);
    Provider::AddFuncImpl("IoThreadToProcess", h_IoThreadToProcess);
    Provider::AddFuncImpl("ZwProtectVirtualMemory", h_ZwProtectVirtualMemory);
    Provider::AddFuncImpl("ZwLockVirtualMemory", h_ZwLockVirtualMemory);
    Provider::AddFuncImpl("ZwUnlockVirtualMemory", h_ZwUnlockVirtualMemory);
    Provider::AddFuncImpl("ZwFlushInstructionCache", h_ZwFlushInstructionCache);
    Provider::AddFuncImpl("ZwAllocateVirtualMemory", h_ZwAllocateVirtualMemory);
    Provider::AddFuncImpl("ZwFreeVirtualMemory", h_ZwFreeVirtualMemory);
    Provider::AddFuncImpl("ZwReadVirtualMemory", h_ZwReadVirtualMemory);
    Provider::AddFuncImpl("ZwWriteVirtualMemory", h_ZwWriteVirtualMemory);
    Provider::AddFuncImpl("ZwDuplicateObject", h_ZwDuplicateObject);
    Provider::AddFuncImpl("ZwMapViewOfSection", h_ZwMapViewOfSection);
    Provider::AddFuncImpl("NtMapViewOfSection", h_ZwMapViewOfSection);
    Provider::AddFuncImpl("ZwUnmapViewOfSection", h_ZwUnmapViewOfSection);
    Provider::AddFuncImpl("NtUnmapViewOfSection", h_ZwUnmapViewOfSection);
    Provider::AddFuncImpl("_wcsnicmp", h__wcsnicmp);
    Provider::AddFuncImpl("_wcsicmp", h__wcsicmp);
    Provider::AddFuncImpl("_stricmp", h__stricmp);
    Provider::AddFuncImpl("_strnicmp", h__strnicmp);
    Provider::AddFuncImpl("wcslen", h_wcslen);
    Provider::AddFuncImpl("strlen", h_strlen);
    Provider::AddFuncImpl("wcsrchr", h_wcsrchr);
    Provider::AddFuncImpl("wcschr", h_wcschr);
    Provider::AddFuncImpl("strrchr", h_strrchr);
    Provider::AddFuncImpl("wcscmp", h_wcscmp);
    Provider::AddFuncImpl("strcmp", h_strcmp);
    Provider::AddFuncImpl("wcsncmp", h_wcsncmp);
    Provider::AddFuncImpl("strncmp", h_strncmp);
    Provider::AddFuncImpl("wcsstr", h_wcsstr);
    Provider::AddFuncImpl("strstr", h_strstr);
    Provider::AddFuncImpl("towupper", h_towupper);
    Provider::AddFuncImpl("towlower", h_towlower);
    Provider::AddFuncImpl("toupper", h_toupper);
    Provider::AddFuncImpl("tolower", h_tolower);

    Provider::AddFuncImpl("MmAllocatePagesForMdl", h_MmAllocatePagesForMdl);
    Provider::AddFuncImpl("MmAllocatePagesForMdlEx", h_MmAllocatePagesForMdlEx);
    Provider::AddFuncImpl("MmFreePagesFromMdl", h_MmFreePagesFromMdl);
    Provider::AddFuncImpl("IoAllocateWorkItem", h_IoAllocateWorkItem);
    Provider::AddFuncImpl("IoFreeWorkItem", h_IoFreeWorkItem);
    Provider::AddFuncImpl("IoQueueWorkItem", h_IoQueueWorkItem);
    Provider::AddFuncImpl("IoInitializeWorkItem", h_IoInitializeWorkItem);
    Provider::AddFuncImpl("KeQuerySystemTimePrecise", h_KeQuerySystemTimePrecise);

    Provider::AddFuncImpl("KeInitializeSemaphore", h_KeInitializeSemaphore);
    Provider::AddFuncImpl("KeReleaseSemaphore", h_KeReleaseSemaphore);
    Provider::AddFuncImpl("KeCapturePersistentThreadState", h_KeCapturePersistentThreadState);
    Provider::AddFuncImpl("ExAcquireFastMutexUnsafe", h_ExAcquireFastMutexUnsafe);
    Provider::AddFuncImpl("ExReleaseFastMutexUnsafe", h_ExReleaseFastMutexUnsafe);
    Provider::AddFuncImpl("ExInitializePushLock", h_ExInitializePushLock);
    Provider::AddFuncImpl("ExAcquirePushLockExclusiveEx", h_ExAcquirePushLockExclusiveEx);
    Provider::AddFuncImpl("ExReleasePushLockExclusiveEx", h_ExReleasePushLockExclusiveEx);
    Provider::AddFuncImpl("ExAcquireSpinLockExclusiveAtDpcLevel", h_ExAcquireSpinLockExclusiveAtDpcLevel);
    Provider::AddFuncImpl("ExReleaseSpinLockExclusiveFromDpcLevel", h_ExReleaseSpinLockExclusiveFromDpcLevel);
    Provider::AddFuncImpl("MmFreeContiguousMemory", h_MmFreeContiguousMemory);
    Provider::AddFuncImpl("HalGetBusDataByOffset", h_HalGetBusDataByOffset);
    Provider::AddFuncImpl("HalAcpiGetTableEx", h_HalAcpiGetTableEx);
    Provider::AddFuncImpl("DbgSetDebugPrintCallback", h_DbgSetDebugPrintCallback);
}
