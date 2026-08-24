/*
 * kevlarproxy.sys -- Phase 2 relay driver (kevlar_proxy/README.md SS4).
 *
 * Plain WDM. Exposes a SYSTEM+Administrators-only control device
 * (\Device\KevlarProxyCtl) that a single KEVLAR.exe instance opens to:
 *   - register exposed devices on behalf of DeviceTracker (IOCTL_KVP_CREATE_DEVICE)
 *   - pull real client IRPs captured on those exposed devices (IOCTL_KVP_GET_REQUEST)
 *   - push back the emulated driver's answer (IOCTL_KVP_COMPLETE_REQUEST)
 *
 * Every real IRP arriving on an exposed device is captured, parked (STATUS_PENDING),
 * and handed to the host relay via the GET_REQUEST/COMPLETE_REQUEST rendezvous
 * instead of being dispatched locally -- this driver has no logic of its own beyond
 * moving bytes and IRPs around.
 *
 * Cancellation and control-channel teardown follow the standard WDM
 * insert+arm-cancel-routine+check pattern throughout (see each IoSetCancelRoutine
 * call site): ownership of a queued item is always resolved by whichever side gets
 * a non-NULL return from IoSetCancelRoutine, decided while holding g_StateLock.
 */

#include <ntddk.h>
#include <wdmsec.h>
#include "kvp_protocol.h"

#pragma comment(lib, "wdmsec.lib")

#define KVP_TAG_REQ 'qvKk'
#define KVP_TAG_BUF 'bvKk'

#define KVP_CONTROL_DEVICE_NAME   L"\\Device\\KevlarProxyCtl"
#define KVP_CONTROL_SYMLINK_NAME  L"\\DosDevices\\Global\\KevlarProxyCtl"

typedef struct _KVP_DEVICE_EXTENSION {
    ULONG DeviceIndex;
} KVP_DEVICE_EXTENSION, *PKVP_DEVICE_EXTENSION;

typedef struct _KVP_DEVICE_SLOT {
    BOOLEAN InUse;
    BOOLEAN HasSymLink;
    PDEVICE_OBJECT DeviceObject;
    WCHAR SymLinkBuffer[KVP_MAX_NAME_CHARS];
} KVP_DEVICE_SLOT;

// Carries a symlink create request onto a system worker thread and back; see the
// IoQueueWorkItem call site in KvpHandleCreateDevice for why this is necessary.
typedef struct _KVP_SYMLINK_WORK_CONTEXT {
    PIO_WORKITEM WorkItem;
    UNICODE_STRING LinkName;
    UNICODE_STRING TargetName;
    WCHAR LinkBuffer[KVP_MAX_NAME_CHARS];
    WCHAR TargetBuffer[KVP_MAX_NAME_CHARS];
    NTSTATUS Status;
    KEVENT Done;
} KVP_SYMLINK_WORK_CONTEXT;

typedef struct _KVP_PENDING_REQUEST {
    LIST_ENTRY ListEntry;
    UINT64 RequestId;
    PIRP Irp;                  // the parked real client IRP
    ULONG DeviceIndex;
    UINT64 FileId;
    KVP_MAJOR_OP Op;
    ULONG IoControlCode;
    ULONG Method;               // diagnostic only (already baked into In/OutputBuffer below)
    PVOID InputBuffer;          // stable kernel pointer for the life of this pend
    ULONG InLen;
    PVOID OutputBuffer;         // where COMPLETE_REQUEST's payload gets written
    ULONG OutCap;
    BOOLEAN Delivered;           // already handed to a GET_REQUEST?
    PMDL NeitherOutputMdl;       // METHOD_NEITHER only
    PVOID NeitherInputPool;      // METHOD_NEITHER only
} KVP_PENDING_REQUEST, *PKVP_PENDING_REQUEST;

// IoCreateDriver is exported by the kernel but is not declared by the public WDK
// headers. Resolve it at runtime so the I/O manager, rather than this driver, builds
// and initializes the backing DRIVER_OBJECT.
typedef NTSTATUS (NTAPI *PKVP_IO_CREATE_DRIVER)(
    PUNICODE_STRING DriverName,
    PDRIVER_INITIALIZE InitializationFunction
    );

static PDRIVER_OBJECT g_DriverObject = NULL;
static PDEVICE_OBJECT g_ControlDevice = NULL;
static PFILE_OBJECT g_ControlOwner = NULL;
static KSPIN_LOCK g_StateLock;
static LIST_ENTRY g_PendingList;         // KVP_PENDING_REQUEST::ListEntry
static LIST_ENTRY g_GetRequestQueue;     // parked GET_REQUEST IRPs via Tail.Overlay.ListEntry
static volatile LONG64 g_NextRequestId = 0;
static KVP_DEVICE_SLOT g_DeviceSlots[KVP_MAX_DEVICES];

DRIVER_INITIALIZE DriverEntry;
DRIVER_INITIALIZE KvpInitializeDriverObject;
static VOID KvpUnload(PDRIVER_OBJECT DriverObject);

static NTSTATUS KvpMajorCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS KvpMajorClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS KvpMajorCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS KvpMajorDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS KvpMajorReadWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS KvpDispatchNotSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static NTSTATUS KvpControlCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS KvpControlClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS KvpControlCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static NTSTATUS KvpControlDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static NTSTATUS KvpHandleCreateDevice(PIRP Irp, PIO_STACK_LOCATION IrpSp);
static VOID KvpCreateSymlinkWorkRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context);
static NTSTATUS KvpHandleGetRequest(PIRP Irp, PIO_STACK_LOCATION IrpSp);
static NTSTATUS KvpHandleCompleteRequest(PIRP Irp, PIO_STACK_LOCATION IrpSp);

static NTSTATUS KvpExposedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp);

static VOID KvpCompleteGetRequestIrp(PIRP GetIrp, PKVP_PENDING_REQUEST Req);
static VOID KvpTeardownAll(VOID);
static VOID KvpFreeNeither(PMDL Mdl, PVOID InputPool);
static VOID KvpCompleteWithStatus(PIRP Irp, NTSTATUS Status);

static VOID KvpCancelGetRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp);
static VOID KvpCancelClientIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp);

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

static VOID
KvpCompleteWithStatus(PIRP Irp, NTSTATUS Status)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

static VOID
KvpCreateSymlinkWorkRoutine(PDEVICE_OBJECT DeviceObject, PVOID Context)
{
    KVP_SYMLINK_WORK_CONTEXT* Ctx = (KVP_SYMLINK_WORK_CONTEXT*)Context;
    UNREFERENCED_PARAMETER(DeviceObject);
    Ctx->Status = IoCreateSymbolicLink(&Ctx->LinkName, &Ctx->TargetName);
    // Last touch of Ctx from this routine -- KvpHandleCreateDevice's wait is what
    // makes freeing Ctx after the wait returns safe (see call site).
    KeSetEvent(&Ctx->Done, IO_NO_INCREMENT, FALSE);
}

static VOID
KvpFreeNeither(PMDL Mdl, PVOID InputPool)
{
    if (Mdl) {
        if (Mdl->MdlFlags & MDL_PAGES_LOCKED)
            MmUnlockPages(Mdl);
        IoFreeMdl(Mdl);
    }
    if (InputPool)
        ExFreePoolWithTag(InputPool, KVP_TAG_BUF);
}

// ---------------------------------------------------------------------------
// DriverEntry / Unload
// ---------------------------------------------------------------------------

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING RoutineName;
    PKVP_IO_CREATE_DRIVER IoCreateDriverRoutine;

    // The loader-supplied object is deliberately not used for dispatch or device
    // ownership. IoCreateDriver supplies a genuine, fully initialized object to
    // KvpInitializeDriverObject. Passing NULL gives that object a unique kernel name.
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&RoutineName, L"IoCreateDriver");
    IoCreateDriverRoutine = (PKVP_IO_CREATE_DRIVER)
        MmGetSystemRoutineAddress(&RoutineName);
    if (IoCreateDriverRoutine == NULL)
        return STATUS_PROCEDURE_NOT_FOUND;

    return IoCreateDriverRoutine(NULL, KvpInitializeDriverObject);
}

NTSTATUS
KvpInitializeDriverObject(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING DeviceName, SymLink, Sddl;
    NTSTATUS Status;
    ULONG I;

    UNREFERENCED_PARAMETER(RegistryPath);

    g_DriverObject = DriverObject;
    KeInitializeSpinLock(&g_StateLock);
    InitializeListHead(&g_PendingList);
    InitializeListHead(&g_GetRequestQueue);
    RtlZeroMemory(g_DeviceSlots, sizeof(g_DeviceSlots));
    g_ControlOwner = NULL;
    g_NextRequestId = 0;

    for (I = 0; I <= IRP_MJ_MAXIMUM_FUNCTION; I++)
        DriverObject->MajorFunction[I] = KvpDispatchNotSupported;

    DriverObject->MajorFunction[IRP_MJ_CREATE] = KvpMajorCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KvpMajorClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = KvpMajorCleanup;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KvpMajorDeviceControl;
    DriverObject->MajorFunction[IRP_MJ_READ] = KvpMajorReadWrite;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = KvpMajorReadWrite;
    DriverObject->DriverUnload = KvpUnload;

    // SYSTEM + Administrators only, single owner enforced in KvpControlCreate --
    // kevlar_proxy/README.md SS4.1/SS4.5.
    RtlInitUnicodeString(&DeviceName, KVP_CONTROL_DEVICE_NAME);
    RtlInitUnicodeString(&Sddl, L"D:P(A;;GA;;;BA)(A;;GA;;;SY)");

    Status = IoCreateDeviceSecure(
        DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, FALSE, &Sddl, NULL, &g_ControlDevice);
    if (!NT_SUCCESS(Status))
        return Status;

    RtlInitUnicodeString(&SymLink, KVP_CONTROL_SYMLINK_NAME);
    Status = IoCreateSymbolicLink(&SymLink, &DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
        return Status;
    }

    g_ControlDevice->Flags |= DO_BUFFERED_IO;
    g_ControlDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

static VOID
KvpUnload(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING SymLink;
    UNREFERENCED_PARAMETER(DriverObject);

    KvpTeardownAll();

    if (g_ControlDevice) {
        RtlInitUnicodeString(&SymLink, KVP_CONTROL_SYMLINK_NAME);
        IoDeleteSymbolicLink(&SymLink);
        IoDeleteDevice(g_ControlDevice);
        g_ControlDevice = NULL;
    }
}

// ---------------------------------------------------------------------------
// Major function routing: control device vs. exposed devices share one table
// (WDM has one MajorFunction array per DRIVER_OBJECT, not per device), so every
// entry point branches on DeviceObject identity first.
// ---------------------------------------------------------------------------

static NTSTATUS
KvpDispatchNotSupported(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    KvpCompleteWithStatus(Irp, STATUS_INVALID_DEVICE_REQUEST);
    return STATUS_INVALID_DEVICE_REQUEST;
}

static NTSTATUS
KvpMajorCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject == g_ControlDevice)
        return KvpControlCreate(DeviceObject, Irp);
    return KvpExposedDispatch(DeviceObject, Irp);
}

static NTSTATUS
KvpMajorClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject == g_ControlDevice)
        return KvpControlClose(DeviceObject, Irp);
    return KvpExposedDispatch(DeviceObject, Irp);
}

static NTSTATUS
KvpMajorCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject == g_ControlDevice)
        return KvpControlCleanup(DeviceObject, Irp);
    return KvpExposedDispatch(DeviceObject, Irp);
}

static NTSTATUS
KvpMajorDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    if (DeviceObject == g_ControlDevice)
        return KvpControlDeviceControl(DeviceObject, Irp);
    return KvpExposedDispatch(DeviceObject, Irp);
}

static NTSTATUS
KvpMajorReadWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    // The control device never receives Read/Write.
    return KvpExposedDispatch(DeviceObject, Irp);
}

// ---------------------------------------------------------------------------
// Control device: single-owner gate + the three control IOCTLs
// ---------------------------------------------------------------------------

static NTSTATUS
KvpControlCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    KIRQL OldIrql;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(DeviceObject);

    KeAcquireSpinLock(&g_StateLock, &OldIrql);
    if (g_ControlOwner == NULL) {
        g_ControlOwner = IrpSp->FileObject;
        Status = STATUS_SUCCESS;
    } else {
        Status = STATUS_ACCESS_DENIED;
    }
    KeReleaseSpinLock(&g_StateLock, OldIrql);

    KvpCompleteWithStatus(Irp, Status);
    return Status;
}

static NTSTATUS
KvpControlClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    KvpCompleteWithStatus(Irp, STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

static NTSTATUS
KvpControlCleanup(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    KIRQL OldIrql;
    BOOLEAN WasOwner = FALSE;

    UNREFERENCED_PARAMETER(DeviceObject);

    KeAcquireSpinLock(&g_StateLock, &OldIrql);
    if (g_ControlOwner == IrpSp->FileObject) {
        g_ControlOwner = NULL;
        WasOwner = TRUE;
    }
    KeReleaseSpinLock(&g_StateLock, OldIrql);

    // If KEVLAR.exe dies (or just closes the control handle), nothing will ever
    // answer a pended request or a parked GET_REQUEST again -- fail all of it now
    // instead of leaving clients hanging (kevlar_proxy/README.md SS4.4).
    if (WasOwner)
        KvpTeardownAll();

    KvpCompleteWithStatus(Irp, STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

static NTSTATUS
KvpControlDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG Code = IrpSp->Parameters.DeviceIoControl.IoControlCode;

    UNREFERENCED_PARAMETER(DeviceObject);

    // Defense in depth beyond the SDDL: only the recorded owner may issue control
    // IOCTLs. A single stale pointer read racing a concurrent open/cleanup is
    // harmless here -- worst case is one IOCTL rejected or allowed a beat late.
    if (IrpSp->FileObject != g_ControlOwner) {
        KvpCompleteWithStatus(Irp, STATUS_ACCESS_DENIED);
        return STATUS_ACCESS_DENIED;
    }

    switch (Code) {
    case IOCTL_KVP_CREATE_DEVICE:
        return KvpHandleCreateDevice(Irp, IrpSp);
    case IOCTL_KVP_GET_REQUEST:
        return KvpHandleGetRequest(Irp, IrpSp);
    case IOCTL_KVP_COMPLETE_REQUEST:
        return KvpHandleCompleteRequest(Irp, IrpSp);
    default:
        KvpCompleteWithStatus(Irp, STATUS_INVALID_DEVICE_REQUEST);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

static NTSTATUS
KvpHandleCreateDevice(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    ULONG InLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PKVP_CREATE_DEVICE_IN In = (PKVP_CREATE_DEVICE_IN)Irp->AssociatedIrp.SystemBuffer;
    KVP_CREATE_DEVICE_OUT Out;
    UNICODE_STRING DeviceName, Sddl;
    PDEVICE_OBJECT NewDevice = NULL;
    PKVP_DEVICE_EXTENSION Ext;
    NTSTATUS Status;
    KIRQL OldIrql;
    ULONG Slot = KVP_MAX_DEVICES;
    ULONG I;

    RtlZeroMemory(&Out, sizeof(Out));
    Out.SymLinkStatus = 0x7FFFFFFF; // sentinel: "never attempted" -- distinct from a real NTSTATUS

    if (!In || InLen < sizeof(KVP_CREATE_DEVICE_IN) || OutLen < sizeof(KVP_CREATE_DEVICE_OUT)) {
        KvpCompleteWithStatus(Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    // Force NUL-termination within the fixed buffers regardless of what the host
    // sent, before RtlInitUnicodeString ever walks them.
    In->DeviceName[KVP_MAX_NAME_CHARS - 1] = L'\0';
    In->SymLinkName[KVP_MAX_NAME_CHARS - 1] = L'\0';

    if (In->DeviceName[0] == L'\0') {
        Out.Status = STATUS_INVALID_PARAMETER;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Out, sizeof(Out));
        Irp->IoStatus.Information = sizeof(Out);
        KvpCompleteWithStatus(Irp, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    RtlInitUnicodeString(&DeviceName, In->DeviceName);

    KeAcquireSpinLock(&g_StateLock, &OldIrql);
    for (I = 0; I < KVP_MAX_DEVICES; I++) {
        if (!g_DeviceSlots[I].InUse) {
            Slot = I;
            g_DeviceSlots[I].InUse = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_StateLock, OldIrql);

    if (Slot == KVP_MAX_DEVICES) {
        Out.Status = STATUS_INSUFFICIENT_RESOURCES;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Out, sizeof(Out));
        Irp->IoStatus.Information = sizeof(Out);
        KvpCompleteWithStatus(Irp, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    // Administrators-only, always -- kevlar_proxy/README.md SS4.5: no knob to widen
    // this. Widening it is precisely how this relay becomes a working LPE.
    RtlInitUnicodeString(&Sddl, L"D:P(A;;GA;;;BA)(A;;GA;;;SY)");

    Status = IoCreateDeviceSecure(
        g_DriverObject, sizeof(KVP_DEVICE_EXTENSION), &DeviceName, In->DeviceType,
        FILE_DEVICE_SECURE_OPEN, FALSE, &Sddl, NULL, &NewDevice);

    if (!NT_SUCCESS(Status)) {
        KeAcquireSpinLock(&g_StateLock, &OldIrql);
        g_DeviceSlots[Slot].InUse = FALSE;
        KeReleaseSpinLock(&g_StateLock, OldIrql);

        Out.Status = Status;
        RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Out, sizeof(Out));
        Irp->IoStatus.Information = sizeof(Out);
        KvpCompleteWithStatus(Irp, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    Ext = (PKVP_DEVICE_EXTENSION)NewDevice->DeviceExtension;
    Ext->DeviceIndex = Slot;

    NewDevice->Flags |= DO_BUFFERED_IO;
    NewDevice->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlZeroMemory(g_DeviceSlots[Slot].SymLinkBuffer, sizeof(g_DeviceSlots[Slot].SymLinkBuffer));
    g_DeviceSlots[Slot].HasSymLink = FALSE;
    g_DeviceSlots[Slot].DeviceObject = NewDevice;

    if (In->SymLinkName[0] != L'\0') {
        // IoCreateSymbolicLink must run on a genuine SYSTEM-process worker thread,
        // not inline here: this dispatch routine runs on a thread borrowed from the
        // calling (usermode) thread, and \DosDevices/\?? resolution from that
        // borrowed context does not land in the real \GLOBAL?? namespace on this
        // platform -- confirmed empirically (IoCreateSymbolicLink reports
        // STATUS_SUCCESS either way, but only the worker-thread version actually
        // resolves via \\.\<name>). DriverEntry's own symlink for the control device
        // works precisely because DriverEntry already runs in that kind of context.
        KVP_SYMLINK_WORK_CONTEXT* SymCtx =
            (KVP_SYMLINK_WORK_CONTEXT*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KVP_SYMLINK_WORK_CONTEXT), KVP_TAG_BUF);

        if (!SymCtx) {
            Out.SymLinkStatus = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            LARGE_INTEGER Timeout;
            Timeout.QuadPart = -100000000LL; // 10s relative; system worker threads are never this slow in practice

            RtlCopyMemory(SymCtx->LinkBuffer, In->SymLinkName, sizeof(SymCtx->LinkBuffer));
            RtlCopyMemory(SymCtx->TargetBuffer, In->DeviceName, sizeof(SymCtx->TargetBuffer));
            RtlInitUnicodeString(&SymCtx->LinkName, SymCtx->LinkBuffer);
            RtlInitUnicodeString(&SymCtx->TargetName, SymCtx->TargetBuffer);
            SymCtx->Status = STATUS_UNSUCCESSFUL;
            KeInitializeEvent(&SymCtx->Done, NotificationEvent, FALSE);
            SymCtx->WorkItem = IoAllocateWorkItem(g_ControlDevice);

            if (!SymCtx->WorkItem) {
                Out.SymLinkStatus = STATUS_INSUFFICIENT_RESOURCES;
                ExFreePoolWithTag(SymCtx, KVP_TAG_BUF);
            } else {
                IoQueueWorkItem(SymCtx->WorkItem, KvpCreateSymlinkWorkRoutine, DelayedWorkQueue, SymCtx);

                if (KeWaitForSingleObject(&SymCtx->Done, Executive, KernelMode, FALSE, &Timeout) == STATUS_SUCCESS) {
                    Status = SymCtx->Status;
                    IoFreeWorkItem(SymCtx->WorkItem);
                    ExFreePoolWithTag(SymCtx, KVP_TAG_BUF);
                } else {
                    // Timed out: the queued work item may still run later and will
                    // touch SymCtx/WorkItem when it does, so freeing here would race
                    // a real use-after-free. Deliberately leak this ~100-byte
                    // allocation instead -- a vastly safer failure mode for a case
                    // this should never actually hit.
                    Status = STATUS_TIMEOUT;
                }

                Out.SymLinkStatus = Status;
                if (NT_SUCCESS(Status)) {
                    g_DeviceSlots[Slot].HasSymLink = TRUE;
                    RtlCopyMemory(g_DeviceSlots[Slot].SymLinkBuffer, In->SymLinkName, sizeof(In->SymLinkName));
                }
                // A symlink failure is non-fatal: the device is still reachable via
                // its NT device path; only \\.\<name> convenience is lost. The real
                // status is still reported back (SymLinkStatus) rather than
                // silently discarded.
            }
        }
    }

    Out.Status = STATUS_SUCCESS;
    Out.DeviceIndex = Slot;
    RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, &Out, sizeof(Out));
    Irp->IoStatus.Information = sizeof(Out);
    KvpCompleteWithStatus(Irp, STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

static VOID
KvpCompleteGetRequestIrp(PIRP GetIrp, PKVP_PENDING_REQUEST Req)
{
    PIO_STACK_LOCATION GetSp = IoGetCurrentIrpStackLocation(GetIrp);
    ULONG OutBufLen = GetSp->Parameters.DeviceIoControl.OutputBufferLength;
    PUCHAR Dest = (PUCHAR)GetIrp->AssociatedIrp.SystemBuffer;
    KVP_REQUEST_HEADER Hdr;
    ULONG NeedLen = sizeof(KVP_REQUEST_HEADER) + Req->InLen;

    RtlZeroMemory(&Hdr, sizeof(Hdr));
    Hdr.RequestId = Req->RequestId;
    Hdr.DeviceIndex = Req->DeviceIndex;
    Hdr.FileId = Req->FileId;
    Hdr.Op = (ULONG)Req->Op;
    Hdr.IoControlCode = Req->IoControlCode;
    Hdr.InLen = Req->InLen;
    Hdr.OutCap = Req->OutCap;

    // Defensive only: capture already enforces InLen <= KVP_MAX_PAYLOAD and the host
    // is documented to always provision sizeof(header)+KVP_MAX_PAYLOAD.
    if (!Dest || OutBufLen < NeedLen) {
        KvpCompleteWithStatus(GetIrp, STATUS_BUFFER_TOO_SMALL);
        return;
    }

    RtlCopyMemory(Dest, &Hdr, sizeof(Hdr));
    if (Req->InLen > 0 && Req->InputBuffer)
        RtlCopyMemory(Dest + sizeof(Hdr), Req->InputBuffer, Req->InLen);

    GetIrp->IoStatus.Status = STATUS_SUCCESS;
    GetIrp->IoStatus.Information = NeedLen;
    IoCompleteRequest(GetIrp, IO_NO_INCREMENT);
}

static NTSTATUS
KvpHandleGetRequest(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    KIRQL OldIrql;
    PKVP_PENDING_REQUEST Found = NULL;
    PLIST_ENTRY Entry;
    BOOLEAN Pend;

    if (IrpSp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(KVP_REQUEST_HEADER)) {
        KvpCompleteWithStatus(Irp, STATUS_BUFFER_TOO_SMALL);
        return STATUS_BUFFER_TOO_SMALL;
    }

    KeAcquireSpinLock(&g_StateLock, &OldIrql);

    for (Entry = g_PendingList.Flink; Entry != &g_PendingList; Entry = Entry->Flink) {
        PKVP_PENDING_REQUEST Cand = CONTAINING_RECORD(Entry, KVP_PENDING_REQUEST, ListEntry);
        if (!Cand->Delivered) {
            Found = Cand;
            break;
        }
    }

    if (Found)
        Found->Delivered = TRUE;

    if (!Found) {
        // Nothing ready: park this GET_REQUEST until a client request arrives.
        InsertTailList(&g_GetRequestQueue, &Irp->Tail.Overlay.ListEntry);
        IoMarkIrpPending(Irp);
        IoSetCancelRoutine(Irp, KvpCancelGetRequest);

        if (Irp->Cancel && IoSetCancelRoutine(Irp, NULL) != NULL) {
            RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
            Pend = FALSE;
        } else {
            Pend = TRUE;
        }
    } else {
        Pend = FALSE; // handled below, outside the lock
    }

    KeReleaseSpinLock(&g_StateLock, OldIrql);

    if (Found) {
        KvpCompleteGetRequestIrp(Irp, Found);
        return STATUS_SUCCESS;
    }
    if (!Pend) {
        KvpCompleteWithStatus(Irp, STATUS_CANCELLED);
        return STATUS_CANCELLED;
    }
    return STATUS_PENDING;
}

static NTSTATUS
KvpHandleCompleteRequest(PIRP Irp, PIO_STACK_LOCATION IrpSp)
{
    ULONG InBufLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    PUCHAR Src = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    KVP_COMPLETE_HEADER Hdr;
    KIRQL OldIrql;
    PKVP_PENDING_REQUEST Found = NULL;
    PLIST_ENTRY Entry;
    PIRP ClientIrp = NULL;
    BOOLEAN Owned = FALSE;

    if (!Src || InBufLen < sizeof(KVP_COMPLETE_HEADER)) {
        KvpCompleteWithStatus(Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    RtlCopyMemory(&Hdr, Src, sizeof(Hdr));

    if (Hdr.OutLen > KVP_MAX_PAYLOAD || sizeof(Hdr) + (SIZE_T)Hdr.OutLen > InBufLen) {
        KvpCompleteWithStatus(Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    KeAcquireSpinLock(&g_StateLock, &OldIrql);

    for (Entry = g_PendingList.Flink; Entry != &g_PendingList; Entry = Entry->Flink) {
        PKVP_PENDING_REQUEST Cand = CONTAINING_RECORD(Entry, KVP_PENDING_REQUEST, ListEntry);
        if (Cand->RequestId == Hdr.RequestId) {
            Found = Cand;
            break;
        }
    }

    if (Found) {
        ClientIrp = Found->Irp;
        // Race with a concurrent client-side cancellation: whichever side gets a
        // non-NULL IoSetCancelRoutine result owns completing+freeing this entry. If
        // we lose, KvpCancelClientIrp is already blocked on g_StateLock and will
        // finish the job the moment we release it below.
        if (IoSetCancelRoutine(ClientIrp, NULL) != NULL) {
            RemoveEntryList(&Found->ListEntry);
            Owned = TRUE;
        } else {
            Found = NULL;
            ClientIrp = NULL;
        }
    }

    KeReleaseSpinLock(&g_StateLock, OldIrql);

    if (!Owned) {
        // Not found, or lost the cancellation race: normal, not an error
        // (kevlar_proxy/README.md SS4.4).
        KvpCompleteWithStatus(Irp, STATUS_SUCCESS);
        return STATUS_SUCCESS;
    }

    {
        ULONG CopyLen = Hdr.OutLen;
        if (CopyLen > Found->OutCap)
            CopyLen = Found->OutCap;
        if (CopyLen > 0 && Found->OutputBuffer)
            RtlCopyMemory(Found->OutputBuffer, Src + sizeof(Hdr), CopyLen);

        ClientIrp->IoStatus.Status = Hdr.Status;
        ClientIrp->IoStatus.Information = (ULONG_PTR)Hdr.Information;
        IoCompleteRequest(ClientIrp, IO_NO_INCREMENT);
    }

    KvpFreeNeither(Found->NeitherOutputMdl, Found->NeitherInputPool);
    ExFreePoolWithTag(Found, KVP_TAG_REQ);

    KvpCompleteWithStatus(Irp, STATUS_SUCCESS);
    return STATUS_SUCCESS;
}

// ---------------------------------------------------------------------------
// Exposed devices: capture the real IRP, park it, relay it
// ---------------------------------------------------------------------------

static NTSTATUS
KvpExposedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PKVP_DEVICE_EXTENSION Ext = (PKVP_DEVICE_EXTENSION)DeviceObject->DeviceExtension;
    KVP_MAJOR_OP Op;
    ULONG IoControlCode = 0;
    ULONG Method = 0;
    PVOID InputBuffer = NULL;
    ULONG InLen = 0;
    PVOID OutputBuffer = NULL;
    ULONG OutCap = 0;
    PMDL NeitherOutMdl = NULL;
    PVOID NeitherInPool = NULL;
    PKVP_PENDING_REQUEST Req;
    KIRQL OldIrql;
    PIRP WaitingGetIrp = NULL;
    BOOLEAN SelfCancelled = FALSE;

    switch (IrpSp->MajorFunction) {
    case IRP_MJ_CREATE:
        Op = KvpOpCreate;
        break;
    case IRP_MJ_CLOSE:
        Op = KvpOpClose;
        break;
    case IRP_MJ_CLEANUP:
        Op = KvpOpCleanup;
        break;
    case IRP_MJ_READ:
        // DO_BUFFERED_IO is set on every exposed device, so this is always SystemBuffer.
        Op = KvpOpRead;
        OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
        OutCap = IrpSp->Parameters.Read.Length;
        break;
    case IRP_MJ_WRITE:
        Op = KvpOpWrite;
        InputBuffer = Irp->AssociatedIrp.SystemBuffer;
        InLen = IrpSp->Parameters.Write.Length;
        break;
    case IRP_MJ_DEVICE_CONTROL:
        Op = KvpOpDeviceControl;
        IoControlCode = IrpSp->Parameters.DeviceIoControl.IoControlCode;
        Method = IoControlCode & 3;

        switch (Method) {
        case METHOD_BUFFERED:
            InputBuffer = Irp->AssociatedIrp.SystemBuffer;
            InLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutputBuffer = Irp->AssociatedIrp.SystemBuffer;
            OutCap = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            break;

        case METHOD_IN_DIRECT:
        case METHOD_OUT_DIRECT:
            // Simplification matching kevlar_proxy/README.md SS4.3: both treated as
            // "buffered input, MDL-backed output" -- covers the overwhelmingly common
            // OUT_DIRECT usage. A driver relying on IN_DIRECT's stricter "MDL is
            // input, not output" meaning sees an empty output here, not a crash.
            InputBuffer = Irp->AssociatedIrp.SystemBuffer;
            InLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutCap = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
            if (Irp->MdlAddress && OutCap > 0) {
                OutputBuffer = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
                if (!OutputBuffer) {
                    KvpCompleteWithStatus(Irp, STATUS_INSUFFICIENT_RESOURCES);
                    return STATUS_INSUFFICIENT_RESOURCES;
                }
            }
            break;

        case METHOD_NEITHER: {
            PVOID RawInput = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
            PVOID RawOutput = Irp->UserBuffer;
            NTSTATUS ExStatus = STATUS_SUCCESS;

            InLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
            OutCap = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;

            // Must happen here, before pending: Type3InputBuffer/UserBuffer are raw
            // usermode VAs valid only in the calling thread's context
            // (kevlar_proxy/README.md SS4.3).
            __try {
                if (RawInput && InLen > 0) {
                    ProbeForRead(RawInput, InLen, 1);
                    NeitherInPool = ExAllocatePool2(POOL_FLAG_NON_PAGED, InLen, KVP_TAG_BUF);
                    if (!NeitherInPool)
                        ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
                    RtlCopyMemory(NeitherInPool, RawInput, InLen);
                    InputBuffer = NeitherInPool;
                }
                if (RawOutput && OutCap > 0) {
                    ProbeForWrite(RawOutput, OutCap, 1);
                    NeitherOutMdl = IoAllocateMdl(RawOutput, OutCap, FALSE, FALSE, NULL);
                    if (!NeitherOutMdl)
                        ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
                    MmProbeAndLockPages(NeitherOutMdl, UserMode, IoWriteAccess);
                    OutputBuffer = MmGetSystemAddressForMdlSafe(NeitherOutMdl, NormalPagePriority);
                    if (!OutputBuffer)
                        ExRaiseStatus(STATUS_INSUFFICIENT_RESOURCES);
                }
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                ExStatus = GetExceptionCode();
            }

            if (!NT_SUCCESS(ExStatus)) {
                KvpFreeNeither(NeitherOutMdl, NeitherInPool);
                KvpCompleteWithStatus(Irp, ExStatus);
                return ExStatus;
            }
            break;
        }

        default:
            KvpCompleteWithStatus(Irp, STATUS_INVALID_DEVICE_REQUEST);
            return STATUS_INVALID_DEVICE_REQUEST;
        }
        break;

    default:
        KvpCompleteWithStatus(Irp, STATUS_INVALID_DEVICE_REQUEST);
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (InLen > KVP_MAX_PAYLOAD || OutCap > KVP_MAX_PAYLOAD) {
        KvpFreeNeither(NeitherOutMdl, NeitherInPool);
        KvpCompleteWithStatus(Irp, STATUS_INVALID_PARAMETER);
        return STATUS_INVALID_PARAMETER;
    }

    Req = (PKVP_PENDING_REQUEST)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(KVP_PENDING_REQUEST), KVP_TAG_REQ);
    if (!Req) {
        KvpFreeNeither(NeitherOutMdl, NeitherInPool);
        KvpCompleteWithStatus(Irp, STATUS_INSUFFICIENT_RESOURCES);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Req, sizeof(*Req));
    Req->RequestId = (UINT64)InterlockedIncrement64(&g_NextRequestId);
    Req->Irp = Irp;
    Req->DeviceIndex = Ext->DeviceIndex;
    Req->FileId = (UINT64)IrpSp->FileObject;
    Req->Op = Op;
    Req->IoControlCode = IoControlCode;
    Req->Method = Method;
    Req->InputBuffer = InputBuffer;
    Req->InLen = InLen;
    Req->OutputBuffer = OutputBuffer;
    Req->OutCap = OutCap;
    Req->NeitherOutputMdl = NeitherOutMdl;
    Req->NeitherInputPool = NeitherInPool;
    Req->Delivered = FALSE;

    Irp->Tail.Overlay.DriverContext[0] = Req;

    KeAcquireSpinLock(&g_StateLock, &OldIrql);

    InsertTailList(&g_PendingList, &Req->ListEntry);
    IoMarkIrpPending(Irp);
    IoSetCancelRoutine(Irp, KvpCancelClientIrp);

    if (Irp->Cancel && IoSetCancelRoutine(Irp, NULL) != NULL) {
        RemoveEntryList(&Req->ListEntry);
        SelfCancelled = TRUE;
    } else if (!IsListEmpty(&g_GetRequestQueue)) {
        PLIST_ENTRY Entry = RemoveHeadList(&g_GetRequestQueue);
        PIRP Candidate = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        if (IoSetCancelRoutine(Candidate, NULL) != NULL) {
            WaitingGetIrp = Candidate;
            Req->Delivered = TRUE;
        }
        // else: that GET_REQUEST is being canceled concurrently; its own cancel
        // routine already re-removed it from the list (or will find it already gone
        // -- either way we must not touch it). Our request stays undelivered for the
        // next GET_REQUEST.
    }

    KeReleaseSpinLock(&g_StateLock, OldIrql);

    if (SelfCancelled) {
        KvpFreeNeither(Req->NeitherOutputMdl, Req->NeitherInputPool);
        ExFreePoolWithTag(Req, KVP_TAG_REQ);
        KvpCompleteWithStatus(Irp, STATUS_CANCELLED);
        return STATUS_CANCELLED;
    }

    if (WaitingGetIrp)
        KvpCompleteGetRequestIrp(WaitingGetIrp, Req);

    return STATUS_PENDING;
}

// ---------------------------------------------------------------------------
// Cancel routines
// ---------------------------------------------------------------------------

static VOID
KvpCancelGetRequest(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    KIRQL OldIrql;
    UNREFERENCED_PARAMETER(DeviceObject);
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    // Only invoked when this Irp was the atomic winner of IoSetCancelRoutine, which
    // by construction only happens while it is still linked in g_GetRequestQueue.
    KeAcquireSpinLock(&g_StateLock, &OldIrql);
    RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
    KeReleaseSpinLock(&g_StateLock, OldIrql);

    KvpCompleteWithStatus(Irp, STATUS_CANCELLED);
}

static VOID
KvpCancelClientIrp(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    KIRQL OldIrql;
    PKVP_PENDING_REQUEST Req = (PKVP_PENDING_REQUEST)Irp->Tail.Overlay.DriverContext[0];

    UNREFERENCED_PARAMETER(DeviceObject);
    IoReleaseCancelSpinLock(Irp->CancelIrql);

    // Same invariant as KvpCancelGetRequest: still linked in g_PendingList by
    // construction whenever this routine actually runs.
    KeAcquireSpinLock(&g_StateLock, &OldIrql);
    RemoveEntryList(&Req->ListEntry);
    KeReleaseSpinLock(&g_StateLock, OldIrql);

    KvpFreeNeither(Req->NeitherOutputMdl, Req->NeitherInputPool);
    ExFreePoolWithTag(Req, KVP_TAG_REQ);

    KvpCompleteWithStatus(Irp, STATUS_CANCELLED);
}

// ---------------------------------------------------------------------------
// Teardown: control channel owner disappeared (cleanup or driver unload)
// ---------------------------------------------------------------------------

static VOID
KvpTeardownAll(VOID)
{
    KIRQL OldIrql;
    LIST_ENTRY LocalPending, LocalGetReqs;
    PLIST_ENTRY Entry, NextEntry;
    ULONG I;
    PDEVICE_OBJECT DevicesToDelete[KVP_MAX_DEVICES];
    UNICODE_STRING SymLinksToDelete[KVP_MAX_DEVICES];
    BOOLEAN HasSymLinkToDelete[KVP_MAX_DEVICES];
    ULONG DeviceCount = 0;

    InitializeListHead(&LocalPending);
    InitializeListHead(&LocalGetReqs);

    KeAcquireSpinLock(&g_StateLock, &OldIrql);

    // Ownership of each entry is resolved via IoSetCancelRoutine, exactly like every
    // other race in this driver: an entry we don't win here is left completely
    // untouched because a concurrent client-side cancellation already owns it and
    // will finish removing/freeing it itself the moment we release this lock.
    for (Entry = g_PendingList.Flink; Entry != &g_PendingList; Entry = NextEntry) {
        PKVP_PENDING_REQUEST Req = CONTAINING_RECORD(Entry, KVP_PENDING_REQUEST, ListEntry);
        NextEntry = Entry->Flink;
        if (Req->Irp && IoSetCancelRoutine(Req->Irp, NULL) != NULL) {
            RemoveEntryList(&Req->ListEntry);
            InsertTailList(&LocalPending, &Req->ListEntry);
        }
    }

    for (Entry = g_GetRequestQueue.Flink; Entry != &g_GetRequestQueue; Entry = NextEntry) {
        PIRP GetIrp = CONTAINING_RECORD(Entry, IRP, Tail.Overlay.ListEntry);
        NextEntry = Entry->Flink;
        if (IoSetCancelRoutine(GetIrp, NULL) != NULL) {
            RemoveEntryList(&GetIrp->Tail.Overlay.ListEntry);
            InsertTailList(&LocalGetReqs, &GetIrp->Tail.Overlay.ListEntry);
        }
    }

    for (I = 0; I < KVP_MAX_DEVICES; I++) {
        if (g_DeviceSlots[I].InUse) {
            DevicesToDelete[DeviceCount] = g_DeviceSlots[I].DeviceObject;
            HasSymLinkToDelete[DeviceCount] = g_DeviceSlots[I].HasSymLink;
            if (g_DeviceSlots[I].HasSymLink)
                RtlInitUnicodeString(&SymLinksToDelete[DeviceCount], g_DeviceSlots[I].SymLinkBuffer);
            DeviceCount++;
            g_DeviceSlots[I].InUse = FALSE;
            g_DeviceSlots[I].HasSymLink = FALSE;
            g_DeviceSlots[I].DeviceObject = NULL;
        }
    }

    KeReleaseSpinLock(&g_StateLock, OldIrql);

    while (!IsListEmpty(&LocalPending)) {
        PLIST_ENTRY E = RemoveHeadList(&LocalPending);
        PKVP_PENDING_REQUEST Req = CONTAINING_RECORD(E, KVP_PENDING_REQUEST, ListEntry);
        KvpCompleteWithStatus(Req->Irp, STATUS_DEVICE_NOT_READY);
        KvpFreeNeither(Req->NeitherOutputMdl, Req->NeitherInputPool);
        ExFreePoolWithTag(Req, KVP_TAG_REQ);
    }

    while (!IsListEmpty(&LocalGetReqs)) {
        PLIST_ENTRY E = RemoveHeadList(&LocalGetReqs);
        PIRP GetIrp = CONTAINING_RECORD(E, IRP, Tail.Overlay.ListEntry);
        KvpCompleteWithStatus(GetIrp, STATUS_DEVICE_NOT_READY);
    }

    // Delete the now-orphaned exposed devices outright: a new client CREATE fails
    // fast at the Object Manager instead of hanging forever waiting for a
    // GET_REQUEST that will never come, and the device names become reusable
    // (kevlar_proxy/README.md SS4.4: "otherwise ... the device cannot be deleted").
    for (I = 0; I < DeviceCount; I++) {
        if (HasSymLinkToDelete[I])
            IoDeleteSymbolicLink(&SymLinksToDelete[I]);
        IoDeleteDevice(DevicesToDelete[I]);
    }
}
