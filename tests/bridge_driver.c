/*
 * bridge_driver.sys -- a real WDM driver, built to be run inside KEVLAR rather than
 * loaded by Windows. It exists so the whole bridge path can be tested end to end:
 *
 *     bridge_client.exe -> kevlar_hook.dll -> \\.\pipe\kevlar-... -> IoManager::Dispatch*
 *         -> this driver's dispatch routines, executing under Unicorn
 *
 * Every reply is something only this code could produce -- a magic value, a byte
 * transform, or a counter it kept between requests -- so a passing run means the guest
 * code actually ran. An echo would have proved only that the relay copies buffers.
 *
 * Deliberately no CRT and no memcpy: memcpy is not one of the exports registered in
 * ntoskrnl_provider.cpp, so a compiler-emitted call to it would resolve through the
 * unimplemented-stub path and silently corrupt the result. The copies below are loops.
 */

#include <ntddk.h>

#define KEVLAR_DEVICE_TYPE  FILE_DEVICE_UNKNOWN

#define IOCTL_KEVLAR_PING \
    CTL_CODE(KEVLAR_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KEVLAR_ECHO \
    CTL_CODE(KEVLAR_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_KEVLAR_STATE \
    CTL_CODE(KEVLAR_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* 'KVLB' -- the client checks for exactly this, so it cannot come from a stub. */
#define KEVLAR_PING_MAGIC 0x4B564C42UL

#define KEVLAR_STORE_MAX 256

typedef struct _KEVLAR_TEST_STATE {
    ULONG CreateCount;
    ULONG IoctlCount;
    ULONG WriteBytes;
    ULONG ReadCount;
} KEVLAR_TEST_STATE;

static UNICODE_STRING g_DeviceName = RTL_CONSTANT_STRING(L"\\Device\\KevlarBridgeTest");
static UNICODE_STRING g_SymLinkName = RTL_CONSTANT_STRING(L"\\DosDevices\\KevlarBridgeTest");

static PDEVICE_OBJECT g_DeviceObject;
static KEVLAR_TEST_STATE g_State;

/* Bytes handed over by the last IRP_MJ_WRITE, returned by the next IRP_MJ_READ. The
 * emulator serialises every dispatch behind IoManager::DispatchMutex, so one in-flight
 * IRP at a time -- no lock is needed here and none would be honest about that model. */
static UCHAR g_Store[KEVLAR_STORE_MAX];
static ULONG g_StoreLength;

static void CopyBytes(UCHAR *Destination, const UCHAR *Source, ULONG Length)
{
    ULONG Index;
    for (Index = 0; Index < Length; Index++)
        Destination[Index] = Source[Index];
}

static ULONG Smaller(ULONG Left, ULONG Right)
{
    return Left < Right ? Left : Right;
}

static NTSTATUS Complete(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS KevlarCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    UNREFERENCED_PARAMETER(DeviceObject);

    if (Stack->MajorFunction == IRP_MJ_CREATE)
        g_State.CreateCount++;

    return Complete(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS KevlarDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG InputLength = Stack->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutputLength = Stack->Parameters.DeviceIoControl.OutputBufferLength;
    ULONG Code = Stack->Parameters.DeviceIoControl.IoControlCode;
    UCHAR *Buffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(DeviceObject);
    g_State.IoctlCount++;

    switch (Code) {
    case IOCTL_KEVLAR_PING: {
        ULONG Magic = KEVLAR_PING_MAGIC;
        if (!Buffer || OutputLength < sizeof(Magic))
            return Complete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        CopyBytes(Buffer, (const UCHAR *)&Magic, sizeof(Magic));
        return Complete(Irp, STATUS_SUCCESS, sizeof(Magic));
    }

    case IOCTL_KEVLAR_ECHO: {
        /* Upper-cases the input in place. A transform rather than a copy: it can only
         * have been produced by this routine running. */
        ULONG Length = Smaller(InputLength, OutputLength);
        ULONG Index;
        if (!Buffer || Length == 0)
            return Complete(Irp, STATUS_INVALID_PARAMETER, 0);
        for (Index = 0; Index < Length; Index++) {
            UCHAR Value = Buffer[Index];
            Buffer[Index] = (Value >= 'a' && Value <= 'z') ? (UCHAR)(Value - 32) : Value;
        }
        return Complete(Irp, STATUS_SUCCESS, Length);
    }

    case IOCTL_KEVLAR_STATE: {
        if (!Buffer || OutputLength < sizeof(g_State))
            return Complete(Irp, STATUS_BUFFER_TOO_SMALL, 0);
        CopyBytes(Buffer, (const UCHAR *)&g_State, sizeof(g_State));
        return Complete(Irp, STATUS_SUCCESS, sizeof(g_State));
    }

    default:
        return Complete(Irp, STATUS_INVALID_DEVICE_REQUEST, 0);
    }
}

static NTSTATUS KevlarWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG Length = Smaller(Stack->Parameters.Write.Length, KEVLAR_STORE_MAX);
    UCHAR *Buffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(DeviceObject);

    if (!Buffer)
        return Complete(Irp, STATUS_INVALID_PARAMETER, 0);

    CopyBytes(g_Store, Buffer, Length);
    g_StoreLength = Length;
    g_State.WriteBytes += Length;

    /* Information is the full requested length: a short store is this driver's limit,
     * not a short write. */
    return Complete(Irp, STATUS_SUCCESS, Stack->Parameters.Write.Length);
}

static NTSTATUS KevlarRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG Length = Smaller(Stack->Parameters.Read.Length, g_StoreLength);
    UCHAR *Buffer = (UCHAR *)Irp->AssociatedIrp.SystemBuffer;

    UNREFERENCED_PARAMETER(DeviceObject);
    g_State.ReadCount++;

    if (!Buffer)
        return Complete(Irp, STATUS_INVALID_PARAMETER, 0);

    /* Hands back what the last write left behind, so a passing read/write pair proves
     * state survived between two separate relayed IRPs. */
    CopyBytes(Buffer, g_Store, Length);
    return Complete(Irp, STATUS_SUCCESS, Length);
}

static void KevlarUnload(PDRIVER_OBJECT DriverObject)
{
    UNREFERENCED_PARAMETER(DriverObject);
    IoDeleteSymbolicLink(&g_SymLinkName);
    if (g_DeviceObject)
        IoDeleteDevice(g_DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);

    Status = IoCreateDevice(DriverObject, 0, &g_DeviceName, KEVLAR_DEVICE_TYPE, 0,
                            FALSE, &g_DeviceObject);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = IoCreateSymbolicLink(&g_SymLinkName, &g_DeviceName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(g_DeviceObject);
        g_DeviceObject = NULL;
        return Status;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = KevlarCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = KevlarCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = KevlarCreateClose;
    DriverObject->MajorFunction[IRP_MJ_READ] = KevlarRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = KevlarWrite;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = KevlarDeviceControl;
    DriverObject->DriverUnload = KevlarUnload;

    /* The emulator's read/write dispatch hands over AssociatedIrp.SystemBuffer, so this
     * flag matches what actually arrives (irp_readwrite.cpp). */
    g_DeviceObject->Flags |= DO_BUFFERED_IO;
    g_DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}
