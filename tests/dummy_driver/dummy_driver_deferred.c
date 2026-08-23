/*
 * dummy_driver_deferred.sys -- variant of dummy_driver.sys that creates its device
 * from a spawned system thread ~2s after DriverEntry returns, instead of directly
 * in DriverEntry. Exercises ProxyRelay's registrar thread (KEVLAR/host/bridge/
 * proxy_relay.cpp): a driver whose device appears only after DriverEntry has
 * already completed must still get registered with kevlarproxy.sys.
 *
 * Exposes \Device\KevlarDeferred (symlink \DosDevices\KevlarDeferred) with the
 * same IOCTL/READ/WRITE handlers as dummy_driver.sys.
 */

#include <ntddk.h>

static const char DummyPattern[] = "KEVLARDEFERRED";
#define DUMMY_PATTERN_LEN (sizeof(DummyPattern) - 1)

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS
DummySimpleComplete(PIRP Irp, NTSTATUS Status, ULONG_PTR Information)
{
    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = Information;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Status;
}

static NTSTATUS
DummyCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    return DummySimpleComplete(Irp, STATUS_SUCCESS, 0);
}

static NTSTATUS
DummyIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG InLen = IrpSp->Parameters.DeviceIoControl.InputBufferLength;
    ULONG OutLen = IrpSp->Parameters.DeviceIoControl.OutputBufferLength;
    PUCHAR Buf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG CopyLen = (InLen < OutLen) ? InLen : OutLen;
    ULONG I;

    UNREFERENCED_PARAMETER(DeviceObject);

    for (I = 0; I < CopyLen; I++)
        Buf[I] = (UCHAR)(Buf[I] ^ 0x5A);

    return DummySimpleComplete(Irp, STATUS_SUCCESS, CopyLen);
}

static NTSTATUS
DummyRead(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG Len = IrpSp->Parameters.Read.Length;
    PUCHAR Buf = (PUCHAR)Irp->AssociatedIrp.SystemBuffer;
    ULONG I;

    UNREFERENCED_PARAMETER(DeviceObject);

    for (I = 0; I < Len; I++)
        Buf[I] = (UCHAR)DummyPattern[I % DUMMY_PATTERN_LEN];

    return DummySimpleComplete(Irp, STATUS_SUCCESS, Len);
}

static NTSTATUS
DummyWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    ULONG Len = IrpSp->Parameters.Write.Length;

    UNREFERENCED_PARAMETER(DeviceObject);

    return DummySimpleComplete(Irp, STATUS_SUCCESS, Len);
}

static VOID
DeferredInitThread(PVOID Context)
{
    PDRIVER_OBJECT DriverObject = (PDRIVER_OBJECT)Context;
    UNICODE_STRING DeviceName, SymLink;
    PDEVICE_OBJECT DeviceObject;
    LARGE_INTEGER Delay;

    // 2s relative delay (100ns units, negative = relative) -- long enough that
    // ProxyRelay::Start()'s initial synchronous registration pass has already come
    // up empty and returned before this device exists.
    Delay.QuadPart = -20000000LL;
    KeDelayExecutionThread(0, FALSE, &Delay);

    RtlInitUnicodeString(&DeviceName, L"\\Device\\KevlarDeferred");
    if (!NT_SUCCESS(IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject)))
        return;

    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&SymLink, L"\\DosDevices\\KevlarDeferred");
    IoCreateSymbolicLink(&SymLink, &DeviceName);
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    HANDLE ThreadHandle;

    UNREFERENCED_PARAMETER(RegistryPath);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DummyCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DummyCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DummyCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DummyIoctl;
    DriverObject->MajorFunction[IRP_MJ_READ] = DummyRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DummyWrite;

    // Device is created from this thread, well after DriverEntry returns -- not
    // inline here.
    PsCreateSystemThread(&ThreadHandle, (ULONG)0x1FFFFF /* THREAD_ALL_ACCESS */,
        NULL, NULL, NULL, DeferredInitThread, DriverObject);

    return STATUS_SUCCESS;
}
