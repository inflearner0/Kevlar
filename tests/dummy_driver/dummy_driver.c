/*
 * dummy_driver.sys -- a small, real, compiled WDM driver used to exercise the
 * KEVLAR Usermode Bridge end-to-end (both Phase 1 and Phase 2). This driver never
 * loads into a real Windows kernel: KEVLAR.exe maps it and runs its DriverEntry
 * inside the Unicorn emulator, so it needs no signing.
 *
 * Exposes \Device\KevlarDummy (symlink \DosDevices\KevlarDummy) with handlers
 * simple enough to prove real driver logic executed, not just pass-through:
 *   - IOCTL (any code, METHOD_BUFFERED): echoes the input XORed with 0x5A
 *   - READ: fills the buffer with a repeating "KEVLARDUMMY" pattern
 *   - WRITE: accepts and reports the full length written
 *   - CREATE/CLOSE/CLEANUP: trivially succeed
 */

#include <ntddk.h>

static const char DummyPattern[] = "KEVLARDUMMY";
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

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    UNICODE_STRING DeviceName, SymLink;
    PDEVICE_OBJECT DeviceObject;
    NTSTATUS Status;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&DeviceName, L"\\Device\\KevlarDummy");
    Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status))
        return Status;

    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    RtlInitUnicodeString(&SymLink, L"\\DosDevices\\KevlarDummy");
    IoCreateSymbolicLink(&SymLink, &DeviceName);

    DriverObject->MajorFunction[IRP_MJ_CREATE] = DummyCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DummyCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLEANUP] = DummyCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DummyIoctl;
    DriverObject->MajorFunction[IRP_MJ_READ] = DummyRead;
    DriverObject->MajorFunction[IRP_MJ_WRITE] = DummyWrite;

    return STATUS_SUCCESS;
}
