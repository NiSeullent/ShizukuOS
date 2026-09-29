/* SPDX-License-Identifier: GPL-2.0-only
 * ShzEcho: an unmodified WDM function driver built against Microsoft's DDK headers
 * (<ddk/wdm.h>) with mingw-w64, loaded as-is by the Kernel64 driver host. It creates a named
 * device with a \DosDevices symbolic link and echoes an IOCTL's input buffer back to its
 * output buffer, counting requests under a spin lock. No source change is made for Shizuku;
 * it is compiled exactly as a real Windows driver:
 *   x86_64-w64-mingw32-gcc -shared -nostdlib -Wl,--subsystem,native -e DriverEntry ...
 */
#include <ddk/wdm.h>

#define IOCTL_SHZ_ECHO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct { KSPIN_LOCK lock; LONG count; } ECHO_EXT;

static DRIVER_UNLOAD EchoUnload;
static DRIVER_DISPATCH EchoCreateClose, EchoControl;

VOID EchoUnload(PDRIVER_OBJECT drv)
{
    UNICODE_STRING dos;
    RtlInitUnicodeString(&dos, L"\\DosDevices\\ShzEcho");
    IoDeleteSymbolicLink(&dos);
    if (drv->DeviceObject)
        IoDeleteDevice(drv->DeviceObject);
    DbgPrint("ShzEcho: unloaded\n");
}

NTSTATUS EchoCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    (void)dev;
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS EchoControl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    ECHO_EXT *ext = dev->DeviceExtension;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;

    if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_SHZ_ECHO) {
        ULONG in = sp->Parameters.DeviceIoControl.InputBufferLength;
        ULONG out = sp->Parameters.DeviceIoControl.OutputBufferLength;
        ULONG n = in < out ? in : out;
        KIRQL irql;
        PVOID buf = irp->AssociatedIrp.SystemBuffer;      /* METHOD_BUFFERED: in and out share this buffer */
        KeAcquireSpinLock(&ext->lock, &irql);
        ext->count++;
        KeReleaseSpinLock(&ext->lock, irql);
        /* input already sits in SystemBuffer; it is also the output buffer, so echo is a copy in place. */
        (void)buf;
        info = n;
        st = STATUS_SUCCESS;
        DbgPrint("ShzEcho: IOCTL echo %u byte(s), request #%d\n", (unsigned)n, (int)ext->count);
    }
    irp->IoStatus.Status = st;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNICODE_STRING name, dos;
    PDEVICE_OBJECT dev;
    NTSTATUS st;
    (void)reg;
    RtlInitUnicodeString(&name, L"\\Device\\ShzEcho");
    st = IoCreateDevice(drv, sizeof(ECHO_EXT), &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    RtlZeroMemory(dev->DeviceExtension, sizeof(ECHO_EXT));
    KeInitializeSpinLock(&((ECHO_EXT *)dev->DeviceExtension)->lock);
    RtlInitUnicodeString(&dos, L"\\DosDevices\\ShzEcho");
    st = IoCreateSymbolicLink(&dos, &name);
    if (!NT_SUCCESS(st)) { IoDeleteDevice(dev); return st; }
    drv->MajorFunction[IRP_MJ_CREATE] = EchoCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE] = EchoCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = EchoControl;
    drv->DriverUnload = EchoUnload;
    dev->Flags |= DO_BUFFERED_IO;
    dev->Flags &= ~DO_DEVICE_INITIALIZING;
    DbgPrint("ShzEcho: DriverEntry, device \\Device\\ShzEcho ready\n");
    return STATUS_SUCCESS;
}
