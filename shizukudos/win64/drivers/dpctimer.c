/* SPDX-License-Identifier: GPL-2.0-only
 * ShzDpc: an unmodified WDM driver exercising the kernel primitives a real driver relies on --
 * a system thread (PsCreateSystemThread), a KEVENT it signals, a KDPC fired by a KTIMER, and a
 * pended IRP completed later from a timer DPC (IoMarkIrpPending -> STATUS_PENDING -> async
 * IoCompleteRequest). DriverEntry runs the thread+timer+DPC self-check inline and fails to load
 * (returns an error NTSTATUS) if any part does not happen, so a green load is real evidence.
 */
#include <ddk/wdm.h>

#define IOCTL_SHZ_PEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define PEND_MAGIC 0xC0FFEE00u

typedef struct {
    KEVENT threadDone, timerDone;
    KDPC dpc; KTIMER timer;
    KDPC pendDpc; KTIMER pendTimer;
    volatile LONG counter;
    PIRP pending;
} DPC_EXT;

static DPC_EXT *g_ext;                                 /* single instance; DPC context also carries it */

static VOID WorkerThread(PVOID ctx)
{
    DPC_EXT *ext = ctx;
    DbgPrint("ShzDpc: system thread running\n");
    KeSetEvent(&ext->threadDone, IO_NO_INCREMENT, FALSE);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

static VOID TimerDpc(PKDPC dpc, PVOID ctx, PVOID a1, PVOID a2)
{
    DPC_EXT *ext = ctx;
    (void)dpc; (void)a1; (void)a2;
    InterlockedIncrement(&ext->counter);
    KeSetEvent(&ext->timerDone, IO_NO_INCREMENT, FALSE);
}

static VOID PendDpc(PKDPC dpc, PVOID ctx, PVOID a1, PVOID a2)
{
    DPC_EXT *ext = ctx;
    PIRP irp = ext->pending;
    (void)dpc; (void)a1; (void)a2;
    if (irp) {
        *(ULONG *)irp->AssociatedIrp.SystemBuffer = PEND_MAGIC;
        irp->IoStatus.Status = STATUS_SUCCESS;
        irp->IoStatus.Information = sizeof(ULONG);
        ext->pending = NULL;
        IoCompleteRequest(irp, IO_NO_INCREMENT);       /* async completion from DPC context */
    }
}

static NTSTATUS DpcCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    (void)dev;
    irp->IoStatus.Status = STATUS_SUCCESS;
    irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

static NTSTATUS DpcControl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    DPC_EXT *ext = dev->DeviceExtension;
    LARGE_INTEGER due;
    if (sp->Parameters.DeviceIoControl.IoControlCode != IOCTL_SHZ_PEND ||
        sp->Parameters.DeviceIoControl.OutputBufferLength < sizeof(ULONG)) {
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    ext->pending = irp;
    IoMarkIrpPending(irp);
    due.QuadPart = -(20LL * 10000);                    /* 20 ms */
    KeSetTimer(&ext->pendTimer, due, &ext->pendDpc);
    return STATUS_PENDING;                             /* completed later by PendDpc */
}

VOID DpcUnload(PDRIVER_OBJECT drv)
{
    UNICODE_STRING dos;
    RtlInitUnicodeString(&dos, L"\\DosDevices\\ShzDpc");
    IoDeleteSymbolicLink(&dos);
    if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
    DbgPrint("ShzDpc: unloaded\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNICODE_STRING name, dos;
    PDEVICE_OBJECT dev;
    DPC_EXT *ext;
    NTSTATUS st;
    HANDLE hThread = NULL;
    LARGE_INTEGER due, wait;
    (void)reg;

    RtlInitUnicodeString(&name, L"\\Device\\ShzDpc");
    st = IoCreateDevice(drv, sizeof(DPC_EXT), &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    ext = dev->DeviceExtension;
    g_ext = ext;
    RtlZeroMemory(ext, sizeof(*ext));
    KeInitializeEvent(&ext->threadDone, NotificationEvent, FALSE);
    KeInitializeEvent(&ext->timerDone, NotificationEvent, FALSE);
    KeInitializeDpc(&ext->dpc, TimerDpc, ext);
    KeInitializeDpc(&ext->pendDpc, PendDpc, ext);
    KeInitializeTimer(&ext->timer);
    KeInitializeTimer(&ext->pendTimer);

    RtlInitUnicodeString(&dos, L"\\DosDevices\\ShzDpc");
    IoCreateSymbolicLink(&dos, &name);
    drv->MajorFunction[IRP_MJ_CREATE] = DpcCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE] = DpcCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DpcControl;
    drv->DriverUnload = DpcUnload;
    dev->Flags |= DO_BUFFERED_IO;
    dev->Flags &= ~DO_DEVICE_INITIALIZING;

    /* 1) system thread signals threadDone */
    st = PsCreateSystemThread(&hThread, THREAD_ALL_ACCESS, NULL, NULL, NULL, WorkerThread, ext);
    if (!NT_SUCCESS(st)) { DbgPrint("ShzDpc: PsCreateSystemThread failed %x\n", st); return st; }
    wait.QuadPart = -(5LL * 1000 * 10000);            /* 5 s */
    st = KeWaitForSingleObject(&ext->threadDone, Executive, KernelMode, FALSE, &wait);
    if (st != STATUS_SUCCESS) { DbgPrint("ShzDpc: thread wait %x\n", st); return STATUS_UNSUCCESSFUL; }

    /* 2) timer -> DPC increments the counter and signals timerDone */
    due.QuadPart = -(30LL * 10000);                   /* 30 ms */
    KeSetTimer(&ext->timer, due, &ext->dpc);
    st = KeWaitForSingleObject(&ext->timerDone, Executive, KernelMode, FALSE, &wait);
    if (st != STATUS_SUCCESS) { DbgPrint("ShzDpc: timer wait %x\n", st); return STATUS_UNSUCCESSFUL; }
    if (ext->counter < 1) { DbgPrint("ShzDpc: DPC did not run\n"); return STATUS_UNSUCCESSFUL; }

    DbgPrint("ShzDpc: DriverEntry OK (thread + timer + DPC), counter=%d\n", (int)ext->counter);
    return STATUS_SUCCESS;
}
