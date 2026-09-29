/* SPDX-License-Identifier: GPL-2.0-only
 * ShzPci: an unmodified WDM driver that enumerates the PCI bus through the HAL, finds QEMU's
 * 'edu' device (1234:11e8), maps its BAR0 with MmMapIoSpace, reads its identification register,
 * connects its interrupt with IoConnectInterrupt over the kernel's IRQ layer and raises one
 * interrupt to confirm the ISR fires. Results are reported through an IOCTL and DbgPrint. When
 * no edu device is present the driver still loads (DriverEntry returns success) and reports
 * found=0, so it is harmless in runs without the device.
 */
#include <ddk/ntddk.h>          /* HalGetBusData / PCIConfiguration live here; it pulls in wdm.h */

/* Classic HAL bus/interrupt prototypes (some are absent from newer mingw DDK headers). */
NTHALAPI ULONG NTAPI HalGetBusData(BUS_DATA_TYPE, ULONG, ULONG, PVOID, ULONG);
NTHALAPI ULONG NTAPI HalGetInterruptVector(INTERFACE_TYPE, ULONG, ULONG, ULONG, PKIRQL, PKAFFINITY);

#define EDU_VENDOR 0x1234
#define EDU_DEVICE 0x11e8
#define IOCTL_SHZ_PCIINFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

/* edu MMIO registers */
#define EDU_IDENT   0x00
#define EDU_INTR_STATUS 0x24
#define EDU_INTR_RAISE  0x60
#define EDU_INTR_ACK    0x64

typedef struct {
    ULONG found, ident;
    volatile LONG isr;
    volatile ULONG *bar;
    PKINTERRUPT interrupt;
    KEVENT irqEvent;
} PCI_EXT;

static PCI_EXT *g_ext;

static BOOLEAN EduIsr(PKINTERRUPT interrupt, PVOID ctx)
{
    PCI_EXT *ext = ctx;
    ULONG status;
    (void)interrupt;
    if (!ext->bar) return FALSE;
    status = READ_REGISTER_ULONG((PULONG)(ext->bar + EDU_INTR_STATUS / 4));
    if (!status) return FALSE;
    WRITE_REGISTER_ULONG((PULONG)(ext->bar + EDU_INTR_ACK / 4), status);   /* acknowledge */
    InterlockedIncrement(&ext->isr);
    KeSetEvent(&ext->irqEvent, IO_NO_INCREMENT, FALSE);
    return TRUE;
}

static NTSTATUS PciControl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    PCI_EXT *ext = dev->DeviceExtension;
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_SHZ_PCIINFO &&
        sp->Parameters.DeviceIoControl.OutputBufferLength >= 12) {
        ULONG *out = irp->AssociatedIrp.SystemBuffer;
        out[0] = ext->found; out[1] = ext->ident; out[2] = (ULONG)ext->isr;
        info = 12; st = STATUS_SUCCESS;
    }
    irp->IoStatus.Status = st;
    irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}
static NTSTATUS PciCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    (void)dev; irp->IoStatus.Status = STATUS_SUCCESS; irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT); return STATUS_SUCCESS;
}

VOID PciUnload(PDRIVER_OBJECT drv)
{
    UNICODE_STRING dos;
    if (g_ext && g_ext->interrupt) IoDisconnectInterrupt(g_ext->interrupt);
    RtlInitUnicodeString(&dos, L"\\DosDevices\\ShzPci");
    IoDeleteSymbolicLink(&dos);
    if (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
    DbgPrint("ShzPci: unloaded\n");
}

static int find_edu(ULONG *slot_out, UCHAR cfg[64])
{
    ULONG slot;
    for (slot = 0; slot < 32; ++slot) {
        UCHAR c[64];
        ULONG n = HalGetBusData(PCIConfiguration, 0, slot, c, sizeof c);
        USHORT ven, dev;
        if (n < 4) continue;
        ven = (USHORT)(c[0] | (c[1] << 8));
        dev = (USHORT)(c[2] | (c[3] << 8));
        if (ven == EDU_VENDOR && dev == EDU_DEVICE) {
            RtlCopyMemory(cfg, c, sizeof c);
            *slot_out = slot;
            return 1;
        }
    }
    return 0;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNICODE_STRING name, dos;
    PDEVICE_OBJECT dev;
    PCI_EXT *ext;
    NTSTATUS st;
    UCHAR cfg[64];
    ULONG slot = 0;
    (void)reg;

    RtlInitUnicodeString(&name, L"\\Device\\ShzPci");
    st = IoCreateDevice(drv, sizeof(PCI_EXT), &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    ext = dev->DeviceExtension;
    g_ext = ext;
    RtlZeroMemory(ext, sizeof(*ext));
    KeInitializeEvent(&ext->irqEvent, NotificationEvent, FALSE);
    RtlInitUnicodeString(&dos, L"\\DosDevices\\ShzPci");
    IoCreateSymbolicLink(&dos, &name);
    drv->MajorFunction[IRP_MJ_CREATE] = PciCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE] = PciCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PciControl;
    drv->DriverUnload = PciUnload;
    dev->Flags |= DO_BUFFERED_IO;
    dev->Flags &= ~DO_DEVICE_INITIALIZING;

    if (!find_edu(&slot, cfg)) {
        DbgPrint("ShzPci: no edu device on PCI bus 0\n");
        return STATUS_SUCCESS;                          /* load anyway; found stays 0 */
    }
    ext->found = 1;
    {
        ULONG bar0 = *(ULONG *)(cfg + 0x10) & ~0xFul;
        PHYSICAL_ADDRESS pa; pa.QuadPart = bar0;
        USHORT cmd = (USHORT)(cfg[4] | (cfg[5] << 8));
        UCHAR irqline = cfg[0x3c];
        KIRQL irql; KAFFINITY aff;
        ULONG vector;
        cmd |= 0x2 | 0x4;                                /* memory space + bus master */
        cmd &= ~0x400;                                   /* ensure INTx enabled */
        HalSetBusDataByOffset(PCIConfiguration, 0, slot, &cmd, 0x04, 2);
        ext->bar = (volatile ULONG *)MmMapIoSpace(pa, 0x100000, MmNonCached);
        if (!ext->bar) { DbgPrint("ShzPci: MmMapIoSpace failed\n"); return STATUS_SUCCESS; }
        ext->ident = READ_REGISTER_ULONG((PULONG)(ext->bar + EDU_IDENT / 4));
        DbgPrint("ShzPci: edu at slot %u bar0=%x ident=%x irq=%u\n", slot, bar0, ext->ident, irqline);
        vector = HalGetInterruptVector(Internal, 0, irqline, irqline, &irql, &aff);
        st = IoConnectInterrupt(&ext->interrupt, EduIsr, ext, NULL, vector, irql, irql,
                                LevelSensitive, TRUE, aff, FALSE);
        if (NT_SUCCESS(st)) {
            LARGE_INTEGER wait;
            WRITE_REGISTER_ULONG((PULONG)(ext->bar + EDU_INTR_RAISE / 4), 1);   /* raise one interrupt */
            wait.QuadPart = -(200LL * 10000);            /* 200 ms */
            KeWaitForSingleObject(&ext->irqEvent, Executive, KernelMode, FALSE, &wait);
            DbgPrint("ShzPci: interrupt connected on vector %u, ISR fired %d time(s)\n", vector, (int)ext->isr);
        } else {
            DbgPrint("ShzPci: IoConnectInterrupt failed %x\n", st);
        }
    }
    return STATUS_SUCCESS;
}
