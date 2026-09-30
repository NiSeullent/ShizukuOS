/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the I/O manager. Device and symbolic-link namespace
 * (\Device, \DosDevices/\??), DEVICE_OBJECT/DRIVER_OBJECT plumbing, the IRP model with a real
 * IoCallDriver stack and IoCompleteRequest completion walk, synchronous IRP builders,
 * interrupt connection over the kernel's irq_register, and the user-mode reachability path
 * (NtCreateFile("\\??\\Name") -> IRP_MJ_CREATE, NtDeviceIoControlFile/NtReadFile/NtWriteFile
 * -> buffered/neither IRPs with async completion when the driver pends). Also the ntdrv
 * syscall router sys_ext_ntdrv() and NtLoadDriver.
 */
#include "ntdrv.h"
#include "fs.h"
#include "registry.h"
#include "pci.h"
#include "ntsys.h"

#define SL_PENDING_RETURNED 0x01
#define SL_INVOKE_ON_CANCEL 0x20
#define SL_INVOKE_ON_SUCCESS 0x40
#define SL_INVOKE_ON_ERROR 0x80
#define IO_TYPE_IRP 6
#define NT_SUCCESS(s) ((int32_t)(s) >= 0)

#define OB_DEVICE 0x50                          /* kobject type for a user handle onto a device */

static ntdrv_devnode_t *devnodes;
static ntdrv_symlink_t *symlinks;
ntdrv_devnode_t *ntdrv_devnodes(void) { return devnodes; }

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);

/* ---------------------------------------------------------------- namespace */
void ntdrv_register_device(DEVICE_OBJECT *dev, ntdrv_driver_t *owner) { (void)dev; (void)owner; }

DEVICE_OBJECT *ntdrv_find_device(const char *name)
{
    ntdrv_devnode_t *n;
    for (n = devnodes; n; n = n->next)
        if (!strcmp(n->name, name)) return n->dev;
    return 0;
}
/* "\??\X" and "\DosDevices\X" name the same object-manager entry: reduce both to the leaf "X". */
static const char *dos_leaf(const char *n)
{
    if (!strncmp(n, "\\??\\", 4)) return n + 4;
    if (!strncmp(n, "\\DosDevices\\", 12)) return n + 12;
    if (!strncmp(n, "\\Global??\\", 10)) return n + 10;
    return n;
}
DEVICE_OBJECT *ntdrv_resolve_symlink(const char *dosname)
{
    ntdrv_symlink_t *s;
    const char *leaf = dos_leaf(dosname);
    for (s = symlinks; s; s = s->next)
        if (!strcmp(s->link, leaf)) return ntdrv_find_device(s->target);
    return 0;
}

/* ---------------------------------------------------------------- IoCreateDevice etc. */
NTSTATUS NTAPI IoCreateDevice(DRIVER_OBJECT *drv, uint32_t ext_size, UNICODE_STRING *name, uint32_t type,
                              uint32_t chars, uint8_t exclusive, DEVICE_OBJECT **out)
{
    DEVICE_OBJECT *dev = kzalloc(SZ_DEV + ext_size);
    ntdrv_devnode_t *node;
    (void)exclusive;
    if (!dev) return STATUS_INSUFFICIENT_RESOURCES;
    dev->Type = 3;
    dev->Size = (uint16_t)(SZ_DEV + ext_size);
    dev->ReferenceCount = 1;
    dev->DriverObject = drv;
    dev->DeviceType = type;
    dev->Characteristics = chars;
    dev->StackSize = 1;
    dev->Flags = DO_DEVICE_INITIALIZING;
    dev->DeviceExtension = ext_size ? (uint8_t *)dev + SZ_DEV : 0;
    dev->NextDevice = drv->DeviceObject;
    drv->DeviceObject = dev;
    if (name && name->Length) {
        node = kzalloc(sizeof *node);
        if (!node) { kfree(dev); return STATUS_INSUFFICIENT_RESOURCES; }
        ntdrv_wide_to_ascii(name->Buffer, name->Length / 2, node->name, sizeof node->name);
        node->dev = dev;
        node->owner = ntdrv_current_driver();
        node->next = devnodes; devnodes = node;
    }
    *out = dev;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI IoCreateDeviceSecure(DRIVER_OBJECT *drv, uint32_t ext, UNICODE_STRING *name, uint32_t type,
                                    uint32_t chars, uint8_t excl, void *sddl, void *guid, DEVICE_OBJECT **out)
{ (void)sddl; (void)guid; return IoCreateDevice(drv, ext, name, type, chars, excl, out); }

void NTAPI IoDeleteDevice(DEVICE_OBJECT *dev)
{
    ntdrv_devnode_t **pp = &devnodes;
    DRIVER_OBJECT *drv = dev->DriverObject;
    if (drv) {                                                  /* unlink from the driver's device chain */
        DEVICE_OBJECT **dp = &drv->DeviceObject;
        while (*dp && *dp != dev) dp = &(*dp)->NextDevice;
        if (*dp) *dp = dev->NextDevice;
    }
    while (*pp) { if ((*pp)->dev == dev) { ntdrv_devnode_t *d = *pp; *pp = d->next; kfree(d); } else pp = &(*pp)->next; }
    kfree(dev);
}

NTSTATUS NTAPI IoCreateSymbolicLink(UNICODE_STRING *link, UNICODE_STRING *target)
{
    ntdrv_symlink_t *s = kzalloc(sizeof *s);
    char full[96];
    const char *leaf;
    unsigned i;
    if (!s) return STATUS_INSUFFICIENT_RESOURCES;
    ntdrv_wide_to_ascii(link->Buffer, link->Length / 2, full, sizeof full);
    leaf = dos_leaf(full);                                     /* store by leaf so \??\ and \DosDevices\ both match */
    for (i = 0; leaf[i] && i + 1 < sizeof s->link; ++i) s->link[i] = leaf[i];
    s->link[i] = 0;
    ntdrv_wide_to_ascii(target->Buffer, target->Length / 2, s->target, sizeof s->target);
    s->next = symlinks; symlinks = s;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI IoDeleteSymbolicLink(UNICODE_STRING *link)
{
    char name[96];
    ntdrv_symlink_t **pp = &symlinks;
    const char *leaf;
    ntdrv_wide_to_ascii(link->Buffer, link->Length / 2, name, sizeof name);
    leaf = dos_leaf(name);
    while (*pp) { if (!strcmp((*pp)->link, leaf)) { ntdrv_symlink_t *s = *pp; *pp = s->next; kfree(s); } else pp = &(*pp)->next; }
    return STATUS_SUCCESS;
}

DEVICE_OBJECT *NTAPI IoAttachDeviceToDeviceStack(DEVICE_OBJECT *src, DEVICE_OBJECT *target)
{
    DEVICE_OBJECT *top = target;
    while (top->AttachedDevice) top = top->AttachedDevice;
    top->AttachedDevice = src;
    src->StackSize = (int8_t)(top->StackSize + 1);
    return top;
}
void NTAPI IoDetachDevice(DEVICE_OBJECT *target)
{
    /* detach the device attached on top of `target` */
    target->AttachedDevice = 0;
}
DEVICE_OBJECT *NTAPI IoGetAttachedDeviceReference(DEVICE_OBJECT *d) { while (d->AttachedDevice) d = d->AttachedDevice; return d; }
DEVICE_OBJECT *NTAPI IoGetAttachedDevice(DEVICE_OBJECT *d) { while (d->AttachedDevice) d = d->AttachedDevice; return d; }

/* ---------------------------------------------------------------- IRP engine */
static IO_STACK_LOCATION *stack_array(IRP *irp) { return (IO_STACK_LOCATION *)((uint8_t *)irp + SZ_IRP); }

void NTAPI IoInitializeIrp(IRP *irp, uint16_t size, uint8_t stackcount)
{
    memset(irp, 0, size);
    irp->Type = IO_TYPE_IRP;
    irp->Size = size;
    irp->StackCount = (int8_t)stackcount;
    irp->CurrentLocation = (int8_t)(stackcount + 1);
    irp->Tail.Overlay.CurrentStackLocation = stack_array(irp) + stackcount;
}
IRP *NTAPI IoAllocateIrp(uint8_t stackcount, uint8_t charge)
{
    uint16_t size = (uint16_t)(SZ_IRP + (uint32_t)stackcount * SZ_STK);
    IRP *irp = kmalloc(size);
    (void)charge;
    if (!irp) return 0;
    IoInitializeIrp(irp, size, stackcount);
    return irp;
}
void NTAPI IoFreeIrp(IRP *irp) { kfree(irp); }
IO_STACK_LOCATION *NTAPI IoGetNextIrpStackLocationF(IRP *irp) { return irp->Tail.Overlay.CurrentStackLocation - 1; }

NTSTATUS NTAPI IofCallDriver(DEVICE_OBJECT *dev, IRP *irp)
{
    IO_STACK_LOCATION *stk;
    PDRIVER_DISPATCH disp;
    if (irp->CurrentLocation <= 0) kpanic("IoCallDriver: IRP stack overflow");
    irp->CurrentLocation--;
    irp->Tail.Overlay.CurrentStackLocation--;
    stk = irp->Tail.Overlay.CurrentStackLocation;
    stk->DeviceObject = dev;
    disp = dev->DriverObject->MajorFunction[stk->MajorFunction];
    if (!disp) { irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST; return STATUS_INVALID_DEVICE_REQUEST; }
    return disp(dev, irp);
}

void NTAPI IofCompleteRequest(IRP *irp, uint8_t boost)
{
    (void)boost;
    for (;;) {
        IO_STACK_LOCATION *stk = irp->Tail.Overlay.CurrentStackLocation;
        int top = irp->CurrentLocation > irp->StackCount;
        PIO_COMPLETION_ROUTINE cr = top ? 0 : stk->CompletionRoutine;
        uint8_t control = top ? 0 : stk->Control;
        DEVICE_OBJECT *setter_dev;
        /* advance to the caller's location */
        irp->CurrentLocation++;
        irp->Tail.Overlay.CurrentStackLocation++;
        setter_dev = irp->CurrentLocation <= irp->StackCount ? irp->Tail.Overlay.CurrentStackLocation->DeviceObject : 0;
        if (cr) {
            int32_t s = irp->IoStatus.Status;
            int invoke = (NT_SUCCESS(s) && (control & SL_INVOKE_ON_SUCCESS)) ||
                         (!NT_SUCCESS(s) && (control & SL_INVOKE_ON_ERROR)) ||
                         (irp->Cancel && (control & SL_INVOKE_ON_CANCEL));
            if (invoke) {
                NTSTATUS r = cr(setter_dev, irp, stk->Context);
                if (r == STATUS_MORE_PROCESSING_REQUIRED) return;
            }
        }
        if (irp->CurrentLocation > irp->StackCount + 1) break;
    }
    /* final completion */
    if (irp->UserIosb) *irp->UserIosb = irp->IoStatus;
    if ((irp->Flags & IRP_INPUT_OPERATION) && irp->AssociatedIrp.SystemBuffer && irp->UserBuffer) {
        uint64_t n = irp->IoStatus.Information;
        memcpy(irp->UserBuffer, irp->AssociatedIrp.SystemBuffer, n);   /* copy buffered output back */
    }
    if ((irp->Flags & IRP_DEALLOCATE_BUFFER) && irp->AssociatedIrp.SystemBuffer) {
        kfree(irp->AssociatedIrp.SystemBuffer);
        irp->AssociatedIrp.SystemBuffer = 0;
    }
    if (irp->UserEvent) KeSetEvent(irp->UserEvent, 0, 0);
}

NTSTATUS NTAPI ntdrv_default_dispatch(DEVICE_OBJECT *dev, IRP *irp)
{
    (void)dev;
    irp->IoStatus.Status = STATUS_SUCCESS;                      /* create/close/cleanup default: succeed */
    irp->IoStatus.Information = 0;
    IofCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
uint32_t NTAPI IoGetRemainingStackSize(void) { return 0x4000; }
DEVICE_OBJECT *NTAPI IoGetRelatedDeviceObject(FILE_OBJECT *f) { return f ? f->DeviceObject : 0; }
IRP *NTAPI IoBuildSynchronousFsdRequest(uint32_t mj, DEVICE_OBJECT *dev, void *buf, uint32_t len, LARGE_INTEGER *off,
                                        void *event, IO_STATUS_BLOCK *iosb);

/* ---------------------------------------------------------------- synchronous engine (kernel buffers) */
struct sync_irp { KEVENT ev; IO_STATUS_BLOCK iosb; };

static int32_t run_sync(DEVICE_OBJECT *dev, IRP *irp, struct sync_irp *s, uint64_t *info)
{
    NTSTATUS st;
    irp->UserEvent = &s->ev;
    irp->UserIosb = &s->iosb;
    KeInitializeEvent(&s->ev, 0 /* Notification */, 0);
    st = IofCallDriver(dev, irp);
    if (st == STATUS_PENDING) {
        int64_t infinite = 0;
        KeWaitForSingleObject(&s->ev, 0, 0, 0, 0);
        (void)infinite;
    }
    if (info) *info = s->iosb.Information;
    st = s->iosb.Status;
    IoFreeIrp(irp);
    return st;
}

int32_t ntdrv_send_irp_sync(DEVICE_OBJECT *dev, IRP *irp, uint64_t *info)
{
    struct sync_irp s;
    return run_sync(dev, irp, &s, info);
}

int32_t ntdrv_device_control(DEVICE_OBJECT *dev, uint32_t ioctl, const void *in, uint32_t inlen,
                             void *out, uint32_t outlen, int internal, uint64_t *info)
{
    struct sync_irp s;
    IRP *irp = IoAllocateIrp((uint8_t)dev->StackSize, 0);
    IO_STACK_LOCATION *stk;
    uint32_t method = METHOD_FROM_CTL_CODE(ioctl);
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;
    stk = irp->Tail.Overlay.CurrentStackLocation - 1;
    stk->MajorFunction = (uint8_t)(internal ? IRP_MJ_INTERNAL_DEVICE_CONTROL : IRP_MJ_DEVICE_CONTROL);
    stk->MinorFunction = 0;
    stk->Parameters.DeviceIoControl.IoControlCode = ioctl;
    stk->Parameters.DeviceIoControl.InputBufferLength = inlen;
    stk->Parameters.DeviceIoControl.OutputBufferLength = outlen;
    if (method == METHOD_BUFFERED) {
        uint32_t max = inlen > outlen ? inlen : outlen;
        void *sysbuf = max ? kzalloc(max) : 0;
        if (max && !sysbuf) { IoFreeIrp(irp); return STATUS_INSUFFICIENT_RESOURCES; }
        if (in && inlen) memcpy(sysbuf, in, inlen);
        irp->AssociatedIrp.SystemBuffer = sysbuf;
        irp->UserBuffer = out;
        irp->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | (outlen ? IRP_INPUT_OPERATION : 0);
    } else if (method == METHOD_NEITHER) {
        stk->Parameters.DeviceIoControl.Type3InputBuffer = (void *)in;
        irp->UserBuffer = out;
    } else {                                                    /* IN/OUT DIRECT: input buffered, output via MDL */
        void *sysbuf = inlen ? kzalloc(inlen) : 0;
        if (in && inlen) memcpy(sysbuf, in, inlen);
        irp->AssociatedIrp.SystemBuffer = sysbuf;
        irp->Flags |= IRP_DEALLOCATE_BUFFER;
        if (out && outlen) irp->MdlAddress = IoAllocateMdl(out, outlen, 0, 0, 0);
    }
    return run_sync(dev, irp, &s, info);
}

int32_t ntdrv_read_write(DEVICE_OBJECT *dev, int write, void *buf, uint32_t len, uint64_t offset, uint64_t *info)
{
    struct sync_irp s;
    IRP *irp = IoAllocateIrp((uint8_t)dev->StackSize, 0);
    IO_STACK_LOCATION *stk;
    void *sysbuf;
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;
    stk = irp->Tail.Overlay.CurrentStackLocation - 1;
    stk->MajorFunction = (uint8_t)(write ? IRP_MJ_WRITE : IRP_MJ_READ);
    stk->Parameters.Read.Length = len;
    stk->Parameters.Read.ByteOffset.QuadPart = (int64_t)offset;
    sysbuf = len ? kzalloc(len) : 0;
    if (len && !sysbuf) { IoFreeIrp(irp); return STATUS_INSUFFICIENT_RESOURCES; }
    if (write && buf && len) memcpy(sysbuf, buf, len);
    irp->AssociatedIrp.SystemBuffer = sysbuf;
    irp->UserBuffer = buf;
    irp->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | (write ? 0 : IRP_INPUT_OPERATION);
    return run_sync(dev, irp, &s, info);
}

int32_t ntdrv_open_close_device(DEVICE_OBJECT *dev, int close)
{
    struct sync_irp s;
    IRP *irp = IoAllocateIrp((uint8_t)dev->StackSize, 0);
    IO_STACK_LOCATION *stk;
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;
    stk = irp->Tail.Overlay.CurrentStackLocation - 1;
    stk->MajorFunction = (uint8_t)(close ? IRP_MJ_CLOSE : IRP_MJ_CREATE);
    return run_sync(dev, irp, &s, 0);
}

IRP *NTAPI IoBuildDeviceIoControlRequest(uint32_t ioctl, DEVICE_OBJECT *dev, void *in, uint32_t inlen,
                                         void *out, uint32_t outlen, uint8_t internal, void *event,
                                         IO_STATUS_BLOCK *iosb)
{
    IRP *irp = IoAllocateIrp((uint8_t)dev->StackSize, 0);
    IO_STACK_LOCATION *stk;
    uint32_t method = METHOD_FROM_CTL_CODE(ioctl);
    if (!irp) return 0;
    stk = irp->Tail.Overlay.CurrentStackLocation - 1;
    stk->MajorFunction = (uint8_t)(internal ? IRP_MJ_INTERNAL_DEVICE_CONTROL : IRP_MJ_DEVICE_CONTROL);
    stk->Parameters.DeviceIoControl.IoControlCode = ioctl;
    stk->Parameters.DeviceIoControl.InputBufferLength = inlen;
    stk->Parameters.DeviceIoControl.OutputBufferLength = outlen;
    if (method == METHOD_BUFFERED) {
        uint32_t max = inlen > outlen ? inlen : outlen;
        void *sysbuf = max ? kzalloc(max) : 0;
        if (in && inlen) memcpy(sysbuf, in, inlen);
        irp->AssociatedIrp.SystemBuffer = sysbuf;
        irp->UserBuffer = out;
        irp->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | (outlen ? IRP_INPUT_OPERATION : 0);
    } else if (method == METHOD_NEITHER) {
        stk->Parameters.DeviceIoControl.Type3InputBuffer = in;
        irp->UserBuffer = out;
    }
    irp->UserEvent = event;
    irp->UserIosb = iosb;
    return irp;
}
IRP *NTAPI IoBuildSynchronousFsdRequest(uint32_t mj, DEVICE_OBJECT *dev, void *buf, uint32_t len, LARGE_INTEGER *off,
                                        void *event, IO_STATUS_BLOCK *iosb)
{
    IRP *irp = IoAllocateIrp((uint8_t)dev->StackSize, 0);
    IO_STACK_LOCATION *stk;
    if (!irp) return 0;
    stk = irp->Tail.Overlay.CurrentStackLocation - 1;
    stk->MajorFunction = (uint8_t)mj;
    stk->Parameters.Read.Length = len;
    if (off) stk->Parameters.Read.ByteOffset = *off;
    if (dev->Flags & DO_BUFFERED_IO) {
        void *sysbuf = len ? kzalloc(len) : 0;
        if (mj == IRP_MJ_WRITE && buf && len) memcpy(sysbuf, buf, len);
        irp->AssociatedIrp.SystemBuffer = sysbuf;
        irp->UserBuffer = buf;
        irp->Flags |= IRP_BUFFERED_IO | IRP_DEALLOCATE_BUFFER | (mj == IRP_MJ_READ ? IRP_INPUT_OPERATION : 0);
    } else if (dev->Flags & DO_DIRECT_IO) {
        irp->MdlAddress = IoAllocateMdl(buf, len, 0, 0, 0);
    } else {
        irp->UserBuffer = buf;
    }
    irp->UserEvent = event;
    irp->UserIosb = iosb;
    return irp;
}

/* ---------------------------------------------------------------- PCI function ownership */
#ifdef SHZ_STANDALONE
/* Without a PnP start IRP the host decides ownership from what a driver does: mapping a region inside a function's
 * memory BAR (MmMapIoSpace) or connecting the interrupt of its legacy line makes that function the driver's. The
 * binding is recorded with pci_claim("ntdrv:<service>") so user mode (T_GUI_STATUS) lists it like a native driver. */
static struct { pci_dev_t dev; ntdrv_driver_t *drv; } owned[16];
static unsigned n_owned;

static int same_fn(const pci_dev_t *a, const pci_dev_t *b) { return a->bus == b->bus && a->dev == b->dev && a->fn == b->fn; }

static void own_function(const pci_dev_t *d, ntdrv_driver_t *drv)
{
    unsigned i;
    if (!drv) return;
    for (i = 0; i < n_owned; ++i)
        if (same_fn(&owned[i].dev, d)) return;
    if (n_owned < 16) { owned[n_owned].dev = *d; owned[n_owned++].drv = drv; }
    if (!drv->claim[0]) {
        static const char pfx[] = "ntdrv:";
        unsigned k = 0, j;
        for (j = 0; pfx[j]; ++j) drv->claim[k++] = pfx[j];
        for (j = 0; drv->name[j] && k + 1 < sizeof drv->claim; ++j) drv->claim[k++] = drv->name[j];
        drv->claim[k] = 0;
    }
    pci_claim(d, drv->claim);                                  /* the string lives in the driver record */
    kprintf("K64 ntdrv: %s owns PCI %x:%x.%x (%x:%x)\n", drv->name, d->bus, d->dev, d->fn, d->vendor, d->device);
}

void ntdrv_pci_note_mmio(uint64_t pa, uint64_t size)
{
    pci_dev_t all[32];
    const unsigned n = pci_enumerate(all, 32);
    unsigned i, b, best = ~0u;
    uint64_t best_base = 0;
    for (i = 0; i < n; ++i) {
        if ((pci_cfg_read32(&all[i], 0x0c) >> 16 & 0x7f) != 0) continue;          /* type-0 header: 6 BARs */
        for (b = 0; b < 6; ++b) {
            const uint32_t v = pci_cfg_read32(&all[i], 0x10 + 4 * b);          /* read only: no size probe on a live device */
            const int mem64 = !(v & 1) && ((v >> 1) & 3) == 2;
            uint64_t base;
            if (v & 1) continue;
            base = (v & ~0xfull) | (mem64 && b < 5 ? (uint64_t)pci_cfg_read32(&all[i], 0x14 + 4 * b) << 32 : 0);
            if (mem64) ++b;
            /* a BAR is naturally aligned to its size: [base, base + lowest set bit) bounds it from above */
            if (base && base <= pa && pa + size <= base + (base & (~base + 1)) && base >= best_base) { best = i; best_base = base; }
        }
    }
    if (best != ~0u) own_function(&all[best], ntdrv_current_driver());
}

static int function_for_line(unsigned line, pci_dev_t *out)
{
    ntdrv_driver_t *cur = ntdrv_current_driver();
    pci_dev_t all[32];
    unsigned i, n;
    for (i = 0; i < n_owned; ++i)                                               /* the caller's own function first */
        if (owned[i].drv == cur && owned[i].dev.irq_line == line) { *out = owned[i].dev; return 1; }
    n = pci_enumerate(all, 32);
    for (i = 0; i < n; ++i)                                                     /* else an unclaimed function on that line */
        if (all[i].irq_line == line && (pci_cfg_read32(&all[i], 0x3c) >> 8 & 0xff) && !pci_claimed_by(&all[i])) {
            own_function(&all[i], cur);
            *out = all[i];
            return 1;
        }
    return 0;
}

void ntdrv_release_claims(ntdrv_driver_t *d)
{
    unsigned i = 0;
    while (i < n_owned) {
        if (owned[i].drv == d) {
            pci_claim(&owned[i].dev, 0);
            kprintf("K64 ntdrv: %s released PCI %x:%x.%x\n", d->name, owned[i].dev.bus, owned[i].dev.dev, owned[i].dev.fn);
            owned[i] = owned[--n_owned];
        } else ++i;
    }
}
unsigned ntdrv_claimed_functions(ntdrv_driver_t *d, pci_dev_t *out, unsigned max)
{
    unsigned i, n = 0;
    for (i = 0; i < n_owned && n < max; ++i)
        if (owned[i].drv == d) out[n++] = owned[i].dev;
    return n;
}

/* Enum\PCI\<hwid>\B<bus>D<dev>F<fn> (shzpnp's instance id for a function of the Kernel64 bus scan): parse it. */
static int hexval(uint16_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int parse_instance(const uint16_t *w, unsigned n, unsigned *bus, unsigned *dev, unsigned *fn)
{
    int a, b, c, d2, e;
    unsigned i, f = 0;
    if (n < 8 || w[0] != 'B' || w[3] != 'D' || w[6] != 'F') return 0;
    a = hexval(w[1]); b = hexval(w[2]); c = hexval(w[4]); d2 = hexval(w[5]);
    if (a < 0 || b < 0 || c < 0 || d2 < 0) return 0;
    for (i = 7; i < n; ++i) { e = hexval(w[i]); if (e < 0) return 0; f = f * 16 + (unsigned)e; }
    *bus = (unsigned)(a * 16 + b); *dev = (unsigned)(c * 16 + d2); *fn = f;
    return 1;
}
static int wide_eq_ascii_ci(const uint16_t *w, unsigned n, const char *a)
{
    unsigned i;
    for (i = 0; i < n; ++i) {
        if (!a[i]) return 0;
        if (reg_upcase_char(w[i]) != reg_upcase_char((uint16_t)(uint8_t)a[i])) return 0;
    }
    return a[n] == 0;
}
void ntdrv_bind_enum(ntdrv_driver_t *d)
{
    static const uint16_t path[] = { 'M','a','c','h','i','n','e','\\','S','y','s','t','e','m','\\','C','u','r','r','e','n','t','C','o','n','t','r','o','l',
                                     'S','e','t','\\','E','n','u','m','\\','P','C','I' };
    static const uint16_t svc[] = { 'S','e','r','v','i','c','e' };
    regkey_t *pci, *hw, *inst;
    uint32_t i, j;
    pci_dev_t all[32];
    unsigned n = 0, scanned = 0, k, bound = 0;
    reg_lock();
    if (reg_resolve(reg_root(), path, sizeof path / 2, 0, 0, 1, 0, 0, &pci, 0)) { reg_unlock(); return; }
    for (i = 0; (hw = reg_nth_child(pci, i)) != 0; ++i) {
        for (j = 0; (inst = reg_nth_child(hw, j)) != 0; ++j) {
            regval_t *v = reg_find_value(inst, svc, 7);
            unsigned chars, bus, dev, fn;
            const uint16_t *data;
            if (!v || (v->type != REG_SZ && v->type != REG_EXPAND_SZ)) continue;
            data = (const uint16_t *)regval_data(v);
            chars = v->data_len / 2;
            while (chars && !data[chars - 1]) --chars;
            if (!wide_eq_ascii_ci(data, chars, d->name)) continue;
            if (!parse_instance(regkey_name(inst), inst->name_len, &bus, &dev, &fn)) continue;   /* SHZnnnn: no function */
            if (!scanned) { n = pci_enumerate(all, 32); scanned = 1; }
            for (k = 0; k < n; ++k)
                if (all[k].bus == bus && all[k].dev == dev && all[k].fn == fn) {
                    char ipath[128];                           /* PCI\<hwid>\B..D..F.., the devnode's instance path */
                    unsigned m = 0, q;
                    static const char pfx[] = "PCI\\";
                    for (q = 0; pfx[q]; ++q) ipath[m++] = pfx[q];
                    for (q = 0; q < hw->name_len && m + 1 < sizeof ipath; ++q) ipath[m++] = (char)(regkey_name(hw)[q] < 0x80 ? regkey_name(hw)[q] : '?');
                    if (m + 1 < sizeof ipath) ipath[m++] = '\\';
                    for (q = 0; q < inst->name_len && m + 1 < sizeof ipath; ++q) ipath[m++] = (char)(regkey_name(inst)[q] < 0x80 ? regkey_name(inst)[q] : '?');
                    ipath[m] = 0;
                    own_function(&all[k], d);
                    ntdrv_pnp_add(d, &all[k], inst, ipath);
                    ++bound;
                }
        }
    }
    reg_unlock();
    if (!bound) kprintf("K64 ntdrv: %s: no Enum\\PCI device names this service (no PCI function claimed)\n", d->name);
}
#else
void ntdrv_pci_note_mmio(uint64_t pa, uint64_t size) { (void)pa; (void)size; }   /* no device is passed through here */
void ntdrv_release_claims(ntdrv_driver_t *d) { (void)d; }
unsigned ntdrv_claimed_functions(ntdrv_driver_t *d, pci_dev_t *out, unsigned max) { (void)d; (void)out; (void)max; return 0; }
void ntdrv_bind_enum(ntdrv_driver_t *d) { (void)d; }
#endif

/* ---------------------------------------------------------------- interrupts */
typedef struct kinterrupt {
    void *service;                              /* PKSERVICE_ROUTINE (ms_abi) */
    void *ctx;
    uint32_t vector;
    int intx;                                   /* attached to the kernel's shared INTx chain for dev */
#ifdef SHZ_STANDALONE
    pci_dev_t dev;
#endif
    struct kinterrupt *next;
} kinterrupt_t;
static kinterrupt_t *interrupts_by_vector[256];

static void call_isr(kinterrupt_t *k)
{
    uint8_t (NTAPI *svc)(void *, void *) = k->service;
    svc(k, k->ctx);                             /* KSERVICE_ROUTINE(Interrupt, ServiceContext) */
}
#ifdef SHZ_STANDALONE
static void intx_isr(void *ctx) { call_isr(ctx); }   /* one link of pci.c's shared-line chain */
#endif
static void irq_trampoline(struct regs *r)      /* exclusive, non-PCI vectors */
{
    kinterrupt_t *k;
    if (r->vector >= 256) return;
    for (k = interrupts_by_vector[r->vector]; k; k = k->next) call_isr(k);
}

uint32_t NTAPI HalGetInterruptVector(uint32_t bus_type, uint32_t bus, uint32_t level, uint32_t vec, uint8_t *irql, uint64_t *aff)
{
    (void)bus_type; (void)bus; (void)vec;
    if (irql) *irql = 5;
    if (aff) *aff = 1;
#ifdef SHZ_STANDALONE
    return standalone_irq_vector(level);
#else
    return level + 0x20;
#endif
}

NTSTATUS NTAPI IoConnectInterrupt(void **interrupt_out, void *service, void *ctx, KSPIN_LOCK *lock, uint32_t vector,
                                  uint8_t irql, uint8_t synch_irql, uint32_t mode, uint8_t share, uint64_t aff, uint8_t fsave)
{
    kinterrupt_t *k = kzalloc(sizeof *k);
    (void)lock; (void)irql; (void)synch_irql; (void)mode; (void)share; (void)aff; (void)fsave;
    if (!k) return STATUS_INSUFFICIENT_RESOURCES;
    if (vector >= 256) { kfree(k); return STATUS_INVALID_PARAMETER; }
    k->service = service; k->ctx = ctx; k->vector = vector;
#ifdef SHZ_STANDALONE
    {
        const unsigned line = vector - standalone_irq_vector(0);
        if (line < 16 && function_for_line(line, &k->dev)) {
            /* a PCI legacy line is level-triggered and may be shared (AHCI, NIC, ...): join the kernel's chain */
            if (pci_intx_attach(&k->dev, intx_isr, k) < 0) { kfree(k); return STATUS_INSUFFICIENT_RESOURCES; }
            k->intx = 1;
            *interrupt_out = k;
            return STATUS_SUCCESS;
        }
    }
#endif
    {   /* any other vector is exclusive: never take one a native driver already owns */
        irq_handler_t cur = irq_handler_get(vector);
        if (cur && cur != irq_trampoline) { kfree(k); return STATUS_INSUFFICIENT_RESOURCES; }
    }
    { uint64_t f = irq_save(); k->next = interrupts_by_vector[vector]; interrupts_by_vector[vector] = k; irq_restore(f); }
    irq_register(vector, irq_trampoline);
#ifdef SHZ_STANDALONE
    if (vector - standalone_irq_vector(0) < 16) standalone_irq_unmask(vector - standalone_irq_vector(0));
#endif
    *interrupt_out = k;
    return STATUS_SUCCESS;
}
void NTAPI IoDisconnectInterrupt(void *interrupt)
{
    kinterrupt_t *k = interrupt, **pp;
    uint64_t f;
    if (!k) return;
#ifdef SHZ_STANDALONE
    if (k->intx) { pci_intx_detach(&k->dev, intx_isr, k); kfree(k); return; }
#endif
    f = irq_save();
    pp = &interrupts_by_vector[k->vector];
    while (*pp && *pp != k) pp = &(*pp)->next;
    if (*pp) *pp = k->next;
    irq_restore(f);
    kfree(k);
}
/* KeSynchronizeExecution: run `routine` with the ISR excluded. On UP with interrupts off. */
uint8_t NTAPI KeSynchronizeExecution(void *interrupt, uint8_t (NTAPI *routine)(void *), void *ctx)
{
    uint64_t f = irq_save();
    uint8_t r;
    (void)interrupt;
    r = routine(ctx);
    irq_restore(f);
    return r;
}

/* ---------------------------------------------------------------- work items (system worker thread, PASSIVE_LEVEL) */
typedef struct io_workitem {
    DEVICE_OBJECT *dev;
    void (NTAPI *routine)(DEVICE_OBJECT *, void *);
    void *ctx;
    int queued;
    struct io_workitem *next;
    void (NTAPI *ex_routine)(void *);           /* ExQueueWorkItem: WORK_QUEUE_ITEM.WorkerRoutine(Parameter) */
    int ex_free;                                /* wrapper allocated by ExQueueWorkItem: freed after the call */
} io_workitem_t;
static io_workitem_t *wq_head, *wq_tail;
static ksem_t wq_sem;
static int wq_started;

static void work_thread(void *arg)
{
    (void)arg;
    for (;;) {
        io_workitem_t *w;
        void (NTAPI *routine)(DEVICE_OBJECT *, void *);
        DEVICE_OBJECT *dev;
        void *ctx;
        uint64_t f;
        sem_wait(&wq_sem);
        f = irq_save();
        w = wq_head;
        if (w) { wq_head = w->next; if (!wq_head) wq_tail = 0; }
        if (!w) { irq_restore(f); continue; }
        routine = w->routine; dev = w->dev; ctx = w->ctx;
        w->queued = 0;                                          /* the routine may requeue or free the item */
        irq_restore(f);
        if (w->ex_routine) { void (NTAPI *r)(void *) = w->ex_routine; if (w->ex_free) kfree(w); r(ctx); }
        else routine(dev, ctx);
    }
}
void *NTAPI IoAllocateWorkItem(DEVICE_OBJECT *dev)
{
    io_workitem_t *w = kzalloc(sizeof *w);
    if (w) w->dev = dev;
    return w;
}
void NTAPI IoFreeWorkItem(void *item) { kfree(item); }
void NTAPI IoQueueWorkItem(void *item, void (NTAPI *routine)(DEVICE_OBJECT *, void *), uint32_t queue_type, void *ctx);
/* WORK_QUEUE_ITEM { LIST_ENTRY List; WorkerRoutine; Parameter } (0x20): run on the same system worker thread */
void NTAPI ExQueueWorkItem(void *item, uint32_t queue_type)
{
    struct { LIST_ENTRY List; void (NTAPI *WorkerRoutine)(void *); void *Parameter; } *wq = item;
    io_workitem_t *w = kzalloc(sizeof *w);
    (void)queue_type;
    if (!w) kpanic("ExQueueWorkItem: out of memory");
    w->ex_routine = wq->WorkerRoutine; w->ex_free = 1;
    IoQueueWorkItem(w, 0, queue_type, wq->Parameter);
}

void NTAPI IoQueueWorkItem(void *item, void (NTAPI *routine)(DEVICE_OBJECT *, void *), uint32_t queue_type, void *ctx)
{
    io_workitem_t *w = item;
    uint64_t f;
    (void)queue_type;                                           /* Critical/Delayed/HyperCritical share one worker */
    if (!wq_started) {
        sem_init(&wq_sem, 0);
        KASSERT(thread_create("ntdrv-work", work_thread, 0));
        wq_started = 1;
    }
    f = irq_save();
    if (w->queued) { irq_restore(f); kpanic("IoQueueWorkItem: work item already queued"); }
    w->routine = routine; w->ctx = ctx; w->queued = 1; w->next = 0;
    if (wq_tail) wq_tail->next = w; else wq_head = w;
    wq_tail = w;
    irq_restore(f);
    sem_post(&wq_sem);
}

/* ================================================================ user-mode reachability */
/* Weak-hook targets referenced from sysfile.c/objects.c. */
struct devfile { DEVICE_OBJECT *dev; FILE_OBJECT fo; };

int32_t ntdrv_open_device_file(process_t *p, const char *path, uint32_t access, uint64_t phandle_out, uint64_t iosb_out)
{
    DEVICE_OBJECT *dev = 0;
    struct devfile *df;
    kobject_t *o;
    uint32_t h;
    int32_t st;
    if (!strncmp(path, "\\??\\", 4) || !strncmp(path, "\\DosDevices\\", 12) || !strncmp(path, "\\Global??\\", 10)) {
        dev = ntdrv_resolve_symlink(path);                    /* \??\Name / \DosDevices\Name -> device */
    } else if (!strncmp(path, "\\Device\\", 8)) {
        dev = ntdrv_find_device(path);
    } else {
        return (int32_t)0x7fff0002;                            /* not a device path: continue normal FS open */
    }
    if (!dev) return (int32_t)0x7fff0002;                      /* unknown name: let the FS report it */
    dev = IoGetAttachedDevice(dev);
    df = kzalloc(sizeof *df);
    o = ob_create(OB_DEVICE, 0);
    if (!df || !o) { kfree(df); if (o) ob_deref(o); return STATUS_INSUFFICIENT_RESOURCES; }
    df->dev = dev;
    df->fo.Type = 5; df->fo.Size = sizeof(FILE_OBJECT); df->fo.DeviceObject = dev;
    o->u.file.file = df;
    st = ntdrv_open_close_device(dev, 0);                      /* IRP_MJ_CREATE */
    if (st && st != STATUS_PENDING) { ob_deref(o); return st; }
    st = handle_insert(p, o, access, &h);
    ob_deref(o);
    if (st) return st;
    if (copy_to_user(p, phandle_out, &(uint64_t){h}, 8)) { handle_close(p, h); return STATUS_ACCESS_VIOLATION; }
    if (iosb_out) { struct { uint64_t s, i; } v = { 0, 1 }; copy_to_user(p, iosb_out, &v, sizeof v); }
    return STATUS_SUCCESS;
}

/* device handle read/write (from sysfile.c hook). Returns 1 if it owned the request. */
int ntdrv_file_dispatch(process_t *p, struct regs *r, uint32_t num, uint64_t handle, int32_t *st_out)
{
    kobject_t *o = handle_lookup(p, handle, OB_DEVICE);
    struct devfile *df;
    if (!o) return 0;
    df = o->u.file.file;
    if (num == SYS_NtReadFile || num == SYS_NtWriteFile) {
        const int write = num == SYS_NtWriteFile;
        const uint64_t iosb = (uint64_t)stack_arg(p, r, 5), buf = (uint64_t)stack_arg(p, r, 6);
        const uint32_t len = (uint32_t)stack_arg(p, r, 7);
        void *k = len ? kmalloc(len) : 0;
        uint64_t info = 0;
        int32_t st;
        if (len && !k) { *st_out = STATUS_INSUFFICIENT_RESOURCES; return 1; }
        if (write && len && copy_from_user(p, k, buf, len)) { kfree(k); *st_out = STATUS_ACCESS_VIOLATION; return 1; }
        st = ntdrv_read_write(df->dev, write, k, len, 0, &info);
        if (!write && info && copy_to_user(p, buf, k, info > len ? len : info)) st = STATUS_ACCESS_VIOLATION;
        kfree(k);
        if (iosb) { struct { uint64_t s, i; } v = { (uint64_t)(int64_t)st, info }; copy_to_user(p, iosb, &v, sizeof v); }
        *st_out = st;
        return 1;
    }
    return 0;
}

void ntdrv_device_handle_closing(kobject_t *o)
{
    struct devfile *df;
    if (o->refs != 1) return;
    df = o->u.file.file;
    if (df) { ntdrv_open_close_device(df->dev, 1); kfree(df); o->u.file.file = 0; }
}

/* NtDeviceIoControlFile (0xe1): (h, event, apc, apcctx, iosb, ioctl, in, inlen, out, outlen) */
static int32_t sys_device_io_control(process_t *p, struct regs *r, uint64_t handle)
{
    kobject_t *o = handle_lookup(p, handle, OB_DEVICE);
    struct devfile *df;
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5);
    const uint32_t ioctl = (uint32_t)stack_arg(p, r, 6);
    const uint64_t inbuf = (uint64_t)stack_arg(p, r, 7);
    const uint32_t inlen = (uint32_t)stack_arg(p, r, 8);
    const uint64_t outbuf = (uint64_t)stack_arg(p, r, 9);
    const uint32_t outlen = (uint32_t)stack_arg(p, r, 10);
    void *kin = 0, *kout = 0;
    uint64_t info = 0;
    int32_t st;
    if (!o) return STATUS_INVALID_HANDLE;
    df = o->u.file.file;
    if (inlen) { kin = kmalloc(inlen); if (!kin) return STATUS_INSUFFICIENT_RESOURCES;
                 if (copy_from_user(p, kin, inbuf, inlen)) { kfree(kin); return STATUS_ACCESS_VIOLATION; } }
    if (outlen) { kout = kzalloc(outlen); if (!kout) { kfree(kin); return STATUS_INSUFFICIENT_RESOURCES; } }
    st = ntdrv_device_control(df->dev, ioctl, kin, inlen, kout, outlen, 0, &info);
    if (kout && info && copy_to_user(p, outbuf, kout, info > outlen ? outlen : info)) st = STATUS_ACCESS_VIOLATION;
    if (iosb) { struct { uint64_t s, i; } v = { (uint64_t)(int64_t)st, info }; copy_to_user(p, iosb, &v, sizeof v); }
    kfree(kin); kfree(kout);
    return st;
}

/* ---------------------------------------------------------------- NtLoadDriver */
/* ImagePath -> file-system path, following the service control manager's rules (SystemRoot = C:\SHZ, the system
 * directory is SYS64 and the driver directory SYS64\DRIVERS on this system):
 *   absent                          \SystemRoot\SYS64\DRIVERS\<service>.sys  (the default for a kernel driver)
 *   %SystemRoot%\x  / \SystemRoot\x  C:\SHZ\x   (REG_EXPAND_SZ variables are expanded first)
 *   \??\X:\x, X:\x, \x              used as is (absolute object-manager / DOS paths; "\x" is on C:)
 *   x (relative)                    C:\SHZ\x   (relative to SystemRoot, as on Windows) */
static int ci_prefix(const char *s, const char *pfx)
{
    for (; *pfx; ++s, ++pfx) {
        char a = *s >= 'a' && *s <= 'z' ? (char)(*s - 32) : *s, b = *pfx >= 'a' && *pfx <= 'z' ? (char)(*pfx - 32) : *pfx;
        if (a != b) return 0;
    }
    return 1;
}
static void image_path(const char *service, const char *raw, char *out, unsigned cap)
{
    static const char root[] = "C:\\SHZ\\";
    const char *rest = 0;
    unsigned n = 0, i;
#define PUT(str) do { const char *s_ = (str); while (*s_ && n + 1 < cap) out[n++] = *s_++; } while (0)
    if (!raw || !raw[0]) {
        PUT(root); PUT("SYS64\\DRIVERS\\"); PUT(service); PUT(".sys");
    } else if (ci_prefix(raw, "%SystemRoot%\\")) {
        rest = raw + 13;
    } else if (ci_prefix(raw, "\\SystemRoot\\")) {
        rest = raw + 12;
    } else if (raw[0] == '\\' || (raw[0] && raw[1] == ':')) {
        PUT(raw);
    } else {
        rest = raw;
    }
    if (rest) { PUT(root); PUT(rest); }
#undef PUT
    out[n] = 0;
    for (i = 0; i < n; ++i) if (out[i] == '/') out[i] = '\\';
}

/* The UNICODE_STRING RegistryPath of NtLoadDriver/NtUnloadDriver: copied in, its last component is the service name. */
static int32_t read_regpath(process_t *p, uint64_t regpath_ustr, uint16_t *w, unsigned *chars, char *service, unsigned cap)
{
    struct { uint16_t len, maxlen; uint32_t pad; uint64_t buf; } u;
    char path[400];
    unsigned i, seg = 0, j = 0;
    if (copy_from_user(p, &u, regpath_ustr, sizeof u) || u.len / 2 >= 200) return STATUS_INVALID_PARAMETER;
    if (copy_from_user(p, w, u.buf, u.len)) return STATUS_ACCESS_VIOLATION;
    *chars = u.len / 2;
    ntdrv_wide_to_ascii(w, *chars, path, sizeof path);
    for (i = 0; path[i]; ++i) if (path[i] == '\\') seg = i + 1;   /* service name = last path component */
    for (i = seg; path[i] && j < cap - 1; ++i) service[j++] = path[i];
    service[j] = 0;
    return service[0] ? STATUS_SUCCESS : STATUS_OBJECT_NAME_INVALID;
}

static int32_t load_driver_from_service(process_t *p, uint64_t regpath_ustr)
{
    uint16_t w[200];
    char service[64], raw[300], imagepath[320];
    unsigned chars, i;
    regkey_t *node, *start;
    regval_t *v;
    fsnode_t *sys;
    int32_t st;
    ntdrv_driver_t *d = 0;
    st = read_regpath(p, regpath_ustr, w, &chars, service, sizeof service);
    if (st) return st;
    if (ntdrv_find_driver(service)) return STATUS_IMAGE_ALREADY_LOADED;   /* one image per service, as on Windows */
    /* resolve the Services\<name> key ("\Registry\..." object path, as sysreg.c does) and read ImagePath */
    reg_lock();
    start = reg_root();
    {
        const uint16_t *rel; unsigned rc2, k = 1;
        static const uint16_t reg[8] = { 'R','E','G','I','S','T','R','Y' };
        int ok;
        while (k < chars && w[k] != '\\') ++k;
        ok = chars && w[0] == '\\' && k - 1 == 8;
        for (i = 0; ok && i < 8; ++i) if (reg_upcase_char(w[1 + i]) != reg[i]) ok = 0;
        if (!ok) { reg_unlock(); return STATUS_OBJECT_PATH_SYNTAX_BAD; }
        rel = w + (k < chars ? k + 1 : k);
        rc2 = chars - (k < chars ? k + 1 : k);
        st = reg_resolve(start, rel, rc2, 0, 0, 1, 0, 0, &node, 0);
    }
    if (st) { reg_unlock(); kprintf("K64 ntdrv: NtLoadDriver(%s): service key not found (%x)\n", service, (uint32_t)st); return st; }
    raw[0] = 0;
    v = reg_find_value(node, (const uint16_t *)u"ImagePath", 9);
    if (v && (v->type == REG_SZ || v->type == REG_EXPAND_SZ)) {
        unsigned n = v->data_len / 2 < sizeof raw - 1 ? v->data_len / 2 : sizeof raw - 1;
        const uint16_t *pw = (const uint16_t *)regval_data(v);
        for (i = 0; i < n && pw[i]; ++i) raw[i] = pw[i] < 0x80 ? (char)pw[i] : '?';
        raw[i] = 0;
    }
    reg_unlock();
    image_path(service, raw, imagepath, sizeof imagepath);
    sys = fs_lookup(imagepath);
    if (!sys || sys->is_dir) { kprintf("K64 ntdrv: %s image %s not found\n", service, imagepath); return STATUS_OBJECT_NAME_NOT_FOUND; }
    kprintf("K64 ntdrv: NtLoadDriver(%s) -> %s\n", service, imagepath);
    st = ntdrv_load_node(sys, service, &d);
    if (st == 0 && d && d->started) {
        ntdrv_bind_enum(d);                       /* the devnodes installed for this service are now its functions */
        ntdrv_pnp_start_pending(d);               /* AddDevice + IRP_MN_START_DEVICE, as the PnP manager would */
    }
    return st;
}

/* NtUnloadDriver(RegistryPath) (0xe2) */
static int32_t unload_driver_from_service(process_t *p, uint64_t regpath_ustr)
{
    uint16_t w[200];
    char service[64];
    unsigned chars;
    int32_t st = read_regpath(p, regpath_ustr, w, &chars, service, sizeof service);
    if (st) return st;
    return ntdrv_unload_service(service);
}

/* NtShzDriverQuery(buffer, length, &count) (0xe3): one shz_driver_info_t per started image. */
static int32_t query_drivers(process_t *p, uint64_t buf, uint64_t len, uint64_t count_out)
{
    ntdrv_driver_t *d;
    uint32_t n = 0;
    int32_t st = STATUS_SUCCESS;
    for (d = ntdrv_drivers(); d; d = d->next) {
        shz_driver_info_t e;
        pci_dev_t fns[4];
        DEVICE_OBJECT *dev;
        ntdrv_devnode_t *node;
        unsigned i, k = 0;
        if (!d->started) continue;
        if ((uint64_t)(n + 1) * sizeof e > len) { st = STATUS_BUFFER_TOO_SMALL; ++n; continue; }   /* keep counting */
        memset(&e, 0, sizeof e);
        for (i = 0; d->name[i] && i < sizeof e.service - 1; ++i) e.service[i] = d->name[i];
        e.image_base = d->image_base;
        e.image_size = (uint32_t)d->image_size;
        e.flags = SHZ_DRV_STARTED | (d->dependency ? SHZ_DRV_DEPENDENCY : 0) | ((d->users & 0xff) << SHZ_DRV_USERS_SHIFT);
        for (dev = d->drv->DeviceObject; dev; dev = dev->NextDevice) ++e.ndevices;
        e.npci = ntdrv_claimed_functions(d, fns, 4);
        for (i = 0; i < e.npci; ++i) { e.pci[i].bus = fns[i].bus; e.pci[i].dev = fns[i].dev; e.pci[i].fn = fns[i].fn; }
        for (node = devnodes; node && k < 4; node = node->next)
            if (node->dev->DriverObject == d->drv) {
                for (i = 0; node->name[i] && i < sizeof e.device[0] - 1; ++i) e.device[k][i] = node->name[i];
                ++k;
            }
        if (copy_to_user(p, buf + (uint64_t)n * sizeof e, &e, sizeof e)) return STATUS_ACCESS_VIOLATION;
        ++n;
    }
    if (count_out && copy_to_user(p, count_out, &n, 4)) return STATUS_ACCESS_VIOLATION;
    return st;
}

/* ---------------------------------------------------------------- ntdrv syscall router */
int32_t sys_ext_ntdrv(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)a4;
    switch (num) {
    case 0xe0: return load_driver_from_service(cur, a1);                     /* NtLoadDriver(RegistryPath) */
    case 0xe1: return sys_device_io_control(cur, r, a1);                     /* NtDeviceIoControlFile(h, ev, apc, ctx, iosb, ...) */
    case 0xe2: return unload_driver_from_service(cur, a1);                   /* NtUnloadDriver(RegistryPath) */
    case 0xe3: return query_drivers(cur, a1, a2, a3);                        /* NtShzDriverQuery(buf, len, &count) */
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}
