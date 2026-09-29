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

#define SL_PENDING_RETURNED 0x01
#define SL_INVOKE_ON_CANCEL 0x20
#define SL_INVOKE_ON_SUCCESS 0x40
#define SL_INVOKE_ON_ERROR 0x80
#define IO_TYPE_IRP 6
#define NT_SUCCESS(s) ((int32_t)(s) >= 0)

#define OB_DEVICE 0x50                          /* kobject type for a user handle onto a device */

static ntdrv_devnode_t *devnodes;
static ntdrv_symlink_t *symlinks;

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
void NTAPI IoStartNextPacket(DEVICE_OBJECT *d, uint8_t cancelable) { (void)d; (void)cancelable; }
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

/* ---------------------------------------------------------------- interrupts */
typedef struct kinterrupt {
    void *service;                              /* PKSERVICE_ROUTINE (ms_abi) */
    void *ctx;
    uint32_t vector, irq;
    struct kinterrupt *next;
} kinterrupt_t;
static kinterrupt_t *interrupts_by_vector[256];

static void irq_trampoline(struct regs *r)
{
    kinterrupt_t *k;
    uint8_t (NTAPI *svc)(void *, void *);
    (void)r;
    if (r->vector >= 256) return;
    for (k = interrupts_by_vector[r->vector]; k; k = k->next) {
        svc = k->service;
        svc(k, k->ctx);                          /* KSERVICE_ROUTINE(Interrupt, ServiceContext) */
    }
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
    { uint64_t f = irq_save(); k->next = interrupts_by_vector[vector]; interrupts_by_vector[vector] = k; irq_restore(f); }
    irq_register(vector, irq_trampoline);
#ifdef SHZ_STANDALONE
    standalone_irq_unmask(vector - standalone_irq_vector(0));
#endif
    *interrupt_out = k;
    return STATUS_SUCCESS;
}
void NTAPI IoDisconnectInterrupt(void *interrupt)
{
    kinterrupt_t *k = interrupt, **pp;
    uint64_t f;
    if (!k) return;
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

/* ---------------------------------------------------------------- misc Io/Ps/Ob exports referenced widely */
void *NTAPI IoAllocateWorkItem(DEVICE_OBJECT *dev) { (void)dev; return kzalloc(64); }
void NTAPI IoFreeWorkItem(void *w) { kfree(w); }
void NTAPI IoQueueWorkItem(void *w, void (NTAPI *routine)(DEVICE_OBJECT *, void *), uint32_t q, void *ctx)
{ (void)w; (void)routine; (void)q; (void)ctx; /* queued to a worker thread in a fuller build */ }
DRIVER_OBJECT *NTAPI IoGetDriverObjectExtension(DRIVER_OBJECT *d, void *id) { (void)id; return d; }

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
static int32_t load_driver_from_service(process_t *p, uint64_t regpath_ustr)
{
    struct { uint16_t len, maxlen; uint32_t pad; uint64_t buf; } u;
    uint16_t w[200];
    char path[400], service[64], imagepath[300];
    unsigned chars, i, seg = 0;
    regkey_t *node, *start;
    regval_t *v;
    fsnode_t *sys;
    int32_t st;
    ntdrv_driver_t *d;
    if (copy_from_user(p, &u, regpath_ustr, sizeof u) || u.len / 2 >= 200) return STATUS_INVALID_PARAMETER;
    if (copy_from_user(p, w, u.buf, u.len)) return STATUS_ACCESS_VIOLATION;
    chars = u.len / 2;
    ntdrv_wide_to_ascii(w, chars, path, sizeof path);
    for (i = 0; path[i]; ++i) if (path[i] == '\\') seg = i + 1;   /* service name = last path component */
    { unsigned j = 0; for (i = seg; path[i] && j < sizeof service - 1; ++i) service[j++] = path[i]; service[j] = 0; }
    /* resolve the Services\<name> key and read ImagePath */
    reg_lock();
    start = reg_root();
    {
        const uint16_t *rel; unsigned rc2 = chars, k = 1;
        static const uint16_t reg[8] = { 'R','E','G','I','S','T','R','Y' };
        int ok;
        while (k < chars && w[k] != '\\') ++k;
        ok = k - 1 == 8;
        for (i = 0; ok && i < 8; ++i) if (reg_upcase_char(w[1 + i]) != reg[i]) ok = 0;
        rel = ok ? w + (k < chars ? k + 1 : k) : w;
        rc2 = ok ? chars - (k < chars ? k + 1 : k) : chars;
        st = reg_resolve(start, rel, rc2, 0, 0, 1, 0, 0, &node, 0);
    }
    if (st) { reg_unlock(); kprintf("K64 ntdrv: NtLoadDriver: service key not found (%x)\n", (uint32_t)st); return st; }
    v = reg_find_value(node, (const uint16_t *)u"ImagePath", 9);
    if (!v) { reg_unlock(); kprintf("K64 ntdrv: %s has no ImagePath\n", service); return STATUS_OBJECT_NAME_NOT_FOUND; }
    {
        unsigned n = v->data_len / 2 < 300 ? v->data_len / 2 : 299;
        const uint16_t *pw = (const uint16_t *)regval_data(v);
        for (i = 0; i < n; ++i) imagepath[i] = pw[i] < 0x80 ? (char)pw[i] : '?';
        imagepath[n] = 0;
    }
    reg_unlock();
    sys = fs_lookup(imagepath);
    if (!sys || sys->is_dir) { kprintf("K64 ntdrv: %s image %s not found\n", service, imagepath); return STATUS_OBJECT_NAME_NOT_FOUND; }
    st = ntdrv_load_image(sys->data, sys->size, service, &d);
    return st;
}

/* ---------------------------------------------------------------- ntdrv syscall router */
int32_t sys_ext_ntdrv(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)a2; (void)a3; (void)a4;
    switch (num) {
    case 0xe0: return load_driver_from_service(cur, a1);                     /* NtLoadDriver(RegistryPath) */
    case 0xe1: return sys_device_io_control(cur, r, a1);                     /* NtDeviceIoControlFile(h, ev, apc, ctx, iosb, ...) */
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}
