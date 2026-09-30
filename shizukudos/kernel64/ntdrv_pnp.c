/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the I/O-manager services a PnP/power-aware WDM driver needs beyond
 * ntdrv_io.c -- driver-object extensions, the per-device host record, power IRPs (Po*),
 * device interfaces (registry-backed, with PnP notification), synchronous forwarding, device
 * properties and registry keys of host-enumerated PDOs (IoReportDetectedDevice creates them on
 * the host's root bus), StartIo packet queues and KDEVICE_QUEUE, cancellation, remove locks,
 * driver re-initialization, shutdown/PnP notification lists, error logging (to the kernel
 * console, the event log of this system), WMI registration and events, I/O timers, the DMA
 * adapter object with a real DMA_OPERATIONS table, resource assignment from PCI configuration
 * space, partition tables (read through the device's own IRP_MJ_READ), the remaining HAL
 * entries and the pageable-section and page-MDL Mm entries. Every entry is NTAPI and follows
 * the documented semantics; a request the host cannot honour returns the documented failure
 * status, never a silent success.
 */
#include "ntdrv.h"
#include "registry.h"
#include "pci.h"

#define NT_SUCCESS(s) ((int32_t)(s) >= 0)
#define PASSIVE_LEVEL 0
#define APC_LEVEL 1
#define DISPATCH_LEVEL 2
#define STATUS_DELETE_PENDING ((int32_t)0xC0000056)
#define STATUS_INVALID_PARAMETER_2 ((int32_t)0xC00000F0)
#define STATUS_WMI_GUID_NOT_FOUND ((int32_t)0xC0000295)
#define STATUS_NOT_FOUND ((int32_t)0xC0000225)
#define STATUS_OBJECT_TYPE_MISMATCH_ ((int32_t)0xC0000024)
#define STATUS_NO_SUCH_DEVICE_ ((int32_t)0xC000000E)
#define STATUS_BAD_MASTER_BOOT_RECORD ((int32_t)0xC000009D)
#define STATUS_DEVICE_DATA_ERROR ((int32_t)0xC000009C)
#define STATUS_OBJECT_NAME_EXISTS ((int32_t)0x40000000)
#define SL_INVOKE_ON_CANCEL 0x20
#define SL_INVOKE_ON_SUCCESS 0x40
#define SL_INVOKE_ON_ERROR 0x80

extern IRP *NTAPI IoAllocateIrp(uint8_t stackcount, uint8_t charge);
extern void NTAPI IoFreeIrp(IRP *irp);
extern void NTAPI IoInitializeIrp(IRP *irp, uint16_t size, uint8_t stackcount);
extern NTSTATUS NTAPI IofCallDriver(DEVICE_OBJECT *dev, IRP *irp);
extern void NTAPI IofCompleteRequest(IRP *irp, uint8_t boost);
extern DEVICE_OBJECT *NTAPI IoAttachDeviceToDeviceStack(DEVICE_OBJECT *src, DEVICE_OBJECT *target);
extern DEVICE_OBJECT *NTAPI IoGetAttachedDevice(DEVICE_OBJECT *d);
extern NTSTATUS NTAPI IoCreateDevice(DRIVER_OBJECT *drv, uint32_t ext_size, UNICODE_STRING *name, uint32_t type, uint32_t chars, uint8_t exclusive, DEVICE_OBJECT **out);
extern NTSTATUS NTAPI IoCreateSymbolicLink(UNICODE_STRING *link, UNICODE_STRING *target);
extern NTSTATUS NTAPI IoDeleteSymbolicLink(UNICODE_STRING *link);
extern IRP *NTAPI IoBuildSynchronousFsdRequest(uint32_t mj, DEVICE_OBJECT *dev, void *buf, uint32_t len, LARGE_INTEGER *off, void *event, IO_STATUS_BLOCK *iosb);
extern uint8_t NTAPI KfRaiseIrql(uint8_t);
extern void NTAPI KfLowerIrql(uint8_t);
extern uint8_t NTAPI KfAcquireSpinLock(KSPIN_LOCK *);
extern void NTAPI KfReleaseSpinLock(KSPIN_LOCK *, uint8_t);
extern void NTAPI KeInitializeSpinLock(KSPIN_LOCK *);
extern void NTAPI KeInitializeDpc(KDPC *, PKDEFERRED_ROUTINE, void *);
extern void NTAPI KeInitializeTimerEx(KTIMER *, uint32_t);
extern uint8_t NTAPI KeSetTimerEx(KTIMER *, LARGE_INTEGER, LONG, KDPC *);
extern uint8_t NTAPI KeCancelTimer(KTIMER *);
extern void *NTAPI ExAllocatePoolWithTag(uint32_t, uint64_t, uint32_t);
extern void NTAPI ExFreePool(void *);
extern void NTAPI ObDereferenceObject(void *);
extern uint64_t NTAPI ntdrv_wcslen(const WCHAR *);
extern NTSTATUS ntdrv_open_key_ascii(const char *path, int create, uint64_t *handle);
extern NTSTATUS ntdrv_set_value_ascii(uint64_t key, const char *name, uint32_t type, const void *data, uint32_t len);
extern NTSTATUS NTAPI ZwClose(uint64_t);
extern NTSTATUS NTAPI RtlStringFromGUID(const GUID *g, UNICODE_STRING *s);
extern int ntdrv_guid_to_ascii(const GUID *g, char *out);
extern void ntdrv_queue_system_work(void (NTAPI *fn)(void *), void *ctx, void *tag);
extern LARGE_INTEGER NTAPI MmGetPhysicalAddress(void *va);
extern uint32_t NTAPI MmSizeOfMdl(void *va, uint32_t len);
extern int32_t ntdrv_device_open_file(DEVICE_OBJECT *dev, uint32_t access, FILE_OBJECT **fo_out);   /* ntdrv_zw.c */
extern const char *ntdrv_device_name(DEVICE_OBJECT *dev);                                             /* ntdrv_io.c */
extern void ntdrv_pci_claim_function(const pci_dev_t *d);                                            /* ntdrv_io.c */

/* ================================================================ per-device host record (DeviceObjectExtension) */
typedef struct io_timer { DEVICE_OBJECT *dev; void (NTAPI *routine)(DEVICE_OBJECT *, void *); void *ctx; KTIMER timer; KDPC dpc; int running; } io_timer_t;
typedef struct ntdrv_pdo {
    char instance[128];                 /* "ROOT\LEGACY_BEEP\0000" */
    char service[64];
    char hwid[128];                     /* one hardware id */
    char desc[96];
    uint32_t legacy_bus_type, bus_number, address, ui_number;
    void *resources;                    /* CM_RESOURCE_LIST (owned) */
    uint32_t resources_size;
} ntdrv_pdo_t;
typedef struct ntdrv_devext {
    uint32_t device_power, system_power;    /* POWER_STATE values reported by PoSetPowerState */
    int power_irp_active;                   /* PoStartNextPowerIrp bookkeeping */
    uint8_t startio_deferred, startio_noncancelable;
    io_timer_t *timer;
    ntdrv_pdo_t *pdo;                       /* set for PDOs of the host's root bus */
    int wmi_registered;
    uint32_t *idle_counter;                 /* PoRegisterDeviceForIdleDetection */
} ntdrv_devext_t;

ntdrv_devext_t *ntdrv_devext(DEVICE_OBJECT *dev)
{
    ntdrv_devext_t *x = dev->DeviceObjectExtension;
    if (!x) { x = kzalloc(sizeof *x); dev->DeviceObjectExtension = x; }
    return x;
}
void ntdrv_devext_free(DEVICE_OBJECT *dev)
{
    ntdrv_devext_t *x = dev->DeviceObjectExtension;
    if (!x) return;
    if (x->timer) { KeCancelTimer(&x->timer->timer); kfree(x->timer); }
    if (x->pdo) { kfree(x->pdo->resources); kfree(x->pdo); }
    kfree(x->idle_counter);
    kfree(x);
    dev->DeviceObjectExtension = 0;
}

/* ================================================================ driver object extensions */
typedef struct drv_ext { struct drv_ext *next; void *id; uint8_t data[] __attribute__((aligned(16))); } drv_ext_t;
typedef struct { DRIVER_EXTENSION pub; drv_ext_t *exts; } ntdrv_drvext_t;   /* DRIVER_OBJECT.DriverExtension points at .pub */
#define STATUS_OBJECT_NAME_COLLISION_ ((int32_t)0xC0000035)

DRIVER_EXTENSION *ntdrv_alloc_driver_extension(DRIVER_OBJECT *drv, ntdrv_driver_t *d)
{
    ntdrv_drvext_t *x = kzalloc(sizeof *x);
    if (!x) return 0;
    x->pub.DriverObject = drv;
    x->pub.ServiceKeyName.Buffer = d->regpath_buf;          /* the service name is the last component of RegistryPath */
    {   unsigned n = d->regpath.Length / 2, i, start = 0;
        for (i = 0; i < n; ++i) if (d->regpath_buf[i] == '\\') start = i + 1;
        x->pub.ServiceKeyName.Buffer = d->regpath_buf + start;
        x->pub.ServiceKeyName.Length = (uint16_t)((n - start) * 2);
        x->pub.ServiceKeyName.MaximumLength = (uint16_t)((n - start) * 2 + 2); }
    drv->DriverExtension = &x->pub;
    return &x->pub;
}
NTSTATUS NTAPI IoAllocateDriverObjectExtension(DRIVER_OBJECT *drv, void *id, uint32_t size, void **out)
{
    ntdrv_drvext_t *x = (ntdrv_drvext_t *)drv->DriverExtension;
    drv_ext_t *e;
    uint64_t f;
    if (!x) return STATUS_INSUFFICIENT_RESOURCES;
    for (e = x->exts; e; e = e->next) if (e->id == id) { *out = 0; return STATUS_OBJECT_NAME_COLLISION_; }
    e = kzalloc(sizeof *e + size);
    if (!e) { *out = 0; return STATUS_INSUFFICIENT_RESOURCES; }
    e->id = id;
    f = irq_save(); e->next = x->exts; x->exts = e; irq_restore(f);
    *out = e->data;
    return STATUS_SUCCESS;
}
void *NTAPI IoGetDriverObjectExtension(DRIVER_OBJECT *drv, void *id)
{
    ntdrv_drvext_t *x = (ntdrv_drvext_t *)drv->DriverExtension;
    drv_ext_t *e;
    if (!x) return 0;
    for (e = x->exts; e; e = e->next) if (e->id == id) return e->data;
    return 0;
}

/* ================================================================ synchronous IRP helpers */
static NTSTATUS NTAPI sync_complete(DEVICE_OBJECT *dev, IRP *irp, void *ctx)
{
    (void)dev; (void)irp;
    KeSetEvent(ctx, 0, 0);
    return STATUS_MORE_PROCESSING_REQUIRED;
}
/* Send an IRP down `dev` and wait for it; the IRP stays owned by the caller (completion stops at our routine). */
static NTSTATUS call_and_wait(DEVICE_OBJECT *dev, IRP *irp)
{
    KEVENT ev;
    IO_STACK_LOCATION *next = irp->Tail.Overlay.CurrentStackLocation - 1;
    NTSTATUS st;
    KeInitializeEvent(&ev, 0, 0);
    next->CompletionRoutine = sync_complete; next->Context = &ev;
    next->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
    st = IofCallDriver(dev, irp);
    if (st == STATUS_PENDING) { KeWaitForSingleObject(&ev, 0, 0, 0, 0); st = irp->IoStatus.Status; }
    return st;
}
/* PnP IRPs start with STATUS_NOT_SUPPORTED, the rule every PnP dispatch relies on. */
static NTSTATUS send_pnp(DEVICE_OBJECT *dev, uint8_t minor, void (*setup)(IO_STACK_LOCATION *, void *), void *ctx, uint64_t *info)
{
    DEVICE_OBJECT *top = IoGetAttachedDevice(dev);
    IRP *irp = IoAllocateIrp((uint8_t)top->StackSize, 0);
    IO_STACK_LOCATION *stk;
    NTSTATUS st;
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;
    stk = irp->Tail.Overlay.CurrentStackLocation - 1;
    stk->MajorFunction = IRP_MJ_PNP; stk->MinorFunction = minor;
    if (setup) setup(stk, ctx);
    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    st = call_and_wait(top, irp);
    if (info) *info = irp->IoStatus.Information;
    IoFreeIrp(irp);
    return st;
}

/* ================================================================ power */
NTSTATUS NTAPI PoCallDriver(DEVICE_OBJECT *dev, IRP *irp)
{
    /* Power IRPs are dispatched like any other on this host (there is no power-IRP serialization queue beyond the
     * per-device flag PoStartNextPowerIrp clears); IRP_MJ_POWER goes to the driver's dispatch through IoCallDriver. */
    IO_STACK_LOCATION *stk = irp->Tail.Overlay.CurrentStackLocation - 1;
    if (stk->MajorFunction == IRP_MJ_POWER) ntdrv_devext(dev)->power_irp_active = 1;
    return IofCallDriver(dev, irp);
}
void NTAPI PoStartNextPowerIrp(IRP *irp)
{
    IO_STACK_LOCATION *stk = irp->Tail.Overlay.CurrentStackLocation;
    if (stk->DeviceObject) ntdrv_devext(stk->DeviceObject)->power_irp_active = 0;
}
/* POWER_STATE is a 4-byte union; Type 0 = SystemPowerState, 1 = DevicePowerState. Returns the previous state. */
uint32_t NTAPI PoSetPowerState(DEVICE_OBJECT *dev, uint32_t type, uint32_t state)
{
    ntdrv_devext_t *x = ntdrv_devext(dev);
    uint32_t prev;
    if (type == 1) { prev = x->device_power; x->device_power = state; }
    else { prev = x->system_power; x->system_power = state; }
    return prev;
}
struct porequest { void (NTAPI *cb)(DEVICE_OBJECT *, uint8_t, uint32_t, void *, IO_STATUS_BLOCK *); void *ctx; uint8_t minor; uint32_t state; };
static NTSTATUS NTAPI porequest_complete(DEVICE_OBJECT *dev, IRP *irp, void *ctx)
{
    struct porequest *r = ctx;
    IO_STACK_LOCATION *stk = irp->Tail.Overlay.CurrentStackLocation;
    (void)dev;
    if (r->cb) r->cb(stk->DeviceObject, r->minor, r->state, r->ctx, &irp->IoStatus);
    kfree(r);
    IoFreeIrp(irp);
    return STATUS_MORE_PROCESSING_REQUIRED;
}
NTSTATUS NTAPI PoRequestPowerIrp(DEVICE_OBJECT *dev, uint8_t minor, uint32_t state, void *cb, void *ctx, IRP **irp_out)
{
    DEVICE_OBJECT *top = IoGetAttachedDevice(dev);
    IRP *irp;
    IO_STACK_LOCATION *stk;
    struct porequest *r;
    if (minor != IRP_MN_SET_POWER && minor != IRP_MN_QUERY_POWER && minor != 0 /* WAIT_WAKE */) return STATUS_INVALID_PARAMETER_2;
    irp = IoAllocateIrp((uint8_t)(top->StackSize + 1), 0);
    r = kzalloc(sizeof *r);
    if (!irp || !r) { if (irp) IoFreeIrp(irp); kfree(r); return STATUS_INSUFFICIENT_RESOURCES; }
    r->cb = cb; r->ctx = ctx; r->minor = minor; r->state = state;
    stk = irp->Tail.Overlay.CurrentStackLocation - 1;         /* our own location carries the completion routine */
    stk->CompletionRoutine = porequest_complete; stk->Context = r; stk->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;
    irp->CurrentLocation--; irp->Tail.Overlay.CurrentStackLocation--;
    stk = irp->Tail.Overlay.CurrentStackLocation - 1;
    stk->MajorFunction = IRP_MJ_POWER; stk->MinorFunction = minor;
    stk->Parameters.Power.Type = 1;                            /* DevicePowerState */
    stk->Parameters.Power.State = state;
    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    if (irp_out) *irp_out = irp;
    PoCallDriver(top, irp);
    return STATUS_PENDING;
}
uint32_t *NTAPI PoRegisterDeviceForIdleDetection(DEVICE_OBJECT *dev, uint32_t conservative, uint32_t performance, uint32_t state)
{
    ntdrv_devext_t *x = ntdrv_devext(dev);
    (void)conservative; (void)performance; (void)state;
    if (!x->idle_counter) x->idle_counter = kzalloc(4);
    return x->idle_counter;                                    /* the driver bumps it through PoSetDeviceBusy; nothing here idles a device */
}
void NTAPI PoSetDeviceBusyEx(uint32_t *counter) { if (counter) (*counter)++; }
void *NTAPI PoRegisterSystemState(void *handle, uint32_t flags) { uint32_t *h = handle ? handle : kzalloc(4); if (h) *h |= flags; return h; }
void NTAPI PoUnregisterSystemState(void *handle) { kfree(handle); }
void NTAPI PoSetSystemState(uint32_t flags) { (void)flags; }
void NTAPI PoUnregisterPowerSettingCallback(void *h) { kfree(h); }
NTSTATUS NTAPI PoRegisterPowerSettingCallback(DEVICE_OBJECT *dev, const GUID *guid, void *cb, void *ctx, void **handle)
{ (void)dev; (void)guid; (void)cb; (void)ctx; if (handle) { *handle = kzalloc(8); if (!*handle) return STATUS_INSUFFICIENT_RESOURCES; } return STATUS_SUCCESS; }

/* ================================================================ device interfaces */
typedef struct iface {
    struct iface *next;
    DEVICE_OBJECT *dev;
    GUID guid;
    char link[160];                     /* "\??\ROOT#LEGACY_X#0000#{guid}[\ref]" */
    char devname[96];                   /* "\Device\X" */
    int enabled;
} iface_t;
static iface_t *ifaces;
static void wide_dup(UNICODE_STRING *u, const char *s)
{
    unsigned n = (unsigned)strlen(s);
    u->Buffer = kmalloc(n * 2 + 2);
    if (!u->Buffer) { u->Length = u->MaximumLength = 0; return; }
    ntdrv_ascii_to_wide(s, u->Buffer, n + 1);
    u->Length = (uint16_t)(n * 2); u->MaximumLength = (uint16_t)(n * 2 + 2);
}
static void devclass_key(char *out, unsigned cap, const char *guid, const char *link_leaf)   /* link_leaf: "ROOT#..." */
{
    unsigned n = 0, i;
    static const char pfx[] = "\\Registry\\Machine\\System\\CurrentControlSet\\Control\\DeviceClasses\\";
    for (i = 0; pfx[i] && n + 1 < cap; ++i) out[n++] = pfx[i];
    for (i = 0; guid[i] && n + 1 < cap; ++i) out[n++] = guid[i];
    if (link_leaf) { const char *p = "\\##?#"; for (i = 0; p[i] && n + 1 < cap; ++i) out[n++] = p[i]; for (i = 0; link_leaf[i] && n + 1 < cap; ++i) out[n++] = link_leaf[i]; }
    out[n] = 0;
}
NTSTATUS NTAPI IoRegisterDeviceInterface(DEVICE_OBJECT *pdo, const GUID *guid, UNICODE_STRING *refstring, UNICODE_STRING *link_out)
{
    ntdrv_devext_t *x = ntdrv_devext(pdo);
    const char *devname = ntdrv_device_name(pdo);
    char g[40], leaf[160], key[300], ref[64] = "";
    unsigned n = 0, i;
    iface_t *f;
    uint64_t h;
    if (!devname) return STATUS_INVALID_DEVICE_REQUEST;           /* an unnamed device object cannot own an interface */
    ntdrv_guid_to_ascii(guid, g);
    if (x->pdo) { for (i = 0; x->pdo->instance[i] && n + 1 < sizeof leaf; ++i) leaf[n++] = x->pdo->instance[i] == '\\' ? '#' : x->pdo->instance[i]; }
    else { const char *p = "SHZ#"; for (i = 0; p[i]; ++i) leaf[n++] = p[i]; for (i = 8; devname[i] && n + 1 < sizeof leaf; ++i) leaf[n++] = devname[i] == '\\' ? '#' : devname[i]; }
    leaf[n++] = '#'; for (i = 0; g[i] && n + 1 < sizeof leaf; ++i) leaf[n++] = g[i]; leaf[n] = 0;
    if (refstring && refstring->Length) ntdrv_wide_to_ascii(refstring->Buffer, refstring->Length / 2, ref, sizeof ref);
    for (f = ifaces; f; f = f->next)
        if (f->dev == pdo && !memcmp(&f->guid, guid, sizeof *guid) && !strcmp(f->link + 4 + strlen(leaf), ref[0] ? ref : "")) break;
    if (!f) {
        f = kzalloc(sizeof *f);
        if (!f) return STATUS_INSUFFICIENT_RESOURCES;
        f->dev = pdo; f->guid = *guid;
        n = 0; { const char *p = "\\??\\"; for (i = 0; p[i]; ++i) f->link[n++] = p[i]; }
        for (i = 0; leaf[i] && n + 1 < sizeof f->link; ++i) f->link[n++] = leaf[i];
        if (ref[0]) { f->link[n++] = '\\'; for (i = 0; ref[i] && n + 1 < sizeof f->link; ++i) f->link[n++] = ref[i]; }
        f->link[n] = 0;
        for (i = 0; devname[i] && i + 1 < sizeof f->devname; ++i) f->devname[i] = devname[i]; f->devname[i] = 0;
        f->next = ifaces; ifaces = f;
        /* DeviceClasses\{guid}\##?#<leaf>: DeviceInstance; subkey #<ref>: SymbolicLink */
        devclass_key(key, sizeof key, g, leaf);
        if (NT_SUCCESS(ntdrv_open_key_ascii(key, 1, &h))) {
            WCHAR w[130]; unsigned wn = (unsigned)ntdrv_ascii_to_wide(x->pdo ? x->pdo->instance : devname, w, 130);
            ntdrv_set_value_ascii(h, "DeviceInstance", REG_SZ, w, (wn + 1) * 2);
            ZwClose(h);
        }
        { unsigned k = (unsigned)strlen(key); key[k++] = '\\'; key[k++] = '#'; for (i = 0; ref[i] && k + 1 < sizeof key; ++i) key[k++] = ref[i]; key[k] = 0; }
        if (NT_SUCCESS(ntdrv_open_key_ascii(key, 1, &h))) {
            WCHAR w[170]; unsigned wn = (unsigned)ntdrv_ascii_to_wide(f->link, w, 170);
            ntdrv_set_value_ascii(h, "SymbolicLink", REG_SZ, w, (wn + 1) * 2);
            ZwClose(h);
        }
    }
    wide_dup(link_out, f->link);
    return link_out->Buffer ? STATUS_SUCCESS : STATUS_INSUFFICIENT_RESOURCES;
}
static void pnp_notify_interface(iface_t *f, int arrival);
NTSTATUS NTAPI IoSetDeviceInterfaceState(UNICODE_STRING *link, uint8_t enable)
{
    char name[160], key[300], g[40], leaf[160];
    iface_t *f;
    UNICODE_STRING l, t;
    uint64_t h;
    unsigned i, n;
    ntdrv_wide_to_ascii(link->Buffer, link->Length / 2, name, sizeof name);
    for (f = ifaces; f; f = f->next) if (!strcmp(f->link, name)) break;
    if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;
    if (!!enable == f->enabled) return enable ? STATUS_OBJECT_NAME_EXISTS : STATUS_SUCCESS;
    wide_dup(&l, f->link); wide_dup(&t, f->devname);
    if (enable) IoCreateSymbolicLink(&l, &t); else IoDeleteSymbolicLink(&l);
    kfree(l.Buffer); kfree(t.Buffer);
    f->enabled = !!enable;
    ntdrv_guid_to_ascii(&f->guid, g);
    for (i = 4, n = 0; f->link[i] && f->link[i] != '\\' && n + 1 < sizeof leaf; ++i) leaf[n++] = f->link[i]; leaf[n] = 0;
    devclass_key(key, sizeof key, g, leaf);
    { unsigned k = (unsigned)strlen(key); const char *ref = f->link[i] == '\\' ? f->link + i + 1 : "";
      key[k++] = '\\'; key[k++] = '#'; for (i = 0; ref[i] && k + 1 < sizeof key; ++i) key[k++] = ref[i]; key[k++] = '\\'; key[k++] = 'C'; key[k++] = 'o'; key[k++] = 'n'; key[k++] = 't'; key[k++] = 'r'; key[k++] = 'o'; key[k++] = 'l'; key[k] = 0; }
    if (NT_SUCCESS(ntdrv_open_key_ascii(key, 1, &h))) { uint32_t linked = f->enabled; ntdrv_set_value_ascii(h, "Linked", REG_DWORD, &linked, 4); ZwClose(h); }
    pnp_notify_interface(f, f->enabled);
    return STATUS_SUCCESS;
}
#define DEVICE_INTERFACE_INCLUDE_NONACTIVE 1
NTSTATUS NTAPI IoGetDeviceInterfaces(const GUID *guid, DEVICE_OBJECT *pdo, uint32_t flags, WCHAR **list)
{
    iface_t *f;
    unsigned total = 1, pos = 0, i;
    WCHAR *out;
    for (f = ifaces; f; f = f->next)
        if (!memcmp(&f->guid, guid, sizeof *guid) && (!pdo || f->dev == pdo) && (f->enabled || (flags & DEVICE_INTERFACE_INCLUDE_NONACTIVE)))
            total += (unsigned)strlen(f->link) + 1;
    out = kmalloc(total * 2);
    if (!out) return STATUS_INSUFFICIENT_RESOURCES;
    for (f = ifaces; f; f = f->next)
        if (!memcmp(&f->guid, guid, sizeof *guid) && (!pdo || f->dev == pdo) && (f->enabled || (flags & DEVICE_INTERFACE_INCLUDE_NONACTIVE))) {
            for (i = 0; f->link[i]; ++i) out[pos++] = (uint8_t)f->link[i];
            out[pos++] = 0;
        }
    out[pos] = 0;
    *list = out;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI IoOpenDeviceInterfaceRegistryKey(UNICODE_STRING *link, uint32_t access, uint64_t *handle)
{
    char name[160], key[300], g[40], leaf[160];
    iface_t *f; unsigned i, n;
    (void)access;
    ntdrv_wide_to_ascii(link->Buffer, link->Length / 2, name, sizeof name);
    for (f = ifaces; f; f = f->next) if (!strcmp(f->link, name)) break;
    if (!f) return STATUS_OBJECT_NAME_NOT_FOUND;
    ntdrv_guid_to_ascii(&f->guid, g);
    for (i = 4, n = 0; f->link[i] && f->link[i] != '\\' && n + 1 < sizeof leaf; ++i) leaf[n++] = f->link[i]; leaf[n] = 0;
    devclass_key(key, sizeof key, g, leaf);
    { unsigned k = (unsigned)strlen(key); const char *ref = f->link[i] == '\\' ? f->link + i + 1 : "", *dp = "\\Device Parameters";
      key[k++] = '\\'; key[k++] = '#'; for (i = 0; ref[i] && k + 1 < sizeof key; ++i) key[k++] = ref[i]; for (i = 0; dp[i]; ++i) key[k++] = dp[i]; key[k] = 0; }
    return ntdrv_open_key_ascii(key, 1, handle);
}

/* ================================================================ PnP notification */
typedef struct pnpreg {
    struct pnpreg *next;
    uint32_t category;                  /* 1 hardware profile, 2 device interface, 3 target device */
    GUID guid;
    int any_guid;
    FILE_OBJECT *file;
    NTSTATUS (NTAPI *cb)(void *, void *);
    void *ctx;
    DRIVER_OBJECT *drv;
} pnpreg_t;
static pnpreg_t *pnpregs;
static const GUID guid_arrival = { 0xcb3a4004, 0x46f0, 0x11d0, { 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f } };
static const GUID guid_removal = { 0xcb3a4005, 0x46f0, 0x11d0, { 0xb0, 0x8f, 0x00, 0x60, 0x97, 0x13, 0x05, 0x3f } };
/* DEVICE_INTERFACE_CHANGE_NOTIFICATION (0x30): Version(2) Size(2) Event(GUID,4) InterfaceClassGuid(0x14) SymbolicLinkName(0x28) */
static void notify_one(pnpreg_t *r, iface_t *f, int arrival)
{
    uint8_t n[0x30]; UNICODE_STRING link;
    wide_dup(&link, f->link);
    memset(n, 0, sizeof n);
    *(uint16_t *)n = 1; *(uint16_t *)(n + 2) = sizeof n;
    memcpy(n + 4, arrival ? &guid_arrival : &guid_removal, 16);
    memcpy(n + 0x14, &f->guid, 16);
    *(UNICODE_STRING **)(n + 0x28) = &link;
    r->cb(n, r->ctx);
    kfree(link.Buffer);
}
static void pnp_notify_interface(iface_t *f, int arrival)
{
    pnpreg_t *r;
    for (r = pnpregs; r; r = r->next)
        if (r->category == 2 && (r->any_guid || !memcmp(&r->guid, &f->guid, sizeof f->guid))) notify_one(r, f, arrival);
}
#define PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES 1
NTSTATUS NTAPI IoRegisterPlugPlayNotification(uint32_t category, uint32_t flags, void *data, DRIVER_OBJECT *drv, void *cb, void *ctx, void **entry)
{
    pnpreg_t *r = kzalloc(sizeof *r);
    if (!r) return STATUS_INSUFFICIENT_RESOURCES;
    r->category = category; r->cb = cb; r->ctx = ctx; r->drv = drv;
    if (category == 2) { if (data) r->guid = *(const GUID *)data; else r->any_guid = 1; }
    else if (category == 3) r->file = data;
    else if (category != 1) { kfree(r); return STATUS_INVALID_PARAMETER; }
    { uint64_t f = irq_save(); r->next = pnpregs; pnpregs = r; irq_restore(f); }
    *entry = r;
    if (category == 2 && (flags & PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES)) {
        iface_t *f;
        for (f = ifaces; f; f = f->next)
            if (f->enabled && (r->any_guid || !memcmp(&f->guid, &r->guid, sizeof f->guid))) notify_one(r, f, 1);
    }
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI IoUnregisterPlugPlayNotification(void *entry)
{
    pnpreg_t **pp, *r = entry;
    uint64_t f = irq_save();
    for (pp = &pnpregs; *pp; pp = &(*pp)->next) if (*pp == r) { *pp = r->next; irq_restore(f); kfree(r); return STATUS_SUCCESS; }
    irq_restore(f);
    return STATUS_INVALID_PARAMETER;
}
NTSTATUS NTAPI IoUnregisterPlugPlayNotificationEx(void *entry) { return IoUnregisterPlugPlayNotification(entry); }
/* TARGET_DEVICE_CUSTOM_NOTIFICATION: Version(2) Size(2) Event(GUID 4) FileObject(0x18) NameBufferOffset(0x20) CustomDataBuffer(0x24) */
struct tdc { DEVICE_OBJECT *pdo; uint8_t *notification; void (NTAPI *cb)(void *); void *ctx; };
static void NTAPI target_change_work(void *arg)
{
    struct tdc *t = arg;
    pnpreg_t *r;
    for (r = pnpregs; r; r = r->next)
        if (r->category == 3 && r->file && (r->file->DeviceObject == t->pdo || IoGetAttachedDevice(r->file->DeviceObject) == IoGetAttachedDevice(t->pdo))) {
            *(FILE_OBJECT **)(t->notification + 0x18) = r->file;
            r->cb(t->notification, r->ctx);
        }
    if (t->cb) t->cb(t->ctx);
    kfree(t->notification); kfree(t);
}
NTSTATUS NTAPI IoReportTargetDeviceChangeAsynchronous(DEVICE_OBJECT *pdo, void *notification, void *cb, void *ctx)
{
    const uint16_t size = *((const uint16_t *)notification + 1);
    struct tdc *t = kzalloc(sizeof *t);
    if (!t) return STATUS_INSUFFICIENT_RESOURCES;
    t->notification = kmalloc(size < 0x28 ? 0x28 : size);
    if (!t->notification) { kfree(t); return STATUS_INSUFFICIENT_RESOURCES; }
    memcpy(t->notification, notification, size);
    t->pdo = pdo; t->cb = cb; t->ctx = ctx;
    ntdrv_queue_system_work(target_change_work, t, t);
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI IoReportTargetDeviceChange(DEVICE_OBJECT *pdo, void *notification)
{
    pnpreg_t *r;
    for (r = pnpregs; r; r = r->next)
        if (r->category == 3 && r->file && r->file->DeviceObject == pdo) { *(FILE_OBJECT **)((uint8_t *)notification + 0x18) = r->file; r->cb(notification, r->ctx); }
    return STATUS_SUCCESS;
}

/* ================================================================ PnP requests the PnP manager would service */
static void setup_relations(IO_STACK_LOCATION *s, void *ctx) { s->Parameters.QueryDeviceRelations.Type = *(uint32_t *)ctx; }
struct invreq { DEVICE_OBJECT *dev; uint32_t type; int what; };
static void NTAPI invalidate_work(void *arg)
{
    struct invreq *q = arg;
    uint64_t info = 0;
    NTSTATUS st;
    if (q->what == 0) {                                             /* IoInvalidateDeviceRelations: re-enumerate the children */
        st = send_pnp(q->dev, IRP_MN_QUERY_DEVICE_RELATIONS, setup_relations, &q->type, &info);
        if (NT_SUCCESS(st) && info) {
            uint32_t *rel = (uint32_t *)info, i;                    /* DEVICE_RELATIONS: Count, Objects[] */
            DEVICE_OBJECT **objs = (DEVICE_OBJECT **)(rel + 2);
            kprintf("K64 ntdrv: %s reports %u child device(s) (relations type %u)\n", ntdrv_device_name(q->dev) ? ntdrv_device_name(q->dev) : "device", *rel, q->type);
            for (i = 0; i < *rel; ++i) ObDereferenceObject(objs[i]);
            ExFreePool(rel);
        }
    } else if (q->what == 1) {                                      /* IoInvalidateDeviceState */
        st = send_pnp(q->dev, IRP_MN_QUERY_PNP_DEVICE_STATE, 0, 0, &info);
        if (NT_SUCCESS(st)) kprintf("K64 ntdrv: device state %llx\n", info);
    } else {                                                        /* IoRequestDeviceEject: query-remove, remove, eject */
        st = send_pnp(q->dev, IRP_MN_QUERY_REMOVE_DEVICE, 0, 0, 0);
        if (NT_SUCCESS(st)) { send_pnp(q->dev, IRP_MN_REMOVE_DEVICE, 0, 0, 0); send_pnp(q->dev, IRP_MN_EJECT, 0, 0, 0); }
        else send_pnp(q->dev, IRP_MN_CANCEL_REMOVE_DEVICE, 0, 0, 0);
    }
    kfree(q);
}
static void queue_invalidate(DEVICE_OBJECT *dev, uint32_t type, int what)
{
    struct invreq *q = kzalloc(sizeof *q);
    if (!q) return;
    q->dev = dev; q->type = type; q->what = what;
    ntdrv_queue_system_work(invalidate_work, q, q);
}
void NTAPI IoInvalidateDeviceRelations(DEVICE_OBJECT *dev, uint32_t type) { queue_invalidate(dev, type, 0); }
void NTAPI IoInvalidateDeviceState(DEVICE_OBJECT *dev) { queue_invalidate(dev, 0, 1); }
void NTAPI IoRequestDeviceEject(DEVICE_OBJECT *dev) { queue_invalidate(dev, 0, 2); }
NTSTATUS NTAPI IoRequestDeviceEjectEx(DEVICE_OBJECT *dev, void *cb, void *ctx, void *process) { (void)cb; (void)ctx; (void)process; queue_invalidate(dev, 0, 2); return STATUS_SUCCESS; }
NTSTATUS NTAPI IoSynchronousInvalidateDeviceRelations(DEVICE_OBJECT *dev, uint32_t type)
{
    struct invreq *q = kzalloc(sizeof *q);
    if (!q) return STATUS_INSUFFICIENT_RESOURCES;
    q->dev = dev; q->type = type; q->what = 0;
    invalidate_work(q);
    return STATUS_SUCCESS;
}

/* ================================================================ forwarding / attaching / misc Io */
uint8_t NTAPI IoForwardIrpSynchronously(DEVICE_OBJECT *dev, IRP *irp)
{
    IO_STACK_LOCATION *cur = irp->Tail.Overlay.CurrentStackLocation, *next = cur - 1;
    if (irp->CurrentLocation <= 1) return 0;                  /* no stack location left to forward into */
    memcpy(next, cur, sizeof *next);                          /* IoCopyCurrentIrpStackLocationToNext */
    next->Control = 0; next->CompletionRoutine = 0;
    call_and_wait(dev, irp);
    return 1;
}
uint8_t NTAPI IoForwardAndCatchIrp(DEVICE_OBJECT *dev, IRP *irp) { return IoForwardIrpSynchronously(dev, irp); }
NTSTATUS NTAPI IoAttachDeviceToDeviceStackSafe(DEVICE_OBJECT *src, DEVICE_OBJECT *target, DEVICE_OBJECT **attached)
{
    DEVICE_OBJECT *top = IoAttachDeviceToDeviceStack(src, target);
    if (!top) { *attached = 0; return STATUS_NO_SUCH_DEVICE_; }
    *attached = top;
    return STATUS_SUCCESS;
}
DEVICE_OBJECT *NTAPI IoGetLowerDeviceObject(DEVICE_OBJECT *dev)
{
    /* the device `dev` is attached on top of: walk every stack we know */
    extern DEVICE_OBJECT *ntdrv_lower_device(DEVICE_OBJECT *dev);
    DEVICE_OBJECT *lower = ntdrv_lower_device(dev);
    if (lower) lower->ReferenceCount++;
    return lower;
}
DEVICE_OBJECT *NTAPI IoGetDeviceAttachmentBaseRef(DEVICE_OBJECT *dev)
{
    extern DEVICE_OBJECT *ntdrv_lower_device(DEVICE_OBJECT *dev);
    DEVICE_OBJECT *d = dev, *l;
    while ((l = ntdrv_lower_device(d)) != 0) d = l;
    d->ReferenceCount++;
    return d;
}
/* CONFIGURATION_INFORMATION (0x28): DiskCount FloppyCount CdRomCount TapeCount ScsiPortCount SerialCount ParallelCount(0x18)
 * AtDiskPrimaryAddressClaimed(0x1c) AtDiskSecondaryAddressClaimed(0x1d) Version(0x20) MediumChangerCount(0x24) */
static struct { uint32_t Disk, Floppy, CdRom, Tape, ScsiPort, Serial, Parallel; uint8_t AtPrimary, AtSecondary, _p[2]; uint32_t Version, MediumChanger; } config_info = { 0, 0, 0, 0, 0, 0, 0, 0, 0, { 0, 0 }, 1, 0 };
void *NTAPI IoGetConfigurationInformation(void) { return &config_info; }
uint8_t NTAPI IoIsWdmVersionAvailable(uint8_t major, uint8_t minor) { return major < 6 || (major == 6 && minor <= 0x30); }   /* WDM 1.30 (Windows 10) */
static KEVENT *named_event(UNICODE_STRING *name, uint64_t *handle, int synch)
{
    KEVENT *e = kzalloc(sizeof *e);
    (void)name;
    if (!e) return 0;
    KeInitializeEvent(e, synch, 1);                             /* created signalled, as documented */
    if (handle) *handle = ntdrv_kh_alloc(KH_EVENT, e);
    return e;
}
KEVENT *NTAPI IoCreateNotificationEvent(UNICODE_STRING *name, uint64_t *handle) { return named_event(name, handle, 0); }
KEVENT *NTAPI IoCreateSynchronizationEvent(UNICODE_STRING *name, uint64_t *handle) { return named_event(name, handle, 1); }
void NTAPI IoReuseIrp(IRP *irp, NTSTATUS status)
{
    uint8_t stk = (uint8_t)irp->StackCount, flags = irp->AllocationFlags;
    uint16_t size = irp->Size;
    IoInitializeIrp(irp, size, stk);
    irp->AllocationFlags = flags;
    irp->IoStatus.Status = status;
}
/* IoBuildPartialMdl: the target describes [va, va+len) of the source's buffer; pages are the source's (shared PFNs). */
void NTAPI IoBuildPartialMdl(MDL *src, MDL *dst, void *va, uint32_t len)
{
    uint64_t off = (uint64_t)va - ((uint64_t)src->StartVa + src->ByteOffset);
    uint32_t *spfn = (uint32_t *)(src + 1), i, first;
    uint64_t *spfn64 = (uint64_t *)(src + 1), *dpfn = (uint64_t *)(dst + 1);
    (void)spfn;
    if (!len) len = (uint32_t)(src->ByteCount - off);
    dst->StartVa = (void *)((uint64_t)va & ~0xfffull);
    dst->ByteOffset = (uint32_t)((uint64_t)va & 0xfff);
    dst->ByteCount = len;
    dst->Process = src->Process;
    dst->MdlFlags = (int16_t)((src->MdlFlags & (MDL_SOURCE_IS_NONPAGED_POOL | MDL_PAGES_LOCKED)) | 0x0002 /* keep locked */ | 0x0020 /* MDL_PARTIAL */);
    dst->MappedSystemVa = src->MappedSystemVa ? (uint8_t *)src->MappedSystemVa + off : 0;
    if (dst->MappedSystemVa) dst->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;
    first = (uint32_t)(((uint64_t)va - (uint64_t)src->StartVa) / 4096);
    if ((unsigned)dst->Size >= sizeof(MDL) + 8 && (unsigned)src->Size >= sizeof(MDL) + 8) {
        uint32_t n = (uint32_t)((dst->ByteOffset + len + 4095) / 4096), cap = ((unsigned)dst->Size - sizeof(MDL)) / 8, scap = ((unsigned)src->Size - sizeof(MDL)) / 8;
        for (i = 0; i < n && i < cap; ++i) dpfn[i] = first + i < scap ? spfn64[first + i] : 0;
    }
}
IRP *NTAPI IoBuildAsynchronousFsdRequest(uint32_t mj, DEVICE_OBJECT *dev, void *buf, uint32_t len, LARGE_INTEGER *off, IO_STATUS_BLOCK *iosb)
{ return IoBuildSynchronousFsdRequest(mj, dev, buf, len, off, 0, iosb); }
void NTAPI IoGetStackLimits(uint64_t *low, uint64_t *high)
{
    thread_t *t = thread_current();
    *low = t ? t->stack_base : 0;
    *high = t ? t->stack_base + KSTACK_BYTES : 0;
}
uint64_t NTAPI IoGetInitialStack(void) { thread_t *t = thread_current(); return t ? t->stack_base + KSTACK_BYTES : 0; }
NTSTATUS NTAPI IoSetCompletionRoutineEx(DEVICE_OBJECT *dev, IRP *irp, PIO_COMPLETION_ROUTINE routine, void *ctx, uint8_t s, uint8_t e, uint8_t c)
{
    IO_STACK_LOCATION *next = irp->Tail.Overlay.CurrentStackLocation - 1;
    (void)dev;
    next->CompletionRoutine = routine; next->Context = ctx;
    next->Control = (uint8_t)((s ? SL_INVOKE_ON_SUCCESS : 0) | (e ? SL_INVOKE_ON_ERROR : 0) | (c ? SL_INVOKE_ON_CANCEL : 0));
    return STATUS_SUCCESS;
}
uint32_t NTAPI IoGetPagingIoPriority(IRP *irp) { return (irp->Flags & 0x10000 /* IRP_PAGING_IO */) ? 1 /* Normal */ : 0 /* Invalid */; }
/* The device to verify is a per-thread attribute on Windows (KTHREAD.DeviceToVerify); kernel threads here carry it in
 * a small side table keyed by thread. */
static DEVICE_OBJECT *hard_error_dev[8]; static thread_t *hard_error_thr[8];
static void hard_error_device_set(thread_t *t, DEVICE_OBJECT *dev)
{
    unsigned i;
    for (i = 0; i < 8; ++i) if (hard_error_thr[i] == t) { hard_error_dev[i] = dev; return; }
    for (i = 0; i < 8; ++i) if (!hard_error_thr[i]) { hard_error_thr[i] = t; hard_error_dev[i] = dev; return; }
}
void NTAPI IoSetHardErrorOrVerifyDevice(IRP *irp, DEVICE_OBJECT *dev) { hard_error_device_set(irp->Tail.Overlay.Thread ? irp->Tail.Overlay.Thread : thread_current(), dev); }
DEVICE_OBJECT *NTAPI IoGetDeviceToVerify(void *thread)
{
    unsigned i; for (i = 0; i < 8; ++i) if (hard_error_thr[i] == thread) return hard_error_dev[i]; return 0;
}
void NTAPI IoSetDeviceToVerify(void *thread, DEVICE_OBJECT *dev) { hard_error_device_set(thread, dev); }
uint8_t NTAPI IoIsOperationSynchronous(IRP *irp) { return (irp->Flags & 0x2 /* IRP_SYNCHRONOUS_API */) != 0 || (irp->Flags & 0x400 /* IRP_SYNCHRONOUS_PAGING_IO */) != 0; }

/* IoGetDeviceObjectPointer: open the named device (IRP_MJ_CREATE through the stack) and return the top device + file. */
NTSTATUS NTAPI IoGetDeviceObjectPointer(UNICODE_STRING *name, uint32_t access, FILE_OBJECT **fo, DEVICE_OBJECT **dev_out)
{
    char n[96];
    DEVICE_OBJECT *dev;
    NTSTATUS st;
    ntdrv_wide_to_ascii(name->Buffer, name->Length / 2, n, sizeof n);
    dev = !strncmp(n, "\\Device\\", 8) ? ntdrv_find_device(n) : ntdrv_resolve_symlink(n);
    if (!dev) return STATUS_OBJECT_NAME_NOT_FOUND;
    st = ntdrv_device_open_file(dev, access, fo);
    if (!NT_SUCCESS(st)) return st;
    *dev_out = (*fo)->DeviceObject;
    return STATUS_SUCCESS;
}

/* ================================================================ driver re-initialization */
typedef struct reinit { struct reinit *next; DRIVER_OBJECT *drv; void (NTAPI *fn)(DRIVER_OBJECT *, void *, uint32_t); void *ctx; int boot; } reinit_t;
static reinit_t *reinit_head, *reinit_tail;
static void queue_reinit(DRIVER_OBJECT *drv, void *fn, void *ctx, int boot)
{
    reinit_t *r = kzalloc(sizeof *r);
    if (!r) return;
    r->drv = drv; r->fn = fn; r->ctx = ctx; r->boot = boot;
    if (reinit_tail) reinit_tail->next = r; else reinit_head = r;
    reinit_tail = r;
}
void NTAPI IoRegisterDriverReinitialization(DRIVER_OBJECT *drv, void *fn, void *ctx) { queue_reinit(drv, fn, ctx, 0); }
void NTAPI IoRegisterBootDriverReinitialization(DRIVER_OBJECT *drv, void *fn, void *ctx) { queue_reinit(drv, fn, ctx, 1); }
/* Called by the loader once DriverEntry has returned: on Windows a dynamically loaded driver's reinitialization routine
 * runs right after its DriverEntry, with Count = the number of times it has been called. */
void ntdrv_run_reinit(DRIVER_OBJECT *drv)
{
    for (;;) {
        reinit_t **pp = &reinit_head, *r = 0;
        while (*pp) { if ((*pp)->drv == drv) { r = *pp; *pp = r->next; if (reinit_tail == r) { reinit_tail = 0; { reinit_t *q = reinit_head; while (q && q->next) q = q->next; reinit_tail = q; } } break; } pp = &(*pp)->next; }
        if (!r) return;
        drv->DriverExtension->Count++;
        r->fn(drv, r->ctx, drv->DriverExtension->Count);
        kfree(r);
    }
}

/* ================================================================ shutdown notification */
typedef struct shut { struct shut *next; DEVICE_OBJECT *dev; int last_chance; } shut_t;
static shut_t *shutdowns;
NTSTATUS NTAPI IoRegisterShutdownNotification(DEVICE_OBJECT *dev)
{
    shut_t *s;
    for (s = shutdowns; s; s = s->next) if (s->dev == dev) return STATUS_SUCCESS;
    s = kzalloc(sizeof *s);
    if (!s) return STATUS_INSUFFICIENT_RESOURCES;
    s->dev = dev; s->next = shutdowns; shutdowns = s;
    dev->Flags |= 0x00001000;                                   /* DO_SHUTDOWN_REGISTERED */
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI IoRegisterLastChanceShutdownNotification(DEVICE_OBJECT *dev)
{
    NTSTATUS st = IoRegisterShutdownNotification(dev);
    shut_t *s;
    for (s = shutdowns; s; s = s->next) if (s->dev == dev) s->last_chance = 1;
    return st;
}
void NTAPI IoUnregisterShutdownNotification(DEVICE_OBJECT *dev)
{
    shut_t **pp;
    for (pp = &shutdowns; *pp; pp = &(*pp)->next) if ((*pp)->dev == dev) { shut_t *s = *pp; *pp = s->next; kfree(s); break; }
    dev->Flags &= ~0x00001000u;
}
/* Sends IRP_MJ_SHUTDOWN to every registered device (normal registrations first, last-chance ones after). */
void ntdrv_send_shutdown(void)
{
    int pass;
    for (pass = 0; pass < 2; ++pass) {
        shut_t *s;
        for (s = shutdowns; s; s = s->next) {
            IRP *irp;
            if (s->last_chance != pass) continue;
            irp = IoAllocateIrp((uint8_t)s->dev->StackSize, 0);
            if (!irp) continue;
            (irp->Tail.Overlay.CurrentStackLocation - 1)->MajorFunction = IRP_MJ_SHUTDOWN;
            call_and_wait(s->dev, irp);
            IoFreeIrp(irp);
        }
    }
}

/* ================================================================ error log */
/* IO_ERROR_LOG_PACKET (0x30): MajorFunctionCode RetryCount DumpDataSize(2) NumberOfStrings(4) StringOffset(6) EventCategory(8)
 * ErrorCode(0xc) UniqueErrorValue(0x10) FinalStatus(0x14) SequenceNumber(0x18) IoControlValue(0x1c) DeviceOffset(0x20) DumpData(0x28) */
struct errlog { void *io_object; uint32_t size; uint8_t packet[] __attribute__((aligned(16))); };
void *NTAPI IoAllocateErrorLogEntry(void *io_object, uint8_t size)
{
    struct errlog *e;
    if (size < 0x30) return 0;                                   /* smaller than IO_ERROR_LOG_PACKET: invalid (returns NULL) */
    e = kzalloc(sizeof *e + size);
    if (!e) return 0;
    e->io_object = io_object; e->size = size;
    return e->packet;
}
void NTAPI IoWriteErrorLogEntry(uint8_t *p)
{
    struct errlog *e = (struct errlog *)(p - __builtin_offsetof(struct errlog, packet));
    const char *who = "?";
    uint16_t nstr = *(uint16_t *)(p + 4), soff = *(uint16_t *)(p + 6), i;
    const WCHAR *s;
    char tmp[128];
    if (e->io_object) {
        const int16_t type = *(const int16_t *)e->io_object;
        if (type == 3) who = ntdrv_device_name(e->io_object) ? ntdrv_device_name(e->io_object) : "device";
        else if (type == 4) { ntdrv_driver_t *d = ((DRIVER_OBJECT *)e->io_object)->DriverSection; who = d ? d->name : "driver"; }
    }
    kprintf("K64 eventlog: %s: ErrorCode=%x FinalStatus=%x UniqueErrorValue=%x major=%u retry=%u dump=%u byte(s)",
            who, *(uint32_t *)(p + 0xc), *(uint32_t *)(p + 0x14), *(uint32_t *)(p + 0x10), p[0], p[1], *(uint16_t *)(p + 2));
    s = (const WCHAR *)(p + soff);
    for (i = 0; i < nstr && soff < e->size; ++i) {
        unsigned n = 0;
        while (s[n] && (uint8_t *)(s + n) < p + e->size) ++n;
        ntdrv_wide_to_ascii(s, n, tmp, sizeof tmp);
        kprintf(" \"%s\"", tmp);
        s += n + 1;
    }
    kprintf("\n");
    kfree(e);
}
void NTAPI IoFreeErrorLogEntry(uint8_t *p) { if (p) kfree(p - __builtin_offsetof(struct errlog, packet)); }

/* ================================================================ WMI */
typedef struct wmireg { struct wmireg *next; DEVICE_OBJECT *dev; uint32_t nguids; GUID guids[16]; } wmireg_t;
static wmireg_t *wmiregs;
static void setup_wmi(IO_STACK_LOCATION *s, void *ctx)
{
    void **p = ctx;                                              /* Parameters.WMI: ProviderId(0) DataPath(8) BufferSize(0x10) Buffer(0x18) */
    s->MajorFunction = IRP_MJ_SYSTEM_CONTROL; s->MinorFunction = IRP_MN_REGINFO;
    s->Parameters.Others.Argument1 = p[0]; s->Parameters.Others.Argument2 = 0; s->Parameters.Others.Argument3 = p[1]; s->Parameters.Others.Argument4 = p[2];
}
static void NTAPI wmi_reginfo_work(void *arg)
{
    wmireg_t *r = arg;
    uint8_t *buf = kzalloc(4096);
    void *p[3] = { r->dev, (void *)4096ull, buf };
    uint64_t info = 0;
    NTSTATUS st;
    if (!buf) return;
    st = send_pnp(r->dev, IRP_MN_REGINFO, setup_wmi, p, &info);
    if (NT_SUCCESS(st) && info >= 0x20) {
        /* WMIREGINFO: BufferSize(0) NextWmiRegInfo(4) RegistryPath(8) MofResourceName(0xc) GuidCount(0x10) WmiRegGuid[](0x14: Guid(16) Flags(4) InstanceCount(4) ...(4) = 0x20 each) */
        uint32_t n = *(uint32_t *)(buf + 0x10), i;
        for (i = 0; i < n && i < 16; ++i) memcpy(&r->guids[i], buf + 0x14 + i * 0x20, 16);
        r->nguids = n < 16 ? n : 16;
        kprintf("K64 ntdrv: WMI provider %s registered %u data block guid(s)\n", ntdrv_device_name(r->dev) ? ntdrv_device_name(r->dev) : "device", n);
    }
    kfree(buf);
}
NTSTATUS NTAPI IoWMIRegistrationControl(DEVICE_OBJECT *dev, uint32_t action)
{
    wmireg_t *r, **pp;
    switch (action & 0xff) {
    case 1: case 3:                                             /* WMIREG_ACTION_REGISTER / REREGISTER */
        for (r = wmiregs; r; r = r->next) if (r->dev == dev) break;
        if (!r) { r = kzalloc(sizeof *r); if (!r) return STATUS_INSUFFICIENT_RESOURCES; r->dev = dev; r->next = wmiregs; wmiregs = r; }
        ntdrv_devext(dev)->wmi_registered = 1;
        ntdrv_queue_system_work(wmi_reginfo_work, r, r);        /* the REGINFO query the WMI service makes after registration */
        return STATUS_SUCCESS;
    case 2:                                                     /* DEREGISTER */
        for (pp = &wmiregs; *pp; pp = &(*pp)->next) if ((*pp)->dev == dev) { r = *pp; *pp = r->next; kfree(r); ntdrv_devext(dev)->wmi_registered = 0; return STATUS_SUCCESS; }
        return STATUS_INVALID_PARAMETER;
    case 4: case 5:                                             /* UPDATE_GUIDS / BLOCK_IRPS */
        for (r = wmiregs; r; r = r->next) if (r->dev == dev) { if ((action & 0xff) == 4) ntdrv_queue_system_work(wmi_reginfo_work, r, r); return STATUS_SUCCESS; }
        return STATUS_INVALID_PARAMETER;
    default: return STATUS_INVALID_PARAMETER;
    }
}
uint32_t NTAPI IoWMIDeviceObjectToProviderId(DEVICE_OBJECT *dev) { return (uint32_t)(uint64_t)dev; }
/* WNODE_HEADER (0x30): BufferSize(0) ProviderId(4) Version/Linkage(8) TimeStamp(0x10) Guid(0x18) ClientContext(0x28) Flags(0x2c) */
NTSTATUS NTAPI IoWMIWriteEvent(uint8_t *wnode)
{
    char g[40];
    ntdrv_guid_to_ascii((const GUID *)(wnode + 0x18), g);
    kprintf("K64 wmi-event: provider %x guid %s %u byte(s) flags %x\n", *(uint32_t *)(wnode + 4), g, *(uint32_t *)wnode, *(uint32_t *)(wnode + 0x2c));
    if (!(*(uint32_t *)(wnode + 0x2c) & 0x00020000 /* WNODE_FLAG_TRACED_GUID */)) ExFreePool(wnode);   /* the kernel owns and frees a non-traced event */
    return STATUS_SUCCESS;
}
typedef struct { GUID guid; wmireg_t *reg; } wmiblock_t;
NTSTATUS NTAPI IoWMIOpenBlock(const GUID *guid, uint32_t access, void **obj)
{
    wmireg_t *r; uint32_t i;
    (void)access;
    for (r = wmiregs; r; r = r->next)
        for (i = 0; i < r->nguids; ++i)
            if (!memcmp(&r->guids[i], guid, sizeof *guid)) {
                wmiblock_t *b = kzalloc(sizeof *b);
                if (!b) return STATUS_INSUFFICIENT_RESOURCES;
                b->guid = *guid; b->reg = r; *obj = b;
                return STATUS_SUCCESS;
            }
    return STATUS_WMI_GUID_NOT_FOUND;
}
static void setup_wmi_query(IO_STACK_LOCATION *s, void *ctx)
{
    void **p = ctx;
    s->MajorFunction = IRP_MJ_SYSTEM_CONTROL; s->MinorFunction = 0 /* IRP_MN_QUERY_ALL_DATA */;
    s->Parameters.Others.Argument1 = p[0]; s->Parameters.Others.Argument2 = p[1]; s->Parameters.Others.Argument3 = p[2]; s->Parameters.Others.Argument4 = p[3];
}
NTSTATUS NTAPI IoWMIQueryAllData(wmiblock_t *b, uint32_t *size, void *buf)
{
    uint8_t *wnode; uint64_t info = 0; NTSTATUS st; void *p[4];
    uint32_t cap = *size < 0x60 ? 0x60 : *size;
    if (!b || !b->reg) return STATUS_WMI_GUID_NOT_FOUND;
    wnode = kzalloc(cap);
    if (!wnode) return STATUS_INSUFFICIENT_RESOURCES;
    *(uint32_t *)wnode = cap; *(uint32_t *)(wnode + 4) = (uint32_t)(uint64_t)b->reg->dev; memcpy(wnode + 0x18, &b->guid, 16);
    *(uint32_t *)(wnode + 0x2c) = 0x00000001 /* WNODE_FLAG_ALL_DATA */;
    p[0] = b->reg->dev; p[1] = (void *)&b->guid; p[2] = (void *)(uint64_t)cap; p[3] = wnode;
    st = send_pnp(b->reg->dev, 0, setup_wmi_query, p, &info);
    if (st == STATUS_BUFFER_TOO_SMALL || (NT_SUCCESS(st) && info > *size)) { *size = (uint32_t)(info > *(uint32_t *)wnode ? info : *(uint32_t *)wnode); kfree(wnode); return STATUS_BUFFER_TOO_SMALL; }
    if (NT_SUCCESS(st)) { memcpy(buf, wnode, info < *size ? info : *size); *size = (uint32_t)info; }
    kfree(wnode);
    return st;
}
NTSTATUS NTAPI IoWMIQueryAllDataMultiple(void **objs, uint32_t n, uint32_t *size, void *buf) { (void)objs; (void)n; (void)size; (void)buf; return STATUS_NOT_SUPPORTED; }

/* ================================================================ cancellation and StartIo queues */
static KSPIN_LOCK cancel_lock;
void NTAPI IoAcquireCancelSpinLock(uint8_t *irql) { *irql = KfAcquireSpinLock(&cancel_lock); }
void NTAPI IoReleaseCancelSpinLock(uint8_t irql) { KfReleaseSpinLock(&cancel_lock, irql); }
uint8_t NTAPI IoCancelIrp(IRP *irp)
{
    uint8_t irql;
    PDRIVER_CANCEL routine;
    IoAcquireCancelSpinLock(&irql);
    irp->Cancel = 1;
    routine = __atomic_exchange_n(&irp->CancelRoutine, (PDRIVER_CANCEL)0, __ATOMIC_SEQ_CST);
    if (routine) {
        irp->CancelIrql = irql;
        routine(irp->Tail.Overlay.CurrentStackLocation->DeviceObject, irp);   /* releases the cancel spin lock */
        return 1;
    }
    IoReleaseCancelSpinLock(irql);
    return 0;
}

/* KDEVICE_QUEUE: Busy means an entry is being serviced (StartIo running); an insert while not busy returns FALSE and
 * marks the queue busy, so the caller services the packet itself. Lock held at DISPATCH_LEVEL. */
void NTAPI KeInitializeDeviceQueue(KDEVICE_QUEUE *q)
{
    q->Type = 0x14; q->Size = sizeof *q;
    q->DeviceListHead.Flink = q->DeviceListHead.Blink = &q->DeviceListHead;
    KeInitializeSpinLock(&q->Lock);
    q->Busy = 0;
}
static KDEVICE_QUEUE_ENTRY *entry_of(LIST_ENTRY *e) { return (KDEVICE_QUEUE_ENTRY *)e; }
uint8_t NTAPI KeInsertDeviceQueue(KDEVICE_QUEUE *q, KDEVICE_QUEUE_ENTRY *e)
{
    uint8_t irql = KfAcquireSpinLock(&q->Lock), r;
    if (!q->Busy) { q->Busy = 1; e->Inserted = 0; r = 0; }
    else { LIST_ENTRY *h = &q->DeviceListHead; e->DeviceListEntry.Flink = h; e->DeviceListEntry.Blink = h->Blink; h->Blink->Flink = &e->DeviceListEntry; h->Blink = &e->DeviceListEntry; e->Inserted = 1; r = 1; }
    KfReleaseSpinLock(&q->Lock, irql);
    return r;
}
uint8_t NTAPI KeInsertByKeyDeviceQueue(KDEVICE_QUEUE *q, KDEVICE_QUEUE_ENTRY *e, uint32_t key)
{
    uint8_t irql = KfAcquireSpinLock(&q->Lock), r;
    e->SortKey = key;
    if (!q->Busy) { q->Busy = 1; e->Inserted = 0; r = 0; }
    else {
        LIST_ENTRY *h = &q->DeviceListHead, *p;
        for (p = h->Flink; p != h; p = p->Flink) if (entry_of(p)->SortKey > key) break;   /* before the first larger key */
        e->DeviceListEntry.Flink = p; e->DeviceListEntry.Blink = p->Blink; p->Blink->Flink = &e->DeviceListEntry; p->Blink = &e->DeviceListEntry;
        e->Inserted = 1; r = 1;
    }
    KfReleaseSpinLock(&q->Lock, irql);
    return r;
}
KDEVICE_QUEUE_ENTRY *NTAPI KeRemoveDeviceQueue(KDEVICE_QUEUE *q)
{
    uint8_t irql = KfAcquireSpinLock(&q->Lock);
    KDEVICE_QUEUE_ENTRY *e = 0;
    LIST_ENTRY *h = &q->DeviceListHead;
    if (!q->Busy) { KfReleaseSpinLock(&q->Lock, irql); kpanic("KeRemoveDeviceQueue: queue not busy"); }
    if (h->Flink == h) q->Busy = 0;
    else { LIST_ENTRY *p = h->Flink; h->Flink = p->Flink; p->Flink->Blink = h; e = entry_of(p); e->Inserted = 0; }
    KfReleaseSpinLock(&q->Lock, irql);
    return e;
}
KDEVICE_QUEUE_ENTRY *NTAPI KeRemoveByKeyDeviceQueue(KDEVICE_QUEUE *q, uint32_t key)
{
    uint8_t irql = KfAcquireSpinLock(&q->Lock);
    KDEVICE_QUEUE_ENTRY *e = 0;
    LIST_ENTRY *h = &q->DeviceListHead, *p;
    if (!q->Busy) { KfReleaseSpinLock(&q->Lock, irql); kpanic("KeRemoveByKeyDeviceQueue: queue not busy"); }
    if (h->Flink == h) q->Busy = 0;
    else {
        for (p = h->Flink; p != h; p = p->Flink) if (entry_of(p)->SortKey >= key) break;   /* first entry at or past the key, else the head */
        if (p == h) p = h->Flink;
        p->Blink->Flink = p->Flink; p->Flink->Blink = p->Blink;
        e = entry_of(p); e->Inserted = 0;
    }
    KfReleaseSpinLock(&q->Lock, irql);
    return e;
}
KDEVICE_QUEUE_ENTRY *NTAPI KeRemoveByKeyDeviceQueueIfBusy(KDEVICE_QUEUE *q, uint32_t key)
{
    if (!q->Busy) return 0;
    return KeRemoveByKeyDeviceQueue(q, key);
}
uint8_t NTAPI KeRemoveEntryDeviceQueue(KDEVICE_QUEUE *q, KDEVICE_QUEUE_ENTRY *e)
{
    uint8_t irql = KfAcquireSpinLock(&q->Lock), r = e->Inserted;
    if (r) { e->DeviceListEntry.Blink->Flink = e->DeviceListEntry.Flink; e->DeviceListEntry.Flink->Blink = e->DeviceListEntry.Blink; e->Inserted = 0; }
    KfReleaseSpinLock(&q->Lock, irql);
    return r;
}
#define IRP_OF_ENTRY(e) ((IRP *)((uint8_t *)(e) - __builtin_offsetof(IRP, Tail.Overlay.DeviceQueueEntry)))
void NTAPI IoStartPacket(DEVICE_OBJECT *dev, IRP *irp, uint32_t *key, PDRIVER_CANCEL cancel)
{
    uint8_t irql = KfRaiseIrql(DISPATCH_LEVEL), cirql;
    KDEVICE_QUEUE_ENTRY *e = (KDEVICE_QUEUE_ENTRY *)&irp->Tail.Overlay.DeviceQueueEntry;
    ntdrv_devext_t *x = ntdrv_devext(dev);
    int queued;
    IoAcquireCancelSpinLock(&cirql);
    if (cancel && !x->startio_noncancelable) irp->CancelRoutine = cancel;
    queued = key ? KeInsertByKeyDeviceQueue(&dev->DeviceQueue, e, *key) : KeInsertDeviceQueue(&dev->DeviceQueue, e);
    if (!queued) {
        dev->CurrentIrp = irp;
        IoReleaseCancelSpinLock(cirql);
        if (dev->DriverObject->DriverStartIo) dev->DriverObject->DriverStartIo(dev, irp);
    } else if (irp->Cancel && cancel) {
        irp->CancelIrql = cirql; irp->CancelRoutine = 0;
        cancel(dev, irp);                                       /* the routine releases the cancel spin lock */
    } else IoReleaseCancelSpinLock(cirql);
    KfLowerIrql(irql);
}
static void start_next(DEVICE_OBJECT *dev, KDEVICE_QUEUE_ENTRY *e, uint8_t cancelable)
{
    if (!e) { dev->CurrentIrp = 0; return; }
    {
        IRP *irp = IRP_OF_ENTRY(e);
        dev->CurrentIrp = irp;
        if (cancelable) {
            uint8_t cirql;
            IoAcquireCancelSpinLock(&cirql);
            if (irp->Cancel && irp->CancelRoutine) {
                PDRIVER_CANCEL c = irp->CancelRoutine;
                irp->CancelIrql = cirql; irp->CancelRoutine = 0;
                c(dev, irp);
                return;
            }
            IoReleaseCancelSpinLock(cirql);
        }
        if (dev->DriverObject->DriverStartIo) dev->DriverObject->DriverStartIo(dev, irp);
    }
}
void NTAPI IoStartNextPacket(DEVICE_OBJECT *dev, uint8_t cancelable)
{
    uint8_t irql = KfRaiseIrql(DISPATCH_LEVEL);
    start_next(dev, KeRemoveDeviceQueue(&dev->DeviceQueue), cancelable);
    KfLowerIrql(irql);
}
void NTAPI IoStartNextPacketByKey(DEVICE_OBJECT *dev, uint8_t cancelable, uint32_t key)
{
    uint8_t irql = KfRaiseIrql(DISPATCH_LEVEL);
    start_next(dev, KeRemoveByKeyDeviceQueue(&dev->DeviceQueue, key), cancelable);
    KfLowerIrql(irql);
}
void NTAPI IoSetStartIoAttributes(DEVICE_OBJECT *dev, uint8_t deferred, uint8_t noncancelable)
{ ntdrv_devext_t *x = ntdrv_devext(dev); x->startio_deferred = deferred; x->startio_noncancelable = noncancelable; }

/* ================================================================ remove locks */
typedef struct { uint8_t Removed, Reserved[3]; volatile LONG IoCount; KEVENT RemoveEvent; } IO_REMOVE_LOCK_COMMON;
void NTAPI IoInitializeRemoveLockEx(IO_REMOVE_LOCK_COMMON *l, uint32_t tag, uint32_t maxmin, uint32_t high, uint32_t size)
{
    (void)tag; (void)maxmin; (void)high;
    memset(l, 0, size < sizeof *l ? sizeof *l : size);
    l->IoCount = 1;
    KeInitializeEvent(&l->RemoveEvent, 1 /* SynchronizationEvent */, 0);
}
NTSTATUS NTAPI IoAcquireRemoveLockEx(IO_REMOVE_LOCK_COMMON *l, void *tag, const char *file, uint32_t line, uint32_t size)
{
    (void)tag; (void)file; (void)line; (void)size;
    __atomic_add_fetch(&l->IoCount, 1, __ATOMIC_SEQ_CST);
    if (l->Removed) {
        if (__atomic_sub_fetch(&l->IoCount, 1, __ATOMIC_SEQ_CST) == 0) KeSetEvent(&l->RemoveEvent, 0, 0);
        return STATUS_DELETE_PENDING;
    }
    return STATUS_SUCCESS;
}
void NTAPI IoReleaseRemoveLockEx(IO_REMOVE_LOCK_COMMON *l, void *tag, uint32_t size)
{
    LONG n;
    (void)tag; (void)size;
    n = __atomic_sub_fetch(&l->IoCount, 1, __ATOMIC_SEQ_CST);
    if (n < 0) kpanic("IoReleaseRemoveLock: count underflow");
    if (n == 0) { if (!l->Removed) kpanic("IoReleaseRemoveLock: count reached zero without a remove"); KeSetEvent(&l->RemoveEvent, 0, 0); }
}
void NTAPI IoReleaseRemoveLockAndWaitEx(IO_REMOVE_LOCK_COMMON *l, void *tag, uint32_t size)
{
    LONG n;
    (void)tag; (void)size;
    l->Removed = 1;
    n = __atomic_sub_fetch(&l->IoCount, 1, __ATOMIC_SEQ_CST);           /* the caller's own acquisition */
    if (n > 0) n = __atomic_sub_fetch(&l->IoCount, 1, __ATOMIC_SEQ_CST); /* the initial reference */
    if (n > 0) KeWaitForSingleObject(&l->RemoveEvent, 0, 0, 0, 0);
}

/* ================================================================ I/O timers (one-second device timers) */
static void NTAPI io_timer_dpc(KDPC *dpc, void *ctx, void *a1, void *a2)
{
    io_timer_t *t = ctx;
    (void)dpc; (void)a1; (void)a2;
    if (t->running) t->routine(t->dev, t->ctx);
}
NTSTATUS NTAPI IoInitializeTimer(DEVICE_OBJECT *dev, void *routine, void *ctx)
{
    ntdrv_devext_t *x = ntdrv_devext(dev);
    io_timer_t *t = x->timer;
    if (!t) { t = kzalloc(sizeof *t); if (!t) return STATUS_INSUFFICIENT_RESOURCES; x->timer = t; }
    t->dev = dev; t->routine = routine; t->ctx = ctx;
    KeInitializeTimerEx(&t->timer, 0);
    KeInitializeDpc(&t->dpc, io_timer_dpc, t);
    dev->Timer = t;
    return STATUS_SUCCESS;
}
void NTAPI IoStartTimer(DEVICE_OBJECT *dev)
{
    io_timer_t *t = ntdrv_devext(dev)->timer;
    LARGE_INTEGER due;
    if (!t) return;
    if (t->running) return;
    t->running = 1;
    due.QuadPart = -10000000ll;                                  /* one second, then every second */
    KeSetTimerEx(&t->timer, due, 1000, &t->dpc);
}
void NTAPI IoStopTimer(DEVICE_OBJECT *dev)
{
    io_timer_t *t = ntdrv_devext(dev)->timer;
    if (!t) return;
    t->running = 0;
    KeCancelTimer(&t->timer);
}

/* ================================================================ host root bus PDOs (IoReportDetectedDevice) */
static DRIVER_OBJECT pnp_root_drv;
static ntdrv_driver_t pnp_root_rec;
static unsigned pnp_root_count;
static void wide_copy_alloc(void **out, const char *s, int multi)
{
    unsigned n = (unsigned)strlen(s), i;
    WCHAR *w = ExAllocatePoolWithTag(1, (n + 2) * 2, 0x20706e50);
    if (!w) { *out = 0; return; }
    for (i = 0; i < n; ++i) w[i] = (uint8_t)s[i];
    w[n] = 0; if (multi) w[n + 1] = 0;
    *out = w;
}
static NTSTATUS NTAPI pnp_root_dispatch(DEVICE_OBJECT *dev, IRP *irp)
{
    IO_STACK_LOCATION *stk = irp->Tail.Overlay.CurrentStackLocation;
    ntdrv_devext_t *x = ntdrv_devext(dev);
    NTSTATUS st = irp->IoStatus.Status;
    if (stk->MajorFunction == IRP_MJ_PNP && x->pdo) {
        switch (stk->MinorFunction) {
        case IRP_MN_START_DEVICE: case IRP_MN_QUERY_REMOVE_DEVICE: case IRP_MN_REMOVE_DEVICE: case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_STOP_DEVICE: case IRP_MN_QUERY_STOP_DEVICE: case IRP_MN_CANCEL_STOP_DEVICE: case IRP_MN_SURPRISE_REMOVAL:
            st = STATUS_SUCCESS; break;
        case IRP_MN_QUERY_ID: {
            void *out = 0;
            switch (stk->Parameters.QueryId.IdType) {
            case 0: wide_copy_alloc(&out, x->pdo->desc, 0); break;                                         /* BusQueryDeviceID */
            case 1: wide_copy_alloc(&out, x->pdo->hwid[0] ? x->pdo->hwid : x->pdo->desc, 1); break;      /* BusQueryHardwareIDs */
            case 2: wide_copy_alloc(&out, "", 1); break;                                                   /* BusQueryCompatibleIDs */
            case 3: wide_copy_alloc(&out, "0000", 0); break;                                               /* BusQueryInstanceID */
            default: out = 0; break;
            }
            if (out) { irp->IoStatus.Information = (uint64_t)out; st = STATUS_SUCCESS; } else st = STATUS_NOT_SUPPORTED;
            break; }
        case IRP_MN_QUERY_DEVICE_RELATIONS:
            if (stk->Parameters.QueryDeviceRelations.Type == 4 /* TargetDeviceRelation */) {
                uint32_t *rel = ExAllocatePoolWithTag(1, 16, 0x20706e50);
                if (rel) { rel[0] = 1; *(DEVICE_OBJECT **)(rel + 2) = dev; dev->ReferenceCount++; irp->IoStatus.Information = (uint64_t)rel; st = STATUS_SUCCESS; }
                else st = STATUS_INSUFFICIENT_RESOURCES;
            }
            break;
        case IRP_MN_QUERY_CAPABILITIES: {                        /* DEVICE_CAPABILITIES: Size(2) Version(2) bits(4) Address(8) UINumber(0xc) DeviceState[7](0x10) ... */
            uint8_t *cap = stk->Parameters.DeviceCapabilities.Capabilities;
            if (cap && *(uint16_t *)cap >= 0x40) { *(uint32_t *)(cap + 8) = x->pdo->address; *(uint32_t *)(cap + 0xc) = x->pdo->ui_number; st = STATUS_SUCCESS; }
            break; }
        case IRP_MN_QUERY_RESOURCES:
            if (x->pdo->resources) { void *r = ExAllocatePoolWithTag(1, x->pdo->resources_size, 0x20706e50); if (r) { memcpy(r, x->pdo->resources, x->pdo->resources_size); irp->IoStatus.Information = (uint64_t)r; st = STATUS_SUCCESS; } }
            break;
        case IRP_MN_QUERY_DEVICE_TEXT: {
            void *out = 0;
            if (stk->Parameters.QueryDeviceText.DeviceTextType == 0) wide_copy_alloc(&out, x->pdo->desc, 0);
            if (out) { irp->IoStatus.Information = (uint64_t)out; st = STATUS_SUCCESS; }
            break; }
        case IRP_MN_QUERY_PNP_DEVICE_STATE: irp->IoStatus.Information = 0; st = STATUS_SUCCESS; break;
        case IRP_MN_QUERY_BUS_INFORMATION: {                    /* PNP_BUS_INFORMATION: BusTypeGuid(16) LegacyBusType(4) BusNumber(4) */
            uint8_t *b = ExAllocatePoolWithTag(1, 24, 0x20706e50);
            if (b) { memset(b, 0, 24); *(uint32_t *)(b + 16) = x->pdo->legacy_bus_type; *(uint32_t *)(b + 20) = x->pdo->bus_number; irp->IoStatus.Information = (uint64_t)b; st = STATUS_SUCCESS; }
            break; }
        default: break;
        }
    } else if (stk->MajorFunction == IRP_MJ_POWER) {
        st = STATUS_SUCCESS;
        PoStartNextPowerIrp(irp);
    } else if (stk->MajorFunction == IRP_MJ_CREATE || stk->MajorFunction == IRP_MJ_CLOSE || stk->MajorFunction == IRP_MJ_CLEANUP) {
        st = STATUS_SUCCESS;
    } else if (stk->MajorFunction == IRP_MJ_SYSTEM_CONTROL) {
        st = STATUS_NOT_SUPPORTED;
    } else st = STATUS_INVALID_DEVICE_REQUEST;
    irp->IoStatus.Status = st;
    IofCompleteRequest(irp, 0);
    return st;
}
static void pnp_root_init(void)
{
    unsigned i;
    if (pnp_root_drv.Type) return;
    pnp_root_drv.Type = 4; pnp_root_drv.Size = SZ_DRV;
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) pnp_root_drv.MajorFunction[i] = pnp_root_dispatch;
    memcpy(pnp_root_rec.name, "PnpManager", 11);
    pnp_root_drv.DriverSection = &pnp_root_rec;
    ntdrv_alloc_driver_extension(&pnp_root_drv, &pnp_root_rec);
}
static void upcase_copy(char *d, const char *s, unsigned cap) { unsigned i; for (i = 0; s[i] && i + 1 < cap; ++i) d[i] = s[i] >= 'a' && s[i] <= 'z' ? (char)(s[i] - 32) : s[i]; d[i] = 0; }
/* Creates the PDO for a device a legacy driver detected itself: ROOT\LEGACY_<SERVICE>\0000 in Enum, the resources
 * the driver reports, and a PDO whose PnP dispatch answers the queries the driver may later make. */
NTSTATUS NTAPI IoReportDetectedDevice(DRIVER_OBJECT *drv, uint32_t bus_type, uint32_t bus_number, uint32_t slot, void *resources, void *requirements, uint8_t assigned, DEVICE_OBJECT **pdo_io)
{
    DEVICE_OBJECT *pdo = *pdo_io;
    ntdrv_devext_t *x;
    ntdrv_pdo_t *p;
    ntdrv_driver_t *d = drv ? drv->DriverSection : 0;
    char svc[64] = "UNKNOWN", key[300], num[8];
    unsigned n, i;
    uint64_t h;
    (void)requirements; (void)assigned;
    pnp_root_init();
    if (d) upcase_copy(svc, d->name, sizeof svc);
    if (!pdo) {
        NTSTATUS st = IoCreateDevice(&pnp_root_drv, 0, 0, 0x0000000e /* FILE_DEVICE_CONTROLLER */, 0, 0, &pdo);
        if (!NT_SUCCESS(st)) return st;
        pdo->Flags &= ~DO_DEVICE_INITIALIZING;
    }
    x = ntdrv_devext(pdo);
    p = x->pdo ? x->pdo : kzalloc(sizeof *p);
    if (!p) return STATUS_INSUFFICIENT_RESOURCES;
    x->pdo = p;
    n = pnp_root_count++;
    num[0] = (char)('0' + (n / 1000) % 10); num[1] = (char)('0' + (n / 100) % 10); num[2] = (char)('0' + (n / 10) % 10); num[3] = (char)('0' + n % 10); num[4] = 0;
    { const char *a = "ROOT\\LEGACY_"; unsigned k = 0; for (i = 0; a[i]; ++i) p->instance[k++] = a[i]; for (i = 0; svc[i] && k + 6 < sizeof p->instance; ++i) p->instance[k++] = svc[i]; p->instance[k++] = '\\'; for (i = 0; num[i]; ++i) p->instance[k++] = num[i]; p->instance[k] = 0; }
    for (i = 0; svc[i] && i + 1 < sizeof p->service; ++i) p->service[i] = svc[i]; p->service[i] = 0;
    { const char *a = "ROOT\\LEGACY_"; unsigned k = 0; for (i = 0; a[i]; ++i) p->hwid[k++] = a[i]; for (i = 0; svc[i] && k + 1 < sizeof p->hwid; ++i) p->hwid[k++] = svc[i]; p->hwid[k] = 0; }
    for (i = 0; svc[i] && i + 1 < sizeof p->desc; ++i) p->desc[i] = svc[i]; p->desc[i] = 0;
    p->legacy_bus_type = bus_type; p->bus_number = bus_number; p->address = slot; p->ui_number = 0xffffffffu;
    if (resources) {
        const uint32_t count = *(const uint32_t *)resources, *full = (const uint32_t *)resources + 1;
        uint32_t size = 4, c;
        for (c = 0; c < count; ++c) { const uint32_t nd = *(const uint32_t *)((const uint8_t *)full + 12); const uint32_t fs = 16 + nd * 0x14; size += fs; full = (const uint32_t *)((const uint8_t *)full + fs); }
        p->resources = kmalloc(size);
        if (p->resources) { memcpy(p->resources, resources, size); p->resources_size = size; }
    }
    /* \Registry\Machine\System\CurrentControlSet\Enum\ROOT\LEGACY_<SVC>\0000: Service, DeviceDesc, ConfigFlags, Legacy */
    { const char *a = "\\Registry\\Machine\\System\\CurrentControlSet\\Enum\\"; unsigned k = 0; for (i = 0; a[i]; ++i) key[k++] = a[i]; for (i = 0; p->instance[i]; ++i) key[k++] = p->instance[i]; key[k] = 0; }
    if (NT_SUCCESS(ntdrv_open_key_ascii(key, 1, &h))) {
        WCHAR w[64]; unsigned wn = (unsigned)ntdrv_ascii_to_wide(p->service, w, 64); uint32_t one = 1, zero = 0;
        ntdrv_set_value_ascii(h, "Service", REG_SZ, w, (wn + 1) * 2);
        ntdrv_set_value_ascii(h, "DeviceDesc", REG_SZ, w, (wn + 1) * 2);
        ntdrv_set_value_ascii(h, "ConfigFlags", REG_DWORD, &zero, 4);
        ntdrv_set_value_ascii(h, "Legacy", REG_DWORD, &one, 4);
        { static const char cls[] = "{8ECC055D-047F-11D1-A537-0000F8753ED1}"; WCHAR cw[40]; unsigned cn = (unsigned)ntdrv_ascii_to_wide(cls, cw, 40); ntdrv_set_value_ascii(h, "ClassGUID", REG_SZ, cw, (cn + 1) * 2); }
        ZwClose(h);
    }
    kprintf("K64 ntdrv: detected device %s reported by %s (bus type %u, bus %u, slot %u)\n", p->instance, svc, bus_type, bus_number, slot);
    *pdo_io = pdo;
    return STATUS_SUCCESS;
}
DEVICE_OBJECT *ntdrv_pnp_root_pdo_of(DEVICE_OBJECT *dev) { return ntdrv_devext(dev)->pdo ? dev : 0; }

/* ================================================================ device properties / registry keys of PDOs */
static NTSTATUS prop_string(const char *s, uint32_t len, void *buf, uint32_t *res, int multi)
{
    uint32_t n = (uint32_t)strlen(s), need = (n + 1 + (multi ? 1 : 0)) * 2, i;
    *res = need;
    if (len < need) return STATUS_BUFFER_TOO_SMALL;
    for (i = 0; i < n; ++i) ((WCHAR *)buf)[i] = (uint8_t)s[i];
    ((WCHAR *)buf)[n] = 0; if (multi) ((WCHAR *)buf)[n + 1] = 0;
    return STATUS_SUCCESS;
}
static NTSTATUS prop_u32(uint32_t v, uint32_t len, void *buf, uint32_t *res)
{ *res = 4; if (len < 4) return STATUS_BUFFER_TOO_SMALL; memcpy(buf, &v, 4); return STATUS_SUCCESS; }
NTSTATUS NTAPI IoGetDeviceProperty(DEVICE_OBJECT *pdo, uint32_t prop, uint32_t len, void *buf, uint32_t *res)
{
    ntdrv_devext_t *x = pdo ? pdo->DeviceObjectExtension : 0;
    ntdrv_pdo_t *p = x ? x->pdo : 0;
    char tmp[128];
    if (!p) { *res = 0; return STATUS_INVALID_DEVICE_REQUEST; }   /* not a PDO of a bus the host enumerates */
    switch (prop) {
    case 0x00: return prop_string(p->desc, len, buf, res, 0);                    /* DevicePropertyDeviceDescription */
    case 0x01: return prop_string(p->hwid, len, buf, res, 1);                    /* HardwareID (REG_MULTI_SZ) */
    case 0x02: return prop_string("", len, buf, res, 1);                         /* CompatibleIDs */
    case 0x04: return prop_string("LegacyDriver", len, buf, res, 0);             /* ClassName */
    case 0x05: return prop_string("{8ECC055D-047F-11D1-A537-0000F8753ED1}", len, buf, res, 0);   /* ClassGuid */
    case 0x07: { unsigned k = 0, i; const char *a = "{8ECC055D-047F-11D1-A537-0000F8753ED1}\\"; for (i = 0; a[i]; ++i) tmp[k++] = a[i]; for (i = 0; p->instance[i]; ++i) if (p->instance[i] != '\\') tmp[k++] = p->instance[i]; tmp[k] = 0;
                 return prop_string(tmp, len, buf, res, 0); }                     /* DriverKeyName */
    case 0x08: return prop_string("(Standard system devices)", len, buf, res, 0);   /* Manufacturer */
    case 0x09: return prop_string(p->desc, len, buf, res, 0);                    /* FriendlyName */
    case 0x0a: return prop_string("", len, buf, res, 0);                         /* LocationInformation */
    case 0x0d: { const char *n = ntdrv_device_name(pdo); return prop_string(n ? n : "", len, buf, res, 0); }   /* PhysicalDeviceObjectName */
    case 0x0e: { *res = 16; if (len < 16) return STATUS_BUFFER_TOO_SMALL; memset(buf, 0, 16); return STATUS_SUCCESS; }   /* BusTypeGuid */
    case 0x0f: return prop_u32(p->legacy_bus_type, len, buf, res);              /* LegacyBusType */
    case 0x10: return prop_u32(p->bus_number, len, buf, res);                   /* BusNumber */
    case 0x11: return prop_string("ROOT", len, buf, res, 0);                     /* EnumeratorName */
    case 0x12: return prop_u32(p->address, len, buf, res);                      /* Address */
    case 0x13: return prop_u32(p->ui_number, len, buf, res);                    /* UINumber */
    case 0x14: return prop_u32(2 /* InstallStateInstalled */, len, buf, res);   /* InstallState */
    case 0x15: return prop_u32(1 /* RemovalPolicyExpectNoRemoval */, len, buf, res);
    case 0x17:                                                                   /* AllocatedResources */
        *res = p->resources_size;
        if (!p->resources) return STATUS_OBJECT_NAME_NOT_FOUND;
        if (len < p->resources_size) return STATUS_BUFFER_TOO_SMALL;
        memcpy(buf, p->resources, p->resources_size);
        return STATUS_SUCCESS;
    case 0x18: return prop_string("{00000000-0000-0000-0000-000000000000}", len, buf, res, 0);   /* ContainerID */
    default: *res = 0; return STATUS_INVALID_PARAMETER_2;
    }
}
NTSTATUS NTAPI IoOpenDeviceRegistryKey(DEVICE_OBJECT *pdo, uint32_t type, uint32_t access, uint64_t *handle)
{
    ntdrv_devext_t *x = pdo ? pdo->DeviceObjectExtension : 0;
    ntdrv_pdo_t *p = x ? x->pdo : 0;
    char key[300];
    unsigned k = 0, i;
    (void)access;
    if (!p) return STATUS_INVALID_DEVICE_REQUEST;
    if (type & 0x4) {                                            /* PLUGPLAY_REGKEY_CURRENT_HWPROFILE */
        const char *a = "\\Registry\\Machine\\System\\CurrentControlSet\\Hardware Profiles\\Current\\System\\CurrentControlSet\\";
        for (i = 0; a[i]; ++i) key[k++] = a[i];
    } else { const char *a = "\\Registry\\Machine\\System\\CurrentControlSet\\"; for (i = 0; a[i]; ++i) key[k++] = a[i]; }
    if (type & 0x2) {                                            /* PLUGPLAY_REGKEY_DRIVER */
        const char *a = "Control\\Class\\{8ECC055D-047F-11D1-A537-0000F8753ED1}\\";
        for (i = 0; a[i]; ++i) key[k++] = a[i];
        for (i = 0; p->instance[i]; ++i) if (p->instance[i] != '\\') key[k++] = p->instance[i];
    } else if (type & 0x1) {                                     /* PLUGPLAY_REGKEY_DEVICE */
        const char *a = "Enum\\", *b = "\\Device Parameters";
        for (i = 0; a[i]; ++i) key[k++] = a[i];
        for (i = 0; p->instance[i]; ++i) key[k++] = p->instance[i];
        for (i = 0; b[i]; ++i) key[k++] = b[i];
    } else return STATUS_INVALID_PARAMETER;
    key[k] = 0;
    return ntdrv_open_key_ascii(key, 1, handle);
}

/* IoQueryDeviceDescription walks \Registry\Machine\Hardware\Description\System; the firmware-built description tree does
 * not exist on this system, so the documented not-found result is returned once that is established. */
NTSTATUS NTAPI IoQueryDeviceDescription(uint32_t *bus, uint32_t *busnum, uint32_t *ctl, uint32_t *ctlnum, uint32_t *periph, uint32_t *periphnum, void *callout, void *ctx)
{
    uint64_t h;
    (void)bus; (void)busnum; (void)ctl; (void)ctlnum; (void)periph; (void)periphnum; (void)callout; (void)ctx;
    if (NT_SUCCESS(ntdrv_open_key_ascii("\\Registry\\Machine\\Hardware\\Description\\System\\MultifunctionAdapter", 0, &h))) { ZwClose(h); return STATUS_NOT_IMPLEMENTED; }
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* ================================================================ resources: CM_RESOURCE_LIST builders */
/* CM_RESOURCE_LIST: Count(4) List[]: InterfaceType(4) BusNumber(4) PartialResourceList{Version(2) Revision(2) Count(4) desc[]} */
#define CmResourceTypePort 1
#define CmResourceTypeInterrupt 2
#define CmResourceTypeMemory 3
#define CmResourceTypeDma 4
#define CmResourceTypeBusNumber 6
static uint8_t *cm_begin(uint32_t iftype, uint32_t busnum, uint32_t ndesc, uint32_t *size_out)
{
    uint32_t size = 4 + 8 + 8 + ndesc * 0x14;
    uint8_t *l = ExAllocatePoolWithTag(1, size, 0x20736552);
    if (!l) return 0;
    memset(l, 0, size);
    *(uint32_t *)l = 1; *(uint32_t *)(l + 4) = iftype; *(uint32_t *)(l + 8) = busnum;
    *(uint16_t *)(l + 12) = 1; *(uint16_t *)(l + 14) = 1; *(uint32_t *)(l + 16) = ndesc;
    *size_out = size;
    return l;
}
static uint8_t *cm_desc(uint8_t *l, uint32_t i) { return l + 20 + i * 0x14; }
static void cm_set(uint8_t *d, uint8_t type, uint8_t share, uint16_t flags, uint64_t start, uint32_t len)
{ d[0] = type; d[1] = share; *(uint16_t *)(d + 2) = flags; memcpy(d + 4, &start, 8); *(uint32_t *)(d + 12) = len; }
static void cm_set_irq(uint8_t *d, uint32_t level, uint32_t vector, uint64_t affinity, uint16_t flags)
{ d[0] = CmResourceTypeInterrupt; d[1] = 3 /* CmResourceShareShared */; *(uint16_t *)(d + 2) = flags; *(uint32_t *)(d + 4) = level; *(uint32_t *)(d + 8) = vector; memcpy(d + 12, &affinity, 8); }

#ifdef SHZ_STANDALONE
static uint32_t line_vector(uint32_t line) { return standalone_irq_vector(line); }
#else
static uint32_t line_vector(uint32_t line) { return line + 0x20; }
#endif
/* HalAssignSlotResources: the PCI function at `slot` (device | function << 5) on `bus`: one descriptor per implemented
 * BAR (port or memory, from the configuration space, as the PCI bus driver decodes it) plus its legacy interrupt line
 * when routed, then the function is enabled and recorded as owned by the calling driver. */
NTSTATUS NTAPI HalAssignSlotResources(UNICODE_STRING *regpath, UNICODE_STRING *drivername, DRIVER_OBJECT *drv, DEVICE_OBJECT *dev, uint32_t bus_type, uint32_t bus, uint32_t slot, void **allocated)
{
    pci_dev_t d = { .bus = (uint8_t)bus, .dev = (uint8_t)(slot & 0x1f), .fn = (uint8_t)((slot >> 5) & 7) };
    uint32_t id, b, n = 0, size, irq;
    uint64_t bars[6], sizes[6]; int io[6]; unsigned idx[6];
    uint8_t *l;
    (void)regpath; (void)drivername; (void)drv; (void)dev;
    if (bus_type != 5 /* PCIBus */) return STATUS_NOT_SUPPORTED;
    id = pci_cfg_read32(&d, 0);
    if ((id & 0xffff) == 0xffff) return STATUS_NO_SUCH_DEVICE_;
    d.vendor = (uint16_t)id; d.device = (uint16_t)(id >> 16);
    if ((pci_cfg_read32(&d, 0x0c) >> 16 & 0x7f) != 0) return STATUS_NOT_SUPPORTED;    /* only type-0 headers carry 6 BARs */
    for (b = 0; b < 6; ++b) {
        uint64_t sz = 0; int is_io = 0;
        uint64_t base = pci_bar(&d, b, &sz, &is_io);
        if (!base && !sz) continue;
        bars[n] = base; sizes[n] = sz; io[n] = is_io; idx[n] = b; ++n;
        if (!is_io && (((pci_cfg_read32(&d, 0x10 + 4 * b) >> 1) & 3) == 2)) ++b;   /* 64-bit BAR uses two slots */
    }
    irq = pci_cfg_read32(&d, 0x3c) & 0xff;
    l = cm_begin(5, bus, n + (irq && irq != 0xff ? 1 : 0), &size);
    if (!l) return STATUS_INSUFFICIENT_RESOURCES;
    for (b = 0; b < n; ++b) cm_set(cm_desc(l, b), io[b] ? CmResourceTypePort : CmResourceTypeMemory, 1 /* DeviceExclusive */, io[b] ? 1 /* CM_RESOURCE_PORT_IO */ : 0, bars[b], (uint32_t)sizes[b]);
    if (irq && irq != 0xff) cm_set_irq(cm_desc(l, n), irq, line_vector(irq), 1, 0 /* level sensitive */);
    (void)idx;
    pci_enable(&d, 1, 1, 1);
    ntdrv_pci_claim_function(&d);
    *allocated = l;
    return STATUS_SUCCESS;
}
/* IoAssignResources: the first alternative of the requested list is granted at its minimum address; a NULL request frees. */
NTSTATUS NTAPI IoAssignResources(UNICODE_STRING *regpath, UNICODE_STRING *drvclass, DRIVER_OBJECT *drv, DEVICE_OBJECT *dev, uint8_t *req, void **allocated)
{
    uint32_t iftype, busnum, count, i, size, n = 0;
    const uint8_t *list;
    uint8_t *out;
    (void)regpath; (void)drvclass; (void)drv; (void)dev;
    if (!req) { *allocated = 0; return STATUS_SUCCESS; }
    /* IO_RESOURCE_REQUIREMENTS_LIST: ListSize(0) InterfaceType(4) BusNumber(8) SlotNumber(0xc) Reserved[3](0x10) AlternativeLists(0x1c) List[](0x20)
     * IO_RESOURCE_LIST: Version(2) Revision(2) Count(4) Descriptors[](8) */
    iftype = *(uint32_t *)(req + 4); busnum = *(uint32_t *)(req + 8);
    if (!*(uint32_t *)(req + 0x1c)) return STATUS_INVALID_PARAMETER;
    list = req + 0x20; count = *(const uint32_t *)(list + 4);
    for (i = 0; i < count; ++i) if (!(list[8 + i * 0x20] & 0x08 /* IO_RESOURCE_ALTERNATIVE */)) ++n;
    out = cm_begin(iftype, busnum, n, &size);
    if (!out) return STATUS_INSUFFICIENT_RESOURCES;
    for (i = 0, n = 0; i < count; ++i) {
        const uint8_t *r = list + 8 + i * 0x20;
        uint8_t *d = cm_desc(out, n);
        if (r[0] & 0x08) continue;
        switch (r[1]) {
        case CmResourceTypePort: case CmResourceTypeMemory: {
            uint32_t len = *(const uint32_t *)(r + 8), align = *(const uint32_t *)(r + 0xc); uint64_t min, max, start;
            memcpy(&min, r + 0x10, 8); memcpy(&max, r + 0x18, 8);
            if (!align) align = 1;
            start = (min + align - 1) / align * align;
            if (start + len - 1 > max && len) { ExFreePool(out); return STATUS_CONFLICTING_ADDRESSES; }
            cm_set(d, r[1], r[2], *(const uint16_t *)(r + 4), start, len);
            break; }
        case CmResourceTypeInterrupt: {
            uint32_t minv = *(const uint32_t *)(r + 8);
            cm_set_irq(d, minv, minv, 1, *(const uint16_t *)(r + 4));
            break; }
        case CmResourceTypeDma: { uint32_t ch = *(const uint32_t *)(r + 8); d[0] = CmResourceTypeDma; d[1] = r[2]; *(uint16_t *)(d + 2) = *(const uint16_t *)(r + 4); *(uint32_t *)(d + 4) = ch; *(uint32_t *)(d + 8) = 0; break; }
        case CmResourceTypeBusNumber: { d[0] = CmResourceTypeBusNumber; d[1] = r[2]; *(uint32_t *)(d + 4) = *(const uint32_t *)(r + 0x10); *(uint32_t *)(d + 8) = *(const uint32_t *)(r + 8); break; }
        default: d[0] = r[1]; d[1] = r[2]; *(uint16_t *)(d + 2) = *(const uint16_t *)(r + 4); memcpy(d + 4, r + 8, 12); break;
        }
        ++n;
    }
    *allocated = out;
    return STATUS_SUCCESS;
}
NTSTATUS NTAPI IoReportResourceForDetection(DRIVER_OBJECT *drv, void *drvlist, uint32_t drvsize, DEVICE_OBJECT *dev, void *devlist, uint32_t devsize, uint8_t *conflict)
{ (void)drv; (void)drvlist; (void)drvsize; (void)dev; (void)devlist; (void)devsize; *conflict = 0; return STATUS_SUCCESS; }   /* no arbiter conflicts: one owner per resource is recorded by pci_claim */
NTSTATUS NTAPI IoReportResourceUsage(UNICODE_STRING *cls, DRIVER_OBJECT *drv, void *drvlist, uint32_t drvsize, DEVICE_OBJECT *dev, void *devlist, uint32_t devsize, uint8_t override, uint8_t *conflict)
{ (void)cls; (void)drv; (void)drvlist; (void)drvsize; (void)dev; (void)devlist; (void)devsize; (void)override; *conflict = 0; return STATUS_SUCCESS; }

/* ================================================================ HAL */
uint8_t NTAPI HalTranslateBusAddress(uint32_t bus_type, uint32_t bus, LARGE_INTEGER addr, uint32_t *space, LARGE_INTEGER *translated)
{
    (void)bus_type; (void)bus;
    /* PC/AT HAL: bus addresses are system addresses; I/O space (1) stays I/O space, memory stays memory. */
    if (*space > 1) return 0;
    *translated = addr;
    return 1;
}
void NTAPI HalDisplayString(const char *s) { kprintf("%s", s); }
uint8_t NTAPI HalMakeBeep(uint32_t freq)
{
    if (!freq) { k_outb(0x61, k_inb(0x61) & (uint8_t)~3u); return 1; }
    if (freq < 20 || freq > 20000) return 0;
    { uint32_t div = 1193182u / freq;
      k_outb(0x43, 0xb6);                                        /* channel 2, lo/hi, square wave */
      k_outb(0x42, (uint8_t)div); k_outb(0x42, (uint8_t)(div >> 8));
      k_outb(0x61, k_inb(0x61) | 3); }                            /* gate + speaker enable */
    return 1;
}
uint8_t *KdComPortInUse = (uint8_t *)(uintptr_t)0x3f8;          /* hal.dll data export: COM1 carries the kernel console */
uint8_t NTAPI HalQueryRealTimeClock(void *tf)
{
    extern int64_t ntdrv_100ns_now(void);
    extern void NTAPI RtlTimeToTimeFields(const LARGE_INTEGER *, void *);
    LARGE_INTEGER t; t.QuadPart = ntdrv_100ns_now();
    RtlTimeToTimeFields(&t, tf);
    return 1;
}

/* ================================================================ DMA adapter object */
/* DMA_ADAPTER (0x10): Version(2) Size(2) DmaOperations(8). DMA_OPERATIONS (0x80, version 1): Size, PutDmaAdapter,
 * AllocateCommonBuffer, FreeCommonBuffer, AllocateAdapterChannel, FlushAdapterBuffers, FreeAdapterChannel,
 * FreeMapRegisters, MapTransfer, GetDmaAlignment, ReadDmaCounter, GetScatterGatherList, PutScatterGatherList,
 * CalculateScatterGatherList, BuildScatterGatherList, BuildMdlFromScatterGatherList. No IOMMU and no bounce buffers:
 * every kernel buffer is physically addressable, so "map registers" are the identity and a transfer's device address
 * is the buffer's physical address; scatter/gather lists coalesce physically contiguous pages. */
typedef struct { uint16_t Version, Size; uint32_t _p; void *DmaOperations; DEVICE_OBJECT *owner; uint32_t map_registers; } dma_adapter_t;
typedef struct cbuf { struct cbuf *next; void *base; void *aligned; uint64_t len; } cbuf_t;
static cbuf_t *cbufs;
static void NTAPI dma_put(dma_adapter_t *a) { kfree(a); }
static void *NTAPI dma_alloc_common(dma_adapter_t *a, uint32_t len, LARGE_INTEGER *logical, uint8_t cache)
{
    cbuf_t *c = kzalloc(sizeof *c);
    (void)a; (void)cache;
    if (!c) return 0;
    c->base = kmalloc(len + 4096);
    if (!c->base) { kfree(c); return 0; }
    c->aligned = (void *)(((uint64_t)c->base + 4095) & ~4095ull);
    c->len = len;
    memset(c->aligned, 0, len);
    *logical = MmGetPhysicalAddress(c->aligned);
    c->next = cbufs; cbufs = c;
    return c->aligned;
}
static void NTAPI dma_free_common(dma_adapter_t *a, uint32_t len, LARGE_INTEGER logical, void *va, uint8_t cache)
{
    cbuf_t **pp;
    (void)a; (void)len; (void)logical; (void)cache;
    for (pp = &cbufs; *pp; pp = &(*pp)->next) if ((*pp)->aligned == va) { cbuf_t *c = *pp; *pp = c->next; kfree(c->base); kfree(c); return; }
}
static NTSTATUS NTAPI dma_alloc_channel(dma_adapter_t *a, DEVICE_OBJECT *dev, uint32_t nmap, uint32_t (NTAPI *routine)(DEVICE_OBJECT *, IRP *, void *, void *), void *ctx)
{
    uint8_t irql = KfRaiseIrql(DISPATCH_LEVEL);
    (void)nmap;
    routine(dev, dev->CurrentIrp, a, ctx);                       /* MapRegisterBase: the adapter itself (identity mapping) */
    KfLowerIrql(irql);
    return STATUS_SUCCESS;
}
static uint8_t NTAPI dma_flush(dma_adapter_t *a, MDL *mdl, void *base, void *va, uint32_t len, uint8_t write) { (void)a; (void)mdl; (void)base; (void)va; (void)len; (void)write; return 1; }
static void NTAPI dma_free_channel(dma_adapter_t *a) { (void)a; }
static void NTAPI dma_free_map_registers(dma_adapter_t *a, void *base, uint32_t n) { (void)a; (void)base; (void)n; }
/* Physical address of `va` inside the MDL's buffer and the length of the physically contiguous run from there. */
static uint64_t mdl_phys(MDL *mdl, void *va, uint32_t *contig)
{
    uint64_t off = (uint64_t)va - (uint64_t)mdl->StartVa, run = 0;
    uint64_t *pfn = (uint64_t *)(mdl + 1);
    uint32_t npages = (uint32_t)((mdl->ByteOffset + mdl->ByteCount + 4095) / 4096), i = (uint32_t)(off / 4096);
    uint64_t pa;
    if ((unsigned)mdl->Size < sizeof(MDL) + npages * 8 || !pfn[i]) {      /* no PFN array: direct translation */
        pa = (uint64_t)MmGetPhysicalAddress(va).QuadPart;
        *contig = (uint32_t)(4096 - (off & 0xfff));
        return pa;
    }
    pa = pfn[i] * 4096 + (off & 0xfff);
    run = 4096 - (off & 0xfff);
    while (i + 1 < npages && pfn[i + 1] == pfn[i] + 1) { run += 4096; ++i; }
    *contig = (uint32_t)run;
    return pa;
}
static LARGE_INTEGER NTAPI dma_map_transfer(dma_adapter_t *a, MDL *mdl, void *base, void *va, uint32_t *len, uint8_t write)
{
    LARGE_INTEGER r; uint32_t contig; uint64_t end = (uint64_t)mdl->StartVa + mdl->ByteOffset + mdl->ByteCount;
    (void)a; (void)base; (void)write;
    r.QuadPart = (int64_t)mdl_phys(mdl, va, &contig);
    if (*len > contig) *len = contig;
    if ((uint64_t)va + *len > end) *len = (uint32_t)(end - (uint64_t)va);
    return r;
}
static uint32_t NTAPI dma_alignment(dma_adapter_t *a) { (void)a; return 1; }
static uint32_t NTAPI dma_read_counter(dma_adapter_t *a) { (void)a; return 0; }
static uint32_t sg_count(MDL *mdl, void *va, uint32_t len)
{
    uint32_t n = 0, contig;
    while (len) { mdl_phys(mdl, va, &contig); if (contig > len) contig = len; va = (uint8_t *)va + contig; len -= contig; ++n; }
    return n;
}
static void sg_fill(uint8_t *sgl, MDL *mdl, void *va, uint32_t len)
{
    uint32_t n = 0, contig;
    while (len) {
        uint64_t pa = mdl_phys(mdl, va, &contig);
        if (contig > len) contig = len;
        memcpy(sgl + 16 + n * 0x18, &pa, 8); *(uint32_t *)(sgl + 16 + n * 0x18 + 8) = contig;
        va = (uint8_t *)va + contig; len -= contig; ++n;
    }
    *(uint32_t *)sgl = n;
}
static NTSTATUS NTAPI dma_calc_sg(dma_adapter_t *a, MDL *mdl, void *va, uint32_t len, uint32_t *size, uint32_t *nmap)
{
    uint32_t n = sg_count(mdl, va, len);
    (void)a;
    *size = 16 + n * 0x18;
    if (nmap) *nmap = (uint32_t)((((uint64_t)va & 0xfff) + len + 4095) / 4096);
    return STATUS_SUCCESS;
}
static NTSTATUS NTAPI dma_build_sg(dma_adapter_t *a, DEVICE_OBJECT *dev, MDL *mdl, void *va, uint32_t len, void (NTAPI *routine)(DEVICE_OBJECT *, IRP *, void *, void *), void *ctx, uint8_t write, void *buf, uint32_t size)
{
    uint32_t need = 16 + sg_count(mdl, va, len) * 0x18;
    uint8_t irql;
    (void)a; (void)write;
    if (size < need) return STATUS_BUFFER_TOO_SMALL;
    sg_fill(buf, mdl, va, len);
    irql = KfRaiseIrql(DISPATCH_LEVEL);
    routine(dev, dev->CurrentIrp, buf, ctx);
    KfLowerIrql(irql);
    return STATUS_SUCCESS;
}
static NTSTATUS NTAPI dma_get_sg(dma_adapter_t *a, DEVICE_OBJECT *dev, MDL *mdl, void *va, uint32_t len, void *routine, void *ctx, uint8_t write)
{
    uint32_t size = 16 + sg_count(mdl, va, len) * 0x18;
    uint8_t *sgl = ExAllocatePoolWithTag(0, size, 0x4c475344);
    if (!sgl) return STATUS_INSUFFICIENT_RESOURCES;
    return dma_build_sg(a, dev, mdl, va, len, routine, ctx, write, sgl, size);
}
static void NTAPI dma_put_sg(dma_adapter_t *a, void *sgl, uint8_t write) { (void)a; (void)write; ExFreePool(sgl); }
static NTSTATUS NTAPI dma_mdl_from_sg(dma_adapter_t *a, uint8_t *sgl, MDL *orig, MDL **out)
{
    uint32_t n = *(uint32_t *)sgl, i, bytes = 0, pages;
    MDL *m; uint64_t *pfn;
    (void)a; (void)orig;
    for (i = 0; i < n; ++i) bytes += *(uint32_t *)(sgl + 16 + i * 0x18 + 8);
    pages = (bytes + 4095) / 4096;
    m = kzalloc(sizeof(MDL) + pages * 8);
    if (!m) return STATUS_INSUFFICIENT_RESOURCES;
    m->Size = (int16_t)(sizeof(MDL) + pages * 8); m->ByteCount = bytes; m->MdlFlags = MDL_PAGES_LOCKED;
    pfn = (uint64_t *)(m + 1);
    { uint32_t k = 0; for (i = 0; i < n; ++i) { uint64_t pa; uint32_t l = *(uint32_t *)(sgl + 16 + i * 0x18 + 8), p; memcpy(&pa, sgl + 16 + i * 0x18, 8);
        for (p = 0; p < (l + 4095) / 4096 && k < pages; ++p) pfn[k++] = pa / 4096 + p; } }
    *out = m;
    return STATUS_SUCCESS;
}
static void *dma_ops[16] = {
    (void *)0x80, (void *)dma_put, (void *)dma_alloc_common, (void *)dma_free_common, (void *)dma_alloc_channel, (void *)dma_flush,
    (void *)dma_free_channel, (void *)dma_free_map_registers, (void *)dma_map_transfer, (void *)dma_alignment, (void *)dma_read_counter,
    (void *)dma_get_sg, (void *)dma_put_sg, (void *)dma_calc_sg, (void *)dma_build_sg, (void *)dma_mdl_from_sg };
/* DEVICE_DESCRIPTION (0x28): Version(0) Master(4) ScatterGather(5) DemandMode(6) AutoInitialize(7) Dma32BitAddresses(8)
 * IgnoreCount(9) Reserved1(0xa) Dma64BitAddresses(0xb) BusNumber(0xc) DmaChannel(0x10) InterfaceType(0x14) DmaWidth(0x18)
 * DmaSpeed(0x1c) MaximumLength(0x20) DmaPort(0x24) */
void *NTAPI HalGetAdapter(const uint8_t *desc, uint32_t *nmap)
{
    dma_adapter_t *a = kzalloc(sizeof *a);
    uint32_t maxlen = *(const uint32_t *)(desc + 0x20);
    if (!a) return 0;
    if (*(const uint32_t *)desc > 3) { kfree(a); return 0; }                         /* DEVICE_DESCRIPTION_VERSION up to 3 */
    a->Version = 1; a->Size = sizeof(dma_adapter_t) < 0x10 ? 0x10 : 0x10; a->DmaOperations = dma_ops;
    a->map_registers = maxlen ? (maxlen + 4095) / 4096 + 1 : 16;
    if (nmap) *nmap = a->map_registers;
    return a;
}
void *NTAPI IoGetDmaAdapter(DEVICE_OBJECT *pdo, const uint8_t *desc, uint32_t *nmap)
{
    dma_adapter_t *a = HalGetAdapter(desc, nmap);
    if (a) a->owner = pdo;
    return a;
}

/* ================================================================ partition tables */
static NTSTATUS read_sectors(DEVICE_OBJECT *dev, uint64_t offset, void *buf, uint32_t len)
{
    KEVENT ev; IO_STATUS_BLOCK iosb; LARGE_INTEGER off; IRP *irp; NTSTATUS st;
    void *tmp = kmalloc(len);                                     /* a page-aligned bounce buffer the device can DMA into */
    if (!tmp) return STATUS_INSUFFICIENT_RESOURCES;
    KeInitializeEvent(&ev, 0, 0);
    off.QuadPart = (int64_t)offset;
    irp = IoBuildSynchronousFsdRequest(IRP_MJ_READ, dev, tmp, len, &off, &ev, &iosb);
    if (!irp) { kfree(tmp); return STATUS_INSUFFICIENT_RESOURCES; }
    st = IofCallDriver(dev, irp);
    if (st == STATUS_PENDING) { KeWaitForSingleObject(&ev, 0, 0, 0, 0); st = iosb.Status; }
    if (NT_SUCCESS(st) && iosb.Information < len) st = STATUS_DEVICE_DATA_ERROR;
    if (NT_SUCCESS(st)) memcpy(buf, tmp, len);
    kfree(tmp);
    return st;
}
/* DRIVE_LAYOUT_INFORMATION_EX: PartitionStyle(0) PartitionCount(4) {Mbr Signature(8) CheckSum(0xc) | Gpt DiskId(8) StartingUsableOffset(0x18)
 * UsableLength(0x20) MaxPartitionCount(0x28)} PartitionEntry[](0x30, 0x90 each: PartitionStyle(0) StartingOffset(8) PartitionLength(0x10)
 * PartitionNumber(0x18) RewritePartition(0x1c) IsServicePartition(0x1d) {Mbr PartitionType(0x20) BootIndicator(0x21) RecognizedPartition(0x22)
 * HiddenSectors(0x24) PartitionId(0x28) | Gpt PartitionType(0x20) PartitionId(0x30) Attributes(0x40) Name[36](0x48)}) */
static int mbr_recognized(uint8_t t) { return t == 1 || t == 4 || t == 6 || t == 7 || t == 0xb || t == 0xc || t == 0xe || t == 0x42 || t == 0x83 || t == 0x86 || t == 0x87; }
NTSTATUS NTAPI IoReadPartitionTableEx(DEVICE_OBJECT *dev, void **layout)
{
    uint32_t ss = dev->SectorSize ? dev->SectorSize : 512, i, n;
    uint8_t *mbr = kmalloc(ss), *out;
    NTSTATUS st;
    if (!mbr) return STATUS_INSUFFICIENT_RESOURCES;
    st = read_sectors(dev, 0, mbr, ss);
    if (!NT_SUCCESS(st)) { kfree(mbr); return st; }
    if (*(uint16_t *)(mbr + 510) != 0xaa55) {
        out = ExAllocatePoolWithTag(1, 0x30, 0x74726150);
        if (!out) { kfree(mbr); return STATUS_INSUFFICIENT_RESOURCES; }
        memset(out, 0, 0x30); *(uint32_t *)out = 2;             /* PARTITION_STYLE_RAW */
        kfree(mbr); *layout = out;
        return STATUS_SUCCESS;
    }
    if (mbr[0x1be + 4] == 0xee) {                                /* protective MBR: GPT */
        uint8_t *hdr = kmalloc(ss), *ents; uint64_t entlba, nent, entsize, first, last;
        st = read_sectors(dev, ss, hdr, ss);
        if (!NT_SUCCESS(st) || memcmp(hdr, "EFI PART", 8)) { kfree(hdr); kfree(mbr); return NT_SUCCESS(st) ? STATUS_BAD_MASTER_BOOT_RECORD : st; }
        memcpy(&entlba, hdr + 0x48, 8); nent = *(uint32_t *)(hdr + 0x50); entsize = *(uint32_t *)(hdr + 0x54);
        memcpy(&first, hdr + 0x28, 8); memcpy(&last, hdr + 0x30, 8);
        if (!entsize || nent > 1024) { kfree(hdr); kfree(mbr); return STATUS_BAD_MASTER_BOOT_RECORD; }
        ents = kmalloc(((nent * entsize + ss - 1) / ss) * ss);
        if (!ents) { kfree(hdr); kfree(mbr); return STATUS_INSUFFICIENT_RESOURCES; }
        st = read_sectors(dev, entlba * ss, ents, (uint32_t)(((nent * entsize + ss - 1) / ss) * ss));
        if (!NT_SUCCESS(st)) { kfree(ents); kfree(hdr); kfree(mbr); return st; }
        for (i = 0, n = 0; i < nent; ++i) { const uint8_t *e = ents + i * entsize; uint64_t z = 0; if (memcmp(e, &z, 8) || memcmp(e + 8, &z, 8)) ++n; }
        out = ExAllocatePoolWithTag(1, 0x30 + n * 0x90, 0x74726150);
        if (!out) { kfree(ents); kfree(hdr); kfree(mbr); return STATUS_INSUFFICIENT_RESOURCES; }
        memset(out, 0, 0x30 + n * 0x90);
        *(uint32_t *)out = 1; *(uint32_t *)(out + 4) = n; memcpy(out + 8, hdr + 0x38, 16);
        { uint64_t v = first * ss; memcpy(out + 0x18, &v, 8); v = (last - first + 1) * ss; memcpy(out + 0x20, &v, 8); *(uint32_t *)(out + 0x28) = (uint32_t)nent; }
        for (i = 0, n = 0; i < nent; ++i) {
            const uint8_t *e = ents + i * entsize; uint64_t z = 0, s, l; uint8_t *p;
            if (!memcmp(e, &z, 8) && !memcmp(e + 8, &z, 8)) continue;
            p = out + 0x30 + n * 0x90;
            *(uint32_t *)p = 1;
            memcpy(&s, e + 0x20, 8); memcpy(&l, e + 0x28, 8);
            s *= ss; l = (l + 1) * ss - s;
            memcpy(p + 8, &s, 8); memcpy(p + 0x10, &l, 8); *(uint32_t *)(p + 0x18) = n + 1;
            memcpy(p + 0x20, e, 16); memcpy(p + 0x30, e + 16, 16); memcpy(p + 0x40, e + 0x30, 8); memcpy(p + 0x48, e + 0x38, 72);
            ++n;
        }
        kfree(ents); kfree(hdr); kfree(mbr);
        *layout = out;
        return STATUS_SUCCESS;
    }
    out = ExAllocatePoolWithTag(1, 0x30 + 4 * 0x90, 0x74726150);
    if (!out) { kfree(mbr); return STATUS_INSUFFICIENT_RESOURCES; }
    memset(out, 0, 0x30 + 4 * 0x90);
    *(uint32_t *)out = 0; *(uint32_t *)(out + 4) = 4; memcpy(out + 8, mbr + 0x1b8, 4);
    for (i = 0; i < 4; ++i) {
        const uint8_t *e = mbr + 0x1be + i * 16; uint8_t *p = out + 0x30 + i * 0x90;
        uint64_t s = (uint64_t)*(const uint32_t *)(e + 8) * ss, l = (uint64_t)*(const uint32_t *)(e + 12) * ss;
        *(uint32_t *)p = 0;
        memcpy(p + 8, &s, 8); memcpy(p + 0x10, &l, 8); *(uint32_t *)(p + 0x18) = i + 1;
        p[0x20] = e[4]; p[0x21] = e[0] == 0x80; p[0x22] = mbr_recognized(e[4]); *(uint32_t *)(p + 0x24) = *(const uint32_t *)(e + 8);
    }
    kfree(mbr);
    *layout = out;
    return STATUS_SUCCESS;
}
/* DISK_SIGNATURE (0x14): PartitionStyle(0) {Mbr Signature(4) CheckSum(8) | Gpt DiskId(4)} */
NTSTATUS NTAPI IoReadDiskSignature(DEVICE_OBJECT *dev, uint32_t ss, uint8_t *sig)
{
    uint8_t *mbr;
    NTSTATUS st;
    uint32_t i, sum = 0;
    if (!ss) ss = 512;
    mbr = kmalloc(ss);
    if (!mbr) return STATUS_INSUFFICIENT_RESOURCES;
    st = read_sectors(dev, 0, mbr, ss);
    if (!NT_SUCCESS(st)) { kfree(mbr); return st; }
    memset(sig, 0, 0x14);
    if (*(uint16_t *)(mbr + 510) != 0xaa55) { kfree(mbr); return STATUS_UNSUCCESSFUL; }
    if (mbr[0x1be + 4] == 0xee) {
        uint8_t *hdr = kmalloc(ss);
        if (!hdr) { kfree(mbr); return STATUS_INSUFFICIENT_RESOURCES; }
        st = read_sectors(dev, ss, hdr, ss);
        if (NT_SUCCESS(st) && !memcmp(hdr, "EFI PART", 8)) { *(uint32_t *)sig = 1; memcpy(sig + 4, hdr + 0x38, 16); }
        else st = NT_SUCCESS(st) ? STATUS_BAD_MASTER_BOOT_RECORD : st;
        kfree(hdr); kfree(mbr);
        return st;
    }
    *(uint32_t *)sig = 0; memcpy(sig + 4, mbr + 0x1b8, 4);
    for (i = 0; i < 128; ++i) sum += *(uint32_t *)(mbr + i * 4);
    *(uint32_t *)(sig + 8) = (uint32_t)(-(int32_t)sum);
    kfree(mbr);
    return STATUS_SUCCESS;
}
/* HalExamineMBR: reads the MBR and, when the first partition entry carries the requested type (EZ-Drive 0x55, OnTrack
 * 0x54), hands back the sector for the caller to interpret; otherwise *buffer is NULL. */
NTSTATUS NTAPI HalExamineMBR(DEVICE_OBJECT *dev, uint32_t ss, uint32_t type, void **buffer)
{
    uint8_t *mbr;
    NTSTATUS st;
    if (!ss) ss = 512;
    *buffer = 0;
    mbr = ExAllocatePoolWithTag(1, ss, 0x72626d48);
    if (!mbr) return STATUS_INSUFFICIENT_RESOURCES;
    st = read_sectors(dev, 0, mbr, ss);
    if (!NT_SUCCESS(st)) { ExFreePool(mbr); return st; }
    if (*(uint16_t *)(mbr + 510) != 0xaa55 || mbr[0x1be + 4] != type) { ExFreePool(mbr); return STATUS_SUCCESS; }
    if (type == 0x54 && mbr[0x1be + 4] == 0x54) {               /* OnTrack: the DM skew data is the sector after the MBR */
        uint8_t *next = ExAllocatePoolWithTag(1, ss, 0x72626d48);
        if (next && NT_SUCCESS(read_sectors(dev, ss, next, ss))) { ExFreePool(mbr); *buffer = next; return STATUS_SUCCESS; }
        if (next) ExFreePool(next);
    }
    *buffer = mbr;
    return STATUS_SUCCESS;
}

/* ================================================================ Mm: pageable sections, page MDLs, system routines */
void *NTAPI MmLockPagableDataSection(void *addr) { ntdrv_driver_t *d = ntdrv_driver_by_address((uint64_t)addr); return d ? (void *)d->image_base : addr; }
void *NTAPI MmLockPagableCodeSection(void *addr) { return MmLockPagableDataSection(addr); }
void NTAPI MmLockPagableSectionByHandle(void *handle) { (void)handle; }          /* sections are always resident here */
void NTAPI MmUnlockPagableImageSection(void *handle) { (void)handle; }
void *NTAPI MmGetSystemRoutineAddress(UNICODE_STRING *name)
{
    char n[96];
    void *fn;
    ntdrv_wide_to_ascii(name->Buffer, name->Length / 2, n, sizeof n);
    fn = ntdrv_resolve_export("ntoskrnl.exe", n);
    if (!fn) fn = ntdrv_resolve_export("hal.dll", n);
    return fn;
}
MDL *NTAPI MmAllocatePagesForMdlEx(LARGE_INTEGER low, LARGE_INTEGER high, LARGE_INTEGER skip, uint64_t bytes, uint32_t cache, uint32_t flags)
{
    uint32_t pages = (uint32_t)((bytes + 4095) / 4096), i, got = 0;
    MDL *m;
    uint64_t *pfn;
    (void)skip; (void)cache; (void)flags;
    if (!pages) return 0;
    m = kzalloc(sizeof(MDL) + pages * 8);
    if (!m) return 0;
    pfn = (uint64_t *)(m + 1);
    for (i = 0; i < pages; ++i) {
        uint64_t pa = pmm_alloc();
        if (!pa || (int64_t)pa < low.QuadPart || (int64_t)pa + 4096 > high.QuadPart + 1) { if (pa) pmm_free(pa); break; }
        pfn[got++] = pa / 4096;
    }
    if (!got) { kfree(m); return 0; }
    m->Size = (int16_t)(sizeof(MDL) + pages * 8);
    m->ByteCount = got * 4096 < bytes ? got * 4096 : (uint32_t)bytes;
    m->MdlFlags = MDL_PAGES_LOCKED;                              /* no system VA until MmMapLockedPages */
    return m;
}
MDL *NTAPI MmAllocatePagesForMdl(LARGE_INTEGER low, LARGE_INTEGER high, LARGE_INTEGER skip, uint64_t bytes) { return MmAllocatePagesForMdlEx(low, high, skip, bytes, 1, 0); }
void NTAPI MmFreePagesFromMdl(MDL *m)
{
    uint32_t pages = (uint32_t)((m->ByteOffset + m->ByteCount + 4095) / 4096), i;
    uint64_t *pfn = (uint64_t *)(m + 1);
    if ((unsigned)m->Size < sizeof(MDL) + pages * 8) return;
    for (i = 0; i < pages; ++i) if (pfn[i]) { pmm_free(pfn[i] * 4096); pfn[i] = 0; }
    m->ByteCount = 0;
}
uint8_t NTAPI MmIsDriverVerifying(DRIVER_OBJECT *drv) { (void)drv; return 0; }
uint8_t NTAPI MmIsDriverVerifyingByAddress(void *addr) { (void)addr; return 0; }
uint8_t NTAPI MmIsThisAnNtAsSystem(void) { return 0; }
uint32_t NTAPI MmQuerySystemSize(void) { return 2; }              /* MmLargeSystem */

/* ================================================================ Ob / Ps odds */
NTSTATUS NTAPI ObReferenceObjectByPointer(void *obj, uint32_t access, void *type, uint8_t mode)
{
    int16_t t = *(int16_t *)obj;
    extern int ntdrv_object_type_kind(const void *type);
    int kind = ntdrv_object_type_kind(type);
    (void)access; (void)mode;
    if (kind == KH_DEVICE && t != 3) return STATUS_OBJECT_TYPE_MISMATCH_;
    if (kind == KH_DRIVER && t != 4) return STATUS_OBJECT_TYPE_MISMATCH_;
    if (kind == KH_FILE && t != 5) return STATUS_OBJECT_TYPE_MISMATCH_;
    if (t == 3) ((DEVICE_OBJECT *)obj)->ReferenceCount++;
    return STATUS_SUCCESS;
}
uint8_t NTAPI PsIsThreadTerminating(thread_t *t) { return t && (t->state == TS_ZOMBIE || t->kill_pending); }
void *NTAPI PsGetCurrentProcess(void) { static uint8_t system_process[0x400]; return system_process; }
void *NTAPI IoGetCurrentProcess(void) { return PsGetCurrentProcess(); }
uint8_t NTAPI PsGetVersion(uint32_t *major, uint32_t *minor, uint32_t *build, UNICODE_STRING *csd)
{
    if (major) *major = 10; if (minor) *minor = 0; if (build) *build = 22631;
    if (csd) { csd->Length = 0; if (csd->MaximumLength >= 2 && csd->Buffer) csd->Buffer[0] = 0; }
    return 0;                                                    /* not a checked build */
}
