/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the PnP root for PCI functions bound through the registry.
 *
 * Windows starts a function driver through the PnP manager: the bus driver's physical device object (PDO) for the
 * function exists, the devnode's Service names the driver, the manager calls the driver's AddDevice(DriverObject, PDO)
 * and sends IRP_MJ_PNP / IRP_MN_START_DEVICE down the new device stack with the function's assigned resources
 * (CM_RESOURCE_LIST: I/O ports, memory windows, the interrupt). The host has no bus driver, so this file plays that
 * part for the functions of the Kernel64 PCI scan: one PDO per devnode that shzpnp add-driver --install wrote under
 * HKLM\SYSTEM\CurrentControlSet\Enum\PCI\<hwid>\B<bus>D<dev>F<fn>, resources read from the function's BARs and
 * interrupt line, AddDevice + IRP_MN_START_DEVICE after the driver's DriverEntry returned success. The PDO answers
 * the PnP requests a function driver sends down: IRP_MN_QUERY_INTERFACE for GUID_BUS_INTERFACE_STANDARD (config
 * space access, DMA adapter), the device properties (IoGetDeviceProperty) and the device/driver registry keys
 * (IoOpenDeviceRegistryKey). The DMA adapter (IoGetDmaAdapter) hands out common buffers from the physically
 * contiguous, direct-mapped kernel heap and builds scatter/gather lists from MDLs. Every structure layout here is
 * Windows x64's (sizes and offsets checked below against the numbers measured from Microsoft's wdm.h).
 */
#include "ntdrv.h"
#include "registry.h"
#include "ipc.h"
#include "../abi/shz_pnp_catalog.h"
#include "blk.h"
#include "laptop_firmware.h"

/* provider routines implemented in ntdrv_io.c (prototyped there only for the drivers' import tables) */
NTSTATUS NTAPI IoCreateDevice(DRIVER_OBJECT *drv, uint32_t ext_size, UNICODE_STRING *name, uint32_t type,
                              uint32_t chars, uint8_t exclusive, DEVICE_OBJECT **out);
void NTAPI IoDeleteDevice(DEVICE_OBJECT *dev);
DEVICE_OBJECT *NTAPI IoGetAttachedDevice(DEVICE_OBJECT *d);
IRP *NTAPI IoAllocateIrp(uint8_t stackcount, uint8_t charge);
NTSTATUS NTAPI IofCallDriver(DEVICE_OBJECT *dev, IRP *irp);
void NTAPI IofCompleteRequest(IRP *irp, uint8_t boost);
uint32_t NTAPI HalGetInterruptVector(uint32_t bus_type, uint32_t bus, uint32_t level, uint32_t vec, uint8_t *irql, uint64_t *aff);

#define NT_SUCCESS(s) ((int32_t)(s) >= 0)
#define STATUS_NOT_SUPPORTED ((int32_t)0xC00000BB)
#define STATUS_BUFFER_OVERFLOW_W ((int32_t)0x80000005)

/* ---- PnP minor functions ---- */
#define IRP_MN_START_DEVICE 0x00
#define IRP_MN_QUERY_REMOVE_DEVICE 0x01
#define IRP_MN_REMOVE_DEVICE 0x02
#define IRP_MN_CANCEL_REMOVE_DEVICE 0x03
#define IRP_MN_STOP_DEVICE 0x04
#define IRP_MN_QUERY_STOP_DEVICE 0x05
#define IRP_MN_CANCEL_STOP_DEVICE 0x06
#define IRP_MN_QUERY_INTERFACE 0x08
#define IRP_MN_QUERY_PNP_DEVICE_STATE 0x14
#define IRP_MN_SURPRISE_REMOVAL 0x17

static const GUID GUID_BUS_INTERFACE_STANDARD = { 0x496b8280, 0x6f25, 0x11d0, { 0xbe, 0xaf, 0x08, 0x00, 0x2b, 0xe2, 0x09, 0x2f } };

/* ---- CM_RESOURCE_LIST: declared under pack(4) in wdm.h, so a descriptor is 0x14 bytes with the union at +4 ---- */
#pragma pack(push, 4)
typedef struct {
    uint8_t Type, ShareDisposition;
    uint16_t Flags;
    union {
        struct { int64_t Start; uint32_t Length; } Generic;
        struct { int64_t Start; uint32_t Length; } Port;
        struct { int64_t Start; uint32_t Length; } Memory;
        struct { uint32_t Level, Vector; uint64_t Affinity; } Interrupt;
        struct { uint32_t Data[3]; } DevicePrivate;
    } u;
} CM_PARTIAL_RESOURCE_DESCRIPTOR;
/* PartialDescriptors is declared [1] in wdm.h; here it is a flexible array so the compiler does not assume a single
 * element when the host walks the list it built (GCC -O2 otherwise cuts such a loop to one iteration). */
typedef struct { uint16_t Version, Revision; uint32_t Count; CM_PARTIAL_RESOURCE_DESCRIPTOR PartialDescriptors[]; } CM_PARTIAL_RESOURCE_LIST;
typedef struct { uint32_t InterfaceType, BusNumber; CM_PARTIAL_RESOURCE_LIST PartialResourceList; } CM_FULL_RESOURCE_DESCRIPTOR;
typedef struct { uint32_t Count; CM_FULL_RESOURCE_DESCRIPTOR List[1]; } CM_RESOURCE_LIST;
#pragma pack(pop)
_Static_assert(sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) == 0x14, "cm desc");
_Static_assert(offsetof(CM_PARTIAL_RESOURCE_DESCRIPTOR, u.Interrupt.Affinity) == 0xc, "cm affinity");
_Static_assert(offsetof(CM_PARTIAL_RESOURCE_DESCRIPTOR, u.Memory.Length) == 0xc, "cm memlen");
_Static_assert(sizeof(CM_RESOURCE_LIST) + sizeof(CM_PARTIAL_RESOURCE_DESCRIPTOR) == 0x28 &&      /* wdm.h's sizeof, one descriptor */
               offsetof(CM_FULL_RESOURCE_DESCRIPTOR, PartialResourceList) == 8 &&
               offsetof(CM_PARTIAL_RESOURCE_LIST, PartialDescriptors) == 8, "cm list");
#define CmResourceTypePort 1
#define CmResourceTypeInterrupt 2
#define CmResourceTypeMemory 3
#define CmResourceShareDeviceExclusive 1
#define CmResourceShareShared 3
#define CM_RESOURCE_PORT_IO 1
#define CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE 0
#define PCIBus 5

/* IO_STACK_LOCATION.Parameters views (the union starts at +8 of the stack location) */
typedef struct { const GUID *InterfaceType; uint16_t Size, Version; uint32_t _pad; void *Interface; void *InterfaceSpecificData; } STK_QUERY_INTERFACE;
typedef struct { CM_RESOURCE_LIST *AllocatedResources, *AllocatedResourcesTranslated; } STK_START_DEVICE;
_Static_assert(offsetof(STK_QUERY_INTERFACE, Interface) == 0x10 && offsetof(STK_QUERY_INTERFACE, InterfaceSpecificData) == 0x18, "qi");

/* BUS_INTERFACE_STANDARD (0x40) */
typedef struct {
    uint16_t Size, Version;
    uint32_t _pad;
    void *Context;
    void *InterfaceReference, *InterfaceDereference;
    void *TranslateBusAddress, *GetDmaAdapter, *SetBusData, *GetBusData;
} BUS_INTERFACE_STANDARD;
_Static_assert(sizeof(BUS_INTERFACE_STANDARD) == 0x40 && offsetof(BUS_INTERFACE_STANDARD, GetBusData) == 0x38, "bus if");

/* DMA_ADAPTER / DMA_OPERATIONS (0x10 / 0x80) */
typedef struct {
    uint32_t Size, _pad;
    void *PutDmaAdapter, *AllocateCommonBuffer, *FreeCommonBuffer, *AllocateAdapterChannel, *FlushAdapterBuffers,
         *FreeAdapterChannel, *FreeMapRegisters, *MapTransfer, *GetDmaAlignment, *ReadDmaCounter, *GetScatterGatherList,
         *PutScatterGatherList, *CalculateScatterGatherList, *BuildScatterGatherList, *BuildMdlFromScatterGatherList;
} DMA_OPERATIONS;
typedef struct { uint16_t Version, Size; uint32_t _pad; DMA_OPERATIONS *DmaOperations; } DMA_ADAPTER;
_Static_assert(sizeof(DMA_OPERATIONS) == 0x80 && offsetof(DMA_OPERATIONS, GetScatterGatherList) == 0x58, "dma ops");
_Static_assert(sizeof(DMA_ADAPTER) == 0x10, "dma adapter");
typedef struct { int64_t Address; uint32_t Length, _pad; uint64_t Reserved; } SCATTER_GATHER_ELEMENT;
typedef struct { uint32_t NumberOfElements, _pad; uint64_t Reserved; SCATTER_GATHER_ELEMENT Elements[1]; } SCATTER_GATHER_LIST;
_Static_assert(sizeof(SCATTER_GATHER_ELEMENT) == 0x18 && offsetof(SCATTER_GATHER_LIST, Elements) == 0x10, "sg");

/* ---------------------------------------------------------------- PDO records */
struct ntdrv_pdo {
    struct ntdrv_pdo *next;
    DEVICE_OBJECT *pdo;
    pci_dev_t dev;
    ntdrv_driver_t *fdo_driver;
    int attempted, started;
    int no_add_device;                  /* bound to a legacy (non-PnP) driver: no AddDevice, no start IRP */
    int32_t start_status;               /* actual AddDevice / IRP_MN_START_DEVICE outcome (driver bring-up report) */
    unsigned index;
    char instance[128];                 /* PCI\VEN_8086&DEV_100E\B00D03F0 */
    uint16_t driverkey[80];             /* Enum "Driver": {ClassGUID}\0000 */
    uint16_t desc[128], mfg[128], cls[64], classguid[40];
    uint16_t hwids[512];                /* REG_MULTI_SZ */
    uint32_t hwids_len;                 /* bytes */
    uint16_t iface[4][160];             /* the device interface links registered on it (IoRegisterDeviceInterface) */
    uint8_t iface_guid[4][16];           /* actual registration GUID, retained without reparsing links */
    int iface_enabled[4];
    unsigned niface;
};
static ntdrv_pdo_t *pdos;
static unsigned pdo_count;
static DRIVER_OBJECT *root_drv;
static uint16_t root_name[] = { '\\', 'D', 'r', 'i', 'v', 'e', 'r', '\\', 'P', 'n', 'p', 'M', 'a', 'n', 'a', 'g', 'e', 'r' };

static NTSTATUS NTAPI root_dispatch(DEVICE_OBJECT *dev, IRP *irp);

ntdrv_pdo_t *ntdrv_pdo_from_device(DEVICE_OBJECT *dev)
{
    ntdrv_pdo_t *p;
    for (p = pdos; p; p = p->next) if (p->pdo == dev) return p;
    return 0;
}

static void copy_value(regkey_t *k, const uint16_t *name, unsigned nchars, uint16_t *out, unsigned cap, uint32_t *bytes_out)
{
    regval_t *v = reg_find_value(k, name, nchars);
    uint32_t n;
    out[0] = 0;
    if (bytes_out) *bytes_out = 0;
    if (!v || (v->type != REG_SZ && v->type != REG_EXPAND_SZ && v->type != REG_MULTI_SZ)) return;
    n = v->data_len / 2 < cap - 1 ? v->data_len / 2 : cap - 1;
    memcpy(out, regval_data(v), n * 2);
    out[n] = 0;
    if (bytes_out) *bytes_out = n * 2 + (v->type == REG_MULTI_SZ ? 2 : 0);
}

static DRIVER_OBJECT *root_driver(void)
{
    unsigned i;
    if (root_drv) return root_drv;
    root_drv = kzalloc(SZ_DRV);
    KASSERT(root_drv);
    root_drv->Type = 4; root_drv->Size = SZ_DRV;
    root_drv->DriverName.Buffer = root_name;
    root_drv->DriverName.Length = root_drv->DriverName.MaximumLength = sizeof root_name;
    for (i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; ++i) root_drv->MajorFunction[i] = root_dispatch;
    return root_drv;
}

/* registry lock held by the caller (ntdrv_bind_enum) */
void ntdrv_pnp_add(ntdrv_driver_t *d, const pci_dev_t *dev, regkey_t *inst_key, const char *instance_path)
{
    static const uint16_t nDriver[] = { 'D','r','i','v','e','r' }, nDesc[] = { 'D','e','v','i','c','e','D','e','s','c' },
        nMfg[] = { 'M','f','g' }, nClass[] = { 'C','l','a','s','s' }, nGuid[] = { 'C','l','a','s','s','G','U','I','D' },
        nHw[] = { 'H','a','r','d','w','a','r','e','I','D' };
    ntdrv_pdo_t *p;
    UNICODE_STRING name;
    uint16_t wname[32];
    char aname[32];
    unsigned i;
    for (p = pdos; p; p = p->next)
        if (p->dev.bus == dev->bus && p->dev.dev == dev->dev && p->dev.fn == dev->fn) {
            if (p->fdo_driver && p->fdo_driver != d) {
                kprintf("K64 ntdrv: PCI %x:%x.%x already has a function driver (%s); %s not bound\n",
                        dev->bus, dev->dev, dev->fn, p->fdo_driver->name, d->name);
                return;
            }
            p->fdo_driver = d; p->attempted = 0; p->started = 0; p->no_add_device = 0; p->start_status = 0;
            return;
        }
    p = kzalloc(sizeof *p);
    if (!p) return;
    p->dev = *dev;
    p->fdo_driver = d;
    p->index = pdo_count++;
    for (i = 0; instance_path[i] && i + 1 < sizeof p->instance; ++i) p->instance[i] = instance_path[i];
    copy_value(inst_key, nDriver, 6, p->driverkey, 80, 0);
    copy_value(inst_key, nDesc, 10, p->desc, 128, 0);
    copy_value(inst_key, nMfg, 3, p->mfg, 128, 0);
    copy_value(inst_key, nClass, 5, p->cls, 64, 0);
    copy_value(inst_key, nGuid, 9, p->classguid, 40, 0);
    copy_value(inst_key, nHw, 10, p->hwids, 512, &p->hwids_len);
    {   /* \Device\NTPNP_PCI%04u, as Windows names a PCI bus driver's PDOs */
        static const char pfx[] = "\\Device\\NTPNP_PCI";
        unsigned n = 0, k = p->index;
        for (i = 0; pfx[i]; ++i) aname[n++] = pfx[i];
        aname[n++] = (char)('0' + k / 1000 % 10); aname[n++] = (char)('0' + k / 100 % 10);
        aname[n++] = (char)('0' + k / 10 % 10); aname[n++] = (char)('0' + k % 10); aname[n] = 0;
        ntdrv_ascii_to_wide(aname, wname, 32);
        name.Buffer = wname; name.Length = (uint16_t)(n * 2); name.MaximumLength = (uint16_t)(n * 2 + 2);
    }
    if (IoCreateDevice(root_driver(), 0, &name, 0x22 /* FILE_DEVICE_UNKNOWN */, 0, 0, &p->pdo) != STATUS_SUCCESS) { kfree(p); return; }
    p->pdo->Flags &= ~DO_DEVICE_INITIALIZING;
    p->next = pdos; pdos = p;
}

/* ---------------------------------------------------------------- resources of a function */
static unsigned pci_resources(const pci_dev_t *d, CM_PARTIAL_RESOURCE_DESCRIPTOR *out, int translated)
{
    unsigned n = 0, b;
    uint8_t line;
    if ((pci_cfg_read32(d, 0x0c) >> 16 & 0x7f) == 0) {                     /* type-0 header: six BARs */
        for (b = 0; b < 6 && n < 8; ++b) {
            const uint32_t raw = pci_cfg_read32(d, 0x10 + 4 * b);
            const int mem64 = !(raw & 1) && ((raw >> 1) & 3) == 2;
            uint64_t size = 0, base;
            int is_io = 0;
            base = pci_bar(d, b, &size, &is_io);
            if (base && size) {
                CM_PARTIAL_RESOURCE_DESCRIPTOR *r = &out[n++];
                memset(r, 0, sizeof *r);
                r->Type = (uint8_t)(is_io ? CmResourceTypePort : CmResourceTypeMemory);
                r->ShareDisposition = CmResourceShareDeviceExclusive;
                r->Flags = (uint16_t)(is_io ? CM_RESOURCE_PORT_IO : 0);
                r->u.Generic.Start = (int64_t)base;
                r->u.Generic.Length = (uint32_t)size;
            }
            if (mem64) ++b;
        }
    }
    line = (uint8_t)(pci_cfg_read32(d, 0x3c) & 0xff);
    if (line && line != 0xff && n < 8) {
        CM_PARTIAL_RESOURCE_DESCRIPTOR *r = &out[n++];
        memset(r, 0, sizeof *r);
        r->Type = CmResourceTypeInterrupt;
        r->ShareDisposition = CmResourceShareShared;
        r->Flags = CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE;
        r->u.Interrupt.Level = line;
        r->u.Interrupt.Vector = line;
        if (translated) {                                                   /* system vector + DIRQL, as the HAL maps it */
            uint8_t irql = 0; uint64_t aff = 1;
            r->u.Interrupt.Vector = HalGetInterruptVector(PCIBus, d->bus, line, line, &irql, &aff);
            r->u.Interrupt.Level = irql;
        }
        r->u.Interrupt.Affinity = 1;
    }
    return n;
}

static CM_RESOURCE_LIST *build_resource_list(const pci_dev_t *d, int translated)
{
    CM_PARTIAL_RESOURCE_DESCRIPTOR tmp[8];
    unsigned n = pci_resources(d, tmp, translated);
    CM_RESOURCE_LIST *l = kzalloc(sizeof *l + n * sizeof tmp[0]);
    if (!l) return 0;
    l->Count = 1;
    l->List[0].InterfaceType = PCIBus;
    l->List[0].BusNumber = d->bus;
    l->List[0].PartialResourceList.Version = 1;
    l->List[0].PartialResourceList.Revision = 1;
    l->List[0].PartialResourceList.Count = n;
    memcpy(l->List[0].PartialResourceList.PartialDescriptors, tmp, n * sizeof tmp[0]);
    return l;
}

static void log_resources(const char *svc, const CM_RESOURCE_LIST *l)
{
    unsigned i;
    kprintf("K64 ntdrv: %s: %u resource(s) for IRP_MN_START_DEVICE\n", svc, l->List[0].PartialResourceList.Count);
    for (i = 0; i < l->List[0].PartialResourceList.Count; ++i) {
        const CM_PARTIAL_RESOURCE_DESCRIPTOR *r = &l->List[0].PartialResourceList.PartialDescriptors[i];
        if (r->Type == CmResourceTypeInterrupt)
            kprintf("K64 ntdrv: %s resource: interrupt line %u (shared, level)\n", svc, r->u.Interrupt.Level);
        else
            kprintf("K64 ntdrv: %s resource: %s %llx +%x\n", svc, r->Type == CmResourceTypePort ? "port" : "memory",
                    (unsigned long long)r->u.Generic.Start, r->u.Generic.Length);
    }
}

/* AddDevice + IRP_MN_START_DEVICE for the PDOs recorded for d (registry lock NOT held) */
void ntdrv_pnp_start_pending(ntdrv_driver_t *d)
{
    ntdrv_pdo_t *p;
    for (p = pdos; p; p = p->next) {
        NTSTATUS (NTAPI *add)(DRIVER_OBJECT *, DEVICE_OBJECT *);
        DEVICE_OBJECT *top;
        IRP *irp;
        IO_STACK_LOCATION *stk;
        STK_START_DEVICE *sd;
        CM_RESOURCE_LIST *raw, *xlat;
        int32_t st;
        if (p->fdo_driver != d || p->attempted) continue;
        p->attempted = 1;
        add = d->drv->DriverExtension ? (void *)d->drv->DriverExtension->AddDevice : 0;
        if (!add) {
            p->no_add_device = 1;
            kprintf("K64 ntdrv: %s has no AddDevice (non-PnP driver): PCI %x:%x.%x is bound, no start IRP\n",
                    d->name, p->dev.bus, p->dev.dev, p->dev.fn);
            continue;
        }
        pci_enable(&p->dev, 1, 1, 1);                             /* what pci.sys does when it starts the function */
        ntdrv_set_current_driver(d);
        st = add(d->drv, p->pdo);
        kprintf("K64 ntdrv: %s AddDevice(PCI %x:%x.%x) = %x\n", d->name, p->dev.bus, p->dev.dev, p->dev.fn, (uint32_t)st);
        if (!NT_SUCCESS(st)) { p->start_status = st; ntdrv_set_current_driver(0); continue; }
        top = IoGetAttachedDevice(p->pdo);
        if (top == p->pdo) {
            kprintf("K64 ntdrv: %s AddDevice attached no FDO\n", d->name);
            p->start_status = STATUS_DEVICE_CONFIGURATION_ERROR; ntdrv_set_current_driver(0); continue;
        }
        raw = build_resource_list(&p->dev, 0);
        xlat = build_resource_list(&p->dev, 1);
        irp = raw && xlat ? IoAllocateIrp((uint8_t)top->StackSize, 0) : 0;
        if (!irp) { p->start_status = STATUS_INSUFFICIENT_RESOURCES; kfree(raw); kfree(xlat); ntdrv_set_current_driver(0); continue; }
        log_resources(d->name, raw);
        stk = irp->Tail.Overlay.CurrentStackLocation - 1;
        stk->MajorFunction = IRP_MJ_PNP;
        stk->MinorFunction = IRP_MN_START_DEVICE;
        sd = (STK_START_DEVICE *)&stk->Parameters;
        sd->AllocatedResources = raw;
        sd->AllocatedResourcesTranslated = xlat;
        irp->IoStatus.Status = STATUS_NOT_SUPPORTED;                 /* the PnP manager's initial status */
        st = ntdrv_send_irp_sync(top, irp, 0);
        p->start_status = st;
        p->started = NT_SUCCESS(st);
        ntdrv_set_current_driver(0);
        kprintf("K64 ntdrv: %s IRP_MN_START_DEVICE(PCI %x:%x.%x) = %x%s\n", d->name, p->dev.bus, p->dev.dev, p->dev.fn,
                (uint32_t)st, p->started ? " (started)" : "");
        kfree(raw); kfree(xlat);
    }
}

static int32_t send_pnp(DEVICE_OBJECT *top, uint8_t minor)
{
    IRP *irp = IoAllocateIrp((uint8_t)top->StackSize, 0);
    IO_STACK_LOCATION *stk;
    if (!irp) return STATUS_INSUFFICIENT_RESOURCES;
    stk = irp->Tail.Overlay.CurrentStackLocation - 1;
    stk->MajorFunction = IRP_MJ_PNP;
    stk->MinorFunction = minor;
    irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    return ntdrv_send_irp_sync(top, irp, 0);
}

/* What the PnP manager does before it lets a function driver go: IRP_MN_QUERY_REMOVE_DEVICE, then (if nobody objects)
 * IRP_MN_REMOVE_DEVICE down every started stack, which is where a WDM driver detaches and deletes its FDO, disconnects
 * its interrupt and unmaps its resources. A refused query is cancelled (IRP_MN_CANCEL_REMOVE_DEVICE) and the status is
 * returned: the driver stays loaded. Exercised by no test here (the test drivers have no AddDevice, and the corpus
 * NDIS miniport has no DriverUnload, which keeps an unload from getting this far). */
int32_t ntdrv_pnp_remove_devices(ntdrv_driver_t *d)
{
    ntdrv_pdo_t *p;
    for (p = pdos; p; p = p->next) {
        DEVICE_OBJECT *top;
        int32_t st;
        if (p->fdo_driver != d || !p->started) continue;
        top = IoGetAttachedDevice(p->pdo);
        if (top == p->pdo) { p->started = 0; continue; }
        ntdrv_set_current_driver(d);
        st = send_pnp(top, IRP_MN_QUERY_REMOVE_DEVICE);
        if (!NT_SUCCESS(st)) {
            kprintf("K64 ntdrv: %s refused IRP_MN_QUERY_REMOVE_DEVICE (%x): not unloaded\n", d->name, (uint32_t)st);
            send_pnp(top, IRP_MN_CANCEL_REMOVE_DEVICE);
            ntdrv_set_current_driver(0);
            return st;
        }
        st = send_pnp(top, IRP_MN_REMOVE_DEVICE);
        kprintf("K64 ntdrv: %s IRP_MN_REMOVE_DEVICE(PCI %x:%x.%x) = %x\n", d->name, p->dev.bus, p->dev.dev, p->dev.fn, (uint32_t)st);
        ntdrv_set_current_driver(0);
        p->started = 0;
    }
    return STATUS_SUCCESS;
}

void ntdrv_pnp_driver_unloading(ntdrv_driver_t *d)
{
    ntdrv_pdo_t **pp = &pdos;
    while (*pp) {
        ntdrv_pdo_t *p = *pp;
        if (p->fdo_driver == d) {
            *pp = p->next;
            p->pdo->AttachedDevice = 0;                              /* the FDO above it is gone with its driver */
            IoDeleteDevice(p->pdo);
            kfree(p);
        } else pp = &p->next;
    }
}

/* ---------------------------------------------------------------- the PDO's dispatch */
static int guid_eq(const GUID *a, const GUID *b) { return memcmp(a, b, sizeof *a) == 0; }

static void NTAPI if_ref(void *ctx) { (void)ctx; }
static void NTAPI if_deref(void *ctx) { (void)ctx; }
static uint8_t NTAPI if_translate(void *ctx, int64_t bus_addr, uint32_t len, uint32_t *space, int64_t *out)
{ (void)ctx; (void)len; (void)space; *out = bus_addr; return 1; }
static uint32_t NTAPI if_get_bus_data(void *ctx, uint32_t type, void *buf, uint32_t off, uint32_t len)
{
    ntdrv_pdo_t *p = ctx;
    uint8_t *out = buf;
    uint32_t i;
    if (!p || type != 0 /* PCI_WHICHSPACE_CONFIG */ || off >= 256) return 0;
    if (off + len > 256) len = 256 - off;
    for (i = 0; i < len; ++i) {
        const uint32_t dw = pci_cfg_read32(&p->dev, (off + i) & ~3u);
        out[i] = (uint8_t)(dw >> (8 * ((off + i) & 3)));
    }
    return len;
}
static uint32_t NTAPI if_set_bus_data(void *ctx, uint32_t type, void *buf, uint32_t off, uint32_t len)
{
    ntdrv_pdo_t *p = ctx;
    const uint8_t *in = buf;
    uint32_t pos, end;
    if (!p || type != 0 || off >= 256) return 0;
    if (off + len > 256) len = 256 - off;
    end = off + len;
    for (pos = off; pos < end; ) {
        const unsigned reg = pos & ~3u;
        uint32_t dw = pci_cfg_read32(&p->dev, reg), mask = 0;
        unsigned b;
        for (b = pos & 3; b < 4 && reg + b < end; ++b) {              /* merge every byte of this dword, then write it once */
            dw = (dw & ~(0xffu << (8 * b))) | ((uint32_t)in[reg + b - off] << (8 * b));
            mask |= 0xffu << (8 * b);
        }
        /* dword 0x04 is Command (RW) | Status (RW1C): writing back the Status bits as read would clear the device's sticky
         * error flags, so they are written as 0 (no effect) unless the caller supplied the Status bytes itself */
        if (reg == 4 && !(mask & 0xffff0000u)) dw &= 0x0000ffffu;
        pci_cfg_write32(&p->dev, reg, dw);
        pos = reg + 4;
    }
    return len;
}
static void *NTAPI if_get_dma_adapter(void *ctx, void *desc, uint32_t *nmap);

static NTSTATUS NTAPI root_dispatch(DEVICE_OBJECT *dev, IRP *irp)
{
    IO_STACK_LOCATION *stk = irp->Tail.Overlay.CurrentStackLocation;
    ntdrv_pdo_t *p = ntdrv_pdo_from_device(dev);
    int32_t st;
    switch (stk->MajorFunction) {
    case IRP_MJ_PNP:
        switch (stk->MinorFunction) {
        case IRP_MN_START_DEVICE:
        case IRP_MN_QUERY_REMOVE_DEVICE: case IRP_MN_REMOVE_DEVICE: case IRP_MN_CANCEL_REMOVE_DEVICE:
        case IRP_MN_STOP_DEVICE: case IRP_MN_QUERY_STOP_DEVICE: case IRP_MN_CANCEL_STOP_DEVICE: case IRP_MN_SURPRISE_REMOVAL:
            irp->IoStatus.Status = STATUS_SUCCESS;
            break;
        case IRP_MN_QUERY_PNP_DEVICE_STATE:
            irp->IoStatus.Status = STATUS_SUCCESS;
            irp->IoStatus.Information = 0;
            break;
        case IRP_MN_QUERY_INTERFACE: {
            STK_QUERY_INTERFACE *qi = (STK_QUERY_INTERFACE *)&stk->Parameters;
            if (p && qi->InterfaceType && guid_eq(qi->InterfaceType, &GUID_BUS_INTERFACE_STANDARD) && qi->Interface &&
                qi->Size >= sizeof(BUS_INTERFACE_STANDARD)) {
                BUS_INTERFACE_STANDARD *b = qi->Interface;
                b->Size = sizeof *b; b->Version = 1; b->Context = p;
                b->InterfaceReference = (void *)if_ref; b->InterfaceDereference = (void *)if_deref;
                b->TranslateBusAddress = (void *)if_translate; b->GetDmaAdapter = (void *)if_get_dma_adapter;
                b->SetBusData = (void *)if_set_bus_data; b->GetBusData = (void *)if_get_bus_data;
                irp->IoStatus.Status = STATUS_SUCCESS;
                kprintf("K64 ntdrv: PCI %x:%x.%x: BUS_INTERFACE_STANDARD handed to the function driver\n", p->dev.bus, p->dev.dev, p->dev.fn);
            }
            /* any other interface: leave IoStatus as the requester set it (STATUS_NOT_SUPPORTED), as a PDO does */
            break;
        }
        default:
            break;                                                   /* unknown minor: status unchanged, completed */
        }
        break;
    case IRP_MJ_POWER:
    case IRP_MJ_CREATE: case IRP_MJ_CLOSE: case IRP_MJ_CLEANUP:
        irp->IoStatus.Status = STATUS_SUCCESS;
        break;
    default:
        irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    st = irp->IoStatus.Status;
    IofCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}

/* ---------------------------------------------------------------- device properties and registry keys */
static unsigned wlen16(const uint16_t *s) { unsigned n = 0; while (s[n]) ++n; return n; }

static int32_t put_property(const void *data, uint32_t bytes, uint32_t buflen, void *buf, uint32_t *reslen)
{
    if (reslen) *reslen = bytes;
    if (buflen < bytes || !buf) return STATUS_BUFFER_TOO_SMALL;
    memcpy(buf, data, bytes);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI n3_IoGetDeviceProperty(DEVICE_OBJECT *dev, uint32_t prop, uint32_t buflen, void *buf, uint32_t *reslen)
{
    ntdrv_pdo_t *p = ntdrv_pdo_from_device(dev);
    uint32_t v;
    uint16_t tmp[64];
    if (!p) return STATUS_INVALID_DEVICE_REQUEST;                /* only a PDO carries device properties */
    switch (prop & 0xff) {                                       /* the 0x1000/0x2000/0x4000 bits only type the property */
    case 0x0: return put_property(p->desc, (wlen16(p->desc) + 1) * 2, buflen, buf, reslen);           /* DeviceDescription */
    case 0x1: return put_property(p->hwids, p->hwids_len, buflen, buf, reslen);                      /* HardwareID */
    case 0x5: return put_property(p->cls, (wlen16(p->cls) + 1) * 2, buflen, buf, reslen);             /* ClassName */
    case 0x6: return put_property(p->classguid, (wlen16(p->classguid) + 1) * 2, buflen, buf, reslen); /* ClassGuid */
    case 0x7: return put_property(p->driverkey, (wlen16(p->driverkey) + 1) * 2, buflen, buf, reslen); /* DriverKeyName */
    case 0x8: return put_property(p->mfg, (wlen16(p->mfg) + 1) * 2, buflen, buf, reslen);             /* Manufacturer */
    case 0xb: {                                                                                       /* PhysicalDeviceObjectName */
        ntdrv_devnode_t *n;
        for (n = ntdrv_devnodes(); n; n = n->next)
            if (n->dev == p->pdo) { ntdrv_ascii_to_wide(n->name, tmp, 64); return put_property(tmp, (wlen16(tmp) + 1) * 2, buflen, buf, reslen); }
        return STATUS_OBJECT_NAME_NOT_FOUND;
    }
    case 0xd: v = PCIBus; return put_property(&v, 4, buflen, buf, reslen);                            /* LegacyBusType */
    case 0xe: v = p->dev.bus; return put_property(&v, 4, buflen, buf, reslen);                        /* BusNumber */
    case 0xf: { static const uint16_t pci[] = { 'P','C','I',0 }; return put_property(pci, 8, buflen, buf, reslen); } /* EnumeratorName */
    case 0x10: v = ((uint32_t)p->dev.dev << 16) | p->dev.fn; return put_property(&v, 4, buflen, buf, reslen); /* Address */
    case 0x11: v = p->dev.dev; return put_property(&v, 4, buflen, buf, reslen);                       /* UINumber */
    default: return STATUS_NOT_SUPPORTED;
    }
}

NTSTATUS NTAPI n3_IoOpenDeviceRegistryKey(DEVICE_OBJECT *dev, uint32_t type, uint32_t access, uint64_t *handle)
{
    static const char ctl[] = "Machine\\System\\CurrentControlSet\\Control\\Class\\", en[] = "Machine\\System\\CurrentControlSet\\Enum\\",
                      params[] = "\\Device Parameters";
    ntdrv_pdo_t *p = ntdrv_pdo_from_device(dev);
    uint16_t path[320];
    unsigned n = 0, i;
    regkey_t *node;
    int32_t st;
    (void)access;
    if (!p) return STATUS_INVALID_DEVICE_REQUEST;
    if (type & 2) {                                                 /* PLUGPLAY_REGKEY_DRIVER: the software (class) key */
        if (!p->driverkey[0]) return STATUS_OBJECT_NAME_NOT_FOUND;
        for (i = 0; ctl[i]; ++i) path[n++] = (uint16_t)ctl[i];
        for (i = 0; p->driverkey[i] && n < 300; ++i) path[n++] = p->driverkey[i];
    } else if (type & 1) {                                          /* PLUGPLAY_REGKEY_DEVICE: Enum\...\Device Parameters */
        for (i = 0; en[i]; ++i) path[n++] = (uint16_t)en[i];
        for (i = 0; p->instance[i] && n < 280; ++i) path[n++] = (uint16_t)p->instance[i];
        for (i = 0; params[i]; ++i) path[n++] = (uint16_t)params[i];
    } else return STATUS_INVALID_PARAMETER;
    reg_lock();
    st = reg_resolve(reg_root(), path, n, (type & 1) ? 1 : 0, 0, 1, 0, 0, &node, 0);
    if (st) { reg_unlock(); return st; }
    ++node->refs;
    reg_unlock();
    *handle = ntdrv_kh_alloc(KH_KEY, node);
    if (!*handle) { reg_key_release(node); return STATUS_INSUFFICIENT_RESOURCES; }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- device interfaces */
static void put_hex(uint16_t *out, unsigned *n, uint64_t v, unsigned digits)
{
    static const char hx[] = "0123456789ABCDEF";
    while (digits--) out[(*n)++] = (uint16_t)hx[(v >> (4 * digits)) & 15];
}
static void guid_to_wide(const GUID *g, uint16_t *out, unsigned *n)
{
    unsigned i;
    out[(*n)++] = '{';
    put_hex(out, n, g->Data1, 8); out[(*n)++] = '-';
    put_hex(out, n, g->Data2, 4); out[(*n)++] = '-';
    put_hex(out, n, g->Data3, 4); out[(*n)++] = '-';
    put_hex(out, n, g->Data4[0], 2); put_hex(out, n, g->Data4[1], 2); out[(*n)++] = '-';
    for (i = 2; i < 8; ++i) put_hex(out, n, g->Data4[i], 2);
    out[(*n)++] = '}';
}

/* The symbolic link name Windows forms: \??\<instance path with '\' -> '#'>#{InterfaceClassGuid}[\<RefString>]. It is
 * recorded on the PDO and handed back; the name is not published in the object namespace (no consumer here). */
NTSTATUS NTAPI n3_IoRegisterDeviceInterface(DEVICE_OBJECT *dev, const GUID *guid, UNICODE_STRING *ref, UNICODE_STRING *link)
{
    ntdrv_pdo_t *p = ntdrv_pdo_from_device(dev);
    uint16_t *buf;
    unsigned n = 0, i;
    if (!p || !guid || !link) return STATUS_INVALID_DEVICE_REQUEST;
    if (p->niface >= 4) return STATUS_INSUFFICIENT_RESOURCES;
    buf = kzalloc(sizeof p->iface[0]);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    buf[n++] = '\\'; buf[n++] = '?'; buf[n++] = '?'; buf[n++] = '\\';
    for (i = 0; p->instance[i] && n < 100; ++i) buf[n++] = (uint16_t)(p->instance[i] == '\\' ? '#' : p->instance[i]);
    buf[n++] = '#';
    guid_to_wide(guid, buf, &n);
    if (ref && ref->Length && n + ref->Length / 2 + 1 < 158) { buf[n++] = '\\'; memcpy(buf + n, ref->Buffer, ref->Length); n += ref->Length / 2; }
    buf[n] = 0;
    memcpy(p->iface[p->niface], buf, (n + 1) * 2);
    memcpy(p->iface_guid[p->niface], guid, 16);
    p->iface_enabled[p->niface++] = 0;
    link->Buffer = buf;
    link->Length = (uint16_t)(n * 2);
    link->MaximumLength = (uint16_t)(n * 2 + 2);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI n3_IoSetDeviceInterfaceState(UNICODE_STRING *link, uint8_t enable)
{
    ntdrv_pdo_t *p;
    char a[160];
    unsigned k;
    if (!link || !link->Buffer) return STATUS_INVALID_PARAMETER;
    for (p = pdos; p; p = p->next)
        for (k = 0; k < p->niface; ++k)
            if (wlen16(p->iface[k]) * 2 == link->Length && !memcmp(p->iface[k], link->Buffer, link->Length)) {
                p->iface_enabled[k] = enable;
                ntdrv_wide_to_ascii(link->Buffer, link->Length / 2, a, sizeof a);
                kprintf("K64 ntdrv: device interface %s %s\n", a, enable ? "enabled" : "disabled");
                return STATUS_SUCCESS;
            }
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* ---------------------------------------------------------------- generic exports live in ntdrv_dev.c
 * IoAllocate/GetDriverObjectExtension, shutdown notifications, PoCallDriver/PoStartNextPowerIrp, IoGetDmaAdapter and
 * HalTranslateBusAddress are implemented once in ntdrv_dev.c (which also serves legacy root-enumerated devices). The four
 * exports that depend on which kind of PDO they are given (properties, device registry key, device interfaces) are exported
 * from there too and call the n3_* versions in this file for the PDOs of PCI functions bound through the registry. */
extern void *NTAPI IoGetDmaAdapter(DEVICE_OBJECT *pdo, const uint8_t *desc, uint32_t *nmap);

static void *NTAPI if_get_dma_adapter(void *ctx, void *desc, uint32_t *nmap) { return IoGetDmaAdapter(((ntdrv_pdo_t *)ctx)->pdo, desc, nmap); }   /* ntdrv_dev.c */

/* Atomic UP snapshot of actually registered PDOs and interfaces. Neither PCI
 * functions without a registered devnode nor imaginary USB devices are added.
 * IRQ serialization prevents driver unload from freeing a visited PDO. The
 * published niface follows all link/GUID writes; no internal pointer escapes.
 */
static void catalog_row(ntdrv_pdo_t *node, shz_pnp_row_t *row, unsigned interface)
{
    unsigned i;
    memset(row,0,sizeof *row);
    row->kind=interface<node->niface?SHZ_PNP_INTERFACE:SHZ_PNP_NODE;
    row->node_id=node->index+1;row->started=node->started!=0;
    for(i=0;node->instance[i]&&i+1<128;++i)row->instance[i]=(uint8_t)node->instance[i];
    memcpy(row->class_guid,node->classguid,sizeof row->class_guid);
    memcpy(row->driver_key,node->driverkey,sizeof row->driver_key);
    memcpy(row->description,node->desc,sizeof row->description);
    memcpy(row->manufacturer,node->mfg,sizeof row->manufacturer);
    if(node->fdo_driver)for(i=0;node->fdo_driver->name[i]&&i+1<sizeof row->service;++i)row->service[i]=node->fdo_driver->name[i];
    if(interface<node->niface){row->enabled=node->iface_enabled[interface]!=0;memcpy(row->interface_guid,node->iface_guid[interface],16);memcpy(row->link,node->iface[interface],sizeof row->link);}
}
int32_t shz_query_pnp_catalog(process_t *process,uint64_t output,uint64_t length,uint64_t return_length)
{
    ntdrv_pdo_t *node;uint64_t flags=irq_save();uint32_t count=0,required,index=0;int32_t status=STATUS_SUCCESS;
    shz_pnp_catalog_t header={SHZ_PNP_CATALOG_VERSION,sizeof(shz_pnp_row_t),0,0};shz_pnp_row_t row;
    for(node=pdos;node;node=node->next){if(node->niface>4 || count>1024-1-node->niface){status=STATUS_INSUFFICIENT_RESOURCES;goto done;}count+=1+node->niface;}
    required=sizeof header+count*sizeof row;header.count=count;
    if(return_length&&copy_to_user(process,return_length,&required,sizeof required)){status=STATUS_ACCESS_VIOLATION;goto done;}
    if(length<required){status=STATUS_INFO_LENGTH_MISMATCH;goto done;}
    if(copy_to_user(process,output,&header,sizeof header)){status=STATUS_ACCESS_VIOLATION;goto done;}
    for(node=pdos;node;node=node->next){unsigned k;
        catalog_row(node,&row,4);if(copy_to_user(process,output+sizeof header+(uint64_t)index++*sizeof row,&row,sizeof row)){status=STATUS_ACCESS_VIOLATION;goto done;}
        for(k=0;k<node->niface;++k){catalog_row(node,&row,k);if(copy_to_user(process,output+sizeof header+(uint64_t)index++*sizeof row,&row,sizeof row)){status=STATUS_ACCESS_VIOLATION;goto done;}}
    }
done:irq_restore(flags);return status;
}

/* ================================================================ boot-time driver bring-up (drivers/common/shz_bringup.h)
 * Enumeration is the existing PCI scan; the installed driver catalog is the Enum\PCI devnode set this file already turns
 * into PDOs and publishes through shz_query_pnp_catalog. Init is done by the existing owners only: disk_init() (ahci/nvme/
 * sdhci cores), the gfx owners, and NtLoadDriver's kernel core for installed services (DriverEntry, devnode binding,
 * AddDevice, IRP_MN_START_DEVICE with the function's own BARs and line). Nothing here maps memory, connects an interrupt
 * or hands out DMA; a function a native driver claimed is never offered to a hosted service. The report copies what
 * the owners actually recorded (pci_claim, blk registration with a hardware locator, PDO start status). */
static shz_bringup_report_t bringup;
static int bringup_devices_done;
static int32_t bringup_laptop = 1;                     /* 1 = discovery not attempted through bring-up */
static uint32_t bringup_boot_flags, bringup_profile;     /* shz_bootinfo_t.flags; SHZ_BRINGUP_PROFILE_* */
static int bringup_quiesced, bringup_quiesce_result;

#ifdef SHZ_STANDALONE
static struct { char name[32]; int32_t status; int attempted; } bringup_svc[SHZ_BRINGUP_SERVICES];
static unsigned bringup_nsvc;

static void bu_copy(char *dst, unsigned cap, const char *src)
{
    unsigned i = 0;
    if (src) for (; src[i] && i + 1 < cap; ++i) dst[i] = src[i];
    dst[i] = 0;
}

/* (bus,dev,fn) -> devnode Service value, from one walk of Enum\PCI under the registry lock */
typedef struct { uint8_t bus, dev, fn, used; char service[32]; } bu_devnode_t;

static int bu_hex(uint16_t c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    return -1;
}
/* "B<2 hex>D<2 hex>F<hex...>", the instance names shzpnp add-driver --install writes (same rule as ntdrv_io.c) */
static int bu_instance(const uint16_t *w, unsigned n, unsigned *bus, unsigned *dev, unsigned *fn)
{
    int a, b, c, d, e;
    unsigned i, f = 0;
    if (n < 8 || n > 12 || w[0] != 'B' || w[3] != 'D' || w[6] != 'F') return 0;
    a = bu_hex(w[1]); b = bu_hex(w[2]); c = bu_hex(w[4]); d = bu_hex(w[5]);
    if (a < 0 || b < 0 || c < 0 || d < 0) return 0;
    for (i = 7; i < n; ++i) { e = bu_hex(w[i]); if (e < 0) return 0; f = f * 16 + (unsigned)e; }
    if (f > 7) return 0;
    *bus = (unsigned)(a * 16 + b); *dev = (unsigned)(c * 16 + d); *fn = f;
    return *dev < 32;
}
/* A service name that can only name a Services subkey: 1..31 of [A-Za-z0-9_.-], no path separators. */
static int bu_service_value(regval_t *v, char *out)
{
    const uint16_t *w;
    unsigned n, i;
    out[0] = 0;
    if (!v || (v->type != REG_SZ && v->type != REG_EXPAND_SZ)) return 0;
    w = (const uint16_t *)regval_data(v);
    n = v->data_len / 2;
    while (n && !w[n - 1]) --n;
    if (!n || n > 31) return 0;
    for (i = 0; i < n; ++i) {
        const uint16_t c = w[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'))
            return 0;
        out[i] = (char)c;
    }
    out[n] = 0;
    return 1;
}
static int bu_dword(regkey_t *k, const uint16_t *name, unsigned chars, uint32_t *out)
{
    regval_t *v = reg_find_value(k, name, chars);
    if (!v || v->type != REG_DWORD || v->data_len < 4) return 0;
    memcpy(out, regval_data(v), 4);
    return 1;
}
/* Installed kernel service eligible for a present devnode: Type = SERVICE_KERNEL_DRIVER (1), Start 0..3 (boot, system,
 * auto, demand: a PnP function driver is loaded when its device is enumerated), never Start = 4 (disabled). Called with
 * the registry lock held. */
static int bu_service_eligible(const char *svc)
{
    static const uint16_t prefix[] = u"Machine\\System\\CurrentControlSet\\Services\\";
    uint16_t path[sizeof prefix / 2 + 32];
    unsigned n = sizeof prefix / 2 - 1, i;
    regkey_t *k;
    uint32_t type = 0, start = 4;
    for (i = 0; i < n; ++i) path[i] = prefix[i];
    for (i = 0; svc[i]; ++i) path[n++] = (uint16_t)svc[i];
    if (reg_resolve(reg_root(), path, n, 0, 0, 1, 0, 0, &k, 0)) return 0;
    if (!bu_dword(k, u"Type", 4, &type) || !bu_dword(k, u"Start", 5, &start)) return 0;
    return type == 1 && start <= 3;
}
static unsigned bu_walk_devnodes(bu_devnode_t *out, unsigned cap)
{
    static const uint16_t path[] = u"Machine\\System\\CurrentControlSet\\Enum\\PCI";
    regkey_t *pci, *hw, *inst;
    uint32_t i, j;
    unsigned n = 0;
    reg_lock();
    if (reg_resolve(reg_root(), path, sizeof path / 2 - 1, 0, 0, 1, 0, 0, &pci, 0)) { reg_unlock(); return 0; }
    for (i = 0; (hw = reg_nth_child(pci, i)) != 0 && n < cap; ++i)
        for (j = 0; (inst = reg_nth_child(hw, j)) != 0 && n < cap; ++j) {
            unsigned bus, dev, fn;
            char svc[32];
            if (!bu_instance(regkey_name(inst), inst->name_len, &bus, &dev, &fn)) continue;   /* SHZnnnn: no function */
            if (!bu_service_value(reg_find_value(inst, u"Service", 7), svc)) continue;
            out[n].bus = (uint8_t)bus; out[n].dev = (uint8_t)dev; out[n].fn = (uint8_t)fn;
            out[n].used = (uint8_t)bu_service_eligible(svc);
            bu_copy(out[n].service, sizeof out[n].service, svc);
            ++n;
        }
    reg_unlock();
    return n;
}
static const bu_devnode_t *bu_devnode_for(const bu_devnode_t *nodes, unsigned n, const pci_dev_t *d)
{
    unsigned i;
    for (i = 0; i < n; ++i)
        if (nodes[i].bus == d->bus && nodes[i].dev == d->dev && nodes[i].fn == d->fn) return &nodes[i];
    return 0;
}

/* The native drivers Kernel64 links, matched exactly as each driver's own probe matches (see the files named). */
static uint16_t bu_native_match(const pci_dev_t *d)
{
    if (d->class_code == 0x01 && d->subclass == 0x06 && d->prog_if == 0x01) return SHZ_BRINGUP_DRV_AHCI;      /* ahci_blk.c */
    if (d->class_code == 0x01 && d->subclass == 0x08 && d->prog_if == 0x02) return SHZ_BRINGUP_DRV_NVME;      /* nvme.c */
    if (d->class_code == 0x08 && d->subclass == 0x05) return SHZ_BRINGUP_DRV_SDHCI;                           /* sdhci.c */
    if (d->vendor == 0x1234 && d->device == 0x1111 && d->class_code == 0x03) return SHZ_BRINGUP_DRV_GFX_BOCHS; /* gfx_fb.c */
    if (d->vendor == 0x1af4 && d->device == 0x1050) return SHZ_BRINGUP_DRV_GFX_VIRTIO;                       /* gfx_virtio.c */
    if (d->class_code == 0x03) return SHZ_BRINGUP_DRV_GFX_GOP;                                                /* gfx_gop.c */
    if (d->vendor == 0x10ec && d->device == 0x8139) return SHZ_BRINGUP_DRV_NET_RTL8139;                      /* net_rtl8139.c */
    if (d->class_code == 0x0c && d->subclass == 0x03 && d->prog_if == 0x30) return SHZ_BRINGUP_DRV_XHCI_UNLINKED;
    if (d->class_code == 0x06 || d->class_code == 0x05) return SHZ_BRINGUP_DRV_PLATFORM;
    return SHZ_BRINGUP_DRV_NONE;
}
static uint32_t bu_blk_published(const pci_dev_t *d, uint16_t drv)
{
    const blk_dev_t *b;
    uint32_t n = 0;
    for (b = blk_first(); b; b = b->next) {
        if (b->flags & BLK_F_PARTITION) continue;
        if (b->storage.version) {
            if (b->storage.bus == d->bus && b->storage.device == d->dev && b->storage.function == d->fn) ++n;
        } else if (drv == SHZ_BRINGUP_DRV_SDHCI && b->driver && !strcmp(b->driver, "sdhci")) ++n;   /* no locator published */
    }
    return n;
}

/* Load each installed service a present, unclaimed devnode names: NtLoadDriver's own core, under its load mutex. */
static void bu_load_services(const bu_devnode_t *nodes, unsigned nnodes, const pci_dev_t *all, unsigned nall)
{
    static const char prefix[] = "\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
    unsigned i, k;
    for (i = 0; i < nnodes; ++i) {
        int present = 0, dup = 0;
        for (k = 0; k < nall; ++k)
            if (all[k].bus == nodes[i].bus && all[k].dev == nodes[i].dev && all[k].fn == nodes[i].fn) {
                present = !pci_claimed_by(&all[k]);      /* a native (or already hosted) owner keeps its function */
                break;
            }
        if (!present || !nodes[i].used) continue;
        for (k = 0; k < bringup_nsvc; ++k)
            if (!strcmp(bringup_svc[k].name, nodes[i].service)) dup = 1;
        if (dup) continue;
        if (bringup_nsvc >= SHZ_BRINGUP_SERVICES) {
            kprintf("K64 bringup: more than %u installed services; %s not loaded\n", SHZ_BRINGUP_SERVICES, nodes[i].service);
            continue;
        }
        bu_copy(bringup_svc[bringup_nsvc].name, sizeof bringup_svc[0].name, nodes[i].service);
        ++bringup_nsvc;
    }
    for (i = 0; i < bringup_nsvc; ++i) {
        uint16_t w[sizeof prefix + 32];
        unsigned n = 0;
        if (bringup_svc[i].attempted) continue;
        bringup_svc[i].attempted = 1;
        if (ntdrv_find_driver(bringup_svc[i].name)) { bringup_svc[i].status = STATUS_SUCCESS; continue; }
        for (k = 0; prefix[k]; ++k) w[n++] = (uint16_t)prefix[k];
        for (k = 0; bringup_svc[i].name[k]; ++k) w[n++] = (uint16_t)bringup_svc[i].name[k];
        w[n] = 0;
        bringup_svc[i].status = ntdrv_load_service_path(w, n);
        if (bringup_svc[i].status == STATUS_IMAGE_ALREADY_LOADED) bringup_svc[i].status = STATUS_SUCCESS;
        kprintf("K64 bringup: installed service %s load = %x\n", bringup_svc[i].name, (uint32_t)bringup_svc[i].status);
    }
}
static const char *bu_state_name(uint16_t s)
{
    static const char *const n[] = { "unsupported", "running", "claimed", "not-started", "init-failed", "bound-no-start",
                                     "infrastructure", "linked-elsewhere" };
    return s < sizeof n / sizeof n[0] ? n[s] : "?";
}
#endif

static void bu_refresh(void)
{
    const struct shz_laptop_firmware *lf = k64_laptop_firmware_snapshot();
    memset(&bringup, 0, sizeof bringup);
    bringup.version = SHZ_BRINGUP_VERSION;
    bringup.row_size = sizeof(shz_bringup_row_t);
    bringup.laptop_firmware = lf ? 0 : bringup_laptop;
    bringup.laptop_has_ecdt = lf ? lf->has_ecdt != 0 : 0;
    ntdrv_catalog_report(&bringup);
    bringup.profile_flags = bringup_profile;
    bringup.install_generation = ntdrv_install_generation();
#ifdef SHZ_STANDALONE
    {
        static bu_devnode_t nodes[64];
        pci_dev_t all[SHZ_BRINGUP_ROWS];
        const unsigned nnodes = bu_walk_devnodes(nodes, 64), n = pci_enumerate(all, SHZ_BRINGUP_ROWS);
        unsigned i, k;
        uint64_t flags;
        bringup.profile_passthrough = 1;
        bringup.rows = n;
        for (k = 0; k < bringup_nsvc; ++k) {
            ++bringup.services_considered;
            if (bringup_svc[k].attempted && bringup_svc[k].status >= 0) ++bringup.services_loaded;
            else if (bringup_svc[k].attempted) ++bringup.services_failed;
        }
        flags = irq_save();                             /* PDOs: the unload path cannot free one while it is read */
        for (i = 0; i < n; ++i) {
            shz_bringup_row_t *r = &bringup.row[i];
            const pci_dev_t *d = &all[i];
            const char *owner = pci_claimed_by(d);
            const bu_devnode_t *node = bu_devnode_for(nodes, nnodes, d);
            const uint16_t native = bu_native_match(d);
            r->bus = d->bus; r->dev = d->dev; r->fn = d->fn; r->vendor = d->vendor; r->device = d->device;
            r->class_code = d->class_code; r->subclass = d->subclass; r->prog_if = d->prog_if; r->irq_line = d->irq_line;
            bu_copy(r->owner, sizeof r->owner, owner);
            if (node) bu_copy(r->service, sizeof r->service, node->service);
            if (owner && !memcmp(owner, "ntdrv:", 6)) {
                ntdrv_pdo_t *p;
                r->driver = SHZ_BRINGUP_DRV_HOSTED;
                r->state = SHZ_BRINGUP_CLAIMED;            /* claimed by MmMapIoSpace/IoConnectInterrupt, no devnode PDO */
                for (p = pdos; p; p = p->next)
                    if (p->dev.bus == d->bus && p->dev.dev == d->dev && p->dev.fn == d->fn && p->fdo_driver) {
                        r->init_status = p->start_status;
                        if (p->started) { r->state = SHZ_BRINGUP_RUNNING; r->published = 1; }
                        else if (p->no_add_device) r->state = SHZ_BRINGUP_BOUND_NO_START;
                        else if (p->attempted && p->start_status < 0) r->state = SHZ_BRINGUP_INIT_FAILED;
                        break;
                    }
            } else if (owner) {
                r->driver = native;
                r->published = bu_blk_published(d, native);
                r->init_status = (int32_t)r->published;
                r->state = r->published ? SHZ_BRINGUP_RUNNING : SHZ_BRINGUP_CLAIMED;
            } else {
                r->driver = node ? SHZ_BRINGUP_DRV_HOSTED : native;
                if (node) {
                    r->state = node->used ? SHZ_BRINGUP_NOT_STARTED : SHZ_BRINGUP_UNSUPPORTED;   /* disabled / not a kernel driver */
                    for (k = 0; k < bringup_nsvc; ++k)
                        if (!strcmp(bringup_svc[k].name, node->service) && bringup_svc[k].attempted) {
                            r->init_status = bringup_svc[k].status < 0 ? bringup_svc[k].status : STATUS_DEVICE_NOT_READY;
                            r->state = SHZ_BRINGUP_INIT_FAILED;   /* loaded or not, the function was not bound */
                        }
                } else if (native == SHZ_BRINGUP_DRV_PLATFORM) r->state = SHZ_BRINGUP_INFRASTRUCTURE;
                else if (native == SHZ_BRINGUP_DRV_XHCI_UNLINKED) r->state = SHZ_BRINGUP_LINKED_ELSEWHERE;
                else if (native != SHZ_BRINGUP_DRV_NONE) r->state = SHZ_BRINGUP_NOT_STARTED;
                else r->state = SHZ_BRINGUP_UNSUPPORTED;
            }
            switch (r->state) {
            case SHZ_BRINGUP_RUNNING: ++bringup.running; break;
            case SHZ_BRINGUP_CLAIMED: case SHZ_BRINGUP_BOUND_NO_START: ++bringup.claimed; break;
            case SHZ_BRINGUP_NOT_STARTED: ++bringup.not_started; break;
            case SHZ_BRINGUP_INIT_FAILED: ++bringup.failed; break;
            case SHZ_BRINGUP_INFRASTRUCTURE: ++bringup.infrastructure; break;
            case SHZ_BRINGUP_LINKED_ELSEWHERE: ++bringup.linked_elsewhere; break;
            default: ++bringup.unsupported; break;
            }
        }
        irq_restore(flags);
    }
#endif
}

/* C4 (routing02 contract): Kernel64 -> Supervisor driver bring-up report, once, only as a Supervisor guest. */
static void bu_send_report(void)
{
#if !defined(SHZ_STANDALONE) && defined(SHZ_DRVREP_MAGIC)
    static shz_drvrep_t rep __attribute__((aligned(64)));
    static int sent;
    hcreg_t value = (hcreg_t)-1;
    long st;
    if (sent || (bringup_boot_flags & SHZ_BIF_UEFI_DIRECT)) return;
    sent = 1;
    memset(&rep, 0, sizeof rep);
    rep.magic = SHZ_DRVREP_MAGIC; rep.version = 1; rep.size = sizeof rep;
    /* exactly one profile bit (the Supervisor refuses both): foundation wins over devices-elsewhere */
    rep.flags = (bringup.profile_flags & SHZ_BRINGUP_PROFILE_FOUNDATION) ? SHZ_DRVREP_FOUNDATION
              : (bringup.profile_flags & SHZ_BRINGUP_PROFILE_DEVICES_ELSEWHERE) ? SHZ_DRVREP_PASSTHROUGH : 0;
    rep.install_generation = bringup.install_generation;
    rep.rows = bringup.rows; rep.running = bringup.running; rep.claimed = bringup.claimed;
    rep.not_started = bringup.not_started; rep.failed = bringup.failed; rep.unsupported = bringup.unsupported;
    rep.infrastructure = bringup.infrastructure; rep.linked_elsewhere = bringup.linked_elsewhere;
    rep.services_considered = bringup.services_considered; rep.services_loaded = bringup.services_loaded;
    rep.services_failed = bringup.services_failed;
    rep.catalog_entries = bringup.catalog_entries; rep.catalog_matched = bringup.catalog_matched;
    rep.catalog_rejected = bringup.catalog_rejected;
    st = shz_hcall(SHZ_HC_DRIVER_REPORT, kimage_v2p((uint64_t)&rep), sizeof rep, &value);   /* .bss is in the image */
    if (st != SHZ_OK || (long)value != SHZ_OK)
        kprintf("DRIVER-REPORT: Supervisor refused the bring-up report: status=%d result=%d (not reported)\n", (int)st, (int)(long)value);
    else
        kprintf("DRIVER-REPORT: delivered to ShizukuCore (rows=%u failed=%u services_failed=%u generation=%llu)\n",
                rep.rows, rep.failed, rep.services_failed, (unsigned long long)rep.install_generation);
#elif !defined(SHZ_STANDALONE)
    kprintf("DRIVER-REPORT: SHZ_HC_DRIVER_REPORT not in this ABI header; ShizukuCore keeps the driver state ABSENT\n");
#endif
}

int shz_driver_bringup_init(const void *bootinfo, unsigned phase, unsigned flags)
{
    if (bootinfo) bringup_boot_flags = ((const shz_bootinfo_t *)bootinfo)->flags;
#ifndef SHZ_STANDALONE
    bringup_profile |= SHZ_BRINGUP_PROFILE_DEVICES_ELSEWHERE;   /* Supervisor guest image: no PCI function is passed through */
#endif
    if (phase == SHZ_BRINGUP_PHASE_EARLY) {
        /* Retained-firmware discovery only: copies FADT/ECDT descriptors; grants no EC/SCI/I2C register access. */
        if (flags & SHZ_BRINGUP_F_LAPTOP_FIRMWARE) {
            if (!bootinfo) return SHZ_INVALID;
            bringup_laptop = k64_laptop_firmware_init((const shz_bootinfo_t *)bootinfo);
            kprintf("K64 bringup: laptop firmware discovery = %d (register_access=0)\n", (int)bringup_laptop);
            return bringup_laptop;
        }
        return 0;
    }
    if (phase != SHZ_BRINGUP_PHASE_DEVICES) return SHZ_INVALID;
    if (bringup_devices_done) { bu_refresh(); return -(int)bringup.failed; }
    bringup_devices_done = 1;
    if (flags & SHZ_BRINGUP_F_FOUNDATION) bringup_profile |= SHZ_BRINGUP_PROFILE_FOUNDATION;
    else if (flags & SHZ_BRINGUP_F_LOAD_SERVICES) ntdrv_catalog_import();   /* registry devnodes before services load */
#ifdef SHZ_STANDALONE
    if ((flags & SHZ_BRINGUP_F_LOAD_SERVICES) && !(flags & SHZ_BRINGUP_F_FOUNDATION)) {
        static bu_devnode_t nodes[64];
        pci_dev_t all[SHZ_BRINGUP_ROWS];
        const unsigned nnodes = bu_walk_devnodes(nodes, 64), n = pci_enumerate(all, SHZ_BRINGUP_ROWS);
        bu_load_services(nodes, nnodes, all, n);
    }
#endif
    bu_refresh();
#ifdef SHZ_STANDALONE
    if (!(flags & SHZ_BRINGUP_F_QUIET)) {
        unsigned i;
        for (i = 0; i < bringup.rows; ++i) {
            const shz_bringup_row_t *r = &bringup.row[i];
            kprintf("K64 bringup: PCI %x:%x.%x %04x:%04x class %02x.%02x.%02x %s status=%x published=%u owner=%s service=%s\n",
                    r->bus, r->dev, r->fn, r->vendor, r->device, r->class_code, r->subclass, r->prog_if,
                    bu_state_name(r->state), (uint32_t)r->init_status, r->published, r->owner[0] ? r->owner : "-",
                    r->service[0] ? r->service : "-");
        }
    }
#endif
    kprintf("DRIVER-BRINGUP: passthrough=%u functions=%u running=%u claimed=%u not_started=%u failed=%u unsupported=%u "
            "infrastructure=%u linked_elsewhere=%u services=%u loaded=%u load_failed=%u laptop_firmware=%d ecdt=%u ec_io=0\n",
            bringup.profile_passthrough, bringup.rows, bringup.running, bringup.claimed, bringup.not_started, bringup.failed,
            bringup.unsupported, bringup.infrastructure, bringup.linked_elsewhere, bringup.services_considered,
            bringup.services_loaded, bringup.services_failed, (int)bringup.laptop_firmware, bringup.laptop_has_ecdt);
    kprintf("DRIVER-BRINGUP: profile=%x catalog=%d entries=%u matched=%u rejected=%u devnodes=%u generation=%llu\n",
            bringup.profile_flags, (int)bringup.catalog_status, bringup.catalog_entries, bringup.catalog_matched,
            bringup.catalog_rejected, bringup.catalog_registered, (unsigned long long)bringup.install_generation);
    bu_send_report();
    return -(int)bringup.failed;
}

const shz_bringup_report_t *shz_driver_bringup_report(void)
{
    bu_refresh();
    return &bringup;
}

int shz_driver_bringup_quiesce(void)
{
    blk_dev_t *b;
    int failed = 0;
    if (bringup_quiesced) return bringup_quiesce_result;
    bringup_quiesced = 1;
    ntdrv_send_shutdown();                              /* hosted drivers first: they may sit above a native volume */
    for (b = blk_first(); b; b = b->next)
        if (!(b->flags & BLK_F_PARTITION) && blk_flush(b)) {
            kprintf("K64 bringup: flush of %s failed during quiesce\n", b->name);
            ++failed;
        }
    kprintf("K64 bringup: quiesce done, %d flush failure(s)\n", failed);
    bringup_quiesce_result = failed;
    return failed;
}
