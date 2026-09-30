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

typedef struct { uint32_t Data1; uint16_t Data2, Data3; uint8_t Data4[8]; } GUID;
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
    int32_t start_status;
    unsigned index;
    char instance[128];                 /* PCI\VEN_8086&DEV_100E\B00D03F0 */
    uint16_t driverkey[80];             /* Enum "Driver": {ClassGUID}\0000 */
    uint16_t desc[128], mfg[128], cls[64], classguid[40];
    uint16_t hwids[512];                /* REG_MULTI_SZ */
    uint32_t hwids_len;                 /* bytes */
    uint16_t iface[160];                /* the device interface link registered on it (IoRegisterDeviceInterface) */
    int iface_enabled;
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
            p->fdo_driver = d; p->attempted = 0; p->started = 0;
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
            kprintf("K64 ntdrv: %s has no AddDevice (non-PnP driver): PCI %x:%x.%x is bound, no start IRP\n",
                    d->name, p->dev.bus, p->dev.dev, p->dev.fn);
            continue;
        }
        pci_enable(&p->dev, 1, 1, 1);                             /* what pci.sys does when it starts the function */
        ntdrv_set_current_driver(d);
        st = add(d->drv, p->pdo);
        kprintf("K64 ntdrv: %s AddDevice(PCI %x:%x.%x) = %x\n", d->name, p->dev.bus, p->dev.dev, p->dev.fn, (uint32_t)st);
        if (!NT_SUCCESS(st)) { ntdrv_set_current_driver(0); continue; }
        top = IoGetAttachedDevice(p->pdo);
        if (top == p->pdo) { kprintf("K64 ntdrv: %s AddDevice attached no FDO\n", d->name); ntdrv_set_current_driver(0); continue; }
        raw = build_resource_list(&p->dev, 0);
        xlat = build_resource_list(&p->dev, 1);
        irp = raw && xlat ? IoAllocateIrp((uint8_t)top->StackSize, 0) : 0;
        if (!irp) { kfree(raw); kfree(xlat); ntdrv_set_current_driver(0); continue; }
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
    uint32_t i;
    if (!p || type != 0 || off >= 256) return 0;
    if (off + len > 256) len = 256 - off;
    for (i = 0; i < len; ++i) {
        const unsigned reg = (off + i) & ~3u, sh = 8 * ((off + i) & 3);
        uint32_t dw = pci_cfg_read32(&p->dev, reg);
        dw = (dw & ~(0xffu << sh)) | ((uint32_t)in[i] << sh);
        pci_cfg_write32(&p->dev, reg, dw);
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

NTSTATUS NTAPI IoGetDeviceProperty(DEVICE_OBJECT *dev, uint32_t prop, uint32_t buflen, void *buf, uint32_t *reslen)
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

NTSTATUS NTAPI IoOpenDeviceRegistryKey(DEVICE_OBJECT *dev, uint32_t type, uint32_t access, uint64_t *handle)
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
NTSTATUS NTAPI IoRegisterDeviceInterface(DEVICE_OBJECT *dev, const GUID *guid, UNICODE_STRING *ref, UNICODE_STRING *link)
{
    ntdrv_pdo_t *p = ntdrv_pdo_from_device(dev);
    uint16_t *buf;
    unsigned n = 0, i;
    if (!p || !guid || !link) return STATUS_INVALID_DEVICE_REQUEST;
    buf = kzalloc(sizeof p->iface);
    if (!buf) return STATUS_INSUFFICIENT_RESOURCES;
    buf[n++] = '\\'; buf[n++] = '?'; buf[n++] = '?'; buf[n++] = '\\';
    for (i = 0; p->instance[i] && n < 100; ++i) buf[n++] = (uint16_t)(p->instance[i] == '\\' ? '#' : p->instance[i]);
    buf[n++] = '#';
    guid_to_wide(guid, buf, &n);
    if (ref && ref->Length && n + ref->Length / 2 + 1 < 158) { buf[n++] = '\\'; memcpy(buf + n, ref->Buffer, ref->Length); n += ref->Length / 2; }
    buf[n] = 0;
    memcpy(p->iface, buf, (n + 1) * 2);
    link->Buffer = buf;
    link->Length = (uint16_t)(n * 2);
    link->MaximumLength = (uint16_t)(n * 2 + 2);
    return STATUS_SUCCESS;
}

NTSTATUS NTAPI IoSetDeviceInterfaceState(UNICODE_STRING *link, uint8_t enable)
{
    ntdrv_pdo_t *p;
    char a[160];
    if (!link || !link->Buffer) return STATUS_INVALID_PARAMETER;
    for (p = pdos; p; p = p->next)
        if (wlen16(p->iface) * 2 == link->Length && !memcmp(p->iface, link->Buffer, link->Length)) {
            p->iface_enabled = enable;
            ntdrv_wide_to_ascii(link->Buffer, link->Length / 2, a, sizeof a);
            kprintf("K64 ntdrv: device interface %s %s\n", a, enable ? "enabled" : "disabled");
            return STATUS_SUCCESS;
        }
    return STATUS_OBJECT_NAME_NOT_FOUND;
}

/* ---------------------------------------------------------------- driver object extensions */
typedef struct drvext { struct drvext *next; DRIVER_OBJECT *drv; void *id; void *mem; } drvext_t;
static drvext_t *drvexts;

NTSTATUS NTAPI IoAllocateDriverObjectExtension(DRIVER_OBJECT *drv, void *id, uint32_t size, void **out)
{
    drvext_t *e;
    for (e = drvexts; e; e = e->next)
        if (e->drv == drv && e->id == id) return STATUS_OBJECT_NAME_COLLISION;
    e = kzalloc(sizeof *e);
    if (!e) return STATUS_INSUFFICIENT_RESOURCES;
    e->mem = kzalloc(size ? size : 1);
    if (!e->mem) { kfree(e); return STATUS_INSUFFICIENT_RESOURCES; }
    e->drv = drv; e->id = id;
    e->next = drvexts; drvexts = e;
    *out = e->mem;
    return STATUS_SUCCESS;
}
void *NTAPI IoGetDriverObjectExtension(DRIVER_OBJECT *drv, void *id)
{
    drvext_t *e;
    for (e = drvexts; e; e = e->next) if (e->drv == drv && e->id == id) return e->mem;
    return 0;
}

/* ---------------------------------------------------------------- shutdown notifications, power */
static DEVICE_OBJECT *shutdown_devs[32];
NTSTATUS NTAPI IoRegisterShutdownNotification(DEVICE_OBJECT *dev)
{
    unsigned i;
    for (i = 0; i < 32; ++i) if (!shutdown_devs[i]) { shutdown_devs[i] = dev; return STATUS_SUCCESS; }
    return STATUS_INSUFFICIENT_RESOURCES;
}
void NTAPI IoUnregisterShutdownNotification(DEVICE_OBJECT *dev)
{
    unsigned i;
    for (i = 0; i < 32; ++i) if (shutdown_devs[i] == dev) shutdown_devs[i] = 0;
}
NTSTATUS NTAPI PoCallDriver(DEVICE_OBJECT *dev, IRP *irp) { return IofCallDriver(dev, irp); }
void NTAPI PoStartNextPowerIrp(IRP *irp) { (void)irp; }        /* power IRPs are not serialized here */

/* ---------------------------------------------------------------- DMA adapter */
/* Physical address of a kernel VA. RAM is mapped with 2 MiB pages at DIRECT_MAP and the kernel image alias likewise
 * (mem.c map_2m), which the page walker vm_lookup() does not understand, so those two ranges are translated by
 * arithmetic exactly as ntdrv_mm.c's MmGetPhysicalAddress does; vm_lookup() serves the 4 KiB-mapped ranges (the driver
 * image window, kernel windows, user pages). 0 = not mapped. */
static uint64_t va_phys(uint64_t va)
{
    uint64_t pa;
    if (va >= DIRECT_MAP && va < DIRECT_MAP + (256ull << 30)) return v2p_direct(va);
    if (va >= K64_VIRT_BASE) return kimage_v2p(va);
    pa = vm_lookup(kernel_pml4(), va, 0);
    return pa;
}

/* common buffers: page-aligned, physically contiguous kernel heap memory; the original pointer is kept for the free */
static struct { void *raw, *aligned; } common[64];
static void *NTAPI dma_alloc_common(void *ad, uint32_t len, int64_t *pa, uint8_t cached)
{
    void *raw, *al;
    unsigned i;
    (void)ad; (void)cached;
    raw = kzalloc((uint64_t)len + 4096);
    if (!raw) return 0;
    al = (void *)(((uint64_t)raw + 4095) & ~4095ull);
    for (i = 0; i < 64; ++i) if (!common[i].raw) { common[i].raw = raw; common[i].aligned = al; break; }
    if (i == 64) { kfree(raw); return 0; }
    if (pa) *pa = (int64_t)va_phys((uint64_t)al);
    return al;
}
static void NTAPI dma_free_common(void *ad, uint32_t len, int64_t pa, void *va, uint8_t cached)
{
    unsigned i;
    (void)ad; (void)len; (void)pa; (void)cached;
    for (i = 0; i < 64; ++i) if (common[i].aligned == va) { kfree(common[i].raw); common[i].raw = common[i].aligned = 0; return; }
}
static void NTAPI dma_put(void *ad) { kfree(ad); }
static uint32_t NTAPI dma_alignment(void *ad) { (void)ad; return 1; }
static uint32_t NTAPI dma_read_counter(void *ad) { (void)ad; return 0; }
static int32_t NTAPI dma_alloc_channel(void *ad, DEVICE_OBJECT *dev, uint32_t nmap, void *routine, void *ctx)
{
    uint32_t (NTAPI *fn)(DEVICE_OBJECT *, IRP *, void *, void *) = routine;   /* PDRIVER_CONTROL */
    (void)ad; (void)nmap;
    fn(dev, dev->CurrentIrp, (void *)1, ctx);                              /* map registers are not real on this platform */
    return STATUS_SUCCESS;
}
static uint8_t NTAPI dma_flush(void *ad, MDL *m, void *base, void *cur, uint32_t len, uint8_t write)
{ (void)ad; (void)m; (void)base; (void)cur; (void)len; (void)write; return 1; }
static void NTAPI dma_free_channel(void *ad) { (void)ad; }
static void NTAPI dma_free_mapregs(void *ad, void *base, uint32_t n) { (void)ad; (void)base; (void)n; }

/* the physically contiguous run starting at `va`, at most `len` bytes */
static uint64_t contiguous_run(uint64_t va, uint32_t len, uint64_t *pa_out)
{
    uint64_t pa = va_phys(va), run, next;
    if (!pa) return 0;
    run = 4096 - (va & 0xfff);
    while (run < len) {
        next = va_phys(va + run);
        if (next != pa + run) break;
        run += 4096;
    }
    if (run > len) run = len;
    *pa_out = pa;
    return run;
}
static int64_t NTAPI dma_map_transfer(void *ad, MDL *m, void *base, void *cur, uint32_t *len, uint8_t write)
{
    uint64_t pa = 0, run = contiguous_run((uint64_t)cur, *len, &pa);
    (void)ad; (void)m; (void)base; (void)write;
    *len = (uint32_t)run;
    return (int64_t)pa;
}
static unsigned sg_count(uint64_t va, uint32_t len)
{
    unsigned n = 0;
    while (len) { uint64_t pa, run = contiguous_run(va, len, &pa); if (!run) break; va += run; len -= (uint32_t)run; ++n; }
    return n;
}
static void sg_fill(SCATTER_GATHER_LIST *l, uint64_t va, uint32_t len)
{
    l->NumberOfElements = 0;
    l->Reserved = 0;
    while (len) {
        uint64_t pa, run = contiguous_run(va, len, &pa);
        if (!run) break;
        l->Elements[l->NumberOfElements].Address = (int64_t)pa;
        l->Elements[l->NumberOfElements].Length = (uint32_t)run;
        l->Elements[l->NumberOfElements].Reserved = 0;
        ++l->NumberOfElements;
        va += run; len -= (uint32_t)run;
    }
}
static int32_t NTAPI dma_calc_sg(void *ad, MDL *m, void *cur, uint32_t len, uint32_t *size, uint32_t *nmap)
{
    unsigned n = sg_count((uint64_t)cur, len);
    (void)ad; (void)m;
    *size = (uint32_t)(offsetof(SCATTER_GATHER_LIST, Elements) + n * sizeof(SCATTER_GATHER_ELEMENT));
    if (nmap) *nmap = (uint32_t)(((uint64_t)cur & 0xfff) + len + 4095) / 4096;
    return STATUS_SUCCESS;
}
static int32_t NTAPI dma_build_sg(void *ad, DEVICE_OBJECT *dev, MDL *m, void *cur, uint32_t len, void *routine, void *ctx,
                                 uint8_t write, void *buf, uint32_t buflen)
{
    void (NTAPI *fn)(DEVICE_OBJECT *, IRP *, SCATTER_GATHER_LIST *, void *) = routine;   /* PDRIVER_LIST_CONTROL */
    uint32_t need, nmap;
    (void)m; (void)write;
    dma_calc_sg(ad, m, cur, len, &need, &nmap);
    if (buflen < need) return STATUS_BUFFER_TOO_SMALL;
    sg_fill(buf, (uint64_t)cur, len);
    fn(dev, dev->CurrentIrp, buf, ctx);
    return STATUS_SUCCESS;
}
static int32_t NTAPI dma_get_sg(void *ad, DEVICE_OBJECT *dev, MDL *m, void *cur, uint32_t len, void *routine, void *ctx, uint8_t write)
{
    uint32_t need, nmap;
    SCATTER_GATHER_LIST *l;
    dma_calc_sg(ad, m, cur, len, &need, &nmap);
    l = kzalloc(need);
    if (!l) return STATUS_INSUFFICIENT_RESOURCES;
    return dma_build_sg(ad, dev, m, cur, len, routine, ctx, write, l, need);
}
static void NTAPI dma_put_sg(void *ad, void *l, uint8_t write) { (void)ad; (void)write; kfree(l); }
static int32_t NTAPI dma_build_mdl(void *ad, void *l, MDL *orig, MDL **out) { (void)ad; (void)l; (void)orig; (void)out; return STATUS_NOT_SUPPORTED; }

static DMA_OPERATIONS dma_ops = {
    sizeof(DMA_OPERATIONS), 0,
    (void *)dma_put, (void *)dma_alloc_common, (void *)dma_free_common, (void *)dma_alloc_channel, (void *)dma_flush,
    (void *)dma_free_channel, (void *)dma_free_mapregs, (void *)dma_map_transfer, (void *)dma_alignment, (void *)dma_read_counter,
    (void *)dma_get_sg, (void *)dma_put_sg, (void *)dma_calc_sg, (void *)dma_build_sg, (void *)dma_build_mdl
};

void *NTAPI IoGetDmaAdapter(DEVICE_OBJECT *pdo, void *desc, uint32_t *nmap)
{
    DMA_ADAPTER *a = kzalloc(sizeof *a);
    (void)pdo; (void)desc;
    if (!a) return 0;
    a->Version = 1; a->Size = sizeof *a; a->DmaOperations = &dma_ops;
    if (nmap) *nmap = 64;                                        /* map registers are not real on this platform */
    return a;
}
static void *NTAPI if_get_dma_adapter(void *ctx, void *desc, uint32_t *nmap) { return IoGetDmaAdapter(((ntdrv_pdo_t *)ctx)->pdo, desc, nmap); }

uint8_t NTAPI HalTranslateBusAddress(uint32_t type, uint32_t bus, int64_t addr, uint32_t *space, int64_t *out)
{
    (void)type; (void)bus; (void)space;                          /* PCI addresses are system addresses on this platform */
    *out = addr;
    return 1;
}
