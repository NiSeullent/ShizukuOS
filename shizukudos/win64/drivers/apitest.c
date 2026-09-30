/* SPDX-License-Identifier: GPL-2.0-only
 * ShzApi: an unmodified WDM driver that exercises the second batch of ntoskrnl.exe/hal.dll
 * exports the Kernel64 driver host provides (registry query tables, driver-object extensions,
 * device interfaces + PnP notification, IRP forwarding through an attached stack, sequenced
 * lists, lookaside lists, executive resources, bitmaps, the CRT, cancellation, StartIo queues,
 * remove locks, the error log, power state and power IRPs, root-enumerated PDOs and their
 * properties, DMA adapters, partition tables read through IRP_MJ_READ, page MDLs, callback
 * objects, timers). Every check prints "apitest: PASS <name>" or "apitest: FAIL <name>" through
 * DbgPrint and DriverEntry fails (STATUS_UNSUCCESSFUL) when any check failed, so the host's
 * runner sees a real load failure, never a green line for a broken export. Built exactly like a
 * real Windows driver, against Microsoft's DDK headers.
 */
#include <ddk/ntddk.h>
#include <ntdddisk.h>

NTHALAPI ULONG NTAPI HalGetBusData(BUS_DATA_TYPE, ULONG, ULONG, PVOID, ULONG);

/* NTSTATUS values the mingw DDK headers may not carry (the numeric values are Windows'). */
#ifndef STATUS_REVISION_MISMATCH
#define STATUS_REVISION_MISMATCH ((NTSTATUS)0xC0000059L)
#endif
#ifndef STATUS_DELETE_PENDING
#define STATUS_DELETE_PENDING ((NTSTATUS)0xC0000056L)
#endif
#ifndef STATUS_OBJECT_NAME_COLLISION
#define STATUS_OBJECT_NAME_COLLISION ((NTSTATUS)0xC0000035L)
#endif
#ifndef STATUS_NO_MORE_ENTRIES
#define STATUS_NO_MORE_ENTRIES ((NTSTATUS)0x8000001AL)
#endif
#ifndef STATUS_DEVICE_NOT_READY
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xC00000A3L)
#endif
#ifndef STATUS_CANCELLED
#define STATUS_CANCELLED ((NTSTATUS)0xC0000120L)
#endif
#ifndef STATUS_BUFFER_TOO_SMALL
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023L)
#endif
#ifndef STATUS_OBJECT_NAME_NOT_FOUND
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#endif
#ifndef STATUS_NOT_SUPPORTED
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BBL)
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000DL)
#endif

/* Exports mingw's DDK headers do not prototype (or hide behind the wrong guard): declared as Windows does. */
NTKERNELAPI PDEVICE_OBJECT NTAPI IoGetLowerDeviceObject(PDEVICE_OBJECT DeviceObject);
NTSYSAPI USHORT NTAPI RtlCaptureStackBackTrace(ULONG FramesToSkip, ULONG FramesToCapture, PVOID *BackTrace, PULONG BackTraceHash);
int __cdecl swprintf(wchar_t *buf, const wchar_t *fmt, ...);
int __cdecl _snwprintf(wchar_t *buf, size_t count, const wchar_t *fmt, ...);
int __cdecl _snprintf(char *buf, size_t count, const char *fmt, ...);

#define IOCTL_SHZ_APIINFO CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SHZ_LOWER   CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)

static LONG g_pass, g_fail;
#define CHECK(cond, name) do { if (cond) { g_pass++; DbgPrint("apitest: PASS %s\n", name); } else { g_fail++; DbgPrint("apitest: FAIL %s\n", name); } } while (0)

typedef struct {
    PDEVICE_OBJECT lower, top, self;
    LONG startio_count, cancel_count, lower_ioctls, power_cb, pnp_cb, cb_notify, timer_ticks, reinit;
    KEVENT power_done;
    UNICODE_STRING iface;
    IO_REMOVE_LOCK rlock;
    LONG sysctl_reginfo;
} API_EXT;
static API_EXT *g_ext;

/* ---- dispatch of the test device (and of the lower device, which shares the driver) ---- */
static NTSTATUS ApiCreateClose(PDEVICE_OBJECT dev, PIRP irp)
{
    (void)dev;
    irp->IoStatus.Status = STATUS_SUCCESS; irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
static NTSTATUS ApiControl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS st = STATUS_INVALID_DEVICE_REQUEST;
    ULONG_PTR info = 0;
    if (dev == g_ext->lower) {                                   /* the bottom of the attached stack answers */
        if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_SHZ_LOWER && sp->Parameters.DeviceIoControl.OutputBufferLength >= 4) {
            InterlockedIncrement(&g_ext->lower_ioctls);
            *(ULONG *)irp->AssociatedIrp.SystemBuffer = 0x10BE1;
            info = 4; st = STATUS_SUCCESS;
        }
    } else if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_SHZ_LOWER) {
        /* top of the stack: forward synchronously and report what came back */
        BOOLEAN fwd = IoForwardIrpSynchronously(g_ext->lower, irp);
        if (fwd) { st = irp->IoStatus.Status; info = irp->IoStatus.Information; }
    } else if (sp->Parameters.DeviceIoControl.IoControlCode == IOCTL_SHZ_APIINFO && sp->Parameters.DeviceIoControl.OutputBufferLength >= 8) {
        ((ULONG *)irp->AssociatedIrp.SystemBuffer)[0] = (ULONG)g_pass;
        ((ULONG *)irp->AssociatedIrp.SystemBuffer)[1] = (ULONG)g_fail;
        info = 8; st = STATUS_SUCCESS;
    }
    irp->IoStatus.Status = st; irp->IoStatus.Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}
/* IRP_MJ_READ: a synthetic 512-byte MBR with two partitions (NTFS at LBA 2048, FAT32 at LBA 4096). */
static NTSTATUS ApiRead(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    UCHAR *buf = irp->AssociatedIrp.SystemBuffer;
    ULONG len = sp->Parameters.Read.Length, i;
    (void)dev;
    if (!buf || len < 512 || sp->Parameters.Read.ByteOffset.QuadPart != 0) {
        irp->IoStatus.Status = STATUS_INVALID_PARAMETER; irp->IoStatus.Information = 0;
        IoCompleteRequest(irp, IO_NO_INCREMENT);
        return STATUS_INVALID_PARAMETER;
    }
    for (i = 0; i < len; ++i) buf[i] = 0;
    *(ULONG *)(buf + 0x1b8) = 0x5A5A1234;                        /* disk signature */
    buf[0x1be] = 0x80; buf[0x1be + 4] = 0x07; *(ULONG *)(buf + 0x1be + 8) = 2048; *(ULONG *)(buf + 0x1be + 12) = 2048;
    buf[0x1ce + 4] = 0x0c; *(ULONG *)(buf + 0x1ce + 8) = 4096; *(ULONG *)(buf + 0x1ce + 12) = 8192;
    buf[510] = 0x55; buf[511] = 0xaa;
    irp->IoStatus.Status = STATUS_SUCCESS; irp->IoStatus.Information = 512;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
static NTSTATUS ApiPower(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    (void)dev;
    if (sp->MinorFunction == IRP_MN_SET_POWER && sp->Parameters.Power.Type == DevicePowerState)
        PoSetPowerState(dev, DevicePowerState, sp->Parameters.Power.State);
    PoStartNextPowerIrp(irp);
    irp->IoStatus.Status = STATUS_SUCCESS;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}
static NTSTATUS ApiSystemControl(PDEVICE_OBJECT dev, PIRP irp)
{
    PIO_STACK_LOCATION sp = IoGetCurrentIrpStackLocation(irp);
    NTSTATUS st = STATUS_NOT_SUPPORTED;
    (void)dev;
    if (sp->MinorFunction == IRP_MN_REGINFO && sp->Parameters.WMI.BufferSize >= 0x14) {
        ULONG *ri = sp->Parameters.WMI.Buffer;                   /* WMIREGINFO: BufferSize, NextWmiRegInfo, RegistryPath, MofResourceName, GuidCount */
        ri[0] = 0x14; ri[1] = 0; ri[2] = 0; ri[3] = 0; ri[4] = 0;
        InterlockedIncrement(&g_ext->sysctl_reginfo);
        irp->IoStatus.Information = 0x14; st = STATUS_SUCCESS;
    }
    irp->IoStatus.Status = st;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    return st;
}
/* StartIo: complete the packet and start the next one */
static VOID ApiStartIo(PDEVICE_OBJECT dev, PIRP irp)
{
    InterlockedIncrement(&g_ext->startio_count);
    irp->IoStatus.Status = STATUS_SUCCESS; irp->IoStatus.Information = 0;
    IoSetCancelRoutine(irp, NULL);
    IoCompleteRequest(irp, IO_NO_INCREMENT);
    IoStartNextPacket(dev, TRUE);
}
static VOID ApiCancel(PDEVICE_OBJECT dev, PIRP irp)
{
    (void)dev;
    IoReleaseCancelSpinLock(irp->CancelIrql);
    InterlockedIncrement(&g_ext->cancel_count);
    irp->IoStatus.Status = STATUS_CANCELLED; irp->IoStatus.Information = 0;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}
static NTSTATUS ApiInternalControl(PDEVICE_OBJECT dev, PIRP irp)     /* queued through StartIo */
{
    IoMarkIrpPending(irp);
    IoStartPacket(dev, irp, NULL, ApiCancel);
    return STATUS_PENDING;
}

/* ---- callbacks ---- */
static NTSTATUS RegQueryRoutine(PWSTR name, ULONG type, PVOID data, ULONG len, PVOID ctx, PVOID entry)
{
    LONG *count = ctx;
    (void)name; (void)data; (void)len; (void)entry;
    if (type == REG_SZ) (*count)++;                              /* each REG_MULTI_SZ member arrives as one REG_SZ call */
    return STATUS_SUCCESS;
}
static NTSTATUS PnpIfaceCallback(PVOID notification, PVOID ctx)
{
    PDEVICE_INTERFACE_CHANGE_NOTIFICATION n = notification;
    LONG *count = ctx;
    if (n->Version == 1 && n->Size == sizeof(*n) && n->SymbolicLinkName && n->SymbolicLinkName->Length) (*count)++;
    return STATUS_SUCCESS;
}
static VOID PowerDone(PDEVICE_OBJECT dev, UCHAR minor, POWER_STATE state, PVOID ctx, PIO_STATUS_BLOCK iosb)
{
    (void)dev; (void)ctx;
    if (minor == IRP_MN_SET_POWER && state.DeviceState == PowerDeviceD3 && NT_SUCCESS(iosb->Status)) InterlockedIncrement(&g_ext->power_cb);
    KeSetEvent(&g_ext->power_done, IO_NO_INCREMENT, FALSE);
}
static VOID ExCallbackFn(PVOID ctx, PVOID a1, PVOID a2)
{
    (void)a2;
    if (ctx == g_ext && a1 == (PVOID)0x1234) InterlockedIncrement(&g_ext->cb_notify);
}
static VOID ApiIoTimer(PDEVICE_OBJECT dev, PVOID ctx) { (void)dev; (void)ctx; InterlockedIncrement(&g_ext->timer_ticks); }
static VOID ApiReinit(PDRIVER_OBJECT drv, PVOID ctx, ULONG count)
{
    (void)drv; (void)ctx;
    g_ext->reinit = (LONG)count;
    CHECK(count == 1, "IoRegisterDriverReinitialization (runs after DriverEntry, Count 1)");
}
static IO_ALLOCATION_ACTION DmaChannelReady(PDEVICE_OBJECT dev, PIRP irp, PVOID mapreg, PVOID ctx)
{
    (void)dev; (void)irp; (void)mapreg;
    *(LONG *)ctx = 1;
    return DeallocateObject;
}
static VOID SgReady(PDEVICE_OBJECT dev, PIRP irp, PSCATTER_GATHER_LIST sgl, PVOID ctx)
{
    ULONG i, total = 0;
    (void)dev; (void)irp;
    for (i = 0; i < sgl->NumberOfElements; ++i) total += sgl->Elements[i].Length;
    *(ULONG *)ctx = total;
}

/* ---- the checks ---- */
static void TestRegistry(PUNICODE_STRING regpath)
{
    NTSTATUS st;
    ULONG dword = 5, direct = 0;
    UNICODE_STRING str = { 0, 0, NULL };
    RTL_QUERY_REGISTRY_TABLE t[4];
    static WCHAR multi[] = L"one\0two\0three\0";
    LONG multi_calls = 0;
    WCHAR params[200];
    UNICODE_STRING paramsPath;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;
    (void)regpath;
    st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, L"shzapi\\Parameters", L"Count", REG_DWORD, &dword, sizeof dword);
    CHECK(NT_SUCCESS(st), "RtlWriteRegistryValue REG_DWORD (creates the key)");
    st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, L"shzapi\\Parameters", L"Name", REG_SZ, L"Shizuku", 8 * sizeof(WCHAR));
    st = RtlWriteRegistryValue(RTL_REGISTRY_SERVICES, L"shzapi\\Parameters", L"Multi", REG_MULTI_SZ, multi, sizeof multi);
    RtlZeroMemory(t, sizeof t);
    t[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED; t[0].Name = L"Count"; t[0].EntryContext = &direct;
    t[1].Flags = RTL_QUERY_REGISTRY_DIRECT; t[1].Name = L"Name"; t[1].EntryContext = &str;
    t[2].QueryRoutine = RegQueryRoutine; t[2].Name = L"Multi";
    st = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"shzapi\\Parameters", t, &multi_calls, NULL);
    CHECK(NT_SUCCESS(st) && direct == 5, "RtlQueryRegistryValues DIRECT REG_DWORD");
    CHECK(str.Buffer && str.Length == 7 * sizeof(WCHAR) && str.Buffer[0] == L'S' && str.Buffer[6] == L'u', "RtlQueryRegistryValues DIRECT REG_SZ allocates a UNICODE_STRING");
    CHECK(multi_calls == 3, "RtlQueryRegistryValues expands REG_MULTI_SZ into three REG_SZ calls");
    if (str.Buffer) ExFreePool(str.Buffer);
    /* default value for an absent name, then REQUIRED without default */
    RtlZeroMemory(t, sizeof t);
    t[0].Flags = RTL_QUERY_REGISTRY_DIRECT; t[0].Name = L"Absent"; t[0].EntryContext = &direct; t[0].DefaultType = REG_DWORD; dword = 77; t[0].DefaultData = &dword; t[0].DefaultLength = 4;
    st = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"shzapi\\Parameters", t, NULL, NULL);
    CHECK(NT_SUCCESS(st) && direct == 77, "RtlQueryRegistryValues DefaultData for an absent value");
    st = RtlDeleteRegistryValue(RTL_REGISTRY_SERVICES, L"shzapi\\Parameters", L"Count");
    RtlZeroMemory(t, sizeof t);
    t[0].Flags = RTL_QUERY_REGISTRY_DIRECT | RTL_QUERY_REGISTRY_REQUIRED; t[0].Name = L"Count"; t[0].EntryContext = &direct;
    st = RtlQueryRegistryValues(RTL_REGISTRY_SERVICES, L"shzapi\\Parameters", t, NULL, NULL);
    CHECK(st == STATUS_OBJECT_NAME_NOT_FOUND, "RtlDeleteRegistryValue + REQUIRED query -> STATUS_OBJECT_NAME_NOT_FOUND");
    /* ZwEnumerateValueKey over the same key: Name and Multi remain */
    RtlInitEmptyUnicodeString(&paramsPath, params, sizeof params);
    RtlAppendUnicodeToString(&paramsPath, L"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\shzapi\\Parameters");
    InitializeObjectAttributes(&oa, &paramsPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    st = ZwOpenKey(&key, KEY_READ, &oa);
    if (NT_SUCCESS(st)) {
        UCHAR buf[256]; ULONG n = 0, len, i;
        KEY_FULL_INFORMATION full;
        for (i = 0; ; ++i) {
            st = ZwEnumerateValueKey(key, i, KeyValueFullInformation, buf, sizeof buf, &len);
            if (st == STATUS_NO_MORE_ENTRIES) break;
            if (!NT_SUCCESS(st)) break;
            ++n;
        }
        CHECK(n == 2 && st == STATUS_NO_MORE_ENTRIES, "ZwEnumerateValueKey enumerates 2 values then STATUS_NO_MORE_ENTRIES");
        st = ZwQueryKey(key, KeyFullInformation, &full, sizeof full, &len);
        CHECK(NT_SUCCESS(st) && full.Values == 2 && full.SubKeys == 0, "ZwQueryKey KeyFullInformation counts values");
        ZwClose(key);
    } else CHECK(FALSE, "ZwOpenKey on the Parameters key");
}

static void TestDriverExtension(PDRIVER_OBJECT drv)
{
    PVOID ext = NULL, again = NULL;
    NTSTATUS st = IoAllocateDriverObjectExtension(drv, (PVOID)TestDriverExtension, 64, &ext);
    CHECK(NT_SUCCESS(st) && ext, "IoAllocateDriverObjectExtension");
    CHECK(IoGetDriverObjectExtension(drv, (PVOID)TestDriverExtension) == ext, "IoGetDriverObjectExtension finds it");
    st = IoAllocateDriverObjectExtension(drv, (PVOID)TestDriverExtension, 64, &again);
    CHECK(st == STATUS_OBJECT_NAME_COLLISION && !again, "IoAllocateDriverObjectExtension twice -> STATUS_OBJECT_NAME_COLLISION");
    CHECK(drv->DriverExtension && drv->DriverExtension->DriverObject == drv && drv->DriverExtension->ServiceKeyName.Length == 6 * sizeof(WCHAR),
          "DRIVER_EXTENSION present with ServiceKeyName 'shzapi'");
}

static void TestInterfaces(PDEVICE_OBJECT dev, PDRIVER_OBJECT drv)
{
    static const GUID cls = { 0x53f56307, 0xb6bf, 0x11d0, { 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b } };   /* GUID_DEVINTERFACE_DISK */
    NTSTATUS st;
    PVOID entry = NULL;
    PWSTR list = NULL;
    PFILE_OBJECT fo = NULL; PDEVICE_OBJECT opened = NULL;
    st = IoRegisterDeviceInterface(dev, &cls, NULL, &g_ext->iface);
    CHECK(NT_SUCCESS(st) && g_ext->iface.Length > 8 && g_ext->iface.Buffer[0] == L'\\' && g_ext->iface.Buffer[1] == L'?', "IoRegisterDeviceInterface returns a \\??\\ link");
    st = IoRegisterPlugPlayNotification(EventCategoryDeviceInterfaceChange, PNPNOTIFY_DEVICE_INTERFACE_INCLUDE_EXISTING_INTERFACES,
                                        (PVOID)&cls, drv, PnpIfaceCallback, &g_ext->pnp_cb, &entry);
    CHECK(NT_SUCCESS(st) && entry, "IoRegisterPlugPlayNotification (device interface class)");
    st = IoSetDeviceInterfaceState(&g_ext->iface, TRUE);
    CHECK(NT_SUCCESS(st), "IoSetDeviceInterfaceState TRUE");
    CHECK(g_ext->pnp_cb == 1, "device interface arrival delivered to the PnP notification callback");
    st = IoGetDeviceInterfaces(&cls, NULL, 0, &list);
    CHECK(NT_SUCCESS(st) && list && list[0] == L'\\' && wcscmp(list, g_ext->iface.Buffer) == 0, "IoGetDeviceInterfaces lists the enabled interface");
    if (list) ExFreePool(list);
    st = IoGetDeviceObjectPointer(&g_ext->iface, FILE_READ_DATA, &fo, &opened);
    CHECK(NT_SUCCESS(st) && opened == dev && fo && fo->DeviceObject == dev, "IoGetDeviceObjectPointer through the interface link");
    if (fo) ObDereferenceObject(fo);
    st = IoUnregisterPlugPlayNotification(entry);
    CHECK(NT_SUCCESS(st), "IoUnregisterPlugPlayNotification");
}

static void TestStack(PDRIVER_OBJECT drv)
{
    UNICODE_STRING lname;
    NTSTATUS st;
    PDEVICE_OBJECT attached = NULL;
    KEVENT ev; IO_STATUS_BLOCK iosb; PIRP irp; ULONG out = 0;
    RtlInitUnicodeString(&lname, L"\\Device\\ShzApiLower");
    st = IoCreateDevice(drv, 0, &lname, FILE_DEVICE_UNKNOWN, 0, FALSE, &g_ext->lower);
    if (!NT_SUCCESS(st)) { CHECK(FALSE, "IoCreateDevice lower"); return; }
    g_ext->lower->Flags |= DO_BUFFERED_IO; g_ext->lower->Flags &= ~DO_DEVICE_INITIALIZING;
    st = IoAttachDeviceToDeviceStackSafe(g_ext->self, g_ext->lower, &attached);
    CHECK(NT_SUCCESS(st) && attached == g_ext->lower && g_ext->self->StackSize == 2, "IoAttachDeviceToDeviceStackSafe (StackSize 2)");
    CHECK(IoGetLowerDeviceObject(g_ext->self) == g_ext->lower, "IoGetLowerDeviceObject");
    KeInitializeEvent(&ev, NotificationEvent, FALSE);
    irp = IoBuildDeviceIoControlRequest(IOCTL_SHZ_LOWER, g_ext->self, NULL, 0, &out, sizeof out, FALSE, &ev, &iosb);
    if (irp) {
        st = IoCallDriver(g_ext->self, irp);
        if (st == STATUS_PENDING) KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
        CHECK(NT_SUCCESS(iosb.Status) && iosb.Information == 4 && out == 0x10BE1 && g_ext->lower_ioctls == 1, "IoForwardIrpSynchronously reached the lower device");
    } else CHECK(FALSE, "IoBuildDeviceIoControlRequest");
    IoDetachDevice(g_ext->lower);
}

typedef struct { SLIST_ENTRY e; ULONG v; } SL_ITEM;
static void TestLists(void)
{
    SLIST_HEADER h;
    static SL_ITEM items[3] __attribute__((aligned(16)));
    PSLIST_ENTRY p;
    LIST_ENTRY head; KSPIN_LOCK lock; LIST_ENTRY a, b; PLIST_ENTRY r;
    NPAGED_LOOKASIDE_LIST la;
    PVOID m1, m2;
    ExInitializeSListHead(&h);
    items[0].v = 1; items[1].v = 2; items[2].v = 3;
    InterlockedPushEntrySList(&h, &items[0].e); InterlockedPushEntrySList(&h, &items[1].e); InterlockedPushEntrySList(&h, &items[2].e);
    CHECK(ExQueryDepthSList(&h) == 3, "ExpInterlockedPushEntrySList x3 -> depth 3");
    p = InterlockedPopEntrySList(&h);
    CHECK(p == &items[2].e && ExQueryDepthSList(&h) == 2, "ExpInterlockedPopEntrySList returns the last pushed");
    p = InterlockedPopEntrySList(&h); p = InterlockedPopEntrySList(&h);
    CHECK(p == &items[0].e && InterlockedPopEntrySList(&h) == NULL, "ExpInterlockedPopEntrySList drains to NULL");
    InitializeListHead(&head); KeInitializeSpinLock(&lock);
    ExInterlockedInsertTailList(&head, &a, &lock); ExInterlockedInsertHeadList(&head, &b, &lock);
    r = ExInterlockedRemoveHeadList(&head, &lock);
    CHECK(r == &b && ExInterlockedRemoveHeadList(&head, &lock) == &a && ExInterlockedRemoveHeadList(&head, &lock) == NULL, "ExInterlocked{InsertTail,InsertHead,RemoveHead}List order");
    ExInitializeNPagedLookasideList(&la, NULL, NULL, 0, 48, 0x74736554u, 0);
    m1 = ExAllocateFromNPagedLookasideList(&la);
    ExFreeToNPagedLookasideList(&la, m1);
    m2 = ExAllocateFromNPagedLookasideList(&la);
    CHECK(m1 && m2 == m1 && la.L.TotalAllocates == 2 && la.L.AllocateMisses == 1, "NPAGED_LOOKASIDE_LIST recycles the freed block (1 miss of 2)");
    ExFreeToNPagedLookasideList(&la, m2);
    ExDeleteNPagedLookasideList(&la);
    CHECK(TRUE, "ExDeleteNPagedLookasideList");
}

static void TestResource(void)
{
    ERESOURCE res;
    NTSTATUS st = ExInitializeResourceLite(&res);
    BOOLEAN ok;
    CHECK(NT_SUCCESS(st), "ExInitializeResourceLite");
    KeEnterCriticalRegion();
    ok = ExAcquireResourceExclusiveLite(&res, TRUE);
    CHECK(ok && ExIsResourceAcquiredExclusiveLite(&res) && KeAreApcsDisabled(), "ExAcquireResourceExclusiveLite inside a critical region");
    ok = ExAcquireResourceSharedLite(&res, FALSE);              /* recursive by the exclusive owner */
    CHECK(ok, "ExAcquireResourceSharedLite by the exclusive owner (recursive)");
    ExReleaseResourceLite(&res); ExReleaseResourceLite(&res);
    CHECK(!ExIsResourceAcquiredExclusiveLite(&res), "ExReleaseResourceLite twice frees it");
    KeLeaveCriticalRegion();
    CHECK(!KeAreApcsDisabled(), "KeLeaveCriticalRegion");
    st = ExDeleteResourceLite(&res);
    CHECK(NT_SUCCESS(st), "ExDeleteResourceLite");
}

static void TestBitmapAndCrt(void)
{
    RTL_BITMAP bm; ULONG bits[4]; ULONG pos;
    WCHAR wbuf[64]; CHAR abuf[64]; int n;
    UNICODE_STRING us; ULONG val = 0; NTSTATUS st;
    ANSI_STRING as; UNICODE_STRING conv;
    LARGE_INTEGER t; TIME_FIELDS tf;
    GUID g = { 0x12345678, 0x9abc, 0xdef0, { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 } };
    UNICODE_STRING gs;
    RTL_OSVERSIONINFOEXW vi;
    ULONGLONG mask = 0;
    RtlInitializeBitMap(&bm, bits, 100);
    RtlClearAllBits(&bm);
    RtlSetBits(&bm, 0, 10);
    pos = RtlFindClearBitsAndSet(&bm, 5, 0);
    CHECK(pos == 10 && RtlNumberOfSetBits(&bm) == 15 && RtlAreBitsSet(&bm, 10, 5), "RtlBitMap set/find/count");
    RtlInitUnicodeString(&us, L"0x1A");
    st = RtlUnicodeStringToInteger(&us, 0, &val);
    CHECK(NT_SUCCESS(st) && val == 26, "RtlUnicodeStringToInteger parses 0x1A");
    RtlInitUnicodeString(&us, L"Z");
    n = swprintf(wbuf, L"%S-%d-%04x-%ws-%wZ", "abc", -42, 0xbeef, L"wide", &us);   /* Microsoft: %S narrow, %s/%ws wide in a wide format */
    CHECK(n == 19 && wcscmp(wbuf, L"abc--42-beef-wide-Z") == 0, "swprintf with %S %d %04x %ws %wZ");
    n = _snwprintf(wbuf, 64, L"%S-%d-%04X-%s-%c", "abc", -42, 0xbeef, L"wide", 'Z');
    CHECK(n == 19 && wcscmp(wbuf, L"abc--42-BEEF-wide-Z") == 0, "_snwprintf with %S %d %04X %s %c");
    n = _snprintf(abuf, 64, "%S|%u|%I64x|%p|%5.2s|%-3d|", L"W", 7u, 0x1122334455667788ULL, (PVOID)0x10, "hello", 1);
    CHECK(n == (int)strlen("W|7|1122334455667788|0000000000000010|   he|1  |") && strcmp(abuf, "W|7|1122334455667788|0000000000000010|   he|1  |") == 0, "_snprintf with %S %u %I64x %p precision width");
    CHECK(wcslen(L"four") == 4 && _wcsnicmp(L"ABCd", L"abce", 3) == 0 && wcscmp(L"a", L"b") < 0 && _stricmp("Foo", "fOO") == 0, "wcslen/_wcsnicmp/wcscmp/_stricmp");
    RtlInitString(&as, "latin");
    st = RtlAnsiStringToUnicodeString(&conv, &as, TRUE);
    CHECK(NT_SUCCESS(st) && conv.Length == 10 && RtlxAnsiStringToUnicodeSize(&as) == 12, "RtlxAnsiStringToUnicodeSize");
    if (NT_SUCCESS(st)) RtlFreeUnicodeString(&conv);
    t.QuadPart = 125911584000000000LL;                           /* 2000-01-01 00:00:00 */
    RtlTimeToTimeFields(&t, &tf);
    CHECK(tf.Year == 2000 && tf.Month == 1 && tf.Day == 1 && tf.Hour == 0 && tf.Weekday == 6, "RtlTimeToTimeFields 2000-01-01 (Saturday)");
    st = RtlStringFromGUID(&g, &gs);
    CHECK(NT_SUCCESS(st) && gs.Length == 38 * 2 && wcscmp(gs.Buffer, L"{12345678-9ABC-DEF0-1122-334455667788}") == 0, "RtlStringFromGUID");
    if (NT_SUCCESS(st)) RtlFreeUnicodeString(&gs);
    RtlZeroMemory(&vi, sizeof vi); vi.dwOSVersionInfoSize = sizeof vi; vi.dwMajorVersion = 6; vi.dwMinorVersion = 1;
    mask = VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL), VER_MINORVERSION, VER_GREATER_EQUAL);
    st = RtlVerifyVersionInfo(&vi, VER_MAJORVERSION | VER_MINORVERSION, mask);
    CHECK(NT_SUCCESS(st), "RtlVerifyVersionInfo >= 6.1 on a 10.0 kernel");
    vi.dwMajorVersion = 11;
    st = RtlVerifyVersionInfo(&vi, VER_MAJORVERSION | VER_MINORVERSION, mask);
    CHECK(st == STATUS_REVISION_MISMATCH, "RtlVerifyVersionInfo >= 11.1 -> STATUS_REVISION_MISMATCH");
    CHECK(KeNumberProcessors == 1 && KdDebuggerNotPresent == TRUE && !KdDebuggerEnabled, "data exports KeNumberProcessors/KdDebuggerNotPresent/KdDebuggerEnabled");
    {
        UNICODE_STRING fn; PVOID p;
        RtlInitUnicodeString(&fn, L"ExAllocatePoolWithTag");
        p = MmGetSystemRoutineAddress(&fn);
        CHECK(p == (PVOID)ExAllocatePoolWithTag, "MmGetSystemRoutineAddress(ExAllocatePoolWithTag) == the import");
        RtlInitUnicodeString(&fn, L"NoSuchRoutine");
        CHECK(MmGetSystemRoutineAddress(&fn) == NULL, "MmGetSystemRoutineAddress(unknown) == NULL");
    }
}

static void TestCancelAndStartIo(PDEVICE_OBJECT dev)
{
    KIRQL irql;
    PIRP irp1, irp2;
    KEVENT ev1, ev2; IO_STATUS_BLOCK io1, io2;
    NTSTATUS st;
    IoAcquireCancelSpinLock(&irql);
    CHECK(KeGetCurrentIrql() == DISPATCH_LEVEL, "IoAcquireCancelSpinLock raises to DISPATCH_LEVEL");
    IoReleaseCancelSpinLock(irql);
    CHECK(KeGetCurrentIrql() == irql, "IoReleaseCancelSpinLock restores the IRQL");
    /* two internal IOCTLs go through StartIo; the second is queued while the first runs -- since StartIo completes
     * synchronously here both are serviced in order */
    KeInitializeEvent(&ev1, NotificationEvent, FALSE); KeInitializeEvent(&ev2, NotificationEvent, FALSE);
    irp1 = IoBuildDeviceIoControlRequest(IOCTL_SHZ_APIINFO, dev, NULL, 0, NULL, 0, TRUE, &ev1, &io1);
    irp2 = IoBuildDeviceIoControlRequest(IOCTL_SHZ_APIINFO, dev, NULL, 0, NULL, 0, TRUE, &ev2, &io2);
    if (irp1 && irp2) {
        st = IoCallDriver(dev, irp1);
        if (st == STATUS_PENDING) KeWaitForSingleObject(&ev1, Executive, KernelMode, FALSE, NULL);
        st = IoCallDriver(dev, irp2);
        if (st == STATUS_PENDING) KeWaitForSingleObject(&ev2, Executive, KernelMode, FALSE, NULL);
        CHECK(g_ext->startio_count == 2 && NT_SUCCESS(io1.Status) && NT_SUCCESS(io2.Status), "IoStartPacket/IoStartNextPacket serviced two packets");
    } else CHECK(FALSE, "IoBuildDeviceIoControlRequest for StartIo");
    /* cancellation: an IRP with a cancel routine set, cancelled by IoCancelIrp */
    irp1 = IoAllocateIrp(dev->StackSize, FALSE);
    if (irp1) {
        BOOLEAN r;
        IoSetCancelRoutine(irp1, ApiCancel);
        IoGetNextIrpStackLocation(irp1)->DeviceObject = dev;
        irp1->CurrentLocation--; irp1->Tail.Overlay.CurrentStackLocation--;   /* pretend the IRP sits at this device */
        r = IoCancelIrp(irp1);
        CHECK(r && irp1->Cancel && g_ext->cancel_count == 1 && irp1->CancelRoutine == NULL, "IoCancelIrp calls the cancel routine once");
        IoFreeIrp(irp1);
        irp2 = IoAllocateIrp(1, FALSE);
        r = irp2 ? IoCancelIrp(irp2) : TRUE;
        CHECK(!r && irp2 && irp2->Cancel, "IoCancelIrp without a cancel routine returns FALSE and sets Cancel");
        if (irp2) IoFreeIrp(irp2);
    }
}

static void TestRemoveLock(void)
{
    NTSTATUS st;
    IoInitializeRemoveLock(&g_ext->rlock, 0x6b6f6c52u, 0, 0);
    st = IoAcquireRemoveLock(&g_ext->rlock, NULL);
    CHECK(NT_SUCCESS(st), "IoAcquireRemoveLock");
    IoReleaseRemoveLock(&g_ext->rlock, NULL);
    st = IoAcquireRemoveLock(&g_ext->rlock, NULL);
    IoReleaseRemoveLockAndWait(&g_ext->rlock, NULL);              /* returns at once: no other holders */
    st = IoAcquireRemoveLock(&g_ext->rlock, NULL);
    CHECK(st == STATUS_DELETE_PENDING, "IoAcquireRemoveLock after IoReleaseRemoveLockAndWait -> STATUS_DELETE_PENDING");
}

static void TestErrorLog(PDEVICE_OBJECT dev)
{
    PIO_ERROR_LOG_PACKET p = IoAllocateErrorLogEntry(dev, (UCHAR)(sizeof(IO_ERROR_LOG_PACKET) + 12));
    CHECK(p != NULL, "IoAllocateErrorLogEntry");
    if (p) {
        PWCHAR s = (PWCHAR)((PUCHAR)p + sizeof(IO_ERROR_LOG_PACKET));
        p->ErrorCode = 0xC0040001; p->FinalStatus = STATUS_DEVICE_NOT_READY; p->UniqueErrorValue = 7; p->NumberOfStrings = 1;
        p->StringOffset = sizeof(IO_ERROR_LOG_PACKET); p->DumpDataSize = 0;
        s[0] = L'A'; s[1] = L'P'; s[2] = L'I'; s[3] = 0;
        IoWriteErrorLogEntry(p);
        CHECK(TRUE, "IoWriteErrorLogEntry");
    }
    CHECK(IoAllocateErrorLogEntry(dev, 4) == NULL, "IoAllocateErrorLogEntry rejects a size below the packet header");
}

static void TestPower(PDEVICE_OBJECT dev)
{
    POWER_STATE ps, prev;
    NTSTATUS st;
    PIRP irp = NULL;
    ps.DeviceState = PowerDeviceD0;
    prev = PoSetPowerState(dev, DevicePowerState, ps);
    ps.DeviceState = PowerDeviceD1;
    prev = PoSetPowerState(dev, DevicePowerState, ps);
    CHECK(prev.DeviceState == PowerDeviceD0, "PoSetPowerState returns the previous state");
    KeInitializeEvent(&g_ext->power_done, NotificationEvent, FALSE);
    ps.DeviceState = PowerDeviceD3;
    st = PoRequestPowerIrp(dev, IRP_MN_SET_POWER, ps, PowerDone, NULL, &irp);
    if (st == STATUS_PENDING) KeWaitForSingleObject(&g_ext->power_done, Executive, KernelMode, FALSE, NULL);
    CHECK(st == STATUS_PENDING && g_ext->power_cb == 1, "PoRequestPowerIrp(SET_POWER D3) reached the power dispatch and the completion callback");
    ps.DeviceState = PowerDeviceD0;
    prev = PoSetPowerState(dev, DevicePowerState, ps);
    CHECK(prev.DeviceState == PowerDeviceD3, "the power dispatch recorded D3 through PoSetPowerState");
}

static void TestPdo(PDRIVER_OBJECT drv)
{
    PDEVICE_OBJECT pdo = NULL;
    NTSTATUS st;
    WCHAR buf[64]; ULONG len = 0;
    HANDLE key = NULL;
    st = IoReportDetectedDevice(drv, InterfaceTypeUndefined, (ULONG)-1, (ULONG)-1, NULL, NULL, FALSE, &pdo);
    CHECK(NT_SUCCESS(st) && pdo, "IoReportDetectedDevice creates a root-enumerated PDO");
    if (!pdo) return;
    st = IoGetDeviceProperty(pdo, DevicePropertyEnumeratorName, sizeof buf, buf, &len);
    CHECK(NT_SUCCESS(st) && wcscmp(buf, L"ROOT") == 0 && len == 10, "IoGetDeviceProperty(EnumeratorName) == ROOT");
    st = IoGetDeviceProperty(pdo, DevicePropertyHardwareID, sizeof buf, buf, &len);
    CHECK(NT_SUCCESS(st) && wcscmp(buf, L"ROOT\\LEGACY_SHZAPI") == 0 && buf[len / 2 - 1] == 0, "IoGetDeviceProperty(HardwareID) == ROOT\\LEGACY_SHZAPI (REG_MULTI_SZ)");
    st = IoGetDeviceProperty(pdo, DevicePropertyEnumeratorName, 2, buf, &len);
    CHECK(st == STATUS_BUFFER_TOO_SMALL && len == 10, "IoGetDeviceProperty short buffer -> STATUS_BUFFER_TOO_SMALL with the size");
    st = IoGetDeviceProperty(g_ext->self, DevicePropertyEnumeratorName, sizeof buf, buf, &len);
    CHECK(st == STATUS_INVALID_DEVICE_REQUEST, "IoGetDeviceProperty on a non-PDO -> STATUS_INVALID_DEVICE_REQUEST");
    st = IoOpenDeviceRegistryKey(pdo, PLUGPLAY_REGKEY_DEVICE, KEY_ALL_ACCESS, &key);
    CHECK(NT_SUCCESS(st) && key, "IoOpenDeviceRegistryKey(PLUGPLAY_REGKEY_DEVICE) opens Enum\\...\\Device Parameters");
    if (key) {
        UNICODE_STRING vn; ULONG v = 42;
        RtlInitUnicodeString(&vn, L"Probe");
        st = ZwSetValueKey(key, &vn, 0, REG_DWORD, &v, 4);
        CHECK(NT_SUCCESS(st), "ZwSetValueKey under the device key");
        ZwClose(key);
    }
    {   /* PnP IRP to the PDO: IRP_MN_QUERY_ID BusQueryDeviceID answered by the host's root bus */
        KEVENT ev; IO_STATUS_BLOCK iosb; PIRP irp; PIO_STACK_LOCATION sp;
        KeInitializeEvent(&ev, NotificationEvent, FALSE);
        irp = IoBuildSynchronousFsdRequest(IRP_MJ_PNP, pdo, NULL, 0, NULL, &ev, &iosb);
        if (irp) {
            sp = IoGetNextIrpStackLocation(irp);
            sp->MajorFunction = IRP_MJ_PNP; sp->MinorFunction = IRP_MN_QUERY_ID; sp->Parameters.QueryId.IdType = BusQueryDeviceID;
            irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
            st = IoCallDriver(pdo, irp);
            if (st == STATUS_PENDING) KeWaitForSingleObject(&ev, Executive, KernelMode, FALSE, NULL);
            CHECK(NT_SUCCESS(iosb.Status) && iosb.Information && wcscmp((PWSTR)iosb.Information, L"SHZAPI") == 0, "IRP_MN_QUERY_ID(BusQueryDeviceID) answered by the root bus PDO");
            if (NT_SUCCESS(iosb.Status) && iosb.Information) ExFreePool((PVOID)iosb.Information);
        }
    }
}

static void TestDma(PDEVICE_OBJECT dev)
{
    DEVICE_DESCRIPTION dd;
    ULONG nmap = 0, total = 0;
    PDMA_ADAPTER a;
    PVOID cb; PHYSICAL_ADDRESS la, pa;
    PMDL mdl;
    UCHAR *buf;
    LONG ready = 0;
    NTSTATUS st;
    RtlZeroMemory(&dd, sizeof dd);
    dd.Version = DEVICE_DESCRIPTION_VERSION; dd.Master = TRUE; dd.ScatterGather = TRUE; dd.Dma32BitAddresses = TRUE; dd.InterfaceType = PCIBus; dd.MaximumLength = 65536;
    a = IoGetDmaAdapter(dev, &dd, &nmap);
    CHECK(a && a->DmaOperations && a->DmaOperations->Size >= sizeof(DMA_OPERATIONS) && nmap >= 17, "IoGetDmaAdapter (DMA_OPERATIONS, map registers)");
    if (!a) return;
    cb = a->DmaOperations->AllocateCommonBuffer(a, 8192, &la, FALSE);
    pa = MmGetPhysicalAddress(cb);
    CHECK(cb && la.QuadPart && la.QuadPart == pa.QuadPart && (la.QuadPart & 0xfff) == 0, "AllocateCommonBuffer is page aligned and MmGetPhysicalAddress agrees");
    st = a->DmaOperations->AllocateAdapterChannel(a, dev, 4, DmaChannelReady, &ready);
    CHECK(NT_SUCCESS(st) && ready == 1, "AllocateAdapterChannel calls the AdapterControl routine");
    buf = ExAllocatePoolWithTag(NonPagedPool, 12000, 0x616d4454u);
    mdl = buf ? IoAllocateMdl(buf, 12000, FALSE, FALSE, NULL) : NULL;
    if (mdl) {
        MmBuildMdlForNonPagedPool(mdl);
        st = a->DmaOperations->GetScatterGatherList(a, dev, mdl, buf, 12000, SgReady, &total, TRUE);
        CHECK(NT_SUCCESS(st) && total == 12000, "GetScatterGatherList covers the whole 12000-byte buffer");
        {
            ULONG len = 12000;
            PHYSICAL_ADDRESS mt = a->DmaOperations->MapTransfer(a, mdl, a, buf, &len, TRUE);
            CHECK(mt.QuadPart == MmGetPhysicalAddress(buf).QuadPart && len >= 1 && len <= 12000, "MapTransfer returns the buffer's physical address");
        }
        IoFreeMdl(mdl);
    } else CHECK(FALSE, "IoAllocateMdl for DMA");
    if (buf) ExFreePool(buf);
    if (cb) a->DmaOperations->FreeCommonBuffer(a, 8192, la, cb, FALSE);
    a->DmaOperations->PutDmaAdapter(a);
    CHECK(TRUE, "PutDmaAdapter");
}

static void TestPartitions(PDEVICE_OBJECT dev)
{
    PDRIVE_LAYOUT_INFORMATION_EX layout = NULL;
    NTSTATUS st = IoReadPartitionTableEx(dev, &layout);
    CHECK(NT_SUCCESS(st) && layout && layout->PartitionStyle == PARTITION_STYLE_MBR && layout->PartitionCount == 4 && layout->Mbr.Signature == 0x5A5A1234,
          "IoReadPartitionTableEx read the MBR through IRP_MJ_READ");
    if (NT_SUCCESS(st) && layout) {
        CHECK(layout->PartitionEntry[0].Mbr.PartitionType == 7 && layout->PartitionEntry[0].Mbr.BootIndicator && layout->PartitionEntry[0].StartingOffset.QuadPart == 2048 * 512 &&
              layout->PartitionEntry[0].PartitionLength.QuadPart == 2048 * 512 && layout->PartitionEntry[1].Mbr.PartitionType == 0x0c && layout->PartitionEntry[1].PartitionNumber == 2,
              "partition entries decoded (type, boot flag, offsets)");
        ExFreePool(layout);
    }
}

static void TestPagesAndMisc(PDEVICE_OBJECT dev, PDRIVER_OBJECT drv)
{
    PHYSICAL_ADDRESS lo, hi, skip;
    PMDL mdl;
    PCALLBACK_OBJECT cbo = NULL; PVOID reg; OBJECT_ATTRIBUTES oa; UNICODE_STRING cbname;
    NTSTATUS st;
    PCONFIGURATION_INFORMATION ci;
    LARGE_INTEGER delay;
    lo.QuadPart = 0; hi.QuadPart = 0xffffffff; skip.QuadPart = 0;
    mdl = MmAllocatePagesForMdl(lo, hi, skip, 3 * 4096);
    CHECK(mdl && MmGetMdlByteCount(mdl) == 3 * 4096, "MmAllocatePagesForMdl 3 pages");
    if (mdl) {
        UCHAR *va = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
        if (va) {
            PPFN_NUMBER pfn = MmGetMdlPfnArray(mdl);
            va[0] = 0x5a; va[3 * 4096 - 1] = 0xa5;
            CHECK(va[0] == 0x5a && va[3 * 4096 - 1] == 0xa5 && MmGetPhysicalAddress(va + 4096).QuadPart == (LONGLONG)(pfn[1] << 12), "MmMapLockedPagesSpecifyCache maps the page list contiguously");
            MmUnmapLockedPages(va, mdl);
        } else CHECK(FALSE, "MmMapLockedPagesSpecifyCache");
        MmFreePagesFromMdl(mdl);
        ExFreePool(mdl);
    }
    RtlInitUnicodeString(&cbname, L"\\Callback\\ShzApiTest");
    InitializeObjectAttributes(&oa, &cbname, OBJ_CASE_INSENSITIVE | OBJ_PERMANENT, NULL, NULL);
    st = ExCreateCallback(&cbo, &oa, TRUE, TRUE);
    reg = NT_SUCCESS(st) ? ExRegisterCallback(cbo, ExCallbackFn, g_ext) : NULL;
    if (reg) ExNotifyCallback(cbo, (PVOID)0x1234, NULL);
    CHECK(NT_SUCCESS(st) && reg && g_ext->cb_notify == 1, "ExCreateCallback/ExRegisterCallback/ExNotifyCallback");
    if (reg) ExUnregisterCallback(reg);
    if (cbo) ObDereferenceObject(cbo);
    ci = IoGetConfigurationInformation();
    CHECK(ci && ci->Version == 1, "IoGetConfigurationInformation");
    if (ci) ci->SerialCount++;
    CHECK(IoIsWdmVersionAvailable(1, 0x30) && !IoIsWdmVersionAvailable(6, 0x40), "IoIsWdmVersionAvailable 1.30");
    st = IoWMIRegistrationControl(dev, WMIREG_ACTION_REGISTER);
    CHECK(NT_SUCCESS(st), "IoWMIRegistrationControl(REGISTER)");
    st = IoInitializeTimer(dev, ApiIoTimer, NULL);
    CHECK(NT_SUCCESS(st), "IoInitializeTimer");
    IoStartTimer(dev);
    delay.QuadPart = -12000000LL;                                /* 1.2 s: the one-second I/O timer fires once */
    KeDelayExecutionThread(KernelMode, FALSE, &delay);
    IoStopTimer(dev);
    CHECK(g_ext->timer_ticks >= 1, "IoStartTimer fires the IoTimer routine once a second");
    CHECK(g_ext->sysctl_reginfo >= 1, "WMI registration queried IRP_MN_REGINFO on the system worker");
    IoWMIRegistrationControl(dev, WMIREG_ACTION_DEREGISTER);
    IoRegisterDriverReinitialization(drv, ApiReinit, NULL);
    {
        PKEVENT e; HANDLE h = NULL; UNICODE_STRING en;
        RtlInitUnicodeString(&en, L"\\BaseNamedObjects\\ShzApiEvent");
        e = IoCreateSynchronizationEvent(&en, &h);
        CHECK(e && h && KeReadStateEvent(e) == 1, "IoCreateSynchronizationEvent is created signalled");
        if (h) ZwClose(h);
    }
    {
        PVOID frames[4]; ULONG hash = 0;
        USHORT n = RtlCaptureStackBackTrace(0, 4, frames, &hash);
        CHECK(n <= 4, "RtlCaptureStackBackTrace stays within the kernel stack");
    }
}

static VOID ApiUnload(PDRIVER_OBJECT drv)
{
    UNICODE_STRING dos;
    if (g_ext && g_ext->iface.Buffer) { IoSetDeviceInterfaceState(&g_ext->iface, FALSE); ExFreePool(g_ext->iface.Buffer); }
    RtlInitUnicodeString(&dos, L"\\DosDevices\\ShzApi");
    IoDeleteSymbolicLink(&dos);
    while (drv->DeviceObject) IoDeleteDevice(drv->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT drv, PUNICODE_STRING reg)
{
    UNICODE_STRING name, dos;
    PDEVICE_OBJECT dev;
    NTSTATUS st;
    RtlInitUnicodeString(&name, L"\\Device\\ShzApi");
    st = IoCreateDevice(drv, sizeof(API_EXT), &name, FILE_DEVICE_UNKNOWN, 0, FALSE, &dev);
    if (!NT_SUCCESS(st)) return st;
    g_ext = dev->DeviceExtension;
    RtlZeroMemory(g_ext, sizeof *g_ext);
    g_ext->self = dev;
    RtlInitUnicodeString(&dos, L"\\DosDevices\\ShzApi");
    IoCreateSymbolicLink(&dos, &name);
    drv->MajorFunction[IRP_MJ_CREATE] = ApiCreateClose;
    drv->MajorFunction[IRP_MJ_CLOSE] = ApiCreateClose;
    drv->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ApiControl;
    drv->MajorFunction[IRP_MJ_INTERNAL_DEVICE_CONTROL] = ApiInternalControl;
    drv->MajorFunction[IRP_MJ_READ] = ApiRead;
    drv->MajorFunction[IRP_MJ_POWER] = ApiPower;
    drv->MajorFunction[IRP_MJ_SYSTEM_CONTROL] = ApiSystemControl;
    drv->DriverStartIo = ApiStartIo;
    drv->DriverUnload = ApiUnload;
    dev->Flags |= DO_BUFFERED_IO;
    dev->Flags &= ~DO_DEVICE_INITIALIZING;

    TestRegistry(reg);
    TestDriverExtension(drv);
    TestInterfaces(dev, drv);
    TestStack(drv);
    TestLists();
    TestResource();
    TestBitmapAndCrt();
    TestCancelAndStartIo(dev);
    TestRemoveLock();
    TestErrorLog(dev);
    TestPower(dev);
    TestPdo(drv);
    TestDma(dev);
    TestPartitions(dev);
    TestPagesAndMisc(dev, drv);

    DbgPrint("apitest: %d passed, %d failed\n", (int)g_pass, (int)g_fail);
    if (g_fail) { ApiUnload(drv); return STATUS_UNSUCCESSFUL; }
    return STATUS_SUCCESS;
}
