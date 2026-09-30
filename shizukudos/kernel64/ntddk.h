/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver ABI: the on-the-wire layout of the Windows kernel structures an
 * unmodified x64 .sys driver sees (DRIVER_OBJECT, DEVICE_OBJECT, IRP, IO_STACK_LOCATION,
 * MDL, dispatcher objects, ...). Every offset here matches Microsoft's wdm.h on x64; the
 * agreement is enforced at build time by win64/tools/ntddk_abi_check.c, which includes both
 * this header and the real <ddk/wdm.h> and _Static_assert()s every offset used by the host.
 *
 * The kernel is built with the System V AMD64 ABI; a Windows driver is built with the
 * Microsoft x64 ABI. Every function the driver may call, and every callback the kernel may
 * invoke in the driver, therefore carries the NTAPI (ms_abi) attribute so the two agree.
 */
#ifndef K64_NTDDK_H
#define K64_NTDDK_H
#include <stdint.h>

#define NTAPI __attribute__((ms_abi))

typedef int32_t NTSTATUS;
typedef uint8_t UCHAR, BOOLEAN, KIRQL, KPROCESSOR_MODE;
typedef int8_t CCHAR;
typedef int16_t CSHORT;
typedef uint16_t USHORT, WCHAR;
typedef int32_t LONG;
typedef uint32_t ULONG, DEVICE_TYPE;
typedef int64_t LONGLONG;
typedef uint64_t ULONGLONG, ULONG_PTR, SIZE_T;
typedef void VOID, *PVOID;

typedef struct _LIST_ENTRY { struct _LIST_ENTRY *Flink, *Blink; } LIST_ENTRY, *PLIST_ENTRY;
typedef struct _UNICODE_STRING { USHORT Length, MaximumLength; uint32_t _pad; WCHAR *Buffer; } UNICODE_STRING, *PUNICODE_STRING;
typedef struct _ANSI_STRING { USHORT Length, MaximumLength; uint32_t _pad; char *Buffer; } ANSI_STRING, *PANSI_STRING;
typedef struct _IO_STATUS_BLOCK { union { NTSTATUS Status; PVOID Pointer; }; ULONG_PTR Information; } IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;
typedef union _LARGE_INTEGER { struct { uint32_t LowPart; int32_t HighPart; }; int64_t QuadPart; } LARGE_INTEGER, *PLARGE_INTEGER;

/* Dispatcher header: the common prefix of every waitable Ke object. We keep Type and
 * SignalState where Windows keeps them; the private pointer to the kernel's own object
 * state lives in the WaitListHead area (drivers only touch these through the Ke* API). */
typedef struct _DISPATCHER_HEADER {
    union { struct { UCHAR Type, Absolute, Size, Inserted; }; LONG Lock; };
    LONG SignalState;
    LIST_ENTRY WaitListHead;            /* [0]=Flink used as the kernel object back-pointer */
} DISPATCHER_HEADER;

typedef struct _KEVENT { DISPATCHER_HEADER Header; } KEVENT, *PKEVENT;
typedef struct _KSEMAPHORE { DISPATCHER_HEADER Header; LONG Limit; } KSEMAPHORE, *PKSEMAPHORE;
/* KTIMER (Windows x64 sizeof 0x40): Header(0x18), DueTime(0x08), TimerListEntry(0x10), Dpc(0x08), Period+Processor. */
typedef struct _KTIMER { DISPATCHER_HEADER Header; uint64_t DueTime; LIST_ENTRY TimerListEntry;
                         struct _KDPC *Dpc; ULONG Period; ULONG _pad; } KTIMER, *PKTIMER;
typedef struct _KMUTANT { DISPATCHER_HEADER Header; LIST_ENTRY MutantListEntry; void *OwnerThread;
                          UCHAR Abandoned, ApcDisable; USHORT _pad; } KMUTANT, KMUTEX, *PKMUTEX;

typedef VOID (NTAPI *PKDEFERRED_ROUTINE)(struct _KDPC *Dpc, PVOID Ctx, PVOID Sa1, PVOID Sa2);
typedef struct _KDPC {
    UCHAR Type, Importance;
    USHORT Number;
    LIST_ENTRY DpcListEntry;            /* 0x08 */
    PKDEFERRED_ROUTINE DeferredRoutine; /* 0x18 */
    PVOID DeferredContext, SystemArgument1, SystemArgument2, DpcData;
} KDPC, *PKDPC;

typedef ULONG_PTR KSPIN_LOCK, *PKSPIN_LOCK;
typedef struct _KDEVICE_QUEUE_ENTRY { LIST_ENTRY DeviceListEntry; ULONG SortKey; BOOLEAN Inserted; uint8_t _pad[3]; } KDEVICE_QUEUE_ENTRY, *PKDEVICE_QUEUE_ENTRY;
/* KDEVICE_QUEUE (x64 0x28): Type/Size, DeviceListHead(8), Lock(0x18), Busy(0x20). */
typedef struct _KDEVICE_QUEUE { CSHORT Type, Size; uint32_t _pad; LIST_ENTRY DeviceListHead; KSPIN_LOCK Lock; BOOLEAN Busy; uint8_t _pad2[7]; } KDEVICE_QUEUE, *PKDEVICE_QUEUE;
typedef struct _GUID { uint32_t Data1; uint16_t Data2, Data3; uint8_t Data4[8]; } GUID, *PGUID;

typedef struct _MDL {
    struct _MDL *Next;
    CSHORT Size;
    CSHORT MdlFlags;
    PVOID Process;
    PVOID MappedSystemVa;
    PVOID StartVa;
    ULONG ByteCount;
    ULONG ByteOffset;
} MDL, *PMDL;

#define MDL_MAPPED_TO_SYSTEM_VA 0x0001
#define MDL_PAGES_LOCKED        0x0002
#define MDL_SOURCE_IS_NONPAGED_POOL 0x0004
#define MDL_ALLOCATED_FIXED_SIZE 0x0008

struct _DRIVER_OBJECT;
struct _DEVICE_OBJECT;
struct _IRP;
struct _FILE_OBJECT;

typedef NTSTATUS (NTAPI *PDRIVER_DISPATCH)(struct _DEVICE_OBJECT *DeviceObject, struct _IRP *Irp);
typedef NTSTATUS (NTAPI *PDRIVER_INITIALIZE)(struct _DRIVER_OBJECT *DriverObject, PUNICODE_STRING RegistryPath);
typedef VOID (NTAPI *PDRIVER_STARTIO)(struct _DEVICE_OBJECT *DeviceObject, struct _IRP *Irp);
typedef VOID (NTAPI *PDRIVER_UNLOAD)(struct _DRIVER_OBJECT *DriverObject);
typedef VOID (NTAPI *PDRIVER_CANCEL)(struct _DEVICE_OBJECT *DeviceObject, struct _IRP *Irp);
typedef NTSTATUS (NTAPI *PIO_COMPLETION_ROUTINE)(struct _DEVICE_OBJECT *DeviceObject, struct _IRP *Irp, PVOID Context);

#define IRP_MJ_MAXIMUM_FUNCTION 0x1b

typedef struct _DRIVER_EXTENSION {
    struct _DRIVER_OBJECT *DriverObject;
    PDRIVER_INITIALIZE AddDevice;
    ULONG Count;
    UNICODE_STRING ServiceKeyName;
} DRIVER_EXTENSION, *PDRIVER_EXTENSION;

typedef struct _DRIVER_OBJECT {
    CSHORT Type;
    CSHORT Size;
    struct _DEVICE_OBJECT *DeviceObject;
    ULONG Flags;
    PVOID DriverStart;
    ULONG DriverSize;
    PVOID DriverSection;
    PDRIVER_EXTENSION DriverExtension;
    UNICODE_STRING DriverName;
    PUNICODE_STRING HardwareDatabase;
    PVOID FastIoDispatch;
    PDRIVER_INITIALIZE DriverInit;
    PDRIVER_STARTIO DriverStartIo;
    PDRIVER_UNLOAD DriverUnload;
    PDRIVER_DISPATCH MajorFunction[IRP_MJ_MAXIMUM_FUNCTION + 1];
} DRIVER_OBJECT, *PDRIVER_OBJECT;

typedef struct _DEVICE_OBJECT {
    CSHORT Type;
    USHORT Size;
    LONG ReferenceCount;
    struct _DRIVER_OBJECT *DriverObject;
    struct _DEVICE_OBJECT *NextDevice;
    struct _DEVICE_OBJECT *AttachedDevice;
    struct _IRP *CurrentIrp;
    PVOID Timer;
    ULONG Flags;
    ULONG Characteristics;
    PVOID Vpb;
    PVOID DeviceExtension;
    DEVICE_TYPE DeviceType;             /* 0x48 */
    CCHAR StackSize;                    /* 0x4c */
    uint8_t _pad0[3];
    uint8_t Queue[0x48];                /* 0x50 WAIT_CONTEXT_BLOCK (opaque here) */
    ULONG AlignmentRequirement;         /* 0x98 */
    uint32_t _pad1;
    KDEVICE_QUEUE DeviceQueue;          /* 0xa0 StartIo queue (KeInsertDeviceQueue & co.) */
    KDPC Dpc;                           /* 0xc8 */
    ULONG ActiveThreadCount;            /* 0x108 */
    uint32_t _pad2;
    PVOID SecurityDescriptor;           /* 0x110 */
    KEVENT DeviceLock;                  /* 0x118 */
    USHORT SectorSize;                  /* 0x130 */
    USHORT Spare1;
    uint32_t _pad3;
    PVOID DeviceObjectExtension;        /* 0x138: the host's side record (struct ntdrv_devext) */
    PVOID Reserved;                     /* 0x140 */
} DEVICE_OBJECT, *PDEVICE_OBJECT;

/* Device flags (subset). */
#define DO_BUFFERED_IO 0x00000004u
#define DO_EXCLUSIVE   0x00000008u
#define DO_DIRECT_IO   0x00000010u
#define DO_DEVICE_INITIALIZING 0x00000080u
#define DO_POWER_PAGABLE 0x00002000u

/* Device types (subset). */
#define FILE_DEVICE_UNKNOWN 0x00000022u
#define FILE_DEVICE_NETWORK 0x00000012u

typedef struct _IO_STACK_LOCATION {
    UCHAR MajorFunction;
    UCHAR MinorFunction;
    UCHAR Flags;
    UCHAR Control;
    union {
        struct { PVOID SecurityContext; ULONG Options; USHORT FileAttributes, ShareAccess; uint32_t _pad; ULONG EaLength; } Create;
        struct { ULONG Length; uint32_t _p0; ULONG Key, Flags; LARGE_INTEGER ByteOffset; } Read;
        struct { ULONG Length; uint32_t _p0; ULONG Key, Flags; LARGE_INTEGER ByteOffset; } Write;
        struct { ULONG OutputBufferLength; uint32_t _p0; ULONG InputBufferLength; uint32_t _p1; ULONG IoControlCode; uint32_t _p2; PVOID Type3InputBuffer; } DeviceIoControl;
        struct { PVOID Argument1, Argument2, Argument3, Argument4; } Others;
        struct { ULONG SystemContext; uint32_t _p0; ULONG Type; uint32_t _p1; ULONG State; uint32_t _p2; ULONG ShutdownType; } Power;
        struct { ULONG Type; } QueryDeviceRelations;
        struct { PVOID AllocatedResources, AllocatedResourcesTranslated; } StartDevice;
        struct { ULONG IdType; } QueryId;
        struct { const GUID *InterfaceType; USHORT Size, Version; uint32_t _p0; PVOID Interface, InterfaceSpecificData; } QueryInterface;
        struct { PVOID Capabilities; } DeviceCapabilities;
        struct { PVOID IoResourceRequirementList; } FilterResourceRequirements;
        struct { ULONG WhichSpace; uint32_t _p0; PVOID Buffer; ULONG Offset; uint32_t _p1; ULONG Length; } ReadWriteConfig;
        struct { ULONG DeviceTextType; uint32_t _p0; ULONG LocaleId; } QueryDeviceText;
        struct { BOOLEAN InPath, Reserved[3]; uint32_t _p0; ULONG Type; } UsageNotification;
    } Parameters;
    PDEVICE_OBJECT DeviceObject;
    struct _FILE_OBJECT *FileObject;
    PIO_COMPLETION_ROUTINE CompletionRoutine;
    PVOID Context;
} IO_STACK_LOCATION, *PIO_STACK_LOCATION;

typedef struct _IRP {
    CSHORT Type;
    USHORT Size;
    PMDL MdlAddress;
    ULONG Flags;
    uint32_t _pad0;
    union { struct _IRP *MasterIrp; LONG IrpCount; PVOID SystemBuffer; } AssociatedIrp;
    LIST_ENTRY ThreadListEntry;
    IO_STATUS_BLOCK IoStatus;
    KPROCESSOR_MODE RequestorMode;
    BOOLEAN PendingReturned;
    CCHAR StackCount;
    CCHAR CurrentLocation;
    BOOLEAN Cancel;
    KIRQL CancelIrql;
    CCHAR ApcEnvironment;
    UCHAR AllocationFlags;
    PIO_STATUS_BLOCK UserIosb;
    PKEVENT UserEvent;
    union { struct { PVOID UserApcRoutine, UserApcContext; } AsynchronousParameters; LARGE_INTEGER AllocationSize; } Overlay;
    PDRIVER_CANCEL CancelRoutine;
    PVOID UserBuffer;
    union {
        struct {
            union { KDEVICE_QUEUE_ENTRY DeviceQueueEntry; PVOID DriverContext[4]; };
            PVOID Thread;
            char *AuxiliaryBuffer;
            struct { LIST_ENTRY ListEntry; union { PIO_STACK_LOCATION CurrentStackLocation; ULONG PacketType; }; };
            struct _FILE_OBJECT *OriginalFileObject;
        } Overlay;
        uint8_t Apc[0x58];
    } Tail;
} IRP, *PIRP;

typedef struct _FILE_OBJECT {
    CSHORT Type;
    CSHORT Size;
    PDEVICE_OBJECT DeviceObject;
    PVOID Vpb;
    PVOID FsContext, FsContext2;
    PVOID SectionObjectPointer;
    PVOID PrivateCacheMap;
    NTSTATUS FinalStatus;
    struct _FILE_OBJECT *RelatedFileObject;
    BOOLEAN LockOperation, DeletePending, ReadAccess, WriteAccess, DeleteAccess, SharedRead, SharedWrite, SharedDelete;
    ULONG Flags;
    UNICODE_STRING FileName;
    LARGE_INTEGER CurrentByteOffset;
} FILE_OBJECT, *PFILE_OBJECT;

/* IRP method codes and access (from CTL_CODE). */
#define METHOD_BUFFERED 0u
#define METHOD_IN_DIRECT 1u
#define METHOD_OUT_DIRECT 2u
#define METHOD_NEITHER 3u
#define METHOD_FROM_CTL_CODE(c) ((ULONG)((c) & 3))

#define IRP_MJ_CREATE 0x00
#define IRP_MJ_CLEANUP_ 0x12
#define IRP_MJ_SYSTEM_CONTROL 0x17
#define IRP_MN_START_DEVICE 0x00
#define IRP_MN_QUERY_REMOVE_DEVICE 0x01
#define IRP_MN_REMOVE_DEVICE 0x02
#define IRP_MN_CANCEL_REMOVE_DEVICE 0x03
#define IRP_MN_STOP_DEVICE 0x04
#define IRP_MN_QUERY_STOP_DEVICE 0x05
#define IRP_MN_CANCEL_STOP_DEVICE 0x06
#define IRP_MN_QUERY_DEVICE_RELATIONS 0x07
#define IRP_MN_QUERY_INTERFACE 0x08
#define IRP_MN_QUERY_CAPABILITIES 0x09
#define IRP_MN_QUERY_RESOURCES 0x0a
#define IRP_MN_QUERY_RESOURCE_REQUIREMENTS 0x0b
#define IRP_MN_QUERY_DEVICE_TEXT 0x0c
#define IRP_MN_FILTER_RESOURCE_REQUIREMENTS 0x0d
#define IRP_MN_READ_CONFIG 0x0f
#define IRP_MN_WRITE_CONFIG 0x10
#define IRP_MN_EJECT 0x11
#define IRP_MN_SET_LOCK 0x12
#define IRP_MN_QUERY_PNP_DEVICE_STATE 0x14
#define IRP_MN_QUERY_BUS_INFORMATION 0x15
#define IRP_MN_DEVICE_USAGE_NOTIFICATION 0x16
#define IRP_MN_SURPRISE_REMOVAL 0x17
#define IRP_MN_REGINFO 0x08                 /* IRP_MJ_SYSTEM_CONTROL (WMI) */
#define IRP_MN_QUERY_ID 0x13
#define IRP_MN_SET_POWER 0x02
#define IRP_MN_QUERY_POWER 0x03
#define IRP_MJ_CLOSE 0x02
#define IRP_MJ_READ 0x03
#define IRP_MJ_WRITE 0x04
#define IRP_MJ_DEVICE_CONTROL 0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL 0x0f
#define IRP_MJ_CLEANUP 0x12
#define IRP_MJ_PNP 0x1b
#define IRP_MJ_POWER 0x16
#define IRP_MJ_SHUTDOWN 0x10

/* IRP flags (subset). */
#define IRP_NOCACHE 0x00000001
#define IRP_BUFFERED_IO 0x00000010
#define IRP_DEALLOCATE_BUFFER 0x00000020
#define IRP_INPUT_OPERATION 0x00000040

#define IO_NO_INCREMENT 0
#define IO_NETWORK_INCREMENT 2

/* NTSTATUS reused from ntsys.h at the .c level (same numeric values). */

/* This side of the ABI contract: our structs must land on the shared offsets. The other
 * side (Microsoft's wdm.h) is checked against the same numbers by ntddk_abi_check.c. */
#include "ntddk_abi.h"
#include <stddef.h>
_Static_assert(sizeof(IRP) == SZ_IRP, "IRP size");
_Static_assert(offsetof(IRP, MdlAddress) == OFF_IRP_MDLADDRESS, "irp mdl");
_Static_assert(offsetof(IRP, Flags) == OFF_IRP_FLAGS, "irp flags");
_Static_assert(offsetof(IRP, AssociatedIrp.SystemBuffer) == OFF_IRP_SYSTEMBUFFER, "irp sysbuf");
_Static_assert(offsetof(IRP, IoStatus) == OFF_IRP_IOSTATUS, "irp iostatus");
_Static_assert(offsetof(IRP, IoStatus.Information) == OFF_IRP_IOSTATUS_INFO, "irp info");
_Static_assert(offsetof(IRP, RequestorMode) == OFF_IRP_REQUESTORMODE, "irp reqmode");
_Static_assert(offsetof(IRP, StackCount) == OFF_IRP_STACKCOUNT, "irp stackcount");
_Static_assert(offsetof(IRP, CurrentLocation) == OFF_IRP_CURRENTLOCATION, "irp curloc");
_Static_assert(offsetof(IRP, UserIosb) == OFF_IRP_USERIOSB, "irp useriosb");
_Static_assert(offsetof(IRP, UserEvent) == OFF_IRP_USEREVENT, "irp userevent");
_Static_assert(offsetof(IRP, CancelRoutine) == OFF_IRP_CANCELROUTINE, "irp cancel");
_Static_assert(offsetof(IRP, UserBuffer) == OFF_IRP_USERBUFFER, "irp userbuf");
_Static_assert(offsetof(IRP, Tail.Overlay.Thread) == OFF_IRP_TAIL_THREAD, "irp thread");
_Static_assert(offsetof(IRP, Tail.Overlay.ListEntry) == OFF_IRP_TAIL_LISTENTRY, "irp listentry");
_Static_assert(offsetof(IRP, Tail.Overlay.CurrentStackLocation) == OFF_IRP_TAIL_CURRENTSTACK, "irp curstk");
_Static_assert(sizeof(IO_STACK_LOCATION) == SZ_STK, "stk size");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters) == OFF_STK_PARAMETERS, "stk params");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.DeviceIoControl.OutputBufferLength) == OFF_STK_IOCTL_OUTLEN, "stk out");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.DeviceIoControl.InputBufferLength) == OFF_STK_IOCTL_INLEN, "stk in");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.DeviceIoControl.IoControlCode) == OFF_STK_IOCTL_CODE, "stk code");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.DeviceIoControl.Type3InputBuffer) == OFF_STK_IOCTL_TYPE3, "stk t3");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.Read.Length) == OFF_STK_READ_LENGTH, "stk rdlen");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.Read.ByteOffset) == OFF_STK_READ_BYTEOFFSET, "stk rdoff");
_Static_assert(offsetof(IO_STACK_LOCATION, DeviceObject) == OFF_STK_DEVICEOBJECT, "stk devobj");
_Static_assert(offsetof(IO_STACK_LOCATION, FileObject) == OFF_STK_FILEOBJECT, "stk fileobj");
_Static_assert(offsetof(IO_STACK_LOCATION, CompletionRoutine) == OFF_STK_COMPLETIONROUTINE, "stk complete");
_Static_assert(sizeof(DRIVER_OBJECT) == SZ_DRV, "drv size");
_Static_assert(offsetof(DRIVER_OBJECT, DriverExtension) == OFF_DRV_DRIVEREXTENSION, "drv ext");
_Static_assert(offsetof(DRIVER_OBJECT, DriverInit) == OFF_DRV_DRIVERINIT, "drv init");
_Static_assert(offsetof(DRIVER_OBJECT, DriverUnload) == OFF_DRV_DRIVERUNLOAD, "drv unload");
_Static_assert(offsetof(DRIVER_OBJECT, MajorFunction) == OFF_DRV_MAJORFUNCTION, "drv major");
_Static_assert(sizeof(DEVICE_OBJECT) == SZ_DEV, "dev size");
_Static_assert(offsetof(DEVICE_OBJECT, DeviceExtension) == OFF_DEV_DEVICEEXTENSION, "dev ext");
_Static_assert(offsetof(DEVICE_OBJECT, DeviceType) == OFF_DEV_DEVICETYPE, "dev type");
_Static_assert(offsetof(DEVICE_OBJECT, StackSize) == OFF_DEV_STACKSIZE, "dev stacksize");
_Static_assert(offsetof(DEVICE_OBJECT, Flags) == OFF_DEV_FLAGS, "dev flags");
_Static_assert(sizeof(MDL) == SZ_MDL, "mdl size");
_Static_assert(offsetof(MDL, MappedSystemVa) == OFF_MDL_MAPPEDSYSTEMVA, "mdl sysva");
_Static_assert(offsetof(MDL, ByteCount) == OFF_MDL_BYTECOUNT, "mdl count");
_Static_assert(offsetof(MDL, ByteOffset) == OFF_MDL_BYTEOFFSET, "mdl offset");
_Static_assert(offsetof(UNICODE_STRING, Buffer) == OFF_USTR_BUFFER, "ustr buf");
_Static_assert(offsetof(KDPC, DeferredRoutine) == OFF_KDPC_DEFERREDROUTINE, "kdpc routine");
_Static_assert(offsetof(KDPC, DeferredContext) == OFF_KDPC_DEFERREDCONTEXT, "kdpc ctx");
_Static_assert(offsetof(KEVENT, Header.SignalState) == OFF_KEVENT_SIGNALSTATE, "kevent signal");
_Static_assert(sizeof(KTIMER) == 0x40 && sizeof(KEVENT) == 0x18 && sizeof(KSEMAPHORE) == 0x20, "ke sizes");
_Static_assert(offsetof(DEVICE_OBJECT, Queue) == OFF_DEV_QUEUE, "dev queue");
_Static_assert(offsetof(DEVICE_OBJECT, AlignmentRequirement) == OFF_DEV_ALIGNMENT, "dev align");
_Static_assert(offsetof(DEVICE_OBJECT, DeviceQueue) == OFF_DEV_DEVICEQUEUE, "dev devqueue");
_Static_assert(offsetof(DEVICE_OBJECT, Dpc) == OFF_DEV_DPC, "dev dpc");
_Static_assert(offsetof(DEVICE_OBJECT, ActiveThreadCount) == OFF_DEV_ACTIVETHREADS, "dev threads");
_Static_assert(offsetof(DEVICE_OBJECT, SecurityDescriptor) == OFF_DEV_SECURITY, "dev sd");
_Static_assert(offsetof(DEVICE_OBJECT, DeviceLock) == OFF_DEV_DEVICELOCK, "dev lock");
_Static_assert(offsetof(DEVICE_OBJECT, SectorSize) == OFF_DEV_SECTORSIZE, "dev sector");
_Static_assert(offsetof(DEVICE_OBJECT, DeviceObjectExtension) == OFF_DEV_DEVOBJEXT, "dev ext");
_Static_assert(sizeof(KDEVICE_QUEUE) == SZ_KDEVICE_QUEUE && offsetof(KDEVICE_QUEUE, Lock) == 0x18 && offsetof(KDEVICE_QUEUE, Busy) == 0x20, "kdevq");
_Static_assert(sizeof(KDEVICE_QUEUE_ENTRY) == SZ_KDEVICE_QUEUE_ENTRY, "kdevqe");
_Static_assert(offsetof(IRP, Tail.Overlay.DeviceQueueEntry) == OFF_IRP_TAIL_DEVQUEUE, "irp devq");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.Power.Type) == OFF_STK_POWER_TYPE, "stk power type");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.Power.State) == OFF_STK_POWER_STATE, "stk power state");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.Power.ShutdownType) == OFF_STK_POWER_SHUTDOWN, "stk power shutdown");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.StartDevice.AllocatedResourcesTranslated) == OFF_STK_START_TRANSLATED, "stk start");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.QueryInterface.Version) == OFF_STK_QI_VERSION, "stk qi ver");
_Static_assert(offsetof(IO_STACK_LOCATION, Parameters.QueryInterface.InterfaceSpecificData) == OFF_STK_QI_SPECIFIC, "stk qi data");
_Static_assert(sizeof(DRIVER_EXTENSION) == SZ_DRIVER_EXTENSION, "drvext");
#endif
