/* SPDX-License-Identifier: GPL-2.0-only
 * Single source of truth for the Windows x64 driver-ABI offsets the driver host relies on.
 * kernel64/ntddk.h asserts its own structs against these numbers (checked by the Linux gcc
 * kernel build); win64/tools/ntddk_abi_check.c asserts Microsoft's <ddk/wdm.h> structs
 * against the same numbers (checked by the mingw build). Agreement on both sides == agreement
 * with Windows. Any drift fails a build; nothing is assumed.
 */
#ifndef K64_NTDDK_ABI_H
#define K64_NTDDK_ABI_H

#define OFF_IRP_MDLADDRESS        0x08
#define OFF_IRP_FLAGS             0x10
#define OFF_IRP_SYSTEMBUFFER      0x18
#define OFF_IRP_IOSTATUS          0x30
#define OFF_IRP_IOSTATUS_INFO     0x38
#define OFF_IRP_REQUESTORMODE     0x40
#define OFF_IRP_PENDINGRETURNED   0x41
#define OFF_IRP_STACKCOUNT        0x42
#define OFF_IRP_CURRENTLOCATION   0x43
#define OFF_IRP_CANCEL            0x44
#define OFF_IRP_USERIOSB          0x48
#define OFF_IRP_USEREVENT         0x50
#define OFF_IRP_CANCELROUTINE     0x68
#define OFF_IRP_USERBUFFER        0x70
#define OFF_IRP_TAIL_THREAD       0x98
#define OFF_IRP_TAIL_LISTENTRY    0xa8
#define OFF_IRP_TAIL_CURRENTSTACK 0xb8
#define SZ_IRP                    0xd0

#define OFF_STK_MAJORFUNCTION     0x00
#define OFF_STK_MINORFUNCTION     0x01
#define OFF_STK_PARAMETERS        0x08
#define OFF_STK_IOCTL_OUTLEN      0x08
#define OFF_STK_IOCTL_INLEN       0x10
#define OFF_STK_IOCTL_CODE        0x18
#define OFF_STK_IOCTL_TYPE3       0x20
#define OFF_STK_READ_LENGTH       0x08
#define OFF_STK_READ_BYTEOFFSET   0x18
#define OFF_STK_DEVICEOBJECT      0x28
#define OFF_STK_FILEOBJECT        0x30
#define OFF_STK_COMPLETIONROUTINE 0x38
#define OFF_STK_CONTEXT           0x40
#define SZ_STK                    0x48

#define OFF_DRV_DEVICEOBJECT      0x08
#define OFF_DRV_DRIVEREXTENSION   0x30
#define OFF_DRV_DRIVERNAME        0x38
#define OFF_DRV_DRIVERINIT        0x58
#define OFF_DRV_DRIVERSTARTIO     0x60
#define OFF_DRV_DRIVERUNLOAD      0x68
#define OFF_DRV_MAJORFUNCTION     0x70
#define SZ_DRV                    0x150

#define OFF_DEV_DRIVEROBJECT      0x08
#define OFF_DEV_NEXTDEVICE        0x10
#define OFF_DEV_ATTACHEDDEVICE    0x18
#define OFF_DEV_FLAGS             0x30
#define OFF_DEV_CHARACTERISTICS   0x34
#define OFF_DEV_DEVICEEXTENSION   0x40
#define OFF_DEV_DEVICETYPE        0x48
#define OFF_DEV_STACKSIZE         0x4c
#define OFF_DEV_QUEUE             0x50
#define OFF_DEV_ALIGNMENT         0x98
#define OFF_DEV_DEVICEQUEUE       0xa0
#define OFF_DEV_DPC               0xc8
#define OFF_DEV_ACTIVETHREADS     0x108
#define OFF_DEV_SECURITY          0x110
#define OFF_DEV_DEVICELOCK        0x118
#define OFF_DEV_SECTORSIZE        0x130
#define OFF_DEV_DEVOBJEXT         0x138
#define SZ_DEV                    0x148
#define SZ_KDEVICE_QUEUE          0x28
#define SZ_KDEVICE_QUEUE_ENTRY    0x18
#define OFF_IRP_TAIL_DEVQUEUE     0x78
#define OFF_STK_POWER_TYPE        0x10
#define OFF_STK_POWER_STATE       0x18
#define OFF_STK_POWER_SHUTDOWN    0x20
#define OFF_STK_START_TRANSLATED  0x10
#define OFF_STK_QI_VERSION        0x12
#define OFF_STK_QI_SPECIFIC       0x20
#define SZ_DRIVER_EXTENSION       0x28
/* Structures the providers hand to or take from a driver (checked on the DDK side only; the host builds them by
 * offset arithmetic where it does not declare a struct). */
#define SZ_CM_PARTIAL_RESOURCE_DESCRIPTOR 0x14
#define SZ_CM_PARTIAL_RESOURCE_LIST 0x1c
#define SZ_CM_FULL_RESOURCE_DESCRIPTOR 0x24
#define SZ_CM_RESOURCE_LIST       0x28
#define SZ_IO_RESOURCE_DESCRIPTOR 0x20
#define SZ_IO_RESOURCE_LIST       0x28
#define SZ_IO_RESOURCE_REQUIREMENTS_LIST 0x48
#define SZ_RTL_QUERY_REGISTRY_TABLE 0x38
#define SZ_IO_REMOVE_LOCK_COMMON  0x20
#define SZ_NPAGED_LOOKASIDE_LIST  0x80
#define OFF_LOOKASIDE_ALLOCATE    0x30
#define OFF_LOOKASIDE_FREE        0x38
#define OFF_LOOKASIDE_DEPTH       0x10
#define OFF_LOOKASIDE_TAG         0x28
#define OFF_LOOKASIDE_SIZE        0x2c
#define SZ_ERESOURCE              0x68
#define SZ_FAST_MUTEX             0x38
#define SZ_KGUARDED_MUTEX         0x38
#define SZ_WORK_QUEUE_ITEM        0x20
#define OFF_WORK_QUEUE_ITEM_ROUTINE 0x10
#define SZ_DMA_ADAPTER            0x10
#define SZ_DMA_OPERATIONS         0x80
#define SZ_DEVICE_DESCRIPTION     0x28
#define SZ_SCATTER_GATHER_LIST    0x28
#define SZ_SCATTER_GATHER_ELEMENT 0x18
#define SZ_IO_ERROR_LOG_PACKET    0x30
#define OFF_ERRLOG_ERRORCODE      0x0c
#define OFF_ERRLOG_FINALSTATUS    0x14
#define OFF_ERRLOG_DUMPDATA       0x28
#define SZ_CONFIGURATION_INFORMATION 0x28
#define OFF_KEY_VALUE_FULL_NAME   0x14
#define OFF_KEY_BASIC_NAME        0x10
#define OFF_KEY_NODE_NAME         0x18
#define SZ_KEY_FULL_INFORMATION   0x30
#define SZ_DEVICE_INTERFACE_CHANGE_NOTIFICATION 0x30
#define SZ_RTL_OSVERSIONINFOEXW   0x11c
#define SZ_SLIST_HEADER           0x10
#define SZ_KLOCK_QUEUE_HANDLE     0x18
#define SZ_TIME_FIELDS            0x10

#define OFF_MDL_MAPPEDSYSTEMVA    0x18
#define OFF_MDL_STARTVA           0x20
#define OFF_MDL_BYTECOUNT         0x28
#define OFF_MDL_BYTEOFFSET        0x2c
#define SZ_MDL                    0x30

#define OFF_USTR_BUFFER           0x08
#define OFF_KDPC_DEFERREDROUTINE  0x18
#define OFF_KDPC_DEFERREDCONTEXT  0x20
#define OFF_KEVENT_SIGNALSTATE    0x04

#endif
