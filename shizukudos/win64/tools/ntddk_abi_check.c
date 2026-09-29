/* SPDX-License-Identifier: GPL-2.0-only
 * Build-time proof that the driver host's ABI numbers (kernel64/ntddk_abi.h) match
 * Microsoft's real <ddk/wdm.h> on x64. Compiled, not run, with mingw-w64: any mismatch is a
 * failed _Static_assert that stops the build. kernel64/ntddk.h asserts the SAME numbers
 * against the host's own structs (checked by the Linux kernel build), so passing both sides
 * means the host and Windows agree field-for-field. Nothing about the ABI is assumed.
 *
 *   x86_64-w64-mingw32-gcc -fsyntax-only -D_WIN64 -I<ddk> -I<kernel64> ntddk_abi_check.c
 */
#include <ddk/wdm.h>
#include <stddef.h>
#include "ntddk_abi.h"

#define CHK(expr, off) _Static_assert(offsetof expr == (off), #expr " != " #off)
#define CHKSZ(t, sz) _Static_assert(sizeof(t) == (sz), #t " size != " #sz)

CHKSZ(IRP, SZ_IRP);
CHK((IRP, MdlAddress), OFF_IRP_MDLADDRESS);
CHK((IRP, Flags), OFF_IRP_FLAGS);
CHK((IRP, AssociatedIrp.SystemBuffer), OFF_IRP_SYSTEMBUFFER);
CHK((IRP, IoStatus), OFF_IRP_IOSTATUS);
CHK((IRP, IoStatus.Information), OFF_IRP_IOSTATUS_INFO);
CHK((IRP, RequestorMode), OFF_IRP_REQUESTORMODE);
CHK((IRP, StackCount), OFF_IRP_STACKCOUNT);
CHK((IRP, CurrentLocation), OFF_IRP_CURRENTLOCATION);
CHK((IRP, UserIosb), OFF_IRP_USERIOSB);
CHK((IRP, UserEvent), OFF_IRP_USEREVENT);
CHK((IRP, CancelRoutine), OFF_IRP_CANCELROUTINE);
CHK((IRP, UserBuffer), OFF_IRP_USERBUFFER);
CHK((IRP, Tail.Overlay.Thread), OFF_IRP_TAIL_THREAD);
CHK((IRP, Tail.Overlay.ListEntry), OFF_IRP_TAIL_LISTENTRY);
CHK((IRP, Tail.Overlay.CurrentStackLocation), OFF_IRP_TAIL_CURRENTSTACK);

CHKSZ(IO_STACK_LOCATION, SZ_STK);
CHK((IO_STACK_LOCATION, Parameters), OFF_STK_PARAMETERS);
CHK((IO_STACK_LOCATION, Parameters.DeviceIoControl.OutputBufferLength), OFF_STK_IOCTL_OUTLEN);
CHK((IO_STACK_LOCATION, Parameters.DeviceIoControl.InputBufferLength), OFF_STK_IOCTL_INLEN);
CHK((IO_STACK_LOCATION, Parameters.DeviceIoControl.IoControlCode), OFF_STK_IOCTL_CODE);
CHK((IO_STACK_LOCATION, Parameters.DeviceIoControl.Type3InputBuffer), OFF_STK_IOCTL_TYPE3);
CHK((IO_STACK_LOCATION, Parameters.Read.Length), OFF_STK_READ_LENGTH);
CHK((IO_STACK_LOCATION, Parameters.Read.ByteOffset), OFF_STK_READ_BYTEOFFSET);
CHK((IO_STACK_LOCATION, DeviceObject), OFF_STK_DEVICEOBJECT);
CHK((IO_STACK_LOCATION, FileObject), OFF_STK_FILEOBJECT);
CHK((IO_STACK_LOCATION, CompletionRoutine), OFF_STK_COMPLETIONROUTINE);
CHK((IO_STACK_LOCATION, Context), OFF_STK_CONTEXT);

CHKSZ(DRIVER_OBJECT, SZ_DRV);
CHK((DRIVER_OBJECT, DeviceObject), OFF_DRV_DEVICEOBJECT);
CHK((DRIVER_OBJECT, DriverExtension), OFF_DRV_DRIVEREXTENSION);
CHK((DRIVER_OBJECT, DriverName), OFF_DRV_DRIVERNAME);
CHK((DRIVER_OBJECT, DriverInit), OFF_DRV_DRIVERINIT);
CHK((DRIVER_OBJECT, DriverStartIo), OFF_DRV_DRIVERSTARTIO);
CHK((DRIVER_OBJECT, DriverUnload), OFF_DRV_DRIVERUNLOAD);
CHK((DRIVER_OBJECT, MajorFunction), OFF_DRV_MAJORFUNCTION);

CHKSZ(DEVICE_OBJECT, SZ_DEV);
CHK((DEVICE_OBJECT, DriverObject), OFF_DEV_DRIVEROBJECT);
CHK((DEVICE_OBJECT, NextDevice), OFF_DEV_NEXTDEVICE);
CHK((DEVICE_OBJECT, AttachedDevice), OFF_DEV_ATTACHEDDEVICE);
CHK((DEVICE_OBJECT, Flags), OFF_DEV_FLAGS);
CHK((DEVICE_OBJECT, Characteristics), OFF_DEV_CHARACTERISTICS);
CHK((DEVICE_OBJECT, DeviceExtension), OFF_DEV_DEVICEEXTENSION);
CHK((DEVICE_OBJECT, DeviceType), OFF_DEV_DEVICETYPE);
CHK((DEVICE_OBJECT, StackSize), OFF_DEV_STACKSIZE);

CHKSZ(MDL, SZ_MDL);
CHK((MDL, MappedSystemVa), OFF_MDL_MAPPEDSYSTEMVA);
CHK((MDL, StartVa), OFF_MDL_STARTVA);
CHK((MDL, ByteCount), OFF_MDL_BYTECOUNT);
CHK((MDL, ByteOffset), OFF_MDL_BYTEOFFSET);

CHK((UNICODE_STRING, Buffer), OFF_USTR_BUFFER);
CHK((KDPC, DeferredRoutine), OFF_KDPC_DEFERREDROUTINE);
CHK((KDPC, DeferredContext), OFF_KDPC_DEFERREDCONTEXT);
CHK((KEVENT, Header.SignalState), OFF_KEVENT_SIGNALSTATE);

int ntddk_abi_ok;
