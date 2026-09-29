/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the export tables the loader resolves a driver's imports against.
 * ntdrv_ntoskrnl_exports[] is what a driver importing from ntoskrnl.exe sees;
 * ntdrv_hal_exports[] is hal.dll. Each entry is a real provider implementation (ntdrv_*.c);
 * no name here is a placeholder. win64/tools/gen_ntoskrnl_exports.py parses this file to emit
 * the machine-readable export list the import-coverage tool consumes, so the measured surface
 * is exactly what the kernel provides.
 */
#include "ntdrv.h"

/* Address-only references; the real prototypes live in the provider translation units. */
#define D(n) extern void n(void);
/* ntoskrnl.exe */
D(KeGetCurrentIrql) D(KeRaiseIrql) D(KeLowerIrql) D(KeRaiseIrqlToDpcLevel) D(KeRaiseIrqlToSynchLevel)
D(KeInitializeSpinLock) D(KeAcquireSpinLock) D(KeReleaseSpinLock) D(KeAcquireSpinLockAtDpcLevel)
D(KeReleaseSpinLockFromDpcLevel) D(KeAcquireSpinLockRaiseToDpc)
D(KeInitializeDpc) D(KeInitializeThreadedDpc) D(KeInsertQueueDpc) D(KeRemoveQueueDpc)
D(KeClearEvent) D(KeResetEvent) D(KeReadStateEvent)      /* KeInitializeEvent/KeSetEvent: prototyped in ntdrv.h */
D(KeInitializeSemaphore) D(KeReleaseSemaphore) D(KeReadStateSemaphore)
D(KeInitializeMutex) D(KeReleaseMutex)
D(KeWaitForMultipleObjects)                              /* KeWaitForSingleObject: prototyped in ntdrv.h */
D(KeInitializeTimer) D(KeInitializeTimerEx) D(KeSetTimer) D(KeSetTimerEx) D(KeCancelTimer) D(KeReadStateTimer)
D(KeQuerySystemTime) D(KeQuerySystemTimePrecise) D(KeQueryPerformanceCounter) D(KeQueryTimeIncrement)
D(KeQueryInterruptTime) D(KeDelayExecutionThread) D(KeStallExecutionProcessor)
D(KeGetCurrentProcessorNumber) D(KeGetCurrentProcessorNumberEx) D(KeQueryActiveProcessorCount)
D(KeQueryMaximumProcessorCount) D(KeGetCurrentThread) D(KeBugCheckEx) D(KeBugCheck)
D(KeSynchronizeExecution) D(KeInitializeDeviceQueue) D(KfRaiseIrql) D(KfLowerIrql)
D(KfAcquireSpinLock) D(KfReleaseSpinLock)
D(InterlockedIncrement) D(InterlockedDecrement) D(InterlockedExchange) D(InterlockedExchangeAdd)
D(InterlockedCompareExchange) D(InterlockedCompareExchange64) D(InterlockedExchangePointer)
D(InterlockedCompareExchangePointer)
D(ExInitializeFastMutex) D(ExAcquireFastMutex) D(ExReleaseFastMutex) D(ExTryToAcquireFastMutex)
D(ExAllocatePool) D(ExAllocatePoolWithTag) D(ExAllocatePoolWithTagPriority) D(ExAllocatePoolUninitialized)
D(ExAllocatePool2) D(ExFreePool) D(ExFreePoolWithTag) D(ExInitializeSListHead)
D(MmGetPhysicalAddress) D(MmMapIoSpace) D(MmMapIoSpaceEx) D(MmUnmapIoSpace)
D(MmAllocateContiguousMemory) D(MmAllocateContiguousMemorySpecifyCache) D(MmFreeContiguousMemory)
D(MmFreeContiguousMemorySpecifyCache) D(MmAllocateNonCachedMemory) D(MmFreeNonCachedMemory) D(MmIsAddressValid)
D(IoFreeMdl) D(MmBuildMdlForNonPagedPool) D(MmProbeAndLockPages) D(MmUnlockPages)  /* IoAllocateMdl: ntdrv.h */
D(MmMapLockedPages) D(MmMapLockedPagesSpecifyCache) D(MmUnmapLockedPages) D(MmGetSystemAddressForMdlSafe)
D(MmGetMdlByteCount) D(MmGetMdlVirtualAddress) D(MmSizeOfMdl) D(MmInitializeMdl)
D(RtlCopyMemory) D(RtlMoveMemory) D(RtlZeroMemory) D(RtlFillMemory) D(RtlSecureZeroMemory)
D(RtlCompareMemory) D(RtlCompareMemoryUlong)
D(RtlInitUnicodeString) D(RtlInitAnsiString) D(RtlUnicodeStringToAnsiString) D(RtlAnsiStringToUnicodeString)
D(RtlFreeUnicodeString) D(RtlFreeAnsiString) D(RtlCopyUnicodeString) D(RtlCompareUnicodeString)
D(RtlEqualUnicodeString) D(RtlAppendUnicodeToString) D(RtlAppendUnicodeStringToString)
D(RtlIntegerToUnicodeString) D(RtlxUnicodeStringToAnsiSize) D(RtlGetVersion)
D(DbgPrint) D(DbgPrintEx) D(vDbgPrintEx) D(DbgBreakPoint)
D(PsCreateSystemThread) D(PsTerminateSystemThread) D(PsGetCurrentThread) D(PsGetCurrentThreadId)
D(PsGetCurrentProcessId)
D(READ_REGISTER_UCHAR) D(READ_REGISTER_USHORT) D(READ_REGISTER_ULONG)
D(WRITE_REGISTER_UCHAR) D(WRITE_REGISTER_USHORT) D(WRITE_REGISTER_ULONG)
D(IoCreateDevice) D(IoCreateDeviceSecure) D(IoDeleteDevice) D(IoCreateSymbolicLink) D(IoDeleteSymbolicLink)
D(IoAttachDeviceToDeviceStack) D(IoDetachDevice) D(IoGetAttachedDeviceReference) D(IoGetAttachedDevice)
D(IoInitializeIrp) D(IoAllocateIrp) D(IoFreeIrp) D(IofCallDriver) D(IofCompleteRequest)
D(IoGetRemainingStackSize) D(IoGetRelatedDeviceObject)
D(IoBuildDeviceIoControlRequest) D(IoBuildSynchronousFsdRequest) D(IoConnectInterrupt) D(IoDisconnectInterrupt)
D(IoAllocateWorkItem) D(IoFreeWorkItem) D(IoQueueWorkItem)
D(ZwOpenKey) D(ZwCreateKey) D(ZwQueryValueKey) D(ZwSetValueKey) D(ZwClose)
D(ZwCreateFile) D(ZwReadFile) D(ZwWriteFile)
D(ObReferenceObjectByHandle) D(ObDereferenceObject) D(ObfDereferenceObject) D(ObfReferenceObject)
extern void *ntdrv_memcpy(void *, const void *, uint64_t);
extern void *ntdrv_memset(void *, int, uint64_t);
extern void *ntdrv_memmove(void *, const void *, uint64_t);
/* hal.dll */
D(READ_PORT_UCHAR) D(READ_PORT_USHORT) D(READ_PORT_ULONG)
D(WRITE_PORT_UCHAR) D(WRITE_PORT_USHORT) D(WRITE_PORT_ULONG)
D(HalGetBusData) D(HalGetBusDataByOffset) D(HalSetBusDataByOffset) D(HalGetInterruptVector)

#define E(n) { #n, (void *)n }
const ntdrv_export_t ntdrv_ntoskrnl_exports[] = {
    E(KeGetCurrentIrql), E(KeRaiseIrql), E(KeLowerIrql), E(KeRaiseIrqlToDpcLevel), E(KeRaiseIrqlToSynchLevel),
    E(KeInitializeSpinLock), E(KeAcquireSpinLock), E(KeReleaseSpinLock), E(KeAcquireSpinLockAtDpcLevel),
    E(KeReleaseSpinLockFromDpcLevel), E(KeAcquireSpinLockRaiseToDpc),
    E(KeInitializeDpc), E(KeInitializeThreadedDpc), E(KeInsertQueueDpc), E(KeRemoveQueueDpc),
    E(KeInitializeEvent), E(KeClearEvent), E(KeResetEvent), E(KeReadStateEvent), E(KeSetEvent),
    E(KeInitializeSemaphore), E(KeReleaseSemaphore), E(KeReadStateSemaphore),
    E(KeInitializeMutex), E(KeReleaseMutex),
    E(KeWaitForSingleObject), E(KeWaitForMultipleObjects),
    E(KeInitializeTimer), E(KeInitializeTimerEx), E(KeSetTimer), E(KeSetTimerEx), E(KeCancelTimer), E(KeReadStateTimer),
    E(KeQuerySystemTime), E(KeQuerySystemTimePrecise), E(KeQueryPerformanceCounter), E(KeQueryTimeIncrement),
    E(KeQueryInterruptTime), E(KeDelayExecutionThread), E(KeStallExecutionProcessor),
    E(KeGetCurrentProcessorNumber), E(KeGetCurrentProcessorNumberEx), E(KeQueryActiveProcessorCount),
    E(KeQueryMaximumProcessorCount), E(KeGetCurrentThread), E(KeBugCheckEx), E(KeBugCheck),
    E(KeSynchronizeExecution), E(KeInitializeDeviceQueue), E(KfRaiseIrql), E(KfLowerIrql),
    E(KfAcquireSpinLock), E(KfReleaseSpinLock),
    E(InterlockedIncrement), E(InterlockedDecrement), E(InterlockedExchange), E(InterlockedExchangeAdd),
    E(InterlockedCompareExchange), E(InterlockedCompareExchange64), E(InterlockedExchangePointer),
    E(InterlockedCompareExchangePointer),
    E(ExInitializeFastMutex), E(ExAcquireFastMutex), E(ExReleaseFastMutex), E(ExTryToAcquireFastMutex),
    E(ExAllocatePool), E(ExAllocatePoolWithTag), E(ExAllocatePoolWithTagPriority), E(ExAllocatePoolUninitialized),
    E(ExAllocatePool2), E(ExFreePool), E(ExFreePoolWithTag), E(ExInitializeSListHead),
    E(MmGetPhysicalAddress), E(MmMapIoSpace), E(MmMapIoSpaceEx), E(MmUnmapIoSpace),
    E(MmAllocateContiguousMemory), E(MmAllocateContiguousMemorySpecifyCache), E(MmFreeContiguousMemory),
    E(MmFreeContiguousMemorySpecifyCache), E(MmAllocateNonCachedMemory), E(MmFreeNonCachedMemory), E(MmIsAddressValid),
    E(IoAllocateMdl), E(IoFreeMdl), E(MmBuildMdlForNonPagedPool), E(MmProbeAndLockPages), E(MmUnlockPages),
    E(MmMapLockedPages), E(MmMapLockedPagesSpecifyCache), E(MmUnmapLockedPages), E(MmGetSystemAddressForMdlSafe),
    E(MmGetMdlByteCount), E(MmGetMdlVirtualAddress), E(MmSizeOfMdl), E(MmInitializeMdl),
    E(RtlCopyMemory), E(RtlMoveMemory), E(RtlZeroMemory), E(RtlFillMemory), E(RtlSecureZeroMemory),
    E(RtlCompareMemory), E(RtlCompareMemoryUlong),
    { "memcpy", (void *)ntdrv_memcpy }, { "memset", (void *)ntdrv_memset }, { "memmove", (void *)ntdrv_memmove },
    E(RtlInitUnicodeString), E(RtlInitAnsiString), E(RtlUnicodeStringToAnsiString), E(RtlAnsiStringToUnicodeString),
    E(RtlFreeUnicodeString), E(RtlFreeAnsiString), E(RtlCopyUnicodeString), E(RtlCompareUnicodeString),
    E(RtlEqualUnicodeString), E(RtlAppendUnicodeToString), E(RtlAppendUnicodeStringToString),
    E(RtlIntegerToUnicodeString), E(RtlxUnicodeStringToAnsiSize), E(RtlGetVersion),
    E(DbgPrint), E(DbgPrintEx), E(vDbgPrintEx), E(DbgBreakPoint),
    E(PsCreateSystemThread), E(PsTerminateSystemThread), E(PsGetCurrentThread), E(PsGetCurrentThreadId),
    E(PsGetCurrentProcessId),
    E(READ_REGISTER_UCHAR), E(READ_REGISTER_USHORT), E(READ_REGISTER_ULONG),
    E(WRITE_REGISTER_UCHAR), E(WRITE_REGISTER_USHORT), E(WRITE_REGISTER_ULONG),
    E(IoCreateDevice), E(IoCreateDeviceSecure), E(IoDeleteDevice), E(IoCreateSymbolicLink), E(IoDeleteSymbolicLink),
    E(IoAttachDeviceToDeviceStack), E(IoDetachDevice), E(IoGetAttachedDeviceReference), E(IoGetAttachedDevice),
    E(IoInitializeIrp), E(IoAllocateIrp), E(IoFreeIrp), E(IofCallDriver), E(IofCompleteRequest),
    E(IoGetRemainingStackSize), E(IoGetRelatedDeviceObject),
    E(IoBuildDeviceIoControlRequest), E(IoBuildSynchronousFsdRequest), E(IoConnectInterrupt), E(IoDisconnectInterrupt),
    E(IoAllocateWorkItem), E(IoFreeWorkItem), E(IoQueueWorkItem),
    E(ZwOpenKey), E(ZwCreateKey), E(ZwQueryValueKey), E(ZwSetValueKey), E(ZwClose),
    E(ZwCreateFile), E(ZwReadFile), E(ZwWriteFile),
    E(ObReferenceObjectByHandle), E(ObDereferenceObject), E(ObfDereferenceObject), E(ObfReferenceObject),
    { 0, 0 }
};

const ntdrv_export_t ntdrv_hal_exports[] = {
    E(READ_PORT_UCHAR), E(READ_PORT_USHORT), E(READ_PORT_ULONG),
    E(WRITE_PORT_UCHAR), E(WRITE_PORT_USHORT), E(WRITE_PORT_ULONG),
    E(HalGetBusData), E(HalGetBusDataByOffset), E(HalSetBusDataByOffset), E(HalGetInterruptVector),
    { 0, 0 }
};

static unsigned count(const ntdrv_export_t *t) { unsigned n = 0; while (t[n].name) ++n; return n; }
const unsigned ntdrv_ntoskrnl_export_count = sizeof ntdrv_ntoskrnl_exports / sizeof ntdrv_ntoskrnl_exports[0] - 1;
const unsigned ntdrv_hal_export_count = sizeof ntdrv_hal_exports / sizeof ntdrv_hal_exports[0] - 1;

static int ci_eq(const char *a, const char *b)
{
    for (; *a && *b; ++a, ++b) {
        char ca = *a >= 'A' && *a <= 'Z' ? (char)(*a + 32) : *a;
        char cb = *b >= 'A' && *b <= 'Z' ? (char)(*b + 32) : *b;
        if (ca != cb) return 0;
    }
    return *a == *b;
}

void *ntdrv_resolve_export(const char *dll, const char *symbol)
{
    const ntdrv_export_t *t;
    unsigned i;
    if (ci_eq(dll, "ntoskrnl.exe") || ci_eq(dll, "ntkrnlpa.exe") || ci_eq(dll, "ntkrnlmp.exe")) t = ntdrv_ntoskrnl_exports;
    else if (ci_eq(dll, "hal.dll")) t = ntdrv_hal_exports;
    else return 0;
    for (i = 0; t[i].name; ++i)
        if (!strcmp(t[i].name, symbol)) return t[i].fn;
    return 0;
    (void)count;
}
