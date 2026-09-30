/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 NT driver host: the export tables the loader resolves a driver's imports against.
 * ntdrv_ntoskrnl_exports[] is what a driver importing from ntoskrnl.exe sees;
 * ntdrv_hal_exports[] is hal.dll. Each entry is a real provider implementation (ntdrv_*.c);
 * no name here is a placeholder. win64/tools/gen_ntoskrnl_exports.py parses this file to emit
 * the machine-readable export list the import-coverage tool consumes, so the measured surface
 * is exactly what the kernel provides.
 *
 * Data exports (KeNumberProcessors, KiBugCheckData, the object-type pointers, the HAL dispatch
 * tables, KdComPortInUse, ...) resolve to the variable's address, exactly as ntoskrnl's export
 * directory does; a driver's __imp_ slot then points at the kernel's own variable.
 */
#include "ntdrv.h"

/* Address-only references; the real prototypes live in the provider translation units. */
#define D(n) extern void n(void);
/* ntoskrnl.exe: Ke (ntdrv_ke.c) */
D(KeGetCurrentIrql) D(KeRaiseIrql) D(KeLowerIrql) D(KeRaiseIrqlToDpcLevel) D(KeRaiseIrqlToSynchLevel)
D(KeInitializeSpinLock) D(KeAcquireSpinLockAtDpcLevel)      /* KeAcquire/ReleaseSpinLock: prototyped in ntdrv.h */
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
D(KeSynchronizeExecution) D(KfRaiseIrql) D(KfLowerIrql) D(KfAcquireSpinLock) D(KfReleaseSpinLock)
D(InterlockedIncrement) D(InterlockedDecrement) D(InterlockedExchange) D(InterlockedExchangeAdd)
D(InterlockedCompareExchange) D(InterlockedCompareExchange64) D(InterlockedExchangePointer)
D(InterlockedCompareExchangePointer)
/* Ke/Ex second batch (ntdrv_ex.c) */
D(KeEnterCriticalRegion) D(KeLeaveCriticalRegion) D(KeAreApcsDisabled) D(KeAreAllApcsDisabled) D(KeEnterGuardedRegion) D(KeLeaveGuardedRegion)
D(KeAcquireInStackQueuedSpinLock) D(KeReleaseInStackQueuedSpinLock) D(KeAcquireInStackQueuedSpinLockAtDpcLevel)
D(KeReleaseInStackQueuedSpinLockFromDpcLevel) D(KeTryToAcquireSpinLockAtDpcLevel) D(KeTestSpinLock)
D(KeFlushQueuedDpcs) D(KeQueryActiveProcessors) D(KeQueryActiveProcessorCountEx) D(KeQueryActiveGroupCount) D(KeQueryMaximumGroupCount)
D(KeQueryMaximumProcessorCountEx) D(KeGetRecommendedSharedDataAlignment) D(KeIpiGenericCall)
D(KeInitializeGuardedMutex) D(KeAcquireGuardedMutex) D(KeReleaseGuardedMutex) D(KeTryToAcquireGuardedMutex)
D(KeAcquireGuardedMutexUnsafe) D(KeReleaseGuardedMutexUnsafe)
D(KeRegisterBugCheckCallback) D(KeDeregisterBugCheckCallback) D(KeRegisterBugCheckReasonCallback) D(KeDeregisterBugCheckReasonCallback)
D(KdRefreshDebuggerNotPresent) D(KdEnableDebugger) D(KdDisableDebugger) D(KdSystemDebugControl) D(DbgBreakPointWithStatus)
D(ExInterlockedInsertTailList) D(ExInterlockedInsertHeadList) D(ExInterlockedRemoveHeadList) D(ExInterlockedRemoveTailList)
D(ExInterlockedPushEntryList) D(ExInterlockedPopEntryList) D(ExInterlockedAddUlong) D(ExInterlockedAddLargeInteger)
D(InitializeSListHead) D(ExQueryDepthSList) D(ExpInterlockedPushEntrySList) D(ExpInterlockedPopEntrySList) D(ExpInterlockedFlushSList)
D(ExInitializeNPagedLookasideList) D(ExInitializePagedLookasideList) D(ExDeleteNPagedLookasideList) D(ExDeletePagedLookasideList)
D(ExAllocatePoolWithQuotaTag)
D(ExInitializeResourceLite) D(ExReinitializeResourceLite) D(ExDeleteResourceLite) D(ExAcquireResourceExclusiveLite)
D(ExAcquireResourceSharedLite) D(ExAcquireSharedStarveExclusive) D(ExAcquireSharedWaitForExclusive) D(ExReleaseResourceForThreadLite)
D(ExReleaseResourceLite) D(ExIsResourceAcquiredExclusiveLite) D(ExIsResourceAcquiredSharedLite) D(ExGetExclusiveWaiterCount)
D(ExGetSharedWaiterCount) D(ExConvertExclusiveToSharedLite) D(ExEnterCriticalRegionAndAcquireResourceExclusive)
D(ExEnterCriticalRegionAndAcquireResourceShared) D(ExReleaseResourceAndLeaveCriticalRegion)
D(ExAcquireFastMutexUnsafe) D(ExReleaseFastMutexUnsafe)
D(ExCreateCallback) D(ExRegisterCallback) D(ExUnregisterCallback) D(ExNotifyCallback)
D(ExSizeOfRundownProtectionCacheAware) D(ExInitializeRundownProtectionCacheAware) D(ExReInitializeRundownProtectionCacheAware)
D(ExAcquireRundownProtectionCacheAware) D(ExAcquireRundownProtectionCacheAwareEx) D(ExReleaseRundownProtectionCacheAware)
D(ExReleaseRundownProtectionCacheAwareEx) D(ExWaitForRundownProtectionReleaseCacheAware) D(ExRundownCompletedCacheAware)
D(ExfInitializeRundownProtection) D(ExfAcquireRundownProtection) D(ExfReleaseRundownProtection) D(ExfWaitForRundownProtectionRelease)
D(ExfReInitializeRundownProtection) D(ExfRundownCompleted)
D(ExIsProcessorFeaturePresent) D(ExGetCurrentProcessorCounts) D(ExGetCurrentProcessorCpuUsage) D(ExQueueWorkItem)
/* Ex (ntdrv_ke.c) */
D(ExInitializeFastMutex) D(ExAcquireFastMutex) D(ExReleaseFastMutex) D(ExTryToAcquireFastMutex)
D(ExAllocatePool) D(ExAllocatePoolWithTag) D(ExAllocatePoolWithTagPriority) D(ExAllocatePoolUninitialized)
D(ExAllocatePool2) D(ExFreePool) D(ExFreePoolWithTag) D(ExInitializeSListHead)
/* Mm (ntdrv_mm.c, ntdrv_pnp.c) */
D(MmGetPhysicalAddress) D(MmMapIoSpace) D(MmMapIoSpaceEx) D(MmUnmapIoSpace)
D(MmAllocateContiguousMemory) D(MmAllocateContiguousMemorySpecifyCache) D(MmFreeContiguousMemory)
D(MmFreeContiguousMemorySpecifyCache) D(MmAllocateNonCachedMemory) D(MmFreeNonCachedMemory) D(MmIsAddressValid)
D(MmPageEntireDriver) D(MmResetDriverPaging)
D(IoFreeMdl) D(MmBuildMdlForNonPagedPool) D(MmProbeAndLockPages) D(MmProbeAndLockProcessPages) D(MmUnlockPages)  /* IoAllocateMdl: ntdrv.h */
D(MmMapLockedPages) D(MmMapLockedPagesSpecifyCache) D(MmUnmapLockedPages) D(MmGetSystemAddressForMdlSafe)
D(MmMapLockedPagesWithReservedMapping) D(MmUnmapReservedMapping) D(MmAllocateMappingAddress) D(MmFreeMappingAddress) D(MmPrepareMdlForReuse)
D(MmGetMdlByteCount) D(MmGetMdlVirtualAddress) D(MmSizeOfMdl) D(MmInitializeMdl) D(MmIsNonPagedSystemAddressValid) D(MmGetVirtualForPhysical)
D(MmLockPagableDataSection) D(MmLockPagableCodeSection) D(MmLockPagableSectionByHandle) D(MmUnlockPagableImageSection)
D(MmGetSystemRoutineAddress) D(MmAllocatePagesForMdlEx) D(MmAllocatePagesForMdl) D(MmFreePagesFromMdl)
D(MmIsDriverVerifying) D(MmIsDriverVerifyingByAddress) D(MmIsThisAnNtAsSystem) D(MmQuerySystemSize)
/* Rtl (ntdrv_rtl.c) */
D(RtlCopyMemory) D(RtlMoveMemory) D(RtlZeroMemory) D(RtlFillMemory) D(RtlSecureZeroMemory)
D(RtlCompareMemory) D(RtlCompareMemoryUlong)
D(RtlInitUnicodeString) D(RtlInitAnsiString) D(RtlUnicodeStringToAnsiString) D(RtlAnsiStringToUnicodeString)
D(RtlFreeUnicodeString) D(RtlFreeAnsiString) D(RtlCopyUnicodeString) D(RtlCompareUnicodeString)
D(RtlEqualUnicodeString) D(RtlAppendUnicodeToString) D(RtlAppendUnicodeStringToString)
D(RtlIntegerToUnicodeString) D(RtlxUnicodeStringToAnsiSize) D(RtlGetVersion)
D(DbgPrint) D(DbgPrintEx) D(vDbgPrintEx) D(vDbgPrintExWithPrefix) D(DbgBreakPoint)
/* Rtl / CRT (ntdrv_crt.c) */
D(RtlMultiByteToUnicodeN) D(RtlMultiByteToUnicodeSize) D(RtlUnicodeToMultiByteN) D(RtlUnicodeToMultiByteSize)
D(RtlUpcaseUnicodeToMultiByteN) D(RtlOemToUnicodeN) D(RtlUnicodeToOemN) D(RtlAnsiCharToUnicodeChar)
D(RtlxAnsiStringToUnicodeSize) D(RtlxUnicodeStringToOemSize) D(RtlxOemStringToUnicodeSize)
D(RtlUpcaseUnicodeChar) D(RtlDowncaseUnicodeChar) D(RtlUpcaseUnicodeString) D(RtlDowncaseUnicodeString) D(RtlUpperString)
D(RtlCreateUnicodeString) D(RtlInitUnicodeStringEx) D(RtlInitAnsiStringEx) D(RtlInitString) D(RtlCompareString) D(RtlEqualString)
D(RtlCopyString) D(RtlPrefixUnicodeString) D(RtlAppendStringToString) D(RtlUnicodeStringToInteger) D(RtlCharToInteger)
D(RtlInt64ToUnicodeString) D(RtlIntegerToChar)
D(RtlInitializeBitMap) D(RtlClearAllBits) D(RtlSetAllBits) D(RtlSetBit) D(RtlClearBit) D(RtlTestBit) D(RtlCheckBit) D(RtlSetBits)
D(RtlClearBits) D(RtlNumberOfSetBits) D(RtlNumberOfClearBits) D(RtlAreBitsClear) D(RtlAreBitsSet) D(RtlFindClearBits) D(RtlFindSetBits)
D(RtlFindClearBitsAndSet) D(RtlFindSetBitsAndClear) D(RtlFindFirstRunClear) D(RtlFindNextForwardRunClear) D(RtlFindLastBackwardRunClear)
D(RtlTimeToTimeFields) D(RtlTimeFieldsToTime) D(RtlTimeToSecondsSince1970) D(RtlSecondsSince1970ToTime)
D(RtlStringFromGUID) D(RtlGUIDFromString) D(VerSetConditionMask) D(RtlVerifyVersionInfo)
D(RtlImageNtHeader) D(RtlImageDirectoryEntryToData) D(RtlFindMessage) D(RtlCaptureStackBackTrace) D(RtlGetCallersAddress)
D(RtlInitializeRangeList) D(RtlFreeRangeList) D(RtlAddRange) D(RtlDeleteRange) D(RtlDeleteOwnersRanges) D(RtlCopyRangeList)
D(RtlGetFirstRange) D(RtlGetNextRange) D(RtlIsRangeAvailable) D(RtlFindRange) D(RtlInvertRangeList) D(RtlMergeRangeLists)
D(RtlCmDecodeMemIoResource) D(RtlCmEncodeMemIoResource) D(RtlIoDecodeMemIoResource) D(RtlIoEncodeMemIoResource)
D(ntdrv_vsprintf) D(ntdrv_sprintf) D(ntdrv_vsnprintf) D(ntdrv_snprintf) D(ntdrv_vswprintf) D(ntdrv_swprintf) D(ntdrv_vsnwprintf) D(ntdrv_snwprintf)
D(ntdrv_strlen) D(ntdrv_strcmp) D(ntdrv_strncmp) D(ntdrv_strncpy) D(ntdrv_strcpy) D(ntdrv_strcat) D(ntdrv_strchr) D(ntdrv_strrchr)
D(ntdrv_strstr) D(ntdrv_stricmp) D(ntdrv_strnicmp) D(ntdrv_memcmp) D(ntdrv_toupper) D(ntdrv_tolower) D(ntdrv_isdigit) D(ntdrv_isspace) D(ntdrv_atoi)
D(ntdrv_wcslen) D(ntdrv_wcscpy) D(ntdrv_wcsncpy) D(ntdrv_wcscat) D(ntdrv_wcsncat) D(ntdrv_wcscmp) D(ntdrv_wcsncmp) D(ntdrv_wcsicmp)
D(ntdrv_wcsnicmp) D(ntdrv_wcschr) D(ntdrv_wcsrchr) D(ntdrv_wcsstr) D(ntdrv_towupper) D(ntdrv_towlower) D(ntdrv_wcsupr) D(ntdrv_strupr) D(ntdrv_strlwr)
extern void *ntdrv_memcpy(void *, const void *, uint64_t);
extern void *ntdrv_memset(void *, int, uint64_t);
extern void *ntdrv_memmove(void *, const void *, uint64_t);
/* Ps (ntdrv_rtl.c, ntdrv_pnp.c) */
D(PsCreateSystemThread) D(PsTerminateSystemThread) D(PsGetCurrentThread) D(PsGetCurrentThreadId)
D(PsGetCurrentProcessId) D(PsIsThreadTerminating) D(PsGetCurrentProcess) D(IoGetCurrentProcess) D(PsGetVersion)
/* register access (ntdrv_rtl.c) */
D(READ_REGISTER_UCHAR) D(READ_REGISTER_USHORT) D(READ_REGISTER_ULONG)
D(WRITE_REGISTER_UCHAR) D(WRITE_REGISTER_USHORT) D(WRITE_REGISTER_ULONG)
/* Io (ntdrv_io.c) */
D(IoCreateDevice) D(IoCreateDeviceSecure) D(IoDeleteDevice) D(IoCreateSymbolicLink) D(IoDeleteSymbolicLink)
D(IoAttachDeviceToDeviceStack) D(IoDetachDevice) D(IoGetAttachedDeviceReference) D(IoGetAttachedDevice)
D(IoInitializeIrp) D(IoAllocateIrp) D(IoFreeIrp) D(IofCallDriver) D(IofCompleteRequest)
D(IoGetRemainingStackSize) D(IoGetRelatedDeviceObject)
D(IoBuildDeviceIoControlRequest) D(IoBuildSynchronousFsdRequest) D(IoConnectInterrupt) D(IoDisconnectInterrupt)
D(IoAllocateWorkItem) D(IoFreeWorkItem) D(IoQueueWorkItem) D(IoQueueWorkItemEx)
D(KeAcquireInterruptSpinLock) D(KeReleaseInterruptSpinLock)
/* Io / Po / WMI / DMA / partitions (ntdrv_pnp.c) */
D(IoAllocateDriverObjectExtension) D(IoGetDriverObjectExtension)
D(PoCallDriver) D(PoStartNextPowerIrp) D(PoSetPowerState) D(PoRequestPowerIrp) D(PoRegisterDeviceForIdleDetection) D(PoSetDeviceBusyEx)
D(PoRegisterSystemState) D(PoUnregisterSystemState) D(PoSetSystemState) D(PoRegisterPowerSettingCallback) D(PoUnregisterPowerSettingCallback)
D(IoRegisterDeviceInterface) D(IoSetDeviceInterfaceState) D(IoGetDeviceInterfaces) D(IoOpenDeviceInterfaceRegistryKey)
D(IoRegisterPlugPlayNotification) D(IoUnregisterPlugPlayNotification) D(IoUnregisterPlugPlayNotificationEx)
D(IoReportTargetDeviceChangeAsynchronous) D(IoReportTargetDeviceChange)
D(IoInvalidateDeviceRelations) D(IoInvalidateDeviceState) D(IoRequestDeviceEject) D(IoRequestDeviceEjectEx) D(IoSynchronousInvalidateDeviceRelations)
D(IoForwardIrpSynchronously) D(IoForwardAndCatchIrp) D(IoAttachDeviceToDeviceStackSafe) D(IoGetLowerDeviceObject) D(IoGetDeviceAttachmentBaseRef)
D(IoGetConfigurationInformation) D(IoIsWdmVersionAvailable) D(IoCreateNotificationEvent) D(IoCreateSynchronizationEvent)
D(IoReuseIrp) D(IoBuildPartialMdl) D(IoBuildAsynchronousFsdRequest) D(IoGetStackLimits) D(IoGetInitialStack) D(IoSetCompletionRoutineEx)
D(IoGetPagingIoPriority) D(IoSetHardErrorOrVerifyDevice) D(IoGetDeviceToVerify) D(IoSetDeviceToVerify) D(IoIsOperationSynchronous)
D(IoGetDeviceObjectPointer) D(IoRegisterDriverReinitialization) D(IoRegisterBootDriverReinitialization)
D(IoRegisterShutdownNotification) D(IoRegisterLastChanceShutdownNotification) D(IoUnregisterShutdownNotification)
D(IoAllocateErrorLogEntry) D(IoWriteErrorLogEntry) D(IoFreeErrorLogEntry)
D(IoWMIRegistrationControl) D(IoWMIDeviceObjectToProviderId) D(IoWMIWriteEvent) D(IoWMIOpenBlock) D(IoWMIQueryAllData) D(IoWMIQueryAllDataMultiple)
D(IoAcquireCancelSpinLock) D(IoReleaseCancelSpinLock) D(IoCancelIrp)
D(KeInitializeDeviceQueue) D(KeInsertDeviceQueue) D(KeInsertByKeyDeviceQueue) D(KeRemoveDeviceQueue) D(KeRemoveByKeyDeviceQueue)
D(KeRemoveByKeyDeviceQueueIfBusy) D(KeRemoveEntryDeviceQueue)
D(IoStartPacket) D(IoStartNextPacket) D(IoStartNextPacketByKey) D(IoSetStartIoAttributes)
D(IoInitializeRemoveLockEx) D(IoAcquireRemoveLockEx) D(IoReleaseRemoveLockEx) D(IoReleaseRemoveLockAndWaitEx)
D(IoInitializeTimer) D(IoStartTimer) D(IoStopTimer)
D(IoReportDetectedDevice) D(IoGetDeviceProperty) D(IoOpenDeviceRegistryKey) D(IoQueryDeviceDescription)
D(IoAssignResources) D(IoReportResourceForDetection) D(IoReportResourceUsage)
D(HalGetAdapter) D(IoGetDmaAdapter) D(IoReadPartitionTableEx) D(IoReadDiskSignature) D(HalExamineMBR)
D(ObReferenceObjectByPointer)
/* Zw / Ob (ntdrv_zw.c, ntdrv_reg.c) */
D(ZwOpenKey) D(ZwCreateKey) D(ZwQueryValueKey) D(ZwSetValueKey) D(ZwClose)
D(ZwCreateFile) D(ZwReadFile) D(ZwWriteFile) D(ZwDeviceIoControlFile)
D(ObReferenceObjectByHandle) D(ObDereferenceObject) D(ObfDereferenceObject) D(ObfReferenceObject) D(ObReferenceObject)
D(ObOpenObjectByPointer) D(ObQueryNameString)
D(ZwEnumerateValueKey) D(ZwEnumerateKey) D(ZwQueryKey) D(ZwDeleteKey) D(ZwDeleteValueKey) D(ZwFlushKey)
D(RtlQueryRegistryValues) D(RtlWriteRegistryValue) D(RtlDeleteRegistryValue) D(RtlCheckRegistryKey) D(RtlCreateRegistryKey)
D(ZwCreateDirectoryObject) D(ZwOpenDirectoryObject) D(ZwMakeTemporaryObject) D(ZwMakePermanentObject)
D(ZwOpenFile) D(ZwQueryInformationFile) D(ZwSetInformationFile) D(ZwQuerySystemInformation) D(ZwLoadDriver) D(ZwUnloadDriver) D(ZwPowerInformation)
/* data exports (ntdrv_ex.c, ntdrv_pnp.c) */
extern int8_t KeNumberProcessors;
extern uint64_t KiBugCheckData[5];
extern uint32_t InitSafeBootMode;
extern uint8_t KdDebuggerEnabled, KdDebuggerNotPresent, NlsMbCodePageTag, NlsMbOemCodePageTag;
extern void *IoFileObjectType, *IoDeviceObjectType, *IoDriverObjectType, *PsThreadType, *PsProcessType, *ExEventObjectType,
            *ExSemaphoreObjectType, *CmKeyObjectType;
extern void *HalDispatchTable[], *HalPrivateDispatchTable[];
extern uint8_t *KdComPortInUse;
/* hal.dll */
D(READ_PORT_UCHAR) D(READ_PORT_USHORT) D(READ_PORT_ULONG)
D(WRITE_PORT_UCHAR) D(WRITE_PORT_USHORT) D(WRITE_PORT_ULONG)
D(HalGetBusData) D(HalGetBusDataByOffset) D(HalSetBusDataByOffset) D(HalGetInterruptVector)
D(HalTranslateBusAddress) D(HalAssignSlotResources) D(HalDisplayString) D(HalMakeBeep) D(HalQueryRealTimeClock)

#define E(n) { #n, (void *)n }
#define C(name, fn) { name, (void *)fn }               /* CRT export under its C name */
#define V(n) { #n, (void *)&n }                        /* data export: the variable's address */
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
    E(KeSynchronizeExecution), E(KfRaiseIrql), E(KfLowerIrql), E(KfAcquireSpinLock), E(KfReleaseSpinLock),
    E(InterlockedIncrement), E(InterlockedDecrement), E(InterlockedExchange), E(InterlockedExchangeAdd),
    E(InterlockedCompareExchange), E(InterlockedCompareExchange64), E(InterlockedExchangePointer),
    E(InterlockedCompareExchangePointer),
    E(KeEnterCriticalRegion), E(KeLeaveCriticalRegion), E(KeAreApcsDisabled), E(KeAreAllApcsDisabled), E(KeEnterGuardedRegion), E(KeLeaveGuardedRegion),
    E(KeAcquireInStackQueuedSpinLock), E(KeReleaseInStackQueuedSpinLock), E(KeAcquireInStackQueuedSpinLockAtDpcLevel),
    E(KeReleaseInStackQueuedSpinLockFromDpcLevel), E(KeTryToAcquireSpinLockAtDpcLevel), E(KeTestSpinLock),
    E(KeFlushQueuedDpcs), E(KeQueryActiveProcessors), E(KeQueryActiveProcessorCountEx), E(KeQueryActiveGroupCount), E(KeQueryMaximumGroupCount),
    E(KeQueryMaximumProcessorCountEx), E(KeGetRecommendedSharedDataAlignment), E(KeIpiGenericCall),
    E(KeInitializeGuardedMutex), E(KeAcquireGuardedMutex), E(KeReleaseGuardedMutex), E(KeTryToAcquireGuardedMutex),
    E(KeAcquireGuardedMutexUnsafe), E(KeReleaseGuardedMutexUnsafe),
    E(KeRegisterBugCheckCallback), E(KeDeregisterBugCheckCallback), E(KeRegisterBugCheckReasonCallback), E(KeDeregisterBugCheckReasonCallback),
    E(KdRefreshDebuggerNotPresent), E(KdEnableDebugger), E(KdDisableDebugger), E(KdSystemDebugControl), E(DbgBreakPointWithStatus),
    E(KeAcquireInterruptSpinLock), E(KeReleaseInterruptSpinLock),
    E(KeInitializeDeviceQueue), E(KeInsertDeviceQueue), E(KeInsertByKeyDeviceQueue), E(KeRemoveDeviceQueue), E(KeRemoveByKeyDeviceQueue),
    E(KeRemoveByKeyDeviceQueueIfBusy), E(KeRemoveEntryDeviceQueue),
    V(KeNumberProcessors), V(KiBugCheckData), V(InitSafeBootMode), V(KdDebuggerEnabled), V(KdDebuggerNotPresent),
    V(NlsMbCodePageTag), V(NlsMbOemCodePageTag), V(HalDispatchTable), V(HalPrivateDispatchTable),
    V(IoFileObjectType), V(IoDeviceObjectType), V(IoDriverObjectType), V(PsThreadType), V(PsProcessType), V(ExEventObjectType),
    V(ExSemaphoreObjectType), V(CmKeyObjectType),
    E(ExInitializeFastMutex), E(ExAcquireFastMutex), E(ExReleaseFastMutex), E(ExTryToAcquireFastMutex),
    E(ExAcquireFastMutexUnsafe), E(ExReleaseFastMutexUnsafe),
    E(ExAllocatePool), E(ExAllocatePoolWithTag), E(ExAllocatePoolWithTagPriority), E(ExAllocatePoolUninitialized),
    E(ExAllocatePool2), E(ExFreePool), E(ExFreePoolWithTag), E(ExInitializeSListHead), E(ExAllocatePoolWithQuotaTag),
    E(ExInterlockedInsertTailList), E(ExInterlockedInsertHeadList), E(ExInterlockedRemoveHeadList), E(ExInterlockedRemoveTailList),
    E(ExInterlockedPushEntryList), E(ExInterlockedPopEntryList), E(ExInterlockedAddUlong), E(ExInterlockedAddLargeInteger),
    E(InitializeSListHead), E(ExQueryDepthSList), E(ExpInterlockedPushEntrySList), E(ExpInterlockedPopEntrySList), E(ExpInterlockedFlushSList),
    E(ExInitializeNPagedLookasideList), E(ExInitializePagedLookasideList), E(ExDeleteNPagedLookasideList), E(ExDeletePagedLookasideList),
    E(ExInitializeResourceLite), E(ExReinitializeResourceLite), E(ExDeleteResourceLite), E(ExAcquireResourceExclusiveLite),
    E(ExAcquireResourceSharedLite), E(ExAcquireSharedStarveExclusive), E(ExAcquireSharedWaitForExclusive), E(ExReleaseResourceForThreadLite),
    E(ExReleaseResourceLite), E(ExIsResourceAcquiredExclusiveLite), E(ExIsResourceAcquiredSharedLite), E(ExGetExclusiveWaiterCount),
    E(ExGetSharedWaiterCount), E(ExConvertExclusiveToSharedLite), E(ExEnterCriticalRegionAndAcquireResourceExclusive),
    E(ExEnterCriticalRegionAndAcquireResourceShared), E(ExReleaseResourceAndLeaveCriticalRegion),
    E(ExCreateCallback), E(ExRegisterCallback), E(ExUnregisterCallback), E(ExNotifyCallback),
    E(ExSizeOfRundownProtectionCacheAware), E(ExInitializeRundownProtectionCacheAware), E(ExReInitializeRundownProtectionCacheAware),
    E(ExAcquireRundownProtectionCacheAware), E(ExAcquireRundownProtectionCacheAwareEx), E(ExReleaseRundownProtectionCacheAware),
    E(ExReleaseRundownProtectionCacheAwareEx), E(ExWaitForRundownProtectionReleaseCacheAware), E(ExRundownCompletedCacheAware),
    E(ExfInitializeRundownProtection), E(ExfAcquireRundownProtection), E(ExfReleaseRundownProtection), E(ExfWaitForRundownProtectionRelease),
    E(ExfReInitializeRundownProtection), E(ExfRundownCompleted),
    E(ExIsProcessorFeaturePresent), E(ExGetCurrentProcessorCounts), E(ExGetCurrentProcessorCpuUsage), E(ExQueueWorkItem),
    E(MmGetPhysicalAddress), E(MmMapIoSpace), E(MmMapIoSpaceEx), E(MmUnmapIoSpace),
    E(MmAllocateContiguousMemory), E(MmAllocateContiguousMemorySpecifyCache), E(MmFreeContiguousMemory),
    E(MmFreeContiguousMemorySpecifyCache), E(MmAllocateNonCachedMemory), E(MmFreeNonCachedMemory), E(MmIsAddressValid),
    E(MmPageEntireDriver), E(MmResetDriverPaging),
    E(IoAllocateMdl), E(IoFreeMdl), E(MmBuildMdlForNonPagedPool), E(MmProbeAndLockPages), E(MmProbeAndLockProcessPages), E(MmUnlockPages),
    E(MmMapLockedPages), E(MmMapLockedPagesSpecifyCache), E(MmUnmapLockedPages), E(MmGetSystemAddressForMdlSafe),
    E(MmMapLockedPagesWithReservedMapping), E(MmUnmapReservedMapping), E(MmAllocateMappingAddress), E(MmFreeMappingAddress), E(MmPrepareMdlForReuse),
    E(MmGetMdlByteCount), E(MmGetMdlVirtualAddress), E(MmSizeOfMdl), E(MmInitializeMdl), E(MmIsNonPagedSystemAddressValid), E(MmGetVirtualForPhysical),
    E(MmLockPagableDataSection), E(MmLockPagableCodeSection), E(MmLockPagableSectionByHandle), E(MmUnlockPagableImageSection),
    E(MmGetSystemRoutineAddress), E(MmAllocatePagesForMdlEx), E(MmAllocatePagesForMdl), E(MmFreePagesFromMdl),
    E(MmIsDriverVerifying), E(MmIsDriverVerifyingByAddress), E(MmIsThisAnNtAsSystem), E(MmQuerySystemSize),
    E(RtlCopyMemory), E(RtlMoveMemory), E(RtlZeroMemory), E(RtlFillMemory), E(RtlSecureZeroMemory),
    E(RtlCompareMemory), E(RtlCompareMemoryUlong),
    C("memcpy", ntdrv_memcpy), C("memset", ntdrv_memset), C("memmove", ntdrv_memmove), C("memcmp", ntdrv_memcmp),
    E(RtlInitUnicodeString), E(RtlInitAnsiString), E(RtlUnicodeStringToAnsiString), E(RtlAnsiStringToUnicodeString),
    E(RtlFreeUnicodeString), E(RtlFreeAnsiString), E(RtlCopyUnicodeString), E(RtlCompareUnicodeString),
    E(RtlEqualUnicodeString), E(RtlAppendUnicodeToString), E(RtlAppendUnicodeStringToString),
    E(RtlIntegerToUnicodeString), E(RtlxUnicodeStringToAnsiSize), E(RtlGetVersion),
    E(RtlMultiByteToUnicodeN), E(RtlMultiByteToUnicodeSize), E(RtlUnicodeToMultiByteN), E(RtlUnicodeToMultiByteSize),
    E(RtlUpcaseUnicodeToMultiByteN), E(RtlOemToUnicodeN), E(RtlUnicodeToOemN), E(RtlAnsiCharToUnicodeChar),
    E(RtlxAnsiStringToUnicodeSize), E(RtlxUnicodeStringToOemSize), E(RtlxOemStringToUnicodeSize),
    E(RtlUpcaseUnicodeChar), E(RtlDowncaseUnicodeChar), E(RtlUpcaseUnicodeString), E(RtlDowncaseUnicodeString), E(RtlUpperString),
    E(RtlCreateUnicodeString), E(RtlInitUnicodeStringEx), E(RtlInitAnsiStringEx), E(RtlInitString), E(RtlCompareString), E(RtlEqualString),
    E(RtlCopyString), E(RtlPrefixUnicodeString), E(RtlAppendStringToString), E(RtlUnicodeStringToInteger), E(RtlCharToInteger),
    E(RtlInt64ToUnicodeString), E(RtlIntegerToChar),
    E(RtlInitializeBitMap), E(RtlClearAllBits), E(RtlSetAllBits), E(RtlSetBit), E(RtlClearBit), E(RtlTestBit), E(RtlCheckBit), E(RtlSetBits),
    E(RtlClearBits), E(RtlNumberOfSetBits), E(RtlNumberOfClearBits), E(RtlAreBitsClear), E(RtlAreBitsSet), E(RtlFindClearBits), E(RtlFindSetBits),
    E(RtlFindClearBitsAndSet), E(RtlFindSetBitsAndClear), E(RtlFindFirstRunClear), E(RtlFindNextForwardRunClear), E(RtlFindLastBackwardRunClear),
    E(RtlTimeToTimeFields), E(RtlTimeFieldsToTime), E(RtlTimeToSecondsSince1970), E(RtlSecondsSince1970ToTime),
    E(RtlStringFromGUID), E(RtlGUIDFromString), E(VerSetConditionMask), E(RtlVerifyVersionInfo),
    E(RtlImageNtHeader), E(RtlImageDirectoryEntryToData), E(RtlFindMessage), E(RtlCaptureStackBackTrace), E(RtlGetCallersAddress),
    E(RtlInitializeRangeList), E(RtlFreeRangeList), E(RtlAddRange), E(RtlDeleteRange), E(RtlDeleteOwnersRanges), E(RtlCopyRangeList),
    E(RtlGetFirstRange), E(RtlGetNextRange), E(RtlIsRangeAvailable), E(RtlFindRange), E(RtlInvertRangeList), E(RtlMergeRangeLists),
    E(RtlCmDecodeMemIoResource), E(RtlCmEncodeMemIoResource), E(RtlIoDecodeMemIoResource), E(RtlIoEncodeMemIoResource),
    C("sprintf", ntdrv_sprintf), C("vsprintf", ntdrv_vsprintf), C("_snprintf", ntdrv_snprintf), C("_vsnprintf", ntdrv_vsnprintf),
    C("swprintf", ntdrv_swprintf), C("vswprintf", ntdrv_vswprintf), C("_snwprintf", ntdrv_snwprintf), C("_vsnwprintf", ntdrv_vsnwprintf),
    C("strlen", ntdrv_strlen), C("strcmp", ntdrv_strcmp), C("strncmp", ntdrv_strncmp), C("strncpy", ntdrv_strncpy), C("strcpy", ntdrv_strcpy),
    C("strcat", ntdrv_strcat), C("strchr", ntdrv_strchr), C("strrchr", ntdrv_strrchr), C("strstr", ntdrv_strstr), C("_stricmp", ntdrv_stricmp),
    C("_strnicmp", ntdrv_strnicmp), C("toupper", ntdrv_toupper), C("tolower", ntdrv_tolower), C("isdigit", ntdrv_isdigit), C("isspace", ntdrv_isspace),
    C("atoi", ntdrv_atoi), C("_strupr", ntdrv_strupr), C("_strlwr", ntdrv_strlwr),
    C("wcslen", ntdrv_wcslen), C("wcscpy", ntdrv_wcscpy), C("wcsncpy", ntdrv_wcsncpy), C("wcscat", ntdrv_wcscat), C("wcsncat", ntdrv_wcsncat),
    C("wcscmp", ntdrv_wcscmp), C("wcsncmp", ntdrv_wcsncmp), C("_wcsicmp", ntdrv_wcsicmp), C("_wcsnicmp", ntdrv_wcsnicmp), C("wcschr", ntdrv_wcschr),
    C("wcsrchr", ntdrv_wcsrchr), C("wcsstr", ntdrv_wcsstr), C("towupper", ntdrv_towupper), C("towlower", ntdrv_towlower), C("_wcsupr", ntdrv_wcsupr),
    E(DbgPrint), E(DbgPrintEx), E(vDbgPrintEx), E(vDbgPrintExWithPrefix), E(DbgBreakPoint),
    E(PsCreateSystemThread), E(PsTerminateSystemThread), E(PsGetCurrentThread), E(PsGetCurrentThreadId),
    E(PsGetCurrentProcessId), E(PsIsThreadTerminating), E(PsGetCurrentProcess), E(IoGetCurrentProcess), E(PsGetVersion),
    E(READ_REGISTER_UCHAR), E(READ_REGISTER_USHORT), E(READ_REGISTER_ULONG),
    E(WRITE_REGISTER_UCHAR), E(WRITE_REGISTER_USHORT), E(WRITE_REGISTER_ULONG),
    E(IoCreateDevice), E(IoCreateDeviceSecure), E(IoDeleteDevice), E(IoCreateSymbolicLink), E(IoDeleteSymbolicLink),
    E(IoAttachDeviceToDeviceStack), E(IoDetachDevice), E(IoGetAttachedDeviceReference), E(IoGetAttachedDevice),
    E(IoInitializeIrp), E(IoAllocateIrp), E(IoFreeIrp), E(IofCallDriver), E(IofCompleteRequest),
    E(IoGetRemainingStackSize), E(IoGetRelatedDeviceObject),
    E(IoBuildDeviceIoControlRequest), E(IoBuildSynchronousFsdRequest), E(IoConnectInterrupt), E(IoDisconnectInterrupt),
    E(IoAllocateWorkItem), E(IoFreeWorkItem), E(IoQueueWorkItem), E(IoQueueWorkItemEx),
    E(IoAllocateDriverObjectExtension), E(IoGetDriverObjectExtension),
    E(PoCallDriver), E(PoStartNextPowerIrp), E(PoSetPowerState), E(PoRequestPowerIrp), E(PoRegisterDeviceForIdleDetection), E(PoSetDeviceBusyEx),
    E(PoRegisterSystemState), E(PoUnregisterSystemState), E(PoSetSystemState), E(PoRegisterPowerSettingCallback), E(PoUnregisterPowerSettingCallback),
    E(IoRegisterDeviceInterface), E(IoSetDeviceInterfaceState), E(IoGetDeviceInterfaces), E(IoOpenDeviceInterfaceRegistryKey),
    E(IoRegisterPlugPlayNotification), E(IoUnregisterPlugPlayNotification), E(IoUnregisterPlugPlayNotificationEx),
    E(IoReportTargetDeviceChangeAsynchronous), E(IoReportTargetDeviceChange),
    E(IoInvalidateDeviceRelations), E(IoInvalidateDeviceState), E(IoRequestDeviceEject), E(IoRequestDeviceEjectEx), E(IoSynchronousInvalidateDeviceRelations),
    E(IoForwardIrpSynchronously), E(IoForwardAndCatchIrp), E(IoAttachDeviceToDeviceStackSafe), E(IoGetLowerDeviceObject), E(IoGetDeviceAttachmentBaseRef),
    E(IoGetConfigurationInformation), E(IoIsWdmVersionAvailable), E(IoCreateNotificationEvent), E(IoCreateSynchronizationEvent),
    E(IoReuseIrp), E(IoBuildPartialMdl), E(IoBuildAsynchronousFsdRequest), E(IoGetStackLimits), E(IoGetInitialStack), E(IoSetCompletionRoutineEx),
    E(IoGetPagingIoPriority), E(IoSetHardErrorOrVerifyDevice), E(IoGetDeviceToVerify), E(IoSetDeviceToVerify), E(IoIsOperationSynchronous),
    E(IoGetDeviceObjectPointer), E(IoRegisterDriverReinitialization), E(IoRegisterBootDriverReinitialization),
    E(IoRegisterShutdownNotification), E(IoRegisterLastChanceShutdownNotification), E(IoUnregisterShutdownNotification),
    E(IoAllocateErrorLogEntry), E(IoWriteErrorLogEntry), E(IoFreeErrorLogEntry),
    E(IoWMIRegistrationControl), E(IoWMIDeviceObjectToProviderId), E(IoWMIWriteEvent), E(IoWMIOpenBlock), E(IoWMIQueryAllData), E(IoWMIQueryAllDataMultiple),
    E(IoAcquireCancelSpinLock), E(IoReleaseCancelSpinLock), E(IoCancelIrp),
    E(IoStartPacket), E(IoStartNextPacket), E(IoStartNextPacketByKey), E(IoSetStartIoAttributes),
    E(IoInitializeRemoveLockEx), E(IoAcquireRemoveLockEx), E(IoReleaseRemoveLockEx), E(IoReleaseRemoveLockAndWaitEx),
    E(IoInitializeTimer), E(IoStartTimer), E(IoStopTimer),
    E(IoReportDetectedDevice), E(IoGetDeviceProperty), E(IoOpenDeviceRegistryKey), E(IoQueryDeviceDescription),
    E(IoAssignResources), E(IoReportResourceForDetection), E(IoReportResourceUsage),
    E(IoGetDmaAdapter), E(IoReadPartitionTableEx), E(IoReadDiskSignature), E(HalExamineMBR),
    E(ZwOpenKey), E(ZwCreateKey), E(ZwQueryValueKey), E(ZwSetValueKey), E(ZwClose),
    E(ZwCreateFile), E(ZwReadFile), E(ZwWriteFile), E(ZwDeviceIoControlFile),
    E(ObReferenceObjectByHandle), E(ObDereferenceObject), E(ObfDereferenceObject), E(ObfReferenceObject), E(ObReferenceObject),
    E(ObOpenObjectByPointer), E(ObQueryNameString), E(ObReferenceObjectByPointer),
    E(ZwEnumerateValueKey), E(ZwEnumerateKey), E(ZwQueryKey), E(ZwDeleteKey), E(ZwDeleteValueKey), E(ZwFlushKey),
    E(RtlQueryRegistryValues), E(RtlWriteRegistryValue), E(RtlDeleteRegistryValue), E(RtlCheckRegistryKey), E(RtlCreateRegistryKey),
    E(ZwCreateDirectoryObject), E(ZwOpenDirectoryObject), E(ZwMakeTemporaryObject), E(ZwMakePermanentObject),
    E(ZwOpenFile), E(ZwQueryInformationFile), E(ZwSetInformationFile), E(ZwQuerySystemInformation), E(ZwLoadDriver), E(ZwUnloadDriver), E(ZwPowerInformation),
    { 0, 0 }
};

const ntdrv_export_t ntdrv_hal_exports[] = {
    E(READ_PORT_UCHAR), E(READ_PORT_USHORT), E(READ_PORT_ULONG),
    E(WRITE_PORT_UCHAR), E(WRITE_PORT_USHORT), E(WRITE_PORT_ULONG),
    E(HalGetBusData), E(HalGetBusDataByOffset), E(HalSetBusDataByOffset), E(HalGetInterruptVector),
    E(HalTranslateBusAddress), E(HalAssignSlotResources), E(HalDisplayString), E(HalMakeBeep), E(HalGetAdapter), E(HalQueryRealTimeClock),
    V(KdComPortInUse),
    /* on x64 these two live in hal.dll too (drivers import them from there); same implementations as ntoskrnl's */
    E(KeStallExecutionProcessor), E(KeQueryPerformanceCounter),
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
