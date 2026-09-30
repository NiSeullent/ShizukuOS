# ShizukuDOS 10.0 — NT Driver Host (NTDRV)

Goal (user requirement): let Windows 10 kernel drivers — Intel integrated families across
generations 1–14 (Gemini Lake, Comet Lake, Tiger Lake, Alder/Raptor Lake, Meteor Lake, …) —
**install and run as-is, without porting each one.** The only truthful route to that is a host
that presents the **NT kernel ABI**: load an unmodified Windows x64 `.sys` (PE32+), satisfy its
imports from `ntoskrnl.exe` / `hal.dll` (later `wdf01000.sys`, `ndis.sys`, `storport.sys`,
`dxgkrnl.sys`) with real implementations that follow documented semantics, and run its
`DriverEntry`. This document describes what is built in `shizukudos/kernel64/ntdrv_*.c`, how it is
verified, and — honestly — how far it is from the Intel families above.

Evidence tags (same convention as `BASELINE.md`/`STATUS.md`): `SOURCE` · `BUILT` · `HOST_TESTED`
· `GUEST_RUN` (real QEMU boot) · `HARDWARE`. "This session" is a KVM-less cloud container
(QEMU 8.2 TCG, mingw-w64 13, gcc 13). No VMX/KVM result is claimed here.

---

## 1. What runs today (reproduced this session)

`tests/run_k64_ntdrv.py` boots the from-scratch Kernel64 (standalone profile, no Supervisor)
under **QEMU TCG** with QEMU's `edu` PCI device attached, mounts a driver-store initrd
(`WIN64_NTDRV.IMG`) and drives the host end to end. All checks PASS (`GUEST_RUN`, TCG):

| Check | Result |
| --- | --- |
| 3 unmodified `.sys` images loaded, relocated/verified, `DriverEntry` called | PASS |
| Echo IOCTL round-trips through a real IRP + `IoCallDriver` + `IoCompleteRequest` (10 bytes) | PASS |
| DPC + KTIMER + `PsCreateSystemThread` driver; **pended IRP** completed later from a **timer DPC** (`0xC0FFEE00`) | PASS |
| PCI driver finds QEMU `edu` via `HalGetBusData`, `MmMapIoSpace`es BAR0, reads identification reg `0x010000ED` | PASS |
| `IoConnectInterrupt` over `irq_register`; a raised `edu` interrupt fires the driver's ISR (vector 42) | PASS |
| Hosted driver recorded as the `edu` function's owner (`pci_claim` → `ntdrv:shzpci`, seen from user mode via `NtQuerySystemInformation(0x101)`) | PASS |
| Provider export surface | 568 `ntoskrnl.exe` + 19 `hal.dll` = **587** (185 at the start of N3's work, 225 after it, then the N4 batch) |
| User mode reaches a driver: `NtLoadDriver` → `NtCreateFile("\\??\\ShzEcho")` → `NtDeviceIoControlFile`; a second `NtLoadDriver` of the running service → `STATUS_IMAGE_ALREADY_LOADED`; a `%SystemRoot%` REG_EXPAND_SZ `ImagePath` resolves | PASS |

**A real, unmodified corpus package installs and starts** (N3, `tests/run_k64_pnp.py`, QEMU `-device e1000`,
`GUEST_RUN` TCG): the ReactOS e1000 NDIS 5 miniport package (`corpus/build.py --packages`) put on the medium with
`store.py`, installed by `SHZPNP.EXE add-driver --legacy --install` (Services key, Enum devnode, the Net class
installer's keys) and loaded by `SHZPNP.EXE load e1000` → `NtLoadDriver`: the host loads the corpus `ndis.sys` first
(e1000 imports it), runs both `DriverEntry`s, claims the function (`ntdrv:e1000`), calls the miniport's `AddDevice`
with a PDO and sends `IRP_MN_START_DEVICE` with the function's BARs and interrupt line; NDIS's `MiniportInitialize`
programmed the NIC (bus interface config reads, BAR0 mapped, DMA rings, reset, EEPROM MAC, interrupt connected) and the
start IRP completed with `STATUS_SUCCESS` (§2.9). `T_DRV_PNP.EXE` checks it from user mode: 24/24 PASS. No NDIS protocol
is bound on top, so no packets flow yet.

The **default** Kernel64 runs (`run_k64_standalone.py`, `run_k64_net.py`, `run_k64_gui.py`) are
byte-for-byte unaffected: the driver store ships only in `WIN64_NTDRV.IMG`, and `kmain`'s single
`ntdrv_selftest()` call is a complete no-op unless `\SHZ\DRIVERS` is present. The plain
standalone runner remains green (17/17 PASS, twice, `GUEST_RUN` TCG), as does `run_k64_gui.py`. In that default run
N2's `T_SHZPNP.EXE` now reaches this host: `shzpnp load synthpnp` → `NtLoadDriver` resolves `\SystemRoot\SYS64\DRIVERS\
synthpnp.sys` and rejects the non-PE payload (`STATUS_INVALID_IMAGE_FORMAT`, exit 1), as its test requires.

The three drivers are built from `shizukudos/win64/drivers/*.c` with Microsoft's DDK headers and
the exact command a real Windows driver uses — no Shizuku-specific source changes:

```
x86_64-w64-mingw32-gcc -shared -nostdlib -Wl,--subsystem,native -Wl,--entry,DriverEntry \
    -I <ddk> ... -lntoskrnl -lhal -lgcc
```

`import_coverage.py --ntoskrnl` measures any `.sys` package against the build-emitted provider
tables; for the three test drivers it reports **25/25 (100%)** imports resolved (`HOST_TESTED`). Against drivers nobody
here wrote — N2's 23 unmodified ReactOS/virtio-win `.sys` built by `shizukudos/ntdrv/corpus/build.py` — the baseline was
`ntoskrnl.exe` 103/313 and `hal.dll` 6/12 and **1 of 23 images loadable**. After the second export batch (§2.10), SEH
(§2.11), the KPCR/KUSER support (§2.12) and export-driver linking (§2.13) the measured state is (`HOST_TESTED` for the
static count, `GUEST_RUN` TCG for the loads):

| Measurement | Result |
| --- | --- |
| Distinct (provider, function) imports of the 23 corpus images resolved | **449 of 449** — `ntoskrnl.exe` 313/313, `hal.dll` 12/12, and the export drivers `ndis.sys` 51/51, `classpnp.sys` 30/30, `scsiport.sys` 28/28, `storport.sys` 11/11, `wdfldr.sys` 4/4 (`import_coverage.py … --export-drivers`) |
| Corpus drivers whose `DriverEntry` returns `STATUS_SUCCESS` in the guest (`run_k64_ntdrv.py --corpus`) | **22 of 23**; the 23rd, `uniata.sys`, loads and runs and returns `STATUS_DEVICE_DOES_NOT_EXIST` because the VM has no ATA controller |
| Export-surface driver `APITEST.SYS` (registry query tables, device interfaces, StartIo/cancel, remove locks, power IRPs, PDO properties, DMA adapters, partition tables, SList/lookaside/ERESOURCE, CRT/Rtl, SEH …) | 99 checks, 0 failures |
| KMDF: `cdrom.sys` and `hdaudbus.sys` `FxDriverEntry` → `WdfVersionBind` → `WdfDriverCreate` (`run_k64_ntdrv.py --kmdf`) | both return `STATUS_SUCCESS`; the framework's `AddDevice`, `DriverUnload` and IRP dispatch are installed on their `DRIVER_OBJECT` |
| Provider export surface | 568 `ntoskrnl.exe` + 19 `hal.dll` = **587** |

Not measured: the **Intel Windows 10 driver list** count. No such package or list exists in this repository or in this
session, so no number is claimed; run `import_coverage.py <package dir> --ntoskrnl build/shizukudos/win64/ntdrv
--export-drivers --rank intel.md` on the real package. "Loads and DriverEntry succeeds" is not "drives hardware": only
the three test drivers drive a device (QEMU `edu`); the corpus drivers were loaded on a VM without their hardware.

---

## 2. Architecture

### 2.1 Kernel image loader — `ntdrv_ldr.c`
- Parses the `.sys` with the shared, fuzzed `win64/pe_parse.c` (AMD64 PE32+ only).
- Reserves a slice of the **driver image window** in the kernel half
  (`0xFFFF_E000_0000_0000`, one PML4 entry), maps headers + sections there (code executable,
  data `NX`), and copies raw section bytes in place.
- Applies base relocations when the image carries a `.reloc` directory; a fully RIP-relative
  `.sys` (empty reloc directory) is accepted and loaded at any base, exactly as it would be on
  Windows.
- Resolves the import table against the provider tables (`ntdrv_prov.c`), writing each function
  VA into the IAT. **One diagnostic line is printed per unresolved import**, and load fails with
  `STATUS_PROCEDURE_NOT_FOUND` rather than stubbing anything.
- Builds a `DRIVER_OBJECT`, points every `MajorFunction[]` slot at a default dispatch, sets
  `DriverInit`, a `\Registry\…\Services\<name>` `RegistryPath`, and calls
  `DriverEntry(DriverObject, RegistryPath)`.

The driver runs in ring 0 in the kernel address space. Because the kernel is built System-V and
a Windows driver is built Microsoft-x64, **every** provider function and **every** callback the
kernel invokes in the driver (DriverEntry, dispatch, DPC, ISR, thread start, completion routine)
carries `NTAPI` (`__attribute__((ms_abi))`). The boundary is honoured in both directions.

### 2.2 ABI contract — `ntddk.h` + `ntddk_abi.h`
The on-the-wire layout of `IRP`, `IO_STACK_LOCATION`, `DRIVER_OBJECT`, `DEVICE_OBJECT`, `MDL`,
`KEVENT`/`KSEMAPHORE`/`KTIMER`/`KDPC` and `UNICODE_STRING` must match Windows exactly, because the
driver's own inline macros (`IoGetCurrentIrpStackLocation`, `IoMarkIrpPending`, …) read them.
Offsets live once in `ntddk_abi.h`; `ntddk.h` asserts the host's structs against them (checked by
the Linux kernel build), and `win64/tools/ntddk_abi_check.c` asserts Microsoft's `<ddk/wdm.h>`
against the **same** numbers (checked by the mingw build). Passing both sides means the host and
Windows agree field-for-field. `sizeof(IRP)==0xD0`, `IO_STACK_LOCATION==0x48`,
`DRIVER_OBJECT==0x150`, `DEVICE_OBJECT==0x148` — all verified (`BUILT`).

### 2.3 Object namespace, DRIVER/DEVICE objects, IRP model — `ntdrv_io.c`
- `\Device\…` device list, `\DosDevices\…`/`\??\…` symbolic links (canonicalized to one leaf).
- `IoCreateDevice`/`IoCreateDeviceSecure`/`IoDeleteDevice`, `IoCreate/DeleteSymbolicLink`,
  `IoAttachDeviceToDeviceStack`/`IoDetachDevice` (real `StackSize` accounting).
- IRP engine with a genuine stack: `IoAllocateIrp`/`IoInitializeIrp`/`IoFreeIrp`,
  `IofCallDriver` (decrement `CurrentLocation`, descend one stack location, dispatch),
  `IofCompleteRequest` (completion-routine walk up the stack honouring
  `SL_INVOKE_ON_SUCCESS/ERROR/CANCEL` and `STATUS_MORE_PROCESSING_REQUIRED`, then user IOSB copy,
  buffered output copy-back, `SystemBuffer` free, `UserEvent` signal).
- `IoBuildDeviceIoControlRequest`/`IoBuildSynchronousFsdRequest` and a synchronous kernel-buffer
  engine used by both the self-test and the user syscall path; **pended IRPs** (`IoMarkIrpPending`
  → `STATUS_PENDING` → later `IoCompleteRequest`) wake the waiter — demonstrated from a timer DPC.
- `IoConnectInterrupt`/`IoDisconnectInterrupt`: a PCI legacy line joins the kernel's **shared, level-triggered INTx
  chain** (`pci_intx_attach`, the same one AHCI/NVMe/NIC use), so a hosted driver never steals a line from a native
  one; any other vector is taken only when it is free (`irq_handler_get`). The chain calls the driver's
  `KSERVICE_ROUTINE`; `HalGetInterruptVector` maps a bus IRQ line to a system vector; `KeSynchronizeExecution`
  excludes the ISR. Buffered / direct (MDL) / neither I/O methods are all handled.
- **PCI ownership:** without a PnP start IRP the host decides from what the driver does — an `MmMapIoSpace` inside a
  function's memory BAR (config BARs read, never size-probed on a live device) or connecting that function's line —
  and records it with `pci_claim(dev, "ntdrv:<service>")`, so user mode (`NtQuerySystemInformation` 0x101,
  `T_GUI_STATUS`, `shzpnp enum`) lists the function as driven by the hosted `.sys`.
- Work items (`IoAllocateWorkItem`/`IoQueueWorkItem`/`IoFreeWorkItem`) run on a system worker thread at
  PASSIVE_LEVEL; `IoStartPacket`/`IoStartNextPacket(ByKey)` (StartIo queues over `KDEVICE_QUEUE`), the cancel spin lock and
  `IoGetDriverObjectExtension` are implemented (§2.9).

### 2.4 Ke / Ex runtime — `ntdrv_ke.c`
DPCs (queue + dedicated dispatch worker), KTIMERs (a 1 ms timer thread arms/fires them and
queues their DPCs), dispatcher objects (events, semaphores, mutexes, timers) with
`KeWaitForSingleObject`/`KeWaitForMultipleObjects`, `KeDelayExecutionThread`,
`KeStallExecutionProcessor`, `KeQuerySystemTime`/`KeQueryPerformanceCounter`, spin locks,
`ExAllocatePool(WithTag)`/`ExAllocatePool2`/`ExFreePool`, fast mutexes, the full Interlocked set,
`KeBugCheckEx`. **IRQL is enforced**: raising to ≥ `DISPATCH_LEVEL` masks the scheduler (the only
preemption source here is the timer interrupt), reproducing the guarantee a driver relies on;
lowering below `DISPATCH_LEVEL` drains the DPC queue at exactly the point Windows does. Illegal
waits/allocations at raised IRQL bugcheck.

### 2.5 Mm / MDL — `ntdrv_mm.c`
`MmMapIoSpace`/`MmUnmapIoSpace` (uncached, via the kernel's MMIO mapper),
`MmAllocateContiguousMemory(SpecifyCache)` and non-cached allocations from the physically
contiguous, direct-mapped kernel heap (so `MmGetPhysicalAddress` is exact),
`IoAllocateMdl`/`MmProbeAndLockPages`/`MmBuildMdlForNonPagedPool`/
`MmMapLockedPagesSpecifyCache`/`MmGetSystemAddressForMdlSafe`/`MmUnlockPages`/`IoFreeMdl`.

### 2.6 Rtl / Dbg / Ps / Hal — `ntdrv_rtl.c`; Zw + Ob — `ntdrv_zw.c`
Counted `UNICODE_STRING`/`ANSI_STRING` routines, `Rtl{Copy,Zero,Fill,Move,Compare}Memory`,
`RtlGetVersion`; `DbgPrint`/`DbgPrintEx` (a real ms_abi vararg formatter → kernel console);
`PsCreateSystemThread`/`PsTerminateSystemThread` over the scheduler; HAL config-space and port/
register access (`HalGetBusData(ByOffset)`, `READ/WRITE_PORT_*`, `READ/WRITE_REGISTER_*`); and a
kernel-mode handle table backing `ZwOpenKey`/`ZwCreateKey`/`ZwQueryValueKey`/`ZwSetValueKey`
(against the real configuration manager, `registry.c`) and `ZwCreateFile`/`ZwReadFile`/
`ZwWriteFile` (against the real in-memory file system, `fs.c`).

### 2.7 User-mode reachability
Syscall range `0xE0–0xEF` ("ntdrv"): `sysext.c` routes it to a strong `sys_ext_ntdrv()`.
`NtLoadDriver(RegistryPath)` reads the service key's `ImagePath` with the service control manager's rules
(absent → `\SystemRoot\SYS64\DRIVERS\<service>.sys`; `%SystemRoot%`/`\SystemRoot\` → `C:\SHZ\`; `\??\X:\`,
`X:\` and `\x` as is; relative → under SystemRoot), loads the file from any volume (initrd/RAM in place, disk-backed
D:/E: read through `fs_read`) and returns `STATUS_IMAGE_ALREADY_LOADED` for a service already running. This is the
call N2's `SHZPNP.EXE load <service>` makes after `add-driver --install` wrote the service key;
`NtCreateFile("\\??\\Name")` opens a device (issuing `IRP_MJ_CREATE`);
`NtDeviceIoControlFile`/`NtReadFile`/`NtWriteFile` become buffered/direct/neither IRPs, with async
completion when the driver pends. Shared-file hooks are minimal: the syscall range in `ntsys.h`,
one routing line in `sysext.c`, device hooks in `sysfile.c`/`objects.c`, and one reserved kernel PML4 slot
(`NTDRV_VA_BASE` = `0xFFFF_E000_0000_0000`, slot 448, declared in `k64.h` next to `KWIN_BASE`, slot 386) whose
PDPT `mem_init` materialises like the kernel-window slot, so a driver mapped after a process exists is visible to
it. Contiguous/non-cached driver memory comes from the kernel heap (physical 3–15 MiB, direct-mapped).

### 2.9 PnP root, device properties, DMA adapter — `ntdrv_pnp.c` (N3)
Windows starts a function driver through the PnP manager; the host has no bus driver, so `ntdrv_pnp.c` plays that part
for the functions of the Kernel64 PCI scan that `shzpnp add-driver --install` bound in the registry. After a service's
`DriverEntry` succeeds, `NtLoadDriver` walks `Enum\PCI\<hwid>\B<bus>D<dev>F<fn>`; every devnode whose `Service` names the
service is claimed (`pci_claim` → `ntdrv:<service>`) and gets a PDO (`\Device\NTPNP_PCI<n>` on the host's
`\Driver\PnpManager`). If the driver set `DriverExtension->AddDevice`, the host enables the function (I/O, memory,
bus master), calls `AddDevice(DriverObject, PDO)` and sends `IRP_MJ_PNP`/`IRP_MN_START_DEVICE` down the new stack with
raw and translated `CM_RESOURCE_LIST`s built from the BARs (port/memory, sized by the write-ones probe) and the interrupt
line (`CmResourceTypeInterrupt`, shared, level; the translated vector is the HAL's). The PDO completes the PnP requests a
function driver sends down: `IRP_MN_START_DEVICE`/stop/remove with success, `IRP_MN_QUERY_INTERFACE` for
`GUID_BUS_INTERFACE_STANDARD` (config-space `GetBusData`/`SetBusData`, identity `TranslateBusAddress`, `GetDmaAdapter`),
anything else with the requester's status. `IoGetDeviceProperty` serves the devnode's values (`DriverKeyName` =
`{ClassGUID}\NNNN`, description, hardware IDs, class, bus number, address, legacy bus type PCI, PDO name);
`IoOpenDeviceRegistryKey` opens the software key (`PLUGPLAY_REGKEY_DRIVER`) or `Device Parameters`;
`IoRegisterDeviceInterface` forms the Windows link name and records it (not published: no consumer here);
`IoGetDmaAdapter` returns a `DMA_ADAPTER` whose common buffers come from the physically contiguous, direct-mapped kernel
heap (page aligned) and whose scatter/gather lists are built from MDLs page by page. Layouts (`CM_PARTIAL_RESOURCE_DESCRIPTOR`
0x14 under pack(4), `BUS_INTERFACE_STANDARD` 0x40, `DMA_OPERATIONS` 0x80, `RTL_QUERY_REGISTRY_TABLE` 0x38, ...) were
measured from Microsoft's wdm.h and are asserted in the source.

**IRQL is CR8.** The DDK's amd64 headers inline `KeGetCurrentIrql`/`KfRaiseIrql`/`KeLowerIrql` as CR8 reads and
writes, so an unmodified x64 driver raises and lowers IRQL without calling any export (the corpus `ndis.sys` carries 85
CR8 instructions; the host's software IRQL never saw them and its `KeAcquireSpinLockAtDpcLevel` check panicked under
`MiniDoRequest`). The host now keeps no software copy: every provider reads CR8, its own raise/lower write CR8, and the
scheduler tick does not preempt while CR8 >= DISPATCH_LEVEL, so DISPATCH_LEVEL means "no dispatching" whichever way a
driver got there. A driver's own CR8 write leaves interrupts enabled, as on Windows.

**Export drivers.** An import from a module other than `ntoskrnl.exe`/`hal.dll` loads `\SHZ\SYS64\DRIVERS\<dll>`
on demand (its `DriverEntry` runs, as a boot-start dependency's would) and resolves the symbol in that image's export
directory; the dependency counts its users and `NtUnloadDriver` refuses it while any remain. `NtUnloadDriver` (0xe2)
and the status query `NtShzDriverQuery` (0xe3) are the other two services N3 added (§2.7).

### 2.8 Registry `Services` keys
`\Registry\Machine\System\CurrentControlSet\Services\<name>` with `ImagePath` and `Type`, created
by the user app via advapi32 and read by `NtLoadDriver` — the same key an INF would populate.

### 2.10 Second export batch (N4)
Implemented against the documented semantics, each with a check in `win64/drivers/apitest.c` (its `DriverEntry` fails,
and the runner fails, on any `FAIL` line). Where N3's work (§2.9) and this batch overlapped, one implementation was kept per export: the generic
ones (driver-object extensions, shutdown notifications, `PoCallDriver`, DMA adapters, `HalTranslateBusAddress`, the Ex/Rtl/Zw lists,
registry query tables) are this batch's in `ntdrv_ex.c`/`ntdrv_crt.c`/`ntdrv_reg.c`/`ntdrv_dev.c`; the four that depend on the kind of PDO
(`IoGetDeviceProperty`, `IoOpenDeviceRegistryKey`, `IoRegisterDeviceInterface`, `IoSetDeviceInterfaceState`) are exported from `ntdrv_dev.c` and call N3's
versions in `ntdrv_pnp.c` for the PDOs of PCI functions bound through the registry, and serve legacy root-enumerated devices themselves. IRQL is N3's
per-thread `CR8` model. Both agents' runners pass on the merged tree (§3).

| File | Contents |
| --- | --- |
| `ntdrv_ex.c` | `ExInterlocked*List`, SLIST (x64 `HeaderX64` layout), lookaside lists, `ERESOURCE`, fast/guarded mutexes, in-stack queued spin locks, critical regions, callbacks, rundown protection, bug-check callbacks, `Kd*`, the data exports (`KeNumberProcessors`, `KdDebuggerNotPresent`, `NlsMbCodePageTag`, `HalDispatchTable`, …), object type descriptors |
| `ntdrv_crt.c` | one printf engine behind `sprintf`/`swprintf`/`_snprintf`/`_vsnwprintf` and `DbgPrint` (Microsoft conversions), `str*`/`wcs*`, code-page and case conversion, counted strings, bitmaps, time fields, GUID strings, `RtlVerifyVersionInfo`, image directory helpers, range lists, resource-descriptor encoders |
| `ntdrv_reg.c` | key/value information classes, `ZwEnumerate*`/`ZwQueryKey`/`ZwDelete*`, `RtlQueryRegistryValues` (query tables), `RtlWriteRegistryValue` & co., `ZwLoadDriver`/`ZwUnloadDriver`, `ZwQuerySystemInformation`, `ZwPowerInformation` |
| `ntdrv_dev.c` | per-device host record, `Po*`, device interfaces and `IoRegisterPlugPlayNotification`, `IoInvalidateDeviceRelations`, WMI registration, cancel/StartIo, remove locks, timers, root-bus PDOs (`IoReportDetectedDevice`, `IoGetDeviceProperty`, `IoOpenDeviceRegistryKey`), resource builders, `HalAssignSlotResources`, DMA adapters (`IoGetDmaAdapter`), partition tables (MBR+GPT), `Mm` pageable/system-routine helpers |
| `ntdrv_io.c`, `ntdrv_zw.c`, `ntdrv_mm.c` | device handles through `IRP_MJ_CREATE`, `ZwDeviceIoControlFile`, `ObReferenceObjectByHandle` with type checks, page-list MDLs mapped into the driver window, `IoQueueWorkItemEx`, per-interrupt spin locks |

The ABI contract grew with it: `ntddk_abi.h`/`ntddk_abi_check.c` now also pin the full `DEVICE_OBJECT`, `KDEVICE_QUEUE`,
the PnP/Power stack-location parameters and about forty structure sizes against Microsoft's `wdm.h`.

### 2.11 Structured exception handling — `ntdrv_seh.c`
Drivers keep `__try`/`__except`/`__finally` state in `.pdata`/`.xdata` with `__C_specific_handler` as the language handler.
Provided: `RtlLookupFunctionEntry`, `RtlVirtualUnwind` (unwind codes, chained info, epilog detection), `RtlUnwind(Ex)`,
`__C_specific_handler` (search and unwind phases over the scope table), `RtlCaptureContext`/`RtlRestoreContext`,
`RtlRaiseException`/`RtlRaiseStatus`/`ExRaiseStatus`/`ExRaiseAccessViolation`/`ExRaiseDatatypeMisalignment`, and a hook in the
CPU-exception path so a ring-0 fault inside a driver (page fault, divide error, bad call target, …) is dispatched to the driver's
handlers. The raise and unwind entry points are assembly thunks that capture the caller's registers at entry. Only driver images carry unwind
data, so the frame walk stops at the first frame outside a driver and an exception nobody handles is a
`KMODE_EXCEPTION_NOT_HANDLED` bug check. `APITEST.SYS` carries hand-assembled functions with real `.pdata` (mingw GCC has no `__try`)
covering software raise, hardware fault, `__finally` during unwind and a `CONTINUE_SEARCH` filter.

### 2.12 What WDK-built drivers read without calling the kernel
- **IRQL**: `KeGetCurrentIrql`/`KeRaiseIrql`/`KeLowerIrql` are inline `CR8` accesses on x64, so the host mirrors its IRQL into `CR8`.
- **KPCR/KPRCB through GS**: `KeGetCurrentThread`/`PsGetCurrentThread` are `gs:[0x188]`. The kernel never uses GS, so each thread that
  runs driver code gets its own small KPCR (`Self` 0x18, `CurrentPrcb` 0x20, PRCB at 0x180 with `CurrentThread`), the scheduler swaps
  GS at every switch once the host is active (one line in `sched.c`), ISRs get a shared block and user-thread entries into the host
  switch GS and restore the TEB on the way out (`ntdrv_ke.c`, `ntdrv_io.c`).
- **KUSER_SHARED_DATA** at `0xFFFFF78000000000`, read-only, refreshed every millisecond (`ntdrv_kuser.c`): tick count, interrupt and system
  time, Windows version, processor features, processor count.

### 2.13 Export drivers and KMDF
An import from a module other than `ntoskrnl.exe`/`hal.dll` (`wdfldr.sys`, `ndis.sys`, `classpnp.sys`, `scsiport.sys`, `storport.sys`) is
resolved against that module's mapped export table, loading `\SHZ\DRIVERS\<MODULE>` on demand; export forwarders
(`scsiport!ScsiPortStallExecution` → `ntoskrnl!KeStallExecutionProcessor`) resolve through the target; an image without an entry point runs
its exported `DllInitialize`. A store load also creates the driver's `Services\<name>` key, since `DriverEntry` opens its `RegistryPath`.
KMDF is the framework's own code, not a reimplementation: the corpus's `wdfldr.sys` and `wdf01000.sys` (ReactOS's port of the WDF sources)
run on this host; `WdfVersionBind` finds `Services\Wdf01000`, `ZwLoadDriver`s it, and the library registers itself with `WdfLdr`.

---

## 3. Verification map

| Artifact | How it is proven |
| --- | --- |
| ABI structs == Windows | `ntddk_abi_check.c` (`_Static_assert`, mingw) + `ntddk.h` asserts (Linux gcc) — `BUILT` |
| Providers behave (semantics) | drivers exercise them; results computed in-guest → evidence slots 13,14,15,25,26,27 — `GUEST_RUN` |
| Loader (relocate/imports/DriverEntry) | 3 real `.sys` loaded and run — `GUEST_RUN` |
| Coverage measurement | `import_coverage.py --ntoskrnl` from build-emitted `ntoskrnl-exports.json` — `HOST_TESTED` |
| Export batch, SEH, KMDF, corpus | `run_k64_ntdrv.py` (default / `--kmdf` / `--corpus`), `GUEST_RUN` TCG: 13/13, 19/19, 21/21 |
| No regression | `run_k64_standalone.py` 14/14, `shz.py test --suite host` 5/5 — `GUEST_RUN`/`HOST_TESTED` |

---

## 4. KMDF

Most modern Intel function drivers are **KMDF**, linking `WdfLdr`/`wdfldr.sys` and calling into a version of `Wdf01000.sys` via the
`WdfFunctions` table fetched by `WdfVersionBind`. The framework is not reimplemented: the host runs the framework's own binaries
(`GUEST_RUN`, TCG, `run_k64_ntdrv.py --kmdf`, image built by `win64/ntdrv/kmdf_image.py`):

1. the client's `FxDriverEntry` imports `WdfVersionBind` from `wdfldr.sys`; the loader maps `WDFLDR.SYS` (an export driver with no
   `DriverEntry`) and calls its exported `DllInitialize`;
2. `WdfVersionBind` finds the library service (`Services\Wdf01000`, the default when no `Control\Wdf\Kmdf` version key exists), calls
   `ZwLoadDriver`, and `Wdf01000`'s `DriverEntry` calls `WdfRegisterLibrary` back into `WdfLdr`;
3. `LibraryRegisterClient` returns the `WdfFunctions` table and the client's own `DriverEntry` runs `WdfDriverCreate`, which installs
   `AddDevice`, `DriverUnload` and the framework's IRP dispatch on the client's `DRIVER_OBJECT`.

Result: `cdrom.sys` and `hdaudbus.sys` both return `STATUS_SUCCESS`. **Not done:** a KMDF client that goes on to create a device
(`AddDevice` → `WdfDeviceCreate`, queues, interrupts) has not been driven; that needs PnP start IRPs sent to the framework's `AddDevice`.

## 5. Class frameworks and which Intel families need which

A function driver is only loadable when its **class framework** is present. Honest-effort classes:

| Family (examples) | Needs | Status |
| --- | --- | --- |
| Chipset/LPC/SMBus/GPIO/PECI, `.inf`-only "null" drivers | WDM/KMDF only | **reachable now** (WDM core, SEH and KMDF binding done) |
| SATA/NVMe/RST (`iaStorAC`, `stornvme`) | StorPort miniport (`storport.sys`) | miniport contract planned |
| Ethernet/Wi-Fi (`e1000`, `e1i`, Killer, Intel Wi-Fi) | NDIS 6 (`ndis.sys`) | NDIS 6 planned |
| USB xHCI / USB devices | USB stack (`usbxhci`, `ucx01000`, `usbhub3`) | planned |
| HID (touchpad, sensors) | HID class (`hidclass`, `kmdf`) | planned |
| **Graphics — every Intel iGPU gen 1–14** (`igdkmd64`) | **WDDM 2.x** (`dxgkrnl.sys` + a KMD DDI) | **not reachable until WDDM exists** |

**Graphics is the load-bearing caveat.** Intel's `igdkmd64` is a WDDM display miniport: it does
not create a device or talk IOCTLs — it registers WDDM DDIs and is driven by `dxgkrnl`/`dxgmms`.
Until a `dxgkrnl` and the WDDM 2.x DDI exist here, no Intel graphics driver of any generation is
loadable, regardless of how complete the WDM/KMDF core is. This is stated plainly rather than
implied by a green IOCTL test.

## 6. Honest distance to Intel gen 1–14

- **Done and proven:** the NT-kernel-ABI host itself — load an unmodified x64 `.sys`, relocate,
  resolve 183 `ntoskrnl`/`hal` exports, run `DriverEntry`, service IRPs (incl. pended/async),
  DPCs/timers/threads, map I/O space, connect and take a real interrupt, all reachable from user
  mode. Demonstrated on three drivers written to the DDK, not to Shizuku.
- **Corpus (Agent N2), measured:** of 23 real unmodified drivers only `null.sys` resolves every import today; the
  next ntoskrnl batch (registry query helpers, power IRPs, device interfaces/properties, SEH `__C_specific_handler`,
  critical regions, StartIo queues) is ranked by `import_coverage.py --ntoskrnl` over that corpus. N2's `shzpnp`
  (INF → Services key) → `NtLoadDriver` path is connected end to end.
- **Framework gap:** KMDF, NDIS 6, StorPort, USB, HID, WDDM are the remaining large blocks. A
  chipset/simple function driver could load once KMDF is built; storage/network/USB/HID need
  their class stack; **graphics needs WDDM and is the farthest.**
- **Done (N3):** one real corpus package taken through install → load → `AddDevice` → `IRP_MN_START_DEVICE` →
  `MiniportInitialize` on the device (ReactOS e1000 over the ReactOS ndis.sys, on QEMU's e1000), driven by the same
  `shzpnp` commands a vendor package uses; 40 more exports; the PnP root of §2.9. Still no protocol above NDIS, so no
  traffic; no NDIS 6, KMDF, StorPort, WDDM.
- **Not claimed:** that any specific Intel production driver loads today. None was run. The export
  surface a real `igdkmd64`/`e1i68x64`/`iaStorAC` imports is far larger than 183 and includes the
  framework DLLs above; `import_coverage.py --ntoskrnl` on such a package is the honest next
  measurement, and it will show the gap quantitatively.
