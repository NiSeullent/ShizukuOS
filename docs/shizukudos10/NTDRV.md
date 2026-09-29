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
| Provider export surface | 173 `ntoskrnl.exe` + 12 `hal.dll` = **185** |
| User mode reaches a driver: `NtLoadDriver` → `NtCreateFile("\\??\\ShzEcho")` → `NtDeviceIoControlFile`; a second `NtLoadDriver` of the running service → `STATUS_IMAGE_ALREADY_LOADED`; a `%SystemRoot%` REG_EXPAND_SZ `ImagePath` resolves | PASS |

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
here wrote — N2's 23 unmodified ReactOS/virtio-win `.sys` built by `shizukudos/ntdrv/corpus/build.py` — it reports
`ntoskrnl.exe` 103/313 and `hal.dll` 6/12 imports provided, and **1 of 23 images loadable** (`null.sys`); the rest
need more ntoskrnl (211 missing names: `RtlQueryRegistryValues`, `PoCallDriver`/`PoStartNextPowerIrp`,
`IoRegisterDeviceInterface`, `IoGetDeviceProperty`, `IoOpenDeviceRegistryKey`, `__C_specific_handler`, …) and the
class frameworks (`ndis.sys` 0/51, `classpnp.sys` 0/30, `scsiport.sys` 0/28, `storport.sys` 0/11, `wdfldr.sys` 0/4)
(`HOST_TESTED`, measurement only — `null.sys` has not been run here).

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
  PASSIVE_LEVEL. `IoStartNextPacket` (StartIo queues) and `IoGetDriverObjectExtension` are **not** exported yet: a
  driver importing them is refused with one diagnostic line per missing import, never given a stub.

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

### 2.8 Registry `Services` keys
`\Registry\Machine\System\CurrentControlSet\Services\<name>` with `ImagePath` and `Type`, created
by the user app via advapi32 and read by `NtLoadDriver` — the same key an INF would populate.

---

## 3. Verification map

| Artifact | How it is proven |
| --- | --- |
| ABI structs == Windows | `ntddk_abi_check.c` (`_Static_assert`, mingw) + `ntddk.h` asserts (Linux gcc) — `BUILT` |
| Providers behave (semantics) | drivers exercise them; results computed in-guest → evidence slots 13,14,15,25,26,27 — `GUEST_RUN` |
| Loader (relocate/imports/DriverEntry) | 3 real `.sys` loaded and run — `GUEST_RUN` |
| Coverage measurement | `import_coverage.py --ntoskrnl` from build-emitted `ntoskrnl-exports.json` — `HOST_TESTED` |
| No regression | `run_k64_standalone.py` 14/14, `shz.py test --suite host` 5/5 — `GUEST_RUN`/`HOST_TESTED` |

---

## 4. KMDF plan (Microsoft's MIT WDF source)

Most modern Intel function drivers are **KMDF**, linking `WdfLdr`/`wdfldr.sys` and calling into a
version of `Wdf01000.sys` via the `WdfFunctions` table fetched by `WdfVersionBind`. The honest
path is to build Microsoft's **open-source WDF** (github.com/microsoft/Windows-Driver-Frameworks,
MIT) `Wdf01000.sys` as another module the host loads, so its own `DriverEntry` runs on this WDM
core; the host then only needs the WDM primitives WDF itself imports from `ntoskrnl`/`hal` (a
large but finite subset, most already present). KMDF's `WDFDEVICE`/`WDFQUEUE`/`WDFREQUEST` map onto
the DEVICE_OBJECT/IRP model implemented here. This is designed for but **not yet built**
(`SOURCE` plan only).

## 5. Class frameworks and which Intel families need which

A function driver is only loadable when its **class framework** is present. Honest-effort classes:

| Family (examples) | Needs | Status |
| --- | --- | --- |
| Chipset/LPC/SMBus/GPIO/PECI, `.inf`-only "null" drivers | WDM/KMDF only | **reachable now** (WDM core done; KMDF planned) |
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
- **Not claimed:** that any specific Intel production driver loads today. None was run. The export
  surface a real `igdkmd64`/`e1i68x64`/`iaStorAC` imports is far larger than 183 and includes the
  framework DLLs above; `import_coverage.py --ntoskrnl` on such a package is the honest next
  measurement, and it will show the gap quantitatively.
