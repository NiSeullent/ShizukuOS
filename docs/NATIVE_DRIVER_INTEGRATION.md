# Native Windows 98 driver integration

Research checkpoint: 2026-09-27. Product: **Windows 98 Shizuku's Second
Edition**. This is an implementation plan grounded in public Microsoft interface
documentation, not a claim that AHCI, xHCI, CONFIGMG or IOS is integrated with
Windows 98. The original [VxD adapter](../ntwrapper/vxd/) and
[AHCI core](../drivers/ahci_native/) are separate components. Their host tests
and the [isolated AHCI guest proof](STORAGE_UTF_CHECKPOINT.md) do not establish a
Windows 98 storage driver. Native VxD loading/querying must have its own guest
receipt before this binding advances.

Historical Microsoft documents below are available through public mirrors;
their original target versions matter. No DDK implementation, sample driver,
binary library or guessed service binding is incorporated by this note.

## Ownership and the first useful binding

Use a disposable **secondary AHCI controller**, with the Win98 boot/system disk
on a different controller. Establish exclusive ownership of the complete PCI
function through its assigned devnode and configuration lifecycle. The AHCI
core disables interrupts and stops every implemented port; sharing the HBA with
an existing driver, paging file or filesystem is incompatible with its contract.
Finding an AHCI class code or a usable BAR does not establish ownership.

Microsoft's Win98 DDK correction documents
`CONFIGMG_Register_Device_Driver(devnode, handler, refdata, flags)`.
`PNP_NEW_DEVNODE` supplies the devnode in EBX; the registered handler receives
configuration notifications such as START and STOP. Win98 adds synchronous,
asynchronous and ACPI/APM registration choices. Drivers must not claim power
compliance without implementing the required lifecycle; omission of the ACPI/APM
flag entails unloading at suspend and reloading at resume.
[Microsoft KB247251](https://ftp.zx.net.nz/pub/archive/ftp.microsoft.com/MISC/KB/en-us/247/251.HTM).

The documented configuration callback has five arguments: function,
subfunction, devnode, reference DWORD and flags. It returns `CONFIGRET`;
the flags argument is reserved and zero. The archived Win98 header identified
below explicitly declares this callback `_cdecl`.
[Microsoft DDK ConfigHandler](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S255E.HTM).

Read the **allocated** logical configuration using
`CONFIGMG_Get_First_Log_Conf(..., ALLOC_LOG_CONF)`, then enumerate resource
handles with `CONFIGMG_Get_Next_Res_Des`; `ResType_All` also returns the type.
Query each data size before copying it. A short buffer can receive truncated
data with `CR_BUFFER_SMALL`, which must not be parsed as a complete descriptor.
Require an adequate assigned MMIO range and a supported IRQ configuration;
do not use the requirements list as evidence of allocation.
[First logical configuration](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2527.HTM),
[next descriptor](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S252B.HTM),
[descriptor size](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2530.HTM),
[descriptor data](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S252F.HTM).

## Versioned header findings

A public archive identifies its DDK as synchronized to **Windows98 build
bld1998.6**. Its CONFIGMG header defaults to version `0x040A`; `WIN40COMPAT`
selects `0x0400`. The C and assembler declarations agree. This is an identifiable
archived Microsoft header set, not an authenticated Microsoft download or a
measurement of the target Windows 98 SE kernel. No headers, inline wrappers,
sample implementations or libraries were incorporated into this project.
[Build identifier][ddk-build], [C declarations][ddk-config-h],
[assembler declarations][ddk-config-inc].

The header includes `pshpack1.h`, which selects one-byte structure packing.
Offsets below are derived from that declaration and the matching assembler
DW/DD fields, not from host C `long` sizes.

| Descriptor | Field offsets and widths | Size |
| --- | --- | --- |
| `MEM_DES` | count 0:u16, type 2:u16, allocated base 4:u32, end 8:u32, flags 12:u16, reserved 14:u16 | 16 |
| `MEM_RANGE` | alignment 0:u32, byte count 4:u32, minimum 8:u32, maximum 12:u32, flags 16:u16, reserved 18:u16 | 20 |
| `IRQ_DES` | flags 0:u16, allocated IRQ 2:u16, request mask 4:u16, reserved 6:u16 | 8 |

In particular, Win98's final IRQ word is **reserved**, unlike the allocation-mask
label in the earlier [Win95 IRQ page](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2582.HTM).
Memory ranges follow the memory header; the IRQ resource contains only its
header. IRQ share/level flags are `1`/`2`. `ResType_All/Mem/IRQ` are `0/1/4`;
`ALLOC_LOG_CONF` is `2`. Use the allocated base/end fields, not a request range,
to determine an assigned aperture. These memory fields cannot represent an
aperture above 4 GiB.
[Packed declarations][ddk-config-inc], [packing header][ddk-pack].

`VMM.INC` assigns CONFIGMG device ID `0x0033`. Its service-table definitions
start at zero and form the service identifier from `(device_id << 16) | index`.
Both CONFIGMG tables have the same 124 entries, including this relevant prefix:

| Service suffix, following `_CONFIGMG_` | Index | Service identifier |
| --- | --- | --- |
| `Get_Version` | `0x00` | `0x00330000` |
| `Register_Device_Driver` | `0x0E` | `0x0033000E` |
| `Get_First_Log_Conf` | `0x1A` | `0x0033001A` |
| `Get_Next_Log_Conf` | `0x1B` | `0x0033001B` |
| `Get_Next_Res_Des` | `0x1F` | `0x0033001F` |
| `Get_Res_Des_Data_Size` | `0x21` | `0x00330021` |
| `Get_Res_Des_Data` | `0x22` | `0x00330022` |
| `Get_Alloc_Log_Conf` | `0x3B` | `0x0033003B` |

These indices were counted from service declarations, not alphabetical API
documentation. `Get_Alloc_Log_Conf` takes a `CMCONFIG` buffer; it is distinct
from `Get_First_Log_Conf`, which returns a logical-configuration handle.
[Service ordering][ddk-config-inc], [device ID and ordinal construction][ddk-vmm].

In the 32-bit declaration, handles, resource IDs, callback arguments and
`CONFIGRET` are 32-bit; the callback is `_cdecl`. The header describes ordinary
service results in EAX and permits ECX/EDX clobbering; `Get_Version` is exceptional.
`CR_SUCCESS`, `CR_NO_MORE_LOG_CONF`, `CR_NO_MORE_RES_DES`, `CR_BUFFER_SMALL`
are `0`, `0x0E`, `0x0F`, `0x1A`. Native thunk stack/register behavior must still
be checked with an actual guest before device resources are touched.
[Native type and result declarations][ddk-config-h].

Do **not** substitute modern `cfgmgr32.h` declarations: Microsoft's current
`MEM_DES` uses DWORD counters and DWORDLONG addresses, while `IRQ_DES_32`
includes counters and affinity. These differ materially from the historical
VxD resource records. A modern Win32 Configuration Manager header is not proof
of the Win98 ring-zero CONFIGMG ABI.
[Current MEM_DES](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/ns-cfgmgr32-mem_des),
[current IRQ_DES_32](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/ns-cfgmgr32-irq_des_32).

Still unresolved: independent authentication against the original DDK media,
target SE service behavior, permitted call contexts, borrowed-handle lifetime,
driver registration/removal ownership, and cleanup across configuration and
power transitions. Do not mistake `Free_Log_Conf` or `Free_Res_Des`, which alter
configuration, for a modern API's handle-only release function. This research
does not authorize an already-owned PCI device to be rebound.

## MMIO, DMA and interrupts

The older Microsoft VxD guide documents `_MapPhysToLinear`, `_PageAllocate`
and `VPICD_Virtualize_IRQ`. Fixed system pages are a candidate for the core's
single 4 KiB DMA allocation; physical addressing must be verified separately
from its CPU mapping. Its hardware IRQ callback returns with a near RET;
carry distinguishes an unhandled shared interrupt. Acknowledging the device
and issuing VPICD EOI are separate responsibilities. This Windows 3.0 material
does not settle Win98 MMIO caching/unmapping, DMA allocation restrictions,
extended IRQ descriptors, sharing flags or safe unvirtualization.
[Microsoft Virtual Device Adaptation Guide, chapters 19 and 37](https://www.pcjs.org/documents/books/mspl13/win/w3ddkvxd/).

The binding must supply uncached MMIO, stable contiguous DMA and ordering,
a native monotonic clock, and a suitable execution context for bounded waits.
Never convert a virtual pointer directly to a DMA address. Stop new requests
before STOP/REMOVE/suspend, finish or cancel outstanding work, confirm the HBA
can no longer DMA, then release memory and mappings. If the core reports
quarantine, retain its context, callbacks and DMA memory; unloading that code
would invalidate the quarantine guarantee. Exact OS lifecycle mechanisms remain
to implement and test. MSI/MSI-X support is outside this initial binding.

## IOS storage publication comes after private diagnostics

Microsoft documents `SYS_DYNAMIC_DEVICE_INIT` registration through
`IOS_Register(&DRP)`, with an asynchronous-event entry, ILB storage and a checked
registration result controlling residency. Its event flow includes INITIALIZE,
DEVICE_INQUIRY, CONFIG_DCB, IOP_TIMEOUT and BOOT_COMPLETE. Initialization creates
an IOS adapter DDB through `ILB_service_rtn`; configuration inserts a request
entry into the call-down chain. That **IOS adapter DDB is distinct from the LE
loader's VxD DDB** already emitted by this project.
[Port-driver initialization](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2F87.HTM),
[asynchronous events](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2F88.HTM),
[IOS service packets](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2F60.HTM).

The request entry receives an IOP pointer on the stack. It examines the IOR
function, transfer and scatter/gather information, then sets status and invokes
the completion chain. The current blocking AHCI loop is not yet a general IOS
request scheduler. Exact DRP/ILB/AEP/ISP/DCB/IOP/IOR packing, constants, service
ordinals, completion stack cleanup and callback-chain advancement remain
prerequisites. The archived event/service pages even use different
`ISP_DDB_CREATE`/`ISP_CREATE_DDB` spellings; names alone cannot define the ABI.
[Request processing](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2F89.HTM),
[DRP fields](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S302E.HTM).

The proposed evidence sequence is:

1. Native load/query/unload of the existing VxD, bound to exact artifact hashes.
2. Owned secondary devnode, assigned resources and read-only CAP/PI/VS reporting.
3. Verified native MMIO/DMA/clock lifetime, followed by private IDENTIFY and one
   sector read; independently compare data and confirm the disk is unchanged.
4. Fault, STOP/REMOVE, suspend and unload tests, including retained DMA failure.
5. IOS registration and a read-only disk request/completion path, initially
   restricted to the tested controller and transfer shape.

Each stage needs its own actual Windows 98 receipt. None establishes modern
vendor-driver compatibility, a complete WDM/WDDM layer, USB device support,
boot-storage support or physical-hardware compatibility.

## Header-source provenance

Only small public interface files and identifying text were read, in memory.
All archive links below pin repository commit
`0c662d32378b9940ed90aee682f4eb5daf816e6a`; SHA-256 values cover the raw bytes.
The unrelated top-level PowerToys readme was not used as DDK version evidence.

| File under `98DDK/` | SHA-256 |
| --- | --- |
| [build.txt][ddk-build] | `beb83e3241c62692cc6809115b43a076e3a977eeb2e9ba46f7bbb5216b66ff1a` |
| [inc/win98/CONFIGMG.H][ddk-config-h] | `012d6e6c8081f03c1e8eb37a54cfaa56554c52b444ec403c2a7bfd5eea05b000` |
| [inc/win98/CONFIGMG.INC][ddk-config-inc] | `e688e53a6e5a601375b149b0699f2dd704bbef43c0dd309291a9bbb887394a36` |
| [inc/win98/VMM.INC][ddk-vmm] | `d640c2994970fabe36c6d4f47ac94b719554d19dc036807c56fe9252ded6d1b2` |
| [inc/win98/PSHPACK1.H][ddk-pack] | `7b33a921482a4f247721a0f2f4329228b7bac3faabbaf40f4ff4864126a5bb98` |

[ddk-build]: https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/build.txt
[ddk-config-h]: https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/CONFIGMG.H
[ddk-config-inc]: https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/CONFIGMG.INC
[ddk-vmm]: https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/VMM.INC
[ddk-pack]: https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/PSHPACK1.H
