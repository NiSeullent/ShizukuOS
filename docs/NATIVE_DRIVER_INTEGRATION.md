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
the flags argument is reserved and zero. This prototype does not establish
the compiler's callback stack-cleanup convention.
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

## Resource layout findings and unresolved ABI values

The archived **Windows 95 DDK** explicitly describes the following layouts.
The sizes below are calculated from its WORD/ULONG fields under ordinary i386
C alignment; they are not a Windows 98 guest measurement.

| Descriptor | Documented fields, in order | Calculated size |
| --- | --- | --- |
| `MEM_DES` | WORD count/type, ULONG allocated base/end, WORD flags/reserved | 16 bytes |
| `MEM_RANGE` | ULONG alignment/byte count/minimum/maximum, WORD flags/reserved | 20 bytes |
| `IRQ_DES` | WORD flags/allocated IRQ/request mask/allocated mask | 8 bytes |

`MEM_RESOURCE` contains that memory header followed by memory ranges;
`IRQ_RESOURCE` contains only the IRQ header. Memory count/type describe the
number and byte size of range records; `fIRQD_Share` names the IRQ sharing flag.
These pages establish field widths and order for the documented version, but
do not supply its numeric flag value or prove unchanged Win98 definitions.
[MEM_DES](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2584.HTM),
[MEM_RANGE](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2585.HTM),
[IRQ_DES](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2582.HTM),
[MEM_RESOURCE](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2586.HTM),
[IRQ_RESOURCE](https://techshelps.github.io/MSDN/WIN95DDK/HTML/S2583.HTM).

Do **not** substitute modern `cfgmgr32.h` declarations: Microsoft's current
`MEM_DES` uses DWORD counters and DWORDLONG addresses, while `IRQ_DES_32`
includes counters and affinity. These differ materially from the historical
VxD resource records. A modern Win32 Configuration Manager header is not proof
of the Win98 ring-zero CONFIGMG ABI.
[Current MEM_DES](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/ns-cfgmgr32-mem_des),
[current IRQ_DES_32](https://learn.microsoft.com/en-us/windows/win32/api/cfgmgr32/ns-cfgmgr32-irq_des_32).

Still unverified from the primary material inspected: Win98-specific descriptor
continuity; numeric `ALLOC_LOG_CONF`, resource IDs, registration/message/error
flags; CONFIGMG device/service identifiers and ordinals; native argument widths,
callback cleanup and valid call contexts. Alphabetical documentation order is
not a service table. Obtain version-identified factual header declarations or
equivalent authoritative documentation before authoring thunks or parsers.

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
