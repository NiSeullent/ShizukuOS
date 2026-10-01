# NTWrapper9x native VxD adapter

This directory builds an original `NTWRAP9X.VXD` for **Windows 98 Shizuku's
Second Edition**, plus a Windows 98 Win32 query program. It connects the existing
NTWrapper9x core to a real i386 VxD control procedure and emits a Linear Executable
(LE) container with an ordinal-1 device descriptor block (DDB) and relocation
records. It does not import KernelEx, an NT kernel, a proprietary DDK library, or
third-party VxD implementation code.

**The refreshed production driver has host evidence only. Its Windows 98 load,
VMM service execution and Win32 query remain unverified.** A separate control-only
fixture with code/data flags `0x2065/0x2063` passed actual Windows 98 SE load and
unload (CF=0, AX=0, DOS exit=0). The otherwise identical shared fixture retaining
permanent-resident bit `0x0200` failed with CF=1, AX=6. This production candidate
adopts the accepted flags, with shared/preloaded 32-bit RX code and RW data; it
does not inherit that fixture's native verdict. Earlier complete-driver failures
and default artifacts remain archived. The manifest and host receipt keep the
production native fields false.

## Build and host validation

From the repository root:

```sh
python3 -B ntwrapper/vxd/build.py --out build/shizukudos/ntwrapper-vxd-shared-nonresident
python3 -B ntwrapper/vxd/test.py --out build/shizukudos/ntwrapper-vxd-shared-nonresident
python3 -B ntwrapper/vxd/inspect_le.py build/shizukudos/ntwrapper-vxd-shared-nonresident/NTWRAP9X.VXD
```

Required installed tools are Python 3, Clang with the i386 bare-metal target,
NASM, GNU `ld`/`nm`, and `i686-w64-mingw32-gcc`/`objdump`. `CLANG` and `MINGW_CC`
override the build compilers. Host sanitizer tests use `clang` directly. All
generated files stay in the explicitly selected `build/` component in this trial,
preserving earlier `ntwrapper/vxd/build/` artifacts. The existing CLI default
remains `ntwrapper/vxd/build/` for deliberately requested normal rebuilds.
Commands do not install or load
a driver, operate hardware, download dependencies, or alter a guest.

The build produces:

| File | Purpose |
| --- | --- |
| `NTWRAP9X.VXD` | i486 LE driver with shared/preloaded RX/RW objects, flags `0x2065/0x2063` |
| `NTWRAP9X.elf` | intermediate ELF containing retained relocation metadata |
| `NTWQUERY.EXE` | freestanding i486 PE32 guest query probe, Windows 4.10 subsystem |
| `manifest.json` | exact driver/probe hashes, compiler versions, build input hashes |
| `host-tests.json` | test status, artifact/source/test hashes, explicit guest limits |
| `host-tests.log` | unittest and sanitizer result log bound by the receipt |

`test.py` requires artifacts matching the current build manifest. It also detects
source/artifact changes during testing. Its container and dispatch groups cover actual emitted
LE relocations at three independent load-base pairs, cross-page fixup records,
malformed containers, 1,000 bounded mutations, exact native service constants
(including the single guarded `VMCALL`/`CPUID`), missing ELF imports, the PE probe
contract, page-operation failure cleanup, and the WIN64 subsystem bridge model.
A further group rejects every single-bit object-flag change, the earlier
resident/nonshared layouts, and swapped RX/RW permissions; the reader accepts
only the two exact production flags.
The C bridge tests run under ASan/UBSan. A freestanding i386 user-process harness
executes the actual assembly control dispatcher with substituted C entrypoints;
it tests registers, stack balance, direction flag, and carry/result conventions.
It does **not** execute privileged interrupt masking or VMM service instructions.

The current suite has thirteen test groups. The WIN64 tests additionally execute
reentrant admission, channel geometry/epoch changes, duplicate pool request IDs,
foreign/stale/wrong-opcode responses and corrupt ring indices. A real pthread
overlap test runs under ASan/UBSan and TSan: a paused owner retains the endpoint,
an overlapping caller receives `ERROR_BUSY` before any page callback, then the
owner resumes and a subsequent request succeeds. It also checks shutdown refuses
that admitted owner and races shutdown against W64 entry across 128 externally
initialized rounds. These remain host tests of the
production C boundary, not native VMM scheduling evidence.

## Implemented native path

The control procedure accepts dynamic initialization (`0x1b`), dynamic exit
(`0x1c`), and Win32 device control (`0x23`, descriptor in ESI). Unknown broadcasts
are ignored. Initialization creates an NTWrapper9x private core context and runs
a real auto-reset event create/pending/set/consume/pending/close check before
allowing queries. Exit shuts down that context. The original i386 bridge preserves
caller registers and flags except the documented EAX/carry results, and clears DF
before entering C.

The DIOC descriptor is a trusted VWIN32-owned 48-byte structure; its application
buffer fields are untrusted addresses. Open code `0` returns zero without touching
buffers. Close code `0xffffffff` returns `VXD_SUCCESS` (1) with carry clear, following
the Microsoft MSDN example cited in [REFERENCES.md](REFERENCES.md). Unknown
application controls return `ERROR_NOT_SUPPORTED` (50).

The only application operation is synchronous `NTWV_IOCTL_QUERY = 0x4e540001`.
It takes no input or OVERLAPPED structure and writes the following eight little
endian DWORDs into a buffer of at least 32 bytes:

| Offset | Field | Current value |
| --- | --- | --- |
| 0 | `magic` | `0x3957544e` (`NTW9`) |
| 4 | `size` | 32 |
| 8 | `abi` | 1 |
| 12 | `core_abi` | `NTW_ABI_VERSION` |
| 16 | `max_objects` | `NTW_MAX_OBJECTS` |
| 20 | `features` | bit 0: version query only |
| 24 | `initialized` | 1 after successful core initialization |
| 28 | `selftest` | 1 after the internal event selftest |

`max_objects` describes the private linked core; it does not advertise an exposed
event/object IOCTL ABI. There are no fake-success NT service exports.

The buffer policy accepts only the Win32 private arena `0x00400000..0x7fffffff`.
It rejects zero/overflowing ranges, short output, input data, OVERLAPPED requests,
and overlapping output/count virtual ranges. `_PageCheckLinRange` must return the
full requested page count; that result is **not** treated as a permission check.
The adapter then pins both ranges with `_LinPageLock(PAGEMAPGLOBAL)`. For each range,
`_CopyPageTable` must show present/writable/user original pages and present/writable
alias pages referring to the same physical frames. Only after both checks pass
does it copy the 32-byte reply and the four-byte returned count to the pinned
aliases. It releases count then output in reverse acquisition order on every
applicable exit path. If an unlock reports failure, both releases are still
attempted and the request returns `ERROR_NOACCESS` (998).

Bad structure arguments return 87, short output 122, unsupported callbacks/control
50, inactive core 21, and page validation/locking/unlocking failures 998. No bytes
are written on validation failure before copying; the returned count remains
untouched by this adapter. An unlock failure can occur after both output writes;
the caller must treat the returned error as authoritative. These are adapter-level
semantics; VWIN32 may independently normalize the Win32 count on failed calls.

The native locking assumption is **uniprocessor Windows 98, synchronous DIOC**.
Page checks and pinning happen with the caller's original interrupt state; the
bounded PTE validation and copy interval saves/disables/restores interrupts. This
assumes `_CopyPageTable` remains a nonblocking metadata operation in that context.
The current PTE policy also assumes the normal VMM Win32 private-arena page-directory
permissions. These native assumptions require actual guest validation. The code
and static data touched inside the interrupt-masked interval also require a
nonpageability/lifetime check in the production guest; preload proves initial
presence and the control fixture does not prove paging behavior for this full
implementation. This is
not an SMP, asynchronous, shared-memory, DMA, or universal safe-copy facility.

## WIN64 subsystem bridge (ShizukuDOS ABI 1.1)

Under the ShizukuDOS Supervisor the Windows 98 installation is one domain among
several; a Long Mode Kernel64 domain runs Win64 PE32+ programs beside it. The
VxD is the Win98 domain's endpoint of the shared-memory channel to Kernel64
(`shizukudos/abi/shz_ipc.h`, message family `0x200..`): it maps the channel
window the Supervisor exposes at a guest-physical address (`_MapPhysToLinear`),
pushes frames that `NTW32.DLL` hands it, pops frames for it and rings the peer's
doorbell with `VMCALL`. The application never sees a channel address, and the
VxD overwrites the source/destination domain and generation of every frame it
sends, so a program cannot spoof another domain or reference pool memory it did
not hand over in the same request.

| Control code | Input | Output | Result |
| --- | --- | --- | --- |
| `0x4e540010` `W64_OPEN` | none | 64-byte `struct ntwv_w64_open` (ABI version, channel id, domains, generation, ring depth, pool size, counters) | 50 without the Supervisor signature, 1306 on an ABI major mismatch, 55 when no Kernel64 channel is announced or the opened epoch changed, 8 when the window cannot be mapped, 31 for invalid/changed layout |
| `0x4e540011` `W64_SEND` | 64-byte header + inline payload (<= 192) [+ up to 3,840 bytes of pool data, at most 4,096 in total] | `int32` status | 87 for inconsistent lengths, 170 for overlap, a full transmit ring, four outstanding pool blocks or a duplicate outstanding pool request ID, 8 when the pool is exhausted |
| `0x4e540012` `W64_RECV` | none | one 256-byte slot (header + payload, zero padded) | 259 (`ERROR_NO_MORE_ITEMS`) when no acceptable frame is found in one bounded ring-depth drain; invalid frames are consumed and counted; corrupt nonconsumable indices return 31 |
| `0x4e540013` `W64_WAIT` | `uint32` timeout (advisory) | `uint32` doorbell mask | acknowledges the doorbell; **does not block** in this revision |

Pool data attached to a `SEND` is copied into a block the VxD allocates in the
channel pool (owned by the Win98 domain); the block is released when the reply
carrying the same request id and opcode is received from Kernel64 for Win98 in
the live channel generation. Foreign or stale frames, invalid flag combinations
and unsupported incoming pool references are dropped before delivery or pool
release. A pool request ID cannot be reused while its block is outstanding.
The user buffers follow the same
policy as the query: private arena only, no overlap, pinned, PTE-validated under
disabled interrupts, input copied into kernel memory before any ring or
hypercall work, and the reply copied out after re-validation. The host test
`tests/test_w64vxd.c` drives all four codes against a real
`shz_channel_init()` region and checks every frame with the Kernel64 library,
injects malformed slots, exhausts the ring and the pool bookkeeping, and fails
each of the 19 VMM calls of a `SEND` in turn.

Each W64 DIOC takes an atomic, nonblocking admission token covering scratch
buffers, both ring endpoints and pool bookkeeping. Overlapping/reentrant W64
calls return 170 before page pinning; the token is released on every normal
success/error return. Shutdown refuses an admitted request, and reset leaves
its state intact. Readiness and query selftest flags use consistent atomic
accesses, including checks before admission, so shutdown cannot race a plain
lifecycle read. Initialization remains externally serialized with every entry
and lifecycle operation because it initializes the underlying object context.
The original QUERY controls and payload remain unchanged. The original bounded interrupt-masked safe-copy intervals
retain their Windows 98 single-vCPU assumptions; admission does not broaden
those VMM page-service assumptions to SMP.

OPEN validates disjoint header/owner-table, ring and pool ranges, aligned bounded
slot/pool sizes, ring/header agreement and the announced channel ID. Operations
compare the live geometry and generation with the captured layout. Epoch changes
return 55 until explicit reset/reopen; layout corruption returns 31. Reset forgets
local state and never frees outstanding pool blocks because the peer may still
consume queued requests. Those blocks require a terminal response or a proven
Supervisor-owned channel teardown; this revision has no cancellation/rundown
acknowledgement.

Limits: `W64_WAIT` is non-blocking (a blocking wait needs the Supervisor's
doorbell vector hooked through VPICD); `_MapPhysToLinear` mappings are never
released; the VxD does not verify that the Win98 domain is really `SHZ_DOM_WIN98`
beyond the channel header the Supervisor initialised. NTW32's caller serialization
and the absence of per-process reply ownership remain limits even though the VxD
now enforces endpoint admission. The refreshed artifact has not run inside
Windows 98 or under the Supervisor. Frozen prior native production load/query
and absent-Supervisor `W64_OPEN=50` evidence is preserved in
[the application campaign](../../docs/shizukudos10/reports/MODERN_APPS_CAMPAIGN.md);
it does not validate this new artifact or a positive live Kernel64 channel.

## Guest probe

Copy `NTWRAP9X.VXD` and `NTWQUERY.EXE` together into a dedicated directory in a
disposable Windows 98 guest. Run `NTWQUERY.EXE` from that directory after Windows
has started. It opens `\\.\NTWRAP9X.VXD` using `CreateFileA`, `OPEN_EXISTING`, and
`FILE_FLAG_DELETE_ON_CLOSE`; it does not edit SYSTEM.INI or install a boot driver.

The program writes and flushes `NTWQUERY.LOG` after each stage. It validates the
query payload, unsupported control 50, short output 122, and unexpected input 87;
it then closes and repeats the load/open/query sequence. The final expected line is
`PASS: NTWrapper9x native VxD probe 0x00000000`, and the process exit code is zero.
Each earlier line records the completed stage or failing Win32 error in hexadecimal.
The two cycles request unload via close; they do not independently prove that VMM
discarded the image between cycles. Do not treat this paragraph as a recorded pass.

## Container scope and remaining work

`le.py` is a deliberately narrow original packager for this freestanding ELF32
i386 executable, not a general ELF/LE linker. It derives internal absolute and
cross-object relative fixups from retained ELF relocation records, exports the
DDB at ordinal 1, supplies fully initialized data/BSS, and duplicates a fixup
crossing a page boundary into both page records. `inspect_le.py` independently
parses that supported subset and simulates relocation. Native loader edge cases
remain unverified.

Before expanding the public kernel interface, the project still needs actual
Windows 98 loader/VMM proof, per-open ownership, cancellation/process-exit cleanup,
blocking scheduler integration, and broader hostile-buffer testing. There is no
CONFIGMG/PCIe resource binding, native interrupt/DMA registration, NT driver binary
compatibility, WDM/WDDM emulation, or Win32 application migration supplied by this
VxD. The private core provides the existing limited event/object primitives.

All implementation, tests, DOS exit stub, assembly glue, and container generation
here were written independently for this project. Public ABI facts and their
limits are recorded in [REFERENCES.md](REFERENCES.md); no referenced source is
downloaded or linked by the build.
