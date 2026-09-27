# NTWrapper9x native VxD adapter

This directory builds an original `NTWRAP9X.VXD` for **Windows 98 Shizuku's
Second Edition**, plus a Windows 98 Win32 query program. It connects the existing
NTWrapper9x core to a real i386 VxD control procedure and emits a Linear Executable
(LE) container with an ordinal-1 device descriptor block (DDB) and relocation
records. It does not import KernelEx, an NT kernel, a proprietary DDK library, or
third-party VxD implementation code.

**Current evidence is host-only. Windows 98 loading, VMM service execution,
and the Win32 query have not yet been verified in a Windows guest.** The build
manifest and host receipt deliberately record those fields as false. A generated
LE file and a relocation simulator are not evidence of successful Windows loading.

## Build and host validation

From the repository root:

```sh
python3 -B ntwrapper/vxd/build.py
python3 -B ntwrapper/vxd/test.py
python3 -B ntwrapper/vxd/inspect_le.py ntwrapper/vxd/build/NTWRAP9X.VXD
```

Required installed tools are Python 3, Clang with the i386 bare-metal target,
NASM, GNU `ld`/`nm`, and `i686-w64-mingw32-gcc`/`objdump`. `CLANG` and `MINGW_CC`
override the build compilers. Host sanitizer tests use `clang` directly. All
generated files stay in `ntwrapper/vxd/build/`; the commands do not install or load
a driver, operate hardware, download dependencies, or alter a guest.

The build produces:

| File | Purpose |
| --- | --- |
| `NTWRAP9X.VXD` | i486 LE driver with separate resident code/data objects |
| `NTWRAP9X.elf` | intermediate ELF containing retained relocation metadata |
| `NTWQUERY.EXE` | freestanding i486 PE32 guest query probe, Windows 4.10 subsystem |
| `manifest.json` | exact driver/probe hashes, compiler versions, build input hashes |
| `host-tests.json` | test status, artifact/source/test hashes, explicit guest limits |
| `host-tests.log` | unittest and sanitizer result log bound by the receipt |

`test.py` requires artifacts matching the current build manifest. It also detects
source/artifact changes during testing. Its ten test groups cover actual emitted
LE relocations at three independent load-base pairs, cross-page fixup records,
malformed containers, 1,000 bounded mutations, exact native service constants,
missing ELF imports, the PE probe contract, and page-operation failure cleanup.
The C bridge tests run under ASan/UBSan. A freestanding i386 user-process harness
executes the actual assembly control dispatcher with substituted C entrypoints;
it tests registers, stack balance, direction flag, and carry/result conventions.
It does **not** execute privileged interrupt masking or VMM service instructions.

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
permissions. These native assumptions require actual guest validation. This is
not an SMP, asynchronous, shared-memory, DMA, or universal safe-copy facility.

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
