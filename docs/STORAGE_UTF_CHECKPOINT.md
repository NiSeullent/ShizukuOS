# Windows 98 Shizuku's Second Edition — storage and UTF checkpoint

Date: 2026-09-27. This checkpoint adds an independently implemented AHCI read
path executing after UEFI exit, and UTF-8 Win32 conversion exports in the
app-local NTWin32Wrapper9x DLL. It does not establish modern Windows application
compatibility, a Windows 98 storage miniport, or UEFI boot into the Windows GUI.
The [previous native checkpoint](NATIVE_PLATFORM_CHECKPOINT.md) and its archive
remain historical snapshots with their original 13-export DLL and proofs.

| Component | Evidence | Boundary |
| --- | --- | --- |
| NTWin32Wrapper9x | 15 PE32 exports including original UTF-8/UTF-16 conversion | Other code pages delegate to native KERNEL32; Win98 execution remains unverified |
| Compiled DLL ABI | 379 checks and 135 actual PE calls at each of two load bases; 54 relocation sites | Linux executes PE machine code with seven original Windows import mocks |
| AHCI driver | Real IDENTIFY and two READ DMA EXT transfers through QEMU ICH9; 1,024 pattern bytes checked | Exclusive controller, polling, coherent DMA, one 512-byte sector per command |
| ShizukuDOS binding | x64 UEFI exit, actual CPL0 32-bit kernel, independent CPU-register and DMA-memory inspection | Controlled VM identity mapping; no general physical-platform or Win98 DMA mapper |
| NTWrapper9x / NTWDDMWrapper9x | Original core and software-presentation tests execute in the storage guest | Scheduler, native display driver, GPU execution and NT WDDM ABI remain incomplete |

## UTF implementation

The original `ntwin32/unicode/` implementation covers all 1,112,064 Unicode
scalar values. Strict and ASan/UBSan runs each passed 15,578,938 assertions;
an independent host-codec oracle checked 80,129 UTF-8 and 4,826 UTF-16 cases.
Malformed input either produces Unicode maximal-subpart replacement or fails
in strict mode. Conversion validates sizes before output, preserves embedded
NULs for explicit lengths, handles NUL-inclusive `-1` lengths, and leaves output
unchanged on failure.

The actual DLL exports `MultiByteToWideChar` and `WideCharToMultiByte` alongside
seven SRW functions, four InitOnce functions, `GetTickCount64` and scoped
`GetProcAddress`. UTF-8 uses the original core; other code pages preserve the
native Windows 98 implementation. No KernelEx, Wine, ReactOS, CRT conversion
library or third-party Unicode implementation is linked.

The PE32 harness executes the built DLL at `68000000` and `69000000`, checks
stack cleanup on every call, and tests UTF errors, output bounds, 131,073-byte
strings, dynamic routing and unchanged argument forwarding to native imports.
These tests do not substitute for the Windows 98 loader or native Windows
differential results.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `build/platform/NTW32.DLL` | 17,151 | `2720dcffac234202598de8498cfbf804d9d3cbfb1c6a9c796a8e5e8398055c24` |
| `build/platform/NTWPROBE.EXE` | 14,336 | `9b764f420933b1ef0b5007f6713f1dfc694a077d5101fc69c04bdf168146bbf2` |
| `shizukudos/uefi_ahci/build/BOOTX64.EFI` | 31,232 | `be234d007749cc1820492bf896f92b454bcd0a456b2785ffcea8eb2fd84dbf86` |
| `shizukudos/uefi_ahci/build/payload.bin` | 13,111 | `029900eb8acd85417a1f87606f1f8a6530dc6bb708ec530818e0c3a97c1a0d74` |

## Actual storage execution

The [AHCI core](../drivers/ahci_native/README.md) supplies bounded ownership,
stop ordering, DMA structures, IDENTIFY parsing and reads. Its host model
passed 5,034,065 assertions, all 94 injected callback failure positions and
ASan/UBSan. The freestanding i486 object has no unresolved runtime dependencies.
DMA storage is retained whenever stopping the engine cannot be proved.

The [live integration](../shizukudos/uefi_ahci/README.md) passed under KVM in
3.291 seconds. QEMU independently reported halted `CS32`, CPL0,
`CR0=00010033`, `CR4=00000648`, `EFER=00000800`, with instruction and stack
addresses inside the reserved low-memory payload. The controller was
`8086:2922` at `00:1f.2`; the disposable disk reported 16,384 512-byte sectors.
LBAs 7 and 11 matched all 1,024 expected bytes. A separate physical DMA dump
matched the last sector with a 512-byte transfer count. Open, reads and close
returned success; no DMA allocation was quarantined.

The whole-disk SHA-256 remained
`6b53aeb8c867d39ae4fdb39cdfa58aee73ff843fb6fc2a002eab08ee961a60aa`.
The guest exited before receipt publication. The
[durable validation record](../shizukudos/uefi_ahci/VALIDATION.json) binds source,
build, guest, driver-test, register, DMA and screenshot hashes.

Actual execution exposed three gaps in the first host model: cold signatures
arrive after FIS reception starts; QEMU's initial task-file `130` is a reset
signature state; and IDENTIFY word 76 advertises NCQ without SATA speed bits.
Regressions now cover these states. Completed commands still reject DF, ERR,
busy state, link loss, controller errors and incorrect transfer counts.

## Reproduction and remaining work

Use [platform/README.md](../platform/README.md) for commands. The package is
`build/windows98-shizuku-second-edition-storage-utf-checkpoint.zip`.
Its sibling checksum and `build/platform/package-rebuild.json` record exact
packaged bytes and the extraction/rebuild result. It excludes Windows media,
keys, guest disks, firmware binaries and third-party implementations. Packaging
rejects mismatched sources, artifacts or required receipts.

The user-supplied Korean OEM ISO was hash-checked and used in a separate
network-isolated installation experiment. Partitioning, formatting, ScanDisk
and entry into the graphical installer were observed. Installation and native
DLL/VxD execution remain separate pending gates; no product key has been
supplied or taken from the archive. Private installation state is excluded
from the public source and package.

Next native gates are clean Windows 98 loader/VxD execution, CONFIGMG/VMM and
storage-stack bindings, USB and display device paths, and DOS/runtime services
capable of continuing beyond this protected-mode kernel. Disk writes,
interrupt-driven I/O, recovery, hotplug, power management and physical hardware
need their own implementations and evidence.
