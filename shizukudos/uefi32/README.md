# Windows 98 Shizuku's Second Edition — native 32-bit handoff

This independently implemented boot path takes an x64 UEFI machine into an
actual **32-bit protected-mode kernel**, with paging and long mode disabled.
The payload executes the project's NTWrapper9x core and NTWDDMWrapper9x software
renderer without KernelEx, Windows libraries, firmware calls, or a C runtime.
It is the next architectural step toward a DOS/Win98 runtime; **DOS services and
Windows 98 GUI boot remain unimplemented**.

## Execution and ownership

The EFI loader reserves exactly 2 MiB of low memory through `AllocateAddress`.
Failure to reserve that region returns to firmware before any shutdown attempt.
It validates the existing page tables, including 4-KiB/2-MiB/1-GiB mappings and
4/5-level walks, to require writable, executable identity mappings. It does not
assume that a physical address is usable merely because it is below 4 GiB.
The GOP framebuffer must also fit entirely below 4 GiB.

| Physical range/address | Purpose |
|---|---|
| `02000000`–`02000FFF` | Original 64/32-bit transition, GDT and descriptor pointers |
| `02001000`–`02001FFF` | Original 256-entry IA-32e exception IDT |
| `02002000`–`020027FF` | Original 256-entry protected-mode exception IDT |
| `02004000`–`0200BFFF` | Retained UEFI memory-map buffer, actual descriptor stride |
| `0200F000` | Fixed-width, pointer-free 112-byte handoff and register receipt |
| `02010000` | Independently linked ELF32 payload entry |
| Below `02100000` | Payload code/data/BSS including its graphics arena |
| `021F0000`–`021FFFFF` | Dedicated 64-KiB boot stack; top `02200000` |

After successful `ExitBootServices`, the original assembly transition installs
its GDT and IA-32e IDT, moves onto the low stack, and uses a far return to a
32-bit compatibility code segment. It clears PCIDE before clearing CR0.PG,
switches to its 32-bit IDT, clears EFER.LME, and disables PAE/LA57. The next call
enters the fixed-address ELF32 payload. The handoff code and following
instructions remain identity mapped while paging is disabled.

The payload reads CR0/CR4/EFER/CS/SS/ESP and refuses a success result unless PE is
set, PG/PAE/PCIDE/LA57/LME/LMA are clear, CPL is zero, and its stack is in the
reserved low range. It then runs auto/manual-reset event and lease/close tests
against the original NTWrapper9x core using local IRQ exclusion, and fills,
presents, and checks a software-rendering fence through NTWDDMWrapper9x.

The image is compiled with an i486 C instruction baseline, no SSE/MMX, no hosted
library, and no unresolved symbols. The transition and register probe still
require the x64 CPU/MSR facilities inherent in the x64 UEFI starting environment;
this is **not a claim that an i486 processor supports UEFI or long mode**.

All firmware memory-map regions remain preserved. The loader does not reclaim
firmware/runtime memory or overwrite another OS. Interrupts remain disabled;
exception handlers only record a failure stage and halt. There is no IRQ
controller setup, scheduler, SMP, TSS/user-mode setup, allocator for the full
memory map, filesystem loader, 16-bit execution, BIOS interrupt emulation, DOS
API, VMM/VxD integration, or installed Windows boot. The inherited task-register
cache is unused; a future privilege-changing kernel must install its own TSS.
Secure Boot signing, arbitrary load addresses and framebuffer addresses above
4 GiB are unsupported. Physical hardware has not been tested.

## Build and verify

The recorded [2026-09-27 validation](VALIDATION.json) passed 39 host contract
checks under Clang ASan/UBSan, verified all 512 IDT gates, and completed the real
KVM handoff in 1.743 seconds. QEMU independently reported `CS32`, `CPL=0`,
`CR0=00010033`, `CR4=00000648`, `EFER=00000800`, and `EIP=02010350` in the
32-bit payload. The test process was stopped after evidence capture.

From the repository root, with the existing NASM, GCC with freestanding `-m32`,
GNU ld/objcopy/nm, MinGW x64, Clang sanitizers, Python, QEMU/OVMF and mtools:

```sh
python3 shizukudos/uefi32/build.py
python3 shizukudos/uefi32/test.py
python3 shizukudos/uefi32/test_qemu.py
```

The build creates `build/BOOTX64.EFI`, `payload.elf`, `payload.bin`,
`transition.bin` and source/artifact hashes. It checks ELF32 load addresses,
the fixed entry, section sizes, absence of runtime dependencies and relocations,
and EFI PE format/imports/relocation data. It never changes the earlier
`shizukudos/uefi/` source, build outputs or validation receipts.

The host tests check mode/ABI rejection cases, identity page-table walks,
permission/NX/reserved-bit rejection and all 512 generated exception gates.
The guest test requires a successful matching build receipt and rejects changed
sources. It starts one disposable q35 KVM guest with a host CPU model, one CPU,
256 MiB, no network, a private OVMF variable copy, and a newly created read-only
16-MiB FAT16 test medium. A watchdog caps the VM at 45 seconds. No existing VM,
host disk, download, service or machine configuration is changed.

A pass requires the live graphics screen, a physical memory snapshot of the
handoff, and **independent QEMU CPU registers** agreeing on CS32, CPL0, low EIP
and stack, PG/PAE off and LME/LMA off. Screenshots alone are insufficient.
Logs, screenshots, handoff bytes and register dumps stay under `build/`; the
final receipt records the KVM state, hashes, process ID and confirmed shutdown.
`--accel tcg` is available explicitly, but does not count as KVM evidence.

## Source provenance

All new files here are original project code under GPL-2.0-only. The loader
reuses the project's original `uefi/efi.h` and `uefi/boot.c` firmware contracts
without modifying them. The renderer reuses the project's independently drawn
capital glyphs; the kernel/display implementations are the original
`ntwrapper/` and `ntwddm/` sources. No Windows, FreeDOS, KernelEx, EDK II,
GNU-EFI implementation, SDK library, or external font is incorporated.

Architecture requirements were checked against the official
[Intel system-programming manual, IA-32e mode transitions](https://cdrdv2-public.intel.com/825758/253668-sdm-vol-3a.pdf),
[UEFI x64 execution environment](https://uefi.org/specs/UEFI/2.10/02_Overview.html),
and [UEFI allocation/ExitBootServices contracts](https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html).
Firmware and build tools are external test dependencies, not redistributed code.
