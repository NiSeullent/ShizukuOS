# ABI research and implementation provenance

The implementation is original project code under GPL-2.0-only. Reference material
was read for factual binary layouts, service numbers, and calling conventions;
no DDK implementation, macro package, sample implementation, third-party driver
body, proprietary object, or third-party LE linker was incorporated. In particular,
the driver does not link MinGW libraries: Clang/NASM compile freestanding code and
GNU ld produces the intermediate ELF. Only the separate Win32 probe uses MinGW
headers and its KERNEL32 import library; it has no C runtime dependency.

References were accessed on 2026-09-27. Historical Microsoft material is linked at
public archives, not represented as a currently hosted Microsoft SDK download.
The maintained header references below are interface cross-checks, not proof that
Microsoft has certified this adapter.

| Reference | Facts used and limits |
| --- | --- |
| [Microsoft Windows 3.0 DDK Virtual Device Adaptation Guide, chapter 19, archived by PCjs](https://www.pcjs.org/documents/books/mspl13/win/w3ddkvxd/) | System page services use USE32 cdecl, caller stack cleanup and EAX/EDX results. `_PageCheckLinRange` returns an adjusted count, so success requires the full requested range. `_CopyPageTable` takes page/count/output/zero flags and returns copied PTEs; zero indicates an absent page-directory region. `_LinPageLock`/`_LinPageUnLock` use page numbers and counts. This older guide does not specify the Windows 95 PAGEMAPGLOBAL return-address extension. |
| [Microsoft MSDN, Manfred Schluttenhofer, “Enhancing WDEB386 with External Debugger Commands”, 1995-10-09](https://techshelps.github.io/MSDN/TECHART/html/msdn_dynvxd.htm) | Dynamic init/exit EAX/CF behavior; W32_DEVICEIOCONTROL descriptor in ESI; DIOC code at offset 12; open returns zero, close returns VXD_SUCCESS with carry clear, unsupported operation returns 50. The original adapter follows that close result even though some other published samples return zero. |
| [Microsoft MSDN, Ruediger R. Asche, “What's New in Windows 95 for VxD Writers?”, April 1994](https://techshelps.github.io/MSDN/TECHART/html/msdn_chicvxd.htm) | Dynamic VxD model and the DDB/LE entry convention, with C permitted in the driver. This is a Windows 95 design article, not a Windows 98 loader certification. |
| [Microsoft Systems Journal, Walter Oney, “Extend Your Application with Dynamically Loaded VxDs Under Windows 95”, May 1995, article starting PDF page 37](https://jacobfilipp.com/MSJ/1995/1995-05.pdf) | Win32 DIOC descriptor layout and dynamic opening. PDF pages 48 and 54 describe/use PAGEMAPGLOBAL, whose returned address is a global alias; cleanup passes that alias shifted by 12 to `_LinPageUnLock`. The article expressly identifies the alias return value as undocumented in the then-current DDK. This is published working-interface evidence, not a stronger contractual guarantee. No sample implementation was copied. |
| [JHRobotics/vmdisp9x maintained VMM interface header](https://github.com/JHRobotics/vmdisp9x/blob/main/vmm.h) | Independent numeric cross-check of DDB fields/sentinels, control messages, DIOC codes, VMM service ordinals, and PAGEMAPGLOBAL `0x40000000`. The header was consulted only; it is not included, downloaded, or compiled by this project. It is not Microsoft-authored certification. |
| [Open Watcom maintained `exeflat.h` format declarations](https://github.com/open-watcom/open-watcom-v2/blob/master/bld/watcom/h/exeflat.h) | LE field offsets, Windows386 target, dynamic-library flags, object/page-map/entry/fixup encoding, and VxD DDK header fields. The packager/parser are independently written Python. No Watcom headers, linker code, or libraries are incorporated. |
| [Intel IA-32 Software Developer's Manuals, volume 3 paging](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html) | Legacy 32-bit 4 KiB PTE present/write/user bits and physical-frame mask. This does not by itself document Windows VMM scheduling or page-directory policy. |

The native service thunks use interrupt `0x20` followed by the VMM identifier in
the high word and the zero-based service ordinal in the low word. The factual
bindings, statically checked in the emitted code, are:

| Service | Ordinal | Encoded DWORD | Arguments |
| --- | --- | --- | --- |
| `_CopyPageTable` | `0x61` | `0x00010061` | page, count, DWORD output pointer, flags=0 |
| `_LinPageLock` | `0x63` | `0x00010063` | page, count, PAGEMAPGLOBAL |
| `_LinPageUnLock` | `0x64` | `0x00010064` | returned alias page, count, PAGEMAPGLOBAL |
| `_PageCheckLinRange` | `0x67` | `0x00010067` | page, count, flags=0 |
| `_MapPhysToLinear` | `0x6C` | `0x0001006C` | physical address, byte count, flags=0; returns a system linear alias (WIN64 bridge channel window) |

These are C services: the original assembly wrapper re-pushes arguments so its own
near return address cannot be mistaken for an argument, then performs caller stack
cleanup. The test suite verifies the five encoded calls. It does not execute them
against Windows VMM.

The WIN64 subsystem bridge additionally uses two CPU instructions whose contracts come
from the [Intel SDM](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html):
`CPUID` (leaf 1 ECX bit 31 "hypervisor present", vendor leaf `0x40000000`) and
`VMCALL`, which raises #UD outside a VMX guest and is therefore only executed after the
ShizukuDOS Supervisor signature (`SSHZ`/`uVMM`/`v-10`, `shizukudos/supervisor/src/domain.c`)
was read. The hypercall register convention is the project's own (`shizukudos/abi/shz_abi.h`). The DDB uses the Windows 4.10 SDK value, unassigned device ID,
an eight-byte `NTWRAP9X` name, and the Windows 4.x 80-byte layout.

`build/manifest.json` records compiler versions and exact build-source/artifact
SHA-256 values. `build/host-tests.json` adds hashes for all local source, docs, tests,
the manifest and intermediate/final artifacts, plus the test log. Those receipts
provide local provenance and change detection; they are not upstream signatures
or evidence of a guest pass. An actual guest receipt must be recorded separately
with the tested driver/probe hashes, OS identity, log, and test conditions.
