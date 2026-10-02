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

## Native QUERY callback contracts (Win98 DDK, pinned archive)

Original Microsoft interface topics were extracted and read from [OTHER.CHM](https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/help/OTHER.CHM), SHA-256
`25bf75cb60f1545147eb868fd2ab2b2452c3d4d559b5e2f440c07a9db187e127`.
The service declaration order is pinned by [VMM.INC](https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/VMM.INC), SHA-256
`d640c2994970fabe36c6d4f47ac94b719554d19dc036807c56fe9252ded6d1b2`,
and [VWIN32.INC](https://github.com/fapablazacl/win98-ddk-toolchain/blob/0c662d32378b9940ed90aee682f4eb5daf816e6a/98DDK/inc/win98/VWIN32.INC), SHA-256
`cc2bacfd25cdf5cdda3abe3396b1d0389a9a1c09f4226fbfdb7a0bd218049e2e`.
The project incorporates original wrappers and factual constants only.

| Binding | Encoded DWORD | Original contract/topic |
| --- | --- | --- |
| Get_Cur_VM_Handle / Get_Sys_VM_Handle | `10001` / `10003` | returns EBX VM handle |
| Get_Cur_Thread_Handle / Get_System_Time | `10108` / `1003f` | EDI thread / EAX milliseconds |
| Call_Restricted_Event / Cancel_Restricted_Event | `1015a` / `1015b` | `kernel_8th5`, `8tip`, `8tdk`; EAX boost, EBX System VM, ECX flags, EDX ref, ESI callback/handle, EDI timeout |
| Set_Global_Time_Out / Cancel_Time_Out | `1003c` / `1003e` | `92sz`; non-asynchronous VMM timer, EAX ms/EDX ref/ESI callback or returned handle |
| _VWIN32_OpenVxDHandle | `2a0025` | VWIN32.H inline declaration: cdecl handle, type1 event, caller cleanup |
| _VWIN32_SetWin32Event / _VWIN32_CloseVxDHandle | `2a000e` / `2a0014` | `4fn4` / `4fld`: EAX owned ring0 handle, EAX nonzero success; signal only in System VM |

The scheduled restricted event uses flags `0x4b`: WAIT_FOR_STI,
WAIT_NOT_CRIT, ALWAYS_SCHED, WAIT_NOT_NESTED_EXEC. It deliberately has no
PEF_TIME_OUT restriction bypass and no PEF_RING0_EVENT promise. It executes
original C in the selected System VM; it performs no DOS/nested execution,
blocking wait or priority adjustment. Its Win32 event handle is an owned ring0
reference. Signaling occurs after both admission and IRQ masking end. Timer
callbacks only enqueue the restricted event. Callback thunks marshal EBX/EDI/EDX,
clear DF and return with IF enabled as the original topic requires. The original
`8whh`/`8whi` page-lock topics support flags0 residency locks on the two relocated
code/data ranges; PAGEMAPGLOBAL remains for DIOC aliases. No DDK declaration or
host test establishes successful execution in the live Windows VMM.

Thread_Not_Executeable (`20`) and Destroy_Thread (`21`) specify only EDI's
thread handle (`9chj`/`9cdt`); no current-VM identity is inferred. VM_Not_Executeable
(`0b`) and Destroy_VM (`0c`) specify EBX's VM handle (pinned VMM.H comments).
Both notification families return carry clear and request real retained cleanup.
The source uses these separate authoritative identities rather than a guessed
process-notification register convention.
