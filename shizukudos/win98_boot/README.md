# ShizukuDOS 10 DOS → Windows 98 VMM contract work

ShizukuOS 1.0.0 remains a development candidate. ShizukuDOS replaces MS-DOS
for the actual Microsoft Windows 98 system; Kernel32, Kernel64 and its other
components serve that Windows 98 goal. A DOS prompt, standalone K64 desktop,
website preview or these host tests does not complete the Windows 98 boot path.

This first source increment corrects three dishonest/mistaken DOSMGR replies
and supplies an opt-in, source-built recorder for the next original-Windows
control comparison. No Microsoft source, OEM file, original Windows binary,
private disk image or captured memory is included or modified.

## Exact DOSMGR correction

The patch `../dos16/patches/0003-dosmgr-honest-contract.patch` applies to public
FreeDOS kernel ke2046, commit `5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3`.
`kernel/inthndlr.c` has SHA-256
`0793e3bb94c558b6fdeb335f9e15577486b4b6ae53e987c89c095909fb363727`.
The existing sorted DOS16 patch list can apply it without changing the builder.
**It does not enable `WIN31SUPPORT`**, which remains an experimental profile.

For INT 2F AX=1607, BX=0015:

| CX function | Result after this patch |
| --- | --- |
| 0001, patch requests in DX | BX=0, because no optional patch bit has completed implementation/acceptance; AX=B97C and DX=A2AB acknowledge the API, not every requested patch. |
| 0003, structure request in DX | Only DX=0001 returns the production `sizeof(struct cds)` with AX=B97C, DX=A2AB. Other requests set CX=0 and preserve the other case-register fields. |
| 0004, instanced structures | CX=DX=0 denotes unsupported, retaining the other case-register fields. No success signature claims verified independent instancing. |

The previous CX=3 case inspected CX instead of DX, so even request zero was
mistakenly reported as a supported CDS query. The previous CX=1 copied the
entire requested mask into BX; the previous CX=4 reported an unverified success.
The outer interrupt dispatcher’s existing carry handling is unchanged.

Protocol provenance: [Ralf Brown's Interrupt List, DOSMGR API](https://delorie.com/djgpp/doc/rbinter/id/23/45.html).
The modified [upstream DOS-C/FreeDOS handler](https://github.com/FDOS/kernel/blob/5ffb5502d39a10a30f5b8a9e8beeba0bf30245d3/kernel/inthndlr.c)
retains its authorship and GPL-2.0-or-later license; the patch does not replace
that attribution with ShizukuOS authorship.

## Experimental startup chain correction

The next public patch, `../dos16/patches/0004-win-startup-chain.patch`, preserves
an earlier caller's nonzero CX veto and leaves standard-mode notifications
unchanged. Enhanced-mode notifications chain the incoming ES:BX startup head
before publishing this kernel's head; receiving its own head again is
idempotent. The real assembler structure now has the optional DWORD at offset
18, so instance records start at 22 bytes as the existing C header requires.

The [Microsoft DDK startup contract](https://dos-help.soulsphere.org/ddag31qh.hlp/Interrupt_2Fh_Function_1605h.html)
requires preserved veto state and enhanced-mode startup data. The versioned
layout is also documented by [Ralf Brown's Interrupt List](https://fd.lod.bz/rbil/interrup/windows/2f1605.html).

`test_startup_contract.py` executes the actual patched C cases and assembles
the actual startup data fragment. GCC and Clang with address/undefined-behavior
sanitizers each pass 294,919 checks: every nonzero CX veto, every odd DX
standard-mode notification, chained enhanced startup, repeated head, exit and
subsequent startup. NASM independently checks the real symbol offset.

Two complete Open Watcom kernel builds passed. The experimental
`WIN31SUPPORT` build linked a 72,687-byte kernel. The normal disabled build
remained byte-identical to the previous 72,239-byte production kernel.
This patch does not enable `WIN31SUPPORT`, advertise DOSMGR patch support, or
establish Windows 98 boot or replacement of MS-DOS. The startup structure's
version and whole-data-segment instancing still need genuine VMM measurement.

## Opt-in control recorder

`trace/dosvmm_trace.asm` is an original 386 real-mode COM TSR source. It observes
1603, 1605, 1606, 1607/BX=0015 and WinOLDAP 4601/4602 before and after the next
handler. It never synthesizes startup broadcasts or issues test DOSMGR requests.
The resident hook calls no DOS/BIOS services, changes no DOSMGR reply and writes
only its private counter/scratch bytes and bounded E9 output. Its chain frame
receives the original caller FLAGS. Host controls preserve returned 32-bit
GPRs, DS/ES, stack and FLAGS with TF=0. Debug-trap/IRQ timing and actual Windows
V86 behavior remain unverified. Unselected calls and calls beyond 4,096 pass
directly through.

Build from the repository root into an explicitly chosen local build directory:

```sh
mkdir -p build/shizukudos/win98_boot
nasm -f bin -w+all -Werror -o build/shizukudos/win98_boot/DOSVMM.COM shizukudos/win98_boot/trace/dosvmm_trace.asm
```

The operator explicitly runs `DOSVMM /I` once in a separately authorized,
disposable instrumented control boot before starting Windows. It is **not**
added to the normal DOS10 user AUTOEXEC/installer/ISO profile by this increment.
There is no unload command; end the disposable boot to remove it. The retained
PSP/environment/TSR changes the control's memory layout, so compare equally
instrumented original-MS-DOS and ShizukuDOS candidates as well as uninstrumented
controls. Check that the VM's E9 capture works and remains compatible through
actual Windows V86 transitions; real DOS/Windows execution is still unverified.
Existing original media and private VM/domain definitions remain unchanged.

The line format is `SHZVMM1 <E|R> <id> <AX BX CX DX DS SI ES DI BP FLAGS>`:
uppercase four-digit hexadecimal words and CRLF. IDs follow the nested call
stack; maximum complete trace output is 4,096 pairs, below 1 MiB. E is the call's
input and R is the actual next handler's result. Keep raw registers/addresses,
private captures and original Windows media outside GitHub and the public site.

After capture has stopped and the file is frozen:

```sh
python3 -B shizukudos/win98_boot/trace/parse_trace.py /path/to/private/e9.log --profile windows98-original-control
```

For the comparison candidate choose `--profile shizukudos-win98-candidate`.
The parser rejects oversized/symlink/FIFO/directory/changing inputs, malformed
records, missing/duplicate/reordered IDs and incomplete returns. Output contains
only a capture digest, length, call counts and the selected profile, without
private paths or raw register rows. `COMPLETE_CALL_MEASUREMENT` means structural
validation, not an attestation of guest execution, Windows 98 boot success or
MS-DOS replacement. Those acceptance flags stay false.

## Verification and remaining real contract work

Host tests compile the **actual patched production case statements**, then
check all 65,536 requested masks and all 65,536 structure requests with two
compiler layouts. NASM builds the real recorder. Optional Unicorn 2.1.4 controls
execute its exact production bytes in a bounded host-only 16-bit CPU with an
original tiny next-handler IRET fixture: original/changed IF, CF, DF and other
FLAGS with TF=0; returned 32-bit registers, DS/ES and stack; selected, no-change,
unselected and exhausted-budget paths; actual E9 record contents. This executes
no BIOS, DOS, Windows binary, OS, disk image or VM. See [Unicorn's API tutorial](https://www.unicorn-engine.org/docs/tutorial.html).

```sh
SHZ_FREEDOS_SOURCE=/path/to/pinned/freedos-kernel python3 -B -W error::ResourceWarning -m unittest discover -s shizukudos/win98_boot/tests -p 'test_*.py' -v
```

The CPU suite is explicitly optional without `unicorn==2.1.4`; a skipped CPU
suite is not evidence of its passing. Install that test dependency only inside
an operator-chosen local environment, never into client-global configuration.
This staging run used a hash-verified wheel unpacked only below `review/vendor`.
Its real run had **17 tests, zero skips, zero warnings**. The entire patched
`inthndlr.c` also compiled as a 16-bit Open Watcom object with WIN31SUPPORT,
I386 and WITHFAT32 enabled. That is a C-object build, not a linked booted kernel.

Next implementation must bind actual control/candidate startup measurements
to unchanged original media and pinned source, then implement and test:

1. Measure the corrected 1605/1606 veto, chain, reentry and physical C/ASM
   layout in an actual Windows control/candidate boot, then verify versioned
   instance-table bounds. The current startup flag and whole-data-segment
   table are not VMM-instancing acceptance.
   Microsoft's historical [1605 notification contract](https://dos-help.soulsphere.org/ddag31qh.hlp/Interrupt_2Fh_Function_1605h.html)
   requires chained startup data and preserved failure state.
2. Verified critical-section, local VM identifier, input polling, stack-fault
   and drive-map notifications before any corresponding patch-mask bit becomes
   supported. Returning BX=0 may make DOSMGR attempt fallback patching; the
   candidate is not safe to promote merely because this register contract passes.
3. Last-conventional-MCB semantics and the still-unimplemented WinOLDAP
   save/restore handlers, alongside PSP/MCB/InDOS/SDA/SFT/device-chain contracts.
4. Actual WIN.COM → VMM → Windows 98 GUI startup and native file persistence on
   ShizukuDOS through the separately maintained opt-in native Windows domain.
   This module does not edit that domain's source, original binaries or VM.
5. GOP/driver/acceleration and actual Chromium, Legcord, current open Office and
   Steam workflows inside that Windows 98 path. Components/host tests cannot
   substitute for those required application acceptance checks.

Publish sources/patches only on GitHub. Any final ISO remains exclusively at
m98.nyase.kr; this module supplies no redistributable Windows installation media.
