# Conventional-memory diagnostic source candidate

The original `CBMEM.COM` diagnostic builds with strict NASM warnings enabled. Its actual 4,896-byte binary passes 20 byte/layout checks; three deliberately corrupted retained-size, stack and allocator-query bytes are rejected. These are build/static checks. This source stage has not executed DOS, measured guest free memory or verified Windows 98.

The source checks that INT 21/AH=62 returns this COM's CS, reads only the preceding own MCB and validates its M/Z type, PSP owner and minimum size. It sets its own retained stack before any DOS call. AH=4A then shrinks only that allocation to exactly 322 paragraphs (5,152 bytes including the PSP, code, data, 2,048-byte report buffer and 1,024-byte stack). It neither grows the block nor frees its executing allocation. The real AH=48/BX=FFFF query must fail with CF set and AX=8; its BX is recorded unchanged. An unexpected successful allocation is failed and only the newly returned block is submitted to AH=49 for cleanup, whose raw status is recorded.

It records real INT 12 total contiguous base memory, current PSP and MCB size/owner/type before and after shrinking, PSP+2 allocation-end values, returned AH=4A and AH=48 registers/FLAGS, allocator strategy, UMB linkage and AX=3306 registers. DH bit 4 is recorded as raw DX&1000h. Pinned FreeDOS source sets this bit only after real kernel HMA relocation; the probe does not infer it from CONFIG.SYS. Before interpreting BX/DH as DOS 5+ version/HMA fields, verify returned BL>=5 and BH<100 and the known kernel/interrupt ownership. PSP+2 is recorded without asserting that DOS updates it after a resize.

`CBMEM.TXT` values are **16-bit hexadecimal**. Full success is `PHASE=0007`, `CHECKS=000B`, `FAILURES=0000`, and actual DOS ERRORLEVEL 0. FFFF is a not-measured sentinel in unexecuted fields and can also be a raw returned value; consult the phase and FLAGS. `AH48_LARGEST_PARAS` is the allocator's actual BX and `LARGEST_KB_FLOOR` is its BX>>6. `INT12_TOTAL_KB` is total memory, never free memory. The probe performs no minimum-free-memory success test and never fabricates a 580 KiB result.

Interpret largest-free as conventional memory only when the actual allocation strategy query succeeded with standard low-memory strategy 0, 1 or 2, and the UMB-link query succeeded with AL=0. The high byte of AX=5802 may remain 58h; interpret its AL, not the whole AX. Other allocator policies are recorded without modification and may include upper memory. The measurement occurs before report creation, with the retained probe and its environment/parent shell still present. It is not the exact free memory a later, separate Windows process will see.

Measurements are kept in the bounded report buffer before any file is opened. Creating, writing and closing `CBMEM.TXT` are real DOS operations. The complete footer and DOS process outcome must both be checked: ERRORLEVEL 0 means contracts plus report I/O succeeded, 1 indicates a contract/write/short-write/close failure, and 2 indicates report creation failure. Text alone cannot independently establish a process exit or successful cleanup following an error. The probe makes no explicit A20 state change, does not invoke Windows, changes no allocator policy and opens no registry files.

Primary contracts come from Ralf Brown's original author-hosted RBIL Release 61 archives, acquired and pinned in `inputs/primary-source-receipt.json`. `primary-authorities.json` identifies consumed corpus preimages and pinned FreeDOS source. `prebuild-receipt.json` freezes source/verifier/NASM hashes before assembly; `build-receipt.json` binds the resulting binary/listing and `layout-result.json` records actual protected bounds and mutation rejection. Original source is GPL-2.0-only. Binaries, listings and guest outputs are private build artifacts.

Fresh source requires Python 3 and NASM; no cached assembler or absolute workspace path is needed:

```sh
nasm -f bin -w+all -Werror -l CBMEM.lst -o CBMEM.COM cbmem.asm
python3 -B verify_cbmem_layout.py CBMEM.COM
```

This producer created only its own ignored source/build stage, using less than 4 MiB, with a 17 GiB free-disk floor and 4 GiB available-host-memory floor plus a 256 MiB build budget. It ran no VM, modified no guest image, installed no global tool and performed no Git operation. A separately owned, bounded guest run and LOW/HIGH comparison are required before any native-memory claim. Windows startup/VMM/desktop, MS-DOS replacement and modern applications remain unverified.
