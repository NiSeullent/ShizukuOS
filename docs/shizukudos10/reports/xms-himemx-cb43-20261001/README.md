# Genuine-source XMS candidate, 2026-10-01

HimemX 3.40 and its alternate allocation variant were built from complete pinned official source using a newly source-built JWasm. Both assemblies exited 0 with zero warnings/errors. **64 static checks** validate their actual MZ/DOS driver headers, strategy/interrupt vectors and twenty XMS 2/3 service table pointers. Those checks do not execute any service.

The reviewed original DOS probe passed **16 actual DOS XMS checks**, with zero failures and zero reported I/O errors, in the separate root-owned v7 guest. It measures real allocation, lock/unlock, handle information, a 256-byte pattern roundtrip through extended memory, release and invalid-handle rejection. [The exact guest-written report](native-xms-v7-results.txt) is 1,272 bytes, SHA-256 `bdf634071d5206e608456e850f69f94a8500d1989a8602ec08e6fdc5f90b7516`. The [limited runtime receipt](native-xms-v7-result.json) binds the manager, reviewed probe, source receipts and root run metadata. Actual Windows 98 startup/VMM/desktop and replacement of MS-DOS remain unverified; XMS success alone cannot establish those outcomes.

The actual v7 guest used the **earlier CB43-only** kernel SHA-256 `62194db22e7d157865f9767c78ca3ecf7d7977d720a99a1afe8c8c02b1aebb3f`, with the primary DOSMGR patch excluded. Its sixteen XMS results must not be transferred to the separately compiled combined-DOSMGR kernel. The owned private volume contained licensed Microsoft/Windows inputs; none are exported here. The host stopped its owned process after 120.2 seconds; no clean guest shutdown or successful Windows boot is inferred. The inherited BOOTLOG was stale and is excluded from this evidence.

| Item | Exact source/build identity |
|---|---|
| HimemX official source | Commit `bbaf6b8951cdac785f1f4e9b67c25439c5bf8e75`; all 5 source files retained unchanged in [upstream/HimemX](upstream/HimemX/Readme.txt) |
| JWasm official source/tool | Commit `7f6f32e78b79565d40bcce496756aadd1ff66900`; all 268 source preimages frozen before compilation; source-built assembler 416,528 bytes, SHA-256 `7becda9a44f981790e505f44690e0417f59deb4f3d6c983c096fdee613224747` |
| Default HimemX candidate | 6,100 bytes, SHA-256 `5e0ed027a150ac1c198e994ca248245c07c1f44796bc0791448afbcf29789211` |
| Alternate HimemX2 candidate | 6,100 bytes, SHA-256 `bc5c29a755a6093b32f59e5117b1ab65f32c67efad2c017f822e67f723b04ff5` |
| Reviewed DOS diagnostic | [cbxms.asm](cbxms.asm), SHA-256 `284177e9c2eb20212b901f9c8e18fabba6e14ef6bb78924f8a97e06e7a0a8cbd`; compiled COM 2,365 bytes, SHA-256 `8c900ac24fccbe10a2c5ea5211ad85d9ae45eaefb08c51b136d9b6ac5a5f227c` |

[Source/build receipt](source-build-receipt.json) records the two immutable archive URLs/hashes, every project source preimage, GCC/cc1/as/ld/make hashes, actual commands and the built assembler. All 273 project source inputs remained unchanged after the single-job build. [Static results](binary-static-result.json) record actual executable bytes and vectors; [probe receipt](native-probe-v2-build-receipt.json) describes its compile-only stage, preceding the separate native run. [Independent review](independent-probe-review.json) is read-only source review, not a runtime test. Public files contain source, text and metadata; manager/compiler/probe binaries, VM disks, Windows files and keys are excluded.

## Actual implementation and limits

The source hooks INT 2F/AX=4300 and 4310 and supplies the real far-call dispatcher and XMS allocation/move/lock/free implementations. Its default build uses the upstream allocation strategy; HimemX2 selects `?ALTSTRAT=1`. The current source requires 80386 or newer, implements real A20/memory handling, and contains real-mode/protected-mode movement paths. It is not an installation-response stub. Source comments and the author's allocation notes do not establish Windows 98 compatibility in this project.

The probe makes **16 successful-path checks**, uses only its own 64 KiB XMS block and 256-byte conventional buffers, and creates `CBXMS.TXT`. It reports checked AX/BX/DX values before logging and the caller ES after preserving the call's segments. It never synthesizes Windows startup or changes a Windows version. A20 checks query actual state and require a zero BL error; they do not explicitly test A20 switching. If a check fails, cleanup is attempted only for the probe's owned block and its raw return status is logged; successful release after a failure is not assumed.

After both successful moves, the probe compares all 256 returned bytes with the original pattern. An AX=1 reply without copying cannot pass the roundtrip check. The report ends with decimal `CHECKS`, `FAILURES` and `IO_ERROR`. DOS ERRORLEVEL 0 means executed checks plus report writes/close succeeded; 1 indicates a service or report I/O failure; 2 indicates report creation failure. A native harness must verify both the complete report and the process outcome.

The first compile-only diagnostic source accepted A20 AX=0 without checking BL=80/81 errors. It was preserved privately and was not executed by this producer. The new immutable v2 source sets input BL=0 and requires output BL=0 for both A20 queries and the free-memory query. These follow original RBIL `INTERRUP.L`, tables 02757/02758; [the prior primary-authority receipt](../dos-internals-cb43-20261001/primary-authorities.json) preserves the author's corpus preimage. There is no native result to transfer from v1.

## Authorship and licensing

The [official HimemX README at the pinned commit](https://github.com/Baron-von-Riedesel/HimemX/blob/bbaf6b8951cdac785f1f4e9b67c25439c5bf8e75/Readme.txt) describes its FDHimem ancestry and the GPL and/or Artistic license applying to Till Gerken/Tom Ehlert's work; HimemX changes are public domain. Michael Devore and other contributors' original source notices are retained. The complete corresponding manager source, build file and history are supplied here unchanged. This checkpoint does not relabel the upstream license or assert a GPL version the upstream README does not state.

JWasm is a separate build tool; its [original Sybase Open Watcom Public License 1.0 text](upstream/JWasm-License.html) and [pinned source acquisition](https://github.com/Baron-von-Riedesel/JWasm/tree/7f6f32e78b79565d40bcce496756aadd1ff66900) are identified separately. The original probe is GPL-2.0-only. A later official ISO carrying the manager must retain its authorship/license and this corresponding source/build recipe.

## Fresh-source reproduction

Use actual Git or an HTTPS source-archive downloader, GCC, GNU make, Python 3 and NASM. Acquire the exact HimemX and JWasm commits above from the author's public repositories, checking the archive/file hashes in the receipt. No cached assembler or private absolute directory is needed. Preserve at least 17 GiB free disk and 4 GiB host available memory beyond a small 256 MiB single-job build budget.

In the pristine JWasm source copy:

```sh
SOURCE_DATE_EPOCH=1785283200 make -f GccUnix.mak -j1
```

Use the resulting `build/GccUnixR/jwasm` by its explicit path. Do not run `make install`. In a separate HimemX source directory, write outputs to your own unused build directory:

```sh
/path/to/JWasm/build/GccUnixR/jwasm -mz -nologo -Sg \
  -Fl/path/to/output/HIMEMX.lst -Fo/path/to/output/HIMEMX.EXE HimemX.asm
/path/to/JWasm/build/GccUnixR/jwasm -mz -nologo -Sg '-D?ALTSTRAT=1' \
  -Fl/path/to/output/HIMEMX2.lst -Fo/path/to/output/HIMEMX2.EXE HimemX.asm
```

These are the upstream Makefile's release assembly options, expressed as Linux arguments. Record the actual GCC/JWasm binary hashes on the new machine; differences in toolchains can change tool outputs. From this checkpoint's directory, compile the probe separately:

```sh
nasm -f bin -w+all -Werror -l /path/to/output/CBXMS.lst \
  -o /path/to/output/CBXMS.COM cbxms.asm
```

Compile-only outputs are private build artifacts. Loading a manager with `DEVICE=HIMEMX.EXE [options]` and running the diagnostic changes a guest and belongs to a separately reviewed, bounded run on an owned volume. This producer did not launch a VM, construct/modify an image, copy files into a guest, install tools globally or operate a Git remote. Complete Windows 98 validation remains the root session's separate gate.

Only the actual workspace prefix was replaced with `${STAGE}` in public build metadata. Raw private record/log hashes preserve provenance; [checkpoint-manifest.json](checkpoint-manifest.json) hashes every public source/text file. Existing DOS and native-source checkpoints remain unchanged.
