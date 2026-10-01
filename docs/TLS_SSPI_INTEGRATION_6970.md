# TLS/SSPI integration and i486 validation — 2026-10-01

The committed Mbed TLS 3.6.7 transport and explicit SSPI foundation are integrated
in this worktree. Fresh host protocol, stream, descriptor/lifetime, sanitizer and
regression checks pass. Corrected native TLS and SSPI artifacts also pass the
original Win98 import/PE gates and complete declared executable-byte i486/x87
instruction inspection. No Windows executable or DLL was run by this work.
Native TLS, native ROOT-store behavior, OS-provider registration, WinSock,
Schannel/WinHTTP/WinINet and browser/application acceptance remain unverified.

The existing independently authored Mbed TLS 4.2.0 foundation remains separate
and unchanged. Its PSA instance and callbacks are not merged or cast into this
3.6.7 adapter.

## Imported source and owned changes

Root cherry-picked only the five committed peer changes from
`/root/Win98-Modern-tls13-7707`, then confirmed they were stable before validation:

| Peer commit | Integrated commit |
| --- | --- |
| `2c5e2a6` | `b7d5292` |
| `1041d05` | `a6e263b` |
| `3720778` | `23e31ac` |
| `ef55f5d` | `df9756c` |
| `d7070b8` | `745506e` |

No peer dirty/untracked observer, guest-probe, controller or verifier source was
copied. No peer originals, global OS provider, trust store or default settings
were edited. The native v11 owner retained its VM lane; this task started no VM.

The corrections are confined to `ntwin32/secure_transport`:

- `build.py` freezes the new native formatter and opcode gate, records original
  archive/source/license/compiler/library bindings, emits compile databases and
  linker maps, and gates the actual linked artifacts. It accepts an earlier
  **own** original upstream tree only after comparing every declared archive
  member with the pinned archive; this avoids repeated source extraction.
- `user_config.h` disables native ASM/SSE2/AESNI/AESCE/PadLock and selects the
  new formatting hooks through the documented Mbed TLS configuration interface.
  Upstream cryptographic source bytes remain unchanged.
- `probe.c` uses the original MSVCRT `I64` spelling for its native epoch output.
  The Linux probe retains its C99 spelling.
- `sspi_native_host_test.py` consumes an explicit `--engine-build`, validates
  retained object/source hashes, links that exact native candidate, and applies
  the same opcode gate. Its forbidden-directory check covers both RVA and size.
- New `i486_format.c/.h` provide bounded C99 count/truncation behavior around
  the original OEM `_vsnprintf`, avoiding precompiled MinGW formatting code.
  New `i486_format_host_test.py`, `i486_gate.py` and `i486_gate_test.py` retain
  independent oracle/failure and actual PE decode regressions.

The nine edited/new source hashes are frozen in
`build/tls-sspi-integration-6970/integration-source-hashes-v1.json`, SHA-256
`ae294162f2af299491dbc7f7436ac569079a714c504367196da9199de06426fc`.
Root owns the corresponding `THIRD_PARTY.md` index update; this task did not
modify that file.

## Why compiler flags alone were insufficient

The committed native recipe already selected `-march=i486`. Its old import/PE
gates passed on the fresh `native-before-v1` build, but actual linked code still
contained CMOV instructions in MinGW's formatting routines. For example the
TLS probe has `cmovg` at address `4199290`, bytes `0f4fd8`, inside
`___mingw_vsnprintf`; other actual failures occur in `___pformat_*` symbols.
The peer's read-only `docs/TLS13_I486_HANDOFF.md` independently identified the
same class of limitation in its separately owned latest-client build.

All declared executable sections are independently bound by address, exact raw
bytes, section hash and complete decode coverage. The gate retains the containing
symbol for rejected instructions and compressed full disassembly. It uses an
explicit legacy integer/x87 instruction list, rejects SIMD registers, newer
instructions and P6 multi-byte NOP encodings, and rejects incomplete/mismatched
decoding. Its actual two-section PE regression proves that a bad instruction in
the second executable section is detected. Imported OS DLL code and execution
on a physical CPU are outside this static gate.

Failures were retained rather than rewritten:

- `native-before-v1` plus `isa-before-*`: header/import checks passed, while
  linked CMOV and other rejected forms prevented i486 acceptance. Initial
  rejection totals also contained conservative unrecognized legacy aliases;
  they are not presented as a pure count of unsupported CPU instructions.
- `native-i486-v2`: a real link failure exposed formatter archive ordering.
  The formatter is now linked as an explicit object where required.
- `native-i486-v3`: the first strict scanner rejected valid legacy `rep stos`
  aliases. Those aliases were corrected and independently regression-tested;
  this build's older failure record remains intact.
- `native-i486-v4`: after removing MinGW formatting/acceleration instructions,
  each TLS artifact still contained six actual compiler-generated `UD2` traps.
  One is at `0x62d06bca`, bytes `0f0b`, in
  `_import_public_into_psa.constprop.0`; the others are in named PSA/SSL/X509
  functions. GCC erroneous-path isolation was disabled for native compilation,
  retaining original source and failure behavior instead of allowing UD2.
- `native-i486-v5`: all three native artifacts pass the corrected complete
  opcode gate. The independent SSPI link also passes that gate.

The native compile flags include:

```text
-Os -march=i486 -mtune=i486 -mno-sse -mno-sse2 -mno-mmx -mno-avx
-fno-isolate-erroneous-paths-dereference -fno-isolate-erroneous-paths-attribute
-D__USE_MINGW_ANSI_STDIO=0
```

The formatter supports bounded byte-string/character and integer forms,
normalizes wide integer length spellings to the native CRT, and measures the
full result in a private growing buffer before committing caller output.
Format/width/precision are bounded to 4,096; strings/output to 1 MiB. Floats,
wide text, `%n`, positional arguments and `hh` fail explicitly. This is a
bounded adapter, not a full replacement CRT. Host tests model the OEM's negative
truncation and compare against an independent libc oracle; they do not prove
execution or every formatting behavior of the Windows 98 runtime.

## Fresh results

| Check | Result and evidence scope |
| --- | --- |
| Transport host probe | PASS, 11 real handshake/payload/certificate/RNG/tamper/closure groups over bounded memory queues; fresh private certificates |
| Real SSPI stream | PASS, 14 groups; 38,187 normal checks and 38,189 ASan/UBSan checks |
| SSPI descriptor/lifetime/status model | PASS, 14 groups; 41,978 normal and 44,034 sanitizer checks; Win32 and stream endpoints are mocked |
| Formatter oracle/legacy model | PASS, 5,394 checks normally and under ASan/UBSan; caller-output immutability and bounded refusal included |
| Native CRT startup ABI model | PASS, 12 cases, including old void-return/output-pointer behavior and full exit propagation |
| Owned-child observer model | PASS, 45 cases, including timeout/reap/freshness/fault/cleanup failures |
| Python/evidence/opcode regressions | PASS, 45 tests; five opcode test methods include newer instructions, byte/address gaps and real two-section PE fixtures |
| Actual compiler macro dumps | PASS, 126 translation units, including 120 configured Mbed TLS units; native acceleration/ASM absent and formatter hooks exact |
| Original upstream preservation | PASS, all 2,039 regular archive members compared byte-for-byte after compilation; frozen authored source hashes still match |

The stream sanitizer instruments the authored transport/stream/fixture;
the reused original upstream static crypto/TLS libraries are not sanitizer
instrumented. Thread scheduling and randomized handshake sizes can vary check
counts; stable groups and zero failures gate acceptance.

The verifier regressions privately bind the exact historical peer Linux log
SHA-256 `b7e7c87196f314880798fa03e72fa48c0cd26a8cc6268925cff60b28cae392c0`.
It is a regression fixture, separate from the fresh own host handshake. The
initial missing-fixture failure is retained in `python-tests-v1.log`; the final
suite binds the private fixture and passes in `python-tests-v2.log`.
The first macro summary used the wrong upstream header-guard name; corrected
`native-compile-macros-v2` independently interprets the unchanged byte-bound
raw dumps using the actual authored configuration guard.

## Exact static native artifacts

| Artifact | Bytes | SHA-256 | Decoded instructions / executable bytes |
| --- | ---: | --- | ---: |
| `native-i486-v5/cmake/TLS13PROB.exe` | 922,660 | `695d6f872eec1f74673b21e47092ed3bbce9963cfa1e2a5475ac2a5ae286e279` | 116,126 / 402,968 |
| `native-i486-v5/cmake/TIMEPROB.exe` | 19,083 | `abf54364249989339401245529c808b27495c138d6f48ce2262625b52c24fb35` | 659 / 2,468 |
| `native-i486-v5/cmake/M98TLS.dll` | 909,660 | `28b639ac74c9ae5947809efdd427085f0733363385583741f40bc38497bd86b6` | 114,272 / 395,692 |
| `sspi-native-i486-v1/M98SSPI.dll` | 1,593,929 | `c1ce8093394af3700b149cec59812f05b95f62d9a90b852fb585514ef765f606` | 117,908 / 407,280 |

Paths in this table are relative to
`/root/Win98-Modern-theme-6970/build/tls-sspi-integration-6970`.
All four have zero rejected instructions and zero executable-byte coverage
errors. SSPI has exactly 15 expected exports, 31 imports present in the frozen
original Win98 inventory, 6,383 HIGHLOW relocations, subsystem/OS 4.10, timestamp
zero, and zero RVA/size for static TLS, load-config, delay-import and CLR
directories. This remains a static loading contract, not a guest ABI pass.

Primary accepted receipts under the same build root:

| Receipt | SHA-256 |
| --- | --- |
| `native-i486-v5/build-result.json` | `7e255da36815670424bc1db18bb004b53cb40e36e272c345bd2a7b54b96c018f` |
| `sspi-native-i486-v1/receipt.json` | `bb4276a76c944cec889ba64905bb2ac9ab91c82a2bcb838c4e4243ccb2026c3c` |
| `host-before-v1/build-result.json` | `8fb90aae3099b1c7ccf7208fff7f389c194f12143046daf72640531e4a108db2` |
| `stream-host-v1/receipt.json` | `39d2f013e11390e50939239c3c0ded839cb53015326ee1a9d47858742e83a287` |
| `stream-sanitize-v1/receipt.json` | `858c3809b9a7ec5fcfdc47d7293bb0336c22104e293fcb5173be0ba0766ca31b` |
| `native-compile-macros-v2/result.json` | `3260ff3e6431a9764182de646c5e7dbbf5efe54a56f60176dcc8b2c408992e91` |
| `native-input-preservation-v1.json` | `1fcbdcb7c1a571c9a531e741dbae0677d8717aec67114d2d632d7ef81e065cd7` |
| `native-toolchain-lineage-v1.json` | `cc57d1cc4e7ed7d793eaac865101b86923c326a3847f295309bbb566f3cadd17` |

The pinned local archive is
`/root/Win98-Modern-tls13-7707/build/secure-transport/upstream/mbedtls-3.6.7.tar.bz2`,
5,473,689 bytes, SHA-256
`a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6`.
It was read without download or modification. Receipts retain upstream
LICENSE/NOTICE hashes, selected GPL-compatible licensing, installed compiler
runtime notices, GCC/objdump hashes and versions, selected cc1/collect2/as/ld
hashes, import/runtime archives, exact compile commands, linker maps and all
compiled object/archive hashes.

## Reproduce with new output directories

Run from this worktree and choose absent output paths. The exact accepted
native build used:

```sh
python3 -B ntwin32/secure_transport/build.py \
  --archive /root/Win98-Modern-tls13-7707/build/secure-transport/upstream/mbedtls-3.6.7.tar.bz2 \
  --upstream-tree build/tls-sspi-integration-6970/native-i486-v3/upstream/mbedtls-3.6.7 \
  --output build/tls-sspi-integration-6970/native-i486-v5 \
  --target win98-x86 --jobs 2
python3 -B ntwin32/secure_transport/sspi_native_host_test.py \
  --engine-build build/tls-sspi-integration-6970/native-i486-v5 \
  --output build/tls-sspi-integration-6970/sspi-native-i486-v1 --native
```

For a fresh host engine, use `build.py --target host --run-probe` with the same
archive and a new output, with at most two jobs. Descriptor models use
`sspi_native_host_test.py --engine-build <successful-host-build> --output <new>`;
add `--sanitize` for Clang ASan/UBSan. Formatter models use
`i486_format_host_test.py --out <new>` with optional `--sanitize`. Full original
stream compiler/run arguments and frozen fixture/library hashes are in the
two stream receipts; these are the portable real-TLS checks, separate from
the mocked native descriptor model.

No reserve guard was lowered. Host free space remained above 20 GiB; the last
observation was 36,215,803,904 bytes. The native VM dirty-write budget remains
unchanged because no VM was started. Each individual retained build/diagnostic
directory stays below the 16-MiB log/capture bound; accumulated generated logs,
macro captures and compressed disassembly across all preserved attempts total
18,083,511 bytes. Old source/build/failure evidence was preserved.

The next acceptance step belongs to the native owner: independently call the
actual DLLs in an isolated installed Windows 98 guest with bound inputs, fresh
nonce, real socket/certificate negative cases, readback and external normal exit.
These static artifacts and Linux tests cannot substitute for that evidence or
for OS-wide/application TLS integration.
