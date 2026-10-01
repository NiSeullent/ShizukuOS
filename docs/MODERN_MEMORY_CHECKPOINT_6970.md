# Private modern-memory continuation — 6970

The Signal 8.28.0 trials probe `VirtualAlloc2`, `MapViewOfFile3` and
`UnmapViewOfFile2`. `ntwddm/win64/memory_bridge` now supplies original,
GPL-2.0-only implementations for a documented basic current-process subset.
Allocation, mapping and unmapping remain owned by real Kernel32 endpoints;
unsupported flags, extended parameters and process handles fail explicitly.
The README records exact supported protections, alignment and ownership.

The frozen candidate at
`ntwddm/win64/memory_bridge/build/20261001T085541Z-9876aa10/result.json`
passes 580 host assertions normally and under ASan/UBSan, 18 archive/build
tests and its actual AMD64 PE gate. Its nine imports resolve in the actual
stopped runtime archive. Another 591 named exports are exact one-hop forwards
to direct Kernel32 exports. These checks establish a static candidate, without
proving guest memory behavior or Signal functionality.

The DLL is 69,609 bytes with SHA-256
`d370ada2423503929a761f271fcf0728d9dadaecd52f906ee52b8167c347efff`.
The builder binds implementation/header/license hashes, generated export
definition and compiler inputs, reviewed owner sources and the original archive.
Earlier structural failures remain intact in separate build directories.

`tools/runtime_extension_overlay.py` freezes this candidate beside the private
Modern theme archive. Its 27 tests cover the actual PE/receipt agreement,
source and generated-input binding, forwarding graph, ownership, sealing and
failure cleanup. It preserves all existing members in order and appends only
`\SHZ\SYS64\KERNELBASE.DLL`; no peer or installed runtime is changed.
The prepared receipt is
`build/required-memory-runtime-6970-v1/extension-overlay.json`.
Its 143-member derived archive has SHA-256
`fa2973620864ad64dfb8c00856f821beab33a3f7abe65024d6439cb7840441d1`.

The actual `build/modern-required-apps-6970/signal-memory-themed-run-v1`
trial mounted 143 members and started the publisher executable as pid 60.
It timed out after 90.1 seconds with no verified UI, normal application exit or
messaging. All original/sealed runtime, firmware, publisher image, source and
receipt preservation checks passed. Independently inspected sealed bytes,
member contents, actual QEMU inputs and mount count agree with the preparation.
Nevertheless, Signal still reports KERNELBASE not found and probes the three
memory APIs unsuccessfully. A higher thread count does not prove that these
adapters executed or explain the timeout.

Read-only comparison also establishes that the executed kernel matches the
available allocated ELF sections and that its compiled KnownDLL branch searches
SYS64. This does not isolate a particular loader/filesystem defect. A separate
owned guest probe will compare file attributes, basename/absolute loads, actual
function addresses and real allocation/mapping ownership. Current memory,
Signal functionality, native Windows 98 integration and OS-wide compatibility
claims remained unverified at this first diagnostic checkpoint. The unchanged
20 GiB reserve, private 256 MiB write limit and 16 MiB output limit apply.

## Genuine direct-call acceptance and controlled app comparison

`build/mp64-run-v1/memory-diagnostic.json` now passes 69 real guest assertions
with a fresh nonce. Live SYS64 file size and a 64-byte MZ header match the
candidate, ANSI/Unicode basenames and absolute loads return the same module,
and direct adapters plus the real Kernel32 forwarder execute. Allocation,
reserve/commit, coherent read-only mappings, private COW, refusal/ownership
checks and cleanup pass. Actual normal child exit is zero and raw `proc_wait`
is zero. All original/sealed inputs and resource checks pass; peak private
writes plus own outputs are 216,265 bytes. The evidence gate has 29 tests.
This proves the exercised standalone AMD64 memory subset; it does not prove
full modern-memory semantics or native Windows 98 integration.

The executed kernel, archive, QEMU and all firmware are byte-identical to the
failing Signal attempt. Reviewed runtime and consumer sources match. Because
the probe used 1 GiB RAM and Signal used 4 GiB, a new controlled Signal trial
changed only `-m 4096` to `-m 1024`. Its exact machine-command and input
comparison is retained at
`build/signal-memory-ram-comparison-6970-v1/comparison.json`, SHA-256
`85cdffa97b2c877b1fd69fefb003c90a21cd606be9687f7ae725b5888e2b1718`.

The 1-GiB Signal run again fails the fibers API-set load, then KERNELBASE,
and times out at 90.1 seconds. No normal app exit or usable UI is verified.
All preservation/resource checks pass; peak own writes/outputs are 1,254,643
bytes and no quota termination occurred. RAM alone therefore does not resolve
this observed failure. A separate source/nonce-bound loader-order and
LoadLibraryEx diagnostic is being prepared; previous PASS and FAIL evidence
and the stable bridge/consumer sources remain unchanged.

## Genuine loader-order acceptance

The separate `memory_loader_probe` source and fresh private guest trial now pass
76 assertions and 37 evidence/resource/preservation regressions. The exact
missing fibers contract fails first with error 126; all five KERNELBASE loads
then return the same genuine module with zero error before any file inspection.
The real memory ownership subset, normal child exit zero and successful raw
proc_wait zero pass again. The original 69-PASS proof remains byte-identical.

`build/lp64-final-audit-root-v1/audit.json` independently rehashes the actual
kernel, archive, QEMU, firmware, candidate and source inputs, verifies KVM and
stopped owned process, and matches the failing 1024-MiB Signal trial's machine
flags after private-path normalization. Its SHA-256 is
`696c72fa9e8b2c60d21e349f6f39a6a4de90eb0af81e0dc099ff17b3f394823e`.
Peak private writes plus own output are 216,586 bytes; measured minimum free
space is 36,987,846,656 bytes. No resource termination occurred.

This exercised load ordering/search flag difference does not reproduce the
retained Signal failure. Application context/concurrency/state remains
unresolved, and no loader patch is justified by this result. The source and
hash-bound handoff are committed as `4e67038`. Signal functionality and native
Windows 98 integration remain unverified.
