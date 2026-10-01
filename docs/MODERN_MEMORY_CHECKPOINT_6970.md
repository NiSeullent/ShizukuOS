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
claims remain unverified. The unchanged 20 GiB reserve, private 256 MiB write
limit and 16 MiB output limit apply to that trial.
