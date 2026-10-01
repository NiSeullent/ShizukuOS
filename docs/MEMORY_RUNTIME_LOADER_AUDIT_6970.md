# Signal memory runtime loader audit — 2026-10-01

The Signal memory overlay was correctly delivered to the executed guest. The
actual sealed archive contains the exact KERNELBASE candidate, and the guest
reports mounting all 143 members. Signal nevertheless reports a basename
`kernelbase.dll` load failure and subsequently misses the three modern memory
APIs. This audit establishes input delivery and identifies the next loader
diagnostic; it does not establish memory adapter execution or Signal functionality.

This was a read-only audit of the stopped `signal-memory-themed-run-v1` attempt.
Only this new document was written. No existing source, receipt, peer record,
application image, firmware or VM was changed, and no VM or network request was
started. The original failed attempt remains intact.

## Executed artifacts and provenance

The run directory is
`/root/Win98-Modern-theme-6970/build/modern-required-apps-6970/signal-memory-themed-run-v1`.
The actual command is recorded in `result.json` under
`resource_guard.actual_qemu_command`. It invokes the run-owned sealed QEMU,
uses the sealed firmware directory with `-L`, and supplies these exact kernel
and archive paths to `-initrd`. The application disk is used with `snapshot=on`.

| Artifact | Exact path | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Executed archive | `/root/Win98-Modern-theme-6970/build/modern-required-apps-6970/signal-memory-themed-run-v1/runtime-inputs/WIN64.IMG` | 17,635,497 | `fa2973620864ad64dfb8c00856f821beab33a3f7abe65024d6439cb7840441d1` |
| Derived overlay archive, source of sealed archive | `/root/Win98-Modern-theme-6970/build/required-memory-runtime-6970-v1/WIN64.IMG` | 17,635,497 | `fa2973620864ad64dfb8c00856f821beab33a3f7abe65024d6439cb7840441d1` |
| Executed kernel | `/root/Win98-Modern-theme-6970/build/modern-required-apps-6970/signal-memory-themed-run-v1/runtime-inputs/KERNEL64S.BIN` | 643,546 | `9de5567e73138b78407bc7993823b564ae63e285395c82367ba1186ffab42d9e` |
| Source of sealed kernel | `/root/Win98-Modern-apps-cb43/build/shizukudos/kernel64s/KERNEL64S.BIN` | 643,546 | `9de5567e73138b78407bc7993823b564ae63e285395c82367ba1186ffab42d9e` |
| Symbol-bearing peer kernel ELF inspected | `/root/Win98-Modern-apps-cb43/build/shizukudos/kernel64s/kernel64s.elf` | 732,104 | `f5f600256551277d795fc83fdc1e58bcdb30b92f7860205e0630ec4803a71a9d` |
| Candidate DLL | `/root/Win98-Modern-theme-6970/ntwddm/win64/memory_bridge/build/20261001T085541Z-9876aa10/KERNELBASE.DLL` | 69,609 | `d370ada2423503929a761f271fcf0728d9dadaecd52f906ee52b8167c347efff` |

The ELF-to-kernel identity was checked independently in memory: copy each
allocated non-NOBITS ELF section to its declared virtual-address offset,
preserve zero-filled gaps, and compare the resulting bytes with the executed
kernel. The resulting address interval is
`[0xffffffff80100000, 0xffffffff8019d1da)`, length 643,546, with exactly the
executed kernel SHA-256 above. The reconstructed image is byte-for-byte equal.
Consequently the inspected machine instructions are those supplied to this
guest, rather than merely an assumption that current C source matches a binary.
This check does not independently prove the entire current C source/build lineage.

Additional binding records:

| Record | Exact path | SHA-256 |
| --- | --- | --- |
| Candidate build receipt | `/root/Win98-Modern-theme-6970/ntwddm/win64/memory_bridge/build/20261001T085541Z-9876aa10/result.json` | `32a42d8d79d1dc8e65a159824a4fd9f25e36c38d23d14ee50b44bcfb3590af6b` |
| Extension overlay receipt | `/root/Win98-Modern-theme-6970/build/required-memory-runtime-6970-v1/extension-overlay.json` | `7af0d26107ddd0e07fe3c0c123adc7081bdf95865b58d4a028892f7a5fefb1c3` |
| Actual application result | `/root/Win98-Modern-theme-6970/build/modern-required-apps-6970/signal-memory-themed-run-v1/result.json` | `37407f402dbe61556f2372a37a3970662d5482b9b0f796074f9bdad3d8b69bef` |
| Runtime seal | `/root/Win98-Modern-theme-6970/build/modern-required-apps-6970/signal-memory-themed-run-v1/runtime-seal.json` | `f6ea15768d6d4bd8f8a3e2f082a4255ac5a93b1a57a8b975ec342cfe953a401b` |
| Extension runtime result | `/root/Win98-Modern-theme-6970/build/modern-required-apps-6970/signal-memory-themed-run-v1/extension-runtime-result.json` | `32f5d6f508b38c4c91a7158df8b9627063063b7e228e6868cbb2a3a5085cc927` |
| Actual guest serial | `/root/Win98-Modern-theme-6970/build/modern-required-apps-6970/signal-memory-themed-run-v1/serial.log` | `c5cae148c12a7a5744e4a7165668a91153fccf33c894abcd3dd18327acd7a69c` |

## Physical archive contents and guest mounting

Independent parsing of the sealed bytes finds `SHZARC01`, count 143, reserved
field zero, with bounded entries of 120 path bytes and two 64-bit offset/size
fields. The final two entries are shown using zero-based indices:

| Index | Guest member path | Payload offset | Payload bytes | Payload SHA-256 |
| ---: | --- | ---: | ---: | --- |
| 141 | `\SHZ\SYS64\UXTHEME.DLL` | 17,525,536 | 40,341 | `f8e69da3c430f9b237fc490ea5f72cae8d3bcffab5b1efc77208ead22ce95442` |
| 142 | `\SHZ\SYS64\KERNELBASE.DLL` | 17,565,888 | 69,609 | `d370ada2423503929a761f271fcf0728d9dadaecd52f906ee52b8167c347efff` |

The actual serial starts with an initrd length of `010d18a9`, equal to
17,635,497 bytes. Serial line 14 then reports:

```text
Kernel64 0.1: initrd mounted, 143 file(s)
```

These independent observations reject the explanations that the old 142-member
archive was executed, that the consumer override omitted KERNELBASE, or that the
app attempted a guest whose initrd never received the candidate. A mount count
and physical member are not proof that a later live filesystem lookup succeeds.

The candidate has three direct adapter exports and 591 forwarders to exact
direct KERNEL32 exports, with nine resolved direct imports. The extension
preparation independently compares its actual full export/import tables and
compiler input bindings. These structural checks do not prove guest ABI or
memory semantics.

## Actual failure and preservation

The application result is dated `2026-10-01T09:18:26Z`. Signal 8.28.0 started
as PID 60 in standalone ShizukuDOS Kernel64. The host run timed out after
90.1 seconds. No external kernel observation establishes normal application
exit. Relevant serial records are:

```text
K64 ldr: kernelbase.dll not loaded: LoadLibrary needs kernelbase.dll: DLL not found [c0000135]
K64 autorun: heartbeat 10 s: pid 60 threads 15, 773340 free pages, kernel heap 820 KiB used
[user Signal.exe pid 60] K32 trace: GetProcAddress miss: signal.exe!VirtualAlloc2
[user Signal.exe pid 60] K32 trace: GetProcAddress miss: signal.exe!MapViewOfFile3
[user Signal.exe pid 60] K32 trace: GetProcAddress miss: signal.exe!UnmapViewOfFile2
K64 autorun: heartbeat 40 s: pid 60 threads 15, 768410 free pages, kernel heap 911 KiB used
```

The extension result records `sealed_extension_runtime_input_verified=true`,
`overlay_inputs_preserved=true`, `handoff_error=null`,
`preservation_error=null`, and handoff return code 1. The application result
records all eight preservation fields as true: sealed runtime inputs, runtime
inputs, runtime sources, sealed firmware, firmware sources, handoff receipt,
publisher tree, and application disk image. Its resource guard retains a
268,435,456-byte write budget. This audit does not relax the selected 20-GiB
reserve or the existing bounded guest/log rules.

The wrapper's status remains FAIL. `modern_memory_semantics_verified`,
`app_functionality_verified`, `windows98_execution_verified`,
`os_wide_theme_verified` and this run's `theme_painting_verified` remain false.
The separate genuine AMD64 theme painter acceptance is a different receipt.

There are more threads than in the preceding three-thread attempt. Thread
counts alone cannot identify a cause or prove these adapters executed. Here
the explicit DLL load failure and subsequent symbol misses prevent attributing
the growth to successful KERNELBASE memory API use. Other differences in
scheduling or application startup have not been isolated.

## Loader evidence and ownership

Read-only source inspection in `/root/Win98-Modern-apps-cb43` identifies these
ownership boundaries:

- `shizukudos/kernel64/ldr.c:68` defines `SYS64_DIR` as `\SHZ\SYS64`.
  The KnownDLL table at line 357 includes `kernelbase.dll`. At line 420,
  `locate_file` searches SYS64 for KnownDLL/system-only requests; it does not
  explicitly reject KERNELBASE. `try_dir` at line 380 constructs the path and
  calls `fs_lookup`; the missing-file branch at lines 1125–1126 reports
  `DLL not found` when `locate_file` returns no node.
- `shizukudos/kernel64/fs.c:90` folds ASCII case when comparing names;
  `child_named` at line 100 uses that comparison and skips delete-pending
  nodes. `fs_lookup` at line 166 resolves paths. `fs_load_archive` at line 337
  iterates all declared members, creates their parent directories/files and
  returns the count. Its bound is 4,096 members, not 142. No KERNELBASE-specific
  mount exclusion was found in this source.
- `shizukudos/win64/ntdll/ldr_search.c:288` and
  `shizukudos/win64/kernel32/k32_mem.c:218` provide the LoadLibrary call path.
  Their inspected path has no explicit basename KERNELBASE denial.

The current loader C source SHA-256 is
`014c51701f0cddc113e43e5cc4a3c780219a1b3890df232c78ff55d9d019ab8b`;
the filesystem C source SHA-256 is
`a264e713c45ca3af845100ced02dae984f9434153d8b9e202af66871c50da954`.

The matching compiled kernel supplies stronger evidence for the relevant
KnownDLL branch. Its pointer table at `0xffffffff80199000` begins with ntdll,
kernel32, and then a pointer to `kernelbase.dll` at
`0xffffffff801929e2`. In `load_dll`, the KnownDLL comparisons lead to
`0xffffffff80130a94`; this branch supplies the actual `\SHZ\SYS64` string
at `0xffffffff80193af0` and calls `try_dir.constprop.0` at
`0xffffffff80130ab5`. That helper calls `fs_lookup` at
`0xffffffff8012e822`. This confirms a compiled SYS64 search path, not an
established intentional KnownDLL prohibition.

No live guest namespace or file-node dump was available from the stopped
attempt. The precise reason the lookup failed remains unproven. A consumer
sealing fix, case alias, KnownDLL policy change or peer source patch would
therefore be speculative. Existing consumer sources and receipts remain stable.

## Next bounded diagnostic

The memory probe owner has been given the exact mounted candidate binding and
the following checks for a fresh, isolated guest: A/W file attributes and
immediately saved errors for `C:\SHZ\SYS64\KERNELBASE.DLL`; independent lower
and upper basename loads; an absolute-path load; full-width module handles,
module file path, and the three dynamically resolved API addresses. A forwarded
`GetCurrentProcessId` call distinguishes adapter and forwarder loading. Memory
subset assertions run only after the absolute module loads, and an external
kernel exit/proc_wait observation gates execution success. Loader discovery,
ABI/memory subset behavior, and application functionality remain distinct claims.

## Read-only peer progress snapshot

The records below were inspected without controlling another session or starting
an application. They describe those specific saved records, not a global claim
that no newer owner work exists.

- LibreOffice 26.8.0: the peer's
  `/root/Win98-Modern-apps-cb43/build/modern-apps/libreoffice-v36-k13-actual/result.json`
  has SHA-256 `066cd89674919ec6d9220c56384e36dd53d0a48abccbf627b9f6f3a68ad8340f`.
  Its actual version command fails because `sal3.dll` needs the missing direct
  `KERNEL32.dll!CreateDirectoryExW` export. Expected version output is absent;
  the raw external exit is `ffffffff`. App functionality and Windows 98
  execution remain false in that record. A subsequent source port would need
  a new bound guest run before this gap can be declared resolved.
- Legcord: the saved interactive state
  `/root/Win98-Modern-apps-cb43/build/modern-apps/legcord-v34-k12-interactive-actual/interactive-state.json`
  has SHA-256 `9ccbcb3079c79f98ec7f531bae62ccf7226702fc2f579346199f57273d45374b`.
  It records nonce `be025794f5e4c342c767079cdca8c7eb`, nine accepted control
  sequences, disabled controls, and false functionality/Windows 98 flags.
  Saved interaction/captures do not establish Discord login, messaging or voice.
- TLS: the newer peer receipt
  `/root/Win98-Modern-tls13-7707/build/secure-transport/sspi-guest-probe-real-host-v1-final/receipt.json`
  has SHA-256 `5ba7449363b178475f3df283dae027964853baaac7ff215a51ef656fb64011ba`.
  It passes the actual probe protocol C with an isolated real SSPI TLS DSO/server
  on Linux, explicitly recording `native_guest_proven=false` and
  `actual_windows_dll_execution=false`. The independent preparation audit
  `/root/Win98-Modern-tls13-7707/build/secure-transport/parent-review-20261001T0825/receipt.json`
  also passes, SHA-256
  `ef591dbae0ca65de9ae076fbe164186167ae1e53b801ce062ce34354b9179107`,
  with scope explicitly limited to frozen preparation binding and no Windows
  execution. These records require separate native guest and OS-provider
  evidence before promoting TLS support inside Windows applications.
