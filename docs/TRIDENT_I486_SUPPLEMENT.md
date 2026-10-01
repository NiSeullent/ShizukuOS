# Frozen Script/Automation CPU supplement guard

`tools/verify_trident_i486_supplement.py` adds a mandatory CPU provenance check to
the frozen canonical Script and Automation stages. The original builders,
verifiers, stages and failed trials remain unchanged. The guard launches nothing,
executes no EXE/DLL or repository scanner, and requires no third-party Python
package. Its pure `verify(manifest, manifest_sha, supplement, supplement_sha)`
function returns evidence only after the complete check succeeds.

The caller supplies the exact manifest hash and the explicitly approved
supplement hash. Only the two original direct-child stages under
`/root/Win98-Modern-boot/build` are admitted:

| Component | Manifest SHA256 |
| --- | --- |
| Script | `5ee49445c47e45537e7fbc563dea4007b345f6b6469305c5aa76c7c3e65b57eb` |
| Automation | `13eddef2f02f8bfc3a1ba331aaf8fa027e334cff8e7a2a225ddeeab517e46a9a` |

The supplement is the unchanged
`build/i486-canonical-supplement-v1/result.json`, SHA256
`e8005132e8f917adedb54b3b85e1d6bfbb0c46bfc432288db34016537bdf53c6`.
All six exact artifact paths are checked even when the caller selects one
component. Three input names, observer command, output plan and source receipts
must agree with the selected canonical stage. Canonical regular evidence files,
bounded reads and before/after descriptor checks exclude symlinks, nonregular
files and changes during reading. Duplicate JSON keys, nonfinite numbers,
incorrect types, extra proof entries and upgraded native/browser scope fail.

The saved proof uses historical helper SHA256
`3da2e3c04fce6a85b1d92ff3c398d43f3f6312c0a56c71c0b4d5f5b53c9f1f7d`,
test SHA256 `40ff19e18fb305dab4006f3e88dbcab3fae6f53b2140248e88d37d0fcda12667`,
and audit-source SHA256
`d4637da446ec7b8f8b703ee38c04e78304eb5cd880781c893e8ca9bf24ae1490`.
The current helper's later BT/BSF/BSR suffix extension is not substituted. The
guard verifies all three frozen source snapshots and the original control log.
It extracts only five literal opcode tables from the historical source AST;
neither that source nor its tests are imported or executed. Historical controls
record three tests with 27 modern instructions after operandless predecessors.
The returned result explicitly says those controls were not rerun.

The guard independently parses actual PE32/i386 headers and section tables. It
rejects truncated/overlapping raw or virtual extents, ambiguous section names
and address overflow. It replays each preserved disassembly log, requiring its
exact artifact header, strict horizontal rows, legal 1–15 byte instruction
lengths, original i486/x87 mnemonics, recursive prefixes and legal operands.
Every instruction must match actual PE bytes at the next contiguous address;
every executable section must appear exactly once and be completely consumed.
Instruction counts and every section's address, size and hash are recomputed
and compared to the frozen receipt. The covered extent is each executable
section's **declared VirtualSize**. Raw file-alignment padding is excluded, as
in the original proof; this is not a claim that every file byte is an instruction.

Selected stage build receipts, source snapshots, prepared engine/math sources,
build logs and every stage provenance member are also checked. The complete
observed closure is read again before returning to detect changes during replay.
The original stage provenance file's actual SHA256 is retained in both
`stage_provenance_sha256` and the complete checked-evidence map; a late change
during raw-log replay must fail the final re-read.
The guard's CLI writes a bounded receipt and snapshots of its own three source
files only to a fresh direct child of this worktree's ignored `build` directory.

Call the pure guard immediately before native launch, then let the existing
collector verify the immutable input hashes again while copying inputs to the
owned private run. Call the guard again as a required conjunct of final native
acceptance, using the same manifest and supplement pins. A previous guard result
must not substitute for checking the files again. The original native verifier
must still validate actual owned-run execution, output freshness, child lifetime,
DOM/numeric observations and any separately trusted paint review.

For example, the read-only proof replay plus fresh local receipt command is:

```text
python3 -B tools/verify_trident_i486_supplement.py \
  --manifest /root/Win98-Modern-boot/build/trident-script-native-5abe-20261001-v1/guest-files.json \
  --manifest-sha256 5ee49445c47e45537e7fbc563dea4007b345f6b6469305c5aa76c7c3e65b57eb \
  --supplement /root/Win98-Modern-theme-tls-5abe/build/i486-canonical-supplement-v1/result.json \
  --supplement-sha256 e8005132e8f917adedb54b3b85e1d6bfbb0c46bfc432288db34016537bdf53c6 \
  --out /root/Win98-Modern-theme-tls-5abe/build/trident-i486-guard-script-v1
```

Tests use the actual frozen proof as the successful CPU baseline and isolated
synthetic read/metadata/PE/disassembly faults as rejection controls. They run
under ordinary Python and `python3 -O`; checks do not depend on `assert`. Test-only
mocked receipt approval exercises deep rejection paths and grants no production
approval. No native logs, paint evidence, VM or simulated native receipt is
produced. Saved CPU provenance alone leaves actual CPU execution, native
execution/styles/paint, full JS/HTML/CSS/browser, WASM, WebGPU/WebGL and modern
application acceptance false. All user-requested modern capabilities remain
mandatory unfinished work.
