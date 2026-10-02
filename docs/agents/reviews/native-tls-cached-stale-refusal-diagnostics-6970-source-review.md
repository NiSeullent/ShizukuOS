# Native TLS cached stale-refusal diagnostics — source review

Reviewed on 2026-10-02 against `ffb6f8652f1966a76ec174dae1a9b5e69de560ba`.

Verdict: **SOURCE CLEAR**. Root and independent resource/builder/workflow reviewers read the frozen implementation and closed the malformed-cache findings. This verdict covers source behavior and bounds; the new seven hosted cases have not executed at this checkpoint.

## Problem and resulting behavior

Actual run `36966443458`, job `110711134045`, failed during CMake configuration. The stale-schedule diagnostic retained an unstable fresh-snapshot hash and counts, but omitted its cached scan events and rows. That evidence cannot establish why the recheck failed or whether scheduled PID2727 was actually absent.

For `REFUSED_RECHECK_PRECONDITION`, the recorder now optionally retains existing cached snapshots, typed scan metadata, phase labels and canonical pins. It preserves the original refusal, base admission, return value and fallback. Other classifications use the unchanged recorder path. No new production process read, signal, retry, validation, timer sample or acceptance rule is introduced.

## Frozen source and plan

| File | Bytes | SHA256 |
| --- | ---: | --- |
| `native_tls_resources_6970.py` | 153260 | `4bab8ebb7fef06a3460ec89dcff8d10ae59b452c79e5268ba9fe873de946d727` |
| `build_native_tls_guarded_6970.py` | 200395 | `f9b843e15aef81050af5722e117ebb86b75ae07895e2a0eac2aa3c809c0989df` |
| `.github/workflows/native-tls-build-6970.yml` | 123368 | `edb380313a0f51d240e80dd9f489772808b72a05b5f4b1b50322e3ee095a4213` |
| `native-tls-cached-stale-refusal-diagnostics-6970.md` | 19901 | `04860b6ba748994c82bf502a9402213bb9944a1f2e71c205bf81e1d2fbace3ed` |

The two Python files are under `ntwin32/secure_transport`; the plan is under `docs/agents/plans`. The 32-source path set is unchanged, totaling 2776707 bytes. The other30 files remain exact FFB bytes, totaling 2423052; production20 remains201016 and support5 remains2016046. All seven preloaded buffers remain within the existing204800-byte per-buffer limit and bind their exact whole-file hashes.

## Semantic and bound checks

- Removing the single optional post-admission classification branch restores the complete original observer-class AST. All19 Guard methods, the other31 observer methods, old free functions, imports and module assignments remain unchanged. The recorder retains its one original monotonic sample.
- Complete canonical byte equality deduplicates whole snapshot or metadata values. Separate cache references preserve their temporal labels; the structurally validated cache may be unstable and does not imply quiet/count acceptance. The stored wrapper match flag remains verbatim.
- Existing base rows, every physically embedded leader/member/task occurrence, and metadata events share one8-item limit. Wrapper descriptors reference the metadata table instead of embedding another event list. Scan-history truncation and retention truncation remain distinct.
- Full values, bounded prefixes, pins, summaries and self-inclusive byte accounting all fit the existing16KiB diagnostic. Accounting converges within32 iterations; enrichment errors or excess preserve the admitted original base and its return value.
- Stored completion time permits only None or finite nonnegative strict numeric scalars. Stored pause phases permit only None or nonnegative strict integers. Optional event exception class and errno permit only string and None/strict integer values. Nested objects, booleans in integer slots and nonfinite values cannot hide uncharged rows/events. Unpinnable values have no invented complete size or hash.
- The explicit hosted API receives no live Guard or process. Seven synthetic cases cover full/mismatched caches, joint overflow, byte overflow, malformed cache values, unchanged confirmed-absence behavior and unchanged original base refusal. The malformed case includes stored-slot and optional-event subfixtures. Input/cache, telemetry and synthetic latch snapshots must remain unchanged.
- The builder compares actual parent command bytes/count, normal/raw pools and first failure before and after the call. It retains the report before validation, then checks exact cases, return/retention classes, scope flags, zero charges and strict JSON plus newline within8192 bytes. Resource report headroom is512 bytes; parent augmentation needs at most193.
- The existing sealer independently validates that report and its current33-command prefix. Reversing only the2727-byte report block and two preload hashes reconstructs the complete FFB workflow120641 bytes/SHA256 `e9fd95f076afee6a9016671d934e04da06e1d992fbaa5cf6ddcd8c9a4ce7dac6`. Workflow structure, other steps, logger/recovery and old sealer statements are unchanged. All seven inline Python ASTs parse.

The reserve20GiB, proof32MiB, receipt1MiB, normal256KiB, raw64MiB, logger512KiB, transfer48MiB and upload64MiB limits are unchanged. Existing19 control drivers and GAS remain byte-exact; the assembly is5187 bytes/SHA256 `fadbff94827c28c11ec2cc9156525b2ab01a52c8b061942ccd8779c85ce6b28e`.

## Verification scope

Whole-file reads, held/named file identities, SHA256 pins, normalized AST comparisons, YAML parsing and `git diff --check` passed. No local project/helper/codec/control/compiler/VM execution occurred; local free space is below the20GiB admission floor. New seven-case runtime success must come from a fresh admitted hosted run.

The independently closed previous run remains **CLEAR_FAILED_SCOPE_ONLY**: root review65580 bytes/SHA256 `b7354794e44ffaaaed8f7fa57f00858c72ef5b00217e000feebbe1045cb62dbb`, all19 actual controls and28 codec checks, 55 retained text bodies152391 bytes, 74 parent frames24944 bytes, normal25099/raw15. The build failed, artifacts0, failure STOP retentionFalse, and the last stdout47-byte body remains unavailable. Its typed cause, final source closure, native objects/PE, TLS runtime, Windows98/app execution and final ISO remain unproved.

Windows98 remains the product OS. ShizukuDOS replaces MS-DOS; Kernel32/Kernel64 are its backends. This source review does not authorize peer/main/live/native-image/NAS mutations or establish completion of the overall modernization goal.
