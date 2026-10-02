# Native TLS cached stale-refusal diagnostics Implementation Plan — 6970

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans for the authorized implementation. Steps use checkbox syntax. This document authorizes no source implementation or hosted dispatch by itself.

**Goal:** Preserve already cached numeric scan evidence when an unstable fresh snapshot causes a stale-schedule precondition refusal, without changing that refusal or any process-control behavior.

**Architecture:** Extend only the existing stale diagnostic for `REFUSED_RECHECK_PRECONDITION`. Pin distinct cached values, retain full values or bounded samples under the existing joint limits, and preserve the admitted original diagnostic and its return value on every enrichment failure. Explicit hosted in-memory checks exercise the recorder on synthetic objects and retain a small report in the existing main receipt.

**Tech Stack:** Existing Python standard library, pinned resource helper, current hosted builder and workflow. No new package, executable, driver, binary, child epoch or output file.

**Spec:** `docs/agents/plans/native-tls-stale-order-6970.md` and `docs/agents/plans/native-tls-main-receipt-columns-6970.md`, narrowed by the immutable eleventh-run evidence and diagnostic-only contract below.

## Actual starting scope

Run `36966443458`, TLS job `110711134045`, source `ffb6f8652f1966a76ec174dae1a9b5e69de560ba` completed FAIL with artifacts0. The older provider job `110711135049` was skipped. The full main receipt is 210664 bytes/SHA256 `762123665ba363499d52c44f76d1aee487ff750fb9a10759a5395d678289abe9`; all 37 command records are retained. Independent JSON-data reconstruction matches the recorded decoded array 89100 bytes/SHA256 `ccbbcbc7c35559dbadd942ea56738ccba0891d4a3bd8f14a74161cdfde807762`.

Root review 65580 bytes/SHA256 `b7354794e44ffaaaed8f7fa57f00858c72ef5b00217e000feebbe1045cb62dbb` binds twelve inputs/935034 bytes, source32/2739303 bytes, all19 closed actual child controls, 28 metadata codec cases, 55 child/GAS/map text bodies/152391 bytes, normal25099 and raw15. Its creation-time pending-crossbind field remains immutable; subsequent independent full crossbind is CLEAR_FAILED_SCOPE_ONLY. This establishes the stated host control/data scope, not a successful production build.

Command36 `cmake-configure` failed with `owned stop candidate disappeared from current group`: leader2708, scheduled nonleader2727/startticks12089/PPID2708/pgrp2708/session2708/UID1001/stateS. The stale record says `REFUSED_RECHECK_PRECONDITION`, fresh stableFalse/member1/task1/SHA256 `7dd2e8faf615f5007146f89cf46a8542a333a85a10e256475c842a3ab1beb458`. No dedicated numeric presence read occurred; errno/class are null and absence checks0. The underlying cached events, typed scan errors and full fresh rows were not retained and cannot now be reconstructed. Scheduled PID equality would not bind a later event to that birth identity.

The command was rc-9/reaped with owned group kill requested; STOP2/CONT2/verified2 belong to prior observations. `failure_stop_retained_until_owned_kill=False` and `failure_observation=null` do not prove held STOP at this refusal. Observed full stdout47/SHA256 `fc10a11774401b45593dedae7c9d21774e295b97a3296498124d03f87f13e279` has retained physical bytes0; those 47 bytes stay missing, not reconstructed. No configured Ninja graph, native object/PE, final source closure, Windows98/TLS/app/ISO success follows from this run.

## Global constraints

- Windows98 remains the product OS. ShizukuDOS replaces MS-DOS; Kernel32/64 are Windows98 backends. Design and publication ownership stay separate; no main/live/peer/NAS/native guest/ISO mutation.
- Keep reserve20GiB, proof32MiB, receipt1MiB, normal256KiB, aggregate decoder64MiB, child logger512KiB, transfer48MiB and upload64MiB. Keep all existing per-command/raw/input/observation limits and original one-second pause/whole-command deadlines.
- Keep the 32-source path set and seven-loader path set. The other30 source bytes, twenty production/five support literal pins, nineteen driver bytes and GAS are unchanged from FFB. Resource/builder hashes and their workflow preload literals necessarily change for this implementation.
- Current loader maximum is 204800 bytes each: builder196850 leaves7950 bytes; resource119401 leaves85399 bytes. Do not increase it. All seven final buffers must be pinned and independently checked before code loading.
- All nineteen `Guard` methods, all existing resource module imports/assignments, and every other existing observer method remain normalized-AST identical to FFB. Only `_OwnedGroupObservation._record_stale_schedule_observation` may change; new helpers are pure data functions or explicitly invoked hosted metadata controls.
- No new production proc read, `_validated` call, retry/skip, signal/wait/reap, timer sample/check/reset, counter/latch/minimum/peak mutation or acceptance rule. Existing `time.monotonic()` in the recorder remains exactly one call; no clock monkeypatching.
- No local project/module/codec/control/helper/compiler/VM execution below20GiB. Source/AST/data reviews are permitted. Production stdout lost earlier and missing historical cache values remain missing.

## Recorder contract and base-result preservation

Keep the method signature and every existing base field/schema/classification. First construct and admit the original FFB base diagnostic using its original `sampled_row_count`, eight-row check, 16KiB check and exception fallback. This establishes the original return bool. If the base already fails, retain its exact original size/encoding-refusal behavior and False return, without enrichment. If classification is anything other than `REFUSED_RECHECK_PRECONDITION`, retain the original diagnostic and return unchanged; especially do not enrich `CONFIRMED_NONLEADER_PROC_ABSENCE`, whose True return authorizes an existing reconciliation path.

For an admitted target refusal, add only `cached_scan_evidence` inside the existing `last_stale_schedule_observation`. It may use only the argument `fresh_snapshot` and existing `last_scan_snapshot`, `last_scan_instability`, `last_validated_snapshot`, `last_validated_scan_instability`, `last_validated_completed_at`, `last_validated_pause_attempt`, and `last_validated_pause_iteration`. Never refresh them. The original observed timestamp and pause/command deadline fields retain their meanings.

`last_validated_snapshot` is the most recent structurally validated `_snapshot()` result and can have stableFalse. It is not the last quiet, accepted or count-stable snapshot. Fresh normally equals this cache, but observer hooks can leave the actual scan cache different. Preserve cached completion time and pause phase independently; never infer quiet/count acceptance from these slots.

Enrichment failure or excess must never turn the admitted base True into False, replace the original error, or authorize absence. Try bounded pins/samples; if even that cannot fit, retain the complete original base without the new field. Do not drop a base row/token/field or clear a failure to make room. No additional fallback hash is mandatory if adding it would cross16KiB.

## Frozen nested wire contract

`cached_scan_evidence.schema` is `owned-stale-cached-scan-evidence-6970-v1`; scope is `existing_completed_cached_numeric_values_at_stale_refusal`. Canonical values use sorted compact JSON, UTF8, ensure_ascii=True, allow_nan=False, without a trailing newline. Hash/byte counts bind the exact complete cached value, not a reconstruction from its samples. Canonicalization is bounded by the unchanged32MiB logical profile. An encoding/nonfinite/limit failure is explicitly UNPINNABLE; omit unmeasured complete length/hash, never coerce NaN, repr values, or invent a digest.

- `snapshot_refs` has exactly `fresh_snapshot`, `last_scan_snapshot`, `last_validated_snapshot`. Each descriptor has `state` AVAILABLE/ABSENT/UNPINNABLE and `table_index` integer-or-null. AVAILABLE adds `canonical_bytes` and `canonical_sha256`; UNPINNABLE adds only `error_class` truncated to128 UTF8 bytes and a fixed `reason_code` when a complete pin was not measured. ABSENT is a real None cache, not an invented empty snapshot.
- `instability_refs.last_scan_instability` uses the same descriptor into `instability_table`. `instability_refs.last_validated_scan_instability` pins the complete original wrapper and retains its original bool `matches_returned_snapshot` plus `metadata_table_index` integer-or-null. Its referenced metadata is stored in the same instability table. An unavailable or malformed wrapper is explicit; never relabel its False match as True.
- `bindings` contains canonical-byte equality, or null when unpinnable/unavailable, for `fresh_equals_last_scan_snapshot`, `fresh_equals_last_validated_snapshot`, and `validated_metadata_equals_last_scan_instability`. Keep these separate from the verbatim wrapper flag. Preserve source labels for caller fresh argument, last actual numeric scan cache, and last completed validated cache; equal data does not merge temporal phases.
- `stored_validation` copies only the existing `completed_at_monotonic`, `pause_attempt`, and `pause_iteration`, including real None values. It adds no current timestamp or claim of a failure-instant observation. A non-JSON/nonfinite stored value is described as unpinnable instead of copied into invalid JSON.
- `snapshot_table` and `instability_table` use first-appearance order. Deduplicate only byte-identical complete canonical values of the same kind, proved by byte equality; SHA/length or Python dictionary equality alone is insufficient. Reference every original slot. A validated wrapper references its exact metadata without embedding a second event list.
- A snapshot FULL entry stores its exact `value` and pin. A SAMPLED entry stores pin, actual stable/member/task counts, `sampled_rows` with leader/member/task roles, `sampled_row_total`, and `sampled_rows_truncated`. A metadata FULL entry stores its exact `value` and pin. A SAMPLED entry stores pin, actual scope/total_events/classification_counts, original `cached_events_truncated`, original cached event count, unchanged sampled `events`, and separate `events_retention_truncated`. Complete cached metadata can itself have truncated scan history; never claim complete original event history from FULL cache retention.
- `retention` states base numeric rows, physically retained snapshot rows, physically retained events, their combined count, full-cached-values retention, sample truncation and final entire diagnostic bytes. Preserve the legacy top `sampled_row_count` as the original base count; do not silently redefine it. All cause/ownership/exit/reap/continuous-stop/new-read/retry-acceptance claims remain false.

## One combined row/event and byte budget

The already admitted scheduled row and optional current row reserve their original one/two slots. Every physically stored snapshot leader, member occurrence and task occurrence then costs one row: leader equal to a member still costs two when both are embedded. Distinct tables repeating equal individual rows cost again; only complete byte-identical table aliases store once and charge once, with all source refs retained. Every stored event costs one, including repeated events in distinct metadata tables. No uncharged full row or event may be hidden in a summary, wrapper, token table or alternate field. Existing base birth tokens are preserved under the original base contract.

FULL is allowed only if base rows + all stored snapshot rows + all stored events <=8 and the complete final diagnostic <=16384 bytes. Otherwise retain complete pins and summaries, then bounded prefixes. Reserve base first; select metadata table event prefixes in last-scan/validated first-appearance order, then snapshot table rows in fresh/scan/validated first-appearance order and leader/members/tasks order. Do not truncate event strings or row fields into fabricated partial values. If a whole next sample cannot fit the byte ceiling, omit it and mark retention truncation. Canonical full-value pins and original source truncation flags still describe what was omitted. Iteratively remove tail samples/optional enrichment until the entire output fits; if no enrichment fits, use the original base. Final encoded byte accounting includes every base field, new field, sample, pin and marker. Stabilize its self-inclusive byte-count field in at most32 iterations; nonconvergence also preserves the original base/result.

## Review focus and deterministic hosted controls

The review must cover mismatched actual/validated phases, duplicate leader/member charging, joint row/event overflow, byte/nonfinite encoding failure, and the original positive/negative recorder return contract. Tests address these directly; they establish synthetic serialization behavior, not kernel observations.

New resource API: `hosted_stale_cached_diagnostic_controls() -> dict`. It executes only when explicitly called after the hosted builder's existing >=20GiB+32MiB admission and verified resource buffer loading. Construct synthetic observer objects with `__new__`; directly call the real recorder with declared numeric JSON fixtures and actual existing recorder clock behavior. Do not instantiate `Guard`, patch the clock/syscalls, read `/proc` or any file, create processes, alter real counters or use a new child proof pool. Keep a60-second overall control bound and report <=8192 canonical bytes; no output/file is written by this function.

Seven ordered cases are mandatory:

1. `matching-caches-full`: one byte-identical fresh/scan/validated snapshot, exact wrapper matchTrue, one typed cached event and source refs. Verify full pins/reconstruction, original True return, and conservative duplicate leader/member charging within8.
2. `mismatched-cache-phases-full`: distinct actual scan versus returned/validated snapshot, original wrapper matchFalse, exact separate pins and equality bindings. Fit exactly8 joint slots and verify no False-to-True relabel or phase merge.
3. `joint-row-event-overflow`: FULL would cross8. Verify final combined count<=8, complete cache pins, exact prefix samples/truncation, source event truncation unchanged, and original True return.
4. `diagnostic-byte-overflow`: an explicitly synthetic oversized encodable cached value would cross16KiB. Verify complete measured pins but omitted oversized whole samples, final diagnostic<=16384, and original base/True result preserved. This fixture is not labelled an actual kernel error payload.
5. `cached-encoding-refusal`: non-JSON and nonfinite cached subvalues are unpinnable. Verify no fabricated complete hash/length, bounded error/available other pins, original base/True result, and no new exception/latch.
6. `confirmed-absence-base-unchanged`: call the other classification with a declared synthetic errno fixture. Verify no new nested field and the original base schema/key set/True result; this is not an actual syscall-absence proof.
7. `original-base-refusal-unchanged`: a synthetic already oversized or unencodable base retains its FFB fallback and False return; enrichment does not revive it.

For each case verify input dictionaries/cached wrappers before-after canonical equality when encodable, or unchanged object values for deliberately unencodable inputs. Verify all synthetic telemetry keys/counters/latch fields except the existing last-stale diagnostic are unchanged; forbid reads/signals/process creation through source/AST review, without monkeypatching production operations. Summaries record only case name, PASS, expected/actual retention and return, bounded pin/count/truncation observations. Do not retain huge fixtures or full synthetic diagnostics in the report.

The report schema is `native-tls-stale-cached-diagnostic-controls-6970-v1`, result `PASS_CACHED_NUMERIC_METADATA_CONTROLS_ONLY`, completed7/failures0. Record ordered case results, synthetic-input status, input-before-after equality, zero commands/child epochs/pool charges, and false actual-proc/kernel/process-control/native/Windows98/TLS claims. Host time bounds constrain tests, not production pause timers.

## Authorized implementation units and gates

### Task 1: Resource recorder and hosted metadata checks

- [ ] First prepare the seven deterministic assertions against the frozen FFB base contract; locally review source/AST only, since project execution is prohibited.
- [ ] Modify only `ntwin32/secure_transport/native_tls_resources_6970.py`: the one recorder method plus new pure canonical/table/retention helpers and the explicit hosted control API. Preserve all imports/module assignments and every other existing class/function/method AST.
- [ ] Prove base return/encoding fallback preservation by source review; source-match the recorder's original clock call count and all nineteen Guard methods to FFB. Freeze complete bytes/SHA before independent review. Runtime RED/GREEN remains hosted-only, not claimed from AST parsing.

### Task 2: Minimal caller/report integration

- [ ] In `build_native_tls_guarded_6970.py`, add one explicit call immediately after existing28 `main_command_codec_controls` and before further production commands. Production enrichment needs no caller change; this caller is necessary only to execute and retain deterministic tests rather than hide tests in import/production paths.
- [ ] Bind `stale_cached_diagnostic_controls` in the existing main receipt, require exact schema/seven cases/result/<=8192 canonical bytes and zero pool charges. Compare actual parent command records/count, capture/decoder pools and first failure before/after; existing counters remain unchanged. Existing final32-source before-after closure checks cover changed resource/builder buffers; add no source file or capture category.
- [ ] Keep all other builder functions/old controls unchanged and final builder<=204800. The bounded report consumes existing self-inclusive main receipt/proof capacity, not an extra allowance. If any report assertion fails, retain ordinary bounded FAIL evidence; never bypass a guard failure or enlarge receipt caps.

### Task 3: Existing workflow seal and final review

- [ ] Update only the two changed builder/resource preload literals and add the corresponding pure-data seven-case/report-bound/no-charge validation inside the existing sealer. Keep workflow structure/conditions and other step bodies unchanged. No new workflow driver, logger/recovery format, source path or upload category: existing lossless nested-value preservation already carries the new diagnostic/report.
- [ ] Independently read the whole final source32 and all7 loader buffers/stat9/hash/ASTs, compare old30/old19/GAS/literal caps to FFB, parse all7 embedded Python ASTs/YAML, check all frozen Guard/observer methods and production clock/read/signal sites. Bind complete final files and plan bytes/SHA.
- [ ] Root and independent exact final design/source reviews precede any isolated commit/push/one hosted dispatch. Root owns integration/Git; designated publisher owns main/live/native guest/ISO. This plan-writing task performs none of those actions.
- [ ] The next hosted run must independently close all19 actual child epochs, seven synthetic metadata cases, existing28 codec cases and their unchanged pool accounting before evaluating production compilation. A diagnostic with new cached data may clarify the next failure; no retry/acceptance fix is authorized by this plan.

## Present status

NOT_IMPLEMENTED. No source/control/runtime change or historical evidence rewrite is authorized by this document alone. Actual eleventh failure stays immutable; its missing scan metadata and physical47-byte stdout remain unavailable. Overall Windows98 modernization and final deployment remain separate, unfinished work.
