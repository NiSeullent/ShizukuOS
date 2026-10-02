# Native TLS first-failure exception metadata — source-only successor plan

Baseline source: `7ab4860709fdb637906693fd0bc9fd3ad95f5e25`. Public actual12 result doc is committed as `7d6ff6506c4d25507f55bbb22c454cc2f5ce4a62`; its code/source32 bytes remain exact7ab. This plan follows independent design assessments, without a new implementation or dispatch.

## Problem and evidence limit

Actual12 run36970091318/job110722074905 is closed FAILED scope. Its166 command records retain a final `cmake-object-2` returncode0 but aborted epoch, with the message `ResourceFailure: [Errno 2] No such file or directory: '2949'`. Stale/cache/failure observations are None. The message alone cannot identify the original exception class, structured errno, process versus task filename role, exact callsite, birth/ownership, exit/reap cause or held STOP.

The existing `Guard.count` catches the actual OSError and calls `_fail(error)` before `Guard.run` retains a formatted string. Preserve bounded exception/code metadata at that first latch, without a new proc observation or an acceptance change. Actual12's original callsite remains unknown permanently; later evidence belongs its later epoch.

## Ownership and frozen behavior

- Resource author: `count_epoch_design_review_6970`, only `ntwin32/secure_transport/native_tls_resources_6970.py`.
- Builder author: root6970, only `ntwin32/secure_transport/build_native_tls_guarded_6970.py`.
- Workflow author: `stale_order_workflow_author_6970`, only `.github/workflows/native-tls-build-6970.yml`.
- Independent source reviewer: `stale_order_source_design_6970`. Root owns plan/result/review docs, exact index, own-branch commit/push, admitted hosted dispatch and data review.

Only `_fail` and the main-opt-in branch of `close_receipt` may change among Guard19. The original failure assignment and `ResourceFailure(self.failure)` return AST remain intact. Guard.count, other17 Guard methods, all existing Owned methods, imports, old constants, old free functions, driver sources/GAS and production20/support5 are frozen7ab. New independently named pure helpers and an explicit hosted synthetic API are allowed. Preserve original default child receipt wire exactly; add the new field only for `main_command_columns=True`, including that main mode's bounded INVALID FAIL fallback.

Production diagnostics add no reads of proc/source/files, signals, wait/reap, clock samples, timer changes, retries, acceptance, counters, limits, logger categories, child epochs, VM/native media/NAS/main/live actions. The explicit hosted synthetic API alone may use its own actual monotonic start/end samples to report finite elapsed0..60 seconds; these are not production diagnostic clock reads or timer changes. Traceback inspection must not invoke linecache, traceback formatting, inspect or source retrieval. No locals, exception args, command arguments, payload or current frame position.

## First-latch contract

Use a lazy internal `Guard._first_failure_exception_metadata` slot; do not change Guard.__init__. Save the prior failure, retain the original assignment, then optionally record only if prior failure was falsy and that assignment produced a truthy latch. Capture occurs after the original string conversion and never calls str/repr(reason) again.

A first string-only truthy latch records explicit NON_EXCEPTION_REASON. An empty string preserves the original falsy behavior and cannot prohibit later genuine latch capture. Later cleanup errors never replace an established slot. Helper errors retain bounded CAPTURE_REFUSED metadata and cannot replace the original failure string, return, exception behavior or acceptance. Store copied JSON-compatible data only, with no exception/frame/traceback object retained. Read traceback/cause/context/suppression and OSError errno/filename through actual built-in descriptors, bypassing arbitrary subclass properties/getattr hooks, or refuse unsupported access. Code/frame/traceback fields use their genuine built-in types. Class/module labels must come from intrinsic class metadata without invoking metaclass/user hooks. The metadata path adds no user str/repr/descriptor call. Export `first_failure_exception_metadata` for main mode only; no failure gives None.

## Metadata and shared bounds

Schema `native-tls-first-failure-exception-metadata-6970-v1`, scope `first_truthy_failure_latch_reason_metadata_only`. Capture states EXCEPTION_METADATA/NON_EXCEPTION_REASON/CAPTURE_REFUSED. Root index0 or None. Preserve actual cause/context presence and suppression separately; identity reuse/cycles use bounded table references.

At most4 exception nodes,64 total observed traceback-next steps and12 retained frames across all nodes. The whole self-inclusive sorted compact ensure_ascii=True/allow_nan=False JSON is at most8192 bytes without newline. Self-inclusive byte accounting converges within at most32 iterations; otherwise use the bounded refusal fallback. Retention prioritizes the primary traceback tail only when actually reached; an incomplete walk cannot claim the innermost frame or exact omitted total. Cycle/truncation/omission labels are explicit. No invented full-chain/full-stack digest or total.

Each node may retain bounded actual class/module labels (128 UTF8 bytes each), strict integer errno or None, an actual numeric filename text (ASCII digits up to32, original str/bytes type labelled) or None with honest omission, traceback presence, bounded frames and cause/context references. Reject boolean/nested/nonfinite scalar substitutes. Frames contain only actual code.co_filename (up to192 UTF8 bytes), code.co_name (up to96), tb.tb_lineno and tb.tb_lasti. Filename/code labels are observations, not loaded-module/source-after-closure attestation or process/task/ownership proof.

If bytes overflow, honestly omit/clip labels and remove retained frames with truncation labels, remeasure, then use a bounded CAPTURE_REFUSED fallback. Explicit flags remainFalse for proc/source reads, locals/args inspection, time samples, process control, original process/task/ownership/producer/kernel cause and loaded-code/runtime attestation. Preserve the existing8 numeric-row/event and16KiB cached-stale diagnostic limits; exception code frames are a separate metadata schema and contain no process rows.

## Seven hosted synthetic cases

API `hosted_first_failure_metadata_controls()` takes no live Guard/process argument. Use isolated Guard.__new__ state without initialization, files, proc, processes or clock patching.

1. Declared raised FileNotFoundError errno2/numeric filename2949; actual traceback exception line, never current frame line. Clearly synthetic, no syscall claim.
2. First string-only unavailable; empty first string followed by a genuine nonempty latch preserves old behavior.
3. First exception remains immutable under later cleanup errors; original string-conversion count and returned ResourceFailure remain unchanged.
4. Explicit cause/context, suppression, shared identities and cycles are represented within bounds.
5. Deep synthetic Python traceback and pure bounded-encoder fixtures exercise64/12/8192 truncation, with no invented omitted totals or innermost claim.
6. Malformed errno/filename or diagnostic-refusal fixtures preserve the original latch/return and copy no nested objects.
7. Pure main-only export/default-child no-key and bounded minimal FAIL retention. Exercise actual relevant pure export/encoder paths, not a mirrored test-only implementation.

Freeze the new report wire: receipt key `first_failure_metadata_controls`; API `hosted_first_failure_metadata_controls()`; schema `native-tls-first-failure-metadata-controls-6970-v1`; result `PASS_FIRST_FAILURE_METADATA_CONTROLS_ONLY` or `FAIL_FIRST_FAILURE_METADATA_CONTROLS_ONLY`; completed strict integer7 and failures strict integer0 for PASS. Exact ordered case names: `raised-oserror-traceback`, `first-string-and-empty-latch`, `first-exception-immutable`, `cause-context-cycle-bounds`, `traceback-and-byte-bounds`, `malformed-metadata-preserves-latch`, `main-only-export-default-wire`. Each case has exact name, PASS/FAIL, bounded error/observations; source tests assert the listed actual helper/latch/export properties before returning PASS.

Common flags synthetic_inputs_only, input_before_after_equal and telemetry_counters_before_after_equal areTrue. Input equality scope is original exception graph identities and typed scalar metadata; the isolated synthetic Guard's expected latch transition and the baseline string-conversion counter are asserted separately and are not claimed immutable. new_commands_or_child_epochs, actual_proc_reads_verified, process_control_execution_verified, native_execution_verified, windows98_integration_verified and tls_execution_verified areFalse. capture_bytes_charged_to_parent and decoder_bytes_charged_to_parent are strict integer0. elapsed_seconds is an actual hosted-only monotonic duration, strict finite number0..60; no zero-time runtime invention. Production exception metadata explicitly reports new_time_sample=False.

Builder augmentation requires actual_parent_command_count strict integer33 plus actual_parent_command_records_before_after_equal, actual_parent_capture_pools_before_after_equal and actual_parent_failure_before_after_equal allTrue, from fresh before/after actual parent snapshots. Compare both the existing failure string and lazy metadata slot, not just string equality. Resource report must leave512-byte headroom for this augmentation; sealer independently validates these exact report literals/order/types/flags/count/bounds.

The compact report is at most8192 bytes with newline and reserves512 bytes for actual parent augmentation. Cases explicitly return metadata-only PASS or FAIL; no control/process/native/TLS/Windows98 claim. No new capture/raw charge, command or child epoch. Builder snapshots actual command bytes/count, pools and failure before/after; validates exact seven-case order/types/result/scope/zero charge/finite elapsed and report size. Keep added builder bytes within its remaining4405-byte preload headroom; total buffer stays<=204800. Workflow adds only corresponding report-data validation and changed builder/resource preload hashes. Existing cached7, codec28, parser14 and old19 validation stay unchanged.

## Verification and one later execution

Before implementation admission, root and independent reviewer close this exact plan. Source review compares frozen ASTs/default-wire branches, first-latch/error fallbacks, graph/step/frame/byte accounting, copied-data types and no I/O/timer side effects. Read complete source files with held/named identity and SHA; verify unchanged source32 path set and every preload limit/pin; parse all changed and embedded ASTs/YAML and run git diff --check.

Local free space is below the unchanged20GiB admission floor. No local helpers/controls/compiler/VM execution, including extracted functions. Source-only assertions do not claim runtime RED/GREEN. A later exact committed/pushed source and independent source review must precede exactly one registered-carrier hosted dispatch. That run must re-execute old19, cached7, codec28, parser14 and new synthetic7, and retain its own production failure or compiler proof under unchanged caps. Observation timeouts never justify duplicate dispatch.

Canonical/main integration belongs163f, native/private media/install-ISO belongsFADA, and sole official m98 publication belongsc957. Windows98 remains the product OS; ShizukuDOS replaces MS-DOS and Kernel32/Kernel64 are its backends. Source/diagnostic success is distinct from native PE/TLS/apps/Windows98/installer/final ISO. The full goal remains active.
