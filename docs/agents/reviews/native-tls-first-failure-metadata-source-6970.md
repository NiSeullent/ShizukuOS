# Native TLS first-failure metadata — static source admission

The original production failure in actual12 retained only numeric ENOENT2949 as a ResourceFailure message. This change preserves copied, bounded metadata from the first original exception before later cleanup strings lose its class and traceback. It changes no acceptance condition and cannot recover actual12's missing historical callsite.

Baseline is7ab4860709fdb637906693fd0bc9fd3ad95f5e25. Final design is docs/agents/plans/native-tls-first-failure-exception-metadata-6970.md,11691 bytes SHA2560b48c1378a2ebbb04b8ee3186f299e10ccec3bdae33a8e26b138880351ec13f8, committed in69e5de12d8fdc3bc44ab134767d8f969a674a9f1. Historical actual12 result doc7d6ff6506c4d25507f55bbb22c454cc2f5ce4a62 remains failed scope.

## Frozen source

| File | Bytes | SHA256 |
| --- | ---: | --- |
| ntwin32/secure_transport/native_tls_resources_6970.py |186773|29c6eca4e9effd92efdf101d653be2dcbf7566915d17d34ca6b8306c40ef6999|
| ntwin32/secure_transport/build_native_tls_guarded_6970.py |204060|76212c7483e2bb505dfbcf27e58bb8d62e77f1d1f1f1d5b65e8daa275c088b4f|
| .github/workflows/native-tls-build-6970.yml |126276|c8bf5c66d1903cc9c6c5d86a28cc28e3e5a45a89003a320593ff3c7ab8aad2cc|

Root and independent source reviewer full-read resource with held/named stat9 equal. Its17 other Guard methods, including count, all32 Owned methods, imports, assignments and every old free function remain exact baseline AST. Only Guard._fail and close_receipt differ. The original failure assignment and ResourceFailure(self.failure) return AST are preserved. Removing the three main-only export branches restores the entire old close_receipt AST, preserving default child wire.

The first truthy latch captures after the original str(reason), with no additional str/repr or arbitrary exception/metaclass hook. Empty-string falsy semantics remain. Later cleanup cannot replace the saved first metadata. Intrinsic BaseException and OSError descriptors read actual traceback/cause/context/suppression and errno/numeric filename. Genuine built-in traceback/frame/code descriptors supply code filename/name and exception-time tb_lineno/tb_lasti. No frame locals, exception args, current frame position, source retrieval or live objects are retained.

Copied JSON metadata has4 exception nodes,64 aggregate observed traceback steps,12 aggregate retained frames and8192 self-inclusive bytes without newline. One shared32-attempt budget covers every canonical size computation across overflow candidates and fallback, reserving4 attempts for refusal. References represent identity reuse/cycles; incomplete walks cannot assert innermost frames, exact omitted totals or full-stack identity. Strict scalar types, intrinsic access refusals and explicit truncation preserve original latch/return. Process/task/ownership/cause/loaded-code claims remainFalse.

Source review corrected two concrete candidate gaps before this freeze: separate32-iteration candidate budgets became one aggregate budget; outer-except main failure receipt export now refreshes the saved first-error field before encoding. Earlier9cf/d068 candidates are superseded source only and were never dispatched.

The seven declared hosted fixtures exercise actual helper/latch/export paths: raised OSError traceback line, first-string/empty behavior, immutable first exception/string conversion counts, cause/context/suppression/cycles/node cap, deep64/12 and encoder byte overflow, arbitrary-hook avoidance/malformed metadata refusal, and actual pure main/default/minimal-FAIL export. Synthetic graph identities/scalars and unrelated telemetry are compared before/after; expected isolated latch and baseline conversion transitions are separately asserted. Only this explicit hosted API samples its actual start/end monotonic duration; production metadata adds no I/O, proc/source/clock, signal, wait/reap, retry or command epoch.

## Builder, workflow and fixed inputs

Root and independent source reviewer closed builder204060/76212c. Its sole3665-byte new block removes to byte-exact baseline200395/f9b843. It snapshots actual33 parent command bytes/count, capture pools, failure string and encoded lazy metadata before/after the no-argument synthetic API; validates exact seven cases, strict schema/result/count/types/scope/zero charge/finite duration and8192-byte report limit. Existing cached7, codec28, parser14 and old19 behavior is unchanged.

Workflow author's final held whole YAML pin is126276/c8bf5c66. Root separately parsed it, all7 embedded ASTs and all7 hashed physical preload buffers. Removing the2908-byte/15-statement metadata validator and reversing only builder/resource preload hashes restores byte-exact baseline123368/edb380. All steps, conditions, logging/recovery, old validation, original carrier and caps remain frozen.

Root and workflow author full-read all32 fixed source inputs:2813885 bytes; the old30 remain exactly2423052 bytes with all baseline hashes. Production20/support5 and other control drivers/GAS are unchanged. Every preload buffer remains<=204800; builder headroom740 bytes and resource headroom18027 bytes. git diff --check passes.

## Runtime boundary

These are static source findings. No repository helper, extracted function, hosted control, compiler or VM was executed locally: local free disk remains below the unchanged20GiB floor. New synthetic7 is not claimed PASS. After exact own-branch commit/push/remote full-body verification, one registered-carrier hosted run may re-execute old19, cached7, codec28, parser14 and new7, retaining its own production result. Timeouts do not authorize duplicate dispatch.

The original8MiB profile is untouched. The separate32MiB profile retains1MiB receipt,256KiB normal capture,64MiB decoder aggregate,512KiB logger,48MiB transfer and64MiB upload limits. This source admission proves no native PE/TLS execution, Windows98 integration, app compatibility or final ISO. Windows98 remains the product OS; ShizukuDOS replaces MS-DOS and Kernel32/64 are its backends. Canonical/main integration remains163f, native/private/installISO remainsFADA, and official m98 publication remainsc957. The user's full goal stays active.
