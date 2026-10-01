# fd5c integrated evidence and remaining acceptance

Worktree: `/root/Win98-Modern-pma-integration-fd5c-20261002`.
Branch: `codex/pma-integration-fd5c-20261002`; baseline `a648e9b`.
This record distinguishes executed host/component tests, reviewed peer evidence
and product acceptance. Windows98 remains the actual product OS/VMM/USER/GDI.

## Executed root validation

| Source path / behavior | Executed evidence | Local artifacts |
|---|---|---|
| Shared IPC geometry, ownership and consistent256-byte receive snapshot | GCC3,665,554;ClangASan/UBSan3,665,540;ClangTSan3,665,540;freestanding32/64/MinGW;6,000C/Python frames | `build/fd5c-abi-snapshot-full.log`, `build/fd5c-abi/snapshot/` |
| Existing Supervisor domain WAIT/ACK, BIOS text/CP437/cursor plus native host controls |7cases×GCC/ClangASan,all14executions PASS,362,215checks/compiler | `build/fd5c-native-combined/result.json` |
| NTW64 record generation retirement |2,162,732checks each GCC/ClangASan;strict real MinGW i486 object compile | `build/fd5c-handles/`, `build/fd5c-abi/handles-green.log` |
| Actual linked NTW32.DLL/NTW64RUN.EXE PE32 client conversation |90,903checks;all10expectations;216slots;VMM/Supervisor/Kernel64 callbacks modeled | `build/fd5c-w64-final-e2e.log`, `platform/abi32/build/w64/w64-results.json` |
| Native ticket gate/NTdriver spin helpers |40,000GCC/ASan publications,2,000TSan,11commands;real i486 compile;3receipt mutation controls | `build/fd5c-sync-final.log`, `build/fd5c-sync-receipt-final.log` |
| Framebuffer aperture/reserved alias bounds and clipping |63handoff+156,579clip checks each GCC/ClangASan;20source inputs pinned | `build/fd5c-display-final-{gcc,clang}/` |
| GOP/EDID selection and restoration |966checks each GCC/ClangASan | `build/fd5c-uefi-*` |
| Fatal GOP selection through actual AUTO loader caller |15scenarios/180checks each GCC/Clang/ClangASan;unwanted CSM fallback reproduced before fix | `build/pma-fd5c-gop-auto/` |
| Actual VxD build/host bridge/wire/concurrency/receipt controls |20tests PASS;50input hashes;manifest parsed/hash identity and both external ABI headers stable | `build/fd5c-vxd-final/host-tests.json`, `build/fd5c-vxd-final-{build,test}.log` |
| Actual Supervisor compile receipt controls |5mutation tests PASS;compiler boundary modeled only for these fixtures | `build/fd5c-compile-source-binding.log` |
| Wrapper capability source contracts/receipt closure |78tests PASS(original67+11receipt controls);120families/56frontend APIs/17backend examples;behavior_tests_run:false | `build/fd5c-capabilities-current/capabilities.json`, `build/fd5c-capabilities-receipt-combined.log` |
| PMA event/wait service |3,429checks each GCC/ClangASan;i486/x64 layouts | `build/fd5c-pma-service/result.json` |
| PMA actual shared-ring transport |37,764GCC/37,716ASan/37,716TSan;2,000threaded WAIT/SIGNAL exchanges/mode;4CRC-valid Python replies | `build/shizukudos/pma-bridge/transport-result.json`, `build/fd5c-pma-transport.log` |
| Four actual normal/standalone kernel profiles |i486 andx86-64 compile/link PASS;211complete source inputs stable;no unresolved symbols | `build/shizukudos/kernels-build-result.json`, `build/fd5c-kbuild-sampler-final.log` |
| Actual Supervisor payload and EFI loader |PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN;105inputs stable | `build/fd5c-supervisor-scheduler-current/result.json`, `.log` |
| Focused real UP Kernel64 scheduler/PIT/context switches after sampler guard |KVM11/11 andTCG11/11;computed exit marker/QEMU status1;211complete kernel inputs pinned | `build/fd5c-k64-sampler-current-{kvm,tcg}/result.json` |
| Focused guest provenance controls |13controls PASS using real successful serial and private copied artifacts;QEMU boundary modeled | `build/fd5c-k64-provenance-final/`, `.log` |
| Bridge runtime outcome controls |5test groups PASS;abnormal exits/timeout/reused output/failed launch refused;QEMU boundary modeled | `build/fd5c-k64-bridge-controls-complete/`, `.log` |
| Own fresh Win64 runtime archive |actual build exit0;831source inputs/current membership match;archive23,183,907bytes | `build/shizukudos/win64/build-result.json`, `build/fd5c-win64-runtime-build.log` |
| Actual combined Kernel64/PMA/runtime component |38/38checks,PMA16/16,W6448/48,all151apps exit0/fault0;199.06s/QEMUstatus1;Bochs fixtureadapter/noNIC | `build/fd5c-k64-pma-merged-current/{result.json,serial.log}` |
| External runtime build provenance admission |before/after exact831-source closure,archive hash and same-byte build receipt unchanged;guest archive/38PASS/151apps match | `build/fd5c-runtime-provenance-{before,after}.json` |

The final kernel receipt names build revision `a9e5816`; subsequent document
commits do not modify its compiled source closure. Individual receipts retain
their original timestamps/revisions; no history was relabeled as a later build.
Final source hashes and artifacts must continue matching the corresponding
receipt rather than only its Git metadata.
Earlier pre-sampler focused runs remain under`build/fd5c-k64-scheduler-*`; their
matching prior binaries/receipt were preserved in`build/fd5c-kernels-before-sampler/`.
The current Supervisor compile105-source closure is unchanged by the sampler
test patch; this is compile evidence with no Supervisor guest execution.

Fresh runtime archive SHA256:
`ef311c5580779fa8554ef1e5491172a8990083bc242dda48ba78909fbea7e40a`.
Final Kernel64S SHA256:
`0ed39a28a1207a2f10ec22930d51ee33984edaa842d5a3bcf71ad004741fd608`.
Actual merged guest receipt SHA256:
`44abe4baca6c54c2a8e6b0f1af65582d5af1aae20294f6ac1df016b8a33fa594`.

## Reviewed peer evidence and observed integration failures

The Kernel32 deadline production repair and fixtures are imports of163f
`f617515`/`d1af3c2`, following6970's reviewed handoff. All eight source pins
match actual hosted RED22/76failures and GREEN76GCC/76ClangASan checks. Root's
final real i486 build/link includes that repair. The earlier6970 local guarded
runner outcome was BLOCKED_NOT_RUN; no execution is inferred from it.

c957's preserved final guest failed an interrupted sampler observation:
raw_gap97,service_gaps32/65,actual ready_wait32.163f's different integrated guest
failed the policy refresh/useful-work test:low_first98,low_loops0. Our independent
read-only review requires refresh-specific dispatch/residence/tick evidence
before a scheduler policy change. Root's focused PASS results do not erase
either failed record or prove the full integrated workload is accepted.
Sampler-only IRQ guard86f52c1 was independently reviewed/imported as`a9e5816`;
current root focused/full guests pass that fixture. Canonical owner retains the
separate refresh failure implementation lane and the40-tick bound.
See `/srv/shizukudos-session-coordination/REVIEW-fd5c-163f-PMA-TIMING-FAIL.md`.

The later c957 sampler-corrected full guest failed a separate T_GUI_STATUS
winmm.dll preferred-address conflict. Root's fresh runtime passes that app and
all151, but a passing random placement does not close the reproduced collision.
Independent PE/archive/source diagnosis and precise relocation-directory limits
were handed to c957's loader owner, without peer code/index changes:
`REVIEW-fd5c-c957-GUI-STATUS-WINMM.md` and
`REVIEW-fd5c-c957-EMPTY-DLL-RELOCATION.md` in the shared directory. Native Windows
and this loader corner case remain open. Capability receipt race successor is
now integrated as`6938618`, equivalent to peer`4e6beea`;78tests validate source
contracts and snapshot-safe receipt decisions. Root captured the exact reviewed
working-source pair by SHA before peer Git publication, checked unchanged second
reads, then committed the identical frozen files using the published peer unit's
author/message. No peer working source/index was changed or fabricated commit
claimed. Its fresh CLI receipt is separate from historical old-validator output.

## Receipt controls and invocation errors

All tests use actual production source where stated. Mocked runtime/compiler
boundaries are explicitly named; capability inventories are source contracts.
Initial/final hashes catch observed persistent drift, not edits reverted between
samples or malicious build-tool behavior.

An attempted repeat Supervisor compile refused its already-existing output
directory before compiling (`build/fd5c-supervisor-final.log`,exit1). The later
fresh105-input compile above passed; the refusal is not compile-success evidence.
The first bridge-control invocation omitted required`--out` and returned2;
the corrected fresh invocation above passed. Historical artifacts were retained.
The first external post-guest check used strict UTF8 for legacy ANSI serial and
stopped on a decoding error. Corrected lossless Latin1 decoding then verified
the unchanged raw serial hash and all151 ASCII app outcome markers; no guest
rerun or result rewrite occurred.

## Remaining product gates

Actual ShizukuDOS→WIN.COM→Windows98VMM/USER/GDI/Explorer remains unverified.
Required follow-ups include a real DOS execution serialization gateway,
authoritative Windows process/thread identities and VMM wait/completion/death
frontend, integrated AP/SMP and syscall MSR domain isolation, VGA contexts/
mode13h/VBE, and actual modern hardware/driver/x64GUI application acceptance.

PMA backend has finite8distinctPID/32TID identity capacity per epoch. Persistent
full TX can terminate after the bounded5,000-ms drain; Supervisor reports domain
death but current Windows frontend does not consume it for abandoned waits.
NTW64 handles guarantee generation retirement within one serialized loaded
wrapper instance, not reload/restart/concurrent-call lifetimes.

No Microsoft media, installed guest image, ISO, release or deployment was
published or changed. No global client configuration was changed.

## Independent final evidence review

Root core_audit independently rehashed complete current kernel211/Supervisor105/
runtime831 inventories, all four kernelBIN/ELF images and standalone stubs,
native compile artifacts, public archive and raw source/receipt/serial pins.
All maps and identities match. It independently recounted38PASS gates,16PMA,
48W64,151successful ordinary app records, oneSHZEXIT0 and no executing kernel
assertion FAIL. Current focused KVM/TCG11PASS receipts also match their binaries
and sources. Root display_audit approved the exact receipt repair bytes and read
the actual78-test combined log. These reviewers executed no builds/tests/VMs.
Final documentation preserves both external corner cases and Windows acceptance
limits; document-only updates do not relabel historical compiled receipts.
