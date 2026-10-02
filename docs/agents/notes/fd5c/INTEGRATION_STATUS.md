# Integration status — fd5c

Baseline: `a648e9b`; branch `codex/pma-integration-fd5c-20261002`.
Reviewed source integration is implemented; aggregate compile, focused scheduler
and actual merged runtime component validation passed.
Actual Windows98/ShizukuDOS/PMA product acceptance is not complete. This is the
fd5c chat's integration record; reconcile canonical163f documents separately.

| Work | State | Evidence |
|---|---|---|
| Three-domain audit | complete read-only | agent findings; current source inspected |
| Channel geometry/pool access | implemented, reviewed, tested | `7252e3e`, 81 added checks and real ELF32 overflow regression |
| Consistent message snapshot | implemented, reviewed, tested | `c6c6577`, CRC-collision RED/GREEN; full GCC3,665,554, ASan/UBSan and TSan3,665,540 checks each;6,000 independent frame verdicts |
| Pending doorbell WAIT | implemented, reviewed, tested | `af06f0e`, actual dispatcher607 checks/compiler |
| Legacy text bounds/CP437/cursor/cache | implemented, reviewed, tested | `149dec3`+font receipt`cded260`,329,657 checks/mode; existing CSMWrap controls pass |
| NTW64 stale handles | implemented, reviewed, tested | `8c51a72`,2,162,732 checks/compiler; strict real i486 Windows object compile |
| Native lock/NT spin helpers | peer fixes reviewed/imported/tested | `e06433b`+`ba584be`+`3c48a0e`,40,000 GCC/ASan and2,000 TSan publications;11 commands;3 receipt mutation cases |
| GOP selection/restoration | peer source reviewed/imported/tested | `4783101`,966 checks/compiler |
| AUTO fatal-display caller | implemented, reviewed, tested | `402f2cb`,180 checks each GCC/Clang/ClangASan; actual loader source, fresh payload/EFI compile |
| Framebuffer bounds/clip/reserved aliases | peer fixes reviewed/imported/tested | `e430bb9`+`6b0e8cc`+`cadaa4a`+`be337fb`,63+156,579 checks/compiler,20 project inputs pinned |
| Kernel32 first-runnable ownership | peer source reviewed/imported/tested | `4b8c53c`,17 actual-source checks/compiler; peer guest evidence retains its own scope |
| VxD admission/epoch/reply lifetime | peer source+combined correction reviewed/tested | `afef8ee`+`f9a7b83`; copied-header geometry separated from mapped-ring validation; actual production build and20 host tests PASS |
| VxD host receipt dependency closure | implemented, reviewed, tested | `04fb9df`,all manifest inputs plus exact parsed manifest identity;7 mutation/control tests, final50-input receipt |
| Supervisor compile source closure | peer source reviewed/imported/tested | `a409351`,5 actual receipt-control tests with mocked compiler boundary |
| Cross-chat cooperation | reciprocal review and tested code exchange | c957/163f/fada plus shared6970 handoff read; no peer source/index mutated |
| Combined native host runner | passed |7 cases×GCC/ClangASan,14 executions,362,215 checks/compiler |
| Linked Windows PE32 client regression | final passed | actual NTW32.DLL/NTW64RUN.EXE code;90,903 checks,10 expectations,216 slots; VMM/Kernel64 callbacks modeled |
| Wrapper source capability contracts | reviewed/imported/validated | corrected timer/work semantics `9aae558`;snapshot-safe receipt `6938618`;78 validator/control tests;120families/56frontend APIs/17backend examples; no runtime-positive claims |
| PMA event/wait backend | reviewed/imported/host-tested | `10e0bb5`;service3429 checks each GCC/ClangASan;ring37764 GCC/37716 ASan/37716 TSan;2000 concurrent exchanges/mode |
| Kernel64 priority/quantum/aging | reviewed/imported/focused guest passed | `7b8efdc`;real UP scheduler,CPU0 affinity;KVM11/11 andTCG11/11;peer integrated failures remain separately recorded |
| Interrupted observation fixture | reviewed/imported/native-tested | `a9e5816` sampler-only IRQ guard;current KVM11/11 andTCG11/11;original sampler failure retained |
| Kernel32 finite deadlines | reviewed/imported/compiled | `bf13471`+`eaefbf5`;eight source pins match actual hosted RED22/76 failures and GREEN76 GCC/76 ASan; final i486 link PASS |
| Guest result admission controls | reviewed/imported/tested | `4e66b72` complete kernel closure;13 modeled controls PASS;`9d402b0` rejects reused bridge outputs/abnormal exits |
| Four kernel build profiles | final combined compile passed |211 pinned inputs; actual i486 andx86-64 normal/standalone images, no unresolved symbols |
| Actual Supervisor payload/EFI loader | final source-bound compile passed |105 stable inputs,`PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN`;no native Windows execution claim |
| Own fresh public Win64 runtime | actual build/source closure passed |831 source inputs,23,183,907-byte archive;fresh build receipt/source membership/archive matched before/after guest |
| Actual merged PMA/runtime component | passed38/38 |real KVM guest199.06s/QEMUstatus1;PMA16/16,W64loopback48/48,151apps exit0/fault0;no Windows98/VMM/Supervisor/SMP execution |
| Actual Windows98 + ShizukuDOS/PMA | pending | host/standalone tests do not establish it |

Each agent records scope, files, decisions, dependencies, blockers, tests,
remaining work and final commit identity under status/. Historical reports and
receipts remain untouched.

## Reciprocal findings and remaining gates

c957 acknowledged/fixed our ticket allocation ABA and receipt closure findings,
reviewed/imported our IPC/doorbell/video/handle/snapshot changes, and reproduced
them in its own integration tree. Its new framebuffer bound rejects all physical
ranges at/above the first private64-GiB arena, including later kernel aliases.
The wrapper inventory timer/work descriptions were corrected from actual
provider code before import. These reports are source contracts, not native API
acceptance.

The PMA service peer addressed process-exit ordering, corrupt-head quarantine,
finite identity budgets and backend shutdown cancellation/draining. We reviewed
the exact committed source and imported it, then passed fresh host service/ring
tests. It admits8 distinct PIDs/32TIDs per epoch; exhaustion is a real error.
Its5000-ms shutdown eventually exits the backend domain if a peer never drains.
Supervisor DOMAIN_STATE exposes death, but the current Windows VxD does not query
it and does not translate an abandoned PMA WAIT into a peer-death completion.
That end-to-end lifecycle gate remains open.

The final root KVM/TCG focused and merged runtime runs passed. Separately, c957 retained
a FAIL from an interrupted sampler observation and163f retained an integrated
refresh test FAIL (first low-worker body observation98 ticks/useful loops0).
Our read-only independent timing review distinguishes these failures and asks
the canonical owner for dispatch/residence/tick evidence before a policy change.
These failed records are not erased or converted into passing admission.
See shared `REVIEW-fd5c-163f-PMA-TIMING-FAIL.md` and FD5C_VALIDATION.md.

c957's later sampler-corrected full run failed a separate Win64 winmm.dll load
at an occupied preferred range. Root's own fresh831-source runtime passes that
program and all151 apps, but this does not close the random-placement/collision
case. Independent root reviewers relayed exact PE/archive/ASLR findings and
empty-directory DLL permission limits to its owner. A stable tested loader
successor remains pending. The capability receipt parse/hash successor was
imported as`6938618`, byte-identical to peer`4e6beea`;78tests and a fresh CLI
receipt passed. Current report remains a source inventory.

Independent final root reviewer rehashed all211kernel/105Supervisor/831runtime
inputs, artifacts and raw serial/receipt hashes, and reconfirmed38PASS gates,
16PMA,48W64 and151app outcomes. Component source/evidence handoff approved;
the native product gates below remain open.

Unimplemented or unverified architecture gates include the actual DOS executor,
ShizukuDOS→WIN.COM→VMM desktop transition, real VMM event/completion frontend,
per-domain SYSCALL/SYSRET/KERNEL_GS_BASE MSR isolation, integrated AP/SMP,
mode13h/VBE/direct VGA context ownership, and modern driver/x64 GUI acceptance.
Windows98 retains the actual VMM/USER/GDI/shell and Windows scheduling authority.
No release, private media, ISO publication or production deployment occurred.
