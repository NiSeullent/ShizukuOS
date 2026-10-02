# NT dispatcher host closure, 163f

Isolated branch `codex/nt-dispatch-host-163f-20261002`, base
`c97842929ab121bff3d5410e5747f268b164f0f4`, worktree
`/root/Win98-Modern-nt-dispatch-host-163f-20261002`.
[Scoped plan](../plans/nt-dispatch-host-163f.md). This is a test-only integration
repair; no production, peer, canonical or global configuration change, commit,
runtime build or guest execution occurred.

The Python extractor now includes the exact unchanged `sched_owner_context()`
body immediately after `bsp_scheduler_owner()`. The existing fixture already
published both global `current` and `runqueues.cpu[0].current`; reset is unchanged.
The compatibility mirror remains available to the actual reclaim bodies.

New C controls deliberately diverge that mirror in an isolated control group.
The actual current getter selects CPU0's record, and the actual NT current-thread
handle query returns CPU0 pid100/tid204 rather than the mirror's pid101/tid208.
A null CPU0 current, a mapped offline CPU1 with a nonnull fixture record, and an
unmapped actual CPUID all return null without BSP fallback. At outer IRQ depths0
and1, getter calls preserve IRQ depth and the complete queue bytes. Only topology
publication and privileged/handle/user-copy/clock/blocking boundaries remain host
adapters; no AP is admitted or executed.

## Preserved RED

The original canonical GCC/Clang compile failure remains historical at
`build/integrated-nt-priority-c978429/result.json`, SHA
`acc2f449f19df9fd267b3b2e15844465bcd084be54b66fd6e81018f1aa580c87`.
Its273 source/schema inputs reconcile to this worktree before repair, including
original C `4aca58c15e276b0b79434f3a0be3fdbf52915d4b39d1543aa82967e1de1974c8`
and Python `8d288f538a49d01bc2b92cadaa6e134e2dba0fff52b7df5219e053f77a0cda79`.

The captured original helper reproduces precisely the missing-owner-helper
compile errors under both compilers. Own fresh RED validation:
`build/nt-dispatch-host-red-1/validation.json`, SHA
`4563c4f328bbb1e044b2f16693f56a0293342c83fdf044942433a24e145bab39`.
Both actual compiler exits are1; input/artifact/tool bytes remain stable.

## Fresh host and eight-unit evidence

`build/nt-dispatch-host-green-2/validation.json`, SHA
`4abc9bce969c420ec8871f7c76a5de6dd33b971eac9a2b034908687f7a987902`,
is terminal `PASS_ACTUAL_HOST_AND_8_UNITS`. The ordinary helper receipt SHA is
`83f462dcb2f0fe4f91a1b52ba2ee63ac85c9aaf1339876f9f2eaa957079c47ae`.
GCC and Clang ASAN/UBSAN each retain all11,221 existing checks with0 failures,
plus59 new current-context checks with0 failures:11,280 total each. The older
4,456 thread baseline and6,764 process cases retain their separate summaries.
The actual frozen `proc`, `objects`, `ipc_proc`, `sysk32_proc`, `sysx`,
`k32_core`, `k32_misc` and `k32_procinfo` translation units all compile; no runtime
is linked or rebuilt.

Exact helper bytes are captured before execution, and273 local C/header/schema
inputs are snapshotted before compilers. Ten actual compiler dependency groups
capture project dependencies plus283 distinct external compiler/system headers
before compilation; no SDK tree is copied. GCC/Clang/MinGW and executed compiler
subtools remain SHA-stable. The2,664 nonowned tracked source files remain equal
between RED and GREEN and at final reconciliation.

The helper's existing30-second subprocess limit and original summary/failure
gates remain unchanged. Additional subprocesses use a60-second ceiling. Lane
output remains below48MiB including the final archive.

## Copied-fixture runtime control

`build/nt-dispatch-host-mirror-control-3/validation.json`, SHA
`7ae71d3b843d24370d709eaa85300a82141d98cece2dba1acd3112b64c47d8f6`,
is `PASS_EXPECTED_COPIED_MIRROR_GETTER_RED`. Only a temporary copied host fixture
receives the actual historical getter from `0fffd07` that returns the BSP mirror.
Actual execution exits1: all11,221 original cases still pass, while six of the59
new ownership checks fail. This is an adverse test control, not a shipped-source
or native scheduler failure; production source bytes are never modified.

## Frozen test pins and remaining scope

- C: `9cfe1d9834b621db96dc8dc6c42871080ef191fc0ff747a16b057493351921e8`.
- Python: `974bce008c4b71d8ee12cde32d2096d5aafe6ac8f4326c88562bc6e45c5660b8`.

The four owned paths and complete source/evidence map are supplied in the ignored
final handoff. No commit is made before independent review. Compiler/project and
external header inputs are bound; this does not claim a complete host dynamic
runtime-library closure. Native UP, hardware context switching, AP scheduling,
full SMP, Supervisor/Windows 98 and final ISO acceptance remain open.
