# Referenced time, process-info and affinity component checkpoint

Isolated ROOT worktree `/root/Win98-Modern-nt-times-c957-20261002` is based
on reviewed `9ab307a7`. That process-priority source has also been adopted
by the canonical owner: at canonical `dce6f3cb`, ROOT independently checked
seven relevant production/test blobs against the previous isolated tree.
No canonical checkout or other chat's owned files were changed by ROOT.

The project remains actual Windows 98 with VMM/USER/GDI/Explorer ownership,
on replacement ShizukuDOS. This checkpoint covers an UP Kernel64/Win64
component. The website is deployed and publicly verified. Native cold boot,
modern applications, SMP, installer and final ISO acceptance remain open.

## Reviewed behavior

Private K32 queries 1/2/3 now require either QUERY_INFORMATION or
QUERY_LIMITED_INFORMATION for the correct object type. Each operation holds
an object reference through its protected snapshot. A process snapshot
captures dead-thread accounting and the unchanged live-thread sum under
one outer IRQ guard, preventing a modeled departure from losing its totals.
Thread snapshots verify the reciprocal object/TCB identity; detached retained
threads use the existing cached counters. References are balanced before
returning or copying results. The 40-byte time and 24-byte process-info
formats, accounting arithmetic and live-thread membership are preserved.

The six public getters are GetProcessTimes, GetThreadTimes,
QueryProcessCycleTime, QueryThreadCycleTime, GetProcessHandleCount and
IsWow64Process. The added thread limited-query constant is 0x0800.
Legacy private thread-settings class 12 retains its prior access policy while
sharing the referenced snapshot helper; this does not harden every query.

Selected time-query callers prepare their boot-epoch candidate after leaving
their own object snapshot guard. Publication uses a separate initialized
flag, allowing a valid zero epoch, and preserves unsigned clock arithmetic.
The legacy system-process-information caller can still inherit an outer
IRQ guard when initializing the same epoch. No global guarantee that WALLTIME
hypercalls occur outside IRQ exclusion is claimed.

GetProcessAffinityMask now validates its process via the checked class-3
query, rejects null outputs with ERROR_INVALID_PARAMETER, and reports the
actual fixed mask 1/1. SetProcessAffinityMask uses a separate private setter
class 14 with an exact eight-byte mask. It holds a SET_INFORMATION reference
and verifies active process/object identity under IRQ exclusion. Only mask 1
is accepted as the existing immutable CPU0 policy; no queue or cached policy
is changed. Other masks are refused. Terminated, teardown and exit-owner
targets are refused. Frontend and consumer must be rebuilt together.

GetProcessMitigationPolicy and K32GetMappedFileNameW need stricter full-query
wrapper enforcement in separate work. Other legacy setters, memory/settings
queries and module-by-PID operations are outside this slice. IRQ exclusion
does not provide SMP lifetime safety for objects, handles or process tables.

## Frozen host evidence and producer correction

Original-production RED v3 is preserved at
`build/nt-time-host-red-v3/result.json`, SHA
`247781bedd04ce8600b484c61b32ce00e00c4a394664732b29b43a076440b983`.
Both GCC O2 and Clang ASan/UBSan recorded 938 checks with 80 failures;
the zero-epoch control recorded 23/1 and wrap control 23/0.
Original GREEN v1, SHA
`f7c397ec973462ebfb0060b7b6242f299152ac69aec986d0b6256f86e30af708`,
recorded 1292/0 normal and 34/0 for each clock control under both compilers,
plus seven real translation-unit compiles. These actual commands completed
normally. Independent review found a producer admission gap: a timed-out
leader could exit zero during cleanup and be admitted; an ignoring descendant
could also escape cleanup after that leader exited. Historical outputs and
their frozen producer preimages remain unchanged.

Only the Python producer was corrected. Timeout, interruption and cleanup
failure independently prevent admission, irrespective of the leader's exit
code. Bounded cleanup sends TERM and then KILL to its exact owned group,
including after leader exit. C assertion SHA remains
`ca4167ce685e85e84d267363bd385f1e83dec4e00256f3bde2fe00068cefa7d2`;
corrected producer SHA is
`ea49f6c5b367b6b6b9c26204e2225562a7b9356c7f38da6c7ff736fb79c83cf2`.

The independently reviewed actual producer negative control is PASS,
`build/nt-time-producer-negative-v1/result.json`, SHA
`184495c1ce977301109641a78d9a76a69fdf8e2cfbd020be2e1649263ca683cd`.
A normal zero exit is admitted. Timeout and SIGINT controls each produce a
factual leader exit zero, are refused, kill their TERM-ignoring descendant
with SIGKILL, reap it through the fixture's process-local subreaper and verify
the owned group is gone. No global process settings or unrelated jobs change.

Corrected paired RED v4 is the expected FAIL, SHA
`151d2d1c28f6d2ba1e1ea9dca34c38294f160a78149164e7e735aad006b414f9`:
both compilers repeat 938/80 normal, 23/1 zero and 23/0 wrap. Corrected
GREEN v2 is PASS, SHA
`8898f043bbd6c1f310c962f63519d16a405e3622e56be04ecb025dd004f712c6`:
both compilers record 1292/0 normal and 34/0 for each clock control, with
seven real translation units compiled. All 15 GREEN commands are admitted;
neither run times out, interrupts or reports cleanup failure. Identical final
C/Python bytes are used in both runs. The 253 source maps and respective
267/281 complete artifact maps match current and frozen inputs after rehash.
The RED clone provenance SHA is
`89a87f07384d083092d7b4cefbade6233891d713ec92a6f8c78e9b5c6fe19f1f`:
the original 253 frozen-source map was verified before cloning, and only the
cloned Python producer changes. Production baseline remains pristine 9ab.

The fixture executes 46 actual selected function bodies and complete process,
object and TCB schemas. Reference/handle close, object detach, last-reference
process free, accounting, queue removal, tickets and native cycles are real
source. IRQ/copy/clock/heap/VAD and static storage are explicit adapters.
Departure is injected specifically at an unguarded live_threads entry using
actual accounting and queue removal plus modeled ZOMBIE publication. This
detects a weak reference-only fix. Exact TCB reuse is modeled after actual
detach; the fixture does not execute the scheduler's full reaper. It does not
prove physical heap UAF, concurrent AP execution or native Windows behavior.
SET-only affinity success is tested; combined SET/query acceptance follows
the existing bit-presence reference helper and has no dedicated success row.

The existing priority regression, with only its helper-extraction adapter
updated, is PASS: GCC and Clang each 11221/0, eight actual units compiled,
256 sources and 270 artifacts. Receipt SHA
`b4586331ed4a9a5152dd5a8d83feccf52e03184af296630a71c9678ec91c7998`.
Its assertion C is byte-identical to the prior reviewed regression.

## Fresh build and guest admission

Actual compiler/header closure is PASS: 222 inventory entries, 221 actual
C dependency units, 398 source pins and 619 artifacts. Independent live/frozen
selection and header-mutation/omitted-process-C controls pass. Receipt SHA
`cd67bc79b90024222b0b9f60d30ec6818b420e365b98b80c3b52c1cdc22d68fb`.

Fresh four-kernel producer is PASS in 97.53 seconds, with 222 live/frozen
source pins, seven tools and ten copied artifacts stable, no timeout, and
six ELF images without undefined symbols. Verification SHA
`d3ebceaae478e64aa3d7f45816534cab7bd97e54c10cbdb5701fc1e48eec5ff8`;
build receipt SHA
`3fb8ce2078dbaf74bc55ad66e5c1d4a3dc91a1a7320479aef6acb10049892cde`;
source/driver ZIP SHA
`b67d301068e60045cb66fb49492adf974cf967db5c673e19283d7fc4dafa8d14`.

Fresh targeted NTDLL/Kernel32 producer is PASS in 114.15 seconds. Its actual
production-flag local dependency scans cover 17 NTDLL and 53 Kernel32 C
units; all six resource/compiler calls exit zero. The 325 source pins, 655
before/after inputs, 408 artifacts and 81 generated inputs remain stable.
Receipt SHA
`c148acbce067e95a10ad01b1222d6bb640c543fc7a915c50d827d6ec28d6c385`;
NTDLL SHA
`f20829e6aad0bfeebd872b64bac8dc58abac3070da5ef8a9cbc47e119635dd8f`;
Kernel32 SHA
`cca22bb1139b2d622366213e625fceb648a98c17afd3f38f437da393ede07740`.
These are freshly compiled local outputs. External compiler support programs,
sysroots and libraries are outside the local closure; full runtime is unbuilt.

Fresh probe production is PASS in 19.531 seconds, receipt SHA
`7714cc096283a86f42a58364a327623252d61195e138b5d2933424300a4c165b`.
Four actual local dependency scans and eight resource/compiler calls exit
zero without timeout or interruption. Its 327 sources, 743 starting inputs,
1071 before/after inputs, 12 generated inputs and 342 complete artifacts are
stable. The exact five-member archive SHA is
`9f6b80e000c6d2e011ebe0eae0d34466905c609c5023cdaf0c4e54a34215ae1c`:
two fresh DLLs, two fresh probes and only retained historical T_HELLO.
Frozen process-probe source SHA is
`9943724318323549f2c8fbeb3e8526da9e4bca320fe479cd31bd4fe0e733d2b9`.
It preserves the original 215 checks and appends 216 expected checks, including
independent query rights, refusal paths, copy bounds and the affinity pair.
It creates a suspended T_HELLO child, holds query handles before first dispatch,
resumes once, waits for both process and primary thread with fixed bounds,
and requires natural exit 7 before comparing retained final process/thread
totals. Forced termination is checked cleanup only. The existing priority
probe remains byte-identical and expects 654 checks. Neither the predicted
431 count nor host results were admitted as actual guest success before
execution; the exact successful counts below were observed in the sole guest.

One bounded actual KVM UP guest is PASS in 7.74 seconds. The fresh priority
and process probes report 654/0 and 431/0, respectively; both applications
exit zero without a fault. All 35 distinct PMA checks pass, and the sole PMA
summary reports zero failures and CPUs 1. Kernel terminal self-test count
and SHZ-EXIT are zero. QEMU exits 1 via isa-debug-exit without a timeout and
its leader is reaped. All 1493 producer/source/tool/generated/artifact input
pins remain unchanged. Receipt
`build/nt-time-c957-api-guest-v1/result.json` SHA is
`cc7b7c04d19164d7046c45f6acb9799e44acb18df1621e3298d8047ca59a2ada`;
serial SHA is
`c15fff58928161919284572bcf9b015e6cef3cd24ea2529baf0110d43e84772a`.
The positive PMA and kernel-terminal gates, exact four probe dependency
command/proof correspondence and complete producer/artifact input admission
were independently reviewed before the sole execution. This is whole success
for this small public component guest, not native Windows 98 acceptance.

## Independent review

The host author and its independent reviewer verified all corrected paired
RED/GREEN sources, artifact maps, actual logs, final assertions and producer
controls. The separate release reviewer checked the five production deltas,
guest source, all three fresh producer closures and the actual guest evaluator
before execution. ROOT independently rehashed current source/artifact maps
and all 1493 final guest input pins. Final clarified plan SHA is
`f1f25cda51d17e0d4d64635c1ed68f242f7e312dc81ea5b083084000cbd6eb51`.
Earlier approved f200bb42 and d69cefd2 plan epochs remain historical; the
successor adds the SPI clock qualification and corrects the obsolete RED-pending
sentence. No production or assertion change accompanies those doc updates.

## Coordination and retained limits

Other chats own native Windows/DOS disk/ESP construction, Supervisor AP/SMP,
K64 stack/dispatch foundations and modern application toolchains. ROOT creates
no NAS allocation, private disk or competing native VM. Native product flags
remain false. The original PMA useful-work 361 failure and diagnostic-clone
failures remain preserved and unresolved; fresh component passes cannot close
those historical runs. Only public source/tests/docs are eligible for handoff.
