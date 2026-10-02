# Referenced process and thread query compatibility slice

User-approved parallel Windows 98 integration work, isolated from other chats
at `/root/Win98-Modern-nt-times-c957-20261002`, base `9ab307a7`.
Actual Windows 98 retains VMM/USER/GDI/Explorer ownership. This is an UP
Kernel64/Win64 component; no AP scheduling, private VM, NAS or ISO action.

## Contract and source findings

GetProcessTimes, GetThreadTimes, QueryProcessCycleTime, QueryThreadCycleTime,
GetProcessHandleCount and IsWow64Process currently reach private K32 queries
1/2/3 without query-right enforcement. Raw handle lookup does not pin objects.
Process time reads dead counters before a separately guarded live-thread sum,
allowing a departing thread's contribution to disappear between those reads.
These are independently reviewed source findings. Original-production RED
confirmed the rights and departing-thread snapshot failures; final producer
and component evidence is recorded in the accompanying status checkpoint.

Each modern getter permits QUERY_INFORMATION or QUERY_LIMITED_INFORMATION
independently for its object type. Keep the existing 40-byte times and
24-byte process-info wire formats, accounting math and live-thread membership.
Add the exact thread limited-query constant 0x0800; process limited-query
0x1000 already exists. Use ipc_ref_handle and alternative-bit checks, not
ipc_ref_process's conjunctive access test.

## Implementation and acceptance sequence

1. Write dedicated host contracts before production edits. Execute real
   selected query/helper/wrapper/reference/detach/free bodies and complete
   process/object/TCB schemas, with explicit host platform adapters. Preserve
   identical RED/GREEN test bytes and meaningful baseline failures.
2. Inject a modeled departure specifically at unguarded live_threads entry,
   using real thread_account_exit and queue removal plus modeled ZOMBIE
   publication. A generic first-IRQ hook could falsely approve a ref-only fix.
   Keep native aggregation math intact and describe the boundary adapter.
3. Hold a reference through selected class-1/2/3 snapshots. Check either query
   right. Under one outer IRQ guard, verify target identity and capture all
   dead/live counters or process metadata. Preserve nested guard state and
   retained exited thread caches/process storage. Verify the referenced object
   and attached TCB point to each other before reading live thread fields.
   Balance references on every
   status and copy path; copy snapshots after releasing the object guard.
4. Preserve class 12's prior access policy while allowing its shared thread
   snapshot helper to hold a reference. Keep required-length, oversized-buffer,
   return-length fault and status behavior of put_out unchanged.
5. For the selected time queries, prepare the private boot-epoch candidate
   outside their protected object snapshots,
   because filetime_now may issue a WALLTIME hypercall. Guard publication and
   distinguish initialized state from epoch zero. Preserve unsigned arithmetic
   and the existing clock source rather than introducing a clock-policy change.
6. Close the class-3 affinity dependency: SetProcessAffinityMask currently
   validates via a query and omits SET enforcement. Give it a separate private
   K32S_PROCESS_AFFINITY class 14 with an exact eight-byte mask. Require a held
   SET_INFORMATION process reference and active identity under IRQ exclusion.
   Support only mask 1, the existing immutable CPU0 execution policy; other
   masks are INVALID_PARAMETER. This idempotent operation adds no policy cache
   or AP admission. Reject terminated, teardown or exit_owner targets, with
   process/object identity and used-state checked in the same guard.
   GetProcessAffinityMask
   must validate its target through the checked class-3 query, accept either
   query right, reject null outputs and report the actual fixed mask 1/1.
7. Cover independent rights, insufficient rights, tags/types/width, buffers,
   reference balance, late handle close, cached exited threads and exact host
   slot reuse. Preserve real scheduler/queue policy. A fresh guest append must
   cover all six getters plus the affinity pair and retained natural child
   totals; wait for both child process and primary thread before final totals.
8. Independently review source/tests, run frozen GCC and Clang sanitizer
   contracts and real translation-unit compiles, then fresh component compiler
   closure, kernels, selected DLLs/probes and one bounded UP guest. Rebuild the
   frontend and consumer together for the added private setter. Commit only
   reviewed public source/tests/docs and deliver a source-only peer patch.

Candidate production ownership: kernel64/ipc.h and sysk32_proc.c;
win64/include/nt.h; kernel32/k32_steam_state.c and k32_misc.c. The existing
priority host runner may need extraction-adapter updates, without changing its
assertions. No proc.c, objects.c, sched.c, main.c, stack or AP-start edits.

The deployed website remains complete. Full runtime/modern-app/native Windows,
VMM/PMA, SMP, installer and final ISO acceptance remain separate. Original
PMA361 and diagnostic failures remain retained and unresolved.

This selected query-right contract does not close every caller of class 3.
GetProcessMitigationPolicy and K32GetMappedFileNameW require full QUERY under
Microsoft contracts; their stricter wrapper checks remain separate work.
Legacy memory/settings/module-by-PID queries and other setter rights are also
outside this slice. Do not claim complete process API access compatibility.
The unchanged system-process-information path can still initialize this epoch
under an inherited outer IRQ guard. That prior caller behavior is outside the
selected time-query tests; no global hypercall-outside-IRQ guarantee is claimed.

Primary contracts: [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes),
[GetThreadTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadtimes),
[QueryProcessCycleTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-queryprocesscycletime),
[QueryThreadCycleTime](https://learn.microsoft.com/en-us/windows/win32/api/realtimeapiset/nf-realtimeapiset-querythreadcycletime),
[GetProcessHandleCount](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesshandlecount),
[IsWow64Process](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64process),
[GetProcessAffinityMask](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprocessaffinitymask),
[SetProcessAffinityMask](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessaffinitymask).
