# Kernel64 shared PMM and heap serialization

Authorized isolated base: `a269fb5f91a0298453bc40abbb6c5fc2765d136e`, branch
`codex/smp-memory-sentinel-163f-20261002`. Parent owns canonical integration. Prior AP
milestone `7a6eff6793b3696da9fc812482c3e8db190b565a` and its 227-source
receipts remain immutable. This slice implements allocation metadata safety;
process page tables, scheduler AP registration, wait objects, shootdowns and
Supervisor/Windows execution remain later dependencies.

The prior memory frozen13 candidate was rejected for a reserved heap sentinel
being accepted by `kfree`. Its 1536-entry archive and all233 native receipts
remain unchanged in `/root/Win98-Modern-smp-memory-163f-20261002`. This fresh
own worktree imports those exact reviewed bytes and applies only the successor
within the same thirteen owned paths.

## Ownership and interfaces

Owned production files: `kernel64/mem.c`, new internal `mem_lock.h`,
`cpu_memory_stress.[ch]`, the existing observer comment in
`cpu_memory_owner.h`, and a narrow opt-in worker/report hook in
`cpu_bringup.c`. No `main.c`, scheduler, public kernel header, architecture,
assembly switch, PMA fixture, Supervisor or producer changes.

`shz_smp_this_cpu()` remains the actual CPUID-to-immutable-topology provider.
The map is published before INIT and AP callbacks. A physical CPU outside the
map rejects allocation/count/observer access rather than using logical CPU0.
AP callbacks run after private architecture and interrupts become ready and
outside the CPU0 scheduler, syscall and per-thread GS paths. The Core owner
confirmed that destination-stack switch completion and reap/join do not hold
queue tickets while allocating/freeing memory.

## Dependency ordered implementation

1. Execute actual `mem.c` and `smp_boot.c` with four distinct pinned host CPUs;
   replace only privileged IRQ/CR3/TLB and direct-map hardware boundaries.
   Track outstanding client ownership and verify zeroing, uniqueness, reuse,
   patterns and exact final conservation. Preserve runtime RED before fixing.
2. Add separate zero-initialized PMM and heap IRQ-save tickets using the
   existing `pma_ticketlock_t`. Disable IRQs before querying physical identity;
   unlock before restoring original IF. Reject same-CPU recursive acquisition.
   No nesting, NMI use, callback, allocation delegation, wait or stack switch
   while either ticket is held. Allocator zeroing occurs after release.
3. Serialize PMM bitmap, allocation provenance, hints, counters and live-page
   observer. Initial unavailable bits include reservations and are not proof
   of allocation. Only successful allocation sets the new provenance bitmap.
   Validate an entire free subrun before modifying it; permit valid partial
   frees and the legacy valid zero-count operation. Reservations, mixed
   reserved runs, invalid alignment/range and double frees are fatal denials.
4. Serialize heap list/header/accounting operations. Preserve zero-size
   allocation behavior. Reject rounding overflow without mutation and require
   actual free-list membership before reading a caller-derived block header.
   Keep sentinel fences around firmware holes. After the independent P1
   review, reproduce actual sentinel+1 free against the prior code; verify
   complete heap/list/accounting/hole snapshots. Give permanent fences a
   distinct state from allocated zero-size blocks, reject them before heap
   mutation, and require physical adjacency during coalescing. Exercise valid
   zero-size allocation and allocation/free in both usable segments afterwards.
5. Run captured-source GCC and Clang ASan/UBSan controls, including the legacy
   observer entry. Capture actual dependency headers, tool traces, assembler,
   linker, compiler runtime and executable loader dependencies before use;
   archive bytes and verify source/tool/dependency stability afterwards.
6. At the existing AP useful-work checkpoint, opt-in `shz.memory=test` makes
   CPU0 and every actual AP perform 128 epochs. Publish all outstanding single
   pages, variable contiguous runs and heaps before any owner may free them.
   Check pairwise disjointness and each owner's pattern, free after all verify,
   then verify page/heap conservation. Every barrier is outside allocator
   tickets. Bound waits and preserve failed probe state instead of claiming
   successful cleanup.
7. Verify fresh normal production stub/firmware 2/4/off and actual normal-main
   AP-memory 2/4. Preserve unrelated whole-kernel failures. The optional
   evaluator admission is permitted only for KVM AP-memory 2/4, unchanged
   fixture `6761e4cd...`, exact singleton known useful-phase failure, three
   terminal original firmware runs, successful artifacts, captured helper and
   complete source/tool/input/raw-log stability. Default refusal remains.
   Admitted results always retain aggregate `FAIL`, `whole_acceptance:false`
   and `known_failure_preserved:true` even when the component passes. A fresh
   changed-memory producer epoch is recorded separately; if it passes, use the
   evaluator's default producer gate. Prior whole FAIL and narrow singleton
   admission controls remain independently preserved without an old off retry.
8. Freeze source, evaluator, host/compiler closure, actual epochs and all
   failures for independent highest review before committing this own branch.

## Subsequent shared-memory dependencies

The allocated-page observer is a locked live snapshot, not a pin or lifetime
reference. Existing table consumers must keep allocations stable throughout
walks. `vm_map`, `vm_unmap`, `vm_protect`, table creation/destruction and CR3
ownership remain unchanged and are not authorized concurrently by this slice.
A later TLB design must serialize address-space mutations, publish a generation
and exact active-CPU target bitmap, invalidate locally/remotely, verify real
completion ACKs, and defer old frame/table reuse until every target completes.
Physical F0/F1 delivery ACKs from the AP milestone do not establish shootdown
completion. Scheduler/AP activation must wait for process/MM/wait/syscall/IRQ
and Supervisor handshakes. Windows98 remains the actual product OS and its
compatibility VMM remains one vCPU; this allocator slice is not final SMP or ISO
acceptance.
