# Kernel32 allocator concurrency prerequisite

Root owns this isolated lane at d91e1bc. Windows98 stays the OS, native Windows
stays one virtual CPU. This is an allocator prerequisite; no Kernel32 AP
bootstrap, page-table concurrency or full SMP acceptance follows from it.

1. Capture actual mem.c, k32.h, ABI and existing pma_sync.h before execution.
   Exercise the actual PMM/heap with checked fixed low host mappings, local
   IRQ adapters and concurrent real host threads. Preserve an actual original
   concurrency/conservation RED and existing valid single-owner behavior.
2. Reuse existing pma_ticketlock_t for separate PMM and heap ownership. Mask
   local IRQ before ticket admission; release ticket before restoring IF.
   Keep page zeroing outside the PMM ticket after unique ownership is reserved.
   Protect counters under their owner, initialize before concurrent admission.
   Retain existing allocator API and heap geometry. Refuse zero/overflow sizes
   and invalid heap pointers before mutation using actual allocated block
   boundaries. VM map/unmap/root reclamation remains owner-restricted and is
   not included in this prerequisite.
3. Run meaningful actual-C concurrent uniqueness/content/free conservation,
   exhaustion/reuse and rejected-size/pointer controls with GCC and Clang
   ASan/UBSan. Bound processes to60s and owned outputs to64MiB, with no compiler
   dependency copies. Pin helper bytes before execution and discover actual
   local headers before compile, retain commands and executable/source hashes.
4. Freeze for independent review before commit/import. Later canonical compile
   and native regression bind merged source; host controls alone do not prove
   physical AP operation, generic MM lifetime safety or Windows runtime.

Owned paths: shizukudos/kernel32/mem.c, new
shizukudos/tests/test_k32_memory_concurrency.c and test_k32_memory_concurrency.py,
this plan and docs/agents/status/k32-memory.md. No shared scheduler, K64, TLB,
Supervisor, peer worktree, private media or global configuration mutation.

## Successor: independent overlapping allocation/free host phase

After root's accepted production prerequisite commit370643cdf209acbc8519e94b88c653abff725e5b,
close the fixture's serialized-free gap without changing mem.c. This successor
owns only the C/Python fixture and appended plan/status; production memory hash
remains8159bfead58a4db9a860b308d3b2c44386a2c521d73e68f57b53cc966ba04e23.

Six pthread actors each perform1200 independent allocation/write/check/free
lifecycles in mixed-pmm and mixed-heap. Heap requests cycle1/17/63/128/511/1024/
3073/8191 bytes; PMM checks complete zeroed pages. Each actor alternates initial
IF on/off and checks it immediately after allocation, free and count queries,
including failed allocations. End conservation requires all256 pages free,
zero heap usage and empty ledger slots. Owner-local counters publish only before
join; ledger fields are mutex-owned; call-interval observation uses atomics.

A separate six-slot ledger checks live requested payload spans only. Every actual
allocator/count call stays outside its mutex. An owner retires its checked
payload BEFORE calling free to avoid falsely rejecting immediate legal reuse.
That retirement leaves a short checker blind interval and is NOT exhaustive
linearizability/race-absence proof. Peak/overlap metrics are host call-boundary
intervals, not physical simultaneous instruction or allocator critical-section
execution. There is only one initial actor barrier; no per-epoch fixture lock
serializes allocator calls. Invalid old-source overlaps stop admission without
allowing two fixture writers onto a known duplicate live payload.

Capture quoted project includes before compiler/dependency discovery, run actual
-MM against copied source and retain only captured local dependency identities.
Capture helper bytes before entry with compile/exec and no project pyc. Compile
original RED from an exact old mem.c build copy; never replace current mem.c.
Require complete, unique phase summaries, actual owners/epochs/checkcounts,
zero failures, all terminal outcomes and IF/ledger boundaries. Preserve a real
bounded child timeout control and receipt rejection controls. Keep60s per run
and aggregate prior+successor outputs below64MiB. Freeze for independent review;
this successor has no inherited PASS, production edit, commit, kernel/VM or AP
acceptance.

## Successor3: owned subprocess lifecycle correction

Independent review reproduced a concrete runner cleanup defect in helper
ed40701f: subprocess.run killed/reaped the direct child at its deadline while
an inherited-pipe grandchild remained alive. Preserve frozen2, its actual
allocator results and root's original proof; their scalar timeout control did
not establish descendant cleanup. This is a runner-resource defect, not an
allocator failure. The original new-fixture allocator RED remains historical
source-bound evidence; it is not rerun or relabeled under the successor helper.

The actual caller now creates a new session/group for each command and enables
Linux child subreaping in the local runner process. On every outcome, including
parent exit0/nonzero and infrastructure exceptions, it checks owned-group
membership, sends TERM then KILL when needed, drains pipes within a separate
2s cleanup bound, reaps its direct child and adopted children in that group,
and rejects cleanup failure. It never signals shared groups or reaps unrelated
children. This covers descendants remaining in the owned session/group; it is
not an arbitrary process that creates a different session containment claim.
Work deadlines remain60s, and the existing scalar timeout remains1s; cleanup
is now separately declared rather than silently extending the work deadline.

Capture the revised helper before execution. Exercise the identical guarded
caller with real inherited-pipe grandchildren on timeout, exit0 and exit7;
exit0/7 without retained pipes; TERM refusal; a real handler exception after
spawn; failed executable launch; and an unrelated session survival control.
Rerun all ten allocator phases and25 actual-summary controls into fresh outputs.
Freeze successor3 for independent review, without changing C, production, index,
canonical sources or prior evidence. Keep aggregate old+new outputs below64MiB.

## Successor4: private process-control capture binding

Independent review identified P2 only in the private process-controls-2 harness:
it captured helper bytes, then hashed the live path separately and later reread
that path into source snapshots. A persistent replacement could therefore bind
new bytes while executing the older capture. Preserve controls2 and frozen3;
they do not establish the missing capture equality gate.

In fresh private controls3, compute the recorded digest from captured bytes,
compare current bytes to that capture immediately before the actual compile/exec
consumer, publish the captured helper into source snapshots, and require the
same equality in the final guard. Use the same actual loader with an exact
copied real helper that is persistently replaced between capture and consumer;
require refusal and no execution entry. Rerun only nine real lifecycle controls.
Do not change or rerun the allocator helper/C/production or ten allocator phases.
Keep green2's historical execution explicitly bound to its identical current
helper/C bytes, then freeze4 current test/docs and retained evidence for review.
