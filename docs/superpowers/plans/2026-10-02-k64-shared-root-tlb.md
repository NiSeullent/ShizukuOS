# Kernel64 shared-root TLB completion implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans inline. Steps use checkbox syntax.

**Goal:** Replace one owned 4KiB kernel mapping and prove every admitted physical CPU invalidates it before its retired frame may be reused.

**Architecture:** One BSP writer owns one aperture, two payload frames, and an immutable in-flight generation. Physical participants retain kernel_pml4, private interrupt architecture, and exact dense identities. Lock-free F1 service performs INVLPG before recording completion. Send or completion failure for the current pending generation is handled by exact PENDING(G)→POISONED(G), blocking later begin and retaining all resources. Successful finish checks every exact ACK and leaves IDLE. Later QA read/collect failure retains resources and cancels the sole stress writer as implemented; it does not retroactively poison completed G.

**Tech Stack:** Freestanding x86-64 C, xAPIC IPIs, GCC/Clang actual-C controls, QEMU normal Multiboot boot.

**Spec:** Root-approved bounded aperture plan below; the user architecture attachment remains the complete project goal.

## Global constraints

- Base 960ecb096cec4918f34c3ae497d4dd89ce402799, isolated OWN branch; preserve all historical memory/AP evidence.
- Own new MM/TLB C/H, minimal cpu_bringup.c/F1/private-worker hooks, optional cpu_arch_bringup.c; isolated tests/plan/status. No scheduler/main/NTconsumer/Supervisor edits.
- AP scheduler/process/syscall admission remains disabled. No generic vm_map/unmap/protect/free_space SMP-safety claim, changed PMA fixture, producer or evaluator thresholds.
- Legacy F1 verify/withheld-verify semantics remain separate from exact TLB completion.
- Existing 2000 timer-IRQ / 100000000 spin deadlines remain finite. No PT/PMM/heap/queue ticket held while sending or waiting.
- Prepare exclusive payload frames and page hierarchy before INIT and process root cloning; never reclaim on failed/missing/late completion.

## Review focus

- Stale/future/duplicate ACK must not authorize reuse or invalidate a forged VA.
- Reject PS ancestors before interpreting a large page as a table.
- An in-flight descriptor cannot be overwritten by a competing writer.
- Postpublication failure retains old/new frames and tables, not an ordinary vm allocation error.
- Poison is limited to exact PENDING(G). Successful finish leaves IDLE; a later QA failure does not provide a generic post-completion abort latch, prevent a new domain begin, or establish old-root reclamation safety.
- Invalid identity/root/CR4 and prepublication collisions cause no PTE/resource mutation.

### Task 1: Actual RED and exclusive aperture

Files: new tests/test_k64_tlb_baseline.c, test_k64_tlb_host.py; new kernel64/cpu_tlb_aperture.[ch].
Interface: prepare(root, owning-reader, context) reserves a private 4KiB upper-half leaf under an existing shared PML4 entry, checks complete table/frame live allocation and firmware RAM cover, and owns two payload frames.

- [x] Execute actual mem.c/provider/cpu_bringup.c: warm AP translation, replace actual leaf, deliver current F1 callback, require new payload. Actual modeled-cache runtime RED is preserved under baseline-red-2.
- [x] Add PS/collision/reservation adversarial controls before implementation.
- [x] Implement separate preparation, no generic VM changes; retain all resources after AP release.

### Task 2: Exact completion generation

Files: new kernel64/cpu_tlb.[ch], minimal cpu_bringup.c hook; tests/test_k64_tlb_host.c.
Interfaces: enroll checks actual identity/root/CR4; sole-BSP begin(expected,new) atomically replaces the leaf, publishes one immutable generation and invalidates locally. F1 service invalidates the immutable VA before exact completion. Finish succeeds only after every target's exact ACK and transitions G to IDLE; QA payload retirement additionally requires all new-frame observations. Failed current pending send/completion or deadline handling poisons G and retains resources. Later application verification failure cannot retroactively poison successful G.

- [x] Write actual-C stale/future/duplicate/missing ACK, bad identity/mask/VA, BUSY, generation overflow and poison-retention negatives.
- [x] Implement acquire/release protocol without IRQ-held waits, allocations or callbacks; cover a real pthread duplicate G overlapping finish G / begin G+1.
- [x] Pass 24 GCC and Clang ASan/UBSan actual-C cases plus memory ownership regression; archive source/compiler/header/runtime dependency closure.

### Task 3: Physical AP proof and handoff

Files: new kernel64/cpu_tlb_stress.[ch], cpu_bringup.c worker hook; tests/run_k64_tlb_ap.py; docs/agents/status/smp-tlb.md.
Interface: explicit shz.tlb=test warms every physical participant, replaces real PTE, requires F1 INVLPG completion and new payload, then overwrites the retired frame's payload for QA. Separate no-invalidate/withhold-completion controls leave a pending completion failure, poison that pending domain and retain resources. After successful finish, a BSP read/collect failure cancels the QA writer while the domain stays IDLE. A post-retirement sample mismatch is recorded in persistent bad metadata without immediate cancellation: it inhibits retirement at the next round's read checkpoint, or rejects final evidence on the last round. There is no generic post-completion abort latch or reclamation proof.

- [x] Create captured-byte source-bound evaluator before native implementation; preserve existing normal/PMA limits.
- [x] Request root guest slot once host/source compile is frozen; execute AP2/4 positives and bounded hardware negatives. Original strict no-INVLPG stale-observation FAIL remains a FAIL; withheld completion correctly retains all resources. Release the slot after four terminal guests.
- [x] Seal exact source/tool/input receipts and complete baseline archive; perform only parent-authorized byte-identical dedup of OWN repeated dependency files, preserving historical stat identities separately.
- [ ] Independent highest review of exact source, receipts and contract successor before OWN commit.

### Task 4: Read-only architectural contract successor

Parent explicitly approved a separate recheck_k64_tlb_no_invalidate.py and test_k64_tlb_recheck.py on the SAME captured 243 source/compiled-input epoch, with no guest/compiler or original evaluator change. Intel SDM Vol.3A 253668-084US June 2024 section 4.10.2.2 printed 4-43 permits arbitrary TLB entry eviction; hardware stale retention after a warming read is not guaranteed. [Official primary source](https://cdrdv2-public.intel.com/825758/253668-sdm-vol-3a.pdf).

- [x] Reproduce the original strict FAIL using its pinned, captured evaluator bytes and unchanged raw serial log.
- [x] Require CPU1 no INVLPG/no ACK, generation1 no completion/no retirement, poisoned domain, retained allocated resources and unchanged free-page count. Record actual payload and mismatches; do not require stale hardware payload.
- [x] Keep the actual-C persistent modeled-cache RED/GREEN and linked INVLPG-before-ACK proof as deterministic instruction/protocol evidence; make no hardware stale-state claim.
- [x] Test 26 semantic controls and 17 full-replay/admission controls, including actual current header/fixture/compiled/tool bytes, unlisted source, post-load evaluator replacement, malformed payload and extra errors. Preserve the full-replay tuple-versus-JSON normalization RED before the bounded correction.
- [ ] Freeze final 16 OWN files and self-contained successor archive for separate independent review. No component import before approval.

## Deferred integration

Generic concurrent PT allocation/publication; process MM active-root join/leave with Core; VAD/COW/image/user-copy pins; section frame ownership; teardown quiescence; permission-fault proof; huge-page splitting; PCID/global handling; Supervisor retained physical AP handoff. Kernel-half invalidation eventually targets every sharing root, regardless of CR3 equality.

## Execution ledger

Pre-flight: aperture resources, descriptor and native worker consume the same immutable VA/PTE/frames. Existing physical identity provider is shared; scheduler remains CPU0 only.
Ruling: parent requires independent frozen review before any OWN commit; per-task commits are deferred to that gate.

Independent review build/review-smp-tlb-frozen-1 approved the exact 14 production/test files for this narrow component and requested only these plan/status corrections: pending-generation poison scope and separately observed AP2/AP4 page counts. The docs-only successor preserves all captured 243 compiled source bytes, artifacts, raw logs, original strict FAIL and the prior complete archive. The revised exact 16-file candidate awaits focused document reapproval; no compiler or guest is needed.
