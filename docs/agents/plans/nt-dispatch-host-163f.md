# NT dispatcher host dependency closure Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Restore the actual NT priority host fixture after the owner-local dispatcher import, retaining every existing case and proving current-context rejection at the production boundary.

**Architecture:** Extract the unchanged production `sched_owner_context()` immediately after `bsp_scheduler_owner()` and before its consumers. Keep the fixture's existing CPU0 publication and global compatibility mirror for actual reclaim bodies. New tests deliberately diverge that mirror only inside a bounded ownership control; native CPU identity and queue/context lookup remain actual production bodies.

**Tech Stack:** Python captured-source extractor, GCC C, Clang ASAN/UBSAN, MinGW unit compiler; no runtime linking or VM.

**Spec:** Root's explicitly assigned test-only integration task; [NT CPU integration plan](nt-cpu-integration-c957.md), [Core dispatcher plan](core-k64-dispatch-163f.md) and repository `AGENTS.md`.

## Global Constraints

- Own isolated worktree `/root/Win98-Modern-nt-dispatch-host-163f-20261002`, base `c97842929ab121bff3d5410e5747f268b164f0f4`; no canonical/index/global configuration mutation.
- Own only `shizukudos/tests/test_nt_thread_priority.c`, `.py`, this plan and unique status document. No production or peer source edits.
- Retain all old cases, summary gates and existing tighter 30-second helper subprocess bound; every additional subprocess is bounded by 60 seconds.
- Aggregate lane output <=48MiB; captured helper/local C/schema bytes precede compilation; no SDK tree copies.
- AP admission remains closed; host fixtures are not native preemption, Windows 98 or full SMP acceptance. No commit until independent review.

## Review Focus

- Missing transitive extracted helper must be detected by actual GCC/Clang compilation, not hidden by a substitute.
- Deliberately divergent CPU0 global mirror must not replace the actual CPU0 context.
- A mapped offline CPU with a nonnull fixture current must return null without borrowing BSP state.
- An unmapped actual CPUID must reject without CPU0 fallback.
- Current lookup must preserve both outer IRQ depth and the complete queue state; original reclaim/priority fixtures retain their publication.

### Task 1: Preserve and reproduce the extractor RED

**Files:** Existing Python/C fixture; ignored `build/nt-dispatch-host-*` evidence.

**Interfaces:** Consume the actual source bodies and complete TCB/process/object schemas. Produce source/helper/tool-bound compilation receipts and a preserved root RED reference.

- [x] Reconcile root receipt `build/integrated-nt-priority-c978429/result.json` SHA `acc2f449f19df9fd267b3b2e15844465bcd084be54b66fd6e81018f1aa580c87` against original fixture pins and frozen source inputs.
- [x] Capture the original helper before execution, reproduce its GCC/Clang `sched_owner_context` compile failure in fresh ignored output, preserve logs/receipts and immutable local source snapshots.

### Task 2: Restore exact helper closure and cover current ownership

**Files:** Modify the Python extraction list; add one C ownership control group. Do not modify reset or any production source.

**Interfaces:** Consume `static k64_cpu_sched_t *sched_owner_context(void)` and `thread_t *thread_current(void)` from the real scheduler, the actual CPUID identity provider, and `k64_runqueues_t` from the existing header.

- [x] Add C controls for CPU0 context with a differing global mirror, null CPU0 current with a nonnull mirror, mapped offline CPU1 with a nonnull record, and unmapped physical identity. At IRQ depths0/1, assert selected return values, unchanged IRQ depth and unchanged complete queues.
- [x] Extract the actual helper immediately after `bsp_scheduler_owner`; leave compatibility mirror, `.current` tokens and original wide cases unchanged.
- [x] Execute captured helper with `--compile-units` against frozen local bytes. Expected: GCC/Clang existing11,221 checks retained, new context controls0 failures, all eight actual units compile.
- [x] In a temporary copied host fixture only, replace the current getter with the historical BSP mirror body and execute the new controls. Expected runtime RED proves mirror-authority regression detection; no real production changes.

### Task 3: Freeze source/evidence for independent review

**Files:** Unique status; ignored manifest/archive.

- [x] Reconcile current production source inventory, actual compiler project dependencies/tools, helper bytes, artifacts and all receipts before/after. Preserve historical failures rather than promote host scope.
- [x] Freeze exact four owned paths and hashes, bounded archive and test commands, with no live handles. End for root's independent review; do not commit or run native/full-build tests.
