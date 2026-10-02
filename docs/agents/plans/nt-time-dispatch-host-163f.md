# NT time host dispatcher adapter implementation plan

> **For agentic workers:** Use superpowers:executing-plans with the existing assertions and a real compile RED before the minimal adapter change.

**Goal:** Compile the unchanged NT time/info/affinity fixture against canonical dispatcher source at 1712a923387c328bae689dd6637b35fa99e6f6f5.

**Architecture:** Extract the actual `sched_owner_context` body before `thread_current`, preserving the existing CPU0 fixture, schemas, C assertions, reset logic and producer admission/cleanup. This is a host adapter component and proves no AP, native Windows98 or ISO behavior.

**Tech Stack:** Python byte capture, actual freestanding C extraction, GCC O2 and Clang ASan/UBSan, seven real translation units.

**Spec:** Root task for `/root/Win98-Modern-nt-time-dispatch-host-163f-20261002`, branch `codex/nt-time-dispatch-host-163f-20261002`, base 1712a92; original exact11 NT production handoff and canonical dispatcher are already reviewed/imported.

## Constraints and review focus

- Own only `shizukudos/tests/test_nt_time_queries.py` and this unique plan/status pair. No production, C assertion, old priority fixture, canonical, index or commit mutation.
- Root-created isolated worktree; output only under ignored `build/nt-time-dispatch-host-163f`, aggregate logical artifact ceiling 48MiB. No SDK copies, VM/native guest, network or NAS work.
- Preserve exact source/helper/schema bytes before compiler commands, compiler/Python identities before and after, generated inputs before consumption, and actual command/log receipts. Record external toolchain closure limits.
- Missing-helper RED must be a real compiler failure. GREEN must execute unchanged normal1292/0, zero34/0 and wrap34/0 under both compilers, plus seven real TUs.
- Preserve nested IRQ and real helper identity; do not replace the helper with a mock. Preserve original timeout/SIGINT admission and bounded cleanup code.

## Task 1: Paired adapter proof

- [x] Save initial source/production/tool pins and plan before changing Python.
- [x] Run `PYTHONDONTWRITEBYTECODE=1 python3 -B shizukudos/tests/test_nt_time_queries.py --out build/nt-time-dispatch-host-163f/red-1`. Expected: FAIL; GCC and Clang reject undeclared `sched_owner_context` from actual `thread_current`.
- [x] Add `sched_owner_context` immediately after `bsp_scheduler_owner` in the scheduler extraction list. Expected source delta: one Python line only; fixture C unchanged.
- [x] Run `PYTHONDONTWRITEBYTECODE=1 python3 -B shizukudos/tests/test_nt_time_queries.py --out build/nt-time-dispatch-host-163f/green-1 --compile-units`. Expected: both compilers normal1292/0, zero34/0, wrap34/0; seven TU compiles admitted; no timeout/interruption/cleanup failure.
- [x] Verify current/frozen helper equality, complete source/artifact maps, unchanged production/C/guard/reset bytes, no new pyc, pre/post tool pins and aggregate size.
- [x] Freeze exact3 owned files and a bounded handoff with RED/GREEN hashes.
- [ ] Await a fresh independent reviewer and root commit gate.

## Execution ruling

Root explicitly supplied this one-step implementation method and acceptance contract. Continue without another approval prompt. Root requires no commit until independent review, so skill commit/workspace-cleanup defaults do not apply; preserve all original evidence and use a small ignored ledger.

RED binds GCC/Clang; GREEN `--compile-units` additionally uses Mingw, which the outer before manifest already pinned before RED. The initial output-parent setup error occurred before compilation and is not the behavioral RED. External system/compiler/runtime dependencies remain outside the sealed local source closure; no SDK duplicates are created.
