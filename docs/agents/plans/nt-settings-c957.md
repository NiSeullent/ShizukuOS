# Held process and thread settings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. ROOT owns production changes and execution releases; disjoint host-fixture and guest-source authors work only after their individual release.

**Goal:** Enforce the selected modern query/set rights and preserve real stored process/thread settings through referenced objects, UP snapshots and actual thread detachment, without adding scheduling, power or memory-eviction behavior.

**Architecture:** Keep process settings on private query13 and legacy boost settings on query12. Add one direct full-QUERY thread-settings selector19 with the same16-byte payload, and route GetThreadInformation to it. Selected setters acquire typed rights and references before any kernel caller-payload copy, then revalidate identity/liveness under IRQ exclusion before mutation; detached thread queries use four fields captured by thread_object_detach.

**Tech Stack:** Existing Kernel64 C, Win64 kernel32/ntdll private transport, GCC and Clang ASAN/UBSAN host fixtures, MinGW production compiles, real GCC -MM closure, bounded UP KVM guest.

**Spec:** ROOT's approved six-path settings design is embedded below, including its explicit rights-before-copy precedence choice. Base is source4409cae03b734cef74aa5c4f34f14d4511f9f55a in `/root/Win98-Modern-nt-settings-c957-20261002`, branch `codex/nt-settings-c957-20261002`. Read `AGENTS.md`, `docs/SHIZUKUDOS_WINDOWS98_ARCHITECTURE.md` and `docs/SHIZUKUOS_ARCHITECTURE_SUPPLEMENT.md` for the unchanged Windows98 architecture; the preceding memory plan/status remain historical component evidence.

## Global Constraints

- Actual Windows98 remains the OS and owns VMM/USER/GDI/Explorer; ShizukuDOS replaces its DOS foundation. Standalone kernels and Win64 probes remain component checks.
- Only the six production paths listed below may change. Preserve existing Q8/Q9 bytes, native priority/time/cycle behavior, scheduler/providers, proc.c, other query/set classes and other owners' work.
- Process settings query13 requires QUERY or LIMITED. Legacy thread-settings query12 requires QUERY or LIMITED. New direct thread-settings query19 requires full QUERY.
- Process setters9/10 require full PROCESS_SET_INFORMATION. Thread setters3/8 require full THREAD_SET_INFORMATION. Boost setter2 requires THREAD_SET_INFORMATION or THREAD_SET_LIMITED_INFORMATION.
- Define named THREAD_SET_LIMITED_INFORMATION=0x0400u in ipc.h. Do not use an anonymous numeric rights mask or change global IPC access semantics.
- Query13 remains12 bytes; thread query12/19 remain16 bytes. Private scalar setters remain4 bytes and power setters8 bytes. Public memory-priority structures remain4 bytes and power structures12 bytes.
- ROOT explicitly authorizes typed rights/reference acquisition before length/value validation or kernel caller-payload copy for every selected setter. This intentionally changes the old thread copy/value-before-handle order.
- Short private setter lengths remain ACCESS_VIOLATION; oversized lengths remain accepted and only the required4/8 bytes are consumed. Raw private power-mask validation remains unchanged.
- Preserve frontend NULL, exact-size, Version and mask checks and their order. Rights denial guarantees zero kernel caller-copy reads and zero metadata writes; it does not claim that unchanged frontend parameter validation never reads its supplied structure.
- Metadata queries may read retained exited process or thread settings. Setters refuse terminated/teardown/exit-owner processes and detached/ZOMBIE/FREE or dying threads. No PML4 requirement belongs in a scalar settings query.
- Store and report metadata only. No dynamic priority boost, EcoQoS/frequency/core selection, timer-resolution change, trim/eviction/page-priority enforcement, AP/SMP or whole-batch guarantee.
- Preserve all original setup/compile/behavioral failures and existing memory/fullquery/time/priority receipts. No retry or threshold waiver turns old failure into success.
- No NAS allocation/read jobs, private Microsoft media, native VM, AP, full-runtime, installer or ISO work. Public source-only delivery remains separate from m98.nyase.kr's final ISO gate.

## Review Focus

- QUERY_LIMITED thread handles must retain boost-query success and fail GetThreadInformation; one shared OR/strict query cannot satisfy both contracts.
- Access-denied setters with malformed or faulting input must perform zero kernel input copies and leave all settings intact.
- A caller-copy departure may detach/free a thread or close its handle; a held object alone does not authorize using a stale TCB after that boundary.
- Pseudo-current thread requests must belong to the actual current TCB/process and reciprocal typed object, without weakening generic IPC or touching a foreign owner.
- Retained ZOMBIE/detached queries must return the last real metadata after actual detach and TCB reuse, while setters refuse and cached output survives later final-free.

---

## Approved contract and minimal file scope

| Production path | Responsibility |
| --- | --- |
| `shizukudos/kernel64/sysk32_proc.c` | Referenced metadata access, query13/query12/new query19 snapshots, setters2/3/8/9/10 and local helpers |
| `shizukudos/kernel64/ipc.h` | Named THREAD_SET_LIMITED_INFORMATION constant only |
| `shizukudos/kernel64/proc_internal.h` | Four uint32 cached fields in OB_THREAD |
| `shizukudos/kernel64/objects.c` | Capture those four fields only in thread_object_detach before clearing the TCB pointer |
| `shizukudos/win64/include/nt.h` | New direct private selector19 declaration |
| `shizukudos/win64/kernel32/k32_procinfo.c` | Route only GetThreadInformation's existing supported settings branches to selector19 |

Create the dedicated pair `shizukudos/tests/test_nt_settings.c` and `shizukudos/tests/test_nt_settings.py` after fixture-author release. The guest author may append only one removable helper block and one call to existing `shizukudos/win64/tests/t_k32_proc.c`; final status documentation is a separate ROOT release. No production edit is authorized by merely reading this plan.

Actual existing ordinals are PROCESS_SETTINGS13 and THREAD_SETTINGS12. Q4 is PROCESS_LIST and Q2 is PROCESS_TIMES; do not repurpose either. New query19 is a direct strict settings snapshot, not a zero-payload gate followed by query12: a two-call gate/query could check one handle lifetime and return another object's settings. The proposed constant is `K32Q_THREAD_SETTINGS_STRICT = 19` in the existing kernel query enum and frontend nt.h declarations; independent plan admission precedes that source reservation.

Add these exact durable fields to `kobject_t.u.thr`:
`uint32_t last_boost_disabled, last_mem_priority, last_power_control, last_power_state;`
Only `thread_object_detach(thread_t *t)` captures them from that actual TCB, with interrupts already excluded, before `o->u.thr.t = 0`. Normalize boost as the stored boolean; retain actual memory priority and both raw power words. Existing time, exit, relative/base priority and process-reference capture/release remains unchanged. Do not add capture to proc.c, release_thread_user_memory or scheduler code, and do not synthesize detached defaults0/5/0/0. Attached defaults come from unchanged TCB initialization: boost0, memory priority5 and power0/0. New object-cache fields may be allocator-zero before capture, but that is not a valid retained snapshot: when t is absent, require captured last_mem_priority in1..5 or return INVALID_HANDLE. Copy all four captured values exactly, including raw power words; do not manufacture a default or add a separate capture flag.

Prefer a dedicated local settings snapshot:
`static int32_t query_thread_settings(process_t *cur, uint64_t h, uint32_t alternatives, uint32_t settings[4]);`
It consumes the referenced typed object, uses one owned UP guard to read attached live/ZOMBIE metadata or the durable detached cache, and returns local scalars after restoring and releasing. The existing `thread_times` function and time/cycle calls remain byte/behavior unchanged; query12 stops using its legacy settings branch. This small helper avoids changing accounting or clock preparation merely to fix metadata.

Use a local metadata-specific acquisition helper:
`static int32_t ref_settings_object(process_t *cur, uint64_t h, uint32_t type, uint32_t alternatives, kobject_t **out);`
For ordinary handles retain existing ipc_ref_handle tag/width/type/reference behavior and check nonzero alternatives by OR. Before publishing a pseudo-current reference, validate the actual current TCB, its proc==cur, object type and reciprocal TCB/object link under IRQ exclusion; validate reciprocal current-process identity for process pseudo handles. Refuse missing/foreign/unpublished identity rather than dereferencing it. Do not alter ipc_ref_handle or other consumers globally.

Under each settings snapshot/mutation guard, process identity means a used process reciprocally linked to the held process object. Attached thread identity includes the held object's TCB back-link, non-FREE state, valid owning process and matching retained PID. Metadata queries permit ZOMBIE/terminated ownership while it remains valid; detached queries use only the held object's cache. Thread mutations additionally require non-ZOMBIE, attached user ownership, no process terminated/teardown/exit_owner and no thread_must_die/kill_pending. Initialized published TS_NEW threads remain eligible.

For process setters a bad reciprocal identity returns INVALID_HANDLE; terminated/teardown/exit_owner returns PROCESS_IS_TERMINATING. For thread setters detached/ZOMBIE or dying ownership returns THREAD_IS_TERMINATING; FREE or broken reciprocal identity returns INVALID_HANDLE. These are chosen private backend distinctions, not promises of Windows error precedence.

### Rights, widths and precedence

| Private operation | Rights | Existing payload |
| --- | --- | --- |
| Query13 process settings | PROCESS_QUERY_INFORMATION OR PROCESS_QUERY_LIMITED_INFORMATION | three uint32,12B |
| Query12 legacy boost/settings | THREAD_QUERY_INFORMATION OR THREAD_QUERY_LIMITED_INFORMATION | four uint32,16B |
| Query19 strict thread settings | THREAD_QUERY_INFORMATION | same four uint32,16B |
| Setter9 process memory | PROCESS_SET_INFORMATION | one uint32,4B, value1..5 |
| Setter10 process power | PROCESS_SET_INFORMATION | control/state uint32 pair,8B |
| Setter2 thread boost | THREAD_SET_INFORMATION OR THREAD_SET_LIMITED_INFORMATION | one uint32,4B, nonzero normalizes true |
| Setter3 thread memory | THREAD_SET_INFORMATION | one uint32,4B, value1..5 |
| Setter8 thread power | THREAD_SET_INFORMATION | control/state uint32 pair,8B |

All selected setters perform typed rights/reference acquisition first, then existing short-length check/caller copy and memory-value validation, then final guarded identity/liveness check and mutation. Keep the reference across caller copies. Every refusal restores owned IRQ state and balances references; rights denial performs zero kernel copy reads even for bad length/value/pointer. Power's two stored words update in one guard. Restore and release before returning; never carry a raw TCB pointer past restore.

Queries acquire access/reference before any target read, snapshot into local12/16-byte storage, then restore/release before unchanged put_out. put_out writes optional uint32 required length first, returns BUFFER_TOO_SMALL for a short buffer, then performs the output copy with ACCESS_VIOLATION on failure. Oversized tails stay untouched. Query refusal preserves caller output and ReturnLength. Retained process settings do not walk PML4 or memory providers.

Frontend memory-priority NULL is ERROR_INVALID_PARAMETER and wrong exact size is ERROR_BAD_LENGTH. Power retains exact12B/version1 validation and existing mask ordering: process control is EXECUTION_SPEED|0x4, thread control is bit1, state must be a subset of control. Do not add that validation to raw private power stores. GetThreadInformation's existing power-read class3 is a retained local extension; Microsoft's current getter documentation does not list it. Keep unsupported absolute-CPU/dynamic-code behavior unchanged.

### Primary contracts and personality boundary

- [GetProcessInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocessinformation) requires at least PROCESS_QUERY_LIMITED_INFORMATION; [process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights) explain that full QUERY automatically grants LIMITED. Use an OR alternative in this backend.
- [SetProcessInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setprocessinformation) requires PROCESS_SET_INFORMATION.
- [GetThreadInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadinformation) requires full THREAD_QUERY_INFORMATION; [SetThreadInformation](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadinformation) requires full THREAD_SET_INFORMATION.
- [GetThreadPriorityBoost](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadpriorityboost) allows QUERY or QUERY_LIMITED; [SetThreadPriorityBoost](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadpriorityboost) allows SET or SET_LIMITED. XP/Server2003 require full rights and do not support the LIMITED bits; this plan retains the selected modern personality.
- [Thread access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-security-and-access-rights) define SET_LIMITED0x0400 and implicit full-to-LIMITED access.
- Microsoft describes actual boosting, working-set prioritization and power policy effects. This backend currently only stores those settings: its scheduler never boosts and its memory manager does not evict by these priorities. Success here acknowledges stored metadata; it does not establish those Windows effects, inherited process-memory policy behavior or modern performance compatibility.
- Documentation supplies rights/public sizes, not the chosen private short-buffer, copy-fault, termination, retained-exit or error-precedence guarantees. State those distinctions in evidence.

## Task 1: Freeze meaningful host acceptance before production

**Files:** Create only `shizukudos/tests/test_nt_settings.c` and `shizukudos/tests/test_nt_settings.py` after ROOT's release. Use fresh ignored `build/nt-settings-host-red-v1`; never overwrite old receipts.

**Interfaces:** Consume frozen base4409 actual schemas/functions and existing audited producer9aa4268ce7383fbb12d3e704f10a620601181b023e0b5c40db3e0b7f1ad3a277. Produce exact C/Python hashes, selected-source/body/header/SDK maps, per-command records and preserved terminal RED.

- [ ] Write `settings_rights_before_copy`: denied process/thread/boost rights return ACCESS_DENIED with reads0/writes0, unchanged complete metadata, balanced refs/IRQ, including zero/short length, invalid memory value and poisoned pointer. Assert OR success independently from combined-mask success.
- [ ] Write `settings_queries_and_buffers`: process QUERY-only/LIMITED-only and legacy thread QUERY/LIMITED success; strict thread full QUERY success/LIMITED denial; exact12/16B payloads, valid public4/12B schemas, optional retlen faults, short buffers and guarded oversized tails.
- [ ] Write `settings_live_mutation`: real valid memory1..5, boost normalization, raw power words and public version/mask refusals; deny QUERY-only/insufficient mutation handles without kernel reads. Include typed/tag/high/closed handles and malformed input under admitted SET rights.
- [ ] Write `settings_copy_departure`: at the actual caller-copy boundary execute real close/ref/free or detach and explicit storage republication. Hold the candidate object across the copy; final revalidation refuses any detached/dead/reused TCB without metadata mutation.
- [ ] Write `settings_current_owner`: actual current pseudo owner succeeds; foreign process, missing/incorrect object type and reciprocal-link failures refuse before payload copy/reference publication. Restore fixture refs/owner state after each row.
- [ ] Write `settings_detach_cache`: set nondefault metadata, query actual ZOMBIE, invoke real thread_object_detach, recycle the TCB and query the held old object again. Require exact old four fields; setters refuse; last-handle final free cannot change an already captured output snapshot.
- [ ] Extract actual selected production branches/wrappers and full process/TCB/object schemas, real handle_ref/ref/close/final OB_PROCESS free/thread_object_detach. Declare caller-copy, IRQ, current-TCB/slot publication, allocator/static reuse and unselected transport adapters. No fake generic query result, generic IRQ departure or fabricated last settings.
- [ ] Pin full canonical header paths and real SDK schemas; reject basename collisions. Preserve audited owned-group timeout/interrupt refusal, TERM then KILL even if leader exited0, bounded waits, partial FAIL and first-use generated-input sealing. Seal sources, compiler executables, emitted actual bodies and complete artifacts before admitting PASS.
- [ ] Obtain both independent fixture/producer reviews, then ROOT may release exactly `python3 -B shizukudos/tests/test_nt_settings.py --out build/nt-settings-host-red-v1`.
- [ ] Preserve actual GCC/Clang compile/run records and meaningful rights/departure/cache failures. Setup/compile failure is separate from behavioral RED; any fixture-only fix needs new frozen evidence and fresh output after review, without weakening assertions. Do not implement production before meaningful paired RED.

## Task 2: Implement and review the six production paths

**Files:** Modify only the six paths in the scope table.

**Interfaces:** Consume Task1's frozen C/Python pair. Produce the direct selector19, local metadata helpers, named SET_LIMITED constant, durable four-field cache and reviewed six-path source freeze.

- [ ] ROOT adds the named ipc.h constant and cached object fields with no global IPC or scheduler changes.
- [ ] ROOT captures all four real values in objects.c thread_object_detach before clearing t, retaining existing ref/drop and time/priority operations.
- [ ] ROOT adds local typed metadata acquisition and query_thread_settings, switches query12 to OR access, adds query19 full access and converts query13 to a local guarded referenced snapshot.
- [ ] ROOT changes only setters2/3/8/9/10 to rights-before-copy plus final guarded identity/liveness and balanced release, preserving widths/value/raw-power rules.
- [ ] ROOT declares selector19 in frontend nt.h and routes only GetThreadInformation settings branches directly to it; keep GetThreadPriorityBoost on12 and other public parameter/capability behavior.
- [ ] Freeze all six exact hashes and diff. Two independent reviewers check references/IRQ, pseudo-current identity, actual detach ordering, no copy under guard, new precedence, cache/no defaults and complete absence of unrelated Q8/Q9/time/native/AP changes before execution release.
- [ ] ROOT may release one `python3 -B shizukudos/tests/test_nt_settings.py --out build/nt-settings-host-green-v1 --compile-units` with identical authoritative RED fixture bytes.
- [ ] Require GCC and Clang ASAN/UBSAN zero failures and actual frozen affected TUs: sysk32_proc.c, objects.c, ipc_core.c, ipc_proc.c, proc.c, sched.c, win64/kernel32/k32_procinfo.c and win64/ntdll/ipc_ntdll.c. These compile existing source; no provider edits are implied.
- [ ] Independently rehash current/frozen sources, all body/schema/SDK/tool/artifact maps and raw logs. Declare modeled/static reuse limitations and actual command admission/reaping/timeout fields rather than inferring broader cleanup.

## Task 3: Preserve regressions and author an append-only guest

**Files:** Guest author modifies only `shizukudos/win64/tests/t_k32_proc.c` after release. Priority probe remains byte-identical.

**Interfaces:** Consume reviewed Task2 source and existing866 process/654 priority probes. Produce a removable settings helper/call, static independently agreed successful count and source-only freeze before any compilation.

- [ ] ROOT separately releases one unchanged memory/fullquery/time/priority regression per fresh prefix. Independently audit complete maps/raw results; retain priority's legacy omitted-log/cleanup-metadata qualifications.
- [ ] Preserve the entire original866-check guest byte-for-byte upon removal of one appended helper block and one call before finish; preserve priority654 unchanged. Never replace baseline checks or weaken unsafe-handle assertions to create a RED.
- [ ] Add guarded independent process QUERY/LIMITED/SET and thread QUERY/LIMITED/SET/SET_LIMITED handles. Exercise metadata getters/setters, strict-vs-boost access, exact sizes, output preservation, raw/private widths and frontend parameter/mask order without deliberate guest faults.
- [ ] Use the existing five-member archive's suspended natural T_HELLO fixture and independently held process/primary-thread handles. Set actual nondefault process/thread metadata, read full/LIMITED as allowed, resume once, and require bounded process AND thread waits plus both natural exit7 before retained queries/refusals.
- [ ] Query last metadata at ZOMBIE/retained stages; use four bounded temporary thread fixtures for churn with checked waits/closes, then require unchanged cached old-thread values and denied old-thread setters. Host actual-detach controls supply the precise detach/reuse proof; guest churn alone is not a slot-reuse proof.
- [ ] Separate any forced99 cleanup and bounded waits from natural success. Close every independent/original/churn handle and restore exact parent count; restore changed current settings on all exits.
- [ ] Independently calculate all helper/loop/child successful counts. Freeze exact expected total `866 + added_settings_checks` before compiler/probe release, and bind it to the appended source hash/removal proof. Keep654 priority expectation unchanged; do not invent a numeric success total before source is complete.
- [ ] Obtain two source-only guest reviews and imports/provider feasibility checks. No new archive member, DLL capability/provider, native scheduler behavior or user-pointer fault experiment.

## Task 4: Fresh builds and one bounded UP guest

**Files:** ROOT-owned fresh ignored producers/receipts only; source and guest frozen.

**Interfaces:** Consume Task2/3 source hashes, complete host/regression evidence and fixed guest counts. Produce independently pinned CPP/four-kernel/two-DLL/probe receipts and one actual UP guest receipt.

- [ ] Preflight fresh producers and exact command inputs before release. Verify full-path helper import pins, complete live/frozen inputs, real command logs and first-use generated maps.
- [ ] Execute actual selected CPP dependency profiles with existing mutation/omitted-C refusal controls; derive inventory/counts from actual source rather than assuming a prior epoch.
- [ ] Build four actual component kernels, selected ntdll/kernel32 DLLs and both actual probes; compile/link unaffected units as required by real closure. Independently audit all actual -MM files, resource/link/import calls, archive ranges and tool/artifact maps.
- [ ] Retain exactly five archive members with both fresh DLLs/both fresh probes and only the qualified historical T_HELLO member. Pin all producer receipts, the new guest source/count, actual kernel inputs and CLI hashes.
- [ ] After both preflight/evidence admissions ROOT alone releases one bounded UP KVM run. Require exact654 and frozen new-process count, both app exit0/fault0, all35 distinct PMA PASS, one failures0/CPU1 summary, done0/SHZ-EXIT0, expectedQEMU1/no timeout/leader reaped and complete before/after/current pin equality.
- [ ] Independently recompute gates from raw serial and confirm natural child waits/exit7 before retained tests, no credited forced cleanup, exact count/restoration and all output bytes. A separate post-return process observation remains separate evidence, not a retroactive receipt edit.
- [ ] Preserve native/AP/SMP/full-runtime/ISO/original361 false flags. Full external sysroot/compiler support/Python standard-library closure remains unsealed unless independently established by a different authorized lane.

## Task 5: Reviewed public source-only handoff

**Files:** ROOT later owns `docs/agents/status/nt-settings-c957.md`, exact reviewed public source/tests/guest and this plan; shared publication remains ROOT-owned.

**Interfaces:** Consume actual Task1–4 terminal receipts and final source epoch. Produce exact public commit/patch/source handoff with explicit component scope.

- [ ] Write final evidence status from actual receipts/logs, including any original setup/compile RED and every current limitation; do not promote stored metadata to real policy behavior.
- [ ] Obtain final independent source/body/map/raw-serial/document review, with exact file hashes and successful check decomposition.
- [ ] ROOT stages only reviewed public paths and commits after that admission. A published plan or proposed command is not proof of execution.
- [ ] Bind commit, patch and source-only handoff hashes for other chats. Canonical adoption needs its own source epoch and fresh closure/build/runtime receipts; do not edit another chat's tree/index/VM/mailbox.
- [ ] Leave actual Windows98 desktop/VMM/PMA, Supervisor/AP, modern apps, installer/final ISO and original whole-PMA/diagnostic failures explicitly open.

## Plan-only checkpoint

This document is the authoring deliverable. At its freeze, production/tests/guest remain base4409 and no new settings baseline, compile, import, guest or policy demonstration has executed. ROOT requests independent plan review before releasing any implementation task.
