# Windows 98 modern backend integration implementation plan

Current canonical source implementation:960ecb0 integrates reviewed K32 QEMU argument providerd716749, actual-header inventory71977a8, Supervisor BSP CPU-bank/retainedVMCS/TSS d0371a7+6ef4b01, AP PMM/heap sentinel serializationbcb603b and exact15-path c957 NT consumers960ecb0. Fresh actual four profiles PASS138.754s/236 inputs;229 actual compiler-local dependency groups plus independent actual-profile selection/header-mutation/omitted-C controls bind the complete local preprocessing closure for this epoch. Helpers execute exact before-captured bytes, no cached bytecode. Actual K32 KVM12/TCG12, K64focus17each, broadKVM38+10policy/151testapps0 in186.98s, and actual NTAPI321/0 wholePASS2.67s all pass. API consumes exact separately verified historical DLL/probe epoch; no full current runtime or modern Windows application claim. Current NThost4203 perGCC/Clang and7actualTU compile pass. Handoff4a5f4ef3/archive17a00ff7 is terminal; independent integration review requested in c957 chat. Earlier230 K32 bootstrap97 and omitted pe_parse.h before-identity, old233 lowuseful104, c957 original361 and diagnostic failures remain preserved.

NASv4 owner6559e06c remainsREADY;163f allocation6GiB and reserve17GiB stay unchanged. Historical Registry Checker diagnostic is fully terminal: originala1e0b2e unchanged, finalownclonec35ed0af fullreadback, result0b66c8f3; actual WIN.COM→RegistryChecker backup, no Enter/RESET/desktop. All owned diagnostic QEMU/controller/leases released. Genuine unchanged ordinaryDOS epoch3 main/collector completes0 in328.51s and allthree compilers0. Independent highest Core review1c66018f APPROVES exact frozen70evidence manifest0d8487b2 and ordinaryreceiptc434780e as freshproducer only: complete2977exec/2177process closure,306/812/666 precompiler sourceZIP maps,14recursivegitarchives/1781source members,5207strict4fdcWatcommembers/sevenactuallyexecutedbinary and32C+23NASMWIN31calls match. Conservative18856genuine terminalinputpins unchanged; excludedcollector stdout is documentedoutput. Exactconsumerhandoff78b9e6d9 goes to Fada under existing source-profile/geometry/constructor/launch guards; retainedRAMcache staysowned. No Windows/runtime acceptance is inferred. Epoch1 storage withholding and epoch2 missingrecursivecache/three-tool audit RED remain unchanged with genuine old outputs preserved. OwncacheRAM718MiB within1GiB, actual compilerWORK/config/finalNAS and all established floors/budgets remain unchanged.

Supervisor V2 and memorysentinel reviews approve exact9/exact13 component scope, and those reviewed sources are imported. Their actual BSPVMX17positive/4negative and APmemory2/4 128epochs are distinct isolated-source evidence, not canonical fullSMP proof. Firmwarelead now implements physicalSupervisorAP startup/private perCPU architecture+VMX in an isolated branch. SMPlead implements real shared-root INVLPG-before-generation-ACK over a preowned kernel aperture; general vm_* and process-root lifetime safety remain open. Fresh nativeVxD/PMAQUERY input capturee232015c binds source/tool/header bytes and matches reviewed endpoint artifacts; actual VMM owned-event/PMA delivery remains pending. Cross-chat 6970 PE32 artifact11199849976 exact24files is content-verified16708d6b only; no native loader mode or compatibility claim. Actual Windows desktop/VMM/PMA, distributed scheduling/objects/waits/VM/TLB/virtualAPs, modern apps, install/coldboot/persistence/restart and final ISO remain live gates.

> Agentic execution uses `superpowers:subagent-driven-development`. Implement and test existing subsystems in dependency order, with explicit ownership and independent review.

**Goal:** Extend the existing native scheduler, firmware display path and Windows bridge with real tested behavior while preserving actual Windows 98 as the product OS.

**Architecture:** Windows 98 keeps VMM, VxD, USER/GDI, Win16/Win32 and Explorer. ShizukuDOS supplies the boot/hardware foundation; Kernel32 and Kernel64 are service domains. The existing native scheduler and NTWRAP9X/channel2 transport are extended, not replaced with competing implementations.

**Tech stack:** Freestanding C and NASM, public UEFI protocols, existing Shizuku ABI 1.1, host C/Python tests, GCC/Clang sanitizers, QEMU/OVMF.

**Spec:** [integration requirements](INTEGRATION_SPEC.md).

## Global constraints

- Windows 98 is the product OS; its VMM remains the Windows scheduling authority.
- Preserve existing BIOS, CSMWrap, DOS16, native Windows, Kernel32/64 and historical evidence paths.
- Keep native Windows single-vCPU compatibility while integrated native SMP is unproven.
- Do not invent VMM service numbers or replace USER/GDI with a development desktop.
- Keep ABI 1.1 wire layouts and opcodes compatible during this slice.
- No proprietary source copying, private Windows media publication or fake-success stubs.
- Component/host tests never establish Windows 98 integration or hardware acceleration.
- No changes to client-global configuration; all new artifacts stay in this isolated worktree.

## Review focus

1. A woken thread must occur once in the runnable queue, including signal/timeout races.
2. Priority selection must retain bounded progress for lower-priority native threads.
3. Corrupt EDID, unsupported masks or unsafe pitch must retain a valid firmware display fallback.
4. Stale bridge responses must never release another epoch's pool allocation or reach a client as valid data.
5. Failed/reentrant bridge operations must release admission ownership and return deterministic errors.

## Task 1: Native PMA scheduler policy and runnable queues

**Owner:** Core Kernel Lead. **Files:** `shizukudos/kernel64/sched.c`, `k64.h`, `pma_tests.c`, and the single PMA test hook in `tests.c`.

**Interface:** Existing `thread_create`, `thread_resume`, `thread_wake`, sleep/join and context-switch paths remain usable. Add documented priority/quantum/CPU0-affinity controls and bounded scheduler statistics; exact declarations belong to the existing `k64.h`, not a new scheduler ABI.

- [x] Establish fresh baseline kernel build and real non-yielding-thread test.
- [x] Add failing tests for duplicate wake, priority changes, timed semaphore waits, invalid policy and runnable accounting.
- [x] Extend the existing ready/block/wake transitions with explicit ready queues and starvation protection; keep CR3, SSE, GS and IRQL restoration.
- [ ] Run the new guest tests and existing standalone Kernel32/64 regressions with freshly built kernels.
- [ ] Record source-bound evidence and create a scoped commit after review.

Task1 acceptance reopened: fresh combined KVM refresh worker starts at98ticks with zero useful loops, despite prior focused11/11 passes. Diagnose actual dispatch/IRQ/body boundaries; retain40/80/>1000 gates. Source provenance corrections also await independent review.

## Task 2: Safe high-resolution firmware GOP selection

**Owner:** Firmware/Display Lead. **Files:** `shizukudos/uefi/efi.h`, `boot.c`, `boot.h`, `test.c`, `main.c`; GOP selection call sites only in `supervisor/loader/loader.c`; optional focused firmware test.

**Interface:** Reuse the existing framebuffer handoff structure and RGBX/BGRX backend. Add typed QueryMode/SetMode and EDID lookup/selection in the shared boot helper; expose the exact helper in `boot.h`.

- [x] Run existing host display tests before editing.
- [x] Add failing mode enumeration, EDID, pitch/mask/budget and firmware-error tests.
- [x] Implement validated EDID geometry preference, requested resolution ladder, allocation cleanup and original-mode fallback before ExitBootServices.
- [x] Run GCC host tests, Clang sanitizer tests, EFI build and bounded fresh OVMF boot.
- [x] Record selected-mode evidence with component scope and create a scoped reviewed commit.

## Task 3: Existing Windows bridge concurrency and epoch safety

**Owner:** Windows/NT Compatibility Lead. **Files:** `ntwrapper/vxd/bridge.c`, `bridge.h`, `tests/test_w64vxd.c`, necessary test driver, `README.md`. The separate c957 chat owns the common capability manifest; fada owns `kernel64/subsys64.c` and the new payload service, and received the bounded-drain/source defects for its implementation.

**Interface:** Retain NTWRAP9X DIOC and SHZ ABI 1.1. Add atomic nonblocking admission to existing shared state; return ERROR_BUSY for overlap. Validate live generation/endpoints and incoming response ownership before delivery or pool release.

- [x] Run current VxD build/host tests.
- [x] Add failing concurrent/reentrant, stale-generation, wrong-domain and corrupt-ring tests.
- [x] Implement bounded admission/receive/reset behavior without fabricating blocking VMM synchronization.
- [x] Keep outstanding pool memory allocated across reset until a terminal peer response; document missing cancellation/rundown acknowledgement rather than freeing peer-visible memory early.
- [x] Run VxD host sanitizer/control/ABI tests and rebuild native VxD artifact.
- [x] Record unchanged actual-Windows runtime gate and create a scoped reviewed commit.

## Task 4: Integration, independent review and reproducible gates

**Owner:** Master/Validation Lead. **Files:** `docs/agents/*`, status reports and focused aggregate validation tooling if needed.

- [ ] Review all cross-subsystem declarations and complete task reports.
- [ ] Build fresh Kernel32/64 and EFI sources after the final source change.
- [ ] Execute appropriate native kernel, bridge and firmware tests; retain logs and source/artifact hashes.
- [ ] Resolve blocking findings through the responsible lead and run covering tests.
- [ ] Commit passing source changes incrementally; preserve all failures and remaining acceptance gates.

## Full integration sequence and remaining gates

The user-requested program continues through audit; PMA; synchronization; integrated SMP; retained GOP; high-resolution console; per-process on-demand legacy VGA/SVGA; serialized DOS gateway; VMM/PMA synchronization; common NT ABI; evidence-driven wrapper families; actual Windows 98/Kernel64 requests; stress/regression; release gates. Independent work may run ahead, but integration follows dependencies.

The present three implementation tasks do not discharge integrated SMP, per-process VGA, the DOS-to-VMM replacement contract, actual PMA/VMM wait/signal, all wrapper families or the final actual-Windows GUI/media acceptance matrix. Those remain explicit in INTEGRATION_STATUS.md until exercised in real execution.

## Persistent final goal: VMM connection, full boot, SMP and final ISO

The user explicitly set the continuing goal to actual Windows98 VMM connection, complete boot, integrated SMP and the final ISO. Passing the current component slice does not complete that goal.

### Task5: Actual replacement-DOS Windows98 boot and native VMM delivery

Root owns the isolated boot integration and private input/output receipts. Windows lead owns the actual VMM endpoint/callback implementation, authoritative context and serialized DOS boundary; Fada retains the PMA service contract. Reuse the inactive primary boot/cb43 lanes' tested sources and preserved failed observations after inspection; do not modify their outputs or main checkout.

- [x] Integrate reviewed genuine FreeDOS DOS/XMS compatibility and persistent Kernel32 service changes using three-way source merges, retaining current compiler, timer and IPC hardening.
- [ ] Reproduce and resolve actual WIN.COM→ScanReg restart/return behavior, preserving original-Microsoft-DOS control separately.
- [ ] Run actual ShizukuDOS→WIN.COM→VMM→USER/GDI/Explorer and existing Win32 applications under Supervisor; record live native boot evidence.
- [ ] Load the actual VxD and execute Windows98 app→wrapper→PMA worker→terminal result, including wait/signal, cancellation and lifecycle cleanup.
- [ ] Exercise genuine serialized DOS services with verified VM/thread/PSP/InDOS/error context and retained Windows semantics.

Current resources: local free space remains below the17GiB native preparation floor. The verified private NAS ext4 workspace supplies a6GiB root lane with the same17GiB reserve and explicit copy/VM/producer budgets. Other chats retain their assigned lanes and evidence.

### Task6: Integrated native SMP with Windows98 kept single-vCPU

SMP integration lead owns CPU bringup/per-CPU design and independent native requirement tests in a separate worktree. Core owns the scheduler service fix first; shared production interfaces must be reviewed before merges.

- [ ] Bring up BSP/APs with per-CPU GDT/IDT/TSS/stacks and interrupt/timer state, retaining UP fallback.
- [ ] Make allocator, MMU shootdowns, object/wait/driver state and syscall stack bookkeeping safe before executing shared native workers on APs.
- [ ] Implement Kernel32 and Kernel64 per-CPU ready queues, affinity, load balancing and interprocessor wakeup/IPI while preserving runnable conservation and useful work; wrapper workers use the integrated service-domain CPUs.
- [ ] Integrate per-CPU VMX/host-state banking and kernel-domain virtual CPU support, with the actual Windows98 domain pinned to one conservative vCPU.
- [ ] Execute source-bound multi-CPU stress with per-CPU useful work, migration, affinity, wake races and UP regression; AP parking alone is not SMP acceptance.

### Task7: Final reproducible ISO and release verification

Root coordinates with the inactive primary ISO owner through the existing cross-chat ledger and preserves the official distribution contract.

- [ ] Consolidate reviewed source and run all full-goal runtime gates on that exact source identity.
- [ ] Build the final project installer ISO with complete corresponding public sources and notices, keeping private Microsoft media out of public artifacts.
- [ ] Test ISO cold boot/install/installed restart, actual Windows98/VMM/PMA path and SMP on supported firmware; retain checksums and exact source/artifact receipts.
- [ ] Deliver the final ISO and only claim1.0/full completion when the above evidence exists. Official public ISO distribution remains exclusive to m98.nyase.kr; no competing blind release.


Checkpoint — reviewed source successors (2026-10-01):
- Canonical b5c49d8 includes 3cbc1f8, which binds Kernel32 IPC validation to compiler-discovered project headers and tools; persistent drift controls and seven actual endpoint cases per compiler passed. Native PMA VxD/client source is committed as 9853325 after independent F4/F5 review: strict i486 VxD,21 host groups and245 client assertions per GCC/Clang sanitizers passed. Failed alias unlocks remain retained, and notification holds fence event lifetime. Actual Windows VMM/caller delivery and DOS execution remain unverified.
- Fresh four-profile212-input build after the PE loader correction passed172.313s, Kernel64S9d8fed5. Its actual combined KVM guest finished200.94s with151 ordinary apps exit0/PMA16/W64loop48; the original refresh check passed first33/useful1015770, but the new arrival assertion failed ready_wait5/remaining4. That whole FAIL and exact source/helper snapshot remain preserved.
- Actual production-scheduler host and native ISR/context RED reproduced a READY coordinator taking its own aged grant. The candidate fixture blocks that coordinator on a finite completion semaphore throughout measurement. The same fresh212-input Kernel64S6518d678 passed natural KVM17/17 and TCG17/17; first_wait4/remaining4/low_charges4/coordinatorBLOCKED1. Scheduler policy and all original bounds remain unchanged. Independent fixture review approved source b5c49d8. Root fresh four-profile212-source build117.152s passed; actual combined KVM38/38 passed210.27s with151 app records exit0/faulted0, PMA16 and48 total loopback (32legacyW64+16PMA), refreshfirst32/useful178744 and arrivalwait4/remaining4. Exact source/helper/serial/build-receipt archive f50c0b80767771085a18f4266834df88a7c85516675f42b9dfd3f90db96e911d preserved. Highest combined review approved that212-source epoch. Same-kernel RAMfb26 checks PASS594.6s with captured6helpers and source-identical prior105-input EFI; actual PS/2/pixels/151apps pass, bindingstable. The prematurely selected360s run timedout93/151 and remainsFAIL; documented900s default used for successor, no kernel bounds changed.
- Isolated boot55a6714 corrects the actual combined DOS startup patch pipeline: five explicit strict patches, rebased standard-mode DX bit0 predicate, no duplicated CBC assembly record. Applying the old complete pipeline failed; the actual old startup body produced98304 failures. Final actual patched body passed294919 assertions each GCC/Clang sanitizers and the22-byte NASM record check. Independent review approved these three files. Actual DOS/FreeCOM component compilation is underway; Watcom archive differs from the manifest pin, so exploratory compilation cannot establish pin-conformant release inputs.
- Isolated SMP b9e9ae5 preserves checked firmware maps and original-RAM-attested SeaBIOS ACPI reads; normal2/4/forced-UP receipts pass with scheduler_cpus1. F6 captured-producer/helper correction and six adversarial helper/reuse controls were independently approved. Frozen Fada backend55b684c4+981debb9 is available for integration. Actual private RED exposes an unreadable level1 page-table ownership gap; proposed common-walker extension passes1567 controls per compiler but is not yet production acceptance. AP execution, per-CPU queues/allocator/syscalls/TLB and Supervisor virtual APs remain open.
- NAS transport failed at21:18:36UTC; the private2GiB copy terminated with EIO before QEMU creation. No Windows VM, Enter or restart ran. Fada owns verified transport/filesystem recovery; root163f has no live NAS handles and holds new NAS writes. Historical USB RED hit17GiBguard and is invalid race evidence. Newv4 realpersistentreplacement RED2fail, correctedGREEN2/full12PASS52.004s and highestF3review accepted; boot cf16a11 commits single-byte-capture receipt policy/digest binding. Root canonical boot import now permitted after local source epoch closure.
- Other-chat collaboration uses shared source handoffs and independent reviews. Fada is implementing a real installed-Windows source/launch producer with explicit WIN.COM invocation and private backups; c957 owns public bilingual site/download verification. Component, source-presence and site checks do not discharge actual Windows98 VMM/desktop, Windows→wrapper→PMA result, full SMP, installer cold boot/install/restart or the final ISO. The full goal remains active.

Root checkpoint: current actual combined guest PASS38/38 and fresh source inventory120/56/17 receiptcd8d1c97, all Windows execution flagsfalse. K32 actualKVM9 evaluator checksPASS0.4s. Isolatedboot dd11b81 imported privateconstructorf7f1aea; c957 later reproduced three actual source validation gaps (extra destination tail +invalid initialFATcluster directory/file). Reviewed peer correctedconstructor9a9e7f8 imported intoisolatedboot as0fca92e; priorf7/sourceRED retained. No actualWin98 producer/preparation/VM proof. Watcom exact01 snapshot unavailable through checkedlocal/officialpaths; explicit prior4fdc pin restoration and same-captured-archive mismatch-refusal correction reviewed/applied/7checksPASS, committed943963c inisolatedboot, exploratory component receipts remain unapproved. NASv4verifiedready6559e06c... with17GiBfloor unchanged; owner allocated163f6GiB. Fresh original-read-leased2GiB controlcopy21714 is underway; noVM yet.

Latest reviewed handoff: isolatedK32 CPU-local FIFO/GS/affinity/live-stack handoff8553ab7, KVM/TCG12 each and host25/14/76/17 each, four controls total(onepositive+three mutants), reviewed CPU0 scope/APunsupported/mask1. RootCore now implements disjointK64 CPU-state foundation; SMPlead actualnormal AP2/AP4/off passed resource-before-INIT/privatearch/physicalIPI/useful-work components withscheduler1, remainingnegative delivery/ACK/lifecycle controls running. Actualfull ordinaryDOSproducer sourcecf16a11 now delegated inprivateNAS6GiBlane, strictpin/physicalWIN31config, freshreceipt only. No Windows98/VMM/wholeSMP/installer/finalISO acceptance.


2026-10-02 parallel continuation: isolated Supervisor physicalAP r2 actual2CPU14/4CPU26/UP6 checks PASS with perAP privatearchitecture/VMXON and bounded2MiBintegrity work; original QA failures preserved. New ownedLAPIC UC proof/realDOS-prefix-work successor is being prepared, so those old artifacts remain separate. Frozen shared-root TLB243-source epoch4 builds and actual24-case concurrency/late-generation controls pass; bounded native2/4/noINVLPG/withheldACK guests now own the sole root componentVMslot. Source adoption awaits their frozen independent reviews. Core owns a new isolated existing-scheduler perCPUdispatch/entry plan; no APscheduler activation follows from architectureONLINE alone.

Other-chat source cooperation: root independently approves Fada exactninefile unifiedentry/conflict seam a3da3329,228originpins/18CPPpreimages/100actualhostcases/4700assertions and110commands0. Fresh mergedfullkernels/Supervisor and actual nativeWindows still required. Root additionally content-verifies current6970 exact24-file PE32artifact16708d6b and allfive historicallegacyproviderDLL contents e99743e3; no install/VM/currentISA/TLS/app/loaderactivation claim. PublicMicrosoftmedia/privateoutput publication staysforbidden; fullgoal active.
