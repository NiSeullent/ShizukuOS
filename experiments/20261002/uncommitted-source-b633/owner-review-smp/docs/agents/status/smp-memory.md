# Kernel64 SMP memory slice — frozen review candidate

Own tree: `/root/Win98-Modern-smp-memory-163f-20261002`, base
`a269fb5f91a0298453bc40abbb6c5fc2765d136e`. No canonical or old frozen AP tree
writes. Production source closure remains 233 entries. PMA fixture SHA256 is
`6761e4cd35de1672406e01dc356303fa84773baf71096fe3fd3a15391f9fed3b`.
Overall acceptance remains **FAIL** because the fresh producer's SMP-off run
retains an existing useful-phase assertion failure. No SMP-off retry, fixture
threshold change, scheduler change or failure relabeling was performed.

## Implemented behavior

Actual PMM and heap metadata now use separate internal IRQ-save tickets.
Identity is sampled after IRQ exclusion, tickets are released before original
IF restoration, and unknown CPU identity rejects mutation. Allocated-provenance
bits distinguish live allocations from initial reservations. Free subruns are
fully validated before mutation; valid partial and zero-count semantics remain.
The live table-page observer uses the same lock and allocation meaning. Heap
overflow and invalid/forged/interior free pointers are rejected. Zeroing,
barriers, callbacks and stack switches occur outside allocator tickets.

An opt-in actual AP worker stage performs simultaneous page/run/heap allocation
and free after private AP architecture/interrupt readiness. Scheduler CPUs
remain one; AP callbacks do not enter current-thread, syscall, GS or VM-map
paths. The Core owner acknowledged this handshake.

## Preserved evidence

All paths below are relative to this own tree.

| Record | Actual outcome |
|---|---|
| `build/smp-memory-host-baseline-red-2/result.json` | Runtime RED: GCC loses live page ownership; Clang ASan detects overlapping outstanding heaps. Both compiled successfully. |
| `build/smp-memory-host-green-4/result.json` | GCC and Clang ASan/UBSan actual allocator controls pass; prior bounded source receipt retained. |
| `build/smp-memory-host-bound-green-7/result.json` | Final actual allocator/provider GCC + Clang ASan/UBSan, fourteen cases, including legacy observer entry; 54,026,272 concurrent checks per compiler; complete captured source and discovered compiler/header/runtime dependencies stable. |
| `build/smp-memory-native-source-1/result.json` | Historical normal firmware 2/4/off PASS before the worker flag short-circuit change. Captured source/archive is preserved separately and not substituted for the current failed gate. |
| `build/smp-memory-native-source-2/result.json` | Current fresh normal production kernel/stub: firmware2 and4 PASS; SMP-off singleton useful-phase FAIL, producer whole FAIL. All 233 source entries, artifacts, tools and helpers stable. |
| `build/smp-memory-admission-red-2/result.json` | Pre-implementation private evaluator admission RED; valid bounded controls cannot reach VM boundary. |
| `build/smp-memory-admission-green-2/result.json` | Thirty actual evaluator/private-copy controls: bounded valid2/4 reach stopped VM boundary; failures, changed fixture/source/tool/helper, missing/bad artifacts, compiler errors, profile broadening and post-launch drift reject. No guest launched by these controls. |
| `build/smp-memory-ap-runner-provenance-2/result.json` | Three F6 captured helper controls PASS; persistent helper replacement after load rejects before VM. Prepared archived219 private-copy receipt only; no origin/guest claim. |
| `build/smp-memory-native-ap2-1/result.json` | Actual KVM2 memory/AP component PASS, aggregate FAIL and original known failure preserved. |
| `build/smp-memory-native-ap4-1/result.json` | Actual KVM4 memory/AP component PASS, aggregate FAIL and original known failure preserved. |

The original failed current producer recorded low useful loops `527473/104`,
the unchanged failure `each low-priority policy phase executes useful CPU
work`, summary failures1, QEMU return3 and SHZ-EXIT1. Its receipt SHA256 is
`b4b8c59728b051bd10442f0d2228fc67c4d47b5d2f29ddf4f5543ab7311ac9f4`.

Actual AP-memory2: logical/physical identities0/1; 128 epochs per CPU,
singles128, contiguous pages128/256, heaps128, IF1/bad0. All 128 epochs hold
every CPU's allocations simultaneously. Pages `60888/60888`, heap `320/320`,
duplicates0/corruption0. AP-memory4: identities0/1/2/3, contiguous
pages128/256/384/512, pages `60848/60848`, heap `320/320`, otherwise the same
invariants. Both actual probe executions also retain private AP architecture,
owned startup resources, useful-work hashes and physical IPI ACK gates;
PMA failures0 and SHZ-EXIT0 in those two executions. The admitted original
producer whole failure remains in every result and the final manifest.

AP-memory2 receipt SHA256:
`c9f51ca34def20601f071c3da2de754e4268fbf08666da21c494d32b8f03e235`.
AP-memory4:
`903bad26955b64446fdd7536bba3ba032ae04ce00c312f87812ced72808230d8`.
Final evaluator SHA256:
`9391e6f28cc5110d2652e11201272bb2226de075529f869135b64d3961ca1e94`.

Initialization failures `smp-memory-host-baseline-red-1` (host evidence symbol
collision), `smp-memory-admission-red-1` (unfinished control bookkeeping), and
`smp-memory-host-bound-green-5` (Clang preprocessor rejects unused linker flag)
remain as historical diagnostic artifacts, without runtime RED/PASS claims.
Intermediate green3/6 and producer source1 source-before-loop-guard ZIP remain
distinct. The original 227/503 AP milestone and original no-ACPI/PMA failures
are untouched.

## Scope remaining

Independent highest review is required before own-branch commit or parent
canonical integration. This implements shared allocation metadata and real AP
allocation/free controls. It does not establish concurrent process page-table
mutation/lifetime, TLB shootdowns, AP scheduler registration, waits/syscalls,
drivers, Supervisor AP handoff, Windows98 VMM integration or final ISO boot.
The original whole-kernel failure remains a separate Core investigation.
