# Kernel64 SMP memory slice — reserved-fence successor

Fresh own tree `/root/Win98-Modern-smp-memory-sentinel-163f-20261002`, branch
`codex/smp-memory-sentinel-163f-20261002`, base
`a269fb5f91a0298453bc40abbb6c5fc2765d136e`. Same thirteen owned paths;
no scheduler/main/public kernel header/ASM/Supervisor/producer writes.
No commit or canonical integration before independent highest rereview.

The prior frozen13 tree, all233 source/receipts and1536-entry archive remain
unchanged at `/root/Win98-Modern-smp-memory-163f-20261002`. Its review
requested P1 changes: a permanent zero-size heap sentinel had `used=1`,
indistinguishable from a live zero-size allocation. Freeing its data pointer
could make list coalescing cross a physical firmware hole.

## Actual reproduction and fix

Both GCC and Clang ASan/UBSan host binaries reproduced actual
`kfree(p2v(0x800000))` returning on the prior source: the complete heap changed
and the first free extent ended at host address `30eff000`, crossing the
reserved hole `[30800000,30801000)`. Heap-fences exits1 in both compilers;
other preexisting controls pass. This is runtime RED, not a static witness.

Permanent fences now use `HFENCE=2`; only live allocated `used=1` blocks may
be freed. The fence rejects before any heap/list/accounting mutation.
Coalescing requires physical adjacency as well as free nodes. A valid
`kmalloc(0)` remains an allocated zero-size block accepted by `kfree`.

The regression compares the complete12MiB heap, list/accounting and hole
bytes after fatal denial in a disposable child. Its fatal lock remains held
and the child exits; it never reuses that lock. The parent then exercises
the verified unchanged state, including zero-size allocation and allocations
and frees in both usable segments. Fence, hole contents and available bytes
remain intact. Both compilers record4126 checks in heap-fences.

Prior shared-memory behavior remains: separate IRQ-save PMM/heap tickets,
identity sampling after IRQ exclusion, original IF restored after unlock,
unknown identity rejection, actual allocated-provenance bitmap, reservation
denial and complete free subrun validation before mutation. Valid partial
page and zero-count frees remain covered. The serialized observer is a live
snapshot, not a lifetime pin. AP callbacks/barriers remain outside tickets,
the UP scheduler, syscall, per-thread GS and VM-map paths.

## Fresh code epoch evidence

All paths below are relative to this successor tree. Native runs use one
captured233-entry source epoch, unchanged fixture
`6761e4cd35de1672406e01dc356303fa84773baf71096fe3fd3a15391f9fed3b`,
unchanged evaluator
`9391e6f28cc5110d2652e11201272bb2226de075529f869135b64d3961ca1e94`,
and full source/helper/tool/input stability guards.

| Record | Actual outcome and SHA256 |
|---|---|
| `build/smp-sentinel-host-red-1/result.json` | Sentinel runtime RED both compilers; `6dd4508cc65b6e66d3b801a8a0d4fdcc676076a57db468d1b4e7574b511865ca`. |
| `build/smp-sentinel-host-green-2/result.json` | PASS16 GCC/Clang ASan/UBSan cases incl fence/legacy observer; 54,026,272 concurrent checks per compiler;446 source/202 external dependencies stable; `cfc96ccbf3d85f7c08c29378db23aef13502848cd1f782a0ca7840cd616fb630`. |
| `build/smp-memory-native-source-2/result.json` | Fresh changed-memory firmware2/4/off each executed once and PASS; `9988bdf5097831a6a5a1fcf208a196f3c46b1240f8ceb8feeca2b91da949bca1`. New epoch, not an old-epoch retry/replacement. |
| `build/smp-sentinel-native-ap2-1/result.json` | Actual memory/AP component PASS under default passing-producer gate; `10162e59588844afd0dd76a71f3d0f0b8c634a0e65c6037bda6e695dd0a00325`. |
| `build/smp-sentinel-native-ap4-1/result.json` | Actual memory/AP component PASS under default passing-producer gate; `e266d4a3faa434feab980c22f450f6c67daea77845752da671b16d2912b005af`. |
| `build/smp-sentinel-admission-green-1/result.json` | PASS30 stopped-VM controls using exact prior failed producer/source in private copies; `efc195777a0503fa7a0206f17cfb9e695fcede86308261c96ea83a1b37c1faa4`. New `--origin-root` makes this modeled old epoch explicit; no guest. |
| `build/smp-sentinel-ap-runner-provenance-1/result.json` | PASS3 F6 persistent helper replacement controls with private archived219 source/prepared receipt; `7861c68bc9c8c6bdfe633c049d1724ad84d131ca72a21d9ae1786df7c2f01375`. |

Actual AP2 identities0/1 and AP4 identities0/1/2/3 each complete128 epochs.
All owners retain their single page, contiguous run and heap simultaneously
before verification/free. Contiguous totals128/256/384/512 as applicable,
single pages128 and heaps128 per CPU, IF1/bad0. AP2 pages60888/60888,
AP4 pages60848/60848, heap320/320, duplicates/corruption0. All128 outstanding
epochs verified. Private AP resources, useful-work hashes and physical F0/F1
ACKs remain passing. Both AP probes have PMA failures0 and SHZ-EXIT0.
Scheduler CPUs remain1 and `whole_acceptance:false` in component receipts.

## Historical failures preserved

Old producer whole FAIL is unchanged
`b4b8c59728b051bd10442f0d2228fc67c4d47b5d2f29ddf4f5543ab7311ac9f4`:
useful loops527473/104, singleton useful-phase FAIL, summary1, QEMU3/EXIT1.
Old admitted AP receipts remain aggregate FAIL with known-failure preservation.
The fresh passing epoch does not demonstrate a Core scheduling fix; Core
source and fixture thresholds are unchanged. No old SMP-off retry occurred.

The complete old1536-entry archive remains in
`build/smp-sentinel-prior-frozen/sources-host-tools-native-controls.zip`, SHA256
`31690137c4f9403ca9e5a9d3c27f39c54dd8897c1e5ca9fb1f808fae5d492a34`,
with manifest `b6efa35d993f986843e2c1d617f2aff3e90edfa3a50854f1f0dc97873fff55e4`.
It includes original runtime concurrency RED, all old native/host/admission
outcomes, dependencies, machines and exact old13 reviewed bytes. Prior AP227
and no-ACPI failures remain untouched. Baseline heap overlap is a client
ownership CHECK in an ASan/UBSan binary, not an ASan runtime diagnostic.

This is a bounded shared allocation metadata/fence successor candidate.
Process page-table mutation/lifetimes, real TLB shootdowns, AP scheduling,
waits/syscalls/drivers, Supervisor/virtual AP, Windows98 VMM and final ISO
acceptance remain open. Highest rereview precedes own commit/integration.
