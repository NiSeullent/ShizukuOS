# NT priority consuming the CPU queue foundation

Isolated ROOT lane: `codex/nt-cpu-c957-20261002`, based on `b0824e02`.
This is a backend component of actual Windows 98; Windows retains VMM, USER,
GDI and Explorer ownership. Product boot, application acceptance and final ISO
remain open. The website is already deployed and independently verified.

## Source boundary

All 12 imported production paths match reviewed `13d3aba` exactly: the scheduler,
TCB header, queue helper and destination-stack hook; six existing SMP provider
files; and the guarded BSP LAPIC owner helper in `pci.c/h`. Existing NT consumer
`ad6fdfa`, canonical PMA fixture and ROOT's `pe_parse.h` inventory correction are
preserved. No main, memory, firmware-worker or AP-start hook was added.

Independent review found no new UP publication, ticket, stack-lifetime or
process-priority retarget blocker. The ticket is released before stack transfer;
the outgoing stack retains `on_cpu` until destination-stack completion before
POPF. Reclamation requires inactive ownership. NT's outer IRQ exclusion still
protects publication and the complete two-pass retarget on the admitted BSP.
The passive dispatch observer runs under the queue ticket and must not reenter
queue APIs, allocate or block.

Online scheduler mask remains **1**, AP scheduler admission **−2**. Before
topology publication the existing physical identity provider returns BSP0. Its
unknown-owner rejection applies after discovery; this lane imports no startup
caller. Neither physical AP identity before discovery nor concurrent NT object,
allocator, wait, syscall or process-batch safety is established here.

Peer core documents retain their historical 219-file evidence. `pe_parse.h` was
an omitted transitive dependency there; the separately new NT policy helper was
not bound by that older consumer epoch. The current closure is recorded below.

## Completed checks

| Check | Actual result |
| --- | --- |
| Compiler dependency closure | 221 inventory entries, 221 actual GCC-MM units; 397 source and 618 artifact pins; header mutation and omitted-C controls pass |
| Native queue host contracts | GCC and Clang ASan/UBSan each 27 actual scheduler checks plus 13 queue checks; six logical pthread owners, 12,000 attempts, 48 identities conserved |
| NT host successor | GCC O2 and Clang ASan/UBSan each 4,203 checks, zero failures; seven actual production translation units compile; 254 source and 266 artifact pins |
| Four kernel profiles | Fresh compile/link PASS, 95.22 seconds; 221 live/frozen sources, seven tools and ten artifacts stable |
| K32 standalone | Nine original checks plus four provenance/exit gates pass; 468 pins stable, QEMU exit 1 |
| K64 focused PMA | 35 kernel assertions and 11 evaluator checks pass; low useful work 1,025,431 / 1,028,704; 1,000-thread cohort returns every stack page |
| New-kernel NT API guest | All 321 API checks pass, app exit/fault 0/0; whole guest PASS, QEMU exit 1, 2.97 seconds; 1,123 old/new input pins stable |
| Historical broad cohort | 38 original evaluator checks and five outer gates pass, QEMU exit 1, 188.35 seconds; 151 ordinary test executables exit/fault 0/0; 32 legacy plus 16 PMA service assertions; 480 pins stable |

The NT host successor executes the real full TCB/object schemas, native queue
guards and policy helpers, CPUID identity lookup, completion and reaper bodies.
IRQ, process/handle tables, allocation, user copying, TLS and resume remain
declared host adapters. A private topology models the owner on one pinned child
host CPU. No hardware context switch or AP executes. The initial unmodified
fixture compilation RED, extraction setup failure and intermediate GREEN remain
preserved. Independent source/evidence review approved both final fixtures,
including the unchanged older assertions and actual completion/reclaim checks.
Compiler evidence seals local headers and three compiler executables; it does
not separately seal external sysroots, compiler support or sanitizer libraries.
The four-profile producer records base HEAD `b0824e02` and a dirty tree; its
explicit live/frozen maps bind the tested source bytes.

The API guest reuses the exact previously verified two DLLs and current probe
from the older frozen producer, with historical `T_HELLO`; it does not rebuild a
whole runtime. Both producer epochs, sources, artifacts and tools are guarded
independently. The broader historical 151-test application/IPC guest also passes
against this same new kernel. Those are component fixtures; they do not establish
the requested modern applications running inside Windows 98.

Receipts under `build/` remain local evidence, excluded from public publication:

- CPP: `9fa0a6e856fa36639cf6f94311ad1d85516a9dd94528ba9f3218f6434e48f343`
- NT host v3: `4a4e0b420ab2ea6d659d6c21ed29ff35ccf8f014cb002014b45b7102829bfe9f`
- Four-profile verification: `1464c966937a214d353c9889a6d35b3a99767ca56680f68cfbc4ebe3f89ba897`
- Source/driver ZIP: `de693b4cb8fbff569c26413fe6b5e95e63de275c0f758add541bbbf62647aeca`
- K32: `515b636527ef7735d4e4962355afc83824b9a326e5fe97379f97ffaf9ff0aae6`
- Focused PMA: `40c247678584c05b1c9cd96ba3c3a0304bcab262ee2a6e9da7d77d665c40912b`
- API guest: `8661115ce1f1c9b357f942fe194bbfcd4167d9dfe33673ddbc62807167edc319`
- API serial: `10188d3249b39c2dd7f35b774be0a28386e0918572693a2dbf5e987cdce43dcd`
- Broad guest: `123afe030bc4ac65855e3cc153ee0014c981efbdd4563b6c379ab051679e9b76`
- Broad serial: `1957adb64eaa3e4fb83560e7aece0b8fd574e4f5806f2381f9fc451097073a7e`

The earlier whole-guest PMA useful-work failure **361 < 1000** and diagnostic
clone's two later failures remain preserved. This new source epoch passing does
not establish their cause or close those historical failures. No thresholds,
timer charging heuristics or acceptance limits were changed. No native Windows
98, whole SMP, Supervisor AP, modern application, installer or ISO acceptance
follows from these component checks. ROOT uses no private media, NAS allocation
or competing native Windows VM in this lane.
