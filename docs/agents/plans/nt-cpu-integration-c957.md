# NT priority and CPU queue integration

User-approved parallel implementation; isolated ROOT lane based on `b0824e02`.
The reviewed NT consumer `ad6fdfa` must retain its process/object lifetime and
two-pass priority-class contract when consuming the reviewed CPU queue
foundation `13d3aba`. Actual Windows 98 retains VMM/USER/GDI/Explorer ownership.

1. Audit the exact physical CPU identity, local header, assembly and link
   prerequisites before importing the queue. Use the existing production
   provider; do not synthesize an AP identity or enable AP scheduling.
2. Import the minimum coherent reviewed prerequisite source and queue change
   in this worktree, preserving the NT consumer, canonical PMA fixture and
   independently verified `pe_parse.h` inventory correction.
3. Adapt the bounded NT host contracts to execute the actual production queue
   and policy bodies with frozen headers. Exercise queue ownership, nested
   IRQ exclusion, running grants and process-wide priority retarget.
4. Run compiler/header closure checks, actual native queue host contracts and
   the NT contracts. Review the final combined source independently.
5. Freeze and compile all four kernel profiles under a new distinct receipt.
   Keep historical and failed receipts unchanged.
6. Run bounded component guests against those exact new artifacts, including
   the current two-DLL NT probe and the historical broader application cohort.
   Preserve all PMA bounds and whole-guest failures.
7. Publish exact reviewed public-source handoffs to the other chats. Supervisor
   integration consumes its independently reviewed commit after that handoff.

Scheduler online mask remains `1`; AP scheduler admission remains `-2`.
Physical AP boot, Supervisor CPU banks and NT logical affinity are separate
contracts. No hardware/AP/native Windows/installer/final ISO acceptance follows
from host tests or standalone component guests. The original PMA useful-work
failure `361 < 1000` remains open unless its cause is established and corrected;
a passing new source epoch does not erase that receipt. ROOT uses no NAS
allocation, private media or competing native Windows VM in this lane.

The imported `core-k64-cpu.md` plan/status preserve the peer's historical source
and evidence. Its declared 219-file inventory omitted `pe_parse.h`; it does not
establish the corrected full header closure in this lane. Physical identity and
unknown-owner refusal in those host checks use a published modeled topology.
Before discovery the unchanged production provider returns BSP0. This lane
imports no discovery/AP-start caller and relies on BSP-only execution; it does
not establish physical mapping or unknown-AP refusal before publication.
