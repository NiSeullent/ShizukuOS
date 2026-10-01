# Core Kernel Lead — c957 synchronization slice

## Scope, ownership and source identity

- Assigned scope: shared native PMA spin primitives and atomic protection in the
  existing Kernel64 NT driver spinlock exports. Audit included existing
  Supervisor/domain, Kernel32/64 scheduler, DOS and SMP boundaries.
- Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52` (`origin/main` at dispatch).
- Worktree: `/root/Win98-Modern-pma-c957-core-20261002`.
- Branch: `codex/pma-c957-core-20261002`.
- Implementation commit: `f07d0e4ba35a49ab8c86bd6c6058fb6a9e7d8e70`.
- Owned sources: `shizukudos/kcommon/pma_sync.h`, the spinlock section of
  `shizukudos/kernel64/ntdrv_ke.c`, `shizukudos/tests/test_pma_sync.{c,py}` and
  `shizukudos/kernel64/tests/test_ntdrv_spin_host.c`; this status is new.
- Scheduler, DOS/BIOS, display, VMM and global planning files were not edited.

The initial audit of `e455f01` was superseded after finding that checkout was
611 commits behind the dispatched baseline. Conclusions about missing current
architecture documents or a missing current Win98 domain were withdrawn.
The current baseline contains `DK_WIN98`, native domain construction and
channel discovery. Historical audit documents remain unchanged.

## Decisions and production integration

Windows 98 remains the product OS and VMM scheduler authority. These locks
protect native backend services and do not convert Windows threads to PMA
threads. Existing Kernel64 NT driver spin exports now call the shared native
word atomics. `KSPIN_LOCK` stays the original pointer-sized `ULONG_PTR`, with
0/1 state and an ABI size assertion; it is not replaced by ticket counters.

Native ticket locks admit callers in ticket order, wrap unsigned 32-bit counters,
and provide non-barging trylock and a release token. Empty, incorrect and
repeated releases are rejected without changing counters. Fewer than 2^32
outstanding tickets are required; issued tickets cannot be canceled. Tokens
validate held state, not a caller's CPU or thread identity.

The helpers do not alter interrupts, IRQL or affinity. Callers must prevent
same-CPU preemption/reentry and must release before blocking, entering DOS/VMM
or taking a blocking lock. Existing NT IRQL/ISR transitions are unchanged.
The NT host retains fail-fast contention on its current UP backend: spinning
behind a same-CPU nonpreemptible owner would deadlock. Existing driver IRQL,
KPCR, DPC queues and scheduler state still require a separate SMP conversion.

## Tests executed and evidence

Final command, exit **0**:

```text
python3 shizukudos/tests/test_pma_sync.py --tsan --out build/shizukudos/pma-core-admission-final
```

The fresh receipt `build/shizukudos/pma-core-admission-final/result.json` records
`PASS_HOST_SYNC_AND_DRIVER_CONTRACTS` and `source_before_after_match=true`.
All production/header/fixture/runner inputs are hashed; extracted Ke/IRQL bodies
come directly from `ntdrv_ke.c`. Hardware CLI/STI/IRQL and DPC flush are bounded
host boundaries, not duplicate lock implementations.

- GCC and Clang ASan/UBSan: each passed actual NT ABI/IRQL/ISR checks and 40,000
  shared publications under ticket and binary locks, with four stress workers.
- Clang TSan: passed 2,000 publications with two stress workers, with no reported
  races. Its explicitly smaller stress configuration appears in the receipt.
- Every variant also checked eight queued FIFO contenders, unsigned rollover,
  no-barging trylock, unchanged trylock token on failure, wrong/empty/duplicate
  release, invalid binary state, and unmatched NT unlock diagnostics.
- Freestanding i486 compilation passed with no undefined runtime symbols.
- `git diff --check` passed before the source commit.

The whole production `ntdrv_ke.c` compiled separately in both Supervisor and
`SHZ_STANDALONE` profiles, exit 0. Exact shared flags:

```text
gcc -m64 -march=x86-64 -std=gnu11 -O2 -Wall -Wextra -Werror -ffreestanding -fno-builtin -fno-pic -fno-pie -mcmodel=kernel -mno-red-zone -mgeneral-regs-only -fno-stack-protector -fno-asynchronous-unwind-tables -fno-ident -fno-common -fwrapv -fno-strict-aliasing -fno-tree-loop-distribute-patterns -I shizukudos -I shizukudos/kernel64 -c shizukudos/kernel64/ntdrv_ke.c -o build/shizukudos/pma-core-checked/ntdrv-ke-supervisor.o
```

The second command adds `-DSHZ_STANDALONE` and changes the output to
`build/shizukudos/pma-core-checked/ntdrv-ke-standalone.o`. Production/header
sources stayed fixed between these compilations and final host verification.
Their SHA256 values are respectively
`fc5408de1021798f17d8dfb42e2615819bcd6645cad03bcce96f0d355f8460de`
and `17a601711bbeff7611e821ddd1f4b9e8485e721ee150193d28afb0bdd514d1ce`.

Earlier evidence is preserved, not relabeled:

- `pma-core-red`: both compilers reproduced the existing unmatched NT unlock.
- `pma-core-api-red`: missing shared API and the unmatched NT unlock failed.
- `pma-core-unheld-red`: both compilers reproduced empty-ticket unlock advancing
  owner without an issued acquisition.
- `pma-core-green`: oversized initial stress exceeded 90 seconds; the original
  runner traceback is a failure, not a pass receipt.
- `pma-core-checked`: ordinary/ASan checks passed; oversized TSan timed out.
- `pma-core-final`: GCC and small TSan passed; ASan stress timed out.

The test's scheduling perturbation was then moved after release to honor the
spinlock no-blocking contract. Final normal operation counts and deterministic
eight-contender checks were retained; the 90-second bound was not extended.
The runner now preserves timeout logs and a failure receipt.

## Hierarchical independent review

Child `/root/core_kernel_lead/display_validation` independently reviewed display
commit `092c4fe5b27559e23781ab3484f707a37a4796d8`, source read-only. Display HEAD
`ac8dd1ce76aa4f81bc5c0c4a3ec9872b1d9a92d8` only adds its status document;
tested display sources matched the assigned implementation commit.

Both fresh normal and Clang ASan/UBSan runs passed 40 framebuffer handoff and
156,579 clipping/statistics checks. No introduced defect was found. An adjacent
pre-existing `pci.c:mmio_map` page-rounding overflow risk was sent to root for
separate ownership. The child did not review this synchronization slice.

## Dependencies, blockers and remaining work

No blocker remains for this scoped source integration. Root owns the combined
kernel/Supervisor build and independent cross-lane review. Ticket-lock consumers
must follow the documented IRQ/preemption contract; replacing existing ISR-shared
or blocking synchronization requires per-call-site review.

Priority/quantum scheduler work belongs to the peer scheduler lane. DOS gateway
admission/execution, AP startup, CPU-local queues/IRQL/KPCR, load balancing,
interrupt routing and actual Win98 VMM synchronization remain separate work.
Existing SPSC IPC rings still require serialized endpoint producers; a shared
lock alone does not make request-table lifetimes or DOS services thread-safe.

These host tests and object compilations provide no SMP kernel, VMX/EPT, Windows
98 boot, driver hardware, DOS replacement or desktop acceptance evidence. No
repository-wide build or guest was run by this lane; root owns those gates.
