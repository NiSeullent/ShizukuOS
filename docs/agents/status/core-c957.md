# Core Kernel Lead — c957 synchronization slice

## Scope, ownership and source identity

- Assigned scope: shared native PMA spin primitives and atomic protection in the
  existing Kernel64 NT driver spinlock exports. Audit included existing
  Supervisor/domain, Kernel32/64 scheduler, DOS and SMP boundaries.
- Baseline: `a648e9baa1c57289d50e58d3380827bd9239bc52` (`origin/main` at dispatch).
- Worktree: `/root/Win98-Modern-pma-c957-core-20261002`.
- Branch: `codex/pma-c957-core-20261002`.
- Current implementation commit: `8a74d9ab5938845e56af7a3dc0f611024fc1675d`.
- Initial implementation commit: `f07d0e4ba35a49ab8c86bd6c6058fb6a9e7d8e70`.
- Owned sources: `shizukudos/kcommon/pma_sync.h`, the spinlock section of
  `shizukudos/kernel64/ntdrv_ke.c`, `shizukudos/tests/test_pma_sync.{c,py}` and
  `shizukudos/kernel64/tests/test_ntdrv_spin_host.c`,
  `shizukudos/tests/test_pma_sync_receipt.py` and this status document.
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

Native ticket locks serve issued tickets in order, wrap unsigned 32-bit counters,
and provide non-barging trylock and a release token. A third 32-bit reservation
word serializes ticket issuance so a paused trylock cannot accept a stale owner
snapshot after `next` wraps. It does not protect the critical section or promise
invocation-order admission before a ticket is issued. Fewer than 2^32 outstanding
tickets are required; issued tickets cannot be canceled. Empty, incorrect and
repeated releases in the current acquisition epoch are rejected without changing
counters. Tokens are single-use and must be discarded on release: their numeric
values eventually recur, so a retired token cannot establish ownership or be
diagnosed reliably after reuse. Tokens do not identify a caller's CPU or thread.

The helpers do not alter interrupts, IRQL or affinity. Callers must prevent
same-CPU preemption/reentry and must release before blocking, entering DOS/VMM
or taking a blocking lock. Existing NT IRQL/ISR transitions are unchanged.
The NT host retains fail-fast contention on its current UP backend: spinning
behind a same-CPU nonpreemptible owner would deadlock. Existing driver IRQL,
KPCR, DPC queues and scheduler state still require a separate SMP conversion.

## Tests executed and evidence

Initial verified epoch, command exit **0**:

```text
python3 shizukudos/tests/test_pma_sync.py --tsan --out build/shizukudos/pma-core-admission-final
```

The preserved receipt `build/shizukudos/pma-core-admission-final/result.json` records
`PASS_HOST_SYNC_AND_DRIVER_CONTRACTS` and `source_before_after_match=true`.
Six listed production/header/fixture/runner inputs are hashed; a later independent
review found a missing transitive ABI header, documented below. Extracted Ke/IRQL
bodies come directly from `ntdrv_ke.c`. Hardware CLI/STI/IRQL and DPC flush are
bounded host boundaries, not duplicate lock implementations.

- GCC and Clang ASan/UBSan: each passed actual NT ABI/IRQL/ISR checks and 40,000
  shared publications under ticket and binary locks, with four stress workers.
- Clang TSan: passed 2,000 publications with two stress workers, with no reported
  races. Its explicitly smaller stress configuration appears in the receipt.
- Every variant also checked eight queued FIFO contenders, unsigned rollover,
  no-barging trylock, unchanged trylock token on failure, wrong/empty/duplicate
  release, invalid binary state, and unmatched NT unlock diagnostics.
- Freestanding i486 compilation passed with no undefined runtime symbols.
- `git diff --check` passed before the source commit.

The initial whole production `ntdrv_ke.c` compiled separately in both Supervisor and
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

## Independent-review repairs and followup verification

Peer fd5c's independent review identified two receipt-binding gaps and a ticket
trylock rollover ABA. The initial review is preserved at
`/srv/shizukudos-session-coordination/MESSAGE-fd5c-c957-CORE-REVIEW.md`.
Commit `79afb00ec02931a4f896c033917627d619b25fb0` fixes all three:

- Driver-only verification now always binds the shared production header.
- The runner hashes the exact bytes captured before function extraction,
  rejects a precompile mismatch before starting a compiler, and compares those
  bytes before every command and after the run. Point sampling does not prove
  the absence of transient edits reverted between samples.
- The ticket reservation gate prevents `next` from progressing while trylock
  holds an owner snapshot. The uint32 token lifetime contract is explicit.

The actual-operator regression pauses the production owner load and models
legitimate counter progress through wrap with two outstanding tickets; it fails
the old trylock and checks that the new gate prevents that progress. A separate
regression demonstrates numeric token reuse while releasing only current tokens.
Receipt mutation fixtures exercise the actual runner, using copied sources and
a modeled compiler boundary: one changes the driver-only shared header, another
changes source during extraction. Both must fail verification; the latter must
also retain the digest of the extracted bytes and start no compiler.

Fresh commands, all exit **0**:

```text
python3 -B shizukudos/tests/test_pma_sync_receipt.py --out build/shizukudos/pma-core-binding-green
python3 -B shizukudos/tests/test_pma_sync.py --tsan --out build/shizukudos/pma-core-reservation-green
```

`pma-core-binding-green/result.json` records both modeled-mutation cases passing;
it explicitly records that no compiler or guest ran. The full suite receipt
records `PASS_HOST_SYNC_AND_DRIVER_CONTRACTS`, `source_precompile_match=true`
and `source_before_after_match=true`. GCC and Clang ASan/UBSan each passed 40,000
publications with four workers; Clang TSan passed 2,000 with two workers. Each
checked eight-contender FIFO/wraparound, paused-snapshot admission, token reuse,
non-barging trylock, invalid release and actual NT ABI/IRQL/ISR behavior.
Freestanding i486 compilation again passed without undefined runtime symbols.

Preserved counterfactual red receipts: `pma-core-binding-red` fails both source
binding requirements on the old runner; `pma-core-paused-red` fails the stale
snapshot admission assertion with the old production trylock in GCC and Clang.

The complete production `ntdrv_ke.c` again compiled in both profiles with the
exact shared flags above, changing outputs to
`build/shizukudos/pma-core-reservation-green/ntdrv-ke-supervisor.o` and
`build/shizukudos/pma-core-reservation-green/ntdrv-ke-standalone.o`; the latter
adds `-DSHZ_STANDALONE`. Both exited 0. Current source SHA256 values:

- `ntdrv_ke.c`: `fc5408de1021798f17d8dfb42e2615819bcd6645cad03bcce96f0d355f8460de`
- `pma_sync.h`: `88a9fc6f5c9ab42139bb57a00d30e14324758107f27ba0961b0cfc458cfc0386`
- `test_pma_sync.py`: `2faad8690b939fea0ac901a3011f4646fde7f5278f0bcc88306ee5c4c323728c`

## Complete current project-header closure

The independent child reviewed frozen `79afb00`, found no production defect in
the reservation/token followup, and reproduced the host suite and two mutation
cases. It withheld complete evidence-binding approval because `ntddk.h` also
includes `ntddk_abi.h`, which was not in the six input snapshots. Its own receipts
remain under `pma-core-independent-final` and `pma-core-independent-binding`.

Commit `8a74d9ab5938845e56af7a3dc0f611024fc1675d` adds that ABI header to snapshots
in both modes and adds its persistent-mutation regression. Actual include
inspection and GCC `-MM` checks confirmed the current compiled project closure:
the NT fixture, `ntddk.h`, `ntddk_abi.h`, `pma_sync.h` and generated exact-body
include; the shared fixture includes only `pma_sync.h`. The shared and ABI headers
have no further project includes. The static list must be updated if future
source edits introduce another dependency; the current source is frozen.

The fresh `pma-core-abi-binding-red` receipt reproduces all four failed ABI-header
guard predicates on the old runner. The following fixed-source commands exited 0:

```text
python3 -B shizukudos/tests/test_pma_sync_receipt.py --out build/shizukudos/pma-core-abi-binding-green
python3 -B shizukudos/tests/test_pma_sync.py --tsan --out build/shizukudos/pma-core-closure-final
```

The mutation fixture passes three cases and 13 predicates; no compiler or guest
ran in that fixture. The final host receipt includes seven exact input snapshots
and records precompile/final equality. All 11 recorded compile/run commands exit
0: GCC and Clang ASan/UBSan each 40,000 publications, Clang TSan 2,000, deterministic
FIFO/wrap/paused-snapshot/token/NT contracts, and freestanding i486 compilation
with no undefined runtime symbols. The production NT/header bytes are unchanged
from the separately successful whole translation-unit compilations above.

Current final runner SHA256:
`e3ecb591767025325952b93fef7b8170bab3a2e481205e0ee45e526c9d86039d`.
Bound baseline ABI-header SHA256:
`342c5189910b63341ca19af06943a9f220e0acac3362f9c9e1a4a971c88351e5`.

## Hierarchical independent review

Child `/root/core_kernel_lead/display_validation` independently reviewed display
commit `092c4fe5b27559e23781ab3484f707a37a4796d8`, source read-only. Display HEAD
`ac8dd1ce76aa4f81bc5c0c4a3ec9872b1d9a92d8` only adds its status document;
tested display sources matched the assigned implementation commit.

Both fresh normal and Clang ASan/UBSan runs passed 40 framebuffer handoff and
156,579 clipping/statistics checks. No introduced defect was found. An adjacent
pre-existing `pci.c:mmio_map` page-rounding overflow risk was sent to root for
separate ownership. Root then fixed the display caller's mapping aperture in
`eb567858bb253954150cf087693b1f5bfd4224db` and strengthened its runner in
`c6199b598e7fb84a8f12da2953026f5d09f198ec`. The child independently reviewed
those exact followups and reran fresh normal and Clang ASan/UBSan tests: each
48 handoff and 156,579 clipping/statistics checks passed with 19 dependency
hashes stable. No introduced defect was found. The display source was read-only.

The same independent child reviewed core source `79afb00` read-only, reported
the ABI-header omission above, and was assigned a narrow final re-review of
`8a74d9ab5938845e56af7a3dc0f611024fc1675d` with fresh reruns. It did not
implement core. The child approved current dependency binding and bounded
production lock changes with no remaining actionable findings in scope.

Its final fresh commands, both exit 0:

```text
python3 -B shizukudos/tests/test_pma_sync_receipt.py --out build/shizukudos/pma-core-independent-abi-binding
python3 -B shizukudos/tests/test_pma_sync.py --tsan --out build/shizukudos/pma-core-independent-closure-final
```

Independent results reproduce three mutation cases / 13 predicates, GCC and
Clang ASan/UBSan 40,000 publications each, TSan 2,000, NT contracts and i486
compilation without undefined symbols. All 11 recorded commands exited 0;
seven input snapshots match before/after. The generated include independently
matched extraction from the pinned production bytes. The reviewer changed no
source or commits and confirmed the frozen implementation identity.

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
