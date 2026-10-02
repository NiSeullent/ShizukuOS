# Kernel32 allocator prerequisite — review candidate

Isolated root-owned branch codex/k32-memory-163f-20261002, based d91e1bc.
Production source is uncommitted and held for independent review. Windows98
VMM/USER/GDI/Explorer stay the OS; native Windows stays one virtual CPU.

The existing PMM bitmap/hint/free count and heap list/used count now use
separate ownership through existing pma_ticketlock_t. Local IRQ masking
precedes ticket admission; release precedes original IF restoration. PMM
zeroing remains outside its lock after unique allocation ownership is reserved.
PMM/heap locks are never nested and cannot be used by NMI, recursive allocator
calls, callbacks, waits or context transfer. Initialization is exclusive before
concurrent use. Generic page-table mutation and address-space reclamation are
unchanged and not certified for AP execution.

Zero/overflow/oversized heap allocations refuse before mutation. Invalid frees
retain the existing fatal assertion contract, while validating the heap span
and real allocated block boundary before altering allocation metadata. A forged
header inside valid payload bytes cannot release a real heap allocation.

Actual original production RED, captured source and exact helper before entry:
build/k32-memory-red-4/result.json SHA
e70eb6e5e41dca719a701ca4736580e3b885e084d4306bf58b2ecc9b12b266e7.
Six actual host threads perform1200 held-allocation epochs. Original PMM
reports66 GCC and1295 Clang failures in34800 checks per run. Both original
heap runs reach their unchanged60s deadline and are killed/reaped by the
subprocess runner; the exact cause of those timeouts is not separately proven.
Sources/compiler drivers remain unchanged. Earlier low-address host mapping
collision and Clang dependency-only linker flag failures are infrastructure,
not behavioral RED, and remain in their original directories.

Deterministic size/pointer RED: build/k32-memory-guards-red-5/result.json SHA
9e067ab5d0a895ce8a7d0777ff09d4ff246e13546c2d6ddcf79b2416f6c86fc8.
GCC and Clang each12 checks/8 failures against original source. The invalid
outside-header read causes the original Clang child sanitizer fault; this is
retained. Child assertion observation is an explicit host fatal-path boundary.

Final GREEN: build/k32-memory-green-2/result.json SHA
e931be6fe8ad9afc89742646d8647d1a8bbe19bc273e75302b4f1a62c57923a1.
GCC and Clang ASan/UBSan each pass42000 PMM,34800 heap concurrency/content
checks and162204 guard/exhaustion/reuse checks. Six host actors hold distinct
allocations before checking and freeing, all caller IF states are preserved,
complete exhaustion returns zero and full PMM/heap conservation follows reuse.
All actual project dependencies are copied before compilation and those copied
production/test bytes execute. The helper's exact captured bytes execute through
compile/exec with no project .pyc reuse; separate pre-entry records bind them.
Host IRQ and contiguous low private mappings substitute the actual guest's
architecture/RAM. Host hblock uses host pointer width; this does not establish
32-bit runtime layout or physical AP execution. System headers/support programs
and sanitizer libraries remain the declared host compiler environment.

Real freestanding i486 compilation: build/k32-memory-i486-compile-1/result.json
SHA0cfa05364928596968c51755be44178b54d8c4bbf712858acd64a557872f257c.
Both actual Supervisor and standalone K32 flag profiles compile the frozen
production C. Nine source/header/recipe inputs and five compiler/subtool
identities are pinned before compilation and remain unchanged; actual object
disassembly/undefined symbols contain no out-of-line atomic support calls.
Dependency discovery's earlier environment consumption is not a full toolchain
attestation. This is compile-only, no full kernel link or native guest.

Own outputs before final source/evidence seal are10656556 bytes, below64MiB.
No commit/index/canonical/peer source change, VM, private media, network service
or global configuration change occurred. Independent review, canonical source
adoption, fresh full kernel build/native regression and genuine K32 AP
architecture/timer/scheduler/MM/objects/waits remain required.
