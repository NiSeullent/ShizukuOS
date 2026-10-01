# Core C957: Kernel32 IPC receive progress

Assigned scope: the existing Kernel32 receive loop, a host fixture running its
actual production translation unit, a source-bound local runner, and this unique
status file. Core Lead owns only `shizukudos/kernel32/ipc.c`,
`shizukudos/kernel32/tests/test_ipc_host.c`, and
`shizukudos/tests/test_k32_ipc.py` in the implementation commit. No scheduler,
`k32.h`, user/process, Kernel64 service, outer ABI or root integration changes.

Branch: `codex/pma-c957-core-20261002`, worktree
`/root/Win98-Modern-pma-c957-core-20261002`. Tested implementation commit:
`97bafff78ef4a67cdc07600147b53c03f5168954`.
Test-runner compiler-path followup:
`20d415c0570c9182b140129b6cf8575c1ce0556c`. Production and fixture bytes are
unchanged between these commits.

Peer prerequisites were cherry-picked before this lane:
`7252e3e38c727c1db289548187d2ecd4b9630f61` as local `81e6829`, and
`c6c6577f0f9ec050eb0580d5d6aa8d282e8a7cce` as local `7efaea5`. They retain
their original peer authorship and evidence; they are not this lane's source
deliverable. Earlier synchronization work and historical receipts are preserved.

## Behavior and constraints

Each receive pass makes at most 32 pop attempts. An empty queue ends the pass.
Consumed malformed frames keep their existing counted-and-dropped behavior,
while invalid metadata or a corrupt head that does not advance the tail ends
the pass after one counted error. The thread yields before the next existing
20 ms semaphore wait, including when queued doorbells make that wait return
immediately. The budget is independent of mutable peer ring metadata.

The existing production `handle` and `reply` bodies are unchanged. Routing,
reply fields, pool checks, time, session-end handling and reply backpressure
retain their existing behavior. The attempt bound is not a bound on a handler's
execution time: `reply` still sleeps while its transmit ring is full.

Actual Windows 98 and its VMM remain the product OS and scheduler authority.
This is auxiliary Kernel32 endpoint progress work. It adds no transport,
authentication, restart epoch, lifecycle policy, DOS gate or shared-state lock.

## Verification and preserved failures

Exact local commands, run in this worktree:

```text
python3 -B shizukudos/tests/test_k32_ipc.py --out build/pma-core-k32-ipc-red
python3 -B shizukudos/tests/test_k32_ipc.py --out build/pma-core-k32-ipc-green
python3 -B shizukudos/tests/test_k32_ipc.py --out build/pma-core-k32-ipc-green-bound
python3 -B shizukudos/tests/test_k32_ipc.py --out build/independent-core-k32-ipc
python3 -B shizukudos/tests/test_k32_ipc.py --out build/independent-core-k32-ipc-bound
```

Both use fresh output paths and preserve logs and `result.json`. They create
only local compiler objects/executables and logs/receipts, and run bounded host
processes. They perform no downloads, installs, VM boots, service operations,
global configuration changes, or source/index modifications.

RED ran the original production endpoint. GCC and Clang ASan/UBSan each timed
out with exit 124 in five independently launched cases: corrupt head, invalid
magic, zero slot count, invalid slot size, and continuously replenished input.
Each failed because the actual endpoint did not reach its next wait within the
two-second watchdog. The existing consumed-malformed-then-valid behavior passed
19 checks, and normal ECHO/TIME/SESSION_END passed 33 checks. Strict i486
production compilation also passed. All RED evidence remains under
`build/pma-core-k32-ipc-red`; it is not a green result for the final source.

GREEN ran all seven cases against the final production source, including queued doorbells
in the compliant peer-refill fixture. GCC and Clang ASan/UBSan each passed
365 checks: head 10, magic 11, slot count 11, slot size 11, malformed followed
by valid 19, continuous refill 270, normal requests 33. All 17 compiler/test
commands exited zero. The strict i486 object compile used the current
`kbuild.py` Kernel32 flags, including `-m32 -march=i486 -ffreestanding`,
`-Wall -Wextra -Werror`, no SSE/MMX, and soft float. It produced
`build/pma-core-k32-ipc-green/ipc-i486.o`; no guest execution is inferred.

Independent review identified a compiler-driver provenance issue in the first
runner epoch: it hashed resolved driver paths but invoked bare PATH names.
The two-line runner followup invokes those exact resolved paths. The original
RED, GREEN and first independent receipts remain preserved; they are not used
to claim that corrected invocation binding. Fresh `green-bound` and
`independent-core-k32-ipc-bound` each reproduce the 365 checks per compiler,
17 successful commands, and strict i486 object compile with the corrected
runner. Their compile command paths match their recorded `/usr/bin/gcc` and
`/usr/bin/clang-21` driver paths.

The host fixture includes the complete actual `ipc.c`, actual `k32.h`, and
actual ABI headers. Only privileged hypercall/time/vector/notify and semaphore/
scheduling boundaries are replaced. The refill fixture consumes real replies
and publishes real requests, then invokes the actual doorbell handler. It runs
synchronously without an invented concurrent shared-memory C data race.

The receipt records exact commands, return codes, outputs, compiler hashes,
binary hashes, and seven current project inputs: endpoint, fixture, runner,
`k32.h`, `khc.h`, `shz_abi.h`, and `shz_ipc.h`. Those files form the complete
current project include closure; system headers/runtime are supplied by the
local compiler environment. Every command checks source/compiler/binary
stability, and the final before/after guard was true. Hashes:

```text
ipc.c                 aedac9a030f22b379e844a66c72ed159cecc4b8796f22218f32dc85e1bab8bd2
test_ipc_host.c       165391eb9704f8e4f0a65b0f2a5d7a9439e710a3bccfd47893dc37b799359e21
test_k32_ipc.py       6fe78436f8d48c5df143cbf7b3018bd686a4db77004a5bcd68594fa7fcef4531
ipc-i486.o            1a3929dbafc9e84f58aa335accc903c2f47ada6341d7139ae89844ab554cac4b
```

## Independent review and remaining work

The independent child reviewer approved the receive logic at `97bafff` and
the compiler-path correction at `20d415c`, with no remaining scoped finding.
Its fresh final receipt is
`build/independent-core-k32-ipc-bound/result.json`. It independently recomputed
all seven input, compiler-driver and binary hashes after execution; all match.
This lane is ready for integration. Root owns merged-source build and acceptance after
importing this source commit and the separately owned prerequisites.

These checks establish receive-loop host behavior and an i486 compile contract.
They do not establish real scheduling timing, SMP support, hostile-peer atomic
publication, generic guest memory mapping safety or actual Windows 98/VMM
acceptance. Ring geometry and storage lifetime retain the existing caller
contract. No full kernel build or guest/Windows 98 test was run in this lane.
Before/after checks are point samples; transient reverted edits and the
compiler's entire system toolchain are not attested by driver-file hashes.
