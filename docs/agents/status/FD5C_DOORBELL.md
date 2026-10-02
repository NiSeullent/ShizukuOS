# FD5C Supervisor doorbell wait repair

Date: 2026-10-02 (Asia/Seoul). Baseline:
`a648e9baa1c57289d50e58d3380827bd9239bc52`. Shared integration tree:
`/root/Win98-Modern-pma-integration-fd5c-20261002`.

## Assigned scope and owned files

Repair a pending-doorbell lost wakeup in the existing Supervisor dispatcher.
Windows 98 remains the product OS and VMM remains the Windows scheduling
authority. This change supports existing Shizuku backend domains; it adds no
scheduler and does not convert VMM threads into PMA threads.

- `shizukudos/supervisor/src/domain.c` (only the `SHZ_HC_WAIT` predicate/comment).
- `shizukudos/supervisor/native_win98/tests/doorbell_host.c`.
- `shizukudos/supervisor/native_win98/tests/test_doorbell_host.py`.
- This status document.

Other agents own the ABI, video and root integration changes in this shared
tree. This lane performs no Git index, commit or remote operations.

## Root cause and architecture decision

`deliver_events()` sets `doorbell_signaled` after injecting an interrupt, but
the notification mask remains pending until `SHZ_HC_DOORBELL_ACK` clears it.
The old WAIT predicate treated an injected notification as consumed and could
mark the vCPU WAITING with an unacknowledged mask. The existing readiness
predicate intentionally suppresses reinjection after delivery, leaving that
wait without a doorbell wakeup.

WAIT now parks only when `doorbell_pending == 0`. An unacknowledged mask keeps
the running caller runnable whether or not its interrupt was injected. ACK,
notification coalescing, timer behavior, ABI layout/version and IRQ delivery
remain unchanged. This follows the current single-CPU Supervisor dispatch
ordering; it does not introduce an SMP synchronization claim.

## Dependencies and validation scope

The fixture includes the actual production `domain.c` dispatcher, delivery
function and kernel readiness predicate. Only VMCS operations, interrupt
injection, time and the device-polling boundary are modeled. It executes
Kernel32, Kernel64 and Win98 caller kinds. It does not execute guest code,
VMX, Windows VMM, a Windows desktop or the complete PMA/VMM bridge.

The following behaviors are checked:

- notification before WAIT;
- WAIT before a notification and the existing kernel wake predicate;
- injected-but-unacknowledged notification surviving WAIT;
- ACK consuming the mask, repeated ACK returning zero, and subsequent WAIT;
- duplicate/distinct notification mask coalescing;
- interrupt inhibition and later delivery without notification consumption;
- preserved timer fields and independent timer eligibility/delivery.

## Tests executed

`python3 shizukudos/supervisor/native_win98/tests/test_doorbell_host.py`:

- RED: both GCC and Clang compiled the production fixture successfully, then
  failed with fixture exit 2 at the injected-but-unacknowledged WAIT assertion.
  The Python runner exited 1. Log: `build/fd5c-doorbell/red.log`.
- GREEN: runner exit 0; GCC strict warnings and Clang ASan/UBSan each passed
  607 actual dispatcher/delivery assertions. Log:
  `build/fd5c-doorbell/green.log`.

`python3 shizukudos/supervisor/native_win98/tests/test_cpuid.py` exited 0 for
the existing actual production CPUID fixture under GCC and Clang sanitizers.
Log: `build/fd5c-doorbell/cpuid.log`.

The modified `domain.c` compiled with the production Supervisor freestanding
x86-64 flags, `-Wall -Wextra -Werror`, exit 0. Object:
`build/fd5c-doorbell/domain.o`.

`python3 shizukudos/supervisor/native_win98/tests/run_host.py --out
build/fd5c-doorbell/native-regressions` exited 0: all five existing ATA,
string/paging, PIC, constructor and channel cases passed under GCC and Clang
ASan/UBSan (10 compiled/executed cases). Result:
`build/fd5c-doorbell/native-regressions/result.json`; log:
`build/fd5c-doorbell/native-regressions.log`. Root owns integration of the new
doorbell fixture into the persistent regression runner.

## Blockers, remaining work and commit

No implementation blocker. Independent compatibility reviewer approved the
actual source, and root integrated the case into the persistent runner. Root's
combined seven cases passed both GCC and Clang sanitizers (14 executions).
Native VMX/guest proof is not supplied by these host controls.

Separate recorded audit gap: K32/K64 pass non-VMCS SYSCALL/SYSRET and
KERNEL_GS_BASE MSRs through without a per-domain bank, while VMCS MSR
load/store counts are zero. This requires separate isolation work before
expanding to SMP; it is outside this repair.

Code commit SHA: `af06f0e`. Existing historical evidence and
receipts were preserved.
