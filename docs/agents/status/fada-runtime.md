# Kernel64 PMA bridge runtime

Assigned scope: extend the existing Kernel64 channel2 service with the versioned
PMA event protocol. Windows 98 VMM keeps scheduling Windows threads; native
Kernel64 workers execute through the existing scheduler.

Owned files:

- `shizukudos/kernel64/subsys64.c`
- `shizukudos/tests/run_k64_pma_bridge.py`
- this status file

Dependencies: the ABI/service owner supplies `abi/shz_vmm_pma.h` and
`pma_bridge/service.h`. The integration lead owns kernel build provenance and
cached public/project-generated Win64 test input preparation.

Decisions: retain the existing W64 message family and channel transport. The
service thread alone mutates PMA event state. A deferred WAIT reply remains
reserved until the channel accepts it; `peek`/`ack` prevents loss on a full ring.
One temporarily rejected inbound frame is retained until completion capacity
becomes available. Monotonic scheduler ticks supply deadlines in nanoseconds;
QUERY returns that clock snapshot to remote callers. Receive work is bounded to
64 messages per pass. A corrupt producer index quarantines the receive ring
until a newer channel epoch, without stopping already accepted timeout replies.
Messages whose source differs from the bound peer cannot act or receive replies.
W64 transmit retries pump PMA deadlines/completions before retrying their own
frame, so legacy back-pressure cannot hold PMA timeout processing for two seconds.
W64 SHUTDOWN stops new receive admission, cancels accepted PMA waits, and pumps
their reserved completions during cleanup. One 5,000 ms deadline bounds the
entire shutdown transmit/reap/drain phase. If the peer never drains, the native
kernel returns to its existing final domain exit. Supervisor clients must check
the existing `DOMAIN_STATE` exited/failed boundary; an unchanged channel epoch
is not evidence that the stopped service can still accept requests.

Validation: the new acceptance runner rejects a historical real
guest log lacking PMA execution (expected FAIL checks, exit 1). Both standalone
and Supervisor source variants compiled with `-Wall -Wextra -Werror` syntax
checks. Sixteen guest assertions exercise real IPC rings and a separate scheduled
service thread, including full-ring retention, caller clock negotiation and
corrupt-index/metadata quarantine. Mixed W64/PMA saturation verifies timeout
wire arrival before the later legacy reply. Process rundown after the last
thread's exit verifies the reviewer-identified lifecycle regression. The legacy
W64 tests also reject a hostile SHUTDOWN.
The terminal fixture queues an infinite WAIT, fills the transmit ring, then
submits SHUTDOWN followed by a trailing WAIT. It requires cancellation of the
admitted waiter, complete drain and worker exit, with the trailing frame unread.
This profile does not execute Windows 98, a VxD, Supervisor, VMX or SMP.

First actual guest: KVM, 119.93 s, 240 s deadline not reached. PMA 16/16 and
W64 loopback 48/48 passed, with complete source/input hashes unchanged. The
overall acceptance remained FAIL: seven existing GUI-required programs could
not create windows because the initial runner omitted every display adapter
under `-nodefaults`; the log explicitly reports an inactive GUI subsystem.
Failing programs: T_CO_WAIT, T_DIALOG_LIFETIME, T_GUI_PRESENT_CHILD,
T_GUI_TRANSPARENT_COVERAGE, T_OLEACC_LOCAL, T_TASKDIALOG, T_U_OLEACC.
Guest `SHZ-EXIT:1`, QEMU status 3, runner status 1 are preserved in
`build/shizukudos/kernel64s/pma-bridge-final-run/`.

The runner now supplies `-vga std -display none`, matching the existing GUI
runner's supported Bochs VBE adapter, and retains `-nic none`. No fixture is
disabled or weakened by the runner. This is a standalone component adapter,
not GOP acceptance. The input fixture retains its three existing absent-host
keyboard/mouse/wheel SKIPs: this runner supplies no QMP host input, so the run
establishes its software assertions but provides no PS/2 hardware input proof.

Supported-display reproduction after the reviewed IPC private-snapshot correction: PASS,
38/38 acceptance gates, KVM, 218.27 s under the 240 s deadline (no timeout).
Guest `SHZ-EXIT:0`, expected `isa-debug-exit` QEMU status 1, runner status 0.
All 151 ordinary app exit records are exit 0 without a fault, including all
seven GUI programs that failed with the missing adapter. PMA reports 16 passed,
0 failed; W64 slot 31 is `0x57343000`, 48 passed, 0 failed. The existing W64
fixtures retain console relay, eight-frame ACK back-pressure, pool-carried
CREATE, kill/release, four-process capacity, malformed input and hostile-source
coverage. Kernel gates also verify 44 preemptions, mutex count 20,000, SSE
exit 42/42, contained user faults, and no physical-page leak by the five flat
process fixtures.

PMA labels: query negotiation; auto-reset deferred wait; manual-reset broadcast;
timeout; cancellation; stale generation; duplicate request; thread cleanup;
process cleanup; full-ring completion retention; domain restart; corrupt-ring
quarantine; process cleanup after thread exit; invalid-ring metadata quarantine;
mixed W64 back-pressure deadline; shutdown cancels waits and stops admission.

That run's complete 206-file compiled-source manifest equals the kernel build receipt
before the run and remains unchanged afterward. Kernel, boot stub and cached
initrd hashes also remain unchanged, as do separately recorded hashes for the
runner and its baseline/QEMU/provenance helpers (five Python inputs).
Kernel SHA-256:
`b9fdfe02433504fc713912c5379fac514b5e22e91a0084304b2f1d1b8d010f64`.
Its receipt and serial log are preserved separately in
`build/shizukudos/kernel64s/pma-bridge-display-final-run/`.

Final merged validation after the independently reviewed physical-framebuffer
alias correction (`d71ec6c`): fresh four-profile build exit 0, followed by the
unchanged acceptance runner against the complete 207-source manifest. PASS,
38/38 gates, 212.08 s under the 240 s limit, no timeout; guest exit 0, runner
exit 0 and expected QEMU debug exit 1. PMA 16/16, W64 48/48 and all 151 ordinary
app exit records again pass without faults. No Kernel64/PMA/W64 FAIL line is
present. The complete manifest, compiled inputs and five evaluator/helper
hashes stay unchanged. Latest Kernel64 SHA-256:
`c4473ffbb3a29b56127bd35763263a5060a07f4f0a1db943880fd09ca8cc8fe8`.
Final receipt and serial log:
`build/shizukudos/kernel64s/pma-bridge-merged-final-run/`.

No runtime implementation work remains; integration review/commit is owned by
the lead. Windows 98/VMM/VxD and Supervisor execution remain separate gates.

Resource limits: the portable service deliberately retains PID/TID tombstones
to reject stale lifetime resurrection. Its advertised finite identity capacity
can exhaust within one channel epoch; an explicit higher process epoch reuses
that process's thread records, and a newer channel epoch resets the registry.
This is a bounded service, not a claim of unlimited or leak-free identity churn.

Implementation commit: `d4615296c27a0ccb27ce1ab344bbd2ed322ce4c8`.
Peer display follow-up: local `d71ec6c`; compiled source is unchanged after its
207-source actual guest PASS. Final runner acceptance successor: local
`21badda`, imported from c957 `4e605359`; reviewed production/test diff and five
modeled controls pass. It requires fresh output and actual expected QEMU status
1 without timeout. Original native execution occurred under its recorded
helper hashes, and those receipts remain intact. Root's recorded-data recheck
confirms actual status 1, real serial gates, current compiled source manifest
and binary inputs; that recheck launches no guest.
