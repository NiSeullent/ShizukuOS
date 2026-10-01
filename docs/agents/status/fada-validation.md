# PMA bridge independent validation — 2026-10-02

Owned files: `shizukudos/pma_bridge/test_transport.c`, `test_transport.py`, and this
report. Implementation belongs to the portable service and Kernel64 integration
agents. No shared implementation files were edited by this validator.

## Final production transport result

These results were freshly rerun after the root agent acknowledged import of
the peer IPC geometry fix as `c117ce2` and its final private-slot-snapshot
successor as `e0007fc` (peer `c6c6577`). The final frozen service includes process
rundown after thread death and admission shutdown. Earlier baseline results and
the missing-artifact failure below are historical, preceding those imports.

Command: `python3 -B shizukudos/pma_bridge/test_transport.py` — exit 0.

| Validation | Observed result |
| --- | --- |
| GCC optimized real-ring fixture | 37,764 checks passed |
| Clang ASan/UBSan real-ring fixture | 37,716 checks passed |
| Clang TSan real-ring fixture | 37,716 checks passed |
| Separate producer/service threads | 2,000 WAIT/SIGNAL exchanges in each build |
| Independent Python wire decoding | Four CRC-valid CREATE/WAIT/SIGNAL/QUERY replies |
| Freestanding production header | GCC i386/x86-64 and i686-mingw syntax passed |

The fixture executes `service.h` and the existing `shz_ipc.h` channel/ring code.
It has no separate event implementation. It acknowledges production completions
only after an actual ring push succeeds. Coverage includes duplicate requests and
advisory notifications, full transmit-ring retention, owner death while transmit
is full, all 128 completion reservations occupied, deferred WAIT timeout at the
exact deadline, cancellation, thread/process tombstones and higher-epoch reuse,
manual reset/broadcast/close, stale object handles, private PID ownership,
exactly one auto-reset token, initially signaled events, unknown features,
future minor negotiation, malformed CRC/payloads and monotonic session restart.

Python uses independent `struct` offsets and `zlib.crc32`. It checks both the outer
ABI 1.1 header and inner 64-byte payloads: magic/version/size, feature bits,
identity, object, request sequence/status agreement and QUERY capacity/domain
fields. QUERY's `now_ns` snapshot is `0x123456789abcdef`, verifying full 64-bit
encoding at offset 40 without relying on the C type definitions.

The runner saves a PASS receipt only after confirming six source hashes were
unchanged throughout execution:
`build/shizukudos/pma-bridge/transport-result.json`. The C source is frozen at
SHA-256 `4b4cf2b322916f7bdba2e062362c3bba1f4ae586f0c0d9c35e97080a7751cb44`;
wire sample SHA-256 is
`31bf690385fc7358295e7b700c4164830ceb0ce8e443bdc47f969ce81b8e0c76`.
An initial run against the intentionally unsupported service skeleton compiled
but failed on the missing CREATE reply, establishing the test's behavioral red
state before the production implementation passed.

The final rerun receipt binds service SHA-256
`0f84e5d7195631165ab01b4004ceab24a5fa424578af5d581b35e3160c115a7e`
and IPC SHA-256
`17c19bcf8295338c02cbcdb83e3ad4c0618e28f78d62ec3568d1ae50b10a2031`.
The independent service rerun used
`python3 -B shizukudos/pma_bridge/test.py --out build/shizukudos/fada-final-service-review`.
It exited 0: GCC and Clang ASan/UBSan each passed 3,429 checks; freestanding
i486/x86-64 layouts passed. Its
`build/shizukudos/fada-final-service-review/result.json` confirms unchanged input
hashes throughout testing and records the exact commands and artifacts.

## Independent final lifetime and shutdown probes

To preserve the frozen kernel source receipt, additional probes were placed
only in `build/shizukudos/fada-final-lifecycle-review.c`. The harness includes
the existing transport fixture and calls the production service over its real
ABI rings. No implementation or tracked C source was changed. Harness SHA-256:
`b3352ebf5b707d9cda8b0cf4137ca7066ac45ca4a2e4b5b349f4145e0b8204cc`.

Exact commands from the repository root:

```sh
gcc -std=c11 -O2 -Wall -Wextra -Werror -pedantic -pthread build/shizukudos/fada-final-lifecycle-review.c -o build/shizukudos/fada-final-lifecycle-review-gcc
build/shizukudos/fada-final-lifecycle-review-gcc
clang -std=c11 -O1 -g -Wall -Wextra -Werror -pedantic -pthread -fsanitize=address,undefined -fno-omit-frame-pointer build/shizukudos/fada-final-lifecycle-review.c -o build/shizukudos/fada-final-lifecycle-review-asan
build/shizukudos/fada-final-lifecycle-review-asan
```

Both compilers and both executables exited 0, including a fresh rebuild and
rerun against final private-snapshot IPC `e0007fc`. Each executable reported:
`PASS: independent final lifecycle/shutdown over real ABI rings (1612 checks)`.
The probes separately exercise last-thread exit followed by PROCESS_EXIT,
PROCESS_EXIT from an unregistered notification TID after all 32 thread entries
are dead, stale process-generation rejection and higher-generation reuse.

The shutdown probe fills the real transmit ring, admits 64 infinite WAITs and
queues 64 QUERY replies, occupying all 128 completion slots. Shutdown and repeated
shutdown succeed without requiring a free slot, preserve the first ready QUERY
byte for byte, reject subsequent CREATE admission with CANCELLED, and deliver all
64 unchanged QUERY replies followed by exactly one CANCELLED reply for each WAIT
after the peer drains. A second probe preserves an already terminal successful
WAIT while cancelling a different infinite WAIT. Equal-epoch restart is rejected;
a higher epoch reopens the service for a new request sequence.

## Lifetime and capacity contract

The service retains identity tombstones, with eight PID entries and 32 registered
TID entries per channel generation. Increasing an exited PID's lifetime generation
reuses that PID and clears its old thread entries; increasing an exited TID's
generation reuses that TID. Active identities cannot be silently replaced. New
distinct identity churn can exhaust the registry and returns NOMEM. PROCESS_EXIT
for a known process uses process-generation authorization and does not allocate
or revive its notifying thread, so dead/full thread registries do not prevent
process cleanup. Completion pressure still retains the request for transport
retry before admission.

There are 32 event slots, 64 simultaneous WAIT slots and 128 completion slots.
Object slots retire when their 16-bit handle generation is exhausted. A strictly
newer channel restart clears all identities, objects, waits and completions; the
peer must invalidate its old waits when the channel changes. Shutdown preserves
queued replies for drain, while runtime cleanup is bounded by one 5,000 ms
deadline if the peer stops draining.

The endpoint must provide authoritative Windows PID/TID lifetime generations.
The existing generic VxD transport does not authenticate those claimed identities;
native lifecycle callbacks and Windows wait/event delivery remain separate work.

## Portable fixture limits and native quarantine review

The host transport fixture assumes valid ring metadata and SPSC publication. Its
`pump()` is a test adapter without the native worker's 64-frame receive budget
or fault quarantine. It exercises malformed slots that are consumed, including
CRC damage. It does not inject a nonconsuming corrupt producer index: that
HEAD_CORRUPT/PROTO path would repeat in the fixture until the runner's timeout.
Invalid ring metadata returning E_INVALID instead fails its assertion. The
portable passing count therefore does not prove fairness under endless input or
native quarantine/recovery. The ephemeral lifecycle probes have the same limit.

Source review of native `subsys64.c` confirms a 64-frame receive budget, with
HEAD_CORRUPT and E_INVALID quarantined until a newer Supervisor channel epoch;
accepted deadlines and outbound pumping continue outside receive processing.
The native shutdown path also stops trailing RX in its batch. These are source
review conclusions here; this validator did not run the guest acceptance cases.

Final `shz_ring_pop` validates and returns its header and payload from one
naturally aligned private slot snapshot. This prevents later peer writes from
mixing separately checked frames. The snapshot copy is not atomic against a
peer that violates SPSC publication, and the host TSan exchange does not claim
such an adversarial publication guarantee.

## Existing regression baseline

After inspecting the runners, the clean baseline
`python3 -B shizukudos/abi/test_abi.py` passed: 3,665,461 GCC assertions and
3,665,447 assertions each under ASan/UBSan and TSan; i386/x86-64/mingw syntax;
independent legacy/WIN64 decoding; and 6,000 generated/adversarial frames with C
and Python verdict agreement.

The initial direct `python3 -B ntwrapper/vxd/tests/test_vxd.py` failed before any
test because the fresh worktree lacked `NTWRAP9X.elf`. The inspected build command
`python3 -B ntwrapper/vxd/build.py --out build/shizukudos/fada-validation-vxd`
created only isolated local host artifacts. The rerun
`NTWV_HOST_TEST_OUT=build/shizukudos/fada-validation-vxd python3 -B ntwrapper/vxd/tests/test_vxd.py`
passed all 12 groups, including 234 bridge assertions and 2,504 WIN64 bridge
assertions under ASan/UBSan. No dependencies were downloaded or installed.

## Review and evidence boundary

Independent source review found no actionable blocking defect in the final
portable service or its Kernel64 integration. Admission reserves a completion
before identity/event mutation; WAIT expiry and cleanup use that reservation;
the ready queue retains the oldest completion until its exact acknowledgement.
Kernel64 retains requests rejected for completion pressure, retries after output
drains, and fences queued state when the Supervisor advances the channel epoch.
Rollback/equal service restart is rejected. QUERY supplies the service clock
snapshot needed to construct finite deadlines.

The final review additionally confirms that admission shutdown precedes cancellation
and needs no new completion slots; previously ready replies remain unchanged.
PROCESS_EXIT no longer depends on a live notifying thread. Kernel64 stops reading
the current receive batch when SHUTDOWN is handled, leaving trailing requests
unread, and pumps accepted terminal completions during bounded cleanup. No
actionable blocking defect was found in the frozen sources. Runtime source
reviewed: SHA-256
`358ff94fcd401f4d1b6d784b2cef5b249bf24a6fe023526ff3d1b918210ef0e9`.

These are host and freestanding component results. This validator did not execute
the Kernel64 guest, Windows 98, VMM services, a VxD guest, Supervisor hardware or native application
UI. Actual Windows 98 on the ShizukuDOS DOS foundation remains the final desktop
target and requires its separate DOS→VMM/service/driver/application evidence.

## Final acceptance-runner independent review

The corrected c957 unit 4e605359, imported as local 21badda, was independently
reviewed and its committed modeled controls replayed in a separate directory.
All five groups pass: old output is rejected before launch and remains intact;
complete success serial cannot mask statuses -9/0/2/3 or timeout; fresh expected
status1 passes; fresh launch failure leaves no PASS receipt. It launches no VM.
An immutable predecessor copy also reproduces both original defects with a
bounded mocked-QEMU harness. Every modeled artifact is explicitly separate
from actual native execution evidence. No tracked implementation was edited.

The reviewer independently confirms the actual final native receipt remains
PASS38 with QEMU status1, its serial/result hashes unchanged, every one of the
207 kernel source hashes matching current source, and all eight recorded
source/binary inputs matching. The runner correction is Python-only; it does
not alter compiled guest code. The source-bound native guest was executed by
the runtime owner, not this reviewer. No actionable blocking defect remains
within this component's documented serialized ownership/capacity contract.

Independent GREEN controls receipt:
`build/shizukudos/modeled-pma-runner-review/successor-controls-21badda/controls-result.json`
(SHA256 `9df570e25f5ec88c0c9a7737ce5bd08b7c4b2e59ad43714925aa3f8fc83abca5`).
Modeled RED aggregate: `build/shizukudos/modeled-pma-runner-review/modeled-summary.json`
(SHA256 `9ce8fc19d364ce86cec3d8e82496ac031b333a00499dbb75d78aac83476c6f29`).
Actual-native preservation proof:
`build/shizukudos/modeled-pma-runner-review/modeled-native-integrity-check.json`.
These controls neither execute nor substitute for the actual guest.
