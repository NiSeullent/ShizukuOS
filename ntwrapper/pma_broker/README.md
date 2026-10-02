# Win98 PMA broker follow-on

This original portable broker binds PMA requests to a trusted native call context
and retains separately reserved completions for each owner. It is a candidate
for the canonical Windows lead's native endpoint adapter. It is not linked into
the current VxD, and host checks are not loaded Windows/VMM evidence. The first
native QUERY/restricted-event endpoint remains owned by the canonical lead.

The adapter captures the current VM, the `VWIN32_GetCurrentProcessHandle` result,
the `Get_Cur_Thread_Handle` result and VWIN32's device connection in the caller's
DIOC context. These opaque native values are never accepted from a user buffer.
The broker maps them to its own PID/TID slots and monotonically increasing
lifetime generations. Its adapter input has no writable PID, TID, generation,
wire sequence or domain. The canonical lead defines the user IOCTL ABI; this
module reserves no alternative IOCTL numbers.

A single transport owner serializes all broker APIs with the existing native
admission gate. The broker itself acquires no IRQ locks, spins on no gate,
performs no wait and schedules no Windows thread. User-side waits must use actual
Windows events/WaitForSingleObject. The backend's QUERY `now_ns` is the clock for
finite absolute PMA deadlines; the Windows tick counter is not interchangeable.

`ntwp_open` identifies one connection per native process and returns an opaque
session token. Another process/device cannot fetch or acknowledge its replies.
`ntwp_submit` stages a request, reserves its terminal reply and assigns a unique
64-bit ticket. `ntwp_tx_peek` exposes the oldest staged request;
`ntwp_tx_ack` is legal only after the actual channel push succeeds. A full ring
must leave the staged request unchanged. Admission and push/ack must remain in
the same serialized interval, so native death cannot interleave them.

The receiver must call `shz_ring_pop` first, thereby checking the outer ABI and
CRC. `ntwp_receive` then matches epoch/endpoints/ticket/opcode and the exact
payload identity, generation and terminal status. QUERY has a distinct info
body. Every submitted request already owns a reply slot, so receive cannot lose
a completion for lack of storage. `ntwp_reply_peek` is stable until successful
copied delivery followed by `ntwp_reply_ack`; a failed user copy does not ack.
The adapter must preserve terminal error replies emitted by the existing
Kernel64 dispatcher for unqueued service rejections. It must never turn a
local wait timeout into a successful backend cancellation.

`ntwp_thread_dead` is invoked from checked native thread-death control messages;
`ntwp_vm_dead` handles the whole-VM notifications that omit thread notifications.
Unsent work from a dead thread is definitively cancelled locally. Sent work
remains reserved until actual matching peer completion. Final connection close
stages PROCESS_EXIT independently of current/dead thread admission. Closed
owners cannot reopen while rundown or any prior sent completion remains. A
successful PROCESS_EXIT ack plus complete draining permits a strictly newer
owner generation. Native unload is refused while an owner or pending request
exists. `ntwp_restart_proven` is only for a strictly newer Supervisor epoch after
proof that the old channel is gone; its name is an integration precondition,
not a claim that this portable module can prove teardown.

Capacity is explicit: eight PID slots, 32 TID slots, 64 ordinary pending entries,
including at most 48 WAITs, plus 32 thread and eight process cleanup entries.
Thus infinite waits leave room for signal/cancel/control and native death.
A TID slot stays assigned to its original broker PID even after thread death:
the backend retains historical `(PID,TID)` tombstones. Reuse within that PID
requires a newer thread generation; repartitioning TID capacity across PIDs
requires a newer channel epoch. Owner generations do not wrap after 24 bits and
thread generations do not wrap after 32 bits. The high ticket range begins at
`0x8000000000000001`; integration must reserve that range from legacy callers or
use one authoritative sequence namespace for both paths. Raw W64 SEND/RECV
must not inject or steal PMA frames. There is no DOS executor here.

Run `python3 -B ntwrapper/pma_broker/test.py`. The runner records fresh source
hashes, commands, UTC time and outputs under `build/pma-broker/`, rejecting input
drift. Tests exercise the actual broker, production PMA service and real ring
helpers, including full 104-entry lifecycle reservation, owner isolation,
malformed/duplicate completion rejection, out-of-order delivery, manual/auto
reset semantics, unsent thread-death cancellation and backend identity limits.
GCC, Clang ASan/UBSan and strict freestanding i486/x64 layouts are component
checks. Actual authoritative identity capture, loaded VxD/native event delivery,
forced native thread/process death, same-VM replacement DOS boot and SMP need
separate source-bound guest evidence.

Native facts were read from the pinned original Win98 DDK archive at
[commit 0c662d32378b9940ed90aee682f4eb5daf816e6a](https://github.com/fapablazacl/win98-ddk-toolchain/tree/0c662d32378b9940ed90aee682f4eb5daf816e6a).
The original Microsoft headers/manuals are not incorporated here. VMM.INC SHA256
is `d640c2994970fabe36c6d4f47ac94b719554d19dc036807c56fe9252ded6d1b2`;
VWIN32.INC is `cc2bacfd25cdf5cdda3abe3396b1d0389a9a1c09f4226fbfdb7a0bd218049e2e`;
OTHER.CHM is `25bf75cb60f1545147eb868fd2ab2b2452c3d4d559b5e2f440c07a9db187e127`.
Checked topics are kernel/95yu (current thread), 4fnd (current process),
9chj/9cdt (thread death), 9cdu (VM destruction), 4fn9 (DIOC event completion),
4fn7/4fld (native event handle lifetime), and 9f7b (DIOC). These establish service
contracts and adapter requirements, not execution acceptance.
