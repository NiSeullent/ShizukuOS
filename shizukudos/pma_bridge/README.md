# Versioned PMA event bridge service

This original GPL-2.0-only service executes event operations and deferred waits
over the existing Shizuku IPC 1.1 rings. Windows 98 remains the product OS and
owns VMM scheduling, Win16 serialization, USER/GDI and its desktop. This service
owns backend event state; it does not schedule Windows threads or introduce VMM
service ordinals. Kernel64 integration and real Windows execution require their
own acceptance evidence.

`../abi/shz_vmm_pma.h` defines the `0x300..0x308` message family. The outer
64-byte message header is unchanged. Request, completion and QUERY information
payloads are each 64 bytes, with fixed widths and layout assertions. Requests
with a different PMA major or unknown required feature bits fail with
`SHZ_E_UNSUPPORTED`; a later minor is accepted when the fixed payload and required
features are understood. Unknown request flags and unsupported operations fail.

The implemented operations are QUERY; manual/auto-reset EVENT_CREATE; WAIT;
SIGNAL; RESET; CLOSE; CANCEL; THREAD_EXIT and PROCESS_EXIT. Manual-reset signal
releases all pending waits and stays signaled until reset. Auto-reset signal
releases the oldest pending wait, or retains one token for the next wait.
Repeated signals do not accumulate tokens. CLOSE invalidates the generation
handle and cancels all its remaining waits. CANCEL identifies one WAIT by its
outer request ID and requires the same process and thread lifetime. Exit
operations apply to the caller's identity: thread exit cancels that thread's
waits; process exit closes its events and cancels all their waits.

QUERY includes the service's current `now_ns` snapshot, independent of the
Windows caller's local clock. A client derives a finite absolute deadline from
that snapshot and its desired duration, checking addition for overflow. Time
spent delivering QUERY and WAIT counts toward that duration. All times use
`SHZ_PMA_CLOCK_UNIT_NS = 1`.

WAIT uses an absolute monotonic nanosecond deadline. Zero is a poll and
`UINT64_MAX` is infinite. A ready event may satisfy a poll immediately;
unsignaled finite waits expire at `now >= deadline`. The runtime supplies the
clock and ticks the service even while no requests arrive. Existing waits are
expired before a newly accepted operation is executed. An accepted deferred WAIT
produces one terminal completion, without an immediate pending reply.

Every accepted request reserves a completion slot before any state change.
WAIT capacity is 64, below the 128 completion slots, so infinite waits leave
room for SIGNAL, CANCEL and exit acknowledgements. Saturated wait admission
returns a `SHZ_E_BUSY` completion. A ready completion stays in the service until
the actual transmit ring accepts it. The runtime retains one unaccepted input
on `SHZ_E_QUEUE_FULL`, drains ready output and retries the same input. Ring
doorbells are advisory; repeated notification does not repeat an operation.

One service thread owns all state. Transport callers must be serialized; the
service has no global locks, IRQ masking, allocation, host pointers on the wire,
blocking calls or callbacks into Windows/DOS. The caller first checks the outer
ring CRC with `shz_ring_pop`; dispatch copies and checks the payload envelope.
The service checks endpoints and channel generation, and requires strictly
increasing nonzero request IDs for accepted requests. Rejected inputs consume no
ID and produce no service completion; the caller may send a bounded error reply.
Only `SHZ_E_QUEUE_FULL` should cause transport admission retry.

The Windows endpoint must supply authoritative PID/TID lifetime generations.
The service cannot independently authenticate a claimed Windows process or
thread. The existing generic VxD transport does not provide that identity binding;
connecting lifecycle callbacks and native Windows wait/event delivery is pending.
Events are private to their process lifetime. Stale event handles and requests
after process/thread exit are rejected.

The identity registry intentionally retains tombstones: at most eight distinct
PIDs and 32 registered TIDs fit in one channel generation. Explicitly increasing
the generation of an exited PID permits that PID's reuse and reclaims its old
thread identities; increasing an exited TID's generation permits that TID's
reuse. An active identity cannot be silently replaced. Unique identity churn can
therefore exhaust the registry and yields `SHZ_E_NOMEM`. A coordinated restart
with a strictly newer channel generation clears the registry, objects, pending
waits and completions. The peer must invalidate its old waits on channel change;
the service does not send old-generation completions into the new channel.
Object slots retire at the maximum 16-bit handle generation. Neither identity
nor handle exhaustion pretends to succeed or resurrects an old lifetime.

`shz_pma_service_shutdown` stops new admission and cancels every admitted WAIT
using the completion slot it already reserved. It preserves previously ready
replies and leaves the queue available for peek/ack; repeated shutdown is
idempotent. Event and identity state becomes closed. A strictly newer channel
restart reopens the service. Kernel64 stops the receive batch at W64 SHUTDOWN,
then bounds reply retries, process cleanup and terminal completion draining to
one 5000 ms deadline. If a peer never drains, the native service returns through
its existing domain-exit boundary. The Supervisor's channel epoch is unchanged.

The freestanding API is:

```c
shz_pma_service_init(&service, self_domain, peer_domain, generation);
shz_pma_service_dispatch(&service, &header, payload, monotonic_ns);
shz_pma_service_tick(&service, monotonic_ns);
/* At endpoint teardown, before draining retained replies: */
shz_pma_service_shutdown(&service);
const shz_pma_frame_t *frame = shz_pma_service_peek(&service);
/* Copy frame->header, push it and frame->payload into the real ring. */
/* Only after successful push: */
shz_pma_service_ack(&service, frame->header.request_id);
```

Run host service and layout verification from the repository root:

```sh
python3 -B shizukudos/pma_bridge/test.py
python3 -B shizukudos/pma_bridge/test_transport.py
```

Generated binaries, layouts, wire samples and receipts stay under `build/`.
The service test receipt includes UTC times, exact commands, source hashes before
and after testing, and artifact hashes. Tests exercise the implementation with
GCC and Clang ASan/UBSan, including timeout equality, identity/handle generation,
private ownership, cancellation/death, exact wait saturation and full completion
backpressure. Independent transport tests exercise actual CRC-checked rings and
serialized service ownership with a concurrent peer. Host verification does not
establish a loaded VxD, VMM event delivery, Windows-hosted completion or SMP.
