# Prospective native device epoch gate

`native_device_epoch.c` implements a bounded readonly PCI observation and
challenge/report/grant protocol. It is deliberately unintegrated. Its callbacks
cannot write PCI configuration, program VGA, reset a device, submit DMA or write
disk sectors. Existing default RAM behavior, 136-byte VGACFG and 192-byte
W98PERS layouts are unchanged. No constructor, loader, source list, QEMU recipe,
guardian or VM has been modified by this component.

`protocol_admitted` means only that the frames and observations passed these C
checks. It does not mean the device is physically authorized. Host fixtures do
not establish an actual owned QEMU process, QMP peer, channel, BAR size, resource
mapping, backing ESP, cache policy, firmware handoff or live device epoch.

The caller supplies one exclusively owned, zero-initialized `w98_epoch_gate_t`,
immutable expectations derived from the exact validated configuration bytes,
their full SHA256 digests, the VGA ROM digest when selected, and a fresh
32-byte nonce already bound to the current owned host attempt. Reuse of that
nonce in another object is not detectable by this helper: freshness and channel
origin are mandatory outer custody obligations. Never clear/reuse the gate
within a process/resource epoch, including after refusal. Calling a consumed
object refuses and removes its protocol-admitted state.

The original absolute deadline is supplied in `now()`'s monotonic units. The
helper never adds a duration, resets or extends it. Every PCI and transport
callback is checked before and after; time at the exact deadline or backward
time refuses. Callbacks must be bounded and nonblocking. Zero transport progress
uses `pause()` and remains limited by both the deadline and a total4096-call cap,
including when a broken modeled clock does not advance. This cannot preempt an
unbounded callback; real integration must prove the callback implementation and
reserve this gate's interval inside the existing controller deadline.

All frames have explicit little-endian fields; never cast a native struct to
the wire. Bytes0..15 are magic `WDE1`, version u16=1, kind u16, byte extent u32,
and selected-device count u32. There are no variable rows or permissive parsing.

| Frame | Bytes | Body |
| --- | ---: | --- |
| Challenge, kind1 | 48 | count0; exact expected nonce at16 |
| Report, kind2 | 256 | nonce16; VGA config SHA48; storage config SHA80; ROM SHA112; original absolute deadline u64 at144 |
| Grant, kind3 | 272 | selected count; exact complete256-byte report echo at16 |

Report slots start at152 and200. Each48-byte slot contains BDF u16, role u16
(VGA1/storage2), reserved u32=0, and ten observed PCI DWORDs at offsets0,4,8,12,
16,20,24,28,32,36. Unselected slots and the last8 report bytes are zero. Rows
use unique bus0 BDFs and increasing unique roles. Known selected QEMU identities
are VGA1234:1111/class030000 or virtio1af4:1001|1042/class010000, header type0.
Raw six BAR DWORDs and required/forbidden command bits must match expectations.
Malformed or unassigned BAR expectations, duplicate functions/roles, missing
selected digest, hidden unselected resources and malformed frame headers refuse.
This performs no BAR-size probe and cannot infer a size from address bits.

The helper receives the challenge, observes selected PCI state, sends its
canonical report, receives a single exact report-bound grant, then reads PCI
again. Any changed ID, command/status, class/revision, header or BAR refuses.
No other CPU/firmware/device-resource writer may run during this stage: these
sequential reads are not an atomic hardware snapshot. Keep the record/report
for a separately pinned outer receipt; its SHA may be computed by the host.

Required future wiring is a pre-device constructor hook before either VGA
initialization or virtio PCI/BAR/reset/DMA writes and before any L2/RUNNABLE
state. A separate typed per-attempt nonce/policy or equivalently reviewed
channel bootstrap must supply the expected nonce; existing blobs contain no
such field. A private Supervisor-only socket UART can exchange the frames.
Its inherited descriptor and sole host endpoint must be held by actual custody,
and guest I/O must never reach that control UART. Ringbuf-write is not UART
input and cannot substitute for this duplex transport.

Before emitting a grant, actual custody must validate its exact Popen, pidfd,
starttime, executable/argv/source leases and freshly checked QMP SO_PEERCRED;
the controller remains the sole QMP reader. Stop/query-status must prove paused
within the original deadline. Bounded current query-pci and native report must
match the exact prepared config/ROM hashes, numeric IDs/classes, selected BDFs,
all implemented BAR sizes/types/addresses and actual RAM/MMIO exclusions.
Selected virtio must bind the exact owned ESP inode/block node and observed
cache.no-flush=false. Firmware queues and DMA ownership require real reset
acknowledgment before reuse, and no hotplug/reset/migration/competing writer is
permitted to silently change an admitted resource epoch. Persist that actual
returned proof before the one grant, then native rechecks PCI on resumption.
If expectations mismatch, refuse; never rewrite the loaded ESP or promote an
old QEMU observation to current authority.

The host C tests exercise the real helper with modeled PCI, transport, clock
and provenance. Compiler execution and output readback can be evidenced; full
external compiler/includes/library closure, actual QMP/channel/device access,
Windows boot, durable write/flush and cold-boot persistence remain unverified.

The first fixture attempt had a compiler indentation warning; its raw terminal
failure and source preimage are retained. The first optimized run passed805
checks, but linking ASan/UBSan runtimes failed because the host
libraries are missing. No download or installation was performed. The selected
sanitizer lane instead executes GCC undefined-behavior trap instrumentation;
address-sanitizer coverage is explicitly false. Later test additions compare
literal report config/ROM/deadline/BAR bytes independently of the mocked host
echo and reject altered ROM grants. Historical proof epochs remain unchanged.
