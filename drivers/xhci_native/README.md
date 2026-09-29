# Independent native xHCI command path

This directory implements an original freestanding controller and command-ring
path for **Windows 98 Shizuku's Second Edition**. It initializes an exclusively
owned xHC and checks command completions through DMA event memory. The default
zero-slot API runs No Ops; the optional one-slot API supplies shared command,
event and DMA ownership machinery to [the original USB2 EP0 module](../xhci_usb/README.md).
This base alone does not enumerate USB devices or provide class drivers,
Win98 USBD/CONFIGMG integration or interrupt-driver functionality.

The evidence in `build/host-tests.json` is a strict i486 object build and an
asynchronous host controller model under ASan/UBSan. Guest DMA execution and
physical hardware support require separate evidence. This directory starts no VM.

## Integration

Compile `xhci.c`, include `xhci.h`, zero-initialize `struct xhci_device`, and provide
the callback and configuration structures:

```c
int result = xhci_open(&device, &callbacks, &configuration);
if (result == XHCI_OK)
    result = xhci_noop(&device); /* repeat to exercise ring wraps */
int closed = xhci_close(&device);
/* XHCI_QUARANTINED requires preserving device/callback/DMA lifetimes. */
```

The caller verifies PCI class `0c/03/30`, the mapped BAR aperture, memory decoding
and bus mastering. It owns the **entire controller** and has ended all firmware
and other driver use of it. Halt/reset changes controller and attached-port
state; no firmware state is restored. A zero-slot disposable test controller
should have no attached USB devices; the EP0 module requires its documented
single USB2 fixture. The core performs no PCI config accesses, address-space
mapping, IOMMU programming, platform interrupt setup or physical hardware I/O.

Callbacks supply checked 32-bit MMIO, DMA allocation/release and synchronization,
a monotonic microsecond clock and bounded relaxation. USB legacy handoff also
requires the optional byte-write callback; the core rejects that capability
before mutation if the callback is absent. Byte writes prevent an ownership
request from overwriting the BIOS semaphore during a read/modify/write race.
Ownership waits at most one second, disables known legacy SMI enables after
handoff, and releases the OS semaphore only after its DMA is detached.

All pointers are trusted, serialized kernel interfaces. Do not copy a live
device, reenter it from an IRQ, or invoke calls concurrently. MMIO failures may
occur after a write took effect. Allocation success transfers ownership even if
the returned metadata is invalid; failure transfers no allocation. Release is
infallible. DMA synchronization must provide actual CPU/device visibility and
ordering, including the barrier before ringing a doorbell. A CPU pointer is
never converted into a DMA address by this implementation.

## Supported bounds

Supported interface versions are 1.0, 1.1 and 1.2. The core checks structural
counts, mapped ranges, overlapping operational/runtime/doorbell registers,
extended capability bounds, a 4 KiB supported page size and DMA address width.
Controllers requiring any scratchpad buffers are explicitly unsupported.
The zero-slot path does not use device contexts. The one-slot path reserves a
separate output context; its USB consumer honors 32-/64-byte context stride.
Unknown extended capability types are skipped by their bounded forward links;
protocol capability contents are not interpreted as USB enumeration.

One 4 KiB allocation must be aligned to 4 KiB in CPU and bus address spaces,
coherent, contiguous, disjoint from all live storage, and stable until release.
The inclusive allocator address limit is 32 bits when AC64 is clear. The core
checks alignment, size and range overflow. An i486 uses the specified low/high
DWORD order for 64-bit registers; AC64-clear controllers receive low writes only.

| Offset | Bytes | Contents |
| --- | --- | --- |
| 0 | 2048 | DCBAA, 256 pointers; entry 1 reserved for optional one-slot mode |
| 2048 | 256 | Command ring: 15 command entries plus Link TRB |
| 2304 | 1024 | One 64-entry event-ring segment |
| 3328 | 16 | One event-ring segment table entry |

Open waits for controller readiness, halts and resets with deadlines, establishes
ring addresses, and runs with global/interrupter interrupt enables cleared.
`CONFIG.MaxSlotsEn` is zero for `xhci_open` and one for `xhci_open_one_slot`.
It is configured while halted, before Run. No Op (TRB type 23) is the base public
command. The private `xhci_internal.h` also exposes bounded Enable Slot, Address
Device, Evaluate Context and Disable Slot helpers for the EP0 module. These
helpers share the same command/event cursors and are not arbitrary public TRB
submission interfaces.
The Link TRB points to the command segment and toggles its consumer cycle. The
producer publishes payload while ownership is invalid, synchronizes it, then
publishes the cycle bit. Repeated commands reuse slots across both cycle values.

The event consumer checks ownership before reading payload and applies
type-specific reserved-field masks. Command waits validate the exact submitted
pointer, Success code, zero command parameter and expected slot: zero for No Op,
one for this bounded USB mode. Valid port-status events are consumed and counted;
the base command waiter performs no port control writes. More than 256 such events
while waiting for one command is an error. Transfer Events are recognized by the
shared reader but only the USB transfer waiter can accept them. Malformed fields,
controller errors, backwards time and missing completion fail. The ERDP records
the last evaluated event and acknowledges EHB; the event cycle toggles at wrap.
Every polling operation also has a one-million-iteration failsafe if time stalls.

After a command error the core closes the controller. DMA is considered
published before the first attempted hardware address write. Close requires
confirmed halt/reset and clears all ring addresses before freeing memory.
An uncertain shutdown, reset or register write retains the DMA and returns
`XHCI_QUARANTINED`; retry close after platform recovery. A failed ownership-release
write also retains the context for retry, even if DMA was already freed safely.
The driver does not forcibly reclaim BIOS ownership or free active DMA.

One-slot open additionally allocates 12 KiB, aligned to 4 KiB, and checks the
requested CPU/bus range is disjoint from the base allocation and within the DMA
limit. Both allocations are owned before publishing DCBAA entry 1. All cleanup
paths release both only after confirmed halt/reset and detachment; failed halt
retains both. `operation_error` preserves an initiating failure while `last_error`
can record the later cleanup failure. The optional USB consumer performs its
documented slot/transfer shutdown through this same ownership boundary.

## Verification

From the repository root:

```sh
python3 -B drivers/xhci_native/test.py
```

The command uses installed Clang, Python and GNU nm; it writes only this
directory's `build/`. No VM, MMIO, host USB device, disk, network download, package,
service or client configuration is accessed. The freestanding i486 object must
have no unresolved runtime helpers. The host model checks descriptor encoding,
publish ordering, AC64 register order, repeated command/event wraps, interleaved
port events, every baseline callback failure including writes with side effects,
malformed capabilities, malformed completions, DMA width/overflow, scratchpad
rejection, timeouts, frozen/backwards clocks and retained-memory cleanup retries.
The assertion total includes repeated frozen-clock checks, not that many distinct
test cases. The JSON receipt binds source, documentation, object, executable and
log hashes and explicitly marks guest/USB/Win98/physical results false.

A future isolated QEMU binding should provide an exclusively owned `qemu-xhci`
PCI function, a verified BAR mapping and reserved coherent DMA with a proven bus
address. Complete more than 128 No Ops, inspect returned pointers/codes and both
ring cycles, independently dump DMA memory, and confirm close. Such evidence
would prove controller commands in that fixture, not USB device support or a
Win98 driver. See [REFERENCES.md](REFERENCES.md) for provenance.
