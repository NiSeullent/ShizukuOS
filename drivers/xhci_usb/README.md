# Windows 98 Shizuku's Second Edition — original USB2 EP0 path

This freestanding module implements one USB2 device-descriptor transaction using
this project's xHCI command/event core and descriptor parser. It also provides a
bounded configuration-descriptor probe. Strict GCC/Clang and ASan/UBSan host
checks cover both. The separate [UEFI integration](../../shizukudos/uefi_usb/)
previously read GET8/GET18 from an actual emulated USB2 device and independently
checked DMA, MMIO and shutdown. The separate
[configuration integration](../../shizukudos/uefi_usb_config/) now checks all
four descriptor reads against an actual emulated USB2 tablet, including its
34-byte configuration and terminal shutdown. Each guest receipt binds its exact
source revision and image; historical receipts do not validate later changes.
Neither host nor emulated-guest evidence establishes physical-device or native
Windows 98 USB support.

The supported operation resets one directly connected USB2 root-port device,
enables one slot, assigns its address, reads the first eight descriptor bytes,
evaluates EP0's packet size when needed, reads all eighteen bytes, and parses
them through `ntwu_parse_device`. The configuration variant additionally reads
one configuration's nine-byte header and full bounded blob through EP0, then
validates it with `ntwu_parse_configuration`. Both disable the slot and close
the entire controller session. SET_CONFIGURATION, non-control transfers, hubs,
transaction translators, SuperSpeed, interrupt delivery, class/HID drivers,
Win98 USBD/CONFIGMG integration and physical-device qualification are absent.

## Integration and lifetime

Compile `xhci_usb.c`, `../xhci_native/xhci.c`, and
`../usb_native/ntwu_usb.c`; include `xhci_usb.h`. The existing zero-slot
`xhci_open` and No Op behavior remain available independently. A USB probe
requires `xhci_open_one_slot` and a disposable, exclusively owned controller.
Slot capacity and DCBAA entry 1 are established while the controller is stopped;
the module never changes `CONFIG.MaxSlotsEn` while running.

```c
struct xhciu_request request = {
    sizeof(request), XHCIU_ABI_VERSION, 0, 0
};
struct xhciu_descriptor descriptor;
int opened = xhci_open_one_slot(&device, &callbacks, &configuration);
if (opened == XHCI_OK) {
    struct xhciu_result result = xhciu_probe_device(&device, &request, &descriptor);
    /* result.status == 0 publishes descriptor; the session is already closed. */
}
/* A quarantined session must retain all context/callback/DMA lifetimes. */
```

The request, descriptor and result records are respectively 16, 84 and 20 bytes,
with static layout assertions in both host and i486 builds. `root_port == 0`
selects the sole connected USB2 device; a nonzero value also requires that exact
port. `flags` must be zero. Pointers are trusted, disjoint kernel storage and all
calls must be serialized. No reentrancy, second outstanding operation or IRQ
invocation is supported.

Invalid arguments are rejected before hardware mutation. Operational failures
attempt the shared controller close; the caller's descriptor remains completely
unchanged on every failure, including cleanup failure. Success is published only
after Disable Slot completion, zeroing/synchronizing DCBAA entry 1, and confirmed
close. Successful `failed_stage` is `XHCIU_COMPLETE` (11).

A failed halt/reset or ambiguous hardware detachment retains **both** allocations
and returns `XHCI_QUARANTINED`. `operation_error` preserves the initiating error;
`last_error` can separately record cleanup failure. The returned `transport_error`
preserves the initiating error, or the cleanup error if the transaction otherwise
succeeded. A later explicit `xhci_close` can retry safely. Release callbacks must
never reclaim retained memory. Disabling a slot does not relax the module's
stronger whole-controller shutdown requirement before allocation release.

`xhciu_probe_configuration` accepts a 20-byte `xhciu_configuration_request`
(`struct_size`, `abi_version`, `root_port`, `configuration_index`, `flags`) and
returns the same 20-byte diagnostic record. It uses the same one-slot open and
terminal lifetime. The original device-probe request/84-byte output ABI and
existing stage values are unchanged; configuration header/read/parse stages are
appended. Flags remain zero and the index must fit one byte before mutation.
After the device descriptor is read, the index must be below its advertised
configuration count; failure at that point still closes the started session.

The new `xhciu_configuration_descriptor` is 3,848 bytes: a 16-byte header,
the existing 84-byte device result, nine header bytes plus three reserved bytes,
2,048 raw bytes at offset 112, and the 1,688-byte parsed configuration at offset
2160. Its raw length names only valid bytes; unused raw bytes and reserved fields
are zero. Parser offsets refer to this owned raw copy, so no result references
released DMA. Failure preserves the entire caller record. The configuration
wrapper uses a private scratch record; the runner records a conservative i486
sum of all internal function stack frames, bounded to 16 KiB. Platform callback
and caller frames require additional stack; the existing EFI harness reserves
64 KiB. The original device-only wrapper does not allocate that large scratch.

## DMA and publication

The base controller uses its existing 4 KiB allocation. The one-slot open adds a
contiguous 12 KiB allocation, aligned to 4 KiB in CPU and bus address spaces.
Both requested ranges must be disjoint and satisfy the controller's inclusive
32-/64-bit DMA address limit. Ownership transfers on allocator success even if
returned metadata is malformed. The platform provides actual DMA visibility,
barriers, stable addresses and infallible release; no CPU pointer is cast into a
bus address by the core.

| Additional allocation offset | Bytes | Contents |
| --- | ---: | --- |
| 0 | 4096 | Controller-owned output device context |
| 4096 | 4096 | Separate input context |
| 8192 | 256 | EP0 ring: 15 usable entries and one Link TRB |
| 8448 | 64 | Eight-byte response followed by `0xa5` guards |
| 8512 | 64 | Eighteen-byte response followed by `0xa5` guards |
| 8576 | 64 | Nine-byte configuration header followed by `0xa5` guards |
| 8704 | 128 reserved | Output slot/EP0 snapshot before Disable Slot |
| 8832 | 192 reserved | Original Address Device input snapshot |
| 9216 | 2112 | Up to 2048 configuration bytes plus guards |

Context stride follows CSZ (32 or 64 bytes). Only the input context is software
modified after Address Device; its final contents are the optional Evaluate
input. Snapshots reserve the maximum stride and are software evidence, not
controller addresses. The output snapshot precedes Disable Slot because live
context fields can be invalidated by teardown. A Running EP's output dequeue
pointer is undefined and is never used as a software cursor or success proof.

Device requests consume EP0 entries 0–2 and 3–5; configuration requests add
entries 6–8 and 9–11. Neither operation wraps or reuses the transfer ring. The
first Setup ownership bit stays invalid until the
following Data/Status stages are synchronized, then the Setup cycle bit is
published and EP0's doorbell rung. Command and event cursor/cycle handling,
including their wraps, remains the single shared base implementation.

The complete configuration buffer, including 64 trailing guard bytes, stays in
the final 4 KiB page of the existing allocation. No third allocation or enlarged
DMA block is needed. Static assertions enforce separation from snapshots and
ring storage; transfer preparation also checks the full storage range and that
the requested data does not cross a physical 64 KiB boundary. All unrequested
bytes in each receive region remain guarded and are checked after completion.

## Bounded device profile

Supported Protocol traversal validates aperture bounds, forward links, full
capability bodies and nonoverlapping root-port intervals. Selection requires
USB name `"USB "`, revision **2.00**, and `PSIC == 0`, the specified implied
low/full/high-speed mapping. Explicit PSI tables, other revisions, overlapping
coverage and non-USB2 selection are unsupported. Reported Slot Type is preserved.
The actual PORTSC speed after reset supplies the parser's speed enum.

Exactly one device may be connected to the controller, and its port must already
be powered. No implicit port-power switching occurs. A 100 ms connected interval
precedes reset, all observed change causes are acknowledged before requesting a
new reset-change edge, and 10 ms recovery precedes addressing. PORTSC writes
preserve only PP/PIC/wake fields, set only the requested action, and acknowledge
only observed W1C change bits; they never echo PED or LWS. Disconnect,
overcurrent, unexpected enabled/link state or speed changes abort the operation.

Address Device uses BSR=0, route zero, root-port topology, A0|A1, Control EP type,
CErr=3, DCS=1 and Average TRB Length=8. The controller performs SET_ADDRESS.
Initial EP0 packet size is 8 for low/full speed and 64 for high speed. A 2 ms
address recovery interval precedes GET8. Full-speed packet values 8/16/32/64 are
accepted; a changed packet size uses Evaluate Context A1 before GET18. Low/high
speed must report their fixed 8/64 limits. The complete response must retain the
same first eight bytes and pass the unchanged independent USB parser.

For configuration discovery, both extra requests are GET_DESCRIPTOR (request 6,
type 2), with the zero-based descriptor index in wValue and wIndex zero. This is
different from GET_CONFIGURATION (request 8), which reports current selection.
The selected descriptor's nonzero `bConfigurationValue` is preserved as data;
it is neither assumed equal to index+1 nor sent to the device. Only one selected
configuration is inspected, not all advertised configurations.

GET9 must return an exact standard header (length 9, type 2) whose little-endian
total is 9 through 2,048. An oversized total reports
`XHCIU_CONFIGURATION_LIMIT` before any full-buffer request. GETfull requests
exactly that total; all nine header bytes must be identical across responses.
The unchanged parser validates the complete blob using the observed speed.
Its own 4,096-byte parser limit is unchanged; this transport intentionally has a
smaller cap. Unsupported endpoints/classes remain parser data or explicit
unsupported cases; power fields do not authorize bus power or configuration.

Each request uses immediate Setup, one IN Data and OUT Status TRBs. Only Status
sets IOC; Data sets ISP. Event type, reserved fields, slot, EP0, event-data flag,
alignment, exact current TRB pointer, completion code and residue are checked.
A Data Short Packet notification is correlated and retained until matching
Status success: its nonzero residue fails even when Status itself succeeds.
Zero-residue short notification plus Status success is accepted. Duplicate,
stale and unrelated transfer events fail. Receive-buffer guards are checked.

The probe allows two or four descriptor transfers, at most one Evaluate, 256 interleaved
port events per wait, a one-million-iteration polling failsafe, per-operation
timeouts, and a ten-second total probe budget. Cleanup clears that probe budget
so shutdown still gets its own bounded deadlines. There are no reconnect,
stall-recovery or endpoint-restart retries. Stop Endpoint and Set TR Dequeue
recovery remain future work. Unknown failed Enable Slot completion forms may be
classified as malformed events when their Slot ID does not match the narrow
one-slot profile; they still terminate safely.

## Verification and guest boundary

From the repository root:

```sh
python3 -B drivers/xhci_native/test.py
python3 -B drivers/xhci_usb/test.py
```

These commands use installed compilers/tools and write only the respective
`build/` directories. They launch no VM and access no host USB device, MMIO,
network service, Windows disk, client configuration or package manager.
The USB runner uses strict GCC/Clang, Clang ASan/UBSan and GCC/Clang freestanding
i486 compilation with linked-object undefined-symbol checks. Its JSON receipt
binds all implementation, independent model, runner and document hashes.

The independently written model maintains separate CPU/device DMA shadows and
asynchronous completion cursors. It validates context/TRB encoding, synchronization
ordering, CSZ/AC64 variants, FS packet-size changes, PSCEG edge behavior,
command/event wraps, exact buffer contents, short packets, malformed pointers,
slot/endpoint mismatches, topology, disconnects, clocks and callback failures
before/after effects. It also tests aggregate quarantine and retry without
allocation release while the controller may still own memory. Counts include
repeated polling checks, not that many distinct scenarios.

Configuration extensions retain the independent model's separate hardware
cursors and DMA shadows. Their byte-level oracle verifies request type/index,
length, buffer address, all four Setup/Data/Status sequences, raw output and
parsed topology. Cases cover both context strides and DMA widths, every EP0
packet size, boundary-sized blobs, an allocation whose last page borders 64 KiB,
nonsequential configuration values, every header-byte change, short replies,
stale events, parser rejection, output aliasing, and every baseline callback
failure before/after effects. Parser failure combined with halt/reset failure
must retain both allocations and the initiating diagnostic. These extensions
were implemented with the transport changes; they do not inherit the original
model author's independent-implementation provenance automatically.

The separate `shizukudos/uefi_usb` integration owns actual guest execution.
New-revision evidence must use one emulated USB2 device behind an exclusively owned xHC,
independent physical DMA/context/TRB/event dumps, parser output and stopped-QEMU
proof. An actual negotiated speed and packet size must be recorded; branches
not exercised by that guest retain only host-model evidence. No USB passthrough,
private Windows disk or existing VM belongs in that disposable fixture. The
3,848-byte result cannot replace the old 84-byte result inside the old fixed
proof location: it would overlap the payload. Any configuration integration
must reserve and verify a separate bounded result region.

## Primary references and original provenance

Interface facts follow Intel's public
[xHCI Requirements Specification 1.2b, April 2023, document 625472](https://cdrdv2-public.intel.com/625472/625472_xHCI_Rev1_2b.pdf),
sections 4.3, 4.6.3–4.6.7, 4.9, 4.19.2, 5.4.7–5.4.8, 6.1–6.2,
6.4.1.2, 6.4.2.1–6.4.2.3 and 7.2.2.1.2. USB request, reset and recovery
requirements come from the
[USB-IF USB 2.0 publication](https://www.usb.org/document-library/usb-20-specification)
and the April 27, 2000
[primary specification mirror](https://bitsavers.trailing-edge.com/components/usb/USB_2.0_2000.pdf),
sections 7.1.7.3, 9.2.6.2–9.2.6.3 and Chapter 9.
Consulted September 27, 2026. All implementation and tests are original project
code under GPL-2.0-only. No external USB stack, firmware, SDK, QEMU implementation,
example driver or specification pseudocode was copied. Memory layout, callback
contracts and this bounded fixture profile are project design choices, not
USB-host conformance or certification claims.
