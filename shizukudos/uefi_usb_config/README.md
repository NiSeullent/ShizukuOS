# Windows 98 Shizuku's Second Edition — USB configuration experiment

This separate, original UEFI/x86 experiment builds the bounded USB configuration
probe into the project's existing 64-bit UEFI to 32-bit protected-mode handoff.
**Current status: actual KVM/OVMF configuration-descriptor execution verified.**
The source-specific receipt is `build/qemu-result.json`; compact tracked hashes
and observations are in `VALIDATION.json`. Earlier execution evidence remains
in its frozen archive. No native Windows 98 USB driver, configured USB device or
HID reports are claimed.

The i486 payload finds the exclusively owned emulated `qemu-xhci` controller
behind a PCI-E root port. It uses the original command/event path to receive
GET8, GET18, configuration GET9 and the complete configuration blob (at most
2,048 bytes), then independently parses both descriptor forms. It disables the
slot, clears its DCBAA entry, halts/resets, detaches both DMA blocks, and restores
the saved PCI command word. The experiment sends no SET_CONFIGURATION or class
request. Descriptor indices are zero-based and separate from the returned
configuration value; this fixture requests index zero.

## Ownership and fixed memory

The controller and device DMA allocations remain 4 KiB and 12 KiB, taken only
from private, aligned payload BSS. Identity bus addresses and coherent memory
are valid only for this no-IOMMU disposable QEMU fixture. Release callbacks retain
physical bytes for inspection after the driver has safely relinquished ownership.
If shutdown is uncertain, the driver retains both allocations and the experiment
cannot report success.

The existing 256-byte proof location `0x0200f100` is retained with a different
magic (`0x43425355`) and version (2). Its final three words identify the
configuration result address, byte size and index. An embedded 84-byte device
result provides a redundant copy for independent comparison. The 3,848-byte
configuration output occupies a separate 4 KiB page at `0x0200d000`; the rest of
that page stays zero. Compile-time checks separate the result from the retained
firmware map, kernel handoff and payload, and the verifier checks the fixed
address and every result-page byte.

GET9 uses device-DMA offset 8576 (64 bytes including guards); the full response
uses offset 9216 (2,048 bytes plus 64 guards). Earlier device responses and
context snapshots remain intact. Four requests occupy twelve transfer TRBs;
no EP0 ring reuse or wrap is needed. The command/event cursor and terminal
cleanup are shared with the original implementation.

## Build and host checks

From the repository root:

```sh
python3 -B drivers/xhci_usb/test.py
python3 -B shizukudos/uefi_usb_config/build.py
python3 -B shizukudos/uefi_usb_config/test.py
```

The integration commands write only this directory's `build/`; the driver command
writes its own `build/`. Installed GCC, MinGW, NASM, binutils, Clang and Python
are used without installing packages, starting services, changing client
configuration, accessing host USB devices or launching a VM. The EFI build has
no imports; its freestanding i486 payload must have no unresolved symbols.
Build receipts bind every directly and transitively included project source,
ELF/PE contracts and the exact boot-image hash. Driver receipts separately cover
GCC/Clang/sanitizer tests, failure injection and bounded internal stack frames.

`verify.py` never calls the C parser. It reconstructs the complete 1,688-byte
parsed configuration from bounded physical descriptor bytes and compares the
entire 3,848-byte result and zero page padding. It checks the exact GET9/full
prefix, index/count relationship, endpoint/interface ownership, opaque offsets,
DMA guards, all four Setup/Data/Status histories and correlated events. The
existing independently authored MMIO/device/context checks are reused. Only the
two newly occupied receive ranges are zeroed in a local context-check view,
after those ranges have been fully validated as configuration data and guards.
All other physical bytes remain subject to the previous unused-space checks.

Synthetic verifier fixtures are built separately from the decoder. They include
all supported speeds and packet sizes, both context strides, bounded lengths,
nonsequential configuration values, every result-page byte, every configuration
DMA/guard byte, malformed descriptors, wrong request/event fields, old context
and shutdown failures. Host clock arithmetic and QMP inventory checks are also
retained. None of those synthetic bytes are presented as guest execution.

## Coordinated guest lane

`test_qemu.py` completed one authorized run in 1.879 seconds. Its bounded fixture
uses one vCPU, 256 MiB, KVM/q35, an emulated USB2 tablet,
no NIC, no host USB passthrough, no Windows disk, no public display listener and
an owned UNIX QMP socket. Only a disposable 16 MiB ESP and private OVMF variables
are created during preparation; the guest ESP is read-only. A 45-second watchdog
and final stopped-process check are mandatory.
It refuses conflicting compatibility guests and preserves the existing 20 GiB
root-disk and 6 GiB memory reserve guards. VM-lane coordination is required
before launch while the separate Windows installation is running.

Success requires the current image/source hashes, final protected-mode/core/GOP
handoff, halted CPU, PCI inventory, physical MMIO, both DMA dumps, configuration
result page, and the independent verifier to agree. The controller must be
halted with all DMA registers detached and both allocations released safely.
The harness keeps exact command, PID, firmware/image hashes, raw evidence hashes,
wall time and clean shutdown status. A screen marker alone cannot pass.

The observed tablet was VID/PID `0627:0001`, high speed (480 Mb/s) on xHCI USB2
root port 5, with EP0 packet size 64 and 32-byte contexts. Configuration index 0
returned value 1 and these 34 bytes in the independent physical DMA dump:

```text
09022200010107a032090400000103000000092101000001224a0007058103080004
```

They describe one interface/alternate, one interrupt IN endpoint `0x81` with
8-byte packet and interval field 4, and one opaque type-0x21 record. GET8,
GET18, GET9 and GET34 each have a correlated Status completion. Enable Slot,
Address Device and Disable Slot add three command completions; one root-port
event makes eight retained events. No Evaluate Context was needed for this
high-speed fixture; changed full-speed EP0 packet sizes retain host-only proof.
Both allocations were safely released, all controller DMA pointers detached,
the saved PCI command restored, and the protected-mode/core/GOP handoff passed.

QEMU PID 788938 exited with return code 0, watchdog false, and process absence
was checked. EFI SHA256 is
`2dffac0094a08b3062c1f66610ecc4f3d3742ebabfa7848988b6c19f1db32430`;
the guest receipt SHA256 is
`dab2e05a62164c0e9c54feb3c3b611b4c2d128a964a1876b7234d9a5ceb7151d`.
The separate result-page hash is
`c4f3b93c809805a8717c107c5154c5779f92e2caceb7540c3d3147b952d4a78d`.

## Provenance

All implementation is original project code under GPL-2.0-only. This experiment
reuses the project's existing loader, transition, clock, kernel, graphics, PCI,
xHCI, descriptor-parser and freestanding support code. Its isolated binding and
harness are adapted from the preceding project USB device experiment; the old
files and evidence remain untouched. No external USB stack, firmware SDK,
QEMU source, driver implementation or specification pseudocode was copied.

Wire facts follow the [USB 2.0 specification, April 27, 2000, sections 9.4.3 and
9.6](https://bitsavers.trailing-edge.com/components/usb/USB_2.0_2000.pdf) and
[Intel xHCI 1.2b, document 625472, sections 4.6, 6.2 and 6.4](https://cdrdv2-public.intel.com/625472/625472_xHCI_Rev1_2b.pdf).
The fixed addresses, memory cap, output ABI and disposable-fixture policy are
project choices. Configuration class-specific bytes are retained as bounded
opaque records; their presence does not establish a working class driver.
