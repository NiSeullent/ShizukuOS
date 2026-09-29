# Independent native AHCI read/write path

This original freestanding C implementation takes exclusive ownership of one AHCI
controller, initializes an active SATA disk port, obtains IDENTIFY data, and reads
one 512-byte sector using READ DMA EXT. When the caller opts in at open
(`ahci_config.allow_write = 1`) it also writes one 512-byte sector using WRITE DMA
EXT and flushes the device write cache using FLUSH CACHE EXT. It is a concrete
storage path for **Windows 98 Shizuku's Second Edition**, ready for a separate
native guest binding. Kernel64 (ShizukuDOS 10, standalone profile) links it as its
AHCI block device through `shizukudos/kernel64/ahci_blk.c`.

**Current evidence here is host-model and i486 compilation only.** The receipt
does not claim Windows 98 driver registration, QEMU DMA execution, physical
hardware support, or a bootable Windows storage driver. The earlier `drivers/`
discovery code and plans are preserved.

## Interface and ownership

Include `ahci.h` and compile `ahci.c`. Zero-initialize `struct ahci_device`, provide
`struct ahci_ops` and `struct ahci_config`, and call:

```c
int status = ahci_open(&device, &callbacks, &configuration);
if (status == AHCI_OK) {
    status = ahci_read_sector(&device, lba, sector, sizeof(sector));
    /* A failed read has not changed sector. */
}
int close_status = ahci_close(&device);
/* AHCI_QUARANTINED means keep device, callbacks and DMA memory alive. */
```

The caller owns the PCI function and the entire HBA exclusively. It must have
finished firmware storage use, established an uncached MMIO mapping with the true
ABAR size, enabled PCI memory decoding/bus mastering, and supplied the verified
`01/06/01` PCI class. The core validates these supplied facts and AHCI capability
registers; it does not enumerate PCI, size/map BARs, or grant itself ownership.
Callbacks and destination pointers are trusted kernel interfaces, not user IOCTL
buffers. Calls are serialized; no concurrent use, IRQ reentry, or copied context
is permitted.

The callbacks provide checked 32-bit MMIO reads/writes, coherent contiguous DMA
allocation/release, DMA synchronization/order barriers, a monotonic microsecond
clock and a bounded relax operation. **A virtual address is never inferred to be
a DMA bus address.** An identity-mapped low-memory allocation is suitable only
when the surrounding guest/firmware contract establishes that identity and the
memory remains reserved after ExitBootServices. Real OS bindings need their own
DMA mapping and lifetime implementation.

The single DMA allocation is 4 KiB, aligned to 1 KiB in both CPU and bus address
space. An allocator success transfers ownership even if validation rejects its
returned address/size, so the core can release malformed allocations. Allocator
failure must transfer nothing. The CPU mapping must be writable, disjoint from
the context and other live storage, physically contiguous in the bus address
space, DMA coherent, and stable until release.

| Allocation offset | Bytes | Use |
| --- | --- | --- |
| 0 | 1,024 | 32-entry command list; only slot 0 is submitted |
| 1,024 | 256 | Received FIS area |
| 1,280 | 256 | Command table, including one PRDT entry |
| 2,048 | 512 | IDENTIFY/read bounce buffer |

The core checks 32-bit DMA limits when CAP.S64A is clear, upper-address encoding
when it is set, range overflow and allocation alignment. No scatter/gather,
IOMMU setup or noncoherent cache-line ownership is implemented.

## Controller and command behavior

Open validates AHCI version/capabilities, implemented-port bounds and PCI inputs.
If CAP2 advertises BIOS/OS handoff, it sets OS ownership and waits up to 2.025
seconds for BIOS-owned/busy bits to clear, without forcibly clearing them. It
then enables AHCI mode and disables global interrupt delivery. It disables port
interrupts and stops **every implemented port**: clear ST, wait up to 500 ms for
CR; clear FRE, wait up to 500 ms for FR. Nonselected ports remain stopped.
There is no restoration of firmware state on close.

The selected port must already have an active link; `AHCI_AUTO_PORT` chooses the
first candidate without a known unsupported signature. A cold controller may
report SIG `0xffffffff` and TFD `0x7f` until FIS reception is enabled. The adapter
therefore confirms the ATA signature and ready task file only after installing
its own receive buffer and enabling FRE, while ST is still clear. Unknown
signatures, unsupported devices and missing initial FIS time out or fail without
issuing an ATA command. It does not retry another port after such a failure.
Initial-signature readiness checks BSY/DRQ, without misclassifying the diagnostic
status as an issued-command result: QEMU 10.1 initially reports TFD `0x130`.
Outstanding CI/SACT entries are
rejected before replacing any DMA address. The adapter programs the DMA bases,
acknowledges existing port error/status bits, enables FIS reception, then starts
the command engine. Port multipliers and inherited enabled FIS-based switching
(which requires a larger receive area) are rejected. Cold-link bring-up, power-up
in standby, COMRESET, command-list override recovery and global HBA reset are
deliberately absent. A port requiring them returns an error.

Four ATA opcodes can be submitted: `0xec` IDENTIFY DEVICE, `0x25` READ DMA EXT,
and, only after an `allow_write = 1` open, `0x35` WRITE DMA EXT and `0xea` FLUSH
CACHE EXT. There is no generic command pass-through and no trim, security,
firmware-update or feature-changing command. Every command uses a five-DWORD
Register H2D FIS. Reads and IDENTIFY use device-to-host direction and one PRDT for
exactly 512 bytes; a write sets the command header's W bit (host-to-device) and
one PRDT for exactly 512 bytes copied from the caller before submission; a flush is
a non-data command with no PRDT whose PRDBC must stay 0. Reads and writes use one
sector and validate LBA against both the reported capacity and the 48-bit command
limit. A write buffer must not overlap the DMA block or the device context.
`ahci_flush` requires IDENTIFY word 83 bit 13 (FLUSH CACHE EXT supported) and
otherwise returns `AHCI_UNSUPPORTED` without device access, as do writes and
flushes on a read-only open. IDENTIFY word 85 bit 5 (volatile write cache enabled,
when word 87 marks words 85..87 valid) is reported as `AHCI_FEATURE_WRITE_CACHE`.
A write success means the device completed the command; the data is durable only
after a successful flush. A failed write leaves that sector undefined.

IDENTIFY parsing requires complete ATA data, DMA/LBA support,
valid LBA48 support and a nonzero bounded capacity. Advertised logical sectors
larger than 512 bytes are rejected; legacy absent sector-size information uses
the ATA 512-byte default. If the optional IDENTIFY checksum signature is present,
the checksum must match. The reported model string is decoded and trimmed.
Word 76 speed metadata is not required for READ DMA EXT: the live path confirms
AHCI class, active SATA link and ATA signature separately. A QEMU 10.1 disk
reported word 76 `0x0100` with no speed bits, valid DMA/LBA48 and 512-byte sectors;
those observed fields have a regression fixture without relaxing mandatory data.

Polling checks new host/interface/task-file interrupt errors, link removal, and CI/SACT.
It resamples status **after** command completion to catch a late error racing the
earlier status reads. Both DF and ERR are rejected in that final task-file status;
stale initial status while a command is pending is not mistaken for completion.
After DMA synchronization, PRDBC must be exactly 512 before
the bounce data reaches the caller. Failure leaves the caller's sector unchanged.
Backwards clock readings are errors; a separate one-million-poll bound prevents
a frozen clock from causing an infinite loop. This bound is a fail-safe, not a
replacement for the callback's real time contract.

On any command failure, the device closes and stops the engine before releasing
memory. A write callback may fail after its MMIO write took effect; the core
therefore regards DMA addresses as published from the first attempted base write.
If engine shutdown or register detachment cannot be confirmed, `ahci_close`
returns `AHCI_QUARANTINED`, sets `AHCI_RETAINED`, and retains the allocation.
The caller must preserve it. A later close may retry after external recovery.
The module never treats an unconfirmed stop as permission to free DMA memory.

## Build and test

From the repository root:

```sh
python3 -B drivers/ahci_native/test.py
```

This uses installed Clang/Python/GNU nm and writes only `build/`. It compiles an
i486 freestanding object and requires zero unresolved runtime symbols. It also
runs the asynchronous host HBA model under AddressSanitizer and UndefinedBehaviorSanitizer.
No MMIO, host disk, PCI device, VM, network download, service or package installation
is performed by the test command.

The model checks the actual generated command/FIS/PRDT layout and address fields.
It injects a failure after each baseline MMIO/allocation/sync operation,
including writes that reached the model before reporting failure. Other cases
cover late completion errors, short transfers, unplug, frozen/backwards clocks,
stuck-engine retention/retry, BIOS handoff timeout, occupied command slots,
malformed IDENTIFY/checksum, 32/64-bit DMA limits, sparse port 31, multiple-port
quiescence, initial status clearing, lifecycle reuse, and unchanged output bounds.
Write-path cases check the WRITE DMA EXT header (W bit, one PRDT) and the non-data
FLUSH CACHE EXT header (no PRDT), read-back of written sectors through the model's
media store, unchanged caller input, bounds and overlap rejection without device
access, read-only and no-FLUSH-EXT refusals without device access, fault injection
after each operation of open + write + flush + close, and the same late-error,
short-transfer, unplug, timeout and clock cases as reads for both write and flush.
Cold-signature cases reproduce the initial QEMU register state and require FRE
before delivering SIG `0x101`/TFD `0x130`; ATA success, ATAPI rejection and no-FIS timeout
are tested, along with rejection of inherited FIS-based switching.
Post-command DF-only and ERR-only failures remain separately tested.
The large assertion count includes repeated checks during the frozen-clock test;
it is not a count of independent test cases.

`build/host-tests.json` binds current source/doc/test hashes, compiler version,
i486 object, host test executable and log. It marks guest DMA, Win98 binding and
physical hardware testing false. Any actual guest result belongs in a separate
receipt with the exact linked source/artifact hashes, PCI identity, isolated disk
hash before/after, requested LBAs and returned data evidence.

The intended next fixture uses an exclusively owned QEMU AHCI device and a newly
created patterned disk, with the EFI boot volume on a different controller. Read
first/middle/last sectors, compare all 512 bytes, reject one-past-end without
submitting a command, stop/release successfully, and verify the disk hash did not
change. This directory does not start that fixture; the Kernel64 binding is exercised under
QEMU by `shizukudos/tests/run_k64_disk.py` (reads, writes, flush, host-side image
verification). A native guest pass would
still leave Win98 IOS/CONFIGMG binding, interrupts, PnP/hotplug, reset recovery,
power management, queued/multisector I/O and real hardware support unimplemented.

See [REFERENCES.md](REFERENCES.md) for interface research and source provenance.
