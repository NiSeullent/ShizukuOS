# Optional V86 disk transfer profile

This is a firmware transfer optimization candidate for the existing native
Windows 98 real-mode disk path. It is not a native Windows storage driver.
No existing runner, source disk, CSM patch list, firmware, or configuration is
changed. A fresh output directory is required.

The pinned SeaBIOS source allocates a 2 KiB permanent low-memory DMA bounce
buffer. Its V86 path splits a 512-byte-sector request into groups of at most
four sectors. The optional patch requests 16 KiB from the same ZoneLow
allocator, records the actual allocated capacity, and falls back to the original
2 KiB allocation if the larger allocation fails. Requests larger than four
sectors can use fewer helper dispatches; the existing traces do not establish
the original request sizes or a performance gain.

The patch also closes an existing error-count gap in this isolated profile.
The raw helper call bypasses the normal `process_op` correction that clears an
unchanged count on error. An AHCI error therefore cannot certify the stale
full chunk count. The optional path reports zero for that failed chunk,
accepts only an explicitly smaller completed count, copies only those bytes
for a partial read, and refuses oversized completion counts before copying.
A short successful completion is treated as an error. Buffer and original LBA
are restored on every dispatched return. A missing or invalid buffer fails
before direct DMA to a V86 caller.

The original segment-aware copy, 64 KiB request limit, AHCI polling/timeout,
single helper mailbox, and read/write behavior remain. CD-ROM sector size is
not changed. There is no data cache, interrupt enable, DBLBUFF removal, native
Windows binary patch, or guessed physical buffer address.

Build an unpatched baseline, then the separate candidate:

```sh
python3 drivers/shizuku_storage/build.py --out build/shizukudos/shizuku-storage-baseline-UNIQUE
python3 drivers/shizuku_storage/build.py --out build/shizukudos/shizuku-storage-v86-16k-UNIQUE --v86-bounce-16k
```

The builder copies only the receipt-pinned private SeaBIOS tree. It does not
download inputs, build or replace CSMWRAP.EFI, or launch a VM. The baseline
must reproduce the original Csm16 SHA exactly. The candidate compiles the
actual copied allocation and transfer function bodies against normal and
sanitized host controls before compiling the real SeaBIOS 16/32-bit APIs.
The original function is also compiled to demonstrate its inflated error
count. Host controls cover chunk boundaries, 512/2048-byte sectors, exact
read/write bytes, 64-bit LBA progression, pointer restoration, partial/error
counts, bounds, and allocator fallback.

Before any native trial, independently review the new source/receipts and
package the candidate through a separate EFI build. The actual allocated
range must survive VMM with reserved ownership, alignment, identity mapping,
and no ROM, GOP locator, or descriptor overlap. Original request counts and
command timing need bounded measurement. The boot budget and free-space
floor remain unchanged. Host compilation does not establish native storage
acceleration, installer completion, or application execution.

The source investigation is frozen at
`build/disk-real-mode-path-investigation-20261001T0744/review.json`
(SHA-256 `608a43c7573a85a3700aa0b67bb2b0cb21f8729a9ad305e9c851629a4cb2fee0`).
