# Windows 98 Shizuku's Second Edition — USB EP0 execution

Date: 2026-09-27. The original xHCI path now transfers actual device-descriptor
requests to an emulated USB2 device after ShizukuDOS exits x64 UEFI and enters
its own CPL0 32-bit kernel. This extends the controller-only NoOp checkpoint.

The [USB integration](../shizukudos/uefi_usb/) completed GET_DESCRIPTOR requests
for eight and eighteen bytes in an actual KVM guest. The independently dumped
response was `120100020000004027060100000001030a01`: VID `0627`, PID `0001`,
USB 2.0 and a 64-byte EP0 maximum packet. QMP reports the QEMU USB Tablet at
480 Mb/s on logical port 1; physical xHCI MMIO identifies its USB2 root port as
5. These are different numbering domains and are checked separately.

The operation includes port stabilization/reset, Enable Slot, Address Device,
both descriptor transfers, independent parsing, Disable Slot, DCBAA entry
removal and controller shutdown. Two DMA allocations were released, the
original PCI command register was restored, and no quarantine remained.
The 1.765-second run stopped QEMU with return code zero and no watchdog expiry.
The [validation record](../shizukudos/uefi_usb/VALIDATION.json) binds the exact
source/build/artifact hashes, CPU handoff and nine physical evidence files.

EFI SHA-256:
`fd11277f84e3baf1493453b8a5c6186fee88fcc7cfe64b1819a3ceab9bd6979c`
(46,080 bytes). Payload SHA-256:
`c798e9965d353c14d9948dd034fbfcc0bb5874467095deb803cb086923e67109`
(28,066 bytes). The i486 payload uses original project code and has no external
runtime imports. NTWrapper9x core and NTWDDMWrapper9x software presentation
also pass within the same guest.

The original zero-slot xHCI entry point remains available. A separate actual
[regression](../shizukudos/uefi_xhci/VALIDATION.json) completed 130 commands,
eight command-ring traversals and two event-ring wraps using the changed base.
Its new EFI is 36,864 bytes, SHA-256
`8dc6bca6ee5323d7c349378ac35fb2c086edd3b5a3d66909f1413c8c40c8d5d8`.
Earlier archives retain the original controller implementation and evidence.

An independently authored asynchronous host model passes 6,597,254 assertions
in each GCC, Clang and ASan/UBSan run: 1,095 scenarios and 984 injected callback
failures. It checks both context strides and DMA widths, hidden disconnect/
reconnect events, short and mismatched transfers, total time bounds, two-block
quarantine and retry, and preservation of the initiating error during cleanup.
Eighteen separate Python tests exercise corrupted physical evidence. Both
GCC and Clang i486 linked objects require zero undefined helpers.

This guest used high-speed EP0 with an unchanged 64-byte packet size. The
optional full-speed Evaluate Context path remains host-tested only. Device
configuration, HID reports, hubs, SuperSpeed, physical hardware and a native
Windows 98 USB driver remain unimplemented or unverified by this checkpoint.

Windows 98 installation separately advanced from 20% to 53% file copy and was
stopped at a new durable snapshot before sharing the QA guest lane. The native
DLL/VxD/GDI probes have not yet run in Windows. Recoverable installation media
and rebuild copies were moved to private tmpfs after byte verification; the
installation disk, backups and historical ZIPs remain on persistent storage.
The 20-GiB disk and 6-GiB RAM reserves remain enforced. No Windows media, keys,
guest installation disk, firmware or external driver implementation is included
in the source or project checkpoint package.
