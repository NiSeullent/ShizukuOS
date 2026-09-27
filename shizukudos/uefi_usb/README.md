# Windows 98 Shizuku's Second Edition — USB EP0 integration

The [2026-09-27 KVM validation](VALIDATION.json) passed in 1.765 seconds.
The 46,080-byte EFI image has SHA-256
`fd11277f84e3baf1493453b8a5c6186fee88fcc7cfe64b1819a3ceab9bd6979c`.
Its original 28,066-byte i486 payload has no unresolved runtime imports.
The [130-command xHCI regression](../uefi_xhci/) also passed after the shared
base changed; earlier archives retain their exact historical sources and proofs.

This original binding connects the bounded [xHCI EP0 implementation](../../drivers/xhci_usb/)
to the project's CPL0 32-bit kernel after x64 UEFI exit. The observed result is
an eight-byte and then an eighteen-byte USB device descriptor obtained through
the controller's DMA rings, validated by the independent USB descriptor parser.
It does not configure the USB device or consume tablet/HID reports.

The disposable fixture contains one `qemu-xhci` controller behind a PCI-E root
port and one emulated `usb-tablet` with `usb_version=2`. Physical MMIO and QMP inventory agree on high-speed 480 Mb/s, xHCI root
port 5, 32-byte contexts and a 64-byte EP0 maximum packet. Both reads identify
VID `0627`, PID `0001`; this run did not exercise Evaluate Context, which remains
covered by the independent host model. No host USB device, Windows installation disk or network
adapter is attached. The loader reuses the original protected-mode transition,
memory-map contract and calibrated TSC arithmetic.

Two disjoint, aligned static allocations provide 4 KiB of controller storage
and 12 KiB of device contexts, an EP0 ring and response buffers. Only this
coherent, identity-mapped fixture equates physical and device addresses. The
base controller owns both lifetimes. A successful terminal probe disables its
slot and closes the controller before publishing the descriptor; uncertain
shutdown retains both allocations. The binding restores the original PCI
command register only after ownership is safely released.

Reproduce the host checks and bounded guest:

```sh
python3 drivers/xhci_native/test.py
python3 drivers/xhci_usb/test.py
python3 shizukudos/uefi_usb/build.py
python3 shizukudos/uefi_usb/test.py
python3 shizukudos/uefi_usb/test_qemu.py
```

Only the final command starts a guest. It uses one CPU, 256 MiB, a read-only
16-MiB ESP, private firmware variables and QMP socket, no public display
listener, and a 45-second watchdog. It checks the laboratory's RAM and disk
headroom and refuses to start while another owned compatibility guest runs.

Host transport tests pass 6,597,254 assertions across 1,095 scenarios and
984 callback failures under GCC, Clang and ASan/UBSan. Both i486 linked builds
have zero unresolved helpers. Eighteen independent evidence tests reject
malformed or inconsistent physical snapshots.

Success requires a stopped guest, the actual CS32/CPL0 and paging/long-mode
register evidence, successful kernel and software-graphics checks, and clean
USB completion. After HLT the harness pauses the CPU and independently dumps
the 256-byte proof record, both physical DMA allocations and the controller's
MMIO aperture. The evidence verifier compares the raw descriptor bytes,
contexts, command and transfer TRBs, completion events, and detached controller
addresses. Source, artifact and evidence hashes bind the result to the tested
EFI bytes. A screen marker or a guest-reported success field alone cannot pass.

This remains a laboratory integration, not a native Windows 98 USB driver,
general USB host stack, physical-hardware claim or UEFI-to-Windows GUI boot.
All implementation code is original project code; external specifications
define interfaces, and no third-party driver implementation is linked.
