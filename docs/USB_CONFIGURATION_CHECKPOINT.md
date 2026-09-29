# Windows 98 Shizuku's Second Edition — USB configuration execution

On 2026-09-27, the original xHCI transport completed device and configuration
descriptor reads in a KVM guest after ShizukuDOS exited x64 UEFI and entered
its own 32-bit CPL0 kernel. The [configuration integration](../shizukudos/uefi_usb_config/)
uses a separately reserved result page, so its 3,848-byte output cannot overlap
the existing handoff, proof or executable payload.

Four EP0 requests read GET8, GET18, the nine-byte configuration header and the
complete 34-byte configuration. Independent physical DMA bytes were:

```text
09022200010107a032090400000103000000092101000001224a0007058103080004
```

The emulated QEMU tablet is `0627:0001`, at 480 Mb/s on USB2 root port 5 with a
64-byte EP0 packet. Configuration index 0 returns value 1, one interface and
alternate, interrupt IN endpoint `0x81` with an eight-byte packet and interval
4, and one opaque HID descriptor. The configuration value is observed data;
this operation sends no SET_CONFIGURATION and reads no HID reports.

The physical event history contains the port reset, Enable Slot, Address
Device, four correlated transfer completions and Disable Slot. Both DMA
allocations were released, the DCBAA pointer was cleared, the controller was
shut down and the PCI command register restored. The 1.879-second guest stopped
with return code zero and no watchdog expiry. Its [validation record](../shizukudos/uefi_usb_config/VALIDATION.json)
binds the exact build, current sources and ten evidence files, including a
4,096-byte result-page dump. An independent Python decoder reconstructs the
entire parsed configuration and checks unused bytes, raw descriptors, guards,
contexts, TRBs and event chronology.

The EFI is 47,616 bytes, SHA-256
`2dffac0094a08b3062c1f66610ecc4f3d3742ebabfa7848988b6c19f1db32430`.
The i486 payload is 29,479 bytes, SHA-256
`0d3255ad83da366c8de0c69a92b44276d28814b987039d02d21a97ffcbbbe851`.
The kernel core and software graphics checks also pass in the same guest.

The shared transport's host model passes 13,275,540 assertions in each GCC,
Clang and ASan/UBSan run, across 2,489 scenarios. It includes 1,315 configuration
probes and 1,036 configuration callback faults in addition to the prior 984
device faults. Configuration index and value are kept distinct; bounds,
changed headers, short transfers, parser errors, cleanup and output preservation
are exercised. Both i486 linked objects require zero external helpers.

A separate current-source [device-only regression](../shizukudos/uefi_usb/VALIDATION.json)
passed GET8/GET18 and shutdown in 1.799 seconds. Its EFI is 47,616 bytes,
SHA-256 `60295012d425c3e43166b2a6e403466800160ec0da0fc000df5b2987e09f11ed`.
The older EP0 archive remains unchanged and retains its earlier sources and
execution proof; it is not substituted for this new regression.

Windows installation separately reached 71% file copy. Its private qcow2
checkpoint was preserved byte for byte in XZ (248,447,433 raw bytes;
79,174,240 archived bytes), then independently restored and checked with all
five internal snapshots present. The original raw disk and previous backups
remain intact. The native DLL, VxD and GDI probes have not yet run on Windows.

This checkpoint does not implement device selection, class/HID I/O, native
Windows 98 USB/CONFIGMG integration, physical hardware support, vendor GPU
drivers or UEFI-to-Windows GUI boot. No Windows media, keys, guest installation
disk, firmware or external driver implementation is distributed.
