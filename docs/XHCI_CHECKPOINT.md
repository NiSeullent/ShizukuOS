# Windows 98 Shizuku's Second Edition — PCI-E/xHCI checkpoint

Date: 2026-09-27. The original xHCI controller core now executes command and
event rings behind a PCI-E bridge in the project's own 32-bit kernel. This
extends the [storage/UTF checkpoint](STORAGE_UTF_CHECKPOINT.md); all earlier
archives remain separate historical snapshots.

Actual KVM execution completed 130 No-Op commands in 2.284 seconds, crossing
eight command-ring links and two event-ring wraps. An independent physical
DMA dump contains the expected final command pointer, success code and cycle
bit. A separate read-only review checked all 15 command TRBs, the Link TRB,
all 64 event TRBs, the zero DCBAA and the event-segment table against the
130-command sequence. QEMU's own PCI inventory agrees with the guest's
`01:00.0` discovery, `1b36:000d` controller and 16-KiB 64-bit BAR at `81000000`.

The guest independently reports CS32/CPL0, paging and long mode off, and a
halted payload in reserved low memory. NTWrapper9x core and NTWDDMWrapper9x
software presentation pass before controller initialization. Controller open,
commands and close succeed, DMA is released without quarantine, and the guest
is stopped before evidence publication.

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| `shizukudos/uefi_xhci/build/BOOTX64.EFI` | 35,840 | `fdcbe313cd1270584582f98033681d4fbd8b20429af487408bcf4132a7b555f5` |

The [driver host model](../drivers/xhci_native/README.md) passed 3,032,647
assertions and 64 injected callback-failure positions with ASan/UBSan. The
i486 core object has no unresolved runtime helpers. Integration host tests
check clock arithmetic and six QMP primary/secondary-bus inventory cases.
The first live run completed all device commands but failed the host's bridge
interpretation; that parser was corrected and the matching final run passed.

[Integration instructions](../shizukudos/uefi_xhci/README.md) document the
memory/MMIO/DMA assumptions and reproduction commands. The
[validation record](../shizukudos/uefi_xhci/VALIDATION.json) binds the EFI,
source, build, host-test, guest, physical DMA, CPU-register and screen hashes.
The expanded source/artifact package is generated as
`build/windows98-shizuku-second-edition-xhci-checkpoint.zip`; its checksum and
extraction/rebuild receipt are separate generated outputs.

This is controller infrastructure, with no attached USB device. It does not
implement slots/endpoints, descriptor requests, keyboard input, USB storage,
interrupts, hotplug or power management. The first slice rejects nonzero
scratchpad requirements explicitly. Native Windows 98 and physical hardware
bindings, full DOS services and Windows GUI boot remain unverified. The
Windows 98 installation experiment continues separately with private media
and guest disks excluded from source and packages.
