# Windows 98 Shizuku's Second Edition — native PCI-E/xHCI execution

This original integration discovers a QEMU xHCI controller behind a PCI-E
root port and executes 130 No-Op commands through its command and event rings.
It runs after x64 UEFI exit in the project's own CPL0 32-bit protected-mode
kernel. No USB device is attached; successful controller commands do not
establish keyboard, storage, USB transfer or Windows 98 driver support.

The [2026-09-27 validation](VALIDATION.json) passed under actual KVM in 2.284
seconds. The EFI image is 35,840 bytes, SHA-256
`fdcbe313cd1270584582f98033681d4fbd8b20429af487408bcf4132a7b555f5`.
The 17,686-byte payload has no runtime imports. The existing NTWrapper9x core
and NTWDDMWrapper9x software-presentation tests also pass in the same guest.

## Device and memory contracts

The integration reuses the original [UEFI32 transition](../uefi32/) without
changing that checkpoint. Its loader reserves low memory, validates identity
mappings, retains the firmware memory map and exits boot services before
entering the 32-bit payload. The original [PCI core](../../drivers/pcie/)
follows firmware-assigned bridges through serialized CF8/CFC reads.

Only the controlled `qemu-xhci` fixture, PCI ID `1b36:000d`, class `0c0330`,
on a non-root bus is accepted. The PCI core validates its assigned 64-bit BAR0
against a below-4-GiB MMIO window. This fixture declares a 16-KiB aperture;
the host separately checks QEMU's actual resource and bridge inventory.
The recorded controller is at `01:00.0`, MMIO `81000000`, behind one bridge.

One static 4-KiB, 4-KiB-aligned DMA allocation holds the DCBAA, command ring,
event ring and event-segment table. Only this single-CPU, coherent,
identity-mapped, no-IOMMU fixture equates physical and device addresses. The
binding is not a general DMA mapper. The original [xHCI core](../../drivers/xhci_native/)
owns initialization, legacy handoff if present, bounded halt/reset, cycle-bit
publication, completion validation and retained-DMA failure behavior.

The payload issues 130 commands: eight command-ring link traversals and two
event-ring wraps. Every completion must identify the submitted command and
report success. Shutdown halts/resets the controller and releases the DMA
allocation before the binding restores the original PCI command register.
Ambiguous shutdown retains the static allocation and context. There are no
interrupts, USB slots/endpoints, data transfers, scratchpads or OS callbacks.

## Reproduce and inspect

From the repository root, using existing compilers, NASM, QEMU/KVM, OVMF,
mtools and the FAT formatter:

```sh
python3 drivers/xhci_native/test.py
python3 shizukudos/uefi_xhci/build.py
python3 shizukudos/uefi_xhci/test.py
python3 shizukudos/uefi_xhci/test_qemu.py
```

The first three commands never start a guest. The driver host model tests
3,032,647 assertions and all 64 injected callback-failure positions under
ASan/UBSan; its i486 object has no unresolved helpers. The integration host
test checks 100,031 clock-division cases in strict and sanitized builds, plus
six QMP inventory regressions. QMP reports a bridge's primary bus as `number`
and the downstream bus as `secondary`; these must not be confused when
independently validating the guest's discovered BDF.

The final command starts one bounded disposable guest with 256 MiB, one CPU,
no network or display listener, no USB devices and a read-only 16-MiB ESP.
It uses private firmware variables and a 45-second watchdog, enforces host
headroom, and stops the guest after evidence collection. It does not attach
host disks or alter an existing VM, firmware or global configuration.

A pass requires matching built/source hashes, independently observed QEMU
CS32/CPL0 registers with paging and long mode off, successful core/display
receipts, 130 successful commands and clean shutdown without quarantine.
The physical 4-KiB DMA dump must contain the final command-completion TRB
with the expected command pointer, success code and cycle. QEMU's PCI
inventory must agree on the downstream bus, BAR type, address and size.
Hashes bind the physical proof, DMA dump, mode handoff, registers and screens.
The validated EFI bytes are copied from a private immutable snapshot; artifact
or source changes during execution invalidate the result.

The RDTSC clock is calibrated against EFI Stall before firmware exit and
shares the same laboratory limitations as the [AHCI experiment](../uefi_ahci/).
Independent host time and polling limits bound execution. Physical hardware,
native Windows 98, DOS services and Windows GUI boot remain untested.

All implementation code is original GPL-2.0-only project code. Public
interface facts are documented in the [xHCI references](../../drivers/xhci_native/REFERENCES.md)
and existing UEFI32/PCI sources. No emulator, firmware, vendor driver, Windows,
Linux or third-party implementation is linked or redistributed.
