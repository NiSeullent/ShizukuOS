# Windows 98 Shizuku's Second Edition — ShizukuDOS UEFI

An independently implemented, bootable **x64 UEFI platform bring-up**. This is
an actual EFI application that exits firmware boot services, retains the memory
map, and executes independent graphics and kernel-core code at CPL 0. It does
**not** boot Windows 98, replace its DOS kernel, or run Windows applications yet.

## Implemented behavior

- Original minimal x64 firmware ABI declarations with checked structure offsets;
  no GNU-EFI, EDK II library, Windows SDK, FreeDOS, or KernelEx linkage.
- Native firmware console output and watchdog disable before the transition.
- GOP discovery and validated framebuffer snapshot: 32-bit RGB/BGR, dimensions,
  pitch, buffer length, alignment, and overflow checks. Unsupported bitmask and
  `PixelBltOnly` modes fail before `ExitBootServices`.
- A versioned `SD_HANDOFF` carrying the framebuffer, descriptor stream with its
  actual firmware stride, descriptor version, memory-map key, conventional page
  count, and discovered ACPI RSDP pointer. ACPI tables are not parsed yet.
- Bounded map allocation with slack for map changes. A stale map key is retried
  up to eight times. After the first exit attempt only `GetMemoryMap` and
  `ExitBootServices` are called. Failures after a partial shutdown halt with a
  red proof tile; they never return to firmware or use console protocols.
- After a successful exit, the native framebuffer displays the product name,
  a green handoff tile, and an explicit unsupported Windows-loader message.
- The original `ntwddm/` software core fills/presents an amber surface through
  the GOP snapshot and verifies its completion fence using loader-owned memory.
- The original `ntwrapper/` core reads CS to require CPL 0, then tests auto/manual
  reset events and lease/close lifetime with local IRQ-save/restore callbacks.
  A cyan tile and `NTWRAPPER9X_RING0_PASS` appear only on success. This proves
  that subset at ring 0 in the UEFI environment, **not Win98 VxD integration**.

The retained loader image, stack, graphics arena, handoff, and map must remain
reserved when a successor memory manager is added. Firmware runtime/ACPI/MMIO
memory is not reclaimed. There is currently no page-table replacement, IDT,
scheduler, runtime-service virtual mapping, filesystem loader, 16-bit DOS
execution bridge, or Win98 VMM entry path. The final state intentionally halts
with interrupts disabled on the single boot CPU; it is not an interactive DOS
shell. Secure Boot signing and IA32 UEFI are not implemented.

## Reproduce

Run from the repository root with **existing** Python 3, native C compiler,
MinGW x86_64 compiler, QEMU, OVMF, `mkfs.vfat`, and mtools:

```sh
python3 shizukudos/uefi/build.py
python3 shizukudos/uefi/test.py
python3 shizukudos/uefi/test.py --cc clang --sanitize
python3 shizukudos/uefi/test_qemu.py \
  --qemu /usr/libexec/qemu-kvm \
  --firmware-code /usr/share/edk2/ovmf/OVMF_CODE.fd \
  --firmware-vars /usr/share/edk2/ovmf/OVMF_VARS.fd
```

The build verifies AMD64 PE32+, EFI application subsystem, relocation data,
empty DLL import descriptors, and a deterministic timestamp. Its receipt records
source hashes; the QEMU test rejects an image whose recorded sources changed.
Sanitizers are opt-in and require an installed runtime. This server's GCC
sanitizer runtime is missing; its Clang ASan/UBSan runtime works.

All output stays under `build/`. QEMU receives one CPU and 256 MiB, no networking,
the original read-only OVMF code, a private writable firmware-variable copy,
and a newly created 16-MiB FAT16 image mounted read-only. No existing VM, host
disk, service, download, or system configuration is used. The harness requires
KVM by default, verifies it through QMP, checks five exact framebuffer pixels
from the live guest, and terminates the process within the bounded test. A
deliberate `--accel tcg` run is possible but does not count as KVM evidence.
`build/qemu-result.json` records the PID, acceleration, EFI/firmware hashes,
elapsed time, screen size, and confirmed process shutdown. The corresponding
directory retains logs and screenshots. Failed runs remain distinguishable.

`BOOTX64.EFI` can be placed at `EFI/BOOT/BOOTX64.EFI` on an isolated x64 UEFI
test medium. The automated test creates only its own media and does not install
the loader onto a machine. Physical firmware/GOP compatibility is unverified.

## Optional PCIe diagnostic

```sh
python3 shizukudos/uefi/build.py --test-pci
python3 shizukudos/uefi/test_qemu.py --test-pci
```

This produces a separate `BOOTX64-PCI-TEST.EFI`, links `drivers/pcie/`, and adds
a PCIe root port with a downstream QEMU xHCI controller. Its guest-only adapter
uses conventional CF8/CFC configuration mechanism 1, explicitly limited to
256-byte config space. It writes only the config-address selector and debug
output port; there are **no PCI config-data/BAR writes, DMA, controller MMIO
operations, USB transfers, or driver-binding claims**. The production image
does not include that adapter or assume those legacy I/O ports exist.

A successful run proves bridge traversal and downstream xHCI class detection,
showing a magenta tile and `PCIE_BRIDGE_XHCI_PASS`. The debug log records device
IDs, BDFs, classes, scan counters, and `NTWPCIE_BRIDGE_XHCI_PASS`. This QEMU build
does not provide an NVMe device model; no live NVMe discovery is claimed.
Receipts are separate in `build/qemu-pci-result.json`.

## Tests and provenance

The recorded 2026-09-27 run in [VALIDATION.json](VALIDATION.json) passed 354 host
checks both natively and under Clang ASan/UBSan. Both final EFI images reached
the live 1280x800 proof screen with KVM enabled; both QEMU processes were stopped.

Host tests exercise memory-map acquisition/resize, larger descriptor strides,
stale-key retry, allocation failure, malformed maps, retry exhaustion, failure
after partial firmware shutdown, framebuffer pitch/padding/bounds, RGB/BGR
conversion, and the NTWDDM bridge. Host tests are separate from actual firmware
boot evidence. No screenshot or simulation is counted as Win98 compatibility.

All files in this directory are new original implementation under
`GPL-2.0-only`. Firmware interfaces were derived from the public
[UEFI 2.10 system table specification](https://uefi.org/specs/UEFI/2.10/04_EFI_System_Table.html),
[boot-services specification](https://uefi.org/specs/UEFI/2.10/07_Services_Boot_Services.html),
and [console/GOP specification](https://uefi.org/specs/UEFI/2.10/12_Protocols_Console_Support.html).
The small bitmap glyphs were independently drawn. No external implementation,
font, firmware image, Microsoft file, or application binary is redistributed.
The firmware/toolchain are test/build dependencies, not shipped components.
