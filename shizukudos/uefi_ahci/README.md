# Windows 98 Shizuku's Second Edition — native AHCI integration

This original integration executes the project's [AHCI driver](../../drivers/ahci_native/)
after leaving x64 UEFI and entering its own 32-bit protected-mode kernel. The
payload issues IDENTIFY DEVICE and two READ DMA EXT commands through controller
MMIO. Disk reads use the driver's command list, command table, received-FIS area
and DMA buffer; they do not call firmware Block I/O or a host file-read service.

This is a bounded storage-driver experiment. It is not a Windows 98 storage
miniport, filesystem, DOS disk service, installer or general physical-hardware
driver. The existing [UEFI32 transition](../uefi32/) remains a separate,
unchanged checkpoint. Both the NTWrapper9x object/event core and NTWDDMWrapper9x
software presentation tests execute before the disk experiment.

## Binding and ownership

The loader reserves the same low 2 MiB and uses the project's original GDT,
IDTs, mode transition, memory-map retention and page-table validation. It adds
an 80-byte storage receipt at physical `0200F100`, below the ELF32 payload.
The payload owns one aligned static 4-KiB DMA allocation in that reserved
region; the linker's bounds and the build's symbol check validate its location
and alignment. No OS-owned or host storage is attached to this experiment.

The binding accepts only its QEMU q35 fixture: Intel `8086:2922`, class
`010601`, BAR5 in the declared below-4-GiB MMIO window, one CPU, no IOMMU, and
coherent identity DMA. The fixture supplies a 4-KiB ABAR aperture. That size is
not guessed for arbitrary hardware, and a CPU pointer is not a general DMA
mapping contract. PCI configuration cycles preserve CF8; command-register
writes leave write-one-to-clear status bits zero.

The driver takes exclusive HBA ownership, disables interrupt delivery, stops
existing engines, and publishes owned DMA addresses before enabling reception
and commands. It polls bounded operations with interrupts disabled. The
allocation and controller context remain alive if engine shutdown cannot be
proved; only confirmed release permits restoring the original PCI command
register. The experiment never enables another guest's controller or accesses
a host disk.

The time callback uses RDTSC calibrated against a 10-ms EFI Stall before
ExitBootServices. Original 64-by-32-bit division avoids compiler runtime
helpers. This is a lab clock, not an invariant clock for all platforms: host
descheduling can inflate the measured rate. The driver also bounds polling,
and the host enforces a separate 45-second wall-clock watchdog.

## Reproduce and interpret evidence

The [2026-09-27 validation](VALIDATION.json) passed under actual KVM in 3.291
seconds. QEMU reported halted `CS32`, `CPL=0`, `CR0=00010033`,
`CR4=00000648`, `EFER=00000800`; both sector reads, independent DMA inspection
and clean shutdown passed. The EFI artifact is 31,232 bytes, SHA-256
`be234d007749cc1820492bf896f92b454bcd0a456b2785ffcea8eb2fd84dbf86`.

Run these commands from the repository root using the existing compilers,
QEMU/KVM, OVMF, mtools and FAT formatter. The build and host test do not boot a
VM or download dependencies.

```sh
python3 drivers/ahci_native/test.py
python3 shizukudos/uefi_ahci/build.py
python3 shizukudos/uefi_ahci/test.py
python3 shizukudos/uefi_ahci/test_qemu.py
```

The guest command creates a private 16-MiB ESP, an 8-MiB patterned SATA disk,
an OVMF variable copy and a QMP socket under ignored `build/`. It uses 256 MiB,
one CPU and no network or display listener. It refuses another compatibility
VM or insufficient host headroom, and stops its own guest after collecting
evidence. Existing VMs, global configuration and host services are untouched.

A successful receipt requires all of the following:

- Source-bound EFI bytes copied from a validated immutable snapshot; the
  public artifact and build receipt must remain unchanged through the run.
- Independent QEMU registers showing halted CS32/CPL0 with paging and long
  mode disabled, plus successful kernel-core and software-display results.
- ATA identity reporting 16,384 sectors of 512 bytes; actual reads of LBAs 7
  and 11 matching all 1,024 independently generated pattern bytes.
- A physical DMA-memory dump containing the final sector and a 512-byte
  transferred count; successful engine shutdown with no retained DMA.
- An unchanged whole-disk hash after the guest exits, and hashes for the
  receipt bytes, DMA dump, register dump and screenshots.

`build/build-result.json`, `build/host-tests.json` and `build/qemu-result.json`
record separate build, arithmetic and live-device evidence. A build receipt's
`guest_test: not_run` describes that build invocation; only a matching passing
guest receipt establishes execution. Windows 98 and physical-device results
remain explicitly untested. Screenshots by themselves do not establish DMA.

## Source provenance

The code here is independently authored GPL-2.0-only project code. It reuses
the project's original UEFI32 transition/contracts, UEFI declarations,
NTWrapper9x core, NTWDDMWrapper9x renderer and AHCI implementation. Public
interface references are recorded in [UEFI32](../uefi32/README.md) and
[AHCI provenance](../../drivers/ahci_native/REFERENCES.md). No Windows, Linux,
QEMU, EDK II, GNU-EFI or vendor implementation is linked or redistributed.
Firmware and emulators are external test dependencies.
