# Interface facts and original source provenance

This integration binds existing original project components; it incorporates
no external operating-system, firmware, filesystem or AHCI implementation.
Specification documents inform interface facts, not imported source algorithms.

- UEFI Forum, [UEFI 2.10 Errata A, Boot Services](https://uefi.org/specs/UEFI/2.10_A/07_Services_Boot_Services.html):
  fixed-address page allocation, GetMemoryMap, ExitBootServices and Stall.
  Firmware storage services are not available after successful firmware exit;
  this payload supplies its own AHCI path. The retained map and reservation
  follow the unchanged original [UEFI32 contracts](../uefi32/README.md).
- Intel, [AHCI revision 1.3.1](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/serial-ata-ahci-spec-rev1-3-1.pdf):
  controller/port ownership, command/FIS/PRDT memory, DMA transfer count and
  engine shutdown. The existing driver's specific interfaces and primary
  ATA sources are recorded in [AHCI provenance](../../drivers/ahci_native/REFERENCES.md).
  The 1.2-second callback admission reserve is an original integration policy
  derived from the unchanged driver's two command waits and two cleanup waits;
  it is not a claimed platform-wide hardware timing guarantee.
- Microsoft, **FAT32 File System Specification v1.03, December 6, 2000**,
  [public copy of Microsoft's white paper](https://www.fysnet.net/docs/fatgen103.pdf):
  MBR/BPB geometry, reserved and mirrored FAT entries, cluster chains and root
  short-directory records. The original publisher is Microsoft and the linked
  site is a document mirror. The bounded profile is documented in
  [FAT reader provenance](../../drivers/fat_native/REFERENCES.md).

The fixture contents, clock monitor, callback admission, guard layout, evidence
format, build checks and host verifier are original project work. Existing
mode-transition source, graphics glyphs, kernel tests and division primitive
are reused from this same project with their original license. GCC/MinGW,
NASM and binutils are build dependencies; QEMU and OVMF are external test tools.
None of their implementation libraries is linked into the boot payload.

Reading a file does not define an IO.SYS execution contract. Real-mode entry,
low-memory layout, BIOS/DOS services, VMM handoff and Windows GUI compatibility
remain separate unimplemented boot contracts. No private Windows media or
installed disk is consulted by this integration.
