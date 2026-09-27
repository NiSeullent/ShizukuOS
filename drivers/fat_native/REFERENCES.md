# Public interface provenance

All source and tests in this directory are original project work under
GPL-2.0-only. No Microsoft, FreeDOS, Linux, ReactOS, firmware or other filesystem
implementation is copied or linked. Public on-disk facts, not implementation
algorithms or specimen source code, inform this reader.

- Microsoft, **FAT32 File System Specification, version 1.03, December 6,
  2000**, [public copy of the original Microsoft hardware white paper](https://www.fysnet.net/docs/fatgen103.pdf).
  The BPB, FAT type determination, FAT32 active/mirrored selection, reserved
  nibble, cluster-link/EOC/bad-cluster values, reserved FAT entries and short
  directory field layouts are the relevant factual interfaces. The original
  publisher is Microsoft; the linked host is a document mirror. The document
  itself is neither included nor redistributed in this project.
- UEFI Forum, **UEFI 2.10, section 13.3**, [file-system and partition format](https://uefi.org/specs/UEFI/2.10/13_Protocols_Media_Access.html).
  The legacy MBR record layout and separation between legacy sector code and
  UEFI image loading provide the partition/boot boundary. This component does
  not execute MBR or VBR code and does not implement EFI filesystem protocols.
- UEFI Forum, **UEFI 2.10 Errata A, section 7**,
  [Boot Services lifetime](https://uefi.org/specs/UEFI/2.10_A/07_Services_Boot_Services.html).
  A later post-ExitBootServices binding must use its own device interface; a
  successful FAT32 host test does not supply that hardware interface.

Bounds, transactional staging, alias checks, duplicate/crosslink policy,
callback deadlines and tests are original implementation choices. They define
a deliberately smaller read-only boot-file profile, not full FAT32 conformance
or a Windows/DOS-compatible runtime. Compiler headers provide scalar types;
GCC/Clang and host libc/sanitizers are test/build tools, not linked boot code.
