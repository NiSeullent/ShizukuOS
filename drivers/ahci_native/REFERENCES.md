# Interface facts and source provenance

All C and Python sources in this directory are independently authored project
code under GPL-2.0-only. No Linux, BSD, ReactOS, OSDev sample implementation,
vendor driver, binary, SDK implementation library or third-party AHCI algorithm
was copied into this implementation. The callbacks, lifecycle, parser, byte
encoding, polling and fault model were written here for this bounded interface.
The build downloads or incorporates none of the linked documents.

The following primary documents were consulted for factual interfaces on
2026-09-27:

| Source | Facts used |
| --- | --- |
| [Intel AHCI revision 1.3.1 specification](https://www.intel.com/content/dam/www/public/us/en/documents/technical-specifications/serial-ata-ahci-spec-rev1-3-1.pdf) | Sections 3.1/3.3 define CAP, GHC, PI, VS, CAP2/BOHC and port registers. Section 4 defines aligned command/FIS/table/PRDT memory and PRDBC; section 10 covers port initialization and BIOS/OS ownership. NP is a count, while PI identifies actual port indexes. Engine stop waits allow 500 ms. Command completion is observed with CI/SACT and transfer/status evidence. |
| [Serial ATA Workgroup, Serial ATA 1.0, hosted by member Seagate](https://www.seagate.com/support/disc/manuals/sata/sata_im.pdf) | Section 8.5.2, figure 58: Register Host-to-Device FIS type `0x27`, command flag, five DWORD length and normal/expanded register byte layout. Reserved FIS fields are zero. The HBA handles link transport and CRC; this module does not reimplement the wire PHY/link layer. |
| [Seagate SkyHawk AI SATA product manual, revision B](https://www.seagate.com/files/www-content/product-content/skyhawk/en-us/docs/200915700b.pdf) | Section 4.3 lists IDENTIFY DEVICE `0xec` and READ DMA EXT `0x25`; section 4.3.1 describes the 512-byte IDENTIFY transfer and ATA/SATA identification, model/capability/capacity fields. Model-specific values are not used as an arbitrary device whitelist. |
| [T13 ATA8-ACS working draft revision 4a, archived at Georgia Tech](https://cs3210.cc.gatech.edu/r/hardware/ATA8-ACS.pdf) | Indexed primary-document excerpts were used to cross-check IDENTIFY support validity bits in word 83 and the logical-sector-size contract in word 106. Direct PDF retrieval from this archive was unavailable in this session; it is not represented as a complete audit of the draft. The older direct T13 document URL also failed retrieval. |
| [T13 command-set working draft, archived at Harvard](https://read.seas.harvard.edu/cs161/2024/pdf/ata-atapi-8.pdf) | Indexed primary-document excerpts distinguish optional SATA identification words from the 48-bit command feature set. Direct PDF retrieval timed out. Word 76 speed bits are not used as an extra command prerequisite: the driver requires DMA/LBA48 and independently establishes the live AHCI ATA transport. The observed QEMU word `0x0100` is covered as a compatibility policy, not presented as full SATA identification conformance. |
| [QEMU 10.1.0 AHCI model, official source tag](https://github.com/qemu/qemu/blob/v10.1.0/hw/ide/ahci.c) | Consulted while diagnosing actual guest initialization: reset gives a disk status `0x30` with error register 1; the initial D2H FIS is delivered when reception becomes available, and updates SIG. This explains observed TFD `0x130`, which must not be treated as an issued-command result. Only this emulator behavior was used as regression input; no emulator implementation was copied. |

The write path added later uses further public interface facts from the same
kinds of primary documents (the ATA8-ACS command set and AHCI 1.3.1; they were not
re-fetched for this change): WRITE DMA EXT is opcode `0x35` with the same 48-bit
LBA/count register layout as READ DMA EXT; FLUSH CACHE EXT is the non-data opcode
`0xea`; IDENTIFY word 83 bit 13 advertises FLUSH CACHE EXT, word 85 bit 5 reports an
enabled volatile write cache and word 87 bits 15:14 = `01` mark words 85..87 valid;
the AHCI command header's DW0 bit 6 (W) selects host-to-device transfer direction
and PRDTL 0 describes a command without data. QEMU's AHCI model accepts these
commands; the Kernel64 fixture verifies the written bytes in the host image file.

The exact supported policy is narrower than those specifications: active ATA
SATA links, complete IDENTIFY, LBA48, 512-byte logical sectors, coherent DMA,
one slot, one PRDT, one read or written sector per command, serialized polling and exclusive HBA ownership.
Larger sectors, NCQ, ATAPI, port multipliers, power sequencing and automatic reset
recovery are not silently approximated. Specification access and interface
research do not constitute hardware conformance or vendor certification.

Host compiler/version and exact source/object/log hashes are recorded by
`test.py` in `build/host-tests.json`. A live guest receipt must separately identify
the binding's MMIO, PCI, DMA-address and time contracts; successful host callbacks
are not evidence that those platform contracts were supplied correctly.
