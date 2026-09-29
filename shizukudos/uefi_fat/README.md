# Windows 98 Shizuku's Second Edition — native FAT32 file read

This original ShizukuDOS integration connects the existing independent FAT32
reader to the existing independent AHCI driver after ExitBootServices and the
project's x64-to-i486 transition. The intended guest reads a fragmented original
fixture file from an MBR/FAT32 SATA disk into owned memory, without firmware disk
services. It does not load or execute that file. IO.SYS, DOS services, a Windows
98 storage binding and a Windows desktop are not implemented by this image.

The new EFI image builds successfully: 35,840 bytes, SHA-256
`e714ff7b68b86f0a2b951aa2cb5ac5a4f93e389cfd5ed7e4db6ee420fd200803`.
Independent host validation passes 24 evidence tests and 1,059,470 checks in
each GCC, Clang and nonrecovering ASan/UBSan variant, including 789 synthetic
sector reads and six AHCI stub calls. The separate actual KVM execution on
2026-09-27 also passed: 131,195 file bytes across 257 fragmented clusters,
778 AHCI sector reads, intact guards and destination tail, one DMA allocation
and release, and restored PCI command state. The complete synthetic disk hash
was unchanged. The guest stopped normally after 2.100 seconds without firing
the watchdog. [VALIDATION.json](VALIDATION.json) binds the actual memory,
registers, controller state, inputs and source hashes;
[the separate root audit](../../docs/FAT32_ROOT_AUDIT.json) reconstructed the
FAT chains and file bytes again. Physical hardware remains untested. Previous
UEFI/AHCI/FAT sources and their frozen evidence remain unchanged.

## Memory and ownership

The loader reuses this project's original UEFI32 reservation, identity-page
validation, retained map, GDT/IDTs and protected-mode transition. It owns exactly
2 MiB at physical `0x02000000`; paging and interrupts are disabled in the i486
payload. The build checks ELF load ranges, individual static-buffer symbols,
64-KiB stack capacity and absence of unresolved runtime helpers.

| Physical range | Purpose |
| --- | --- |
| `02000000..020027ff` | Transition and private interrupt tables |
| `02004000..0200bfff` | Retained firmware memory map |
| `0200f000..0200f06f` | Original 112-byte CPU/graphics handoff |
| `0200f100..0200f1ff` | Version 1, 256-byte FAT proof record |
| `02010000..020fefff` | Linked payload, 530,176-byte FAT scratch, 4-KiB DMA, graphics arena |
| `020ff000..020fffff` | Before-output guard, `0xa5` |
| `02100000..0217ffff` | 512-KiB file destination, initially `0xa5` |
| `02180000..02180fff` | After-output guard, `0xa5` |
| `021f0000..021fffff` | Private 64-KiB stack |

The linker must place `__payload_end <= 0x020ff000`. The two large file buffers
are separate: the reader stages and validates the complete file in its static
workspace, then publishes only its exact file length to the destination. Output
guard bit 0 means the lower guard remains intact, bit 1 means the upper guard,
and bit 2 means the unused destination tail. Success requires all three (`7`),
and independent host verification must inspect every captured byte as well.

The fixture binding accepts only QEMU q35's `8086:2922`, class `010601`, with the
declared 4-KiB BAR5 aperture, one CPU, no IOMMU and coherent identity DMA. It
preserves CF8 and never copies W1C PCI status bits into a command-register write.
After firmware exit it exclusively owns this controller; no firmware callbacks
or concurrent storage users remain. The DMA page is 4-KiB aligned and remains
reserved along with its static controller context. If shutdown cannot confirm
DMA release, both remain retained and the PCI command register is not restored.
Confirmed release permits restoration; this does not restore firmware HBA state.

## Clock and callback boundary

The loader calibrates RDTSC against a 10-ms EFI Stall before firmware exit.
`budget.c` rejects backwards raw ticks and latches a failure after 64 consecutive
identical raw readings; rounded equal microseconds do not count as a stalled
raw clock. Faults are sticky. The FAT callback can report a clock error. The
unchanged AHCI clock API cannot, so its callback holds the last valid reading;
finite polling limits and the independent host watchdog are still required.
A successful AHCI return after a clock fault cannot become a successful FAT
read or final guest pass. Final file-read time must also have advanced.

Each AHCI command timeout is fixed at 10,000 microseconds when opening the
controller. A read failure can consume two command waits plus two 500-ms engine
cleanup waits, approximately 1.02 seconds on a valid clock. The bridge refuses
to enter AHCI unless the FAT reader supplies at least **1,200,000 microseconds**
remaining. It samples time immediately before and after the call and rejects
an elapsed time equal to or greater than the supplied remainder. No live device
fields are changed to adjust these timeouts.

These are **cooperative clock budgets**, not a hard five-second wall-clock
guarantee. Descheduling during calibration can inflate the measured rate; a
broken clock or stuck hardware callback invalidates the elapsed-time assumption.
The FAT operation has a five-second clock budget and 8,192-read cap. AHCI open,
IDENTIFY, any final close retry, output verification and rendering are outside
that file-operation budget. The controlled host must enforce a separate
45-second watchdog over the whole guest and stop it on failure.

## Independent fixture and evidence

The fixture is a newly generated 64-MiB sparse disk, 131,072 logical sectors.
Primary partition 0 starts at LBA 2,048 and contains 129,024 sectors: 32 reserved,
two 1,024-sector mirrored FATs, one sector per cluster and 126,944 data clusters.
The root directory follows `9 -> 71 -> 15 -> EOC`; the target short name is
`NTWBOOT BIN` on its second cluster. The original 131,195-byte file occupies
257 distinct fragmented clusters. Its final sector's unused disk bytes are
`0xcc`; those bytes must not reach the `0xa5` destination tail. This is synthetic
test data and contains no Windows file, boot code or product key.

The installed QEMU rejects a read-only backend for its `ide-hd` device. The
test therefore attaches only this disposable generated SATA image with a
writable backend, while the ESP and firmware code remain read-only. It verifies
the complete SATA image hash before and after execution; any changed byte fails
the test. The original AHCI/FAT payload issues reads only. The host reserves
20 GiB plus 128 MiB for the entire fixture and evidence captures.

The independent fixture/verifier reconstructs file bytes and metadata, checks
the whole 512-KiB output and both guard pages, and compares the retained final
AHCI command/FIS/PRDT, transfer count and bounce sector with the actual fixture
LBA. It must also establish halted 32-bit CPL0 execution, detached DMA registers,
no retained allocation, restored PCI command state, unchanged disk contents,
source/build hashes, and clean guest shutdown. A displayed PASS string alone
does not supply these facts.

From the repository root, the compile-only command is:

```sh
python3 -B shizukudos/uefi_fat/build.py
```

It uses installed GCC, MinGW, NASM and binutils; writes only the new `build/`
directory; and does not download, install, start a VM or access a disk device.
`build/build-result.json` records all linked source hashes and memory spans.
The peer-owned `test.py`, `fixture.py`, `verify.py` and `test_qemu.py` provide
separate host and guest validation. The checked-in guest receipt is tied to
these exact source and build inputs; later changes require new evidence.

```sh
python3 -B shizukudos/uefi_fat/test.py
```

The host command creates original sparse images, generated test glue, binaries,
logs and `build/host-tests.json`; temporary images are removed after testing.
It does not start QEMU. The guest command additionally requires an explicitly
coordinated lane: `python3 -B shizukudos/uefi_fat/test_qemu.py --guest-lane authorized`.
It creates its own media under `build/`, uses one CPU/256MiB/no NIC, rejects
another compatibility QA guest, preserves 20GiB disk and 6GiB host-RAM headroom, and stops
its own process within the separate watchdog. Existing VMs and Windows media
are not test inputs. `--verify-only PATH` rechecks saved evidence without a VM.

All implementation is original project code under GPL-2.0-only. Reused code is
from this repository's independently authored UEFI32, UEFI, NTWrapper9x,
NTWDDMWrapper9x and AHCI components. See [REFERENCES.md](REFERENCES.md) for primary
interface documents and the limits of this step toward a boot-file loader.
