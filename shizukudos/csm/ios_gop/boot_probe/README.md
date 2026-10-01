# Actual Windows 98 early GOP boot probe

This original 16-bit diagnostic replaces only the first 440 bytes of an MBR on
a disposable private Windows 98 clone. Its final action runs the original
Windows volume boot sector, which continues to the original IO.SYS. It contains
no Microsoft binary bytes, independent kernel, or replacement DOS runtime.

The probe relocates the complete MBR from 7c00 to 0600, reserves its stack below
7c00, sets BIOS mode 03, and requires INT10 AH0F mode03/80 columns plus BDA
80 columns, 25 rows, 16-pixel font and 4096-byte text pages. COM1 output is 115200
8N1; each transmitted byte waits at most 65535 status polls. A stalled UART
does not block boot. Runtime disk checks require one exact active primary
FAT16/32 partition (types06/0b/0c/0e), nonzero geometry, a hard-disk BIOS drive,
INT13 EDD support, AH48 512-byte sectors and sufficient real disk sectors. AH42
reads exactly one signed VBR into 0000:7c00 and chains with the original DL and
DS:SI pointing to the relocated partition entry. No BPB bytes are changed.

Markers are `IOGOP:S` after relocation, `IOGOP:T` after text checks,
`IOGOP:D` after EDD disk checks, `IOGOP:C` immediately before the VBR jump, and
`IOGOP:F` on any guard failure. Failure halts with interrupts disabled.
`TEST_DEBUG_EXIT` additionally exits a test-only isa-debug-exit device at f4:
value10h (QEMU exit33) only after all guards and the signed VBR read, or value11h
(exit35) after failure. Normal builds contain no debug-exit instruction path.

The build module emits a signed 512-byte sector with code confined to its first
440 bytes and an empty disk identity and partition table. `build_probe(out_dir, test_exit=False)`
also writes a source/artifact hash receipt. The profile builder must obtain the
physical disk sector count, call `validate_mbr(mbr, sector_count)` followed by
`apply_to_mbr(mbr, probe)` on the immutable source MBR, and write the returned
sector only to its private clone. Those
helpers reject protective/hybrid GPT, malformed/overlapping partitions,
ambiguous active entries and geometry outside the disk or the 32-bit MBR range.
They preserve all bytes440..511, including the disk identity, complete partition
table and signature. The host validation is mandatory; the runtime probe does
not duplicate the complete overlap/GPT-table audit. It uses physical0500..0519
for AH48 scratch, 0600..07ff for the relocated MBR and 7c00..7dff for the VBR.

Build/test commands for the profile owner:

```text
python3 shizukudos/csm/ios_gop/boot_probe/build.py --output build/ios-gop/boot-probe.bin
python3 -m unittest discover -s shizukudos/csm/ios_gop/boot_probe -p test_boot_probe.py
```

Host tests establish safe clone preparation. A real guest acceptance requires
all four ordered success markers under OVMF/CSMWrap firmware GOP, followed by
actual Windows 98 IO.SYS/GUI progress and fresh retained guest evidence. The
markers alone establish only the early text and disk handoff.

Source references: the pinned SeaBIOS `src/boot.c` `boot_disk`/`call_boot_entry`
use INT13 then a canonical0000:7c00 entry with DL; pinned `src/disk.c`
`disk_1341`, `disk_1348` and `extended_access` define the EDD interface used
here. [Syslinux's public chainloader](https://raw.githubusercontent.com/geneC/syslinux/master/com32/chain/mangle.c)
documents DS:SI partition handover. Implementation is original GPL-2.0-only
source, without copied third-party assembly.
