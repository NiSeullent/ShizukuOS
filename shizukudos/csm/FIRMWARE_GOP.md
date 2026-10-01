# Firmware GOP handover for native Windows 98

Build the optional firmware profile in a separate artifact directory:

```text
python3 shizukudos/csm/build.py --out build/shizukudos/csm-gop-anchor --firmware-gop
```

This adds `patches/0002-force-firmware-gop.patch` to the pinned CSMWrap tree.
The default build excludes this patch. The optional firmware still defaults
to `gop_only=false`; its adjacent `EFI/BOOT/csmwrap.ini` must explicitly contain
`gop_only=true` for the GOP path. Keep existing CPU/helper settings as required
by the guest. Do not combine this setting with `vga=` or `vgabios=`.

With `gop_only=true`, firmware selects a usable linear GOP mode and embedded
SeaVGABIOS before all VGA option ROM paths. It retains `SEAVGABIOS` video type,
keeps the GOP controller connected, and emits the standard coreboot framebuffer
record. Missing linear memory, invalid masks, bad pitch or insufficient buffer
size stops the boot. PixelBltOnly is unsupported. SeaVGABIOS exposes the retained
firmware mode through VBE; consumers must discover it rather than assume mode
number `0x140`. Dynamic hardware mode changes are outside this interface.

The standard coreboot table begins at physical `0x500`. Its normal header and
table checksums cover both the framebuffer record and an additional private
record with tag `0x53485a47`. The private record is packed, little-endian:

| Offset | Field |
| ---: | --- |
| 0 | u32 tag = `0x53485a47` |
| 4 | u32 record size = 24 |
| 8 | u64 physical descriptor address |
| 16 | u32 descriptor size = 96 |
| 20 | u32 reserved = 0 |

The descriptor occupies its own unreleased EFI runtime-data page, allocated
above 1 MiB and wholly below 4 GiB. The existing E820 conversion marks that page
reserved. The initial coreboot record locates it; the descriptor never stores host or
firmware protocol pointers. All fields below are packed and little-endian:

| Offset | Field |
| ---: | --- |
| 0 | 8-byte magic `SHZGOP1\0` |
| 8 | u16 ABI major = 1; u16 minor = 0 |
| 12 | u32 descriptor size = 96 |
| 16 | u32 checksum: sum of all 24 u32 words, including checksum, equals zero modulo 2^32 |
| 20 | u32 flags: linear = 1, fixed mode = 2, valid PCI identity = 4 |
| 24 | u64 final framebuffer physical base, written after PCI relocation |
| 32 | u64 actual GOP FrameBufferSize, captured before ExitBootServices |
| 40 | u64 visible bytes = pitch × height, at most FrameBufferSize |
| 48 | u32 width; u32 height; u32 pitch in bytes; u32 bits per pixel |
| 64 | u32 red mask; u32 green mask; u32 blue mask; u32 reserved mask |
| 80 | u16 PCI segment; u8 bus; u8 device/function (`device << 3 | function`) |
| 84 | u16 PCI vendor; u16 PCI device |
| 88 | u32 original firmware GOP mode number |
| 92 | u32 reserved = 0 |

The low coreboot table can be reused by a legacy operating system. The additional
`SHZLOC1` locator provides a separate persistent discovery interface without
changing either coreboot or the 96-byte descriptor. After successful SeaBIOS
initialization, CSMWrap calls `Legacy16GetTableAddress`: AX=6, BX=1 (F000 only),
CX=48, DX=16. The pinned `seabios/src/fw/csm.c` implementation allocates from
`ZoneFSeg` using `_malloc`; `malloc_init` obtains that zone from linker symbols
`zonefseg_start` and `zonefseg_end`, and `malloc_prepboot` clears only unused
space. No hardcoded ROM hole is overwritten. The allocated anchor is populated
before PrepareToBoot, whose whole-BIOS checksum then includes it, and checked
again before boot. No allocation is released. The existing reserved descriptor
has already received its final PCI-relocated base and checksum.

The locator is packed and little-endian:

| Offset | Field |
| ---: | --- |
| 0 | 8-byte magic `SHZLOC1\0` |
| 8 | u16 ABI major = 1; u16 minor = 0 |
| 12 | u32 locator size = 48 |
| 16 | u32 checksum: sum of all 12 u32 words equals zero modulo 2^32 |
| 20 | u32 self physical address, 16-byte aligned in the F-segment |
| 24 | u64 physical descriptor address, page aligned above 1 MiB and below 4 GiB |
| 32 | u32 descriptor size = 96 |
| 36 | u32 final descriptor checksum copied from descriptor offset 16 |
| 40 | u32 flags = 1 (F-segment allocator) |
| 44 | u32 reserved = 0 |

Consumers scan only the 64 KiB physical F-segment, `0xF0000..0xFFFFF`, at
16-byte boundaries. Require exactly one matching, self-validating anchor,
complete 48-byte containment, ABI 1.0, checksum, flags and reserved fields.
A matching-magic malformed or duplicate anchor fails the entire scan. Follow
only its validated descriptor page; require the descriptor's own checksum
and a match to the checksum copied into the anchor. This is a deliberate BIOS
discovery ABI, not an arbitrary RAM signature search. Physical capture of the
entire F-segment and pointed descriptor page through actual Windows VMM startup
and reboot must establish lifetime before reporting that behavior as validated.

A native Windows 98 consumer must validate the selected locator's bounds/checksum,
descriptor bounds/version/checksum, geometry, actual framebuffer range and
pixel format before mapping memory. PCI fields are usable only when flag 4 is
set. A consumer using 32-bit physical mapping must reject any framebuffer range
crossing 4 GiB. The first BGRX consumer can reject other firmware formats.

This firmware profile supplies the framebuffer handover. A native Windows 98
display `.DRV` and its VxD must separately implement GDI/DIBEngine and VDD
interfaces. Building firmware does not establish native driver installation,
guest rendering, or successful forced-GOP boot; each needs guest evidence.
