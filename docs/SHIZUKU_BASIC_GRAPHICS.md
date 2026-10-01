# Shizuku 기본 그래픽 드라이버

The native package consists of SHZGOP.DRV (16-bit DIBEngine minidriver),
SHZGOP.VXD (32-bit MiniVDD) and CP949 SHZGOP.INF. The adapter name is
“Shizuku 기본 그래픽 드라이버”. It uses the opt-in firmware GOP profile,
not the independent ShizukuDOS graphics driver.

The retained fixed mode is 32-bit BGRX. DIBEngine renders into a software
buffer and copies changed areas to the validated physical framebuffer.
There is no GPU 3D acceleration, dynamic resolution or fullscreen DOS mode
in this version. CPU KVM acceleration is separately demonstrated in the
native Windows 98 legacy-VGA runs.

The firmware profile refuses VGA option-ROM boot and emits the checksummed
96-byte SHZGOP1 ABI 1.0 descriptor in reserved firmware runtime memory.
Its coreboot-table locator is the private tag 0x53485a47. The native backend
checks bounds, channel masks, geometry, PCI identity and the current BAR
before mapping the visible aperture. UEFI services are not called from
Windows. Locator survival across Windows startup needs the actual physical
memory trial; a reserved descriptor alone is insufficient.

339 actual C-parser host checks passed, including all descriptor-byte
corruptions and malformed coreboot records. Firmware source/config tests and
NE/LE/package checks also passed. These are host results, not installed
Windows graphics proof.

The current NE-selector-fix package is 415,345 bytes, SHA-256
`5fdc6ca5942012b6d29a291ca85e6ad4e5ca28421477394bfd2909c64f9c5dbb`.
The original frozen package remains archived separately.
The ZIP includes complete frozen corresponding source, source adaptation
patches, GPL/MIT notices and the linked Watcom runtime notice. Its build
receipt is `build/shizukudos/shizuku-gop-ne-selector/build-result.json`. No Microsoft display-engine
binary, Windows disk or proprietary application is shipped.

Frozen opt-in CSMWrap EFI: 475,136 bytes, SHA-256
`17926603f65cb465ea3750d3b5cf51e839ddd3a04c614c989a9b2ab09aa3d0b0`.
The native Windows firmware-handoff and driver-install/render trials are
passed the tested native fixed-mode GUI/GDI boundary. A stock VGA driver can fail under forced GOP; this must remain
separate from the historical successful VGA option-ROM GUI screenshots.

Build/install details: `drivers/shizuku_gop/README.md`.
Firmware details: `shizukudos/csm/FIRMWARE_GOP.md`.
Minimal VxD load/unload acceptance is described in
`ntwrapper/vxd/minimal/README.md`; it does not prove this full MiniVDD.

## Native continuation

The original 0x500 coreboot locator was overwritten during Windows startup;
the reserved descriptor survived. The additive 48-byte SHZLOC1 locator is
allocated through SeaBIOS Legacy16GetTableAddress AX6/BX1 ZoneFSeg, not a
hardcoded ROM overwrite. Native consumers scan only aligned F-segment slots,
require a unique checksummed self-bound locator and validate its descriptor.

The genuine Windows98 class installer completed and both installed files
matched the frozen input bytes. That screenshot precedes restart and does not
establish GOP rendering. The next forced-GOP boot actually executed the
MiniVDD, found SHZLOC1 at0xF0FD0, validated its descriptor and logged native
READY at1280x800x32, pitch5120/base0x80000000. GUI entry then failed.

The native Win16 dependency audit confirmed all six required KERNEL ordinals
and all35 DIBENG ordinals. A single internal selector relocation incorrectly
references nonexistent segment3 in the two-segment DRV. The corrected build
uses its real CS selector; 18 strict relocation and native-ordinal closure
checks passed. The current native run reaches DriverInit/VxD connection and
1280x800x32 Enable, and a validated physical framebuffer capture contains the
actual Korean Windows98 desktop.

An earlier review incorrectly treated early black initialization captures as
the final monitor state. The additive correction at
`build/shizukudos/csm/gop-monitor-correction-audit-20260930T155157/correction-audit.json`
(SHA-256 `a01cef2ab1b74594fcac22a68d97450ff513560b446f2621c817dba1ff6b9969`)
preserves both original execution receipts and their old reviews. The first
corrected cold run's original QMP `screen-061.png` shows the genuine Windows98
Start menu. The second run's original `screen-089.png` shows the native GDI
test window; all 15,360 client pixels match the probe's actual red/blue pattern
and BGR FNV-1a `7ba089c5`. Fresh native reports identify OS4.10.2222, the
installed Shizuku adapter, successful fill/copy/display-readback and actual
child exit0. Both installed driver files match the frozen package inputs.

These two runs needed no MMIO register intervention. This establishes actual
Windows98 UEFI/forced-GOP GUI and native GDI rendering in Q35/KVM's retained
1280x800x32 mode. It does not establish GPU3D acceleration, all hardware,
automatic prompt-free boot or complete latest-application support.
