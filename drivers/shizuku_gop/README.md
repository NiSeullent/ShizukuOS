# Shizuku basic graphics driver

Native Windows 98 display package: SHZGOP.DRV is a 16-bit DIBEngine display
minidriver; SHZGOP.VXD is its 32-bit MiniVDD. It uses the retained firmware GOP
framebuffer supplied by the separate Shizuku CSMWrap firmware GOP profile.
The refreshed interface requires its SHZLOC1 locator allocated by SeaBIOS in
the BIOS F-segment. The native backend scans only that bounded region, rejects
invalid or ambiguous anchors, validates the unchanged 96-byte SHZGOP1 descriptor
and its copied checksum, and matches the recorded PCI owner and current BAR.
The initial low coreboot table is retained for firmware compatibility; it may
be overwritten during a legacy boot and is not the native driver's locator.

This first version supports the exact retained firmware resolution, pitch and
32-bit BGRX format. It renders through the Windows DIBEngine into a software
buffer, then copies changed areas to the physical framebuffer. GPU hardware
acceleration, dynamic resolution changes and fullscreen DOS switching need
separate implementations. Build success does not establish successful guest
installation or rendering; use the native guest validation receipts.
An initialized MiniVDD keeps its callbacks until guest shutdown; live dynamic
unload is rejected because this first version has no callback teardown.

Build from the project checkout:

    python3 drivers/shizuku_gop/build.py --out build/shizukudos/shizuku-gop-anchor

The private Open Watcom toolchain, pinned VMDisp9x reference and pinned fixlink
reference stay under build/. The build never installs drivers, starts a VM,
changes global compiler settings or modifies the reference sources.

Install only in the intended native Windows 98 guest after booting the firmware
profile with gop_only=true. Keep a private clone/checkpoint for returning to the
standard VGA driver. Open Control Panel, Display, Settings, Advanced, Adapter,
Change; choose Have Disk and point to SHZGOP.INF in this package. Select the
Shizuku entry, finish the class installer and restart that guest.

SHZGOP.INF uses CP949 for its Korean device name. The installer copies only the
two driver files into the guest system directory and sets display-device HKR
values. It contains no global registry deletion or application installation.

The package includes complete frozen compiled source inputs, source adaptations
and copyright/license notices. Windows DIBENG.DLL and other Microsoft operating
system files must come from the user's own Windows installation; none are
included. See NOTICE.txt and the build receipt for source lineage and hashes.
