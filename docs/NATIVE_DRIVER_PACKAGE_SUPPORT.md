# Native driver package support (installer default catalog)

Source base: HEAD 487000bd43f7b07d51a77cacac2665b642d0b700 (dirty tree, peer edits present).

The production `DRIVERS` list in `shizukudos/install/mkpayload.py` advertises only drivers for which
`shz_catalog_builtin_driver()` (`shizukudos/kernel64/ntdrv_catalog.c`) returns a linked native provider.

| Package | Match | Provider |
|---|---|---|
| rtl8139 | 10ec:8139 | net_rtl8139.c |
| bochs-vbe | 1234:1111 | gfx_fb.c |
| ahci | class 01:06:01 | ahci_blk.c |
| nvme | class 01:08:02 | nvme.c |
| sdhci | class 08:05 | sdhci.c |
| virtio-gpu | 1af4:1050 | gfx_virtio.c (gfx_backend_virtio, first entry of gfx_backends in gfx_fb.c; probe via virtio_pci_find(GPU)) |

Not advertised:
- `1af4:1110` RAM block device (blk_ram.c): no native builtin mapping. It remains a source and installer
  developer test target; it is not a native production builtin package.
- generic virtio `1af4:1040-107f`: virtio_pci.c is a transport library, not a device provider; the range has no
  mapping and the parser refuses it. Only the exact GPU id 1af4:1050 is claimed.

The runtime catalog parser, allowlist, Kind validation, security checks and driver initialization are unchanged.

The default answer `Install=all` selects these six packages. Explicit selections use the package names in the table;
use `virtio-gpu` for the exact GPU package. Old selections `ram` and `virtio` select no package in this catalog.
The developer target setting `[Target] Select=first-ram` is independent of package selection and remains available.

Check: `python3 shizukudos/install/tests/test_native_driver_package_catalog.py` builds the real parser host-side and
feeds it every production row; all must be accepted. This is not a boot, installation or VM proof. virtio-gpu has
not been exercised in a guest by this change. Driver support is limited to the listed devices.
