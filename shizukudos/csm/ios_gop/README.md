# GOP BIOS mode 03 text geometry

This optional source patch makes BIOS text mode `03h` report an 80-column,
25-row viewport over CSMWrap's existing GOP framebuffer. It retains the
physical framebuffer address, pitch, native resolution and VBE mode list.
It does not modify Microsoft's `IO.SYS` or implement a Windows display driver.

The native framebuffer and the logical text screen are separate. With the
observed 1280×800, 32-bit framebuffer and 5120-byte pitch, unmodified
SeaVGABIOS copies the native geometry into its emulated text mode. Mode 03
then reports 160 columns and 50 rows. Its graphics-derived page-size formula
returns 131072 through a 16-bit value, producing a zero BDA page size.

The patch changes only the emulated mode:

| Item | Explicit GOP profile, mode 03 |
| --- | --- |
| Logical pixel viewport | 640×400 |
| Font cell | 8×16 |
| BDA columns / final row | 80 / 24 |
| BDA text page size | 4096 bytes |
| Cursor shape | Existing text-emulation `0607h` |
| Physical pitch / framebuffer | Existing values, unchanged |
| Native VBE geometry / mode list | Existing values, unchanged |

`MM_DIRECT` and `BF_EMULATE_TEXT` retain their existing meanings. Character
rendering continues through SeaVGABIOS's graphics path. Changing the memory
model to `MM_TEXT` would redirect character writes to legacy VGA memory;
this patch keeps the framebuffer path selected.

The behavior is enabled only when coreboot framebuffer setup observes the
private Shizuku GOP record, tag `0x53485a47`, with its 24-byte record size.
The decision is cached in SeaVGABIOS during setup. Later BIOS mode switches
do not reread the low coreboot table, which the native DOS boot may reuse.
The ordinary coreboot, Bochs-display and ramfb profiles retain their existing
behavior. A malformed marker, missing framebuffer or geometry unable to
contain the viewport causes setup to fail instead of claiming compatibility.

The pure helper accepts the existing direct-color depths 15, 16, 24 and 32.
It rejects undersized screens, dimensions exceeding SeaVGABIOS's 16-bit mode
fields, undersized or misaligned pitches, and scanline spans exceeding signed
32-bit arithmetic. Framebuffer aperture and pixel-mask validation remain the
firmware GOP profile's responsibility. The acceptance target for this change
is BIOS text page 0; additional text pages and direct VGA-memory writes require
separate implementation and evidence.

## Integrating the optional patch

`patches/0001-legacy-gop-mode03-text-geometry.patch` is intentionally outside
the existing `shizukudos/csm/patches` directory. Existing CSM builders do not
pick it up automatically. Apply it only to a private CSMWrap source tree used
for the intended IO.SYS/GOP experiment:

```sh
git -C /absolute/private/csmwrap apply --check /root/Win98-Modern-boot/shizukudos/csm/ios_gop/patches/0001-legacy-gop-mode03-text-geometry.patch
git -C /absolute/private/csmwrap apply /root/Win98-Modern-boot/shizukudos/csm/ios_gop/patches/0001-legacy-gop-mode03-text-geometry.patch
```

The patch adds its own `seabios/vgasrc/shz_legacy_text_geometry.h`; no manual
header copy is required. The canonical header in this module must match the
added header byte-for-byte. The patch touches `cbvga.c` and `vgabios.c` and
does not overlap the helper-AP fix in `stacks.c` or the firmware GOP patch's
CSMWrap files. Helper, geometry and GOP patches can therefore be applied in
that order. Runtime activation still requires `gop_only=true` and the
firmware GOP profile's private record. Rebuild embedded SeaVGABIOS as well
as the EFI application in the private tree; applying source alone does not
update an existing `csmwrap.efi`.

## Host validation and source lineage

```sh
PYTHONDONTWRITEBYTECODE=1 python3 /root/Win98-Modern-boot/shizukudos/csm/ios_gop/tests/test_mode03_geometry.py
```

The host suite needs a C compiler (`CC`, default `cc`) and `git`. It runs three
tests without requiring the project build tree. It checks the recorded source
and patch hashes, applies the actual patch to pinned open-source fixtures in a
temporary directory, then compiles and runs the actual patched functions with
host memory accessors. This exercises geometry rejection, output preservation
on rejection, real BDA and `AH=0Fh` updates, physical-pitch retention, native
mode switching, ordinary-profile behavior and the cached activation gate.

The retained fixtures are an unmodified pinned `cbvga.c` and the upstream
license/includes plus complete `calc_page_size`, `vga_set_mode` and
`handle_100f` functions from `vgabios.c`. Unrelated handlers are omitted.
No Microsoft binary is included or inspected by these tests. Only temporary
host files are patched or compiled; no VM, firmware service, network or
privileged device is used. The three tests passed on the implementation host.

`source-lineage.json` records the CSMWrap revision
`7f30b740c352ee952eb596bf10ae263a8a5da4c7`, its SeaBIOS revision
`578d260b94f62150bf6ab9149784287bd1154f06`, original source hashes, retained
fixture hashes, helper identity and patch identity. The fixtures retain their
upstream copyrights; this module and its integration patch use LGPL-3.0-only.
Complete license texts are under `LICENSES/`.

## Native acceptance still required

Host validation establishes the source-level geometry and mode-state change.
The next guest check must query mode 03 through `INT 10h/AH=0Fh`, independently
read the BDA, exercise the rightmost column and 25-row scrolling, and capture
pixels from the actual retained GOP framebuffer. It should record the tested
EFI hash and verify that the native VBE mode still reports its original
physical dimensions and pitch.

Actual Windows 98 acceptance then requires its IO.SYS to reach the DOS screen
through this firmware path. GUI entry, driver loading, application interaction
and saved-file persistence are separate checks. The previously retained GOP
recovery run reached a real-mode `mshbios` missing-device prompt; neither this
geometry diagnosis nor the host tests establish the cause of that stop or a
successful native GOP desktop. A low-table locator-survival fix and the native
Windows display driver remain independently owned work.
