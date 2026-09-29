# NTWDDMWrapper9x source provenance

All tracked files in this directory were authored for this project on
2026-09-27. They are licensed under **GPL-2.0-only**, consistent with the
repository's `LICENSE` text. No Microsoft implementation, KernelEx, Wine,
ReactOS, Linux DRM, Mesa, vendor driver, or other third-party implementation was
copied or translated into this directory.

| File | Origin and role |
| --- | --- |
| `include/ntwddm.h` | Original project C interface and capability vocabulary |
| `src/ntwddm.c` | Original allocation ownership, bounds validation, pixel conversion, directed overlapping copy, and completion tracking |
| `tests/test_ntwddm.c` | Original contract tests with a separate snapshot-copy oracle and component-layout table |
| `Makefile` | Original host, sanitizer, and freestanding build checks |
| `README.md`, `PROVENANCE.md` | Original integration, limitations, validation, and provenance documentation |
| `include/nttheme.h`, `src/nttheme.c`, `src/ntstyle.c`, `theme/*.ntth` | Original in-process style loader and pixel painter. See the theme note below |
| `include/ntwd_present.h`, `src/ntwd_present.c` | Original software device, context, and present wrapper. See the present note below |
| `tests/test_theme.c`, `tests/test_present.c`, `tests/sample_window.c`, `tests/evidence.c`, `tests/ppm_to_png.py` | Original host contracts and PPM/PNG evidence |

Only standard compiler-provided integer/size declarations are required by the
core. Host tests use the host C runtime to allocate memory, report failures, and
construct their reference buffers; that runtime is not linked into the
freestanding core object. Common framebuffer component layouts, rectangle
copying, reference counts, and tagged handles are independently implemented
interface concepts, not imported source algorithms.

The `NTWDDMWrapper9x` name identifies the proposed graphics extension family.
It does not assert Microsoft's WDDM ABI compatibility, Direct3D support, vendor
driver compatibility, Windows 98 driver loading, or Windows 10/11 equivalence.

## Theme painter

Reviewed, not copied:

- One-Core-API `dll/win32/uxtheme/draw.c` at
  [`9eb3c31de9460c1ccce3f6a10c9c4a704f032514`](https://github.com/shorthorn-project/One-Core-API-Source/blob/9eb3c31de9460c1ccce3f6a10c9c4a704f032514/dll/win32/uxtheme/draw.c).
  The file header is LGPL-2.1-or-later, copyright 2003 Kevin Koltzau. It is the
  Wine/ReactOS theme painter carried by that tree. The functions read for this
  slice were `UXTHEME_DrawBorderRectangle`, `UXTHEME_DrawBackgroundFill`,
  `UXTHEME_DrawBorderBackground`, and `DrawThemeBackgroundEx`.
- The same border-fill sequence is the ReactOS `dll/win32/uxtheme/draw.c`
  implementation. The repository's ReactOS pin remains
  [`9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8`](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/uxtheme/draw.c)
  and the Wine pin remains
  [`df15af3652511150490934682202d45af892f887`](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/uxtheme/draw.c).
  Both files are LGPL-2.1-or-later. No line from them was copied.

Adaptations: there is no theme service, HDC, GDI pen, or `.msstyles` image.
A text style is parsed in process. A missing part still paints the upstream
defaults (1-pixel black border, white solid fill). A declared image, radial, or
tiled background returns failure and writes nothing; the upstream file returns
success after a `FIXME` for the radial and tile cases. The border is an interior
ring of `bordersize` pixels, not a GDI pen centered on the rectangle edge.
Solid fill and a two-color horizontal or vertical blend are implemented. Text
uses a project 5×7 glyph set with a transparent background, not `DrawTextW`.
Gray text is fixed `0x808080`. Unknown class names fail. This does not make
the historical KernelEx no-theme bridge a themed window.

## Software present

Microsoft documents `D3DKMTCreateDevice`, `D3DKMTCreateContext`, and
`D3DKMTPresent` as Windows Vista kernel calls in `d3dkmthk.h`
([device](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/nf-d3dkmthk-d3dkmtcreatedevice),
[context](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/nf-d3dkmthk-d3dkmtcreatecontext),
[present](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmthk/nf-d3dkmthk-d3dkmtpresent)).
Those headers were not copied. `ntwd_device_create` binds the existing software
framebuffer and allocates a primary, `ntwd_context_create` accepts only the
software node, and `ntwd_present` copies that primary with `ntwg_present`.
`NTWD_CREATE_GPU` and the GPU node return `NTWG_E_UNSUPPORTED` before any
success. This is not `Dxgkrnl`, a vendor miniport, or scanout.
