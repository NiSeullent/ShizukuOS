# Section-backed software DIB pixels

The existing 32-bpp raster backend now maps a writable section supplied to
`CreateDIBSection`. Its pixel pointer refers to the actual shared pages; creation
does not allocate a private copy or clear preexisting pixels. DWORD-aligned pixel
offsets are accepted by mapping the preceding 64-KiB-aligned section offset and
retaining the separate owned view base. Checked arithmetic bounds dimensions,
row bytes, pixel extent and view extent before mapping. The real section provider
enforces handle type, access rights and section length.

`DeleteObject` retains a bitmap selected into a live DC. An unselected shared
bitmap unmaps its owned view, and never closes the caller's section handle.
`GetObject` reports the actual pixel pointer, caller handle, section offset and
BITFIELDS masks. Extended V4/V5 headers use masks at their documented header
offset. Private DIBs continue to ignore the offset when no section is supplied.

This is original GPL-2.0-only adaptation, with no upstream code copied, after
reviewing these pinned providers:

- Wine 11.0 commit `db11d0fe6a169c457e23d007e20404643d067aa8`,
  `dlls/win32u/dib.c`, `NtGdiCreateDIBSection` and `DIB_DeleteObject`.
- ReactOS commit `9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8`,
  `win32ss/gdi/ntgdi/dibobj.c`, `DIB_CreateDIBSection`.
- [Microsoft CreateDIBSection contract](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createdibsection).

The implementation supports the existing 32-bpp `BI_RGB` and standard RGB-mask
`BI_BITFIELDS` formats with `DIB_RGB_COLORS`. Other formats fail explicitly.
Writable shared views require a read-write section; the section provider does
not yet support a `PAGE_WRITECOPY` DIB view. No compatibility percentage, graphics
factory, D3D acceleration or completed application rendering is established.

The host test compiles the actual production layout helper and checks arithmetic
under address and undefined-behavior sanitizers. The AMD64 guest fixture
`tests/t_dib_section_shared.c` uses real sections, memory DCs, a child process,
cross-process pixel writes, `BitBlt`, metadata, rights failures and mapped-view
release. Native compilation of both full GDI and the fixture has passed; actual
guest execution must have its own runtime/kernel/log receipt before being called
a behavior pass.

Chromium 150's existing GDI software output device needs a shared section for its
Skia canvas. Its default Win11 `RemoveRedirectionBitmap` feature instead selects
a DXGI/DComp software swapchain even with `--disable-gpu`. The official
`--disable-direct-composition` switch disables that selection and exposes the GDI
path for an actual application experiment. The application argument and
framebuffer outcome must be recorded separately from these API contract checks.

Sources: [software device selection](https://raw.githubusercontent.com/chromium/chromium/150.0.7871.129/components/viz/service/display_embedder/software_output_device_win.cc),
[feature and switch gate](https://raw.githubusercontent.com/chromium/chromium/150.0.7871.129/components/viz/common/features.cc).
