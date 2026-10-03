# Source provenance for the native ShizukuOS shell

Scope: code, data and designs that the Korean ShizukuOS shell (`shizukudos/win64/apps/shizuku_shell`) and its
font data (`shizukudos/win64/dlls/gdi32`) take from outside this repository. The older whole-repository record
is [THIRD_PARTY.md](../THIRD_PARTY.md). An entry exists only when a worker has actually reported imported or
adapted material; "reference only" is stated as such. Per-file license headers in the imported files take
precedence over the summary here. Entries marked PENDING are not yet reported and are not claims.

| Upstream | Source | Intended use | License (verify per file) | Status |
| --- | --- | --- | --- | --- |
| ReactOS | https://github.com/reactos/reactos (Explorer, shell32, comctl32 shell components) | Shell structure and adapted code | Explorer: LGPL-2.1-or-later; other files per header (GPL-2.0-or-later/LGPL) | Reference only: `apps/shizuku_shell` is original project code; no Explorer source imported in this cohort |
| One-Core-API-Source | https://github.com/shorthorn-project/One-Core-API-Source | Modern Win32 API wrapper reference/adaptations | Per-file (GPL-2.0 / LGPL) | Reference only: no One-Core source imported in this cohort; current file-manager API implementations are original project code |
| Shorthorn 4074 visual style | No verified public source of a 4074 or 4083 shell binary or source has been identified | Visual reference only; no code, resources or binaries are used | n/a | Reference; do not copy Microsoft resources |
| GNU Unifont | https://unifoundry.com/unifont/ | Hangul glyph data for the GDI32 text path | GPL-2.0-or-later with the GNU font embedding exception (OFL-1.1 for the licensed font variants); verify the release used | Imported glyph data: Unifont 18.0.01, source SHA-256 `e66385c79a0b8b24a466f3129930e08a966a935b4bf3b28c6bb17a9df9bf791d`; generated `gdi_font_data.c` SHA-256 `4bf779c75ab1149e4bece1ccfb8b1f2d93bdde6b95861a1f4de4718b834fadec`. Full license and generation record: `shizukudos/win64/dlls/gdi32/fonts/README.md` |

Rules: preserve upstream copyright and license headers; record the upstream commit or release and the SHA-256 of
every imported file here when it lands; no Microsoft binaries, resources or private installation media; the
public Core ISO contains none of them. `win64/build.py` hashes every local source (including generated glyph
C and data files) into `sources_sha256` of `build-result.json`.

## Native GUI rasterization

The built-in raster font now has real grayscale antialiasing: a bilinear contour of the public bitmap glyph is area-sampled at 4×4 positions per output pixel, then its coverage is composited against the actual destination RGB. This is not a TrueType/outline font engine or ClearType. Current GDI font sizes remain integer cell scales; shaping, arbitrary font loading and Hanja coverage are separate work. `ANTIALIASED_QUALITY` smooths both ASCII and Hangul, and `NONANTIALIASED_QUALITY` retains discrete bitmap rendering. Kernel non-client caption rendering uses the same licensed data and coverage routines. Actual guest validation is recorded separately from host glyph checks and builds.
