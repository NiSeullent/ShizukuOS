# Opt-in Windows 98 visual-style provider

`M98THEME.DLL` renders the existing NTWDDM Classic/Modern styles through native
Windows 98 GDI. It starts disabled. A cooperating application loads this unique
DLL or imports it by name, calls `M98SetThemeStyle(1)` for Classic or `(2)` for
Modern, opens a supported class, and uses the exported theme APIs to paint.
`M98SetThemeStyle(0)` disables this provider. The application sends its own
`WM_THEMECHANGED` after a style selection and closes/reopens its theme handles.

The original `src/uxtheme_shim.c`, its no-theme tests, and KernelEx KnownDLL
build/install routes are unchanged. This DLL does not install itself, replace
UXTHEME, hook or repaint arbitrary applications, theme system common controls,
change the desktop, or enable msstyles/DWM/GPU composition. Office, Signal and
Legcord require separate integration and app-function tests; this change is a
real rendering prerequisite, not evidence that those applications run.

## Exact supported surface

| Class | Part | States |
| --- | --- | --- |
| BUTTON | PUSHBUTTON (1) | normal (1), hot (2), pressed (3), disabled (4) |
| WINDOW | CAPTION (1) | active (1), inactive (2) |
| WINDOW | FRAMELEFT (7), FRAMERIGHT (8), FRAMEBOTTOM (9) | active (1) |

`OpenThemeData` recognizes ASCII class names without case sensitivity and
honors ordered semicolon lists. Unknown classes and unknown part/state queries
fail. `IsThemePartDefined` reports only declared states. The background path
uses the original parsed NTWDDM border-fill/linear-gradient pixels, a temporary
top-down 32-bit DIB, native BitBlt and GdiFlush. It preserves DC state and clip.
Background rendering supports MM_TEXT, signed target positions, optional
rectangular clipping, and empty rectangles. It bounds a temporary part to
16,384 pixels per dimension and 128 MiB; larger requests fail before painting.

Available properties are border/fill/text color, the two gradient colors on
gradient parts, border size, background/fill enumeration and derived
one-pixel content/sizing margins. Content rectangles clamp tiny parts to an
empty interior. `GetThemeFont(TMT_FONT)` and text drawing use the actual Windows
message font; `GetThemeSysFont` supports the six original system-font IDs.

`DrawThemeText`/`DrawThemeTextEx` use real ANSI GDI formatting for UTF-16 strings
that round-trip exactly through the active ANSI code page. Punctuation,
accelerator prefixes, layout flags, explicit lengths and DT_CALCRECT work;
`DTT_TEXTCOLOR` overrides the color. Part zero keeps the caller's selected font.
The conversion checks both usedDefaultChar and an exact ANSI-to-UTF16 round
trip, so best-fit mappings and unsupported text fail without drawing.
Korean text is supported when exactly representable in CP949. This is not a
full Unicode shaping/font-fallback implementation. Other DTT effects fail.

`Get/SetThemeAppProperties` retains the documented three flags. The provider
has controls and nonclient-part painters; web-only enablement does not report
`IsAppThemed`. These flags do not install automatic nonclient hooks.
`SetWindowTheme` supports empty-string disabling, NULL reset and a supported
class override, followed by synchronous WM_THEMECHANGED outside the engine
lock. Application-specific namespaces return E_NOTIMPL. HWND APIs require
windows belonging to the current process. Foreign HWNDs cannot import cookies
from another process. Closing a handle clears its matching window association.

## Ownership and validation

The adapter maps opaque 32-bit cookies to the painter's 64-bit handles. It never
dereferences caller-supplied handles. There are 128 live API handles, with
generations that retire instead of wrapping. A style change invalidates drawing
with older handles but permits their close. Process-local access is serialized
by a lazily initialized critical section; window callbacks run outside that
lock. Explicit DLL unload cleans open core handles and matching window handle
properties. Applications must finish outstanding calls before FreeLibrary.

The portable painter gains `ntth_query_part`, which performs the same handle
and style-generation validation as drawing and leaves outputs unchanged on
failure. The internal painter capacity increases from 8 to 256 to accommodate
multiple application controls; no drawing algorithm or existing default-part
fallback is changed.

Build and run the meaningful host checks with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/build_theme_engine.py
make -C ntwddm test freestanding freestanding32
```

The builder writes only `build/theme-engine/`, compiles/runs the portable
ordinary and ASan/UBSan tests, and cross-builds native DLL/direct/static probes.
Its PE gates require i386 Windows GUI/OS 4.10, relocations, no ASLR/NX/TLS/CLR/
delay/load-config directories, exact undecorated exports, and every system
import in the pinned Windows 98 OEM-native manifest. The static probe imports
ordinary named M98THEME functions. KernelEx sources are not required.

The source-bound receipt is `build/theme-engine/result.json`. It reports
`native_win98: not_tested` until the guest owner runs both probes. Host results
and PE checks are not guest execution evidence.

For a disposable authorized Windows 98 clone, copy `M98THEME.DLL`,
`M98THPRO.EXE` and `M98THSTA.EXE` from that directory to one writable guest
directory. Freeze their SHA-256 values from the receipt first. Run each probe
with stdout captured. Each displays a real Classic/Modern comparison for fifteen
seconds and then exits. Accept guest evidence only with `WIN98_IDENTIFIED=1`,
the final PASS, exit code 0, matching file hashes, and a separately captured
visible comparison. The probes check GDI pixels, clip preservation, real font
metrics, content geometry, text/DC restoration, stale/double-close behavior,
window notifications and exact-code-page behavior. CP1252 additionally tests
silent best-fit minus rejection; CP949 tests Korean; non-UTF8 ACP tests lossless
rejection of an unsupported emoji. No guest settings, registry route, installed
system DLL, or shared VM is changed by the probes.

## Source lineage

All new files are original GPL-2.0-only project code. No upstream implementation
was copied. The NTWDDM painter retains `ntwddm/PROVENANCE.md`. Reviewed contracts:

- [Wine system.c](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/uxtheme/system.c)
  and [draw.c](https://github.com/wine-mirror/wine/blob/df15af3652511150490934682202d45af892f887/dlls/uxtheme/draw.c).
- [ReactOS system.c](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/uxtheme/system.c)
  and [draw.c](https://github.com/reactos/reactos/blob/9dc3ca87209fd8ebabd96c8ea95d439c13e7fdf8/dll/win32/uxtheme/draw.c).
- Microsoft [OpenThemeData](https://learn.microsoft.com/en-us/windows/win32/api/uxtheme/nf-uxtheme-openthemedata),
  [SetWindowTheme](https://learn.microsoft.com/en-us/windows/win32/api/uxtheme/nf-uxtheme-setwindowtheme),
  [DrawThemeTextEx](https://learn.microsoft.com/en-us/windows/win32/api/uxtheme/nf-uxtheme-drawthemetextex)
  and [SetThemeAppProperties](https://learn.microsoft.com/en-us/windows/win32/api/uxtheme/nf-uxtheme-setthemeappproperties).
