# Private AMD64 theme provider candidate

This module builds an application-local `UXTHEME.DLL` for the independent
Kernel64 runtime. It compiles the existing shared painter and GDI adapter:
`src/uxtheme_engine_core.c`, `src/uxtheme_engine_win32.c`, `src/uxtheme_sysfont.c`,
`ntwddm/src/nttheme.c`, `ntwddm/src/ntstyle.c`, and the freestanding memory
primitives. It does not modify those files or any consumer's runtime/image.

The final Modern candidate has **zero unresolved import names** in the supplied
51-DLL cb43 runtime. The six initial USER32 ANSI dependencies are resolved by
private, checked transport to the actual W endpoints. All 14 GDI32, 13 Kernel32
and nine USER32 import names are present. Export presence does not establish
Windows ABI semantics, loader behavior or actual guest rendering.

The original 22 exports retain their implementation and explicit process-local
style selection. The build option `--default-style off|classic|modern` selects
an initial application-local style, with OFF as the default. This is applied
once after successful engine creation inside the original lazy `enter()` lock.
The helper calls core APIs directly, so it does not reenter public theme
initialization or run in DllMain. Later process-local style changes still work.
The final private trial DLL explicitly selects Modern. Actual integration must
test real window/HDC rendering and cleanup. There is no native Windows 98 AMD64
loader/GUI bridge supplied by this module and no system theme registration.

Two additional exports cover the six UXTHEME delay imports observed in the
official Signal 8.28.0 AMD64 executable:

* `GetThemePartSize` queries the real shared theme's background type and border
  thickness. It supports the built-in borderfill parts: `TS_MIN` is twice the
  border width on each axis; `TS_TRUE` and `TS_DRAW` add one content pixel.
  Invalid enums/rectangles, stale handles, property query failures and overflow
  leave caller storage unchanged. Image backgrounds return `E_NOTIMPL`.
* `DrawThemeBackgroundEx` is exported by name and ordinal **47**. No options and
  `DTBG_CLIPRECT` delegate to the existing GDI/DIB renderer. Other options return
  `E_NOTIMPL` before drawing. This is partial documented support, not a blanket
  claim that Signal's calls will succeed.

The ordinal is verified in the [pinned primary Wine export specification](https://raw.githubusercontent.com/wine-mirror/wine/df15af3652511150490934682202d45af892f887/dlls/uxtheme/uxtheme.spec).
The ABI and options follow Microsoft's
[GetThemePartSize](https://learn.microsoft.com/en-us/windows/win32/api/uxtheme/nf-uxtheme-getthemepartsize),
[DrawThemeBackgroundEx](https://learn.microsoft.com/en-us/windows/win32/api/uxtheme/nf-uxtheme-drawthemebackgroundex)
and [DTBGOPTS](https://learn.microsoft.com/en-us/windows/win32/api/uxtheme/ns-uxtheme-dtbgopts)
documentation. The borderfill size behavior was checked against the
[pinned Wine implementation](https://raw.githubusercontent.com/wine-mirror/wine/df15af3652511150490934682202d45af892f887/dlls/uxtheme/draw.c).
The small extensions were written originally; no Wine implementation was copied.
All module source and shared dependencies use GPL-2.0-only; see repository
`LICENSE` and the existing adapter's Wine/ReactOS reference comments.

The build makes exact-anchor cookie and lazy-creation substitutions in a private
generated copy of the shared adapter, plus private header inclusions. It also
adds a transport header to a generated copy of the shared system-font source.
A 64-bit `HTHEME` with
nonzero upper bits must not alias a valid 32-bit generation cookie. The tested
`cookie.h` helper rejects it; the existing i386 adapter remains untouched.
Both original and generated adapter hashes and the replacement are retained.

The private `transport.c` helpers marshal only the shared painter's calls:

* Bounded ASCII property names become UTF-16 for real Get/Set/RemovePropW calls;
  window and data handles keep all 64 bits.
* Only `WM_THEMECHANGED` with zero parameters is forwarded to SendMessageW.
* The metrics getter maps 340/344-byte ANSI structures to the 504-byte Unicode
  form and copies back only the caller's declared bytes. Numeric font fields
  are preserved, and face names require an exact ACP conversion roundtrip.
* The icon-title getter maps 60-byte ANSI fonts to 92-byte Unicode fonts and
  propagates endpoint failures. The currently inspected consumer SPI W source
  does not implement that request, so icon-title queries remain unsupported
  there; this provider does not invent a font or return false success.
* Text is bounded to 1 MiB and strictly roundtripped before DrawTextW. Supported
  alignment, wrapping, clipping, CALCRECT, prefix and end-ellipsis flags are
  passed through. Other flags, including EXPANDTABS and MODIFYSTRING, are
  rejected. The inspected W renderer supports a fixed font and incomplete
  prefix decoration; only a guest test can establish the resulting display.

These helpers are not exported USER32 functions and never change system
parameters. Every getter writes caller output only after successful transport
and conversion. See Microsoft's [metrics compatibility documentation](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-nonclientmetricsa)
and [SystemParametersInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow).

Build and read-only consumer inspection:

```text
python3 -B ntwddm/win64/theme_provider/build.py --runtime-dir /absolute/consumer/runtime/dll-directory --default-style modern
```

Each run creates a unique private `build/<UTC>-<id>` directory containing the
candidate DLL, generated adapter, commands and `result.json`. It runs the
shared engine's lifecycle/pixel tests, extension geometry/dispatch tests,
Unicode transport/buffer tests and all three default-style initialization tests
with and without AddressSanitizer/UndefinedBehaviorSanitizer. The extension
tests use the actual shared theme engine for size queries but mock GDI dispatch;
the transport tests use strict host iconv conversions and mock Windows endpoints.
Default-style tests use the actual shared engine, render real pixels and inject
all initialization allocation failures. These tests do not execute the Windows
adapter, exercise actual Windows locking or establish Windows ABI execution.

The PE gate checks an AMD64 PE32+ DLL, all 24 exports, true ordinal 47, normal
named Kernel32/User32/Gdi32 imports, relocations and absence of CRT/TLS/delay/CLR
dependencies. It hashes and parses the consumer's actual DLLs before and after
the build. Missing exports or unresolved forwarders yield
`STATIC_CANDIDATE_BLOCKED`; present names yield only
`STATIC_CANDIDATE_READY_FOR_GUEST_TEST`. Export presence cannot establish API
semantics. Native Win98, Kernel64, OS-wide themes and Signal functionality
verification are always recorded as false here.

Validated local build:

```text
receipt: build/20261001T075428Z-c6a4cba4/result.json
receipt SHA256: d600690879ef79edd2f871faf6676989dbe4745eb09afd48407ef7db1cbb63b3
UXTHEME.DLL SHA256: f8e69da3c430f9b237fc490ea5f72cae8d3bcffab5b1efc77208ead22ce95442
bytes: 40341
default style: Modern (explicit application-local build option)
shared engine: 312 checks, normal and ASan/UBSan
extensions: 507 assertions, normal and ASan/UBSan
Unicode transport: 878 assertions, normal and ASan/UBSan
default styles: 192 assertions, normal and ASan/UBSan
consumer: 51 AMD64 DLLs, hashes/exports stable before and after build
result: STATIC_CANDIDATE_READY_FOR_GUEST_TEST (zero unresolved import names)
```
