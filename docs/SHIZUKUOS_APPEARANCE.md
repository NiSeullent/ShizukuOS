# ShizukuOS appearance settings

`SHZAPPEAR.EXE` is the userland settings application for Classic and ShizukuOS.
Keep it next to its matching `M98THEME.DLL`. It loads that adjacent DLL by its
absolute path and draws its caption preview and action buttons through the real
theme/GDI provider. The ShizukuOS palette is a third style, not an alias for
Modern. Existing OFF 0, Classic 1 and Modern 2 retain their values; ShizukuOS is 3.

Choose Classic or ShizukuOS to preview it. Apply saves the selection for the
current user; Close leaves the saved selection unchanged. Tab and Space select
controls. Enter applies the selection, except when Close has focus; Escape
closes. The dynamic theme function types are checked against the MinGW SDK ABI,
including the second flags argument of `DrawThemeText`.

Participating userland uses these undecorated stdcall exports:

```c
HRESULT WINAPI ShizukuOSLoadUserTheme(void);
HRESULT WINAPI ShizukuOSSaveUserTheme(DWORD style);
```

The profile is `HKCU\Software\ShizukuOS\Appearance`, value `ThemeStyle`, with
type `REG_DWORD` and valid values 1 and 3. Loading a missing key/value selects
ShizukuOS 3 for a new user. Reading malformed values or access errors fails
without rewriting the registry. The settings application shows an error and
temporarily previews ShizukuOS; only an explicit Apply can replace the saved
value. Saving validates the selector before opening a key, closes all keys it
successfully opens and returns registry errors. Save does not change another
process's active style.

The shell and other themed applications must explicitly call Load at startup
and reload the profile when their integration receives a settings change. They
must reopen theme handles after changing styles. This source batch does not
install global hooks, replace a system DLL or automatically repaint existing
applications. Common controls, nonclient windows, the AMD64 provider, Kernel64
and the installer still need their own integration and fresh acceptance.

Build into a fresh directory to preserve previous receipts:

```sh
python3 tools/build_theme_engine.py --output-dir build/shizukuos-theme-new
```

Run the separate static fault controls against that exact build:

```sh
python3 -O tests/test_theme_engine_build_gate.py --artifact-dir build/shizukuos-theme-new --output-dir build/shizukuos-theme-controls-new
```

These controls reject eight malformed PE directory fields, the original
missing-argument GUI ABI defect and an attempt to overwrite the historical
default build directory. Every build output must be absent or empty; existing
receipts are preserved even when the builder is called without options.

The builder runs the unchanged Classic/Modern regression, genuine ShizukuOS
parser/pixel tests and production profile code with mocked registry APIs, each
normally and with AddressSanitizer/UndefinedBehaviorSanitizer. It builds the
provider, both older probes and the appearance application as freestanding
i486 PE32 4.10 files. Every imported stock API must occur in the pinned Windows
98 SE OEM export inventory. The CPU gate decodes all linked executable-section
bytes with a fail-closed i486/x87 allowlist; the receipt pins source and output
hashes. Registry mocks and static PE/CPU checks are not Windows 98 execution.

Actual Windows 98 painting, mouse/keyboard selection, Apply, process restart,
saved selection reload and OS-wide installation remain mandatory, unverified
steps. The old two-style guest probe and its verifier do not certify the new
style or profile. They need a separate versioned native acceptance path owned
by the shared VM/integration session.

The final product is ShizukuOS 1.0.0, distributed at https://m98.nyase.kr.
ShizukuDOS must replace MS-DOS in the Windows 98 installation and boot chain;
this appearance change is not evidence for that separate kernel requirement.
Private Windows installation media is excluded from public source and ISO.
