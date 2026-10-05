# ShizukuOS native shell: Slade / Flute / Jade / Custom theme integration

Status: **source and native-import proof only**. The new shell EXE links against the real runtime DLL export tables
(see the build receipt); it has **not run in a guest**. The existing guest/ISO still run the old
UNTHEMED f0e176 shell and font-out2 binaries and must never be described as themed. The theme GUI is guest-UNVERIFIED.
No Windows 10 compatibility, audio, blur, transparency or animation claim is made.

There is exactly one shell. Themes extend `integration/shizuku-shell`; there is no second shell, provider or desktop
authority, and the Korean 16x22 bitmap renderer (`shz_text.c`) and its contract are unchanged.

## Files

| file | role |
|---|---|
| `src/theme.h`, `src/theme.c` | strict bounded INI schema/parser, atomic state, capability masks, native load/persist (GPL-2.0-only; provenance below) |
| `themes/{Slade,Flute,Jade}/theme.ini` | the three full external definitions (no palette is hardcoded in C; Slade is the default and is data) |
| `tests/test_theme.c` | cheap host control (portable parser/state/capabilities only) |
| `tools/build_theme_extension.py` | stages theme files beside the EXE, emits the staged file map, runs the host control |
| `build.py` (extended) | new `theme.c` object, pinned theme inputs, real-DLL import checks for the new calls, theme staging |
| `src/{shell.h,ui.c,main.c,taskbar.c,tasks.c,desktop.c,startmenu.c,files.c,launcher.c,strings_ko.h}` | actual consuming call sites (below) |

Adaptation provenance: colour convention `0x00RRGGBB` and strict declared-parts approach from
`ntwddm/include/nttheme.h` (NTTH, GPL-2.0-only); bounded exact reader and temp/flush/read-back/`MoveFileExW` publish idea
from `shizukudos/win64/apps/shzdesk/theme.h` (GPL-2.0-only). Ideas only; neither file is copied and NTTH's painter is not
linked. `theme.c` is GPL-2.0-only; the repository `LICENSE` text is already staged as `GPL-2.0.txt` beside the EXE.

## Colour formats (explicit)

Theme data and the parser use `0x00RRGGBB` (NTTH order, written `#RRGGBB`). GDI uses `COLORREF` `0x00BBGGRR`.
`ShzThemeColorRefFromRgb` / `ShzThemeRgbFromColorRef` swap explicitly (tested: `0x00112233 <-> 0x00332211`);
shell code calls `TC(x)` (= `ShzThemeCR`) at every GDI use. Nothing passes raw theme values to `RGB()`/GDI.

## Schema (all keys required exactly once; unknown/duplicate/missing/out-of-range rejected)

Bounds: file <= 16384 bytes, <= 512 lines, <= 200 bytes/line, key <= 32, <= 32 sections, references <= 64 chars
(1..4 segments `[A-Za-z0-9_.-]{1,32}`, no leading `.`, no `..`, no `\ : /`-prefix, must end `.bmp/.png/.jpg/.jpeg`,
`.wav` or `.cur/.ani` by key; `none` allowed). Input must be printable ASCII (+ TAB, CRLF/LF); control, non-ASCII, BOM and
lone CR are rejected. No allocation exists in `theme.c`; every loop is bounded by input length, table size or a constant.

Cross-field invariants (reject atomically): taskbar.height >= buttons.height+4 (and the Korean 22 px cell floor: buttons,
menu rows, files rows/footer >= 22, files bar >= 28, titlebar >= 22); taskbar fixed widths + start button <= 760;
icon cell holds icon + gap + a 22 px label; typography.line_height >= size; start.width >= 10 cells + indent;
`transparency`/`blur`/`animation`: `enabled=0` forbids non-neutral settings, `enabled=1` requires real ones;
`wallpaper.mode=image` iff `image != none`; `sound.enabled=1` needs at least one event reference; text/background
luma contrast >= 96 for 17 text/surface pairs; builtin slots need their own `meta.name` and `kind=builtin`, the Custom slot
needs `kind=custom` and a non-reserved name (case-insensitive vs Slade/Flute/Jade).

### Field classification (requested vs this shell build)

Supported = actually consumed by painting/layout/hit-test in this source; Retained = parsed, validated, kept, reported as
unsupported, never applied.

| category | keys | class | consumer / reason |
|---|---|---|---|
| window metrics | border_width, padding | supported | `ShzFrame` button/menu frames; desktop icon margin |
| window | corner_radius, shadow | retained | no region/shadow engine (`SHZ_CAP_CORNER_RADIUS`, `SHZ_CAP_WINDOW_SHADOW`) |
| title bar | height, colours, align, buttons, `nonclient` | retained | shell windows keep the system non-client caption (Run dialog); `nonclient=1` is reported `nctitle` |
| borders | active/inactive/light/dark/focus | partial | `inactive` (disabled drive buttons) and button edge/menu frame used; others retained data |
| backgrounds | desktop_top/bottom/text, panel_face/text, surface*, input_* | supported | desktop, Files list, Run dialog |
| transparency | enabled, *_alpha | retained | opaque GDI only (`alpha`) |
| blur | enabled, radius, target | retained | not implemented (`blur`) |
| typography | face | policy-enforced | `face` must be exactly `Noto Sans KR` (case-exact ASCII, any other family rejected atomically, also in Custom); requested Noto rendering is always reported `notorender` (unsupported) |
| typography | size, weight, antialias, line_height | partial | actual renderer is the root-protected 1-bit 16x22 Noto-derived bitmap fallback; exact geometry 22/normal/none/22 makes it the effective backend (`bitmapfont`), anything else reports `font` |
| icons | size, cell_w/h, label_gap, glyph_* | supported | desktop placeholder glyph geometry, colours, hit-test |
| icons | set, style | retained | no icon images; non-default reports `iconimg` |
| buttons | height, gap, start_width, min_width, colours, text | supported | taskbar/start button, task layout (`ShzTaskLayout`), Files bar, Run dialog |
| taskbar | height, widths, colours | supported | `ShzTaskbarCreate/Relayout`, paint, `OnClick` |
| taskbar | position != bottom, autohide | retained | bottom only (`tbedge`) |
| start interface | width, max_task_rows, bg, frame | supported | `startmenu.c` size/paint/hit-test |
| start | user_panel | retained | `userpanel` |
| menus | row_height, sep_height, indent, text/header/separator colours | supported | start menu (disabled_text retained: no disabled rows) |
| selection states | top/bottom/text/border, inactive_* | supported | menu rows, Files rows (active vs `GetForegroundWindow`), desktop icon frame |
| animation | enabled, duration, easing, menu, window | retained | none implemented (`anim`) |
| sound scheme | enabled, volume, scheme, 10 event refs | retained | refs are **names only**; no audio output driver, no PlaySound, nothing copied (`audio`). Root's NAS inventory of 10 WAVs is a reference namespace, not staged |
| wallpaper | mode none/solid/gradient | supported | `desktop.c` (gradient default; solid fills `wallpaper.color`) |
| wallpaper | mode image, style | retained | no image decoder (`wallimg`); desktop falls back to gradient |
| cursor | scheme=system,size=32,custom=none,shadow=0 | supported (system cursors) | anything else reports `cursor` |

## Font policy: requested vs actual

User requirement: Noto Sans family, Noto Sans KR for Hangul. `typography.face` is parser-enforced to exactly
`Noto Sans KR` (builtin themes updated; ShizukuKRBitmap and every other family, case variants, `Noto Sans`, `Noto Sans CJK KR`
and padded/overlong values are rejected with the previous config and generation preserved). No canonical equivalent is
accepted; if root wants one (e.g. `Noto Sans CJK KR`) that is a ROOT choice. The requested face is stored in theme state
(`typography_face`), exposed by `ShzThemeRequestedFace`, gates `ShzFont()` via `ShzThemeFontAllowed`, and is printed in the
serial line (`font_requested="Noto Sans KR" font_actual="ShizukuKRBitmap-1bit-16x22 (Noto-derived fallback)"
font_gaps=no-antialias,fixed-cell-not-proportional,no-nonclient-font`); the taskbar status lists `notorender` as unsupported.
The ACTUAL renderer is the root-protected `shz_text.c` bitmap (rough fallback): no anti-aliasing, fixed cell (not
proportional), no non-client font. Real Noto Sans KR rendering is NOT implemented; the root font backend is untouched.

## Runtime capability report

`ShzThemeSupportedMask()` = palette, metrics, gradient, bitmap font (fallback renderer), solid wallpaper, system cursor.
`ShzThemeRequestedMask(t)` is derived from the definition; `ShzThemeEffectiveMask = requested & supported`;
`ShzThemeUnsupportedMask = requested & ~supported`; `ShzThemeMaskNames` renders names. Every theme requests `notorender`; Flute also alpha/blur/anim;
Jade also audio/nctitle: both load, and the taskbar shows `일부 효과 미지원 Flute:alpha,blur,anim` (string id 140 +
ASCII names, 8 s) and the serial marker `SHZ-SHELL THEME ... requested=0x.. effective=0x.. unsupported=0x.. [names]
guest=unverified`. Nothing is silently reported applied.

## Public consuming API (theme.h) and shell symbols

`ShzThemeParse`, `ShzThemeCheckIdentity`, `ShzThemeStateInit/Apply`, `ShzThemeGlobal`, `ShzThemeCurrent`
(palette/metrics query), `ShzThemeGeneration`, `ShzThemeCurrentId`, `ShzThemeRequestedMask/SupportedMask/EffectiveMask/
UnsupportedMask/MaskNames`, `ShzThemeColorRefFromRgb/RgbFromColorRef/ParseColor`, native `ShzThemeLoadSlot`,
`ShzThemePersistedSelection`, `ShzThemePersistSelection`.
Shell glue (`ui.c`): `ShzThemeShellStartup/Select/Reload`, `ShzFrame`, `ShzSetStatusText`; macros `TH()`, `TC()`.

Call sites: `main.c` (startup before any window; refuses to start visibly if no external Slade loads — no hardcoded fallback
palette exists), `taskbar.c` (metrics macros START_W/CLOCK_W/..., paint, `OnClick`, `ShzTaskbarRelayout`), `tasks.c`
(`ShzTaskLayout` button height/gap/min width), `startmenu.c` (MENU_W/ROW_H/SEP_H, paint, hit-test, three theme rows,
`ShzStartMenuRelayout`), `desktop.c` (icon geometry/hit-test, wallpaper, colours, `ShzDesktopRelayout`), `files.c`
(ROW_H/BAR_H/FOOT_H shared by paint/scroll/click, `ShzFilesRelayoutAll`), `launcher.c` (Run dialog colours and button
metrics, `ShzRunDialogRelayout`), `ui.c` (automatic startup and same-window propagation). User theme selection and reload are owned solely by `tasks.c` Settings → Personalization. F7/F8/F9 have no global theme action.
Visible Files behaviour change: row height is now the 22 px Korean cell (was 20, which clipped glyphs); taskbar height is
the theme's 34 (was derived 34 from system metrics).

## Load, atomicity, persistence, reload

* Builtin slot `<Name>`: `C:\SHZ\SYSTEM\THEMES\<Name>\theme.ini`; only if that file is absent, `<exe dir>\THEMES\<Name>\theme.ini`
  (the staged copy beside the EXE). Custom: `E:\SHZ\THEME\CUSTOM.INI` (user data, never shipped).
* Parse into a stack draft; identity + invariants checked; only then the global state is replaced and `generation++`.
  Any failure (I/O, size, parse, identity) leaves the published theme, id and generation untouched, bumps `rejects`, records
  `last_reject`, shows `테마 거부 이전 유지 <section.key>` and prints `SHZ-SHELL THEME-REFUSED`.
* File reads are bounded (<=16 KiB, `GetFileSizeEx`, bounded read loop, `CloseHandle` failure counted).
* Selection `E:\SHZ\THEME\SELECT.CFG` (`SHZTHSEL1\n<Name>\n`): created after a successful select; `CreateDirectoryW`
  E:\SHZ and E:\SHZ\THEME, write `SELNEW.TMP`, `FlushFileBuffers`, read back and compare, `MoveFileExW(REPLACE_EXISTING)`;
  failure deletes the temp and shows a persistence error while the already-applied theme stays active. An unreadable
  record means Slade; a malformed Custom at startup is refused and Slade is loaded.
* Reload propagation (same process, no executable replacement): `ThemePropagate` calls tray relayout (resize, work area),
  start menu close/rebuild, desktop repaint, Run dialog repaint and `WM_SIZE`+repaint on every `ShizukuFiles` window.

## Staged theme-file map (also recorded in the build receipt `theme_stage_map`)

| source | beside the new EXE | intended media target (root stager to be extended later) |
|---|---|---|
| `integration/shizuku-shell/themes/Slade/theme.ini` | `THEMES/Slade/theme.ini` | `C:\SHZ\SYSTEM\THEMES\Slade\theme.ini` |
| `integration/shizuku-shell/themes/Flute/theme.ini` | `THEMES/Flute/theme.ini` | `C:\SHZ\SYSTEM\THEMES\Flute\theme.ini` |
| `integration/shizuku-shell/themes/Jade/theme.ini` | `THEMES/Jade/theme.ini` | `C:\SHZ\SYSTEM\THEMES\Jade\theme.ini` |

The media stager (`integration/shizuku-shell-media/stage_runtime.py`) and ISO are untouched; wiring these into media remains
pending root work.

## Remaining / unsupported / unverified

Guest execution of any theme path; media staging of the three files; transparency, blur, animation, image wallpaper, custom
fonts, custom cursors, audio output and sound playback, non-client title bar theming, icon images, rounded corners, shadows,
taskbar edges/auto-hide, start user panel; hover states; a Custom-theme editor UI (Custom is a hand-placed file).

## Settings-only personalization

The native Settings window is the sole user entry point for theme selection and
reload. Selection applies immediately using the existing bounded external-theme
loader; successful persistence uses E:\SHZ\THEME\SELECT.CFG and is restored
at the next shell startup. Settings reports save failures without claiming
restart persistence. Custom is disabled when its definition is absent and is
skipped by keyboard navigation. Theme diagnostics remain in serial logs rather
than permanent taskbar status.

Actual guest verification for this revision is recorded in the owned settings
verification lane; build/import checks alone do not establish guest behavior.
