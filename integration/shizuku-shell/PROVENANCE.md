# Provenance

Upstream: ReactOS, commit `ce41f2e98e0450ce624c5fc6155fb671af7cc3b5` (files and sha256 in
`upstream/provenance.json`; `upstream/reactos/COPYING.LIB` is the LGPL-2.1 text; the upstream files keep their
`LGPL-2.1-or-later` headers untouched). Derived files here are LGPL-2.1-or-later.

| Local file | Upstream function / lines (pinned commit) | What was taken |
|---|---|---|
| `src/tasks.c` `ShzIsTaskWnd` | traywnd.cpp `CTrayWindow::IsSpecialHWND` 2239-2243, `IsTaskWnd` 2300-2316 | eligibility rule (visible, not tray/desktop, not WS_EX_TOOLWINDOW, WS_EX_APPWINDOW or no owner). DEVIATION: upstream IsSpecialHWND (2241-2242) compares `m_hWnd == m_DesktopWnd` (looks like a ReactOS bug); here the desktop test is `hwnd == desktop` |
| `src/tasks.c` `EnumProc`, `ShzTasksRefresh` | taskswnd.cpp `EnumWindowsProc`/`RefreshWindowList` 1486-1508; array bound 22, 1025-1060 | EnumWindows population; heap-growth replaced by fixed 64 table + overflow report; mark/sweep removal is original |
| `src/tasks.c` `ShzTaskLayout` | taskswnd.cpp `UpdateButtonsSize` horizontal branch 1351-1440 | rows/width clamp (SM_CXSIZE+2*SM_CXEDGE .. SM_CXMINIMIZED)/per-line recompute; toolbar spacing fixed at 2 |
| `src/taskbar.c` | traywnd.cpp `RegLoadSettings` 1659-1686 (min height), start button state 1957/1971 (the 821-824 hotkey block is `#if 0`-style context, approximate), `ResizeWorkArea` at 1583 (call at 1652) | tray height formula, pushed-state coupling, SPI_SETWORKAREA reserve |
| `src/startmenu.c` | traywnd.cpp start menu placement/lifecycle 1957-1971 and NC button handling near 2947-2990 (approximate citations) | lifecycle only; ReactOS COM `CreateStartMenu` (2376, 2567) NOT adapted |
| `src/desktop.c`, `src/main.c`, `src/files.c` | IsSpecialHWND desktop exclusion; explorer start order | structural role only |
| `src/ui.c`, `src/launcher.c`, strings | original ShizukuOS | - |

Shorthorn / Longhorn: **no source used.** Public One-Core-API contents verified as XP/Server 2003 wrappers only;
no 4074-4083 shell source exists in this tree. "4074" appears solely as a tentative visual direction
(gradient/glass-like taskbar) implemented with plain FillRect. Korean strings are original text.

## Font (shell20)
`src/ui.c` `ShzDrawText` draws via `integration/shizuku-font/shz_text.[ch]` (SPDX GPL-2.0-only, root-owned,
read-only; pinned by sha256 in `font-input-pins.json`, compiled from a hash-verified copy under `build/<out>/fontsrc`).
Glyph data `generated/glyphs.h`: OFL-1.1, derived from Noto Sans CJK KR, (c) 2014-2021 Adobe with Reserved Font Name
'Source' (source and license hashes in `generation.json`); `OFL.txt` is staged beside the EXE (`stage/`) along with the
ReactOS `COPYING.LIB`. No Noto font file/TTC is copied. The linked EXE therefore combines LGPL-2.1-or-later shell code,
GPL-2.0-only helper code and OFL data; the combination's distribution terms have not been legally reviewed here.
`SetShellWindow` is a user32 export called from `src/desktop.c`; no ReactOS code is taken for it. All ReactOS notices above remain.

The GPL-2.0-only text for `shz_text.c` is staged as `stage/GPL-2.0.txt`, copied unchanged from the repository `LICENSE` (GNU GPL v2 text; receipt records its sha256).
