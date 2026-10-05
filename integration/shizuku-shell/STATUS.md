# Status: SOURCE-ONLY candidate (not run in a guest, no OS qualification, not Windows 10 compatibility)

Target: Windows 10 Win32 API, PE32+ x64, MS x64 ABI. No version query or version string claims anywhere;
identity string: "ShizukuOS development candidate shell (not Windows 10; source-only)".
Default boot is unchanged. This lane is default-off: `python3 build.py --out <fresh dir>`.

## What exists (source + host link receipt only)
desktop window with 3 icons (computer/files/run), `Shell_TrayWnd` taskbar (start button, task buttons via
EnumWindows/GetWindowTextW, status line, clock), start menu (keyboard+mouse, live window list),
Files top-level window (FindFirstFileW/FindNextFileW, attribute bits, size, E:/C:/D: buttons, computer drive list),
Run dialog stub, CreateProcessW launcher closing hProcess+hThread once. Keys: Win/Ctrl-less toggle, Esc, Enter,
Bksp (parent), F5 (reload), F2 (inline rename via MoveFileW). Bounds: 64 tasks, 128 entries, 260-char paths;
long paths are rejected and counted, overflow is shown ("+N" / status), failed APIs set a visible taskbar status
with the Win32 error code.

## Build / import receipt
`build.py` writes `receipt.json`: source sha256 before/after, step results, exe sha256, exact PE import table
and its comparison with real export tables of the runtime's kernel32/user32/gdi32/ntdll DLLs. Missing
export or unreadable runtime => `stageable:false`. Runtime read uses `sudo -n cat` fallback; never written.
`stageable:true` = links, x64, all imports resolve by name. It is NOT an execution result.

## Shell20 additions (source + host link receipt `build/font-out1/receipt.json`; nothing executed in a guest)
- Korean own-paint: `ShzDrawText` (ui.c) draws through the root font helper (`ShzTextMeasureW/DrawW`, fixed 16x22
  cell, ShizukuKRBitmap glyphs derived from Noto Sans CJK KR, OFL-1.1). DrawTextW is no longer used for shell text.
  Honoured: DT_SINGLELINE, DT_WORDBREAK (multi-line, break at space else mid-word), DT_CENTER, DT_RIGHT, DT_VCENTER,
  DT_END_ELLIPSIS ("..." only if >=4 cells). Ignored: all other DT_* (prefix `&` is always literal). Output is
  clipped to the RECT with SaveDC/IntersectClipRect (partial glyphs cut, nothing drawn if clipping fails). Foreground =
  GetTextColor(dc). Unsupported scalars (not ASCII/Jamo/Hangul, surrogate pairs = one scalar) show as `?` and are counted
  (`font_unsupported`, per paint); helper/clip failures count in `draw_text_failures` (debug counters, not displayed).
  Run dialog OK/Cancel are Korean custom paint (no Win32 button controls). Native window captions (title bars) and
  MessageBoxW text still use the backend GDI/ASCII font: Hangul there is unverified. No IME/composition, no shaping,
  no wide-font GDI path. Rows are 20 px, glyph cell 22 px: VCENTER text in 20 px rows is clipped by up to 1 px top/bottom.
- Shell registration: `SetShellWindow(desktop)` (real user32 export, declared locally; the MinGW header lacks it)
  right after CreateWindowExW; refusal is returned as startup failure with a visible status (GetLastError). Backend
  clears it on window destroy. WM_WINDOWPOSCHANGING keeps HWND_BOTTOM. SetFocus(desktop) is requested without raising;
  whether keyboard focus lands there is unverified (recorded as `focus_on_desktop`).
- Serial markers (project CRT printf): `SHZ-SHELL FONT ready` (compiled renderer exists), `REGISTERED` (SetShellWindow
  returned TRUE), `READY` (registered + timers + first desktop and tray paint calls returned + no draw failures).
  They describe process self-observation only; all say guest=unverified. No marker means a screen showed anything.
- Fixes: Files footer click no longer selects rows (hit test limited to the list client area); startup failure now runs
  `ShzShellCleanup()` (windows destroyed, work area restored, registration cleared) before exit; timer failure returns
  FALSE with a status instead of continuing; build self-hash covers build.py, font inputs, pins, CRT headers.
- Build: font helper compiled from a hash-verified staged copy of the root inputs (`font-input-pins.json`, values
  recorded by shell20 from the root files; mismatch fails closed). `stage/` holds the exe + OFL.txt + generation.json +
  COPYING.LIB (no Noto font file). Runtime DLL hashes are captured before/after and a change fails the receipt.
  No reproducible-binary claim.
- windows10_compatibility=false, runtime_qualification=false, guest=unverified.

## Shell20 review fixes (build/font-out2; font-out1 kept as the first receipt)
- Layout sized for the 16 px cell: clock box 88 px ("HH:MM" = 5 cells); "+N" overflow in its own 56 px box right of the
  task buttons (task area shrinks accordingly); Files attribute column 5 cells (all of DRHSA); size column 8 cells with
  compact K/M/G/T/P/E formatting above 9,999,999 (never silently cut); status box 384 px (24 cells).
- Status text: error code is printed FIRST ("0x00000005 message") so truncation cannot hide it; the idle identity text is
  now just "Windows 10 아님" (15 cells, fits untruncated). Long messages are still ellipsized (not wrapped).
- `g_shell.tray` is cleared on tray WM_DESTROY.
- GPL-2.0 text (the repository `LICENSE`, hash in receipt `gpl2_text_source`) is staged as `stage/GPL-2.0.txt` beside the exe.
- Still unexecuted: no host/guest layout test; fit is by arithmetic on the fixed cell width only.

## Gaps (explicit)
- Desktop window no longer takes focus on click (MA_NOACTIVATE), so desktop icon keyboard navigation is unavailable until focus is routed otherwise.
- Never executed on a guest. No window, paint, click or keyboard behavior is verified.
- Korean: strings are UTF-16 in a ko-KR (0x0412) STRINGTABLE resource (compiled by windres, -c 65001; present in
  the exe). Not verified: LoadStringW result at runtime, font glyph coverage for DEFAULT_GUI_FONT, Hangul
  rendering through DrawTextW (superseded for shell-painted text by the bitmap own-paint above),
  keyboard layout / IME (WM_CHAR is used; Hangul composition needs imm32/TSF not wired: captions/typing IME unverified).
- Not implemented: COM shell namespace (IShellFolder/IShellView/IShellBrowser), shell hooks
  (RegisterShellHookWindow/HSHELL_*), DWM/theme/Aero composition (gradients are plain FillRect; GradientFill is
  not exported by the runtime gdi32 anyway), notification area/balloons, tray icons, task grouping/icons/flash,
  taskbar settings/auto-hide/multi-monitor, drag/drop, context menus, file associations/ShellExecute, real
  system shutdown (the "shell exit" entry only ends this process), a separate Win32 desktop object
  (CreateDesktopW not used; "desktop" is a window), 4074-style visuals beyond flat gradients.
- Task eligibility uses the ReactOS rule only; no rude-app/fullscreen detection, no UWP/cloaked-window test
  (Windows 10 needs DWMWA_CLOAKED filtering; DWM not available).
- Probed but absent in runtime user32/gdi32/kernel32 (so deliberately not used): user32 `SetLastError`
  (really kernel32 on Windows; not a gap), `SwitchToThisWindow`, `IsHungAppWindow`; gdi32 `RoundRect`, `GradientFill`.
- Process handling: children are not tracked or waited; no job object; no CREATE_NEW_CONSOLE handling.
- Checks not run: no behavior tests, no path-policy unit control, no guest/VM, no multiple-config matrix.
