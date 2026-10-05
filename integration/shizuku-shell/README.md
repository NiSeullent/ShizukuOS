# ShizukuOS native shell candidate (source-only, default-off)

Win32 shell (desktop, `Shell_TrayWnd` taskbar, start menu, Files, Run) adapted in structure from ReactOS
explorer `traywnd.cpp`/`taskswnd.cpp` (pinned commit in `upstream/provenance.json`), Korean UI text, PE32+ x64.
Build (isolated, <=8 MiB, each command <=60 s): `python3 build.py --out <fresh-empty-dir> [--runtime-dir DIR]`.
Layout: `src/` (main.c, ui.c, tasks.c, taskbar.c, startmenu.c, desktop.c, files.c, launcher.c, shell.h,
strings_ko.h), `res/shell_ko.rc.in` + `tools/gen_rc.py` (ko-KR STRINGTABLE), `PROVENANCE.md`, `STATUS.md`.

Roadmap to Windows 10 shell parity (all UNIMPLEMENTED unless in STATUS.md "What exists"): COM shell namespace
-> shell hooks (HSHELL_WINDOWCREATED etc.) -> tray notification area/balloons -> task icons/grouping/flash ->
DWM/theme composition (DwmExtendFrame*, uxtheme) -> Korean font fallback + IME/TSF input -> real shutdown path
through ShizukuCore -> launcher via ShellExecuteEx associations. Each step needs actual guest execution before any
compatibility claim. The default boot is unchanged; nothing here is staged.

Shell20: Korean text is own-painted with the bitmap font helper (see STATUS.md; no IME, captions of native windows
unverified), the desktop window registers with `SetShellWindow`. Build writes `<out>/stage/` (exe + licenses) and
`<out>/receipt.json`. Not a Windows 10 compatibility claim; guest unverified.

Latest build: `build/font-out2` (shell20 review fixes); `font-out1` is the earlier receipt.
