/*
 * ShizukuOS native shell candidate -- shared declarations.
 * Target: Windows 10 Win32 API / x64 ABI (PE32+). Only documented Win32 calls are used; this header never
 * queries or reports an OS version. Status: source-only candidate, no guest execution evidence.
 *
 * Structure adapted from ReactOS explorer (LGPL-2.1-or-later), pinned commit
 * ce41f2e98e0450ce624c5fc6155fb671af7cc3b5, see ../PROVENANCE.md. Adaptation sites carry their own notices.
 * This file: original ShizukuOS work, distributed under LGPL-2.1-or-later (see ../upstream/reactos/COPYING.LIB).
 */
#ifndef SHZ_SHELL_H
#define SHZ_SHELL_H

#ifndef UNICODE
#define UNICODE 1
#endif
#ifndef _UNICODE
#define _UNICODE 1
#endif
#include <windows.h>
#define SHZ_THEME_NATIVE 1   /* theme.c native load/persist part (exported kernel32 file calls) */
#include "theme.h"
#include "strings_ko.h"
#include "shz_text.h"      /* root-owned font helper, hash-pinned copy staged by build.py */

/* Real user32 export (shared backend); the MinGW public headers do not declare it. */
__declspec(dllimport) BOOL WINAPI SetShellWindow(HWND hwnd);

#define SHZ_MAX_TASKS   64      /* task table bound (ReactOS TASK_ITEM_ARRAY_ALLOC is also 64) */
#define SHZ_MAX_FILES   128     /* directory entries held per Files window */
#define SHZ_MAX_PATH    260     /* no long-path support: longer paths are rejected, never truncated */
#define SHZ_MAX_FILES_WINDOWS 8
#define SHZ_STATUS_CHARS 128

#define SHZ_TIMER_CLOCK 1
#define SHZ_TIMER_TASKS 2

#define SHZ_CLASS_TRAY    L"Shell_TrayWnd"       /* same class name ReactOS/Windows use for the taskbar */
#define SHZ_CLASS_DESKTOP L"ShizukuDesktop"
#define SHZ_CLASS_START   L"ShizukuStartMenu"
#define SHZ_CLASS_FILES   L"ShizukuFiles"
#define SHZ_CLASS_RUN     L"ShizukuRunDialog"

typedef struct SHZ_TASK {
    HWND  hwnd;
    WCHAR title[96];
    BOOL  seen;                 /* mark/sweep flag used by ShzTasksRefresh */
} SHZ_TASK;

typedef struct SHZ_SHELL {
    HINSTANCE inst;
    HWND desktop, tray, startmenu, runwnd;
    SHZ_TASK tasks[SHZ_MAX_TASKS];
    int  ntasks;
    BOOL tasks_overflow;        /* more eligible windows exist than the table holds */
    BOOL start_open;            /* start button pushed state (BM_SETSTATE analogue) */
    DWORD start_closed_tick;
    int  files_windows;
    WCHAR status[SHZ_STATUS_CHARS];
    DWORD status_tick;
    unsigned draw_text_failures;     /* ShzDrawText: font/clip/colour call failed, text (partly) not rendered */
    unsigned font_unsupported;       /* scalars in neither Noto face (.notdef box drawn), counted per paint */
    unsigned font_truncated;         /* strings longer than 32767 UTF-16 units: tail not drawn */
    BOOL shell_registered;           /* SetShellWindow(desktop) returned TRUE */
    BOOL focus_on_desktop;           /* GetFocus()==desktop right after SetFocus (unverified in a guest) */
    BOOL desktop_painted, tray_painted, timers_ok, ready_emitted;
    unsigned string_fallbacks;       /* LoadStringW failed, compiled table used */
    BOOL quit_requested;
    /* theme (theme.c): counters for the visible diagnostics/serial marker; the data lives in theme.c state */
    BOOL     theme_ready;            /* a theme has been published (startup loads it before any window exists) */
    unsigned theme_reloads;          /* successful runtime reload/select propagations */
    unsigned theme_refusals;         /* refused candidates at runtime (previous theme and generation kept) */
    unsigned theme_persist_failures; /* selection record could not be published */
} SHZ_SHELL;

extern SHZ_SHELL g_shell;
extern const char ShzShellBuildId[];

/* ui.c */
const WCHAR *ShzStr(int id);
SIZE_T ShzWcsLen(const WCHAR *s);
BOOL   ShzWcsCopy(WCHAR *dst, SIZE_T cap, const WCHAR *src);   /* FALSE (dst emptied) if it would not fit */
BOOL   ShzWcsCat(WCHAR *dst, SIZE_T cap, const WCHAR *src);    /* FALSE (dst unchanged) if it would not fit */
void   ShzSetStatus(int id, DWORD err);                        /* visible message; err==0 omits code */
void   ShzFillGradientV(HDC dc, const RECT *rc, COLORREF top, COLORREF bottom);
void   ShzFrame(HDC dc, const RECT *rc, COLORREF c, int width);      /* nested 1px frames, width 0..4 (clamped) */
void   ShzSetStatusText(int id, const char *ascii);                   /* visible status: string id + ASCII suffix */
/* Theme glue (ui.c). TC() converts a stored 0x00RRGGBB theme colour to a GDI COLORREF explicitly. */
#define TC(rgb) ((COLORREF)ShzThemeCR(rgb))
#define TH()    (ShzThemeCurrent())     /* never NULL once ShzThemeShellStartup() succeeded (main.c refuses to start otherwise) */
BOOL   ShzThemeShellStartup(void);                  /* load persisted selection (else Slade) before windows exist */
void   ShzThemeShellSelect(int id);                 /* Settings only; refused theme keeps previous config+generation */
void   ShzThemeShellReload(void);                   /* Settings only; re-read the current external file */
/* Own paint through the Noto/FreeType text provider (font23-native/shz_text_noto.c, proportional pixel layout), see ui.c.
 * Honoured fmt bits: DT_SINGLELINE, DT_WORDBREAK (multi-line), DT_CENTER, DT_RIGHT, DT_VCENTER, DT_END_ELLIPSIS;
 * DT_NOPREFIX is always in effect ('&' is drawn literally); all other DT_* bits are ignored. Output is clipped to rc. */
void   ShzDrawText(HDC dc, const WCHAR *s, RECT *rc, UINT fmt);
void   ShzMarkPainted(BOOL tray);                              /* serial readiness markers, see ui.c */
void   ShzMarkRegistered(void);
BOOL   ShzMarkFontReady(void);        /* real font init; FALSE = fonts unavailable (shell must not run) */
void   ShzShellCleanup(void);                                  /* main.c: destroy shell windows, restore work area */
HFONT  ShzFont(void);
void   ShzFormatTime(const SYSTEMTIME *st, WCHAR out[8]);
void   ShzFormatU64(unsigned long long v, WCHAR *out, SIZE_T cap);

/* tasks.c (ReactOS taskswnd.cpp / traywnd.cpp eligibility, refresh and layout) */
BOOL ShzIsTaskWnd(HWND hwnd);
void ShzTasksRefresh(void);
void ShzTaskActivate(HWND hwnd);
typedef struct SHZ_TASKLAYOUT { int btn_w, per_line, rows, hidden; } SHZ_TASKLAYOUT;
void ShzTaskLayout(int client_w, int client_h, int count, SHZ_TASKLAYOUT *out);

/* tasks.c: one native Settings window; consumed by main cleanup and ui theme propagation. */
HWND ShzSettingsOpen(void);
void ShzSettingsClose(void);
void ShzSettingsRelayout(void);

/* taskbar.c */
BOOL ShzTaskbarCreate(void);
void ShzTaskbarInvalidate(void);
void ShzTaskbarGetStartRect(RECT *rc);
void ShzTaskbarRelayout(void);          /* theme metrics changed: resize tray, work area, repaint */

/* startmenu.c */
BOOL ShzStartMenuRegister(void);
void ShzStartMenuToggle(void);
void ShzStartMenuClose(void);
void ShzStartMenuRelayout(void);

/* desktop.c */
BOOL ShzDesktopCreate(void);
void ShzDesktopRelayout(void);

/* files.c */
BOOL ShzFilesRegister(void);
void ShzFilesRefreshAll(void);
void ShzFilesRelayoutAll(void);        /* every Files window: re-clamp scroll, repaint */
HWND ShzFilesOpen(const WCHAR *path);   /* NULL path: drive list ("computer") view */

/* launcher.c */
BOOL ShzLaunch(const WCHAR *cmdline, const WCHAR *cwd);    /* CreateProcessW; closes both handles; visible errors */
BOOL ShzRunDialogRegister(void);
void ShzRunDialogOpen(void);
void ShzRunDialogRelayout(void);

/* keyboard shared by shell windows: returns TRUE when consumed */
BOOL ShzGlobalKey(UINT vk);

#endif
