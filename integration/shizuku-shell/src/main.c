/*
 * ShizukuOS native shell candidate -- entry point and message loop.
 *
 * Structure follows ReactOS Explorer's startup order (pinned commit ce41f2e98e0450ce624c5fc6155fb671af7cc3b5,
 * base/shell/explorer): create the desktop window, create the Shell_TrayWnd taskbar (which fills its task list
 * with EnumWindows, taskswnd.cpp RefreshWindowList lines 1503-1508), then run the Win32 message loop until the
 * tray is destroyed. Explorer's COM/OLE init, shell hooks (RegisterShellHookWindow), DDE and
 * session/autostart handling are NOT implemented here.
 * Upstream notices: ReactOS Explorer, LGPL-2.1-or-later, Copyright ReactOS contributors.
 * This file: ShizukuOS, LGPL-2.1-or-later; see ../upstream/reactos/COPYING.LIB.
 *
 * Entry: the project CRT's ShzStart (shizukudos/win64/crt/shzcrt.c) parses the command line and calls main().
 * No OS version query is made anywhere; this binary identifies itself only via ShzShellBuildId.
 */
#include "shzcrt.h"
#include "shell.h"
#include "wallpaper.h"
#include "sound.h"
#include "shz_text_diag.h"
#include "editor.h"
#include "search.h"
#include "fileops.h"
#include "catalog.h"
#include "firstboot.h"
#include <string.h>

#define SEARCH_HOTKEY 0x5348
#define EDITOR_HOTKEY 0x5349
static BOOL search_hotkey, editor_hotkey;

/* Explicit startup/shutdown cleanup (also reached before ExitProcess in ShzStart): destroys the shell windows;
 * the tray's WM_DESTROY restores the work area and kills its timers, destroying the desktop clears the
 * SetShellWindow registration in the backend. */
void ShzShellCleanup(void)
{
    if (search_hotkey) { UnregisterHotKey(NULL,SEARCH_HOTKEY); search_hotkey=FALSE; }
    if (editor_hotkey) { UnregisterHotKey(NULL,EDITOR_HOTKEY); editor_hotkey=FALSE; }
    ShzSearchClose();
    ShzEditorCloseAll();
    ShzSoundShutdown();
    ShzSettingsClose();   /* destroy the Settings window before font/image teardown */
    if (g_shell.runwnd)    { DestroyWindow(g_shell.runwnd);    g_shell.runwnd = NULL; }
    if (g_shell.startmenu) { DestroyWindow(g_shell.startmenu); g_shell.startmenu = NULL; }
    if (g_shell.tray)      { DestroyWindow(g_shell.tray);      g_shell.tray = NULL; }
    if (g_shell.desktop)   { DestroyWindow(g_shell.desktop);   g_shell.desktop = NULL; }
    ShzWallpaperRelease();     /* windows are gone before releasing image state */
    ShzThemeSetFontReady(0);
    ShzTextFontShutdown();       /* no window can paint after provider teardown */
}

int main(int argc, char **argv)
{
    MSG msg;
    int rc = 0;
    BOOL got;
    (void)argc; (void)argv;
    g_shell.inst = GetModuleHandleW(NULL);
    if (!g_shell.inst) return 2;

    /* Fonts before any window can paint: the Noto faces are real files; if they cannot be opened the shell does not run
     * (no bitmap/stock fallback and no "font ready" marker). */
    if (!ShzMarkFontReady()) {
        MessageBoxW(NULL, L"글꼴을 불러오지 못했습니다.", ShzStr(IDS_TASKBAR), MB_OK | MB_ICONERROR);
        return 6;
    }

    /* Theme first: the external definition (persisted selection, else Slade) must be published before any window
     * paints. No hardcoded palette exists, so a missing/malformed Slade refuses to start visibly (nothing is faked). */
    if (!ShzThemeShellStartup()) {
        MessageBoxW(NULL, g_shell.status[0] ? g_shell.status : ShzStr(IDS_ERR_THEME), ShzStr(IDS_TASKBAR), MB_OK | MB_ICONERROR);
        ShzShellCleanup();
        return 5;
    }
    /* UI arguments never grant authority: the kernel binds the helper image. */
    if(argc==2&&!strcmp(argv[1],"--firstboot")) {
        rc=ShzFirstBootRun();ShzShellCleanup();return rc;
    }
    if(argc==2&&!strcmp(argv[1],"--firstboot-complete")&&!ShzFirstBootComplete()) {
        ShzShellCleanup();return 7;
    }
    if (!ShzDesktopCreate() || !ShzTaskbarCreate() || !ShzStartMenuRegister() || !ShzFilesRegister() || !ShzRunDialogRegister() ||
        !ShzEditorRegister() || !ShzSearchRegister()) {
        /* Report visibly. MessageBoxW is a real user32 export; if it fails nothing more can be done. */
        MessageBoxW(NULL, g_shell.status[0] ? g_shell.status : ShzStr(IDS_ERR_WINDOW), ShzStr(IDS_TASKBAR), MB_OK | MB_ICONERROR);
        ShzShellCleanup();      /* tray, desktop (registration), work area released before ExitProcess */
        return 3;
    }
    ShzTasksRefresh();
    ShzTaskbarInvalidate();
    ShzSoundStartup();  /* accepted async only; real playback awaits guest PCM evidence */
    search_hotkey=RegisterHotKey(NULL,SEARCH_HOTKEY,MOD_CONTROL|MOD_SHIFT|MOD_NOREPEAT,L'P');
    editor_hotkey=RegisterHotKey(NULL,EDITOR_HOTKEY,MOD_CONTROL|MOD_ALT|MOD_NOREPEAT,L'N');
    printf("SHZ-SHELL hotkeys search=%u editor=%u\n",search_hotkey?1u:0u,editor_hotkey?1u:0u);

    while ((got = GetMessageW(&msg, NULL, 0, 0)) != 0) {
        if (got < 0) { ShzSetStatus(IDS_ERR_WINDOW, GetLastError()); rc = 4; break; }   /* GetMessage error (-1) is not a message */
        if (msg.message==WM_HOTKEY) {
            if (msg.wParam==SEARCH_HOTKEY) { ShzCommandInvoke(SHZ_CMD_SEARCH); continue; }
            if (msg.wParam==EDITOR_HOTKEY) { ShzCommandInvoke(SHZ_CMD_TEXT); continue; }
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (got == 0) rc = (int)msg.wParam;
    ShzShellCleanup();
    return rc;
}
