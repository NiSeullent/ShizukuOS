/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: process start-up of Unicode executables (Wine programs built with -municode, such as
 * programs/iexplore). wmainCRTStartup splits GetCommandLineW() with the same documented Microsoft rules as
 * mainCRTStartup (wcrt_startup.c), calls wmain, runs the atexit handlers and exits with wmain's return value. A GUI
 * program that defines only wWinMain gets wmain from Wine's winecrt0 (exe_wmain.c, libshzwinexe.a), which calls
 * wWinMain with the rest of the command line and the STARTUPINFO show command.
 * This object is linked instead of wcrt_startup.o, never together with it.
 */
#include "shzwcrt.h"

extern int __cdecl wmain(int argc, wchar_t **argv, wchar_t **envp);

static int g_argc;
static wchar_t **g_wargv;
static char **g_argv;
static wchar_t *g_wenv[1];
static char *g_env[1];
static wchar_t **g_wenvp = g_wenv;
static char **g_envp = g_env;

int *__cdecl __p___argc(void) { return &g_argc; }
wchar_t ***__cdecl __p___wargv(void) { return &g_wargv; }
char ***__cdecl __p___argv(void) { return &g_argv; }
wchar_t ***__cdecl __p__wenviron(void) { return &g_wenvp; }
char ***__cdecl __p__environ(void) { return &g_envp; }

static wchar_t **split_command_line(const wchar_t *src, int *ret_argc)
{
    size_t len = wcslen(src) + 1;
    int argc = 0, in_quotes = 0, bcount = 0, cap = 2 + (int)len / 2;
    wchar_t **argv = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*argv) + len * sizeof(wchar_t));
    wchar_t *dst, *arg;
    if (!argv) return NULL;
    arg = dst = (wchar_t *)(argv + cap);
    while (*src == ' ' || *src == '\t') src++;
    while (*src) {
        if ((*src == ' ' || *src == '\t') && !in_quotes) {
            *dst++ = 0;
            argv[argc++] = arg;
            while (*src == ' ' || *src == '\t') src++;
            arg = dst;
            bcount = 0;
            if (!*src) { arg = NULL; break; }
        } else if (*src == '\\') {
            *dst++ = *src++;
            bcount++;
        } else if (*src == '"') {
            if (!(bcount & 1)) {
                dst -= bcount / 2;
                src++;
                if (in_quotes && *src == '"') *dst++ = *src++;
                else in_quotes = !in_quotes;
            } else {
                dst -= bcount / 2 + 1;
                *dst++ = *src++;
            }
            bcount = 0;
        } else {
            *dst++ = *src++;
            bcount = 0;
        }
    }
    if (arg) { *dst = 0; argv[argc++] = arg; }
    argv[argc] = NULL;
    *ret_argc = argc;
    return argv;
}

int __cdecl wmainCRTStartup(void)
{
    int ret;
    g_wargv = split_command_line(GetCommandLineW(), &g_argc);
    if (!g_wargv) ExitProcess(255);
    ret = wmain(g_argc, g_wargv, g_wenvp);
    exit(ret);
    return ret;
}
