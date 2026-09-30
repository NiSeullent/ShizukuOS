/* SPDX-License-Identifier: GPL-2.0-only
 * C runtime for the Wine port: process start-up of console executables (the Wine conformance test programs).
 * mainCRTStartup splits the command line with the documented Microsoft rules (2N backslashes + quote -> N backslashes and
 * a quote toggle; 2N+1 -> N backslashes and a literal quote; "" inside quotes -> a literal quote), calls main, runs the
 * atexit handlers and exits with main's return value. The environment passed to main is empty (use getenv).
 */
#include "shzwcrt.h"

void shzw_run_atexit(void);
extern int __cdecl main(int argc, char **argv, char **envp);

static int g_argc;
static char **g_argv;
static wchar_t **g_wargv;
static char *g_env[1];

int *__cdecl __p___argc(void) { return &g_argc; }
char ***__cdecl __p___argv(void) { return &g_argv; }
wchar_t ***__cdecl __p___wargv(void) { return &g_wargv; }
static char **g_envp = g_env;
char ***__cdecl __p__environ(void) { return &g_envp; }

static char **split_command_line(const char *src, int *ret_argc)
{
    size_t len = strlen(src) + 1;
    int argc = 0, in_quotes = 0, bcount = 0, cap = 2 + (int)len / 2;
    char **argv = HeapAlloc(GetProcessHeap(), 0, cap * sizeof(*argv) + len);
    char *dst, *arg;
    if (!argv) return NULL;
    arg = dst = (char *)(argv + cap);
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

int __cdecl mainCRTStartup(void)
{
    int ret;
    g_argv = split_command_line(GetCommandLineA(), &g_argc);
    if (!g_argv) ExitProcess(255);
    ret = main(g_argc, g_argv, g_envp);
    exit(ret);
    return ret;
}
