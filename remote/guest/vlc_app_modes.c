/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed hash-bound official VLC image paths only. No wildcard, default,
 * Notepad++ setting or pre-existing application entry is overwritten.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "vlc_paths.h"
#define CONFIGS "Software\\KernelEx\\AppSettings\\Configs"
#define FLAGS "Software\\KernelEx\\AppSettings\\Flags"
static HANDLE report = INVALID_HANDLE_VALUE;
static unsigned written[MAX_VLC_PATHS], failures;
static int io_failed;
static unsigned length(const char *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static void text(const char *s) {
    DWORD done, count = length(s);
    if (!WriteFile(report, s, count, &done, NULL) || done != count) io_failed = 1;
}
static void value(const char *name, DWORD n) {
    char data[9]; unsigned i;
    for (i = 0; i < 8; ++i) data[i] = "0123456789ABCDEF"[(n >> (28 - i * 4)) & 15];
    data[8] = 0; text(name); text(data); text("\r\n");
}
static int same(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; } return *a == *b;
}
static const char *argument(void) {
    const char *s = GetCommandLineA(); BOOL quote = FALSE;
    while (*s) {
        if (*s == '"') quote = !quote;
        else if (!quote && (*s == ' ' || *s == '\t')) break;
        ++s;
    }
    while (*s == ' ' || *s == '\t') ++s;
    return s;
}
static LONG inspect(HKEY configs, HKEY flags, unsigned index, int *absent, int *expected) {
    char name[64]; DWORD kind = 0, bytes = sizeof(name), flag = 0, flag_bytes = sizeof(flag), flag_kind = 0;
    LONG config_result = RegQueryValueExA(configs, vlc_paths[index], NULL, &kind, (BYTE *)name, &bytes);
    LONG flag_result = RegQueryValueExA(flags, vlc_paths[index], NULL, &flag_kind, (BYTE *)&flag, &flag_bytes);
    *absent = config_result == ERROR_FILE_NOT_FOUND && flag_result == ERROR_FILE_NOT_FOUND;
    *expected = config_result == ERROR_SUCCESS && flag_result == ERROR_SUCCESS && kind == REG_SZ && bytes == 6 &&
                name[5] == 0 && same(name, "WINXP") && flag_kind == REG_DWORD && flag_bytes == sizeof(flag) && flag == 0;
    if ((config_result != ERROR_SUCCESS && config_result != ERROR_FILE_NOT_FOUND) ||
            (flag_result != ERROR_SUCCESS && flag_result != ERROR_FILE_NOT_FOUND)) return ERROR_INVALID_DATA;
    return ERROR_SUCCESS;
}
static int rollback(HKEY configs, HKEY flags) {
    unsigned i; int absent, expected, ok = 1;
    for (i = 0; i < MAX_VLC_PATHS; ++i) {
        if (written[i] & 1) if (RegDeleteValueA(configs, vlc_paths[i]) != ERROR_SUCCESS) ok = 0;
        if (written[i] & 2) if (RegDeleteValueA(flags, vlc_paths[i]) != ERROR_SUCCESS) ok = 0;
    }
    if (RegFlushKey(configs) != ERROR_SUCCESS || RegFlushKey(flags) != ERROR_SUCCESS) ok = 0;
    for (i = 0; i < MAX_VLC_PATHS; ++i) {
        if (written[i] && (inspect(configs, flags, i, &absent, &expected) != ERROR_SUCCESS || !absent)) ok = 0;
    }
    value("OWN_NEW_ENTRIES_ROLLBACK_ABSENT=", ok);
    return ok;
}
void WINAPI entry(void) {
    HKEY configs = NULL, flags = NULL;
    unsigned i; int absent, expected; LONG error; DWORD mode_flags = 0, code = 3;
    const char *mode = argument(); BOOL apply = same(mode, "apply"), verify = same(mode, "verify");
    DWORD access = KEY_QUERY_VALUE | (apply ? KEY_SET_VALUE : 0);
    if (!apply && !verify && !same(mode, "inspect")) ExitProcess(2);
    report = CreateFileA(apply ? "C:\\VLCLAB\\MODEA.LOG" : verify ? "C:\\VLCLAB\\MODEV.LOG" : "C:\\VLCLAB\\MODEI.LOG",
                         GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(20);
    text("SCOPE=EXACT_OFFICIAL_VLC_IMAGES_ONLY\r\n"); value("FIXED_IMAGE_PATHS=", MAX_VLC_PATHS);
    error = RegOpenKeyExA(HKEY_LOCAL_MACHINE, CONFIGS, 0, access, &configs);
    if (error != ERROR_SUCCESS) { value("OPEN_CONFIG_ERROR=", (DWORD)error); goto done; }
    error = RegOpenKeyExA(HKEY_LOCAL_MACHINE, FLAGS, 0, access, &flags);
    if (error != ERROR_SUCCESS) { value("OPEN_FLAGS_ERROR=", (DWORD)error); goto done; }
    for (i = 0; i < MAX_VLC_PATHS; ++i) {
        error = inspect(configs, flags, i, &absent, &expected);
        text("IMAGE="); text(vlc_paths[i]); text("\r\n");
        value("OLD_EXACT_VALUES_ABSENT=", absent); value("EXACT_WINXP_FLAGS_ZERO=", expected);
        if (error != ERROR_SUCCESS || (apply && !absent) || (verify && !expected)) {
            text("GUARD_REJECTED=EXISTING_OR_INVALID_EXACT_VALUES\r\n"); code = 4; goto done;
        }
    }
    if (!apply) { code = 0; goto done; }
    for (i = 0; i < MAX_VLC_PATHS; ++i) {
        error = inspect(configs, flags, i, &absent, &expected);
        if (error != ERROR_SUCCESS || !absent) { code = 4; goto failed_apply; }
        error = RegSetValueExA(configs, vlc_paths[i], 0, REG_SZ, (const BYTE *)"WINXP", 6);
        if (error != ERROR_SUCCESS) goto failed_apply;
        written[i] = 1;
        error = RegSetValueExA(flags, vlc_paths[i], 0, REG_DWORD, (const BYTE *)&mode_flags, sizeof(mode_flags));
        if (error != ERROR_SUCCESS) goto failed_apply;
        written[i] |= 2;
    }
    error = RegFlushKey(configs); if (error != ERROR_SUCCESS) goto failed_apply;
    error = RegFlushKey(flags); if (error != ERROR_SUCCESS) goto failed_apply;
    for (i = 0; i < MAX_VLC_PATHS; ++i) {
        error = inspect(configs, flags, i, &absent, &expected);
        if (error != ERROR_SUCCESS || !expected) goto failed_apply;
    }
    text("EXACT_READBACK_VERIFIED=1\r\n"); code = 0; goto done;
failed_apply:
    value("APPLY_ERROR=", error); ++failures;
    if (!rollback(configs, flags)) ++failures;
    code = 5;
done:
    value("SELECTED_EXIT=", code); value("FAILURES=", failures);
    text(code || failures || io_failed ? "STATUS=FAIL\r\n" : "STATUS=SCOPED_MODE_OPERATION_PASS\r\n");
    if (configs && RegCloseKey(configs) != ERROR_SUCCESS) io_failed = 1;
    if (flags && RegCloseKey(flags) != ERROR_SUCCESS) io_failed = 1;
    if (!FlushFileBuffers(report)) io_failed = 1;
    if (!CloseHandle(report)) io_failed = 1;
    ExitProcess(io_failed || failures ? 31 : code);
}
