/* SPDX-License-Identifier: GPL-2.0-only
 * Hidden =X: drive entries are documented in Microsoft CreateProcessA remarks.
 * Steam's own static _wchdir calls SetCurrentDirectoryW, GetCurrentDirectoryW,
 * then SetEnvironmentVariableW(=X:, cwd); any failure makes _wchdir return -1.
 * Exercise those real guest APIs, without claiming other-drive path resolution
 * or arbitrary leading-'=' variable support. */
#include "k32test.h"

static unsigned drive_entries(const WCHAR *env, WCHAR drive)
{
    unsigned count = 0;
    for (; *env; env += k32t_wlen(env) + 1)
        if (env[0] == '=' && (env[1] | 32) == (drive | 32) && env[2] == ':' && env[3] == '=') ++count;
    return count;
}

static int crt_drive_chdir(const WCHAR *path, WCHAR *cwd, DWORD cap)
{
    WCHAR name[4];
    DWORD n;
    if (!SetCurrentDirectoryW(path)) return -1;
    n = GetCurrentDirectoryW(cap, cwd);
    if (!n || n >= cap || cwd[1] != ':') return -1;
    name[0] = '=';
    name[1] = cwd[0] >= 'a' && cwd[0] <= 'z' ? cwd[0] - ('a' - 'A') : cwd[0];
    name[2] = ':'; name[3] = 0;
    return SetEnvironmentVariableW(name, cwd) ? 0 : -1;
}

int main(void)
{
    WCHAR original_cwd[1024], old_value[1024], cwd[1024], value[1024], name[4], lower_name[4];
    char ansi_name[4];
    const WCHAR *invalid[] = {L"ordinary=name", L"=D:=extra", L"==D:", L"=D:="};
    LPWCH before;
    DWORD n, old_len, error, after_len;
    BOOL ok, had_old;
    unsigned i;
    n = GetCurrentDirectoryW(1024, original_cwd);
    CHECK(n > 1 && n < 1024 && original_cwd[1] == ':', "guest has a real DOS current directory");
    if (n <= 1 || n >= 1024 || original_cwd[1] != ':') return 1;
    name[0] = '='; name[1] = original_cwd[0] & ~32; name[2] = ':'; name[3] = 0;
    lower_name[0] = '='; lower_name[1] = name[1] | 32; lower_name[2] = ':'; lower_name[3] = 0;
    SetLastError(0);
    old_len = GetEnvironmentVariableW(name, old_value, 1024);
    had_old = old_len != 0 || GetLastError() != ERROR_ENVVAR_NOT_FOUND;
    CHECK(old_len < 1024, "original drive value fits fixture preservation buffer");
    if (old_len >= 1024) return 1;

    CHECK(crt_drive_chdir(original_cwd, cwd, 1024) == 0 && k32t_weq(cwd, original_cwd),
          "Steam CRT chdir sequence changes a real directory and stores =X: successfully");
    n = GetEnvironmentVariableW(lower_name, value, 1024);
    CHECK(n == (DWORD)k32t_wlen(cwd) && k32t_weq(value, cwd), "hidden drive value is retrieved case insensitively");
    before = GetEnvironmentStringsW();
    CHECK(before && drive_entries(before, name[1]) == 1, "environment exposes exactly one =X:=directory entry");
    SetLastError(0x71a5);
    n = GetEnvironmentVariableW(name, NULL, 0);
    error = GetLastError();
    CHECK(n == (DWORD)k32t_wlen(cwd) + 1 && error == 0x71a5, "hidden value size query includes terminator and preserves caller error");
    value[0] = 0x1234; value[1] = 0;
    n = GetEnvironmentVariableW(name, value, 1);
    CHECK(n == (DWORD)k32t_wlen(cwd) + 1 && value[0] == 0x1234, "small hidden-value buffer remains untouched");

    CHECK(SetEnvironmentVariableW(lower_name, L"D:\\env-second"), "lowercase drive entry can be replaced");
    after_len = GetEnvironmentVariableW(name, value, 1024);
    CHECK(after_len == 13 && k32t_weq(value, L"D:\\env-second"), "replacement value is real and stored under the same hidden name");
    CHECK(drive_entries(GetEnvironmentStringsW(), name[1]) == 1 && before && drive_entries(before, name[1]) == 1,
          "case replacement keeps one current entry and preserves borrowed old environment block");
    CHECK(SetEnvironmentVariableW(name, L""), "hidden drive empty value is supported");
    value[0] = 0x1234;
    SetLastError(0x71a5);
    n = GetEnvironmentVariableW(name, value, 1024);
    error = GetLastError();
    CHECK(n == 0 && value[0] == 0 && error == 0x71a5, "empty hidden value is distinct from an absent variable");
    CHECK(SetEnvironmentVariableW(name, NULL), "hidden drive entry can be deleted");
    SetLastError(0);
    n = GetEnvironmentVariableW(name, value, 1024);
    error = GetLastError();
    CHECK(n == 0 && error == ERROR_ENVVAR_NOT_FOUND && drive_entries(GetEnvironmentStringsW(), name[1]) == 0,
          "deleted drive entry is absent from lookup and environment block");

    for (i = 0; i < sizeof invalid / sizeof invalid[0]; ++i) {
        SetLastError(0);
        ok = SetEnvironmentVariableW(invalid[i], L"bad");
        error = GetLastError();
        CHECK(!ok && error == ERROR_INVALID_PARAMETER, "interior equals still fails with invalid parameter");
    }
    ansi_name[0] = '='; ansi_name[1] = (char)name[1]; ansi_name[2] = ':'; ansi_name[3] = 0;
    CHECK(SetEnvironmentVariableA(ansi_name, "Z:\\ansi-drive"), "ANSI hidden drive setter uses the real wide implementation");
    n = GetEnvironmentVariableW(lower_name, value, 1024);
    CHECK(n == 13 && k32t_weq(value, L"Z:\\ansi-drive"), "ANSI hidden value is readable through wide lookup");
    CHECK(SetEnvironmentVariableA(ansi_name, NULL), "ANSI hidden drive deletion succeeds");
    CHECK(SetEnvironmentVariableW(name, had_old ? old_value : NULL), "original current-drive entry restored");
    CHECK(SetCurrentDirectoryW(original_cwd), "original real working directory retained");
    CHECK(FreeEnvironmentStringsW(before), "borrowed environment block released through API");
    return k32t_finish("T_DRIVE_ENVIRONMENT");
}
