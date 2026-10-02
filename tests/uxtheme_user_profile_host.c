/* SPDX-License-Identifier: GPL-2.0-only
 * Executes the production profile code with injected registry failures.
 */
#include "uxtheme_profile_win32_mock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct {
    LONG open_error, query_error, create_error, write_error, close_error;
    HRESULT apply_error;
    DWORD value, type, size, applied, written;
    unsigned opens, queries, creates, writes, closes, applies, live;
} registry;
static unsigned checks;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #x); exit(1); } } while (0)

static void reset(void)
{
    memset(&registry, 0, sizeof(registry));
    registry.value = 1;
    registry.type = REG_DWORD;
    registry.size = sizeof(DWORD);
}
static void check_key(HKEY parent, const char *name, DWORD reserved, DWORD access)
{
    CHECK(parent == HKEY_CURRENT_USER);
    CHECK(!strcmp(name, "Software\\ShizukuOS\\Appearance"));
    CHECK(reserved == 0);
    CHECK(access == KEY_QUERY_VALUE || access == KEY_SET_VALUE);
}
LONG RegOpenKeyExA(HKEY parent, const char *name, DWORD reserved, DWORD access, HKEY *key)
{
    check_key(parent, name, reserved, access);
    CHECK(access == KEY_QUERY_VALUE);
    ++registry.opens;
    if (!registry.open_error) { CHECK(!registry.live); registry.live = 1; *key = 42; }
    return registry.open_error;
}
LONG RegQueryValueExA(HKEY key, const char *name, DWORD *reserved, DWORD *type, BYTE *value, DWORD *size)
{
    CHECK(key == 42 && registry.live);
    CHECK(!strcmp(name, "ThemeStyle"));
    CHECK(reserved == NULL && *size == sizeof(DWORD));
    ++registry.queries;
    if (!registry.query_error) {
        memcpy(value, &registry.value, sizeof(DWORD));
        *type = registry.type;
        *size = registry.size;
    }
    return registry.query_error;
}
LONG RegCloseKey(HKEY key)
{
    CHECK(key == 42 && registry.live);
    registry.live = 0;
    ++registry.closes;
    return registry.close_error;
}
LONG RegCreateKeyExA(HKEY parent, const char *name, DWORD reserved, char *klass,
                    DWORD options, DWORD access, void *security, HKEY *key, DWORD *disposition)
{
    check_key(parent, name, reserved, access);
    CHECK(access == KEY_SET_VALUE && options == REG_OPTION_NON_VOLATILE);
    CHECK(klass == NULL && security == NULL && disposition == NULL);
    ++registry.creates;
    if (!registry.create_error) { CHECK(!registry.live); registry.live = 1; *key = 42; }
    return registry.create_error;
}
LONG RegSetValueExA(HKEY key, const char *name, DWORD reserved, DWORD type, const BYTE *value, DWORD size)
{
    CHECK(key == 42 && registry.live);
    CHECK(!strcmp(name, "ThemeStyle"));
    CHECK(reserved == 0 && type == REG_DWORD && size == sizeof(DWORD));
    ++registry.writes;
    if (!registry.write_error) memcpy(&registry.written, value, sizeof(DWORD));
    return registry.write_error;
}
HRESULT m98e_M98SetThemeStyle(DWORD style)
{
    CHECK(!registry.live);
    ++registry.applies;
    registry.applied = style;
    return registry.apply_error;
}
int main(void)
{
    DWORD style;
    LONG missing;
    for (style = 1; style <= 3; style += 2) {
        reset(); registry.value = style;
        CHECK(m98e_ShizukuOSLoadUserTheme() == S_OK);
        CHECK(registry.applied == style && registry.applies == 1);
        CHECK(registry.closes == 1 && !registry.live && !registry.writes);
        reset();
        CHECK(m98e_ShizukuOSSaveUserTheme(style) == S_OK);
        CHECK(registry.written == style && registry.writes == 1 && registry.closes == 1);
        CHECK(!registry.applies && !registry.live);
    }
    for (missing = ERROR_FILE_NOT_FOUND; missing <= ERROR_PATH_NOT_FOUND; ++missing) {
        reset(); registry.open_error = missing;
        CHECK(m98e_ShizukuOSLoadUserTheme() == S_OK && registry.applied == 3);
        CHECK(!registry.queries && !registry.closes && !registry.creates);
    }
    reset(); registry.query_error = ERROR_FILE_NOT_FOUND;
    CHECK(m98e_ShizukuOSLoadUserTheme() == S_OK && registry.applied == 3);
    CHECK(registry.closes == 1 && !registry.writes);
    reset(); registry.query_error = ERROR_FILE_NOT_FOUND; registry.close_error = ERROR_INVALID_HANDLE;
    CHECK(m98e_ShizukuOSLoadUserTheme() == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE));
    CHECK(!registry.applies && registry.closes == 1);
    reset(); registry.open_error = ERROR_ACCESS_DENIED;
    CHECK(m98e_ShizukuOSLoadUserTheme() == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
    CHECK(!registry.queries && !registry.closes && !registry.applies);
    reset(); registry.query_error = ERROR_ACCESS_DENIED;
    CHECK(m98e_ShizukuOSLoadUserTheme() == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
    CHECK(registry.closes == 1 && !registry.applies);
    reset(); registry.query_error = ERROR_MORE_DATA;
    CHECK(m98e_ShizukuOSLoadUserTheme() == HRESULT_FROM_WIN32(ERROR_MORE_DATA));
    CHECK(registry.closes == 1 && !registry.applies);
    reset(); registry.type = 1;
    CHECK(m98e_ShizukuOSLoadUserTheme() == E_INVALIDARG && !registry.applies);
    reset(); registry.size = 2;
    CHECK(m98e_ShizukuOSLoadUserTheme() == E_INVALIDARG && !registry.applies);
    for (style = 0; style <= 4; ++style) {
        if (style == 1 || style == 3) continue;
        reset(); registry.value = style;
        CHECK(m98e_ShizukuOSLoadUserTheme() == E_INVALIDARG && !registry.applies);
        CHECK(registry.closes == 1 && !registry.writes);
        reset();
        CHECK(m98e_ShizukuOSSaveUserTheme(style) == E_INVALIDARG);
        CHECK(!registry.creates && !registry.writes && !registry.applies);
    }
    reset(); registry.close_error = ERROR_INVALID_HANDLE;
    CHECK(m98e_ShizukuOSLoadUserTheme() == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE));
    CHECK(!registry.applies && registry.closes == 1);
    reset(); registry.apply_error = E_OUTOFMEMORY;
    CHECK(m98e_ShizukuOSLoadUserTheme() == E_OUTOFMEMORY);
    CHECK(registry.applies == 1 && registry.closes == 1 && !registry.writes);
    reset(); registry.create_error = ERROR_ACCESS_DENIED;
    CHECK(m98e_ShizukuOSSaveUserTheme(3) == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
    CHECK(!registry.writes && !registry.closes && !registry.applies);
    reset(); registry.write_error = ERROR_ACCESS_DENIED;
    CHECK(m98e_ShizukuOSSaveUserTheme(3) == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
    CHECK(registry.closes == 1 && !registry.written && !registry.applies);
    reset(); registry.close_error = ERROR_INVALID_HANDLE;
    CHECK(m98e_ShizukuOSSaveUserTheme(3) == HRESULT_FROM_WIN32(ERROR_INVALID_HANDLE));
    CHECK(registry.written == 3 && registry.closes == 1 && !registry.applies);
    reset(); registry.write_error = ERROR_ACCESS_DENIED; registry.close_error = ERROR_INVALID_HANDLE;
    CHECK(m98e_ShizukuOSSaveUserTheme(3) == HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED));
    CHECK(registry.closes == 1 && !registry.applies);
    printf("PASS: %u profile assertions (production code; registry API mocked, native guest pending)\n", checks);
    return 0;
}
