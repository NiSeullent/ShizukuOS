/* SPDX-License-Identifier: GPL-2.0-only
 * Explicit per-user profile access for participating ShizukuOS userland.
 */
#ifdef M98_PROFILE_HOST
#include "uxtheme_profile_win32_mock.h"
#else
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif
#include "uxtheme_engine_core.h"

HRESULT WINAPI m98e_M98SetThemeStyle(DWORD style);
static const char user_theme_key[] = "Software\\ShizukuOS\\Appearance";

HRESULT WINAPI m98e_ShizukuOSLoadUserTheme(void)
{
    HKEY key;
    DWORD style = M98_THEME_SHIZUKUOS, type = 0, bytes = sizeof(style);
    LONG error = RegOpenKeyExA(HKEY_CURRENT_USER, user_theme_key, 0,
                              KEY_QUERY_VALUE, &key);
    if (error == ERROR_SUCCESS) {
        LONG closed;
        error = RegQueryValueExA(key, "ThemeStyle", NULL, &type,
                                (BYTE *)&style, &bytes);
        closed = RegCloseKey(key);
        if ((error == ERROR_SUCCESS || error == ERROR_FILE_NOT_FOUND) &&
            closed != ERROR_SUCCESS) return HRESULT_FROM_WIN32(closed);
        if (error == ERROR_FILE_NOT_FOUND) style = M98_THEME_SHIZUKUOS;
        else if (error != ERROR_SUCCESS) return HRESULT_FROM_WIN32(error);
        else if (type != REG_DWORD || bytes != sizeof(style) ||
                 (style != M98_THEME_CLASSIC && style != M98_THEME_SHIZUKUOS))
            return E_INVALIDARG;
    } else if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND)
        return HRESULT_FROM_WIN32(error);
    return m98e_M98SetThemeStyle(style);
}

HRESULT WINAPI m98e_ShizukuOSSaveUserTheme(DWORD style)
{
    HKEY key;
    LONG error, closed;
    if (style != M98_THEME_CLASSIC && style != M98_THEME_SHIZUKUOS)
        return E_INVALIDARG;
    error = RegCreateKeyExA(HKEY_CURRENT_USER, user_theme_key, 0, NULL,
                           REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &key, NULL);
    if (error != ERROR_SUCCESS) return HRESULT_FROM_WIN32(error);
    error = RegSetValueExA(key, "ThemeStyle", 0, REG_DWORD,
                          (const BYTE *)&style, sizeof(style));
    closed = RegCloseKey(key);
    if (error == ERROR_SUCCESS && closed != ERROR_SUCCESS) error = closed;
    return error == ERROR_SUCCESS ? S_OK : HRESULT_FROM_WIN32(error);
}
