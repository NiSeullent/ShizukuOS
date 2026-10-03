/* SPDX-License-Identifier: GPL-2.0-only
 * Per-user SHZWALL settings/startup registry access shared by SHZWALL.EXE and
 * the SHZPERS settings app. Win32 (KERNEL32/ADVAPI32) only; i486 Win98 safe.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#include <windows.h>
#include <string.h>
#include "desktop_agent.h"
#include "agent_ctl.h"

DWORD szw_load_settings(szw_settings *out)
{
    HKEY key; DWORD i, error; uint32_t values[SZW_V_COUNT] = {0}, mask = 0;
    error = (DWORD)RegOpenKeyExA(HKEY_CURRENT_USER, SZW_SETTINGS_KEY, 0, KEY_QUERY_VALUE, &key);
    if (error == ERROR_FILE_NOT_FOUND) { szw_defaults(out); return ERROR_SUCCESS; }
    if (error != ERROR_SUCCESS) return error;
    for (i = 0; i < SZW_V_COUNT; i++) {
        DWORD type = 0, value = 0, size = sizeof value;
        error = (DWORD)RegQueryValueExA(key, szw_value_names[i], NULL, &type, (BYTE *)&value, &size);
        if (error == ERROR_FILE_NOT_FOUND) continue;
        if (error != ERROR_SUCCESS) break;
        if (type != REG_DWORD || size != sizeof value) { error = ERROR_INVALID_DATA; break; }
        values[i] = value; mask |= 1u << i; error = ERROR_SUCCESS;
    }
    RegCloseKey(key);
    if (error != ERROR_SUCCESS && error != ERROR_FILE_NOT_FOUND) return error;
    return szw_settings_from_values(mask, values, out) ? ERROR_SUCCESS : ERROR_INVALID_DATA;
}

DWORD szw_save_settings(const szw_settings *s)
{
    HKEY key; DWORD i, error, disposition; uint32_t values[SZW_V_COUNT];
    if (!szw_valid(s)) return ERROR_INVALID_PARAMETER;
    szw_settings_to_values(s, values);
    error = (DWORD)RegCreateKeyExA(HKEY_CURRENT_USER, SZW_SETTINGS_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                                   KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &key, &disposition);
    if (error != ERROR_SUCCESS) return error;
    for (i = 0; i < SZW_V_COUNT && error == ERROR_SUCCESS; i++) {
        DWORD value = values[i], back = 0, type = 0, size = sizeof back;
        error = (DWORD)RegSetValueExA(key, szw_value_names[i], 0, REG_DWORD, (const BYTE *)&value, sizeof value);
        if (error == ERROR_SUCCESS)
            error = (DWORD)RegQueryValueExA(key, szw_value_names[i], NULL, &type, (BYTE *)&back, &size);
        if (error == ERROR_SUCCESS && (type != REG_DWORD || size != sizeof back || back != value))
            error = ERROR_INVALID_DATA;
    }
    if (error == ERROR_SUCCESS) error = (DWORD)RegFlushKey(key);
    RegCloseKey(key);
    return error;
}

DWORD szw_set_startup(int enable)
{
    HKEY key; DWORD error, disposition, length;
    char path[MAX_PATH], quoted[MAX_PATH + 3], back[MAX_PATH + 3]; DWORD type = 0, size = sizeof back;
    error = (DWORD)RegCreateKeyExA(HKEY_CURRENT_USER, SZW_RUN_KEY, 0, NULL, REG_OPTION_NON_VOLATILE,
                                   KEY_QUERY_VALUE | KEY_SET_VALUE, NULL, &key, &disposition);
    if (error != ERROR_SUCCESS) return error;
    if (!enable) {
        error = (DWORD)RegDeleteValueA(key, SZW_RUN_VALUE);
        if (error == ERROR_FILE_NOT_FOUND) error = ERROR_SUCCESS;
    } else {
        length = GetModuleFileNameA(NULL, path, sizeof path);
        if (!length || length >= sizeof path) error = length ? ERROR_FILENAME_EXCED_RANGE : GetLastError();
        else {
            quoted[0] = '"'; memcpy(quoted + 1, path, length); quoted[length + 1] = '"'; quoted[length + 2] = 0;
            error = (DWORD)RegSetValueExA(key, SZW_RUN_VALUE, 0, REG_SZ, (const BYTE *)quoted, length + 3);
            if (error == ERROR_SUCCESS)
                error = (DWORD)RegQueryValueExA(key, SZW_RUN_VALUE, NULL, &type, (BYTE *)back, &size);
            if (error == ERROR_SUCCESS && (type != REG_SZ || size != length + 3 || memcmp(back, quoted, length + 3)))
                error = ERROR_INVALID_DATA;
        }
    }
    if (error == ERROR_SUCCESS) error = (DWORD)RegFlushKey(key);
    RegCloseKey(key);
    return error;
}


/* Start SHZWALL.EXE (sibling of the calling module) with /enable or /disable.
 * /disable is awaited (bounded) and its exit code returned; /enable leaves the
 * agent resident, so only a successful process creation is reported. */
DWORD szw_launch(int enable)
{
    char path[MAX_PATH], cmd[MAX_PATH + 24]; DWORD length, i, cut = 0, error = ERROR_SUCCESS;
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    length = GetModuleFileNameA(NULL, path, sizeof path);
    if (!length || length >= sizeof path) return length ? ERROR_FILENAME_EXCED_RANGE : GetLastError();
    for (i = 0; i < length; i++) if (path[i] == '\\' || path[i] == '/') cut = i + 1;
    if (cut + sizeof "SHZWALL.EXE" > sizeof path) return ERROR_FILENAME_EXCED_RANGE;
    memcpy(path + cut, "SHZWALL.EXE", sizeof "SHZWALL.EXE");
    if (GetFileAttributesA(path) == 0xFFFFFFFFu) return GetLastError();
    cmd[0] = '"'; length = (DWORD)lstrlenA(path);
    memcpy(cmd + 1, path, length);
    memcpy(cmd + 1 + length, enable ? "\" /enable" : "\" /disable", enable ? 10 : 11);
    memset(&si, 0, sizeof si); si.cb = sizeof si;
    if (!CreateProcessA(path, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) return GetLastError();
    if (!enable) {
        DWORD wait = WaitForSingleObject(pi.hProcess, 5000), code = 1;
        if (wait != WAIT_OBJECT_0) error = wait == WAIT_TIMEOUT ? WAIT_TIMEOUT : GetLastError();
        else if (!GetExitCodeProcess(pi.hProcess, &code)) error = GetLastError();
        else if (code) error = code;
    }
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return error;
}
