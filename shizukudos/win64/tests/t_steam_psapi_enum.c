/* SPDX-License-Identifier: GPL-2.0-only
 * Real child-process IDs and loaded-image PSAPI forwards for Valve startup.
 */
#define PSAPI_VERSION 1
#include "k32test.h"
#include <psapi.h>

static BOOL contains(const DWORD *ids, DWORD count, DWORD pid)
{
    DWORD i;
    for (i = 0; i < count; ++i) if (ids[i] == pid) return TRUE;
    return FALSE;
}

int main(void)
{
    static const WCHAR event_name[] = L"SHZ.PSAPI.ENUM.CHILD.DONE";
    DWORD ids[256], returned = 0, module_bytes = 0, length, i, exit_code;
    HMODULE modules[128], main_image = GetModuleHandleW(NULL);
    WCHAR path[512], base[512], command[600];
    char ansi[512];
    HANDLE completion;
    PROCESS_INFORMATION child;
    STARTUPINFOW startup;
    BYTE partial[8];
    if (strstr(GetCommandLineA(), "--psapi-child")) {
        HANDLE done = OpenEventW(SYNCHRONIZE, FALSE, event_name);
        DWORD waited;
        if (!done) return 2;
        waited = WaitForSingleObject(done, 5000);
        CloseHandle(done);
        return waited == WAIT_OBJECT_0 ? 0 : 3;
    }
    CHECK(EnumProcesses(ids, sizeof ids, &returned) && returned > 0 && returned <= sizeof ids && !(returned % sizeof(DWORD)),
          "legacy PSAPI enumerates actual whole system process identifiers");
    CHECK(contains(ids, returned / sizeof(DWORD), GetCurrentProcessId()), "real running test process is in the system snapshot");
    returned = 99;
    CHECK(EnumProcesses(NULL, 0, &returned) && returned == 0, "zero capacity returns zero written process bytes");
    CHECK(!EnumProcesses(NULL, sizeof(DWORD), &returned) && GetLastError() == ERROR_INVALID_PARAMETER,
          "nonzero process capacity requires an actual output array");
    CHECK(!EnumProcesses(ids, sizeof ids, NULL) && GetLastError() == ERROR_INVALID_PARAMETER,
          "process enumeration requires a returned-byte output");
    memset(partial, 0xa5, sizeof partial);
    CHECK(EnumProcesses((DWORD *)partial, 5, &returned) && returned == sizeof(DWORD) && partial[4] == 0xa5 && partial[7] == 0xa5,
          "short odd-sized array reports only written bytes and preserves its trailing canary");
    CHECK(EnumProcessModules(GetCurrentProcess(), NULL, 0, &module_bytes) && module_bytes >= sizeof(HMODULE),
          "module enumeration separately reports actual required bytes with no output array");
    CHECK(EnumProcessModules(GetCurrentProcess(), modules, sizeof modules, &module_bytes) && module_bytes <= sizeof modules,
          "legacy PSAPI enumerates actual loaded current-process modules");
    for (i = 0; i < module_bytes / sizeof(HMODULE) && modules[i] != main_image; ++i) {}
    CHECK(i < module_bytes / sizeof(HMODULE), "loaded module list contains the actual executable image");
    length = GetModuleFileNameW(NULL, path, 512);
    CHECK(length > 0 && length < 512, "actual executable path supplies independent basename reference");
    if (length) {
        DWORD begin = length;
        while (begin && path[begin - 1] != L'\\' && path[begin - 1] != L'/') --begin;
        CHECK(GetModuleBaseNameW(GetCurrentProcess(), NULL, base, 512) == length - begin && k32t_weq(base, path + begin),
              "wide legacy PSAPI basename equals the actual executable filename");
        CHECK(GetModuleBaseNameA(GetCurrentProcess(), main_image, ansi, sizeof ansi) > 0 &&
              MultiByteToWideChar(CP_ACP, 0, ansi, -1, base, 512) > 0 && k32t_weq(base, path + begin),
              "ANSI legacy PSAPI basename preserves actual module identity");
    }
    completion = CreateEventW(NULL, TRUE, FALSE, event_name);
    CHECK(completion != NULL, "create actual child completion object");
    memset(&startup, 0, sizeof startup); startup.cb = sizeof startup;
    memset(&child, 0, sizeof child);
    command[0] = L'"';
    for (i = 0; i < length && i + 20 < 600; ++i) command[i + 1] = path[i];
    memcpy(command + i + 1, L"\" --psapi-child", sizeof L"\" --psapi-child");
    CHECK(completion && CreateProcessW(path, command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &startup, &child),
          "create a real suspended child whose process ID remains observable");
    if (child.hProcess) {
        CHECK(EnumProcesses(ids, sizeof ids, &returned) && contains(ids, returned / sizeof(DWORD), child.dwProcessId),
              "process snapshot contains the independently created child's actual ID");
        CHECK(!EnumProcessModules(child.hProcess, modules, sizeof modules, &module_bytes) && GetLastError() == ERROR_NOT_SUPPORTED,
              "unimplemented remote module traversal reports failure rather than current-process modules");
        CHECK(SetEvent(completion) && ResumeThread(child.hThread) == 1, "release real child for normal completion");
        CHECK(WaitForSingleObject(child.hProcess, 5000) == WAIT_OBJECT_0 && GetExitCodeProcess(child.hProcess, &exit_code) && exit_code == 0,
              "real child process exits normally after its completion signal");
        CHECK(CloseHandle(child.hThread) && CloseHandle(child.hProcess), "release actual child handles");
    }
    if (completion) CloseHandle(completion);
    return k32t_finish("T_STEAM_PSAPI_ENUM");
}
