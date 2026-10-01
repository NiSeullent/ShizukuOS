/* SPDX-License-Identifier: GPL-2.0-only
 * Diagnostic only: the original process deliberately exits 7. Its real child
 * confirms that exit through the real process handle, then prints a delayed
 * marker. This does not turn the parent's nonzero result into an app PASS.
 */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "shzcrt.h"

static int child(int argc, char **argv)
{
    char *end;
    unsigned long pid;
    HANDLE parent, ready;
    DWORD code = STILL_ACTIVE;
    if (argc != 4) return 21;
    pid = strtoul(argv[2], &end, 10);
    if (!pid || *end) return 22;
    parent = OpenProcess(SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, (DWORD)pid);
    if (!parent || GetProcessId(parent) != (DWORD)pid) return 23;
    ready = OpenEventA(EVENT_MODIFY_STATE, FALSE, argv[3]);
    if (!ready) { CloseHandle(parent); return 24; }
    if (!SetEvent(ready) || !CloseHandle(ready)) { CloseHandle(parent); return 25; }
    if (WaitForSingleObject(parent, 10000) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(parent, &code) || code != 7) {
        CloseHandle(parent); return 26;
    }
    if (!CloseHandle(parent)) return 27;
    Sleep(10000);
    printf("K64 observation fixture: real child pid %lu survived actual parent pid %lu exit %lu after delayed scheduling\n",
           (unsigned long)GetCurrentProcessId(), pid, (unsigned long)code);
    return 0;
}

int main(int argc, char **argv)
{
    char image[MAX_PATH], command[512], event_name[48];
    HANDLE ready;
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    DWORD length, error;
    BOOL joined, thread_closed, process_closed;
    if (argc > 1 && !strcmp(argv[1], "--child")) return child(argc, argv);
    if (argc != 1) return 11;
    length = GetModuleFileNameA(NULL, image, sizeof image);
    if (!length || length >= sizeof image) return 12;
    if (snprintf(event_name, sizeof event_name, "Local\\K64_OBS_%lu",
                 (unsigned long)GetCurrentProcessId()) >= (int)sizeof event_name) return 13;
    SetLastError(ERROR_SUCCESS);
    ready = CreateEventA(NULL, TRUE, FALSE, event_name);
    error = GetLastError();
    if (!ready || error == ERROR_ALREADY_EXISTS) { if (ready) CloseHandle(ready); return 14; }
    if (snprintf(command, sizeof command, "\"%s\" --child %lu %s", image,
                 (unsigned long)GetCurrentProcessId(), event_name) >= (int)sizeof command) {
        CloseHandle(ready); return 15;
    }
    memset(&startup, 0, sizeof startup); startup.cb = sizeof startup;
    memset(&process, 0, sizeof process);
    if (!CreateProcessA(image, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) {
        CloseHandle(ready); return 16;
    }
    joined = WaitForSingleObject(ready, 10000) == WAIT_OBJECT_0;
    thread_closed = CloseHandle(process.hThread);
    process_closed = CloseHandle(process.hProcess);
    if (!CloseHandle(ready) || !joined || !thread_closed || !process_closed) return 17;
    printf("K64 observation fixture: actual parent pid %lu exits 7 after real child pid %lu acquired its process handle\n",
           (unsigned long)GetCurrentProcessId(), (unsigned long)process.dwProcessId);
    return 7;
}
