/* SPDX-License-Identifier: GPL-2.0-only
 * WKBATCH.EXE: runs one jsc.exe process per test file for tests/run_k64_webkit.py's stress mode (one guest boot for the
 * whole JSTests subset). Usage: wkbatch <list file> [seconds per test]. Each list line is "<file> <original path>";
 * the file is run as `jsc.exe <file>` in the current directory with inherited console handles. One result line per
 * test: "WKBATCH <file> exit=<decimal exit code> ms=<elapsed>[ timeout| fault| nostart]" ("fault" = an NTSTATUS error
 * code as the exit code, i.e. the process died of an exception), then "WKBATCH DONE <count>". Exit status 0 when the
 * list was read, whatever the tests did: the runner decides pass/fail from the lines. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    FILE *f;
    char line[512];
    unsigned limit_ms = (argc > 2 ? (unsigned)atoi(argv[2]) : 300) * 1000u, count = 0;
    if (argc < 2 || !(f = fopen(argv[1], "rb"))) {
        printf("WKBATCH cannot open the list\n");
        return 2;
    }
    while (fgets(line, sizeof line, f)) {
        char file[256], cmd[400];
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        DWORD code = 0, wait;
        ULONGLONG t0;
        const char *note = "";
        if (sscanf(line, "%255s", file) != 1) continue;
        snprintf(cmd, sizeof cmd, "jsc.exe %s", file);
        memset(&si, 0, sizeof si);
        si.cb = sizeof si;
        t0 = GetTickCount64();
        fflush(stdout);
        if (!CreateProcessA("jsc.exe", cmd, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            printf("WKBATCH %s exit=-1 ms=0 nostart\n", file);
            ++count;
            continue;
        }
        wait = WaitForSingleObject(pi.hProcess, limit_ms);
        if (wait != WAIT_OBJECT_0) {
            TerminateProcess(pi.hProcess, 0x102);
            WaitForSingleObject(pi.hProcess, 10000);
            note = " timeout";
        }
        GetExitCodeProcess(pi.hProcess, &code);
        if (!*note && code >= 0xC0000000u) note = " fault";
        printf("WKBATCH %s exit=%lu ms=%llu%s\n", file, (unsigned long)code, (unsigned long long)(GetTickCount64() - t0), note);
        fflush(stdout);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        ++count;
    }
    fclose(f);
    printf("WKBATCH DONE %u\n", count);
    return 0;
}
