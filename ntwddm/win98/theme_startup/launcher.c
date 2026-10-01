/* SPDX-License-Identifier: GPL-2.0-only
 * Argument-free WIN.INI executable: launch the unchanged observer with one
 * bounded staged challenge. This is separate from the theme/child verdict.
 * No CRT, registry, network, inherited handles, or arbitrary command input.
 */
#ifdef NTTHBOOT_HOST_TEST
#include "../theme_probe/observer_mock.h"
#else
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0400
#define _WIN32_WINNT 0x0400
#include <windows.h>
#endif

#define OBSERVER_WAIT_MS 90000u
static HANDLE boot_log = INVALID_HANDLE_VALUE;
static int boot_io_failed;

static void boot_zero(void *object, DWORD bytes)
{
    volatile unsigned char *p = (volatile unsigned char *)object;
    while (bytes--) *p++ = 0;
}

static void boot_text(const char *text)
{
    DWORD count = 0;
    if (boot_log == INVALID_HANDLE_VALUE || boot_io_failed) return;
    while (text[count]) ++count;
    while (count) {
        DWORD written = 0;
        if (!WriteFile(boot_log, text, count, &written, NULL) ||
            !written || written > count) { boot_io_failed = 1; return; }
        text += written; count -= written;
    }
}

static void boot_number(const char *key, DWORD value)
{
    char digits[11]; DWORD at = 10;
    digits[at] = 0;
    do { digits[--at] = (char)('0' + value % 10u); value /= 10u; } while (value);
    boot_text(key); boot_text(digits + at); boot_text("\r\n");
}

static int boot_equal(const char *a, const char *b)
{
    DWORD i = 0;
    while (a[i] && b[i]) {
        unsigned char x = (unsigned char)a[i], y = (unsigned char)b[i];
        if (x >= 'a' && x <= 'z') x = (unsigned char)(x - 'a' + 'A');
        if (y >= 'a' && y <= 'z') y = (unsigned char)(y - 'a' + 'A');
        if (x != y) return 0;
        ++i;
    }
    return a[i] == b[i];
}

static int boot_pin(char pin[33])
{
    DWORD read = 0, tail = 0, i; char extra; int valid = 0;
    HANDLE file = CreateFileA("C:\\VXDLAB\\THNONCE.TXT", GENERIC_READ, FILE_SHARE_READ,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    if (ReadFile(file, pin, 32u, &read, NULL) && read == 32u &&
        ReadFile(file, &extra, 1u, &tail, NULL) && !tail) {
        valid = 1;
        for (i = 0; i < 32u; ++i)
            if (!((pin[i] >= '0' && pin[i] <= '9') || (pin[i] >= 'a' && pin[i] <= 'f')))
                valid = 0;
        pin[32] = 0;
    }
    if (!CloseHandle(file)) valid = 0;
    return valid;
}

static DWORD boot_main(void)
{
    static const char prefix[] = "\"C:\\VXDLAB\\NTTHRUN.EXE\" --nonce=";
    char command[sizeof(prefix) + 32u], pin[33], module[MAX_PATH];
    OSVERSIONINFOA version; STARTUPINFOA startup; PROCESS_INFORMATION process;
    DWORD module_bytes, i, pos = 0, wait = WAIT_FAILED, child_exit = 0, code = 2;
    int created = 0, queried = 0, thread_closed = 1, process_closed = 1;
    int cleanup = 1, observer_success = 0;
    boot_io_failed = 0;
    boot_log = CreateFileA("C:\\VXDLAB\\THBOOT.LOG", GENERIC_WRITE, FILE_SHARE_READ,
                          NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (boot_log == INVALID_HANDLE_VALUE) return 2u;
    boot_text("NTTHBOOT_LOG_VERSION=1\r\nSCOPE=startup-bootstrap-and-observer-lifecycle\r\nTHEME_VERDICT=NOT-EVALUATED\r\n");
    if (!FlushFileBuffers(boot_log)) boot_io_failed = 1;
    module[0] = 0; module[MAX_PATH - 1u] = 0;
    module_bytes = GetModuleFileNameA(NULL, module, MAX_PATH);
    if (!module_bytes || module_bytes >= MAX_PATH || module[module_bytes] ||
        !boot_equal(module, "C:\\VXDLAB\\NTTHBOOT.EXE")) goto done;
    boot_zero(&version, sizeof(version)); version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version) || version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS ||
        version.dwMajorVersion != 4u || version.dwMinorVersion != 10u ||
        LOWORD(version.dwBuildNumber) != 2222u) goto done;
    boot_number("OS_PLATFORM=", version.dwPlatformId);
    boot_number("OS_MAJOR=", version.dwMajorVersion);
    boot_number("OS_MINOR=", version.dwMinorVersion);
    boot_number("OS_BUILD_LOW=", LOWORD(version.dwBuildNumber));
    if (!boot_pin(pin)) goto done;
    boot_text("BEGIN_NONCE="); boot_text(pin); boot_text("\r\n");
    for (i = 0; prefix[i]; ++i) command[pos++] = prefix[i];
    for (i = 0; i < 32u; ++i) command[pos++] = pin[i];
    command[pos] = 0;
    boot_text("OBSERVER_COMMAND="); boot_text(command); boot_text("\r\n");
    boot_zero(&startup, sizeof(startup)); boot_zero(&process, sizeof(process));
    startup.cb = sizeof(startup);
    created = CreateProcessA("C:\\VXDLAB\\NTTHRUN.EXE", command, NULL, NULL, FALSE,
                             0, NULL, "C:\\VXDLAB", &startup, &process);
    if (!created) goto done;
    boot_number("OBSERVER_PID=", process.dwProcessId);
    wait = WaitForSingleObject(process.hProcess, OBSERVER_WAIT_MS);
    if (wait == WAIT_OBJECT_0) queried = GetExitCodeProcess(process.hProcess, &child_exit);
    /* A timeout/failed wait never terminates the observer or fabricates an
     * exit: its own child lifecycle remains intact. The host VM is bounded. */
    thread_closed = CloseHandle(process.hThread);
    process_closed = CloseHandle(process.hProcess);
    observer_success = wait == WAIT_OBJECT_0 && queried && child_exit == 0u;
    cleanup = thread_closed && process_closed;
    if (observer_success && cleanup) code = 0;
done:
    boot_number("OBSERVER_CREATED=", (DWORD)created);
    boot_number("OBSERVER_WAIT=", wait);
    boot_number("OBSERVER_EXIT_QUERY=", (DWORD)queried);
    if (queried) boot_number("OBSERVER_ACTUAL_EXIT_CODE=", child_exit);
    boot_text("OBSERVER_TERMINATION_ATTEMPTED=0\r\n");
    boot_number("OBSERVER_THREAD_CLOSED=", (DWORD)thread_closed);
    boot_number("OBSERVER_PROCESS_CLOSED=", (DWORD)process_closed);
    boot_text(observer_success && cleanup && !boot_io_failed ?
              "OBSERVER_LIFECYCLE_BEFORE_FINAL_LOG_IO=PASS\r\n" :
              "OBSERVER_LIFECYCLE_BEFORE_FINAL_LOG_IO=FAIL\r\n");
    boot_text("RESULT=NOT-A-FINAL-BOOTSTRAP-EXIT-VERDICT\r\n");
    boot_text("EXTERNAL_BOOTSTRAP_EXIT=NOT-OBSERVED\r\nBOOTSTRAP_LOG_CLOSE_ATTEMPTED=1\r\n");
    if (!FlushFileBuffers(boot_log)) boot_io_failed = 1;
    if (!CloseHandle(boot_log)) boot_io_failed = 1;
    boot_log = INVALID_HANDLE_VALUE;
    if (boot_io_failed) code = 2;
    return code;
}

#ifndef NTTHBOOT_HOST_TEST
void mainCRTStartup(void) { ExitProcess(boot_main()); }
#endif
