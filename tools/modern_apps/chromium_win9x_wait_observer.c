/* Observe a real address-wait probe through its complete process exit.
 * Derived from tools/iewebkit_wtf_runner.c, IEWebKit contributors (2026).
 * SPDX-License-Identifier: MIT */
#include <windows.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>

/* Closing every checkpoint also commits Win9x FAT length metadata. The probe
 * may abort with a modal CRT dialog and never close its own stdio stream. */
static BOOL checkpoint(BOOL first, const char *format, ...)
{
    char text[512];
    va_list arguments;
    int length;
    HANDLE file;
    DWORD written;
    BOOL success;
    va_start(arguments, format);
    length = vsnprintf(text, sizeof(text), format, arguments);
    va_end(arguments);
    if (length <= 0 || (size_t)length >= sizeof(text))
        return FALSE;
    file = CreateFileA("C:\\GOPLAB\\CWWEXIT.LOG", GENERIC_WRITE,
        FILE_SHARE_READ, NULL, first ? CREATE_NEW : OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return FALSE;
    SetLastError(0);
    success = first || SetFilePointer(file, 0, NULL, FILE_END) != INVALID_SET_FILE_POINTER ||
        GetLastError() == NO_ERROR;
    success = success && WriteFile(file, text, (DWORD)length, &written, NULL) &&
        written == (DWORD)length && FlushFileBuffers(file);
    if (!CloseHandle(file))
        success = FALSE;
    return success;
}

int main(int argc, char **argv)
{
    char module[MAX_PATH], command[256];
    OSVERSIONINFOA version;
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    DWORD waited, exit_code = STILL_ACTIVE, error, module_length;
    BOOL exited = FALSE;
    int success, length;
    if (argc != 2 || !strlen(argv[1]) || strlen(argv[1]) > 80 ||
        strspn(argv[1], "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != strlen(argv[1]))
        return 10;
    memset(module, 0, sizeof(module));
    module_length = GetModuleFileNameA(NULL, module, sizeof(module));
    if (!module_length || module_length >= sizeof(module) ||
        lstrcmpiA(module, "C:\\GOPLAB\\CWWAITR.EXE"))
        return 11;
    if (!checkpoint(TRUE,
        "scope=chromium-win9x-address-wait-owned-child-exit\r\nnonce=%s\r\n", argv[1]))
        return 2;
    memset(&version, 0, sizeof(version));
    version.dwOSVersionInfoSize = sizeof(version);
    success = GetVersionExA(&version) && version.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS &&
        version.dwMajorVersion == 4 && version.dwMinorVersion == 10 &&
        LOWORD(version.dwBuildNumber) == 2222;
    if (!checkpoint(FALSE, "os.exact-target=%u\r\n", !!success))
        return 2;
    if (!success) {
        checkpoint(FALSE, "exit=3\r\n");
        return 3;
    }
    length = snprintf(command, sizeof(command),
        "\"C:\\GOPLAB\\CWWAIT.EXE\" \"C:\\GOPLAB\\CWWAIT.LOG\" %s", argv[1]);
    if (length < 0 || (size_t)length >= sizeof(command)) {
        return 10;
    }
    memset(&startup, 0, sizeof(startup));
    memset(&process, 0, sizeof(process));
    startup.cb = sizeof(startup);
    SetLastError(0);
    success = CreateProcessA("C:\\GOPLAB\\CWWAIT.EXE", command, NULL, NULL,
        FALSE, 0, NULL, "C:\\GOPLAB", &startup, &process);
    error = GetLastError();
    if (!checkpoint(FALSE, "child.created=%u\r\nchild.create-error=%lu\r\n", !!success, error)) {
        if (success) {
            /* Own only this exact newly created child's handles. */
            TerminateProcess(process.hProcess, 7);
            WaitForSingleObject(process.hProcess, 5000);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        return 2;
    }
    if (!success) {
        checkpoint(FALSE, "exit=4\r\n");
        return 4;
    }
    success = checkpoint(FALSE, "child.pid=%lu\r\n", process.dwProcessId);
    CloseHandle(process.hThread);
    if (!success) {
        TerminateProcess(process.hProcess, 7);
        WaitForSingleObject(process.hProcess, 5000);
        CloseHandle(process.hProcess);
        return 2;
    }
    waited = WaitForSingleObject(process.hProcess, 90000);
    if (waited == WAIT_OBJECT_0)
        exited = GetExitCodeProcess(process.hProcess, &exit_code);
    success = checkpoint(FALSE,
        "child.wait=%lu\r\nchild.exit-query=%u\r\nchild.exit-code=%lu\r\n",
        waited, !!exited, exit_code) && success;
    success = success && waited == WAIT_OBJECT_0 && exited && exit_code == 0;
    if (waited != WAIT_OBJECT_0) {
        /* Only the handle returned by this invocation may be terminated. */
        BOOL terminated = TerminateProcess(process.hProcess, 6);
        DWORD reap = terminated ? WaitForSingleObject(process.hProcess, 5000) : WAIT_FAILED;
        checkpoint(FALSE, "child.timeout-terminated=%u\r\nchild.reaped=%u\r\n",
            !!terminated, reap == WAIT_OBJECT_0);
    }
    CloseHandle(process.hProcess);
    if (!checkpoint(FALSE, "child.post-CRT-exit-verified=%u\r\nexit=%u\r\n",
        !!success, success ? 0 : 5))
        return 2;
    return success ? 0 : 5;
}
