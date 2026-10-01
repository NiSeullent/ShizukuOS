/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise the exact single-child CSS observer control flow with injected native API failures.
 * This is host evidence only: inheritance, Win98 APIs and pixels need a guest. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define M98_RUNNER_HOST_TEST
#define M98_RUN_NONCE "host-fixture-css-5abe"
#include "m98_css_mshtml_runner.c"

enum { NORMAL, WRONG_OS, STALE_RUN, STALE_FIRST, STALE_SECOND, CREATE_FAILURE,
       CRASH_EXIT, TIMEOUT_REAPED, TIMEOUT_UNREAPED, EXIT_QUERY_FAILURE,
       OUTPUT_RACE, FLUSH_FAILURE, SHORT_WRITES, WRITE_FAILURE, WRONG_PATH, WAIT_FAILURE,
       FINAL_FLUSH_FAILURE, FINAL_CLOSE_FAILURE };
struct mock_file { int exists, length; char text[8192]; };
struct mock_handle { int open, kind, file, child; };
static struct mock_file files[3];
static struct mock_handle handles[32];
static int mode, allocated, child_calls, wait_calls[2], termination_calls, checks, run_flushes;
static DWORD last_error;
#define CHECK(v) do { ++checks; if (!(v)) { fprintf(stderr,"FAIL %s:%d: %s mode=%d\n",__FILE__,__LINE__,#v,mode); exit(1); } } while (0)

static struct mock_handle *valid(HANDLE h)
{
    struct mock_handle *p = (struct mock_handle *)h;
    CHECK(p >= handles && p < handles + allocated && p->open);
    return p;
}

static HANDLE new_handle(int kind, int file, int child)
{
    struct mock_handle *h;
    CHECK(allocated < 32);
    h = &handles[allocated++]; h->open = 1; h->kind = kind; h->file = file; h->child = child;
    return h;
}

static int file_index(const char *path)
{
    if (!strcmp(path, RUN_LOG)) return 0;
    if (!strcmp(path, FIRST_LOG)) return 1;
    if (!strcmp(path, CHILD_LOG)) return 2;
    CHECK(0); return -1;
}

BOOL WriteFile(HANDLE handle, const void *data, DWORD length, DWORD *written, void *overlapped)
{
    struct mock_handle *h = valid(handle);
    struct mock_file *f = &files[h->file];
    CHECK(h->kind == 1 && !overlapped);
    if (mode == WRITE_FAILURE && f->length > 70) { last_error = 29; return FALSE; }
    if (mode == SHORT_WRITES && length > 7) length = 7;
    CHECK(length < sizeof(f->text) - (size_t)f->length);
    memcpy(f->text + f->length, data, length); f->length += (int)length;
    f->text[f->length] = 0; *written = length;
    /* Successful APIs may change last-error: retain failing API provenance. */
    last_error = 99;
    return TRUE;
}

DWORD GetFileAttributesA(const char *path)
{
    if (files[file_index(path)].exists) return FILE_ATTRIBUTE_NORMAL;
    last_error = ERROR_FILE_NOT_FOUND; return INVALID_FILE_ATTRIBUTES;
}
DWORD GetLastError(void) { return last_error; }
void SetLastError(DWORD value) { last_error = value; }
BOOL CloseHandle(HANDLE handle)
{
    struct mock_handle *h = valid(handle);
    h->open = 0;
    return !(mode == FINAL_CLOSE_FAILURE && h->kind == 1 && h->file == 0);
}

HANDLE CreateFileA(const char *path, DWORD access, DWORD share, SECURITY_ATTRIBUTES *attributes,
                   DWORD disposition, DWORD flags, HANDLE template_file)
{
    int index;
    CHECK(!template_file && flags == FILE_ATTRIBUTE_NORMAL);
    if (!strcmp(path, "NUL")) {
        CHECK(access == GENERIC_READ && share == (FILE_SHARE_READ | FILE_SHARE_WRITE));
        CHECK(disposition == OPEN_EXISTING && attributes && attributes->bInheritHandle);
        return new_handle(2, -1, -1);
    }
    index = file_index(path);
    CHECK(access == GENERIC_WRITE && share == FILE_SHARE_READ && disposition == CREATE_NEW);
    CHECK(index ? attributes && attributes->bInheritHandle : !attributes);
    if (files[index].exists || (mode == OUTPUT_RACE && index == 1)) {
        last_error = 80; return INVALID_HANDLE_VALUE;
    }
    files[index].exists = 1;
    return new_handle(1, index, -1);
}

BOOL CreateProcessA(const char *application, char *command, void *psa, void *tsa,
                    BOOL inherit, DWORD flags, void *environment, const char *directory,
                    STARTUPINFOA *startup, PROCESS_INFORMATION *process)
{
    int index = child_calls++;
    struct mock_handle *output = valid(startup->hStdOutput);
    CHECK(index == 0 && !psa && !tsa && inherit && !flags && !environment);
    CHECK(!strcmp(directory, ROOT_DIR) && !strcmp(command, application));
    CHECK(!strcmp(application, CHILD_PATH));
    CHECK(startup->cb == sizeof(*startup) && startup->dwFlags == STARTF_USESTDHANDLES);
    CHECK(startup->hStdError == startup->hStdOutput && output->kind == 1 && output->file == index + 1);
    CHECK(valid(startup->hStdInput)->kind == 2);
    if (mode == CREATE_FAILURE && !index) { last_error = 193; return FALSE; }
    process->hProcess = new_handle(3, -1, index);
    process->hThread = new_handle(4, -1, index); process->dwProcessId = 100u + (DWORD)index;
    CHECK(write_all(startup->hStdOutput, "native CSS child fixture stdout\r\n"));
    return TRUE;
}

DWORD WaitForSingleObject(HANDLE handle, DWORD timeout)
{
    struct mock_handle *h = valid(handle);
    int count = wait_calls[h->child]++;
    CHECK(h->kind == 3);
    CHECK(timeout == (count ? REAP_TIMEOUT_MS : CHILD_TIMEOUT_MS));
    if (!h->child && (mode == TIMEOUT_REAPED || mode == TIMEOUT_UNREAPED || mode == WAIT_FAILURE)) {
        if (!count) { last_error = 6; return mode == WAIT_FAILURE ? WAIT_FAILED : WAIT_TIMEOUT; }
        return mode == TIMEOUT_UNREAPED ? WAIT_TIMEOUT : WAIT_OBJECT_0;
    }
    return WAIT_OBJECT_0;
}

BOOL GetExitCodeProcess(HANDLE handle, DWORD *value)
{
    struct mock_handle *h = valid(handle);
    CHECK(h->kind == 3);
    if (!h->child && mode == EXIT_QUERY_FAILURE) { last_error = 6; return FALSE; }
    *value = !h->child && mode == CRASH_EXIT ? 0xc0000005u :
             !h->child && termination_calls ? ERROR_TIMEOUT : 0u;
    return TRUE;
}
BOOL TerminateProcess(HANDLE handle, DWORD code)
{
    struct mock_handle *h = valid(handle);
    CHECK(h->kind == 3 && h->child == 0 && code == ERROR_TIMEOUT);
    ++termination_calls;
    if (mode == TIMEOUT_UNREAPED) { last_error = 5; return FALSE; }
    return TRUE;
}
BOOL FlushFileBuffers(HANDLE handle)
{
    struct mock_handle *h = valid(handle);
    CHECK(h->kind == 1);
    if (!h->file && ++run_flushes == 3 && mode == FINAL_FLUSH_FAILURE) return FALSE;
    return !(mode == FLUSH_FAILURE && h->file == 1);
}
BOOL GetVersionExA(OSVERSIONINFOA *v)
{
    CHECK(v->dwOSVersionInfoSize == sizeof(*v));
    v->dwMajorVersion = 4; v->dwMinorVersion = mode == WRONG_OS ? 90 : 10;
    v->dwBuildNumber = 0x04000000u + 2222u; v->dwPlatformId = VER_PLATFORM_WIN32_WINDOWS;
    return TRUE;
}
DWORD GetModuleFileNameA(HANDLE module, char *target, DWORD size)
{
    const char *path = mode == WRONG_PATH ? ROOT_DIR "\\OTHER.EXE" : SELF_PATH;
    size_t n = strlen(path); CHECK(!module && n + 1 < size);
    memcpy(target, path, n + 1); return (DWORD)n;
}
int lstrcmpiA(const char *a, const char *b) { return strcmp(a, b); }

static void scenario(int selected, DWORD expected, int children)
{
    int i;
    DWORD result;
    mode = selected; allocated = child_calls = termination_calls = run_flushes = 0;
    last_error = 0; memset(files, 0, sizeof(files)); memset(handles, 0, sizeof(handles));
    memset(wait_calls, 0, sizeof(wait_calls)); run_log = INVALID_HANDLE_VALUE; log_ok = TRUE;
    if (mode == STALE_RUN || mode == STALE_FIRST || mode == STALE_SECOND) {
        int index = mode == STALE_RUN ? 0 : mode == STALE_FIRST ? 1 : 2;
        files[index].exists = 1; strcpy(files[index].text, "retained-evidence"); files[index].length = 17;
    }
    result = supervise(); CHECK(result == expected); CHECK(child_calls == children);
    for (i = 0; i < allocated; ++i) CHECK(!handles[i].open);
    if (mode == STALE_RUN) CHECK(!strcmp(files[0].text, "retained-evidence"));
    if (mode == STALE_FIRST) CHECK(!strcmp(files[1].text, "retained-evidence"));
    if (mode == STALE_SECOND) CHECK(!strcmp(files[2].text, "retained-evidence"));
    if (mode == CRASH_EXIT) CHECK(strstr(files[0].text, "child.exit-code=3221225477\r\n"));
    if (mode == EXIT_QUERY_FAILURE) CHECK(strstr(files[0].text, "child.exit-query=0\r\n"));
    if (mode == TIMEOUT_REAPED || mode == TIMEOUT_UNREAPED || mode == WAIT_FAILURE)
        CHECK(termination_calls == 1);
    if (mode == WAIT_FAILURE) CHECK(strstr(files[0].text, "child.wait-error=6\r\n"));
    if (mode == TIMEOUT_UNREAPED) CHECK(strstr(files[0].text, "child.terminate-error=5\r\n"));
    if (mode == FINAL_FLUSH_FAILURE || mode == FINAL_CLOSE_FAILURE)
        CHECK(strstr(files[0].text, "supervisor.requested-exit-code=0\r\n"));
    if (mode == NORMAL || mode == SHORT_WRITES) {
        CHECK(strstr(files[0].text, "nonce=host-fixture-css-5abe\r\n"));
        CHECK(strstr(files[0].text, "supervisor.requested-exit-code=0\r\n"));
        CHECK(strstr(files[1].text, "native CSS child fixture stdout\r\n"));
    }
}

int main(void)
{
    scenario(NORMAL, 0, 1); scenario(SHORT_WRITES, 0, 1);
    scenario(WRONG_OS, 11, 0); scenario(WRONG_PATH, 12, 0);
    scenario(STALE_RUN, 10, 0); scenario(STALE_FIRST, 13, 0); scenario(STALE_SECOND, 13, 0);
    scenario(CREATE_FAILURE, 15, 1); scenario(CRASH_EXIT, 15, 1);
    scenario(TIMEOUT_REAPED, 15, 1); scenario(TIMEOUT_UNREAPED, 15, 1);
    scenario(WAIT_FAILURE, 15, 1); scenario(EXIT_QUERY_FAILURE, 15, 1);
    scenario(OUTPUT_RACE, 15, 0); scenario(FLUSH_FAILURE, 15, 1);
    scenario(WRITE_FAILURE, 14, 0);
    scenario(FINAL_FLUSH_FAILURE, 14, 1); scenario(FINAL_CLOSE_FAILURE, 14, 1);
    printf("PASS: %d supervisor API/lifecycle assertions across 18 injected scenarios\n", checks);
    return 0;
}
