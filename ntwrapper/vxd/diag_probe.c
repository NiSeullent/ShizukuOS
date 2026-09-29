/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded Windows 98 VxD diagnostic. No CRT or VxD changes. */
#if defined(NTWVDIAG_HOST_TEST)
#include "diag_mock.h"
#else
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#endif
#include "bridge.h"
#include "diag_expected.h"

static HANDLE log_file;
static unsigned logging_error;
static unsigned char file_bytes[sizeof(ntwdiag_expected)];

/* Logging has a separate failure channel: it must never convert an error
 * into success or prevent a best-effort close of an acquired handle. */
static int line(const char *text) {
    DWORD count = 0, written = 0;
    if (logging_error != 0u) return 0;
    while (text[count] != '\0') ++count;
    if (!WriteFile(log_file, text, count, &written, NULL) || written != count) {
        logging_error = 3u;
        return 0;
    }
    if (!FlushFileBuffers(log_file)) {
        logging_error = 4u;
        return 0;
    }
    return 1;
}

static int value(const char *key, DWORD number) {
    static const char digits[] = "0123456789abcdef";
    char text[80];
    unsigned i = 0, bit;
    while (key[i] != '\0' && i < 64u) {
        text[i] = key[i];
        ++i;
    }
    text[i++] = '='; text[i++] = '0'; text[i++] = 'x';
    for (bit = 0; bit != 8u; ++bit)
        text[i++] = digits[(number >> (28u - bit * 4u)) & 15u];
    text[i++] = '\r'; text[i++] = '\n'; text[i] = '\0';
    return line(text);
}

static DWORD little32(const unsigned char *p) {
    return (DWORD)p[0] | ((DWORD)p[1] << 8) | ((DWORD)p[2] << 16) | ((DWORD)p[3] << 24);
}

/* Exit codes and the numeric FAIL_STAGE are deliberately identical. A Win32
 * error is captured before any logging API may change GetLastError(). */
unsigned ntwdiag_run(void) {
    HANDLE file = INVALID_HANDLE_VALUE, device = INVALID_HANDLE_VALUE;
    OSVERSIONINFOA version;
    struct ntwv_query query;
    DWORD error = 0, observed = 0, high = 0, size, got = 0, le = 0, i;
    unsigned stage = 0;
    unsigned char extra = 0;
    unsigned char *raw;

    logging_error = 0;
    log_file = CreateFileA("C:\\NTWLAB\\NTWVDIAG.LOG", GENERIC_WRITE, FILE_SHARE_READ,
                           NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log_file == INVALID_HANDLE_VALUE) return 2u;
    if (!line("START=NTWVDIAG/1\r\n") ||
        !line("FILE_PATH=C:\\NTWLAB\\NTWRAP9X.VXD\r\n") ||
        !line("DEVICE_PATH=\\\\.\\C:\\NTWLAB\\NTWRAP9X.VXD\r\n") ||
        !line("EXPECTED_SHA256=" NTWVDIAG_EXPECTED_SHA256 "\r\n")) goto done;

    raw = (unsigned char *)&version;
    for (i = 0; i < sizeof(version); ++i) raw[i] = 0;
    version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version)) { stage = 6u; error = GetLastError(); goto done; }
    if (!value("OS_PLATFORM", version.dwPlatformId) || !value("OS_MAJOR", version.dwMajorVersion) ||
        !value("OS_MINOR", version.dwMinorVersion) || !value("OS_BUILD", version.dwBuildNumber)) goto done;
    if (version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS || version.dwMajorVersion != 4u ||
        version.dwMinorVersion != 10u) { stage = 1u; observed = version.dwPlatformId; goto done; }

    file = CreateFileA("C:\\NTWLAB\\NTWRAP9X.VXD", GENERIC_READ, FILE_SHARE_READ,
                       NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) { stage = 10u; error = GetLastError(); goto done; }
    size = GetFileSize(file, &high);
    if (size == INVALID_FILE_SIZE) {
        error = GetLastError();
        if (error != 0u) { stage = 11u; goto done; }
    }
    if (!value("FILE_BYTES", size) || !value("FILE_BYTES_HIGH", high)) goto done;
    if (high != 0 || size != sizeof(ntwdiag_expected)) {
        stage = 12u; observed = size; goto done;
    }
    if (!ReadFile(file, file_bytes, size, &got, NULL)) { stage = 13u; error = GetLastError(); goto done; }
    if (got != size) { stage = 14u; observed = got; goto done; }
    if (!ReadFile(file, &extra, 1u, &got, NULL)) { stage = 15u; error = GetLastError(); goto done; }
    if (got != 0u) { stage = 16u; observed = got; goto done; }
    if (file_bytes[0] != 'M' || file_bytes[1] != 'Z') { stage = 17u; goto done; }
    le = little32(file_bytes + 60);
    if (!value("LE_OFFSET", le)) goto done;
    if (le < 64u || le > sizeof(ntwdiag_expected) - 196u) { stage = 18u; observed = le; goto done; }
    if (file_bytes[le] != 'L' || file_bytes[le + 1u] != 'E') { stage = 19u; goto done; }
    for (i = 0; i < size; ++i) {
        if (file_bytes[i] != ntwdiag_expected[i]) { stage = 20u; observed = i; goto done; }
    }
    if (!CloseHandle(file)) {
        stage = 21u; error = GetLastError(); file = INVALID_HANDLE_VALUE; goto done;
    }
    file = INVALID_HANDLE_VALUE;
    if (!line("PREFLIGHT=PASS\r\n")) goto done;

    device = CreateFileA("\\\\.\\C:\\NTWLAB\\NTWRAP9X.VXD", 0, 0, NULL, OPEN_EXISTING,
                         FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (device == INVALID_HANDLE_VALUE) { stage = 30u; error = GetLastError(); goto done; }
    raw = (unsigned char *)&query;
    for (i = 0; i < sizeof(query); ++i) raw[i] = 0;
    got = 0;
    if (!DeviceIoControl(device, NTWV_IOCTL_QUERY, NULL, 0, &query, sizeof(query), &got, NULL)) {
        stage = 31u; error = GetLastError(); goto done;
    }
    if (!value("QUERY_RETURNED", got) || !value("QUERY_MAGIC", query.magic) ||
        !value("QUERY_SIZE", query.size) || !value("QUERY_ABI", query.abi) ||
        !value("QUERY_CORE_ABI", query.core_abi) || !value("QUERY_MAX_OBJECTS", query.max_objects) ||
        !value("QUERY_FEATURES", query.features) || !value("QUERY_INITIALIZED", query.initialized) ||
        !value("QUERY_SELFTEST", query.selftest)) goto done;
    if (got != sizeof(query) || query.magic != NTWV_QUERY_MAGIC || query.size != sizeof(query) ||
        query.abi != 1u || query.core_abi != NTW_ABI_VERSION || query.max_objects != NTW_MAX_OBJECTS ||
        query.features != 1u || query.initialized != 1u || query.selftest != 1u) {
        stage = 32u; observed = got; goto done;
    }

done:
    if (file != INVALID_HANDLE_VALUE && !CloseHandle(file)) {
        DWORD close_error = GetLastError();
        (void)value("CLEANUP_FILE_ERROR", close_error);
        if (stage == 0u) { stage = 21u; error = close_error; }
    }
    if (device != INVALID_HANDLE_VALUE && !CloseHandle(device)) {
        DWORD close_error = GetLastError();
        (void)value("CLEANUP_DEVICE_ERROR", close_error);
        if (stage == 0u) { stage = 33u; error = close_error; }
    }
    if (stage != 0u) {
        (void)value("FAIL_STAGE", stage);
        (void)value("WIN32_ERROR", error);
        (void)value("OBSERVED", observed);
        (void)line("RESULT=FAIL\r\n");
    } else if (logging_error == 0u) {
        (void)line("RESULT=PASS\r\n");
    }
    if (logging_error != 0u) stage = logging_error;
    if (!CloseHandle(log_file) && stage == 0u) stage = 5u;
    return stage;
}

#if !defined(NTWVDIAG_HOST_TEST)
void mainCRTStartup(void) { ExitProcess(ntwdiag_run()); }
#endif
