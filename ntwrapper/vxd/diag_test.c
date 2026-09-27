/* SPDX-License-Identifier: GPL-2.0-only -- independently authored host oracle.
 * Models documented Win32 file/IOCTL contracts; does not run or validate VMM. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "diag_mock.h"
#include "diag_expected.h"

unsigned ntwdiag_run(void);
enum { H_LOG = 1, H_FILE = 2, H_DEVICE = 3 };
enum api {
    A_LOG_OPEN = 1, A_OS, A_FILE_OPEN, A_SIZE, A_READ, A_EOF,
    A_FILE_CLOSE, A_DEVICE_OPEN, A_QUERY, A_DEVICE_CLOSE,
    A_WRITE, A_FLUSH, A_LOG_CLOSE
};
static unsigned long checks, scenarios, injected;
static struct {
    unsigned calls, fault, fired, failed_api, writes, flushes, reads, opens;
    unsigned short_write, short_read, extra_eof, existing_log, query_bad;
    unsigned query_returned, query_failure_writes, specific_api;
    unsigned close_fail[4], acquired[4], live[4], close_calls[4];
    unsigned created_device, queried, ordinary_checked, first_read_ok, eof_ok;
    DWORD platform, major, minor, build, file_size, file_high, last_error;
    DWORD specific_error, first_error;
    unsigned char file[sizeof(ntwdiag_expected)];
    char log[32768];
    size_t log_size;
} m;

#define CHECK(x) do { ++checks; if (!(x)) { \
    fprintf(stderr, "line %u: %s (scenario %lu call %u fault %u api %u)\n", \
            __LINE__, #x, scenarios, m.calls, m.fault, m.failed_api); \
    exit(1); } } while (0)

static int call(enum api which) {
    ++m.calls;
    if (m.calls == m.fault || (unsigned)which == m.specific_api ||
        (which == A_FILE_CLOSE && m.close_fail[H_FILE]) ||
        (which == A_DEVICE_CLOSE && m.close_fail[H_DEVICE]) ||
        (which == A_LOG_CLOSE && m.close_fail[H_LOG])) {
        m.fired = 1;
        m.failed_api = (unsigned)which;
        m.last_error = m.specific_error ? m.specific_error : 0xd0000000u + m.calls;
        if (!m.first_error) m.first_error = m.last_error;
        return 1;
    }
    m.last_error = 0xaaaabbbbu;
    return 0;
}

static void reset(void) {
    memset(&m, 0, sizeof(m));
    m.platform = 1; m.major = 4; m.minor = 10; m.build = 0x040a08aeu;
    m.file_size = (DWORD)sizeof(ntwdiag_expected);
    m.query_returned = 32;
    memcpy(m.file, ntwdiag_expected, sizeof(m.file));
}

static int has(const char *value) { return strstr(m.log, value) != NULL; }

static DWORD field(const char *key) {
    const char *p = strstr(m.log, key);
    char *end = NULL;
    unsigned long n;
    CHECK(p != NULL);
    p += strlen(key);
    CHECK(p[0] == '=' && p[1] == '0' && p[2] == 'x');
    n = strtoul(p + 3, &end, 16);
    CHECK(end == p + 11 && end[0] == '\r' && end[1] == '\n' && n <= 0xfffffffful);
    return (DWORD)n;
}

static void put32(size_t offset, DWORD value) {
    unsigned i;
    CHECK(offset + 4 <= sizeof(m.file));
    for (i = 0; i < 4; ++i) m.file[offset + i] = (unsigned char)(value >> (8u * i));
}

DWORD GetLastError(void) { return m.last_error; }

HANDLE CreateFileA(const char *path, DWORD access, DWORD share, void *sa,
                   DWORD creation, DWORD flags, void *template_file) {
    unsigned h;
    enum api which;
    CHECK(path && !sa && !template_file);
    ++m.opens;
    if (!strcmp(path, "C:\\NTWLAB\\NTWVDIAG.LOG")) {
        CHECK(m.opens == 1 && !m.acquired[H_LOG]);
        CHECK(access == GENERIC_WRITE && share == FILE_SHARE_READ &&
              creation == CREATE_NEW && flags == FILE_ATTRIBUTE_NORMAL);
        h = H_LOG; which = A_LOG_OPEN;
    } else if (!strcmp(path, "C:\\NTWLAB\\NTWRAP9X.VXD")) {
        CHECK(m.opens == 2 && m.live[H_LOG] && !m.close_calls[H_LOG]);
        CHECK(m.platform == 1 && m.major == 4 && m.minor == 10);
        CHECK(access == GENERIC_READ && share == FILE_SHARE_READ &&
              creation == OPEN_EXISTING && flags == FILE_ATTRIBUTE_NORMAL);
        h = H_FILE; which = A_FILE_OPEN;
    } else {
        CHECK(!strcmp(path, "\\\\.\\C:\\NTWLAB\\NTWRAP9X.VXD"));
        CHECK(m.opens == 3 && m.live[H_LOG] && !m.close_calls[H_LOG]);
        CHECK(m.acquired[H_FILE] && m.close_calls[H_FILE] == 1 && !m.live[H_FILE]);
        CHECK(m.ordinary_checked && m.first_read_ok && m.eof_ok);
        CHECK(!memcmp(m.file, ntwdiag_expected, sizeof(m.file)));
        CHECK(access == 0 && share == 0 && creation == OPEN_EXISTING &&
              flags == FILE_FLAG_DELETE_ON_CLOSE);
        h = H_DEVICE; which = A_DEVICE_OPEN;
        ++m.created_device;
    }
    if (call(which)) return INVALID_HANDLE_VALUE;
    if (h == H_LOG && m.existing_log) {
        m.last_error = ERROR_FILE_EXISTS;
        return INVALID_HANDLE_VALUE;
    }
    CHECK(!m.live[h] && !m.acquired[h]);
    m.live[h] = 1; m.acquired[h] = 1;
    return (HANDLE)h;
}

BOOL GetVersionExA(OSVERSIONINFOA *os) {
    CHECK(m.live[H_LOG] && !m.acquired[H_FILE] && os);
    CHECK(os->dwOSVersionInfoSize == sizeof(*os));
    if (call(A_OS)) return FALSE;
    os->dwPlatformId = m.platform; os->dwMajorVersion = m.major;
    os->dwMinorVersion = m.minor; os->dwBuildNumber = m.build;
    return TRUE;
}

DWORD GetFileSize(HANDLE h, DWORD *high) {
    CHECK(h == H_FILE && m.live[H_FILE] && !m.close_calls[H_FILE] && high);
    CHECK(!m.reads && !m.ordinary_checked);
    if (call(A_SIZE)) return INVALID_FILE_SIZE;
    *high = m.file_high; ++m.ordinary_checked;
    /* A legitimate low size word of 0xffffffff is distinguished from an
     * API failure by NO_ERROR, even with a non-NULL high-size output. */
    if (m.file_size == INVALID_FILE_SIZE) m.last_error = ERROR_SUCCESS;
    return m.file_size;
}

BOOL ReadFile(HANDLE h, void *output, DWORD bytes, DWORD *read, void *overlap) {
    CHECK(h == H_FILE && m.live[H_FILE] && !m.close_calls[H_FILE]);
    CHECK(output && read && !overlap && m.ordinary_checked);
    CHECK(m.file_size == sizeof(m.file) && !m.file_high);
    ++m.reads;
    CHECK(m.reads <= 2);
    if (m.reads == 1) {
        CHECK(bytes == sizeof(m.file));
        if (call(A_READ)) return FALSE;
        *read = m.short_read ? bytes - m.short_read : bytes;
        CHECK(*read <= bytes);
        memcpy(output, m.file, *read);
        m.first_read_ok = *read == bytes;
    } else {
        CHECK(bytes == 1 && m.first_read_ok);
        if (call(A_EOF)) return FALSE;
        *read = m.extra_eof ? 1u : 0u;
        if (*read) *(unsigned char *)output = 0xcc;
        m.eof_ok = *read == 0;
    }
    return TRUE;
}

BOOL DeviceIoControl(HANDLE h, DWORD code, void *input, DWORD input_bytes,
                     void *output, DWORD output_bytes, DWORD *returned, void *overlap) {
    DWORD answer[8] = {0x3957544eu, 32u, 1u, 1u, 64u, 1u, 1u, 1u};
    int failed;
    CHECK(h == H_DEVICE && m.live[H_DEVICE] && !m.close_calls[H_DEVICE]);
    CHECK(code == 0x4e540001u && !input && !input_bytes && output &&
          output_bytes == 32 && returned && !overlap && !m.queried);
    ++m.queried;
    failed = call(A_QUERY);
    if (failed && !m.query_failure_writes) return FALSE;
    if (m.query_bad) {
        CHECK(m.query_bad <= 8);
        answer[m.query_bad - 1] ^= 1u;
    }
    memcpy(output, answer, sizeof(answer));
    *returned = m.query_returned;
    return failed ? FALSE : TRUE;
}

BOOL WriteFile(HANDLE h, const void *data, DWORD bytes, DWORD *written, void *overlap) {
    CHECK(h == H_LOG && m.live[H_LOG] && !m.close_calls[H_LOG]);
    CHECK(data && bytes && written && !overlap);
    ++m.writes;
    if (call(A_WRITE)) return FALSE;
    *written = m.short_write == m.writes ? bytes - 1u : bytes;
    CHECK(m.log_size + *written < sizeof(m.log));
    memcpy(m.log + m.log_size, data, *written);
    m.log_size += *written; m.log[m.log_size] = 0;
    m.last_error = 0xaabbccddu;
    return TRUE;
}

BOOL FlushFileBuffers(HANDLE h) {
    CHECK(h == H_LOG && m.live[H_LOG] && !m.close_calls[H_LOG]);
    ++m.flushes;
    return call(A_FLUSH) ? FALSE : TRUE;
}

BOOL CloseHandle(HANDLE h) {
    enum api which;
    CHECK(h >= H_LOG && h <= H_DEVICE && m.live[h] && !m.close_calls[h]);
    ++m.close_calls[h];
    which = h == H_LOG ? A_LOG_CLOSE : h == H_FILE ? A_FILE_CLOSE : A_DEVICE_CLOSE;
    if (h == H_LOG) {
        CHECK(!m.acquired[H_FILE] || m.close_calls[H_FILE] == 1);
        CHECK(!m.acquired[H_DEVICE] || m.close_calls[H_DEVICE] == 1);
    }
    if (call(which)) return FALSE;
    m.live[h] = 0;
    return TRUE;
}

static unsigned run(void) {
    unsigned h, result;
    unsigned char saved[sizeof(m.file)];
    memcpy(saved, m.file, sizeof(saved));
    ++scenarios;
    result = ntwdiag_run();
    CHECK(!memcmp(saved, m.file, sizeof(saved)));
    for (h = H_LOG; h <= H_DEVICE; ++h) {
        CHECK(m.acquired[h] == m.close_calls[h]);
        if (m.live[h]) CHECK(m.close_calls[h] == 1 && result != 0);
    }
    if (result == 0) {
        CHECK(m.opens == 3 && m.reads == 2 && m.queried == 1);
        CHECK(m.writes == m.flushes);
        CHECK(has("START=NTWVDIAG/1\r\n") && has("PREFLIGHT=PASS\r\n"));
        CHECK(has("RESULT=PASS\r\n") && !has("RESULT=FAIL\r\n") && !has("FAIL_STAGE="));
        CHECK(has("FILE_PATH=C:\\NTWLAB\\NTWRAP9X.VXD\r\n"));
        CHECK(has("DEVICE_PATH=\\\\.\\C:\\NTWLAB\\NTWRAP9X.VXD\r\n"));
        CHECK(field("OS_PLATFORM") == m.platform && field("OS_MAJOR") == m.major);
        CHECK(field("OS_MINOR") == m.minor && field("OS_BUILD") == m.build);
        CHECK(field("FILE_BYTES") == sizeof(m.file) && field("LE_OFFSET") == 0x80u);
        CHECK(field("QUERY_MAGIC") == 0x3957544eu && field("QUERY_SIZE") == 32);
        CHECK(field("QUERY_ABI") == 1 && field("QUERY_CORE_ABI") == 1);
        CHECK(field("QUERY_MAX_OBJECTS") == 64 && field("QUERY_FEATURES") == 1);
        CHECK(field("QUERY_INITIALIZED") == 1 && field("QUERY_SELFTEST") == 1);
    }
    return result;
}

static void expect_failure(unsigned expected) {
    CHECK(run() == expected);
    if (expected != 2 && expected != 3 && expected != 4 && expected != 5) {
        CHECK(has("RESULT=FAIL\r\n") && !has("RESULT=PASS\r\n"));
        CHECK(field("FAIL_STAGE") == expected);
    }
}

static unsigned api_status(unsigned api) {
    switch (api) {
    case A_LOG_OPEN: return 2; case A_OS: return 6; case A_FILE_OPEN: return 10;
    case A_SIZE: return 11; case A_READ: return 13; case A_EOF: return 15;
    case A_FILE_CLOSE: return 21; case A_DEVICE_OPEN: return 30; case A_QUERY: return 31;
    case A_DEVICE_CLOSE: return 33; case A_WRITE: return 3; case A_FLUSH: return 4;
    case A_LOG_CLOSE: return 5;
    default: CHECK(0); return 255;
    }
}

int main(void) {
    unsigned i, j, baseline_calls, baseline_writes, failure_calls, failure_writes;
    DWORD changed;
    static const DWORD invalid_offsets[] = {0, 1, 63, 0xfffffff0u, 0xffffffffu};
    static const unsigned operation_apis[] = {
        A_OS, A_FILE_OPEN, A_SIZE, A_READ, A_EOF, A_FILE_CLOSE,
        A_DEVICE_OPEN, A_QUERY, A_DEVICE_CLOSE
    };
    reset(); CHECK(run() == 0);
    baseline_calls = m.calls; baseline_writes = m.writes;
    reset(); m.build = 1998; CHECK(run() == 0);
    reset(); m.existing_log = 1;
    strcpy(m.log, "sentinel existing diagnostic evidence\r\n"); m.log_size = strlen(m.log);
    expect_failure(2); CHECK(m.opens == 1 && m.calls == 1);
    CHECK(!strcmp(m.log, "sentinel existing diagnostic evidence\r\n") && !m.acquired[H_LOG]);
    for (i = 0; i < 5; ++i) {
        reset();
        if (i == 0) m.platform = 2;
        if (i == 1) m.major = 5;
        if (i == 2) m.minor = 0;
        if (i == 3) m.minor = 90;
        if (i == 4) m.platform = 0;
        expect_failure(1); CHECK(m.opens == 1 && !m.reads && !m.queried);
    }
    for (i = 0; i < 4; ++i) {
        reset();
        if (i == 0) m.file_size = 0;
        if (i == 1) --m.file_size;
        if (i == 2) ++m.file_size;
        if (i == 3) m.file_high = 1;
        expect_failure(12); CHECK(!m.reads && !m.created_device);
    }
    for (i = 0; i < 2; ++i) {
        reset(); m.file_size = INVALID_FILE_SIZE; m.file_high = i;
        expect_failure(12); CHECK(!m.reads && !m.created_device);
        CHECK(field("WIN32_ERROR") == ERROR_SUCCESS);
        CHECK(field("FILE_BYTES") == INVALID_FILE_SIZE && field("FILE_BYTES_HIGH") == i);
    }
    for (i = 1; i <= 2; ++i) {
        reset(); m.short_read = i == 1 ? 1u : (unsigned)sizeof(m.file);
        expect_failure(14); CHECK(m.reads == 1 && !m.created_device);
    }
    reset(); m.extra_eof = 1; expect_failure(16); CHECK(!m.created_device);
    for (i = 0; i < 2; ++i) {
        reset(); m.file[i] ^= 1u; expect_failure(17); CHECK(!m.created_device);
    }
    for (i = 0; i < sizeof(invalid_offsets) / sizeof(invalid_offsets[0]); ++i) {
        reset(); put32(0x3c, invalid_offsets[i]); expect_failure(18); CHECK(!m.created_device);
    }
    reset(); put32(0x3c, (DWORD)sizeof(m.file) - 195u); expect_failure(18);
    for (i = 0; i < 2; ++i) {
        reset(); m.file[0x80u + i] ^= 1u; expect_failure(19); CHECK(!m.created_device);
    }
    reset(); put32(0x3c, 64); m.file[64] = 'L'; m.file[65] = 'E'; expect_failure(20);
    reset(); put32(0x3c, (DWORD)sizeof(m.file) - 196u);
    m.file[sizeof(m.file) - 196] = 'L'; m.file[sizeof(m.file) - 195] = 'E'; expect_failure(20);
    /* Every non-header byte must be identity bound, including DOS stub, LE
     * tables, padding, code and resident data. The model never interprets code. */
    for (i = 0; i < sizeof(m.file); ++i) {
        if (i < 2 || (i >= 0x3c && i < 0x40) || i == 0x80 || i == 0x81) continue;
        reset(); m.file[i] ^= 0x80u; expect_failure(20); CHECK(!m.created_device);
    }
    for (i = 1; i <= 8; ++i) {
        reset(); m.query_bad = i; expect_failure(32); CHECK(m.queried == 1);
    }
    for (i = 0; i <= 33; ++i) {
        if (i == 32) continue;
        reset(); m.query_returned = i; expect_failure(32);
    }
    reset(); m.query_returned = 0xffffffffu; expect_failure(32);
    for (i = 0; i < sizeof(operation_apis) / sizeof(operation_apis[0]); ++i) {
        reset(); m.specific_api = operation_apis[i]; m.specific_error = 0x1234fedcu;
        expect_failure(api_status(operation_apis[i]));
        CHECK(field("WIN32_ERROR") == 0x1234fedcu);
    }
    /* API failure is authoritative even when it wrote a plausible output. */
    reset(); m.specific_api = A_QUERY; m.specific_error = 998; m.query_failure_writes = 1;
    expect_failure(31); CHECK(field("WIN32_ERROR") == 998);
    for (i = 0; i < 3; ++i) {
        reset(); m.specific_api = A_DEVICE_OPEN; m.specific_error = i == 0 ? 2u : i == 1 ? 5u : 193u;
        expect_failure(30); CHECK(field("WIN32_ERROR") == m.specific_error && m.opens == 3);
    }
    /* Sweep every successful-path callback and all log writes, including the
     * terminal record and final close. A failed close must never be retried. */
    for (i = 1; i <= baseline_calls; ++i) {
        reset(); m.fault = i; changed = run(); ++injected;
        CHECK(m.fired && changed == api_status(m.failed_api));
        if (m.failed_api != A_WRITE && m.failed_api != A_FLUSH &&
            m.failed_api != A_LOG_OPEN && m.failed_api != A_LOG_CLOSE)
            CHECK(field("WIN32_ERROR") == m.first_error);
    }
    for (i = 1; i <= baseline_writes; ++i) {
        reset(); m.short_write = i; expect_failure(3); ++injected;
    }
    /* Also reach error-reporting and cleanup callbacks absent on success. */
    reset(); m.query_bad = 1; expect_failure(32);
    failure_calls = m.calls; failure_writes = m.writes;
    for (i = 1; i <= failure_calls; ++i) {
        reset(); m.query_bad = 1; m.fault = i; changed = run(); ++injected;
        CHECK(m.fired && changed != 0);
        if (m.failed_api == A_LOG_CLOSE || m.failed_api == A_DEVICE_CLOSE) CHECK(changed == 32);
        else CHECK(changed == api_status(m.failed_api));
    }
    for (i = 1; i <= failure_writes; ++i) {
        reset(); m.query_bad = 1; m.short_write = i; expect_failure(3); ++injected;
    }
    /* Preserve the first operation failure through any ambiguous cleanup close
     * errors; attempt all owned closes and record their distinct error fields. */
    for (i = 0; i < 2; ++i) {
        for (j = 1; j < 4; ++j) {
            reset();
            if (i == 0) m.short_read = 1; else m.query_bad = 1;
            m.close_fail[H_LOG] = j & 1u;
            m.close_fail[i == 0 ? H_FILE : H_DEVICE] = (j >> 1) & 1u;
            expect_failure(i == 0 ? 14u : 32u);
            if (j & 2u) CHECK(has(i == 0 ? "CLEANUP_FILE_ERROR=" : "CLEANUP_DEVICE_ERROR="));
        }
    }
    printf("{\"assertions\":%lu,\"scenarios\":%lu,\"injected_callbacks\":%lu,"
           "\"baseline_calls\":%u,\"baseline_writes\":%u,\"identity_mutations\":%lu}\n",
           checks, scenarios, injected, baseline_calls, baseline_writes,
           (unsigned long)sizeof(m.file) - 8ul);
    return 0;
}
