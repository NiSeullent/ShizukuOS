/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed-path, digest-bound VLC prerequisites. No wildcard or NPP writes.
 * The original CORE backup is independent and retained after success.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "sha256.h"
#include "vlc_install_pins.h"

static HANDLE report = INVALID_HANDLE_VALUE;
static unsigned owned[3];
static int io_failed, core_started;
static unsigned length(const char *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static int same(const char *a, const char *b) {
    while (*a && *a == *b) { ++a; ++b; }
    return *a == *b;
}
static void text(const char *s) {
    DWORD written, bytes = length(s);
    if (!WriteFile(report, s, bytes, &written, NULL) || written != bytes) io_failed = 1;
}
static void number(const char *name, DWORD n) {
    char data[9]; unsigned i;
    for (i = 0; i < 8; ++i) data[i] = "0123456789ABCDEF"[(n >> (28 - i * 4)) & 15];
    data[8] = 0; text(name); text(data); text("\r\n");
}
static const char *argument(void) {
    const char *s = GetCommandLineA(); BOOL quote = FALSE;
    while (*s) {
        if (*s == '"') quote = !quote;
        else if (!quote && (*s == ' ' || *s == '\t')) break;
        ++s;
    }
    while (*s == ' ' || *s == '\t') ++s;
    return s;
}
static int absent(const char *path) {
    DWORD attributes = GetFileAttributesA(path), error;
    if (attributes != INVALID_FILE_ATTRIBUTES) return 0;
    error = GetLastError();
    return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
static int exact(const char *path, const char *pin, DWORD bytes) {
    /* Single-threaded helper: no 4KiB stack commitment or CRT probe needed. */
    static BYTE block[4096];
    HANDLE file; sha256_ctx hash; BYTE digest[32]; char hex[65];
    DWORD count, total = 0; int good = 1;
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    sha256_init(&hash);
    for (;;) {
        if (!ReadFile(file, block, sizeof(block), &count, NULL)) { good = 0; break; }
        if (!count) break;
        if (total > bytes || count > bytes - total) { good = 0; break; }
        total += count; sha256_update(&hash, block, count);
    }
    if (!CloseHandle(file)) good = 0;
    sha256_final(&hash, digest); sha256_hex(digest, hex);
    return good && total == bytes && same(hex, pin);
}
/* Ownership starts only when our CREATE_NEW actually succeeds. A failed
 * partial write belongs to this helper, and rollback cannot remove a
 * pre-existing destination. Replacement is used solely for saved CORE.
 */
static int copy(const char *source, const char *destination, const char *pin,
                DWORD bytes, int replace, unsigned *created) {
    static BYTE block[4096];
    HANDLE input, output; DWORD count, done, total = 0; int good = 1;
    if (!exact(source, pin, bytes)) return 0;
    input = CreateFileA(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE) return 0;
    output = CreateFileA(destination, GENERIC_WRITE, 0, NULL,
                         replace ? CREATE_ALWAYS : CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output == INVALID_HANDLE_VALUE) { CloseHandle(input); return 0; }
    if (created) *created = 1;
    if (replace) core_started = 1;
    for (;;) {
        if (!ReadFile(input, block, sizeof(block), &count, NULL)) { good = 0; break; }
        if (!count) break;
        if (total > bytes || count > bytes - total) { good = 0; break; }
        total += count;
        if (!WriteFile(output, block, count, &done, NULL) || done != count) { good = 0; break; }
    }
    if (!FlushFileBuffers(output)) good = 0;
    if (!CloseHandle(output)) good = 0;
    if (!CloseHandle(input)) good = 0;
    return good && total == bytes && exact(destination, pin, bytes);
}
static int rollback(void) {
    unsigned i; int good = 1;
    if (core_started) {
        if (!copy(CORE_BACKUP, CORE_DESTINATION, CORE_OLD_SHA, CORE_OLD_BYTES, 1, NULL)) good = 0;
        if (!exact(CORE_DESTINATION, CORE_OLD_SHA, CORE_OLD_BYTES)) good = 0;
    }
    for (i = 0; i < 3; ++i) {
        if (owned[i]) {
            if (!DeleteFileA(providers[i].destination) || !absent(providers[i].destination)) good = 0;
        }
    }
    number("OWNED_MUTATIONS_ROLLBACK_VERIFIED=", good);
    return good;
}
static int verify(void) {
    unsigned i;
    if (!exact(CORE_BACKUP, CORE_OLD_SHA, CORE_OLD_BYTES) ||
        !exact(CORE_DESTINATION, CORE_NEW_SHA, CORE_NEW_BYTES)) return 0;
    for (i = 0; i < 3; ++i) {
        if (!exact(providers[i].destination, providers[i].sha256, providers[i].bytes)) return 0;
        text("VERIFIED_INSTALLED="); text(providers[i].destination); text("\r\n");
    }
    text("CORE_INDEPENDENT_BACKUP_OLD_EXACT=1\r\nCORE_INSTALLED_NEW_EXACT=1\r\n");
    return !io_failed;
}
void WINAPI entry(void) {
    const char *mode = argument(); BOOL apply = same(mode, "apply");
    char windows[MAX_PATH]; DWORD count, version = GetVersion(), code = 4;
    unsigned i, backup_created = 0, copies_completed = 0;
    if (!apply && !same(mode, "verify")) ExitProcess(2);
    report = CreateFileA(apply ? "C:\\VLCLAB\\INSTALLA.LOG" : "C:\\VLCLAB\\INSTALLV.LOG",
                         GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(20);
    text("SCOPE=THREE_ONLY_ABSENT_VLC_PROVIDERS_AND_HASH_BOUND_CORE\r\n");
    count = GetWindowsDirectoryA(windows, sizeof(windows));
    if (!(version & 0x80000000U) || LOBYTE(LOWORD(version)) != 4 ||
        HIBYTE(LOWORD(version)) != 10 || count != 10 ||
        !same(windows, "C:\\WINDOWS")) {
        text("GUARD_REJECTED=NATIVE_WIN98_FIXED_WINDOWS_DIRECTORY\r\n"); goto done;
    }
    if (!apply) { code = verify() ? 0 : 6; goto done; }
    if (!absent(CORE_BACKUP) || !exact(CORE_DESTINATION, CORE_OLD_SHA, CORE_OLD_BYTES) ||
        !exact(CORE_SOURCE, CORE_NEW_SHA, CORE_NEW_BYTES)) {
        text("GUARD_REJECTED=CORE_OR_BACKUP\r\n"); goto done;
    }
    for (i = 0; i < 3; ++i) {
        if (!absent(providers[i].destination) ||
            !exact(providers[i].source, providers[i].sha256, providers[i].bytes)) {
            text("GUARD_REJECTED=EXISTING_PROVIDER_OR_SOURCE_HASH\r\n"); goto done;
        }
    }
    if (io_failed) goto done;
    if (!copy(CORE_DESTINATION, CORE_BACKUP, CORE_OLD_SHA, CORE_OLD_BYTES, 0, &backup_created)) {
        text("BACKUP_FAILED_CORE_NOT_CHANGED=1\r\n"); code = 5; goto done;
    }
    text("CORE_INDEPENDENT_BACKUP_OLD_EXACT=1\r\n");
    for (i = 0; i < 3; ++i) {
        if (!copy(providers[i].source, providers[i].destination, providers[i].sha256,
                  providers[i].bytes, 0, &owned[i])) goto failed;
        ++copies_completed;
    }
    if (!exact(CORE_DESTINATION, CORE_OLD_SHA, CORE_OLD_BYTES) || io_failed) goto failed;
    if (!copy(CORE_SOURCE, CORE_DESTINATION, CORE_NEW_SHA, CORE_NEW_BYTES, 1, NULL)) goto failed;
    if (!verify()) goto failed;
    text("NEXT_REQUIRED=COLD_REBOOT_BEFORE_VLC_EXECUTION\r\n");
    if (io_failed || !FlushFileBuffers(report)) goto failed;
    code = 0; goto done;
failed:
    text("INSTALL_FAILED=1\r\n");
    code = rollback() ? 5 : 7;
done:
    number("BACKUP_CREATED_BY_HELPER=", backup_created);
    number("PROVIDER_COPIES_COMPLETED=", copies_completed); number("SELECTED_EXIT=", code);
    text(code ? "STATUS=FAIL\r\n" : "STATUS=SCOPED_PREREQUISITE_INSTALL_PASS\r\n");
    if (!FlushFileBuffers(report)) io_failed = 1;
    if (!CloseHandle(report)) io_failed = 1;
    ExitProcess(io_failed ? 31 : code);
}
