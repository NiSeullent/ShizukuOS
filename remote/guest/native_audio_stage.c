/* SPDX-License-Identifier: GPL-2.0-only
 * Copy only a pinned licensed SB16 file set into a fresh private source folder.
 * No Windows-system, registry, INF-directory or existing-file replacement.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "sha256.h"
#include "audio_stage_pins.h"

static HANDLE report = INVALID_HANDLE_VALUE;
static BYTE block[4096];
static unsigned owned[AUDIO_FILE_COUNT];
static int io_failed, directory_owned;
static unsigned length(const char *s) { unsigned n = 0; while (s[n]) ++n; return n; }
static int same(const char *a, const char *b) { while (*a && *a == *b) { ++a; ++b; } return *a == *b; }
static void text(const char *s) {
    DWORD done, n = length(s);
    if (!WriteFile(report, s, n, &done, NULL) || done != n) io_failed = 1;
}
static void number(const char *key, DWORD value) {
    char data[9]; unsigned i;
    for (i = 0; i < 8; ++i) data[i] = "0123456789ABCDEF"[(value >> (28 - i * 4)) & 15];
    data[8] = 0; text(key); text(data); text("\r\n");
}
static int absent(const char *path) {
    DWORD attributes = GetFileAttributesA(path), error;
    if (attributes != INVALID_FILE_ATTRIBUTES) return 0;
    error = GetLastError(); return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
}
static int exact(const char *path, const char *pin, DWORD bytes) {
    HANDLE file; DWORD count, total = 0; sha256_ctx hash; BYTE value[32]; char hex[65]; int good = 1;
    file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    sha256_init(&hash);
    for (;;) {
        if (!ReadFile(file, block, sizeof(block), &count, NULL)) { good = 0; break; }
        if (!count) break;
        if (total > bytes || count > bytes - total) { good = 0; break; }
        total += count; sha256_update(&hash, block, count);
    }
    if (!CloseHandle(file)) good = 0;
    sha256_final(&hash, value); sha256_hex(value, hex);
    return good && total == bytes && same(hex, pin);
}
static int copy_member(HANDLE bundle, unsigned index) {
    HANDLE file; DWORD remaining = audio_files[index].bytes, count, done; int good = 1;
    if (SetFilePointer(bundle, audio_files[index].offset, NULL, FILE_BEGIN) != audio_files[index].offset) return 0;
    file = CreateFileA(audio_files[index].path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return 0;
    owned[index] = 1;
    while (remaining) {
        DWORD next = remaining < sizeof(block) ? remaining : sizeof(block);
        if (!ReadFile(bundle, block, next, &count, NULL) || count != next ||
            !WriteFile(file, block, count, &done, NULL) || done != count) { good = 0; break; }
        remaining -= count;
    }
    if (!FlushFileBuffers(file)) good = 0;
    if (!CloseHandle(file)) good = 0;
    return good && remaining == 0 && exact(audio_files[index].path, audio_files[index].sha256, audio_files[index].bytes);
}
static int rollback(void) {
    unsigned i; int good = 1;
    for (i = 0; i < AUDIO_FILE_COUNT; ++i) {
        if (owned[i] && (!DeleteFileA(audio_files[i].path) || !absent(audio_files[i].path))) good = 0;
    }
    if (directory_owned && (!RemoveDirectoryA(AUDIO_SOURCE_DIRECTORY) || !absent(AUDIO_SOURCE_DIRECTORY))) good = 0;
    number("OWNED_SOURCE_COPY_ROLLBACK_VERIFIED=", good); return good;
}
void WINAPI entry(void) {
    HANDLE bundle = INVALID_HANDLE_VALUE;
    unsigned i, completed = 0; DWORD code = 3; OSVERSIONINFOA version = {0};
    report = CreateFileA("C:\\VXDLAB\\AUDSTG.LOG", GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (report == INVALID_HANDLE_VALUE) ExitProcess(20);
    text("SCOPE=PINNED_LICENSED_SB16_SOURCE_COPY_ONLY\r\nNO_SYSTEM_REGISTRY_OR_DRIVER_INSTALL=1\r\n");
    version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version) || version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS ||
        version.dwMajorVersion != 4 || version.dwMinorVersion != 10) goto done;
    if (!absent(AUDIO_SOURCE_DIRECTORY)) { text("SOURCE_DIRECTORY_ALREADY_PRESENT_OR_UNREADABLE=1\r\n"); goto done; }
    if (!exact(AUDIO_BUNDLE_PATH, AUDIO_BUNDLE_SHA, AUDIO_BUNDLE_BYTES)) { text("PINNED_SOURCE_BUNDLE_VERIFICATION_FAILED=1\r\n"); goto done; }
    text("WHOLE_BUNDLE_SHA_AND_EXACT_LENGTH_VERIFIED=1\r\n");
    if (io_failed || !FlushFileBuffers(report)) { io_failed = 1; goto done; }
    bundle = CreateFileA(AUDIO_BUNDLE_PATH, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (bundle == INVALID_HANDLE_VALUE) goto done;
    if (!CreateDirectoryA(AUDIO_SOURCE_DIRECTORY, NULL)) goto done;
    directory_owned = 1;
    for (i = 0; i < AUDIO_FILE_COUNT; ++i) {
        if (!copy_member(bundle, i)) goto done;
        ++completed; text("EXACT_SOURCE_FILE_VERIFIED="); text(audio_files[i].path); text("\r\n");
    }
    if (!CloseHandle(bundle)) { bundle = INVALID_HANDLE_VALUE; goto done; }
    bundle = INVALID_HANDLE_VALUE;
    if (!io_failed) code = 0;
done:
    if (bundle != INVALID_HANDLE_VALUE && !CloseHandle(bundle)) code = 3;
    if ((code || io_failed) && directory_owned) rollback();
    number("ACTUAL_SOURCE_FILES_COPIED=", completed); number("SELECTED_STAGE_EXIT=", code);
    text(code || io_failed ? "STATUS=LICENSED_SB16_SOURCE_COPY_FAIL\r\n" : "STATUS=EXACT_LICENSED_SOURCE_COPY_ONLY\r\n");
    text("MANUAL_NATIVE_DRIVER_INSTALL_AND_ACTUAL_OS_EXIT_REQUIRE_SEPARATE_PROOF=1\r\n");
    if (!FlushFileBuffers(report)) io_failed = 1;
    if (!CloseHandle(report)) io_failed = 1;
    ExitProcess(io_failed ? 31 : code);
}
