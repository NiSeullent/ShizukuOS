/* GUI probe of the exact filesystem path backend staged for genuine WTF/JSC.
 * Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
 * This measures file APIs; it does not execute JavaScript or render documents.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "src/core_FileSystemWin9x.h"

static int valid_nonce(const char* value)
{
    size_t count = strlen(value);
    return count && count <= 80
        && strspn(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") == count;
}

static int read_provenance(char values[4][65])
{
    FILE* file = fopen("C:\\GOPLAB\\FSPATH.DAT", "rb");
    char line[68];
    unsigned i;
    int valid = file != NULL;
    if (!file)
        return 0;
    for (i = 0; i < 4 && valid; ++i) {
        valid = fgets(line, sizeof(line), file) != NULL;
        if (!valid)
            break;
        line[strcspn(line, "\r\n")] = 0;
        valid = strlen(line) == 64 && strspn(line, "0123456789abcdef") == 64;
        if (valid)
            memcpy(values[i], line, 65);
    }
    valid = valid && fgetc(file) == EOF && !ferror(file);
    fclose(file);
    return valid;
}

static int absent(const char* path)
{
    DWORD attributes, error;
    SetLastError(0);
    attributes = GetFileAttributesA(path);
    error = GetLastError();
    return attributes == INVALID_FILE_ATTRIBUTES && error == ERROR_FILE_NOT_FOUND;
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR commandLine, int show)
{
    const WCHAR originalName[] = L"C:\\GOPLAB\\FS9XW.TMP";
    const WCHAR portedName[] = L"C:\\GOPLAB\\FS9XA.TMP";
    const WCHAR invalidName[] = { 'C', ':', '\\', 'x', 0xd83d, 0xde80, '.', 't', 'm', 'p', 0 };
    const WCHAR embeddedNul[] = { 'C', ':', '\\', 'x', 0, 'y' };
    const unsigned char contents[] = { 'J', 'S', ':', 0xed, 0x95, 0x9c, 0xea, 0xb8, 0x80, '\n' };
    unsigned char readBack[sizeof(contents)];
    char encoded[MAX_PATH], rejected[MAX_PATH], hashes[4][65];
    OSVERSIONINFOA os;
    FILE* log;
    HANDLE original = INVALID_HANDLE_VALUE, ported = INVALID_HANDLE_VALUE, collision;
    DWORD originalError, writeCount = 0, readCount = 0;
    int code = 0, originalClosed = 0, originalDeleted = 0;
    int portedClosed = 0, portedDeleted = 0, converted = 0, exact = 0;
    int invalidRejected, nulRejected;
    (void)instance; (void)previous; (void)show;
    if (!valid_nonce(commandLine) || !read_provenance(hashes))
        return 10;
    log = fopen("C:\\GOPLAB\\FSPATH.LOG", "wb");
    if (!log)
        return 11;
    fprintf(log, "scope=actual-shared-WTF-JSC-Win9x-path-helper\r\nnonce=%s\r\n", commandLine);
    fprintf(log, "expected.source.sha256=%s\r\nexpected.header.sha256=%s\r\nexpected.binary.sha256=%s\r\nexpected.receipt.sha256=%s\r\n",
        hashes[0], hashes[1], hashes[2], hashes[3]);
    memset(&os, 0, sizeof(os));
    os.dwOSVersionInfoSize = sizeof(os);
    exact = GetVersionExA(&os) && os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS
        && os.dwMajorVersion == 4 && os.dwMinorVersion == 10 && (os.dwBuildNumber & 0xffff) == 2222;
    fprintf(log, "os.major=%lu\r\nos.minor=%lu\r\nos.build=%lu\r\nos.platform=%lu\r\nos.exact-target=%d\r\nacp=%u\r\n",
        os.dwMajorVersion, os.dwMinorVersion, os.dwBuildNumber & 0xffff, os.dwPlatformId, exact, GetACP());
    if (!exact) { code = 12; goto finish; }
    if (!absent("C:\\GOPLAB\\FS9XW.TMP") || !absent("C:\\GOPLAB\\FS9XA.TMP")) {
        code = 13; goto finish;
    }
    SetLastError(0);
    original = CreateFileW(originalName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    originalError = GetLastError();
    fprintf(log, "original.CreateFileW.created=%d\r\noriginal.CreateFileW.error=%lu\r\n",
        original != INVALID_HANDLE_VALUE, originalError);
    if (original != INVALID_HANDLE_VALUE) {
        originalClosed = CloseHandle(original);
        if (originalClosed)
            original = INVALID_HANDLE_VALUE;
        originalDeleted = originalClosed && DeleteFileA("C:\\GOPLAB\\FS9XW.TMP");
        if (!originalClosed || !originalDeleted) { code = 14; goto finish; }
    }
    converted = iewkWin9xPathFromWide(portedName, sizeof(portedName) / sizeof(WCHAR) - 1, encoded, sizeof(encoded));
    fprintf(log, "path.ascii.converted=%d\r\npath.ascii.exact=%d\r\n", converted,
        converted && !strcmp(encoded, "C:\\GOPLAB\\FS9XA.TMP"));
    if (!converted || strcmp(encoded, "C:\\GOPLAB\\FS9XA.TMP")) { code = 15; goto finish; }
    invalidRejected = !iewkWin9xPathFromWide(invalidName, sizeof(invalidName) / sizeof(WCHAR) - 1, rejected, sizeof(rejected))
        && GetLastError() == ERROR_NO_UNICODE_TRANSLATION && !rejected[0];
    nulRejected = !iewkWin9xPathFromWide(embeddedNul, sizeof(embeddedNul) / sizeof(WCHAR), rejected, sizeof(rejected))
        && GetLastError() == ERROR_INVALID_NAME && !rejected[0];
    fprintf(log, "path.unrepresentable.rejected=%d\r\npath.embedded-nul.rejected=%d\r\n", invalidRejected, nulRejected);
    if (!invalidRejected || !nulRejected) { code = 16; goto finish; }
    SetLastError(0);
    ported = CreateFileA(encoded, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    fprintf(log, "ported.CreateFileA.created=%d\r\nported.CreateFileA.error=%lu\r\n",
        ported != INVALID_HANDLE_VALUE, GetLastError());
    if (ported == INVALID_HANDLE_VALUE) { code = 17; goto finish; }
    if (!WriteFile(ported, contents, sizeof(contents), &writeCount, NULL)
        || writeCount != sizeof(contents) || SetFilePointer(ported, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER
        || !ReadFile(ported, readBack, sizeof(readBack), &readCount, NULL)
        || readCount != sizeof(contents) || memcmp(contents, readBack, sizeof(contents))) {
        code = 18; goto finish;
    }
    fprintf(log, "contents.utf8.exact=1\r\ncontents.bytes=%lu\r\n", readCount);
    SetLastError(0);
    collision = CreateFileA(encoded, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    fprintf(log, "ported.create-new.collision=%d\r\nported.create-new.error=%lu\r\n",
        collision == INVALID_HANDLE_VALUE, GetLastError());
    if (collision != INVALID_HANDLE_VALUE) { CloseHandle(collision); code = 19; goto finish; }
finish:
    if (original != INVALID_HANDLE_VALUE) {
        originalClosed = CloseHandle(original);
        originalDeleted = originalClosed && DeleteFileA("C:\\GOPLAB\\FS9XW.TMP");
    }
    if (ported != INVALID_HANDLE_VALUE) {
        portedClosed = CloseHandle(ported);
        portedDeleted = portedClosed && DeleteFileA("C:\\GOPLAB\\FS9XA.TMP");
        if (!portedClosed || !portedDeleted)
            code = 20;
    }
    fprintf(log, "cleanup.original.closed=%d\r\ncleanup.original.deleted=%d\r\ncleanup.ported.closed=%d\r\ncleanup.ported.deleted=%d\r\n",
        originalClosed, originalDeleted, portedClosed, portedDeleted);
    fprintf(log, "engine.executed=0\r\nrendering.verified=0\r\nexit=%d\r\n", code);
    fclose(log);
    return code;
}
