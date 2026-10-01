/* Native Win98 source-lease semantics probe, independent of Node execution.
 * SPDX-License-Identifier: GPL-2.0-only
 * Uses only a new owned directory; no existing source file is written/deleted.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include "legcord_win9x_source_lease.h"
#ifndef LEG_NAPI_PROBE_SHA
#error "Require exact probe/source/header provenance from the bounded builder"
#endif

extern int __argc;
extern char **__argv;
static HANDLE log_handle = INVALID_HANDLE_VALUE;
static BOOL log_good = TRUE;

static void field(const char *name, DWORD value)
{
    char text[160]; DWORD bytes; int length;
    length = snprintf(text, sizeof(text), "%s=%lu\r\n", name, (unsigned long)value);
    if (length < 0 || length >= (int)sizeof(text) ||
            !WriteFile(log_handle, text, length, &bytes, NULL) || bytes != (DWORD)length)
        log_good = FALSE;
    if (!FlushFileBuffers(log_handle)) log_good = FALSE;
}

static void provenance(const char *name, const char *value)
{
    char text[160]; DWORD bytes; int length;
    length = snprintf(text, sizeof(text), "%s=%s\r\n", name, value);
    if (length < 0 || length >= (int)sizeof(text) ||
            !WriteFile(log_handle, text, length, &bytes, NULL) || bytes != (DWORD)length ||
            !FlushFileBuffers(log_handle)) log_good = FALSE;
}

static BOOL local_directory(const char *directory)
{
    size_t index, start = 3, length = strlen(directory);
    char root[4] = { directory[0], ':', '\\', 0 };
    UINT type;
    if (length < 4 || length > MAX_PATH - 20 ||
            !((directory[0] >= 'A' && directory[0] <= 'Z') ||
              (directory[0] >= 'a' && directory[0] <= 'z')) ||
            directory[1] != ':' || directory[2] != '\\') return FALSE;
    for (index = 3; index <= length; ++index) {
        unsigned char value = (unsigned char)directory[index];
        if (index < length && (value < 32 || value > 126 || strchr(":/*?\"<>|", value))) return FALSE;
        if (index == length || value == '\\') {
            if (index == start || directory[index - 1] == '.' || directory[index - 1] == ' ')
                return FALSE;
            start = index + 1;
        }
    }
    type = GetDriveTypeA(root);
    return type == DRIVE_FIXED || type == DRIVE_REMOVABLE ||
        type == DRIVE_CDROM || type == DRIVE_RAMDISK;
}

static BOOL create_owned_file(const char *path)
{
    DWORD bytes;
    HANDLE file = CreateFileA(path, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL result;
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    result = WriteFile(file, "legcord-native-lease\r\n", 22, &bytes, NULL) && bytes == 22;
    if (!CloseHandle(file)) result = FALSE;
    return result;
}

static BOOL can_write(const char *path)
{
    HANDLE file = CreateFileA(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) return FALSE;
    return CloseHandle(file);
}

static int probe(int argc, char **argv)
{
    OSVERSIONINFOA version = { 0 };
    char first[MAX_PATH], second[MAX_PATH], absent[MAX_PATH], log[MAX_PATH];
    LPCSTR paths[2]; legcord_source_lease *lease = NULL;
    BOOL ok = TRUE, cleaned = TRUE, created_first = FALSE, created_second = FALSE;
    BOOL held, blocked_write, blocked_delete, released_write, reacquired, invalid, partial, existing_writer;
    HANDLE writer;
    DWORD count, bytes; char nonce[140];
    if (argc != 3 || !argv[1][0] || strlen(argv[1]) > 80 || !local_directory(argv[2]) ||
            strspn(argv[1], "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != strlen(argv[1]) ||
            !(((argv[2][0] >= 'A' && argv[2][0] <= 'Z') || (argv[2][0] >= 'a' && argv[2][0] <= 'z')) &&
              argv[2][1] == ':' && argv[2][2] == '\\')) return 10;
    version.dwOSVersionInfoSize = sizeof(version);
    if (!GetVersionExA(&version) || version.dwPlatformId != VER_PLATFORM_WIN32_WINDOWS ||
            version.dwMajorVersion != 4 || version.dwMinorVersion != 10 ||
            LOWORD(version.dwBuildNumber) != 2222 || sizeof(void *) != 4) return 11;
    /* CREATE_NEW directory/log/files is fail-closed on preexisting artifacts. */
    if (!CreateDirectoryA(argv[2], NULL)) return 12;
    snprintf(first, sizeof(first), "%s\\LEASE0.TXT", argv[2]);
    snprintf(second, sizeof(second), "%s\\LEASE1.TXT", argv[2]);
    snprintf(absent, sizeof(absent), "%s\\ABSENT.TXT", argv[2]);
    snprintf(log, sizeof(log), "%s\\LEASE.LOG", argv[2]);
    log_handle = CreateFileA(log, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (log_handle == INVALID_HANDLE_VALUE) { RemoveDirectoryA(argv[2]); return 13; }
    count = snprintf(nonce, sizeof(nonce), "scope=actual-native-source-lease\r\nnonce=%s\r\n", argv[1]);
    if (!WriteFile(log_handle, nonce, count, &bytes, NULL) || bytes != count) log_good = FALSE;
    field("os.major", version.dwMajorVersion); field("os.minor", version.dwMinorVersion);
    field("os.build", LOWORD(version.dwBuildNumber));
    provenance("source.probe.sha256", LEG_NAPI_PROBE_SHA);
    provenance("source.lease.sha256", LEG_LEASE_SOURCE_SHA);
    provenance("source.header.sha256", LEG_LEASE_HEADER_SHA);
    created_first = create_owned_file(first); created_second = create_owned_file(second);
    if (!created_first || !created_second) { ok = FALSE; goto done; }
    paths[0] = first; paths[1] = second;
    writer = CreateFileA(first, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                         NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (writer == INVALID_HANDLE_VALUE) { ok = FALSE; goto done; }
    existing_writer = !legcord_win9x_AcquireSourceReadLeases(paths, 2, &lease) && !lease;
    if (lease) { legcord_win9x_ReleaseSourceReadLeases(lease); lease = NULL; }
    if (!CloseHandle(writer)) existing_writer = FALSE;
    field("existing.writer-acquisition-rejected", existing_writer);
    held = legcord_win9x_AcquireSourceReadLeases(paths, 2, &lease);
    if (!held || !lease) { ok = FALSE; goto done; }
    blocked_write = !can_write(first);
    blocked_delete = !DeleteFileA(first);
    field("held.writer-blocked", blocked_write); field("held.delete-blocked", blocked_delete);
    legcord_win9x_ReleaseSourceReadLeases(lease); lease = NULL;
    released_write = can_write(first);
    reacquired = legcord_win9x_AcquireSourceReadLeases(paths, 2, &lease);
    field("release.writer-opened", released_write); field("release.reacquired", reacquired);
    if (lease) { legcord_win9x_ReleaseSourceReadLeases(lease); lease = NULL; }
    paths[1] = "relative.txt";
    invalid = !legcord_win9x_AcquireSourceReadLeases(paths, 2, &lease) && !lease && can_write(first);
    if (lease) { legcord_win9x_ReleaseSourceReadLeases(lease); lease = NULL; }
    paths[1] = absent;
    partial = !legcord_win9x_AcquireSourceReadLeases(paths, 2, &lease) && !lease && can_write(first);
    field("invalid.partial-handle-closed", invalid); field("missing.partial-handle-closed", partial);
    ok = existing_writer && blocked_write && blocked_delete && released_write && reacquired && invalid && partial;
done:
    if (lease) legcord_win9x_ReleaseSourceReadLeases(lease);
    if (created_first && !DeleteFileA(first)) cleaned = FALSE;
    if (created_second && !DeleteFileA(second)) cleaned = FALSE;
    ok = ok && cleaned;
    field("owned.fixture-files-cleaned", cleaned);
    field("exit", ok && log_good ? 0 : 20);
    if (!CloseHandle(log_handle)) ok = FALSE;
    /* Preserve the fresh bounded returned log and its owned directory. */
    return ok && log_good ? 0 : 20;
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE previous, LPSTR command, int show)
{
    (void)instance; (void)previous; (void)command; (void)show;
    return probe(__argc, __argv);
}
