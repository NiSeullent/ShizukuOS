/* SPDX-License-Identifier: GPL-2.0-only
 * Node/libuv scans use native directory enumeration before skipping '.' and
 * '..'. These entries must identify real directory objects, not fake files.
 */
#include "k32test.h"
typedef LONG NTSTATUS;
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } N_USTR;
typedef struct { ULONG_PTR Status, Information; } N_IOSB;
NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE, HANDLE, PVOID, PVOID, N_IOSB *, PVOID, ULONG, ULONG, BOOLEAN, N_USTR *, BOOLEAN);
#define ST_END ((NTSTATUS)0x80000006)
#define ST_MISSING ((NTSTATUS)0xc000000f)

static BOOL name_is(const BYTE *entry, unsigned name_offset, unsigned length_offset, const WCHAR *name)
{
    DWORD length;
    memcpy(&length, entry + length_offset, sizeof length);
    return length == (DWORD)k32t_wlen(name) * 2 && !memcmp(entry + name_offset, name, length);
}

static HANDLE open_directory(const WCHAR *path)
{
    return CreateFileW(path, FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | SYNCHRONIZE,
                       FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
}

int main(void)
{
    static const WCHAR directory[] = L"C:\\SHZ\\TESTS\\LEGDIR";
    HANDLE h;
    BYTE buffer[1024] __attribute__((aligned(8)));
    N_IOSB io;
    N_USTR pattern;
    NTSTATUS status;
    DWORD next;
    BY_HANDLE_FILE_INFORMATION self, parent;
    ULONGLONG actual_id, expected_id;
    memset(&self, 0, sizeof self);
    memset(&parent, 0, sizeof parent);
    CHECK(CreateDirectoryW(directory, NULL), "create an actual empty user directory");
    h = open_directory(directory);
    CHECK(h != INVALID_HANDLE_VALUE, "open real empty directory for native enumeration");
    if (h == INVALID_HANDLE_VALUE) return 1;
    memset(&io, 0, sizeof io);
    status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buffer, sizeof buffer, 1, FALSE, NULL, TRUE);
    CHECK(status == 0 && io.Status == 0 && io.Information > 0 && io.Information <= sizeof buffer,
          "libuv's exact first native scan succeeds for an actual empty directory");
    if (status == 0) {
        memcpy(&next, buffer, sizeof next);
        CHECK(name_is(buffer, 64, 60, L".") && *(DWORD *)(buffer + 56) & FILE_ATTRIBUTE_DIRECTORY,
              "first returned entry names the actual directory itself");
        CHECK(next >= 64 && next < io.Information && name_is(buffer + next, 64, 60, L"..") &&
              *(DWORD *)(buffer + next + 56) & FILE_ATTRIBUTE_DIRECTORY && *(DWORD *)(buffer + next) == 0,
              "second returned entry names the actual parent and ends the chain");
    }
    status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buffer, sizeof buffer, 1, FALSE, NULL, FALSE);
    CHECK(status == ST_END && (NTSTATUS)io.Status == ST_END && io.Information == 0,
          "empty scan ends normally after the two hierarchy entries");
    /* Windows captures a pattern on each handle's first query. Each distinct
     * pattern below therefore starts on a newly opened real handle. */
    CHECK(CloseHandle(h) && (h = open_directory(directory)) != INVALID_HANDLE_VALUE, "open fresh handle for self-name pattern");
    pattern.Buffer = L"."; pattern.Length = 2; pattern.MaximumLength = 4;
    status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buffer, sizeof buffer, 37, TRUE, &pattern, TRUE);
    CHECK(status == 0 && name_is(buffer, 104, 60, L"."), "filtered native restart enumerates the self entry");
    CHECK(GetFileInformationByHandle(h, &self), "query the real directory's independent identity");
    if (status == 0) {
        memcpy(&actual_id, buffer + 96, sizeof actual_id);
        expected_id = ((ULONGLONG)self.nFileIndexHigh << 32) | self.nFileIndexLow;
        CHECK(actual_id == expected_id, "native self entry has the actual opened directory file ID");
    }
    CHECK(CloseHandle(h) && (h = open_directory(directory)) != INVALID_HANDLE_VALUE, "open fresh handle for parent-name pattern");
    pattern.Buffer = L".."; pattern.Length = 4; pattern.MaximumLength = 6;
    status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buffer, sizeof buffer, 37, TRUE, &pattern, TRUE);
    CHECK(status == 0 && name_is(buffer, 104, 60, L".."), "filtered native restart enumerates the parent entry");
    {
        HANDLE p = CreateFileW(L"C:\\SHZ\\TESTS", FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
        CHECK(p != INVALID_HANDLE_VALUE && GetFileInformationByHandle(p, &parent), "open and query the actual parent independently");
        if (p != INVALID_HANDLE_VALUE) {
            if (status == 0) {
                memcpy(&actual_id, buffer + 96, sizeof actual_id);
                expected_id = ((ULONGLONG)parent.nFileIndexHigh << 32) | parent.nFileIndexLow;
                CHECK(actual_id == expected_id, "native parent entry has its independently queried actual file ID");
            }
            CloseHandle(p);
        }
    }
    CHECK(CloseHandle(h) && (h = open_directory(directory)) != INVALID_HANDLE_VALUE, "open fresh handle for missing-name pattern");
    pattern.Buffer = L"missing*"; pattern.Length = 16; pattern.MaximumLength = 18;
    status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buffer, sizeof buffer, 12, FALSE, &pattern, TRUE);
    CHECK(status == ST_MISSING, "an explicit unmatched filename pattern retains first-query missing-file semantics");
    status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buffer, sizeof buffer, 12, FALSE, NULL, FALSE);
    CHECK(status == ST_END, "subsequent unmatched-pattern query reports enumeration completion");
    CHECK(CloseHandle(h) && (h = open_directory(directory)) != INVALID_HANDLE_VALUE, "open fresh handle for wildcard cursor checks");
    pattern.Buffer = L"*"; pattern.Length = 2; pattern.MaximumLength = 4;
    status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buffer, sizeof buffer, 12, TRUE, &pattern, TRUE);
    CHECK(status == 0 && name_is(buffer, 12, 8, L"."), "single-entry wildcard restart begins with self");
    status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buffer, sizeof buffer, 12, TRUE, NULL, FALSE);
    CHECK(status == 0 && name_is(buffer, 12, 8, L".."), "single-entry continuation preserves the actual parent cursor");
    status = NtQueryDirectoryFile(h, NULL, NULL, NULL, &io, buffer, sizeof buffer, 12, TRUE, NULL, FALSE);
    CHECK(status == ST_END, "single-entry enumeration completes without repeating hierarchy entries");
    CHECK(CloseHandle(h) && RemoveDirectoryW(directory), "release actual directory handle and remove the empty directory");
    return k32t_finish("T_LEGCORD_DIRECTORY");
}
