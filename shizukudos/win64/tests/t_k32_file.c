/* SPDX-License-Identifier: GPL-2.0-only
 * kernel32 files: directory enumeration (FindFirstFileEx and wildcards), file information by handle and by name, times and attributes,
 * SetFileInformationByHandle, ReplaceFile, byte-range locks, overlapped results, drives and volumes, path names, temporary files.
 * Expected values follow the Win32 documentation or are computed independently (FILETIME constants from the calendar). */
#define _WIN32_WINNT 0x0A00
#include "k32test.h"

#define D L"C:\\T_K32_FILE"
#define DA "C:\\T_K32_FILE"

/* FILETIME (100 ns since 1601) of 2000-01-01, 2005-01-01 and 2010-01-01 00:00:00 UTC: (days since 1601-01-01) * 86400 * 10^7. */
#define LONGLEN 39                                     /* wcslen(L"C:\\T_K32_FILE\\LongDirName\\MixedCase.Txt") */
#define FT_2000 125911584000000000ULL
#define FT_2005 127490112000000000ULL
#define FT_2010 129067776000000000ULL

static ULONGLONG ftv(FILETIME f) { return ((ULONGLONG)f.dwHighDateTime << 32) | f.dwLowDateTime; }
static FILETIME mkft(ULONGLONG v) { FILETIME f; f.dwLowDateTime = (DWORD)v; f.dwHighDateTime = (DWORD)(v >> 32); return f; }
static ULONGLONG now_ft(void) { FILETIME f; GetSystemTimeAsFileTime(&f); return ftv(f); }
static int near_now(ULONGLONG t) { const ULONGLONG n = now_ft(); return (t > n ? t - n : n - t) < 120ULL * 10000000ULL; }     /* within two minutes */

static int wsub(const WCHAR *s, const WCHAR *needle)     /* needle is a prefix of s (exact case) */
{
    while (*needle && *s == *needle) { ++s; ++needle; }
    return *needle == 0;
}
static int wends(const WCHAR *s, const WCHAR *tail)
{
    const int a = k32t_wlen(s), b = k32t_wlen(tail);
    return a >= b && k32t_weq(s + a - b, tail);
}
static int wieq(const WCHAR *a, const WCHAR *b)          /* ASCII case-insensitive equality */
{
    for (;; ++a, ++b) {
        WCHAR x = *a, y = *b;
        if (x >= 'A' && x <= 'Z') x += 32;
        if (y >= 'A' && y <= 'Z') y += 32;
        if (x != y) return 0;
        if (!x) return 1;
    }
}

static BOOL put_file(const WCHAR *path, const void *data, DWORD n)
{
    DWORD put = 0;
    HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = n == 0 || (WriteFile(h, data, n, &put, NULL) && put == n);
    CloseHandle(h);
    return ok;
}

static DWORD get_file(const WCHAR *path, void *buf, DWORD cap)     /* bytes read, or 0xffffffff */
{
    DWORD got = 0;
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0xffffffffu;
    if (!ReadFile(h, buf, cap, &got, NULL)) got = 0xffffffffu;
    CloseHandle(h);
    return got;
}

static void delete_tree(const WCHAR *dir)
{
    WIN32_FIND_DATAW fd;
    WCHAR spec[300], p[300];
    HANDLE h;
    int n = k32t_wlen(dir), i;
    for (i = 0; i < n; ++i) spec[i] = dir[i];
    spec[n] = '\\'; spec[n + 1] = '*'; spec[n + 2] = 0;
    h = FindFirstFileW(spec, &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do {
            int m = 0, k;
            if (fd.cFileName[0] == '.' && (!fd.cFileName[1] || (fd.cFileName[1] == '.' && !fd.cFileName[2]))) continue;
            for (k = 0; k < n; ++k) p[m++] = dir[k];
            p[m++] = '\\';
            for (k = 0; fd.cFileName[k] && m < 299; ++k) p[m++] = fd.cFileName[k];
            p[m] = 0;
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) delete_tree(p);
            else { SetFileAttributesW(p, FILE_ATTRIBUTE_NORMAL); DeleteFileW(p); }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    SetFileAttributesW(dir, FILE_ATTRIBUTE_NORMAL);
    RemoveDirectoryW(dir);
}

typedef WCHAR name_t[64];
static int enum_names(const WCHAR *spec, name_t *out, int max, DWORD *last_err)
{
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW(spec, &fd);
    int n = 0, k;
    if (h == INVALID_HANDLE_VALUE) { if (last_err) *last_err = GetLastError(); return -1; }
    do {
        if (n < max) { for (k = 0; fd.cFileName[k] && k < 63; ++k) out[n][k] = fd.cFileName[k]; out[n][k] = 0; }
        ++n;
    } while (FindNextFileW(h, &fd));
    if (last_err) *last_err = GetLastError();
    FindClose(h);
    return n;
}
static int has(name_t *names, int n, const WCHAR *w) { int i; for (i = 0; i < n; ++i) if (k32t_weq(names[i], w)) return 1; return 0; }

/* ================================================================ directory enumeration */
static void test_find(void)
{
    static const WCHAR uni[] = { 0x00e9, 't', 0x00e9, 0x4e2d, 0xd83d, 0xde00, '.', 't', 'x', 't', 0 };     /* e-acute t e-acute, CJK, U+1F600 */
    name_t names[32];
    WIN32_FIND_DATAW fd;
    WIN32_FIND_DATAA fa;
    HANDLE h;
    int n, i;
    DWORD err;
    WCHAR path[300];

    CreateDirectoryW(D L"\\sub", NULL);
    put_file(D L"\\alpha.txt", "hello", 5);
    put_file(D L"\\beta.txt", "beta!", 5);
    put_file(D L"\\gamma.dat", "g", 1);
    put_file(D L"\\noext", "n", 1);
    put_file(D L"\\Mixed.CASE", "", 0);
    put_file(D L"\\file.tar.gz", "z", 1);
    put_file(D L"\\sub\\inner.txt", "in", 2);
    for (i = 0; i < 300; ++i) path[i] = 0;
    { int k = 0; const WCHAR *d = D L"\\"; while (*d) path[k++] = *d++; for (i = 0; uni[i]; ++i) path[k + i] = uni[i]; }
    CHECK(put_file(path, "u", 1), "a file with non-ASCII and supplementary-plane characters in its name can be created");

    n = enum_names(D L"\\*", names, 32, &err);
    CHECKV(n == 10, "FindFirstFile(dir\\*) lists six files, the directory, the non-ASCII file, '.' and '..': ten names", "count %d", n);
    CHECK(err == ERROR_NO_MORE_FILES, "FindNextFile after the last entry fails with ERROR_NO_MORE_FILES");
    CHECK(has(names, n, L".") && has(names, n, L".."), "a non-root directory lists '.' and '..'");
    CHECK(has(names, n, L"alpha.txt") && has(names, n, L"beta.txt") && has(names, n, L"gamma.dat") && has(names, n, L"noext"),
          "the created files are listed");
    CHECK(has(names, n, L"sub") && has(names, n, L"Mixed.CASE") && has(names, n, L"file.tar.gz"), "the directory and mixed-case names are listed with stored case");
    CHECK(has(names, n, uni), "the non-ASCII name comes back exactly as created (UTF-16 with a surrogate pair)");

    n = enum_names(D L"\\*.txt", names, 32, &err);
    CHECKV(n == 3 && has(names, n, L"alpha.txt") && has(names, n, L"beta.txt") && has(names, n, uni),
           "*.txt matches alpha.txt, beta.txt and the non-ASCII .txt file, nothing else", "n=%d", n);
    n = enum_names(D L"\\*.*", names, 32, 0);
    CHECKV(n == 10, "*.* matches every name including those without an extension", "n=%d", n);
    CHECK(has(names, n, L"noext"), "*.* matches noext");
    n = enum_names(D L"\\a*", names, 32, 0);
    CHECK(n == 1 && has(names, n, L"alpha.txt"), "a* matches alpha.txt only");
    n = enum_names(D L"\\ALPHA.TXT", names, 32, 0);
    CHECKV(n == 1 && has(names, n, L"alpha.txt"), "matching is case-insensitive and reports the stored name", "n=%d", n);
    n = enum_names(D L"\\?eta.txt", names, 32, 0);
    CHECK(n == 1 && has(names, n, L"beta.txt"), "? matches exactly one character");
    n = enum_names(D L"\\??eta.txt", names, 32, &err);
    CHECK(n == -1 && err == ERROR_FILE_NOT_FOUND, "?? does not match a name with one character fewer");
    n = enum_names(D L"\\file.*", names, 32, 0);
    CHECK(n == 1 && has(names, n, L"file.tar.gz"), "file.* matches file.tar.gz");
    n = enum_names(D L"\\*.gz", names, 32, 0);
    CHECK(n == 1 && has(names, n, L"file.tar.gz"), "*.gz matches the last extension");
    n = enum_names(D L"\\noext.*", names, 32, 0);
    CHECKV(n == 1 && has(names, n, L"noext"), "name.* also matches the name without an extension (DOS rule)", "n=%d", n);
    n = enum_names(D L"\\*.", names, 32, 0);
    CHECKV(n >= 1 && has(names, n, L"noext") && !has(names, n, L"alpha.txt"), "*. matches names without an extension only", "n=%d", n);
    n = enum_names(D L"\\*.zzz", names, 32, &err);
    CHECK(n == -1 && err == ERROR_FILE_NOT_FOUND, "no match: INVALID_HANDLE_VALUE with ERROR_FILE_NOT_FOUND");
    n = enum_names(D L"\\nope\\*", names, 32, &err);
    CHECK(n == -1 && err == ERROR_PATH_NOT_FOUND, "a missing directory gives ERROR_PATH_NOT_FOUND");
    h = FindFirstFileW(L"", &fd);
    CHECK(h == INVALID_HANDLE_VALUE, "an empty search string fails");
    CHECK_ERR(ERROR_PATH_NOT_FOUND, "an empty search string sets ERROR_PATH_NOT_FOUND");

    h = FindFirstFileW(D L"\\alpha.txt", &fd);
    CHECK(h != INVALID_HANDLE_VALUE, "FindFirstFile on a plain file name");
    if (h != INVALID_HANDLE_VALUE) {
        CHECK(fd.nFileSizeLow == 5 && fd.nFileSizeHigh == 0, "the size in WIN32_FIND_DATA is 5");
        CHECK(!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY), "a file has no DIRECTORY attribute");
        CHECK(near_now(ftv(fd.ftLastWriteTime)), "the last write time of a fresh file is about now");
        CHECK(!FindNextFileW(h, &fd) && GetLastError() == ERROR_NO_MORE_FILES, "there is no second entry");
        CHECK(FindClose(h), "FindClose succeeds");
        SetLastError(0);
        CHECK_W(!FindClose(h) && GetLastError() == ERROR_INVALID_HANDLE, "FindClose on a closed search handle fails with ERROR_INVALID_HANDLE");
    }
    h = FindFirstFileW(D L"\\sub", &fd);
    CHECK(h != INVALID_HANDLE_VALUE && (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && k32t_weq(fd.cFileName, L"sub"),
          "FindFirstFile on a directory name (no wildcard) returns the directory itself");
    if (h != INVALID_HANDLE_VALUE) FindClose(h);

    h = FindFirstFileExW(D L"\\*", FindExInfoBasic, &fd, FindExSearchLimitToDirectories, NULL, 0);
    CHECK(h != INVALID_HANDLE_VALUE, "FindFirstFileEx(FindExInfoBasic, FindExSearchLimitToDirectories)");
    if (h != INVALID_HANDLE_VALUE) {
        int seen_sub = 0;
        do { if (k32t_weq(fd.cFileName, L"sub")) seen_sub = 1; } while (FindNextFileW(h, &fd));
        CHECK(seen_sub, "the directory is found by the directories-only search");
        FindClose(h);
    }
    h = FindFirstFileExW(D L"\\ALPHA.TXT", FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, FIND_FIRST_EX_CASE_SENSITIVE);
    CHECK_W(h == INVALID_HANDLE_VALUE, "FIND_FIRST_EX_CASE_SENSITIVE: a different-case name no longer matches");
    if (h != INVALID_HANDLE_VALUE) FindClose(h);
    h = FindFirstFileExW(D L"\\alpha.txt", FindExInfoStandard, &fd, FindExSearchNameMatch, NULL, FIND_FIRST_EX_CASE_SENSITIVE);
    CHECK(h != INVALID_HANDLE_VALUE, "FIND_FIRST_EX_CASE_SENSITIVE: the same-case name matches");
    if (h != INVALID_HANDLE_VALUE) FindClose(h);
    h = FindFirstFileExW(D L"\\*", (FINDEX_INFO_LEVELS)9, &fd, FindExSearchNameMatch, NULL, 0);
    CHECK(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_INVALID_PARAMETER, "an invalid info level gives ERROR_INVALID_PARAMETER");

    n = enum_names(L"C:\\*", names, 32, 0);
    CHECKV(n >= 1 && !has(names, n, L".") && !has(names, n, L".."), "the volume root does not list '.' and '..'", "n=%d", n);
    CHECK(has(names, n, L"T_K32_FILE"), "the root lists the test directory");

    h = FindFirstFileA(DA "\\alpha.txt", &fa);
    CHECK(h != INVALID_HANDLE_VALUE && fa.nFileSizeLow == 5 && fa.cFileName[0] == 'a' && fa.cFileName[8] == 't' && fa.cFileName[9] == 0,
          "FindFirstFileA returns the ANSI name");
    if (h != INVALID_HANDLE_VALUE) { CHECK(!FindNextFileA(h, &fa), "FindNextFileA at the end fails"); FindClose(h); }
}

/* ================================================================ info by handle, times, attributes */
static void test_handle_info(void)
{
    BY_HANDLE_FILE_INFORMATION bi, bi2, bd;
    FILE_BASIC_INFO fb;
    FILE_STANDARD_INFO fs;
    FILE_ATTRIBUTE_TAG_INFO ft;
    FILE_ID_INFO fid;
    BYTE nbuf[600];
    FILETIME c, a, w, c2, a2, w2;
    unsigned char data[1024], back[2100];
    HANDLE h, h2, hd;
    DWORD put, got, i;
    LARGE_INTEGER pos;

    for (i = 0; i < sizeof data; ++i) data[i] = (unsigned char)(i * 7 + 3);
    h = CreateFileW(D L"\\info.bin", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h != INVALID_HANDLE_VALUE, "create info.bin");
    CHECK(WriteFile(h, data, 1000, &put, NULL) && put == 1000, "write 1000 bytes");
    CHECK(GetFileInformationByHandle(h, &bi), "GetFileInformationByHandle");
    CHECK(bi.nFileSizeHigh == 0 && bi.nFileSizeLow == 1000, "the file size is 1000");
    CHECK(bi.nNumberOfLinks == 1, "a plain file has one link");
    CHECK(!(bi.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY), "not a directory");
    CHECK(bi.dwVolumeSerialNumber != 0, "the volume serial number is not zero");
    CHECK(bi.nFileIndexLow != 0 || bi.nFileIndexHigh != 0, "the file index is not zero");
    CHECK(near_now(ftv(bi.ftLastWriteTime)), "the last write time is about now");
    CHECK(near_now(ftv(bi.ftCreationTime)), "the creation time is about now");
    CHECKV(ftv(bi.ftCreationTime) <= ftv(bi.ftLastWriteTime) + 10000000ULL, "creation is not after the last write", "%llu %llu",
           (unsigned long long)ftv(bi.ftCreationTime), (unsigned long long)ftv(bi.ftLastWriteTime));
    CHECK(GetFileSize(h, NULL) == 1000, "GetFileSize agrees");

    h2 = CreateFileW(D L"\\info.bin", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(h2 != INVALID_HANDLE_VALUE && GetFileInformationByHandle(h2, &bi2), "a second handle to the same file");
    CHECK(bi2.nFileIndexLow == bi.nFileIndexLow && bi2.nFileIndexHigh == bi.nFileIndexHigh && bi2.dwVolumeSerialNumber == bi.dwVolumeSerialNumber,
          "both handles report the same file index and volume serial");
    {
        HANDLE ho = CreateFileW(D L"\\alpha.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        BY_HANDLE_FILE_INFORMATION bo;
        CHECK(ho != INVALID_HANDLE_VALUE && GetFileInformationByHandle(ho, &bo), "another file");
        CHECK(bo.nFileIndexLow != bi.nFileIndexLow || bo.nFileIndexHigh != bi.nFileIndexHigh, "different files have different file indices");
        CHECK(bo.dwVolumeSerialNumber == bi.dwVolumeSerialNumber, "files on the same volume share its serial number");
        if (ho != INVALID_HANDLE_VALUE) CloseHandle(ho);
    }
    hd = CreateFileW(D, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    CHECK(hd != INVALID_HANDLE_VALUE, "open a directory with FILE_FLAG_BACKUP_SEMANTICS");
    CHECK(GetFileInformationByHandle(hd, &bd) && (bd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY), "a directory handle reports FILE_ATTRIBUTE_DIRECTORY");
    CHECK(bd.nNumberOfLinks >= 1, "a directory has at least one link");
    CHECK(GetFileType(hd) == FILE_TYPE_DISK && GetFileType(h) == FILE_TYPE_DISK, "GetFileType is FILE_TYPE_DISK for files and directories");
    CloseHandle(hd);
    CHECK(GetFileInformationByHandle(INVALID_HANDLE_VALUE, &bi2) == FALSE, "GetFileInformationByHandle(INVALID_HANDLE_VALUE) fails");

    /* extend by appending, then check sizes again */
    pos.QuadPart = 0;
    CHECK(SetFilePointerEx(h, pos, NULL, FILE_END), "seek to the end");
    CHECK(WriteFile(h, data, 24, &put, NULL) && put == 24, "append 24 bytes");
    CHECK(GetFileInformationByHandle(h, &bi) && bi.nFileSizeLow == 1024, "the size is 1024 after the append");

    /* GetFileInformationByHandleEx */
    memset(&fb, 0xcc, sizeof fb);
    CHECK(GetFileInformationByHandleEx(h, FileBasicInfo, &fb, sizeof fb), "GetFileInformationByHandleEx(FileBasicInfo)");
    CHECK((ULONGLONG)fb.LastWriteTime.QuadPart == ftv(bi.ftLastWriteTime), "FileBasicInfo carries the same last write time");
    CHECK(fb.FileAttributes == bi.dwFileAttributes, "FileBasicInfo carries the same attributes");
    memset(&fs, 0xcc, sizeof fs);
    CHECK(GetFileInformationByHandleEx(h, FileStandardInfo, &fs, sizeof fs), "GetFileInformationByHandleEx(FileStandardInfo)");
    CHECK(fs.EndOfFile.QuadPart == 1024 && fs.AllocationSize.QuadPart >= 1024, "EndOfFile is 1024 and the allocation covers it");
    CHECK(fs.NumberOfLinks == 1 && fs.DeletePending == FALSE && fs.Directory == FALSE, "one link, no delete pending, not a directory");
    memset(nbuf, 0, sizeof nbuf);
    CHECK(GetFileInformationByHandleEx(h, FileNameInfo, nbuf, sizeof nbuf), "GetFileInformationByHandleEx(FileNameInfo)");
    {
        const FILE_NAME_INFO *ni = (const FILE_NAME_INFO *)nbuf;
        static const WCHAR expect[] = L"\\T_K32_FILE\\info.bin";
        CHECKV(ni->FileNameLength == sizeof expect - sizeof(WCHAR) && wieq(ni->FileName, expect) && ni->FileName[ni->FileNameLength / 2] == 0,
               "FileNameInfo is the volume-relative name", "len %u", (unsigned)ni->FileNameLength);
    }
    CHECK(!GetFileInformationByHandleEx(h, FileNameInfo, nbuf, 8) && (GetLastError() == ERROR_MORE_DATA || GetLastError() == ERROR_BAD_LENGTH),
          "a buffer too small for the name fails with ERROR_MORE_DATA");
    CHECK(GetFileInformationByHandleEx(h, FileAttributeTagInfo, &ft, sizeof ft) && ft.FileAttributes == bi.dwFileAttributes && ft.ReparseTag == 0,
          "FileAttributeTagInfo: attributes and no reparse tag");
    memset(&fid, 0, sizeof fid);
    CHECK_W(GetFileInformationByHandleEx(h, FileIdInfo, &fid, sizeof fid) && fid.VolumeSerialNumber == bi.dwVolumeSerialNumber &&
            *(const ULONGLONG *)fid.FileId.Identifier == (((ULONGLONG)bi.nFileIndexHigh << 32) | bi.nFileIndexLow),
            "FileIdInfo: volume serial and the file index in the low 64 bits");
    SetLastError(0);
    CHECK(!GetFileInformationByHandleEx(h, FileBasicInfo, &fb, 8) && GetLastError() == ERROR_BAD_LENGTH, "a buffer smaller than FILE_BASIC_INFO fails with ERROR_BAD_LENGTH");
    SetLastError(0);
    CHECK(!GetFileInformationByHandleEx(h, (FILE_INFO_BY_HANDLE_CLASS)999, &fb, sizeof fb) && GetLastError() == ERROR_INVALID_PARAMETER,
          "an out-of-range class fails with ERROR_INVALID_PARAMETER");

    /* times */
    CHECK(GetFileTime(h, &c, &a, &w) && ftv(w) == ftv(bi.ftLastWriteTime), "GetFileTime returns the last write time of the handle information");
    CHECK(GetFileTime(h, NULL, NULL, &w2) && ftv(w2) == ftv(w), "GetFileTime accepts NULL for times it should skip");
    CloseHandle(h2);
    CloseHandle(h);
    h = CreateFileW(D L"\\info.bin", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    c = mkft(FT_2000); a = mkft(FT_2005); w = mkft(FT_2010);
    CHECK(SetFileTime(h, &c, &a, &w), "SetFileTime sets creation, access and last write times");
    CHECK(GetFileTime(h, &c2, &a2, &w2), "GetFileTime reads them back");
    CHECKV_N(ftv(c2) == FT_2000, "the creation time is 2000-01-01", "%llu", (unsigned long long)ftv(c2));     /* Wine cannot store creation times */
    CHECKV(ftv(a2) == FT_2005, "the last access time is 2005-01-01", "%llu", (unsigned long long)ftv(a2));
    CHECKV(ftv(w2) == FT_2010, "the last write time is 2010-01-01", "%llu", (unsigned long long)ftv(w2));
    w = mkft(FT_2000);
    CHECK(SetFileTime(h, NULL, NULL, &w), "SetFileTime with NULL for creation and access");
    GetFileTime(h, &c2, &a2, &w2);
    CHECKV(ftv(w2) == FT_2000 && ftv(a2) == FT_2005, "only the last write time changed", "%llu %llu", (unsigned long long)ftv(w2), (unsigned long long)ftv(a2));
    CloseHandle(h);
    {
        WIN32_FILE_ATTRIBUTE_DATA ad;
        CHECK(GetFileAttributesExW(D L"\\info.bin", GetFileExInfoStandard, &ad) && ftv(ad.ftLastWriteTime) == FT_2000,
              "the times are visible by name as well");
    }
    h = CreateFileW(D L"\\info.bin", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    w = mkft(FT_2010);
    SetLastError(0);
    CHECK_N(!SetFileTime(h, NULL, NULL, &w), "SetFileTime on a handle without write access fails");
    CHECK_N(GetLastError() == ERROR_ACCESS_DENIED, "and reports ERROR_ACCESS_DENIED");
    CloseHandle(h);
    h = CreateFileW(D L"\\info.bin", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(WriteFile(h, "Z", 1, &put, NULL) && put == 1, "write through another handle");
    CloseHandle(h);
    {
        WIN32_FILE_ATTRIBUTE_DATA ad;
        CHECK(GetFileAttributesExW(D L"\\info.bin", GetFileExInfoStandard, &ad) && near_now(ftv(ad.ftLastWriteTime)),
              "a write brings the last write time back to now");
    }
    h = CreateFileW(D L"\\info.bin", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(ReadFile(h, back, 1, &got, NULL) && got == 1 && back[0] == 'Z', "the byte written is read back");
    CloseHandle(h);

    /* SetFileInformationByHandle */
    h = CreateFileW(D L"\\info.bin", GENERIC_READ | GENERIC_WRITE | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    {
        FILE_END_OF_FILE_INFO eof;
        FILE_ALLOCATION_INFO ai;
        eof.EndOfFile.QuadPart = 2048;
        CHECK(SetFileInformationByHandle(h, FileEndOfFileInfo, &eof, sizeof eof), "FileEndOfFileInfo extends the file to 2048");
        CHECK(GetFileSize(h, NULL) == 2048, "the size is 2048");
        pos.QuadPart = 1024;
        SetFilePointerEx(h, pos, NULL, FILE_BEGIN);
        memset(back, 0xee, sizeof back);
        CHECK(ReadFile(h, back, 1024, &got, NULL) && got == 1024, "read the extension");
        for (i = 0; i < 1024 && back[i] == 0; ++i) {}
        CHECK(i == 1024, "the extension reads as zeros");
        eof.EndOfFile.QuadPart = 10;
        CHECK(SetFileInformationByHandle(h, FileEndOfFileInfo, &eof, sizeof eof) && GetFileSize(h, NULL) == 10, "FileEndOfFileInfo shrinks the file to 10");
        ai.AllocationSize.QuadPart = 1 << 20;
        CHECK_W(SetFileInformationByHandle(h, FileAllocationInfo, &ai, sizeof ai), "FileAllocationInfo accepts a larger allocation");
        CHECK(GetFileSize(h, NULL) == 10, "and leaves the end of file alone");
    }
    {
        FILE_BASIC_INFO bset;
        DWORD at;
        memset(&bset, 0, sizeof bset);
        bset.FileAttributes = FILE_ATTRIBUTE_HIDDEN;
        CHECK(SetFileInformationByHandle(h, FileBasicInfo, &bset, sizeof bset), "FileBasicInfo sets the HIDDEN attribute");
        at = GetFileAttributesW(D L"\\info.bin");
        CHECK(at != INVALID_FILE_ATTRIBUTES && (at & FILE_ATTRIBUTE_HIDDEN), "the attribute is visible by name");
        bset.FileAttributes = FILE_ATTRIBUTE_NORMAL;
        CHECK(SetFileInformationByHandle(h, FileBasicInfo, &bset, sizeof bset), "FILE_ATTRIBUTE_NORMAL clears it again");
        at = GetFileAttributesW(D L"\\info.bin");
        CHECK(at != INVALID_FILE_ATTRIBUTES && !(at & FILE_ATTRIBUTE_HIDDEN), "HIDDEN is gone");
    }
    CloseHandle(h);

    /* delete-on-close through FileDispositionInfo, and rename */
    put_file(D L"\\dispose.tmp", "x", 1);
    h = CreateFileW(D L"\\dispose.tmp", GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    {
        FILE_DISPOSITION_INFO di;
        di.DeleteFile = TRUE;
        CHECK(SetFileInformationByHandle(h, FileDispositionInfo, &di, sizeof di), "FileDispositionInfo marks the file for deletion");
        CHECK_N(GetFileInformationByHandleEx(h, FileStandardInfo, &fs, sizeof fs) && fs.DeletePending, "DeletePending is reported");
    }
    CloseHandle(h);
    SetLastError(0);
    CHECK(GetFileAttributesW(D L"\\dispose.tmp") == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND, "the file is gone once the handle is closed");

    put_file(D L"\\ren1.tmp", "rename me", 9);
    put_file(D L"\\ren2.tmp", "in the way", 10);
    h = CreateFileW(D L"\\ren1.tmp", GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    {
        static const WCHAR newname[] = L"C:\\T_K32_FILE\\ren3.tmp", blocked[] = L"C:\\T_K32_FILE\\ren2.tmp";
        union { FILE_RENAME_INFO ri; BYTE raw[512]; } u;
        memset(&u, 0, sizeof u);
        u.ri.ReplaceIfExists = FALSE;
        u.ri.RootDirectory = NULL;
        u.ri.FileNameLength = sizeof blocked - sizeof(WCHAR);
        memcpy(u.ri.FileName, blocked, sizeof blocked);
        SetLastError(0);
        CHECK(!SetFileInformationByHandle(h, FileRenameInfo, &u, sizeof u), "FileRenameInfo onto an existing file without ReplaceIfExists fails");
        CHECK_ERR(ERROR_ALREADY_EXISTS, "with ERROR_ALREADY_EXISTS");
        u.ri.ReplaceIfExists = TRUE;
        CHECK(SetFileInformationByHandle(h, FileRenameInfo, &u, sizeof u), "with ReplaceIfExists the rename replaces the file");
        CloseHandle(h);
        CHECK(GetFileAttributesW(D L"\\ren1.tmp") == INVALID_FILE_ATTRIBUTES, "the old name is gone");
        CHECK(get_file(D L"\\ren2.tmp", back, sizeof back) == 9 && back[0] == 'r', "the new name holds the renamed file's content");
        h = CreateFileW(D L"\\ren2.tmp", GENERIC_READ | DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
        memset(&u, 0, sizeof u);
        u.ri.FileNameLength = sizeof newname - sizeof(WCHAR);
        memcpy(u.ri.FileName, newname, sizeof newname);
        CHECK(SetFileInformationByHandle(h, FileRenameInfo, &u, sizeof u), "rename to a free name");
        CloseHandle(h);
        CHECK(GetFileAttributesW(D L"\\ren3.tmp") != INVALID_FILE_ATTRIBUTES, "the new file exists");
    }
}

/* ================================================================ by name */
static void test_by_name(void)
{
    WIN32_FILE_ATTRIBUTE_DATA ad;
    DWORD at;
    HANDLE h;
    unsigned char buf[64];

    put_file(D L"\\attr.txt", "0123456789", 10);
    CHECK(GetFileAttributesExW(D L"\\attr.txt", GetFileExInfoStandard, &ad), "GetFileAttributesEx on a file");
    CHECK(ad.nFileSizeHigh == 0 && ad.nFileSizeLow == 10, "its size is 10");
    CHECK(!(ad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) && near_now(ftv(ad.ftLastWriteTime)), "a file, written just now");
    CHECK(GetFileAttributesExW(D L"\\sub", GetFileExInfoStandard, &ad) && (ad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY), "GetFileAttributesEx on a directory");
    SetLastError(0);
    CHECK(!GetFileAttributesExW(D L"\\missing.txt", GetFileExInfoStandard, &ad) && GetLastError() == ERROR_FILE_NOT_FOUND, "a missing file gives ERROR_FILE_NOT_FOUND");
    SetLastError(0);
    CHECK(!GetFileAttributesExW(D L"\\nodir\\x.txt", GetFileExInfoStandard, &ad) && GetLastError() == ERROR_PATH_NOT_FOUND, "a missing directory gives ERROR_PATH_NOT_FOUND");
    SetLastError(0);
    CHECK(!GetFileAttributesExW(D L"\\attr.txt", GetFileExMaxInfoLevel, &ad) && GetLastError() == ERROR_INVALID_PARAMETER, "an invalid info level gives ERROR_INVALID_PARAMETER");
    CHECK(GetFileAttributesExA(DA "\\attr.txt", GetFileExInfoStandard, &ad) && ad.nFileSizeLow == 10, "GetFileAttributesExA");
    SetLastError(0);
    CHECK(GetFileAttributesW(L"") == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_PATH_NOT_FOUND, "GetFileAttributes on an empty name gives ERROR_PATH_NOT_FOUND");

    /* SetFileAttributes and its consequences */
    CHECK(SetFileAttributesW(D L"\\attr.txt", FILE_ATTRIBUTE_READONLY), "SetFileAttributes(READONLY)");
    at = GetFileAttributesW(D L"\\attr.txt");
    CHECK(at != INVALID_FILE_ATTRIBUTES && (at & FILE_ATTRIBUTE_READONLY), "the READONLY attribute is set");
    SetLastError(0);
    CHECK_N(DeleteFileW(D L"\\attr.txt") == FALSE && GetLastError() == ERROR_ACCESS_DENIED, "a read-only file cannot be deleted (ERROR_ACCESS_DENIED)");
    SetLastError(0);
    h = CreateFileW(D L"\\attr.txt", GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);
    CHECK_N(h == INVALID_HANDLE_VALUE && GetLastError() == ERROR_ACCESS_DENIED, "a read-only file cannot be opened for writing");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    h = CreateFileW(D L"\\attr.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE, "but it can be opened for reading");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    CHECK(SetFileAttributesW(D L"\\attr.txt", FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_ARCHIVE), "SetFileAttributes(HIDDEN | ARCHIVE) replaces the set");
    at = GetFileAttributesW(D L"\\attr.txt");
    CHECK((at & FILE_ATTRIBUTE_HIDDEN) && (at & FILE_ATTRIBUTE_ARCHIVE) && !(at & FILE_ATTRIBUTE_READONLY), "HIDDEN and ARCHIVE set, READONLY cleared");
    CHECK(SetFileAttributesW(D L"\\attr.txt", FILE_ATTRIBUTE_NORMAL), "SetFileAttributes(NORMAL)");
    at = GetFileAttributesW(D L"\\attr.txt");
    CHECK(!(at & (FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)), "no attribute flags remain");
    CHECK(SetFileAttributesA(DA "\\attr.txt", FILE_ATTRIBUTE_TEMPORARY), "SetFileAttributesA(TEMPORARY)");
    CHECK_N((GetFileAttributesW(D L"\\attr.txt") & FILE_ATTRIBUTE_TEMPORARY) != 0, "TEMPORARY is set");
    CHECK(SetFileAttributesW(D L"\\sub", FILE_ATTRIBUTE_HIDDEN), "SetFileAttributes on a directory");
    at = GetFileAttributesW(D L"\\sub");
    CHECK((at & FILE_ATTRIBUTE_DIRECTORY) && (at & FILE_ATTRIBUTE_HIDDEN), "the directory keeps DIRECTORY and gains HIDDEN");
    SetFileAttributesW(D L"\\sub", FILE_ATTRIBUTE_NORMAL);
    at = GetFileAttributesW(D L"\\sub");
    CHECK((at & FILE_ATTRIBUTE_DIRECTORY) && !(at & FILE_ATTRIBUTE_HIDDEN), "clearing attributes never clears DIRECTORY");
    SetLastError(0);
    CHECK(!SetFileAttributesW(D L"\\missing.txt", FILE_ATTRIBUTE_READONLY) && GetLastError() == ERROR_FILE_NOT_FOUND, "SetFileAttributes on a missing file gives ERROR_FILE_NOT_FOUND");
    SetFileAttributesW(D L"\\attr.txt", FILE_ATTRIBUTE_NORMAL);
    CHECK(DeleteFileW(D L"\\attr.txt"), "the file can be deleted once READONLY is cleared");
    CHECK(AreFileApisANSI(), "AreFileApisANSI is TRUE by default");
    (void)buf;
}

/* ================================================================ ReplaceFile */
static void test_replace(void)
{
    unsigned char buf[64];
    DWORD n;
    put_file(D L"\\rep_old.txt", "old contents", 12);
    put_file(D L"\\rep_new.txt", "new", 3);
    put_file(D L"\\rep_bak.txt", "stale backup", 12);
    CHECK(ReplaceFileW(D L"\\rep_old.txt", D L"\\rep_new.txt", D L"\\rep_bak.txt", 0, NULL, NULL), "ReplaceFile with a backup name");
    n = get_file(D L"\\rep_old.txt", buf, sizeof buf);
    CHECK(n == 3 && buf[0] == 'n' && buf[1] == 'e' && buf[2] == 'w', "the replaced name now has the replacement's content");
    n = get_file(D L"\\rep_bak.txt", buf, sizeof buf);
    CHECK(n == 12 && buf[0] == 'o' && buf[1] == 'l' && buf[2] == 'd', "the backup holds the original content (the stale backup was overwritten)");
    SetLastError(0);
    CHECK(GetFileAttributesW(D L"\\rep_new.txt") == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND, "the replacement name is gone");

    put_file(D L"\\rep_new.txt", "second", 6);
    CHECK(ReplaceFileW(D L"\\rep_old.txt", D L"\\rep_new.txt", NULL, 0, NULL, NULL), "ReplaceFile without a backup");
    n = get_file(D L"\\rep_old.txt", buf, sizeof buf);
    CHECK(n == 6 && buf[0] == 's', "the content is the replacement's");
    CHECK(GetFileAttributesW(D L"\\rep_new.txt") == INVALID_FILE_ATTRIBUTES, "the replacement is consumed");

    put_file(D L"\\rep_new.txt", "third", 5);
    SetLastError(0);
    CHECK(!ReplaceFileW(D L"\\rep_nothing.txt", D L"\\rep_new.txt", NULL, 0, NULL, NULL), "ReplaceFile fails when the replaced file does not exist");
    CHECKV(GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_UNABLE_TO_REMOVE_REPLACED || GetLastError() == ERROR_PATH_NOT_FOUND,
           "with ERROR_FILE_NOT_FOUND or ERROR_UNABLE_TO_REMOVE_REPLACED", "err %u", (unsigned)GetLastError());
    CHECK(GetFileAttributesW(D L"\\rep_new.txt") != INVALID_FILE_ATTRIBUTES, "and the replacement is untouched");
    CHECK(!ReplaceFileW(D L"\\rep_old.txt", D L"\\rep_missing_replacement.txt", NULL, 0, NULL, NULL), "ReplaceFile fails when the replacement does not exist");
}

/* ================================================================ byte-range locks and overlapped I/O */
static void test_locks_overlapped(void)
{
    HANDLE a, b;
    OVERLAPPED ov;
    unsigned char data[256], buf[256];
    DWORD n, got, i;
    LARGE_INTEGER pos;

    for (i = 0; i < sizeof data; ++i) data[i] = (unsigned char)i;
    put_file(D L"\\lock.bin", data, sizeof data);
    a = CreateFileW(D L"\\lock.bin", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    b = CreateFileW(D L"\\lock.bin", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(a != INVALID_HANDLE_VALUE && b != INVALID_HANDLE_VALUE, "two handles to lock.bin");

    memset(&ov, 0, sizeof ov); ov.Offset = 0;
    CHECK(LockFileEx(a, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 100, 0, &ov), "an exclusive lock of bytes 0-99 through the first handle");
    memset(&ov, 0, sizeof ov); ov.Offset = 50;
    SetLastError(0);
    CHECK(!LockFileEx(b, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 100, 0, &ov), "an overlapping exclusive lock through the second handle fails");
    CHECK_ERR(ERROR_LOCK_VIOLATION, "with ERROR_LOCK_VIOLATION");
    SetLastError(0);
    CHECK(!LockFileEx(b, LOCKFILE_FAIL_IMMEDIATELY, 0, 100, 0, &ov), "an overlapping shared lock through the second handle fails too");
    memset(&ov, 0, sizeof ov); ov.Offset = 100;
    CHECK(LockFileEx(b, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 50, 0, &ov), "a lock of the adjacent range 100-149 is granted");
    SetFilePointer(b, 10, NULL, FILE_BEGIN);
    SetLastError(0);
    CHECK_N(!ReadFile(b, buf, 10, &got, NULL), "reading a range locked exclusively through the other handle fails");
    CHECK_N(GetLastError() == ERROR_LOCK_VIOLATION, "with ERROR_LOCK_VIOLATION");
    SetFilePointer(b, 10, NULL, FILE_BEGIN);
    SetLastError(0);
    CHECK_N(!WriteFile(b, buf, 10, &got, NULL) && GetLastError() == ERROR_LOCK_VIOLATION, "writing there fails as well");
    SetFilePointer(a, 10, NULL, FILE_BEGIN);
    CHECK(ReadFile(a, buf, 10, &got, NULL) && got == 10 && buf[0] == 10, "the owner reads its own locked range");
    SetFilePointer(a, 10, NULL, FILE_BEGIN);
    CHECK(WriteFile(a, "\x55\x55", 2, &got, NULL) && got == 2, "and writes to it");
    SetFilePointer(b, 200, NULL, FILE_BEGIN);
    CHECK(ReadFile(b, buf, 10, &got, NULL) && got == 10, "the other handle reads outside the locked ranges");
    SetLastError(0);
    CHECK_N(!UnlockFile(b, 0, 0, 100, 0) && GetLastError() == ERROR_NOT_LOCKED, "unlocking a range the handle does not hold fails with ERROR_NOT_LOCKED");
    SetLastError(0);
    CHECK_N(!UnlockFile(a, 0, 0, 99, 0) && GetLastError() == ERROR_NOT_LOCKED, "unlocking needs the exact locked range");
    CHECK(UnlockFile(a, 0, 0, 100, 0), "UnlockFile releases the exact range");
    memset(&ov, 0, sizeof ov); ov.Offset = 50;
    CHECK(LockFileEx(b, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 20, 0, &ov), "the released range can be locked through the other handle");
    CHECK(UnlockFileEx(b, 0, 20, 0, &ov), "UnlockFileEx");
    memset(&ov, 0, sizeof ov); ov.Offset = 100;
    CHECK(UnlockFileEx(b, 0, 50, 0, &ov), "UnlockFileEx of the 100-149 lock");

    memset(&ov, 0, sizeof ov); ov.Offset = 200;
    CHECK(LockFileEx(a, LOCKFILE_FAIL_IMMEDIATELY, 0, 20, 0, &ov), "a shared lock through the first handle");
    CHECK(LockFileEx(b, LOCKFILE_FAIL_IMMEDIATELY, 0, 20, 0, &ov), "a shared lock of the same range through the second handle is granted");
    SetFilePointer(b, 205, NULL, FILE_BEGIN);
    CHECK(ReadFile(b, buf, 5, &got, NULL) && got == 5, "reading a shared-locked range works");
    SetFilePointer(b, 205, NULL, FILE_BEGIN);
    SetLastError(0);
    CHECK_N(!WriteFile(b, "x", 1, &got, NULL) && GetLastError() == ERROR_LOCK_VIOLATION, "writing a shared-locked range through another handle fails");
    memset(&ov, 0, sizeof ov); ov.Offset = 200;
    SetLastError(0);
    CHECK(!LockFileEx(b, LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY, 0, 20, 0, &ov), "an exclusive request over a shared lock fails");
    UnlockFileEx(a, 0, 20, 0, &ov);
    UnlockFileEx(b, 0, 20, 0, &ov);
    CHECK(LockFile(a, 0, 0, 1, 0) && LockFile(a, 0xfffff000u, 0, 100, 0), "LockFile locks ranges, also beyond the end of the file");
    CloseHandle(a);
    SetLastError(0);
    CHECK(LockFile(b, 0, 0, 1, 0), "closing a handle releases its locks");
    UnlockFile(b, 0, 0, 1, 0);

    /* overlapped reads on a synchronous handle complete at once and honour the offset */
    memset(&ov, 0, sizeof ov);
    ov.Offset = 32;
    memset(buf, 0, sizeof buf);
    CHECK(ReadFile(b, buf, 16, NULL, &ov) || GetLastError() == ERROR_IO_PENDING, "ReadFile with an OVERLAPPED offset");
    CHECK(GetOverlappedResult(b, &ov, &n, FALSE) && n == 16, "GetOverlappedResult reports the 16 bytes");
    CHECK(buf[0] == 32 && buf[15] == 47, "the data comes from offset 32");
    memset(&ov, 0, sizeof ov);
    ov.Offset = (DWORD)sizeof data;
    SetLastError(0);
    CHECK(!ReadFile(b, buf, 16, &got, &ov), "an overlapped read at the end of file fails");
    CHECKV(GetLastError() == ERROR_HANDLE_EOF, "with ERROR_HANDLE_EOF", "err %u", (unsigned)GetLastError());
    pos.QuadPart = 0;
    SetFilePointerEx(b, pos, NULL, FILE_BEGIN);
    SetLastError(0);
    CHECK(CancelIo(b), "CancelIo with nothing pending succeeds");
    SetLastError(0);
    CHECK_W(!CancelIoEx(b, NULL) && GetLastError() == ERROR_NOT_FOUND, "CancelIoEx with nothing pending fails with ERROR_NOT_FOUND");
    CloseHandle(b);
    CHECK(!CancelIo(b), "CancelIo on a closed handle fails");
}

/* ================================================================ drives and volumes */
static int guid_ok(const WCHAR *s, int with_slash)
{
    static const WCHAR pre[] = L"\\\\?\\Volume{";
    int i, len = k32t_wlen(s);
    if (len != (with_slash ? 49 : 48) || !wsub(s, pre)) return 0;
    for (i = 0; i < 36; ++i) {
        const WCHAR c = s[11 + i];
        const int dash = i == 8 || i == 13 || i == 18 || i == 23;
        const int hex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
        if (dash ? c != '-' : !hex) return 0;
    }
    return s[47] == '}' && (!with_slash || s[48] == '\\');
}

static void test_volumes(void)
{
    WCHAR buf[300], label[64], fsn[64], strs[200], nt[300];
    char abuf[300];
    DWORD serial, maxc, flags, mask, i, n, count = 0, off;
    ULARGE_INTEGER avail, total, tfree;
    DWORD spc, bps, nfree, ntotal;
    BY_HANDLE_FILE_INFORMATION bi;
    HANDLE h;
    UINT t;

    t = GetDriveTypeW(L"C:\\");
    CHECKV(t == DRIVE_FIXED || t == DRIVE_RAMDISK, "C:\\ is a fixed disk or a RAM disk", "type %u", t);
    CHECK(GetDriveTypeW(NULL) == t, "GetDriveType(NULL) describes the current drive (C:)");
    CHECK(GetDriveTypeW(L"Q:\\") == DRIVE_NO_ROOT_DIR, "Q:\\ has no root directory");
    CHECK(GetDriveTypeA("C:\\") == t, "GetDriveTypeA");
    mask = GetLogicalDrives();
    CHECK(mask & (1u << ('C' - 'A')), "GetLogicalDrives has the bit for C:");
    CHECK(!(mask & (1u << ('Q' - 'A'))), "and none for Q:");
    for (i = 0; i < 26; ++i) {
        WCHAR root[4];
        root[0] = (WCHAR)('A' + i); root[1] = ':'; root[2] = '\\'; root[3] = 0;
        if (((mask >> i) & 1) != (GetDriveTypeW(root) != DRIVE_NO_ROOT_DIR)) break;
        count += (mask >> i) & 1;
    }
    CHECK(i == 26, "the drive bits agree with GetDriveType for every letter");
    n = GetLogicalDriveStringsW(200, strs);
    CHECKV(n == 4 * count, "GetLogicalDriveStringsW returns four characters per drive (without the final NUL)", "n=%u count=%u", n, count);
    for (i = 0, off = 0; i < count && off + 3 < 200; ++i, off += 4)
        if (!(strs[off + 1] == ':' && strs[off + 2] == '\\' && strs[off + 3] == 0 && ((mask >> (strs[off] - 'A')) & 1))) break;
    CHECK(i == count && strs[n] == 0, "each entry is X:\\ for a drive in the mask, and the list ends with an extra NUL");
    CHECK(GetLogicalDriveStringsW(2, strs) == 4 * count + 1, "a too small buffer yields the required size including the final NUL");
    CHECK(GetLogicalDriveStringsA(sizeof abuf, abuf) == 4 * count, "GetLogicalDriveStringsA");

    CHECK(GetVolumeInformationW(L"C:\\", label, 64, &serial, &maxc, &flags, fsn, 64), "GetVolumeInformationW(C:\\)");
    CHECK(k32t_wlen(label) <= 32, "the volume label is at most 32 characters");
    CHECK(fsn[0] != 0, "the file system name is not empty");
    CHECKV(maxc >= 12 && maxc <= 255, "the maximum component length is between 12 and 255", "%u", maxc);
    CHECK(flags & FILE_CASE_PRESERVED_NAMES, "the file system preserves case");
    CHECK_N(flags & FILE_UNICODE_ON_DISK, "the file system stores Unicode names");
    CHECK(serial != 0, "the volume serial number is not zero");
    h = CreateFileW(D L"\\alpha.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(h != INVALID_HANDLE_VALUE && GetFileInformationByHandle(h, &bi) && bi.dwVolumeSerialNumber == serial,
          "the serial number equals the volume serial reported for a file on C:");
    if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    CHECK(GetVolumeInformationW(NULL, NULL, 0, &serial, NULL, NULL, NULL, 0), "GetVolumeInformation(NULL) uses the current drive");
    SetLastError(0);
    CHECK(!GetVolumeInformationW(L"Q:\\", label, 64, &serial, &maxc, &flags, fsn, 64) && GetLastError() == ERROR_PATH_NOT_FOUND,
          "a drive that does not exist gives ERROR_PATH_NOT_FOUND");
    CHECK(GetVolumeInformationA("C:\\", abuf, sizeof abuf, NULL, NULL, NULL, abuf + 100, 100) && abuf[100] != 0, "GetVolumeInformationA");

    CHECK(GetDiskFreeSpaceExW(L"C:\\", &avail, &total, &tfree), "GetDiskFreeSpaceExW(C:\\)");
    CHECK(total.QuadPart > 0 && tfree.QuadPart <= total.QuadPart && avail.QuadPart <= tfree.QuadPart, "0 < total, free <= total and available <= free");
    CHECK(GetDiskFreeSpaceExW(NULL, &avail, NULL, NULL), "GetDiskFreeSpaceEx(NULL) uses the current drive");
    CHECK(GetDiskFreeSpaceW(L"C:\\", &spc, &bps, &nfree, &ntotal), "GetDiskFreeSpaceW(C:\\)");
    CHECK(bps >= 512 && bps <= 4096 && (bps & (bps - 1)) == 0 && spc >= 1 && (spc & (spc - 1)) == 0, "sector size and cluster size are powers of two");
    CHECK(nfree <= ntotal && ntotal > 0, "free clusters do not exceed total clusters");
    CHECK_W((ULONGLONG)ntotal * spc * bps == total.QuadPart, "the cluster counts describe the same total size as GetDiskFreeSpaceEx");
    CHECK(GetDiskFreeSpaceExA("C:\\", &avail, &total, &tfree) && total.QuadPart > 0, "GetDiskFreeSpaceExA");
    SetLastError(0);
    CHECK(!GetDiskFreeSpaceExW(L"Q:\\", &avail, &total, &tfree), "GetDiskFreeSpaceEx on a missing drive fails");

    /* volume names and mount points */
    CHECK(GetVolumeNameForVolumeMountPointW(L"C:\\", buf, 50), "GetVolumeNameForVolumeMountPointW(C:\\)");
    CHECKV(guid_ok(buf, 1), "the name has the form \\\\?\\Volume{GUID}\\", "'%d chars'", k32t_wlen(buf));
    SetLastError(0);
    CHECK(!GetVolumeNameForVolumeMountPointW(L"C:\\", buf, 10), "a buffer of 10 characters is too small");
    CHECK(GetVolumePathNamesForVolumeNameW(buf, NULL, 0, &n) == FALSE, "GetVolumePathNamesForVolumeNameW with no buffer reports the size needed");
    if (guid_ok(buf, 1)) {
        WCHAR names[16];
        CHECK(GetVolumeNameForVolumeMountPointW(L"C:\\", buf, 50) && GetVolumePathNamesForVolumeNameW(buf, names, 16, &n), "GetVolumePathNamesForVolumeNameW(volume)");
        CHECK(names[0] == 'C' && names[1] == ':' && names[2] == '\\' && names[3] == 0, "the volume is mounted at C:\\");
        {
            WCHAR first[64];
            HANDLE fv = FindFirstVolumeW(first, 64);
            int found = 0;
            CHECK(fv != INVALID_HANDLE_VALUE, "FindFirstVolumeW");
            if (fv != INVALID_HANDLE_VALUE) {
                do {
                    CHECKV(guid_ok(first, 1), "an enumerated volume name is \\\\?\\Volume{GUID}\\ (with the trailing backslash)", "len %d", k32t_wlen(first));
                    if (k32t_weq(first, buf)) found = 1;
                } while (FindNextVolumeW(fv, first, 64));
                CHECK(GetLastError() == ERROR_NO_MORE_FILES, "the enumeration ends with ERROR_NO_MORE_FILES");
                CHECK(FindVolumeClose(fv), "FindVolumeClose");
            }
            CHECK(found, "the volume of C:\\ is among the enumerated volumes");
        }
    }
    CHECK(GetVolumePathNameW(D L"\\no\\such\\file.txt", buf, 300) && k32t_weq(buf, L"C:\\"), "GetVolumePathNameW gives the mount point C:\\ even for a missing file");
    CHECK(GetVolumePathNameW(L"C:\\", buf, 300) && k32t_weq(buf, L"C:\\"), "and for the root itself");
    CHECK(GetVolumePathNameA(DA "\\alpha.txt", abuf, sizeof abuf) && abuf[0] == 'C' && abuf[1] == ':' && abuf[2] == '\\' && abuf[3] == 0, "GetVolumePathNameA");

    n = QueryDosDeviceW(L"C:", nt, 300);
    CHECK(n > 0, "QueryDosDevice(C:) returns a target");
    CHECK_W(wsub(nt, L"\\Device\\"), "the target of C: is an NT device path \\Device\\...");
    CHECK(n == (DWORD)k32t_wlen(nt) + 2 && nt[n - 1] == 0 && nt[n - 2] == 0, "and the result ends with two NULs");
    SetLastError(0);
    CHECK(QueryDosDeviceW(L"Q:", nt, 300) == 0 && GetLastError() == ERROR_FILE_NOT_FOUND, "Q: is not a DOS device (ERROR_FILE_NOT_FOUND)");
    SetLastError(0);
    CHECK(QueryDosDeviceW(L"C:", nt, 3) == 0 && GetLastError() == ERROR_INSUFFICIENT_BUFFER, "a small buffer gives ERROR_INSUFFICIENT_BUFFER");
    {
        WCHAR all[600];
        DWORD k = QueryDosDeviceW(NULL, all, 600), p = 0;
        int seen = 0;
        while (k && p < k && all[p]) { if (wieq(all + p, L"C:")) seen = 1; p += k32t_wlen(all + p) + 1; }
        CHECK_W(k > 0 && seen, "the list of DOS devices includes C:");
    }
    h = CreateFileW(D L"\\alpha.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        WCHAR fin[400];
        static const WCHAR tail[] = L"\\T_K32_FILE\\alpha.txt";
        n = GetFinalPathNameByHandleW(h, fin, 400, VOLUME_NAME_NT);
        CHECKV_W(n > 0 && n < 400 && wsub(fin, L"\\Device\\") && wends(fin, tail), "GetFinalPathNameByHandle(VOLUME_NAME_NT) is <device>\\dir\\file", "n=%u", n);
        CHECK_W(n > 0 && n < 400 && wsub(fin, nt) && k32t_weq(fin + k32t_wlen(nt), tail), "and its device part is what QueryDosDevice(C:) returns");
        n = GetFinalPathNameByHandleW(h, fin, 400, VOLUME_NAME_DOS);
        CHECK(n == 4 + 2 + 21 && k32t_weq(fin, L"\\\\?\\C:\\T_K32_FILE\\alpha.txt"), "VOLUME_NAME_DOS gives \\\\?\\C:\\T_K32_FILE\\alpha.txt");
        CHECK(GetFinalPathNameByHandleW(h, fin, 400, 0) == n, "the default flags are VOLUME_NAME_DOS | FILE_NAME_NORMALIZED");
        CHECK(GetFinalPathNameByHandleW(h, fin, 5, VOLUME_NAME_DOS) == n + 1, "a small buffer yields the required size including the NUL");
        n = GetFinalPathNameByHandleW(h, fin, 400, VOLUME_NAME_NONE);
        CHECK(n == 21 && k32t_weq(fin, tail), "VOLUME_NAME_NONE gives the volume-relative path");
        n = GetFinalPathNameByHandleW(h, fin, 400, VOLUME_NAME_GUID);
        CHECK(n > 21 && wends(fin, L"}\\T_K32_FILE\\alpha.txt") && wsub(fin, L"\\\\?\\Volume{"), "VOLUME_NAME_GUID gives \\\\?\\Volume{GUID}\\dir\\file");
        n = GetFinalPathNameByHandleW(h, fin, 400, FILE_NAME_OPENED | VOLUME_NAME_DOS);
        CHECK(n > 0 && k32t_weq(fin, L"\\\\?\\C:\\T_K32_FILE\\alpha.txt"), "FILE_NAME_OPENED is accepted");
        SetLastError(0);
        CHECK(GetFinalPathNameByHandleW(h, fin, 400, 0x100) == 0 && GetLastError() == ERROR_INVALID_PARAMETER, "unknown flags give ERROR_INVALID_PARAMETER");
        n = GetFinalPathNameByHandleA(h, abuf, sizeof abuf, VOLUME_NAME_DOS);
        CHECK(n == 27 && abuf[0] == '\\' && abuf[4] == 'C' && abuf[n - 1] == 't', "GetFinalPathNameByHandleA");
        CloseHandle(h);
    }
}

/* ================================================================ a second volume
 * Runs when D: is a fixed disk (Kernel64 with a FAT32 disk: tests/run_k64_disk.py; many Windows machines). Every property is
 * checked against what the API reports for C: or against another API, so no volume-specific constant is assumed. */
/* The first regular file under dir ("D:"), searching `depth` directory levels: its full path into out (300 characters). */
static int find_file_on(const WCHAR *dir, WCHAR *out, int depth)
{
    WIN32_FIND_DATAW fd;
    WCHAR spec[300];
    HANDLE h;
    int dl = k32t_wlen(dir), ok = 0;
    if (dl + 3 >= 300) return 0;
    memcpy(spec, dir, dl * sizeof(WCHAR));
    spec[dl] = '\\'; spec[dl + 1] = '*'; spec[dl + 2] = 0;
    h = FindFirstFileW(spec, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        const int nl = k32t_wlen(fd.cFileName);
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || dl + 1 + nl >= 300) continue;
        memcpy(out, dir, dl * sizeof(WCHAR));
        out[dl] = '\\';
        memcpy(out + dl + 1, fd.cFileName, (nl + 1) * sizeof(WCHAR));
        ok = 1;
    } while (!ok && FindNextFileW(h, &fd));
    FindClose(h);
    if (ok || depth <= 1) return ok;
    h = FindFirstFileW(spec, &fd);
    if (h == INVALID_HANDLE_VALUE) return 0;
    do {
        const int nl = k32t_wlen(fd.cFileName);
        WCHAR sub[300];
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == '.' || dl + 1 + nl >= 290) continue;
        memcpy(sub, dir, dl * sizeof(WCHAR));
        sub[dl] = '\\';
        memcpy(sub + dl + 1, fd.cFileName, (nl + 1) * sizeof(WCHAR));
        ok = find_file_on(sub, out, depth - 1);
    } while (!ok && FindNextFileW(h, &fd));
    FindClose(h);
    return ok;
}

static void test_second_volume(void)
{
    WCHAR cdev[300], ddev[300], cguid[64], dguid[64], names[16], fin[400], label[64], fsn[64], all[600];
    DWORD cserial = 0, dserial = 0, maxc, flags, n, k, p;
    ULARGE_INTEGER avail, total, tfree;
    BY_HANDLE_FILE_INFORMATION bi;
    WIN32_FIND_DATAW fd;
    HANDLE h;
    int seen_c = 0, seen_d = 0;
    if (!(GetLogicalDrives() & (1u << ('D' - 'A'))) || GetDriveTypeW(L"D:\\") != DRIVE_FIXED) {
        printf("NOTE: D: is not a fixed disk here; the second-volume checks do not apply\n");
        return;
    }
    CHECK(GetVolumeInformationW(L"C:\\", NULL, 0, &cserial, NULL, NULL, NULL, 0), "GetVolumeInformationW(C:\\) serial");
    CHECK(GetVolumeInformationW(L"D:\\", label, 64, &dserial, &maxc, &flags, fsn, 64), "GetVolumeInformationW(D:\\)");
    CHECK(fsn[0] != 0 && maxc >= 12, "D: reports a file system name and a component length");
    CHECK(dserial != cserial, "D: has a volume serial number of its own");
    CHECK(GetDiskFreeSpaceExW(L"D:\\", &avail, &total, &tfree) && total.QuadPart > 0 && tfree.QuadPart <= total.QuadPart,
          "GetDiskFreeSpaceExW(D:\\): 0 < total, free <= total");
    n = QueryDosDeviceW(L"C:", cdev, 300);
    k = QueryDosDeviceW(L"D:", ddev, 300);
    CHECK_W(n > 0 && k > 0 && wsub(ddev, L"\\Device\\") && !k32t_weq(cdev, ddev), "QueryDosDevice(D:) is a \\Device\\ path other than C:'s");
    k = QueryDosDeviceW(NULL, all, 600);
    for (p = 0; k && p < k && all[p]; p += k32t_wlen(all + p) + 1) {
        if (wieq(all + p, L"C:")) seen_c = 1;
        if (wieq(all + p, L"D:")) seen_d = 1;
    }
    CHECK_W(seen_c && seen_d, "the list of DOS devices has both C: and D:");
    CHECK(GetVolumeNameForVolumeMountPointW(L"C:\\", cguid, 64) && GetVolumeNameForVolumeMountPointW(L"D:\\", dguid, 64),
          "GetVolumeNameForVolumeMountPointW(C:\\ and D:\\)");
    CHECK(guid_ok(dguid, 1) && !k32t_weq(cguid, dguid), "D: has its own \\\\?\\Volume{GUID}\\ name");
    CHECK(GetVolumePathNamesForVolumeNameW(dguid, names, 16, &n) && k32t_weq(names, L"D:\\") && names[4] == 0,
          "GetVolumePathNamesForVolumeNameW(D:'s volume) is D:\\");
    {
        WCHAR v[64];
        HANDLE fv = FindFirstVolumeW(v, 64);
        int c = 0, d = 0;
        if (fv != INVALID_HANDLE_VALUE) {
            do { if (k32t_weq(v, cguid)) c = 1; if (k32t_weq(v, dguid)) d = 1; } while (FindNextVolumeW(fv, v, 64));
            FindVolumeClose(fv);
        }
        CHECK(c && d, "FindFirstVolume/FindNextVolume enumerate the volumes of C: and D:");
    }
    h = CreateFileW(L"D:\\", FILE_READ_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
    CHECK(h != INVALID_HANDLE_VALUE, "the root directory of D: opens");
    if (h != INVALID_HANDLE_VALUE) {
        n = GetFinalPathNameByHandleW(h, fin, 400, VOLUME_NAME_DOS);
        CHECKV_W(n == 7 && k32t_weq(fin, L"\\\\?\\D:\\"), "GetFinalPathNameByHandle(D:\\ root, VOLUME_NAME_DOS) is \\\\?\\D:\\", "n=%u", n);
        n = GetFinalPathNameByHandleW(h, fin, 400, VOLUME_NAME_NT);
        CHECK_W(n > 0 && wsub(fin, ddev) && k32t_weq(fin + k32t_wlen(ddev), L"\\"), "... and VOLUME_NAME_NT is QueryDosDevice(D:) + \\");
        n = GetFinalPathNameByHandleW(h, fin, 400, VOLUME_NAME_GUID);
        CHECK(n == 49 && k32t_weq(fin, dguid), "... and VOLUME_NAME_GUID is D:'s volume name");
        CloseHandle(h);
    }
    SetLastError(0);
    h = FindFirstFileW(L"D:\\*", &fd);
    CHECKV(h != INVALID_HANDLE_VALUE, "FindFirstFileW(D:\\*) lists the root of D:", "GetLastError=%u", (unsigned)GetLastError());
    if (h != INVALID_HANDLE_VALUE) FindClose(h);
    {
        WCHAR path[300], want[320];
        HANDLE f;
        if (!find_file_on(L"D:", path, 2)) {
            printf("NOTE: D: holds no file in its first two levels; the per-file checks do not apply\n");
            return;
        }
        f = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
        CHECK(f != INVALID_HANDLE_VALUE, "a file found on D: opens");
        if (f != INVALID_HANDLE_VALUE) {
            CHECK(GetFileInformationByHandle(f, &bi) && bi.dwVolumeSerialNumber == dserial,
                  "its volume serial number is the one GetVolumeInformation(D:\\) reports");
            want[0] = '\\'; want[1] = '\\'; want[2] = '?'; want[3] = '\\';
            memcpy(want + 4, path, (k32t_wlen(path) + 1) * sizeof(WCHAR));
            n = GetFinalPathNameByHandleW(f, fin, 400, VOLUME_NAME_DOS);
            CHECK(n > 0 && wieq(fin, want), "GetFinalPathNameByHandle of a D: file is \\\\?\\D:\\<path>");
            n = GetFinalPathNameByHandleW(f, fin, 400, VOLUME_NAME_NT);
            CHECK(n > 0 && wsub(fin, ddev) && wieq(fin + k32t_wlen(ddev), path + 2), "... and VOLUME_NAME_NT is QueryDosDevice(D:) + \\<path>");
            CloseHandle(f);
        }
    }
}

/* ================================================================ path names */
static void test_paths(void)
{
    WCHAR out[300];
    char aout[300];
    DWORD n;
    WCHAR tmp[300], tmp2[300];
    UINT u, u2;
    HANDLE h;

    CreateDirectoryW(D L"\\LongDirName", NULL);
    put_file(D L"\\LongDirName\\MixedCase.Txt", "m", 1);

    n = GetLongPathNameW(D L"\\LongDirName\\MixedCase.Txt", out, 300);
    CHECKV(n == LONGLEN && k32t_weq(out, D L"\\LongDirName\\MixedCase.Txt"), "GetLongPathName of an existing path returns it unchanged", "n=%u", n);
    n = GetLongPathNameW(L"C:\\T_K32_FILE\\LONGDIRNAME\\MIXEDCASE.TXT", out, 300);
    CHECKV(n == LONGLEN && k32t_weq(out, L"C:\\T_K32_FILE\\LONGDIRNAME\\MIXEDCASE.TXT"), "components that cannot be 8.3 names are returned as given", "n=%u", n);
    CreateDirectoryW(D L"\\Short.Dir", NULL);
    put_file(D L"\\Short.Dir\\AbC.tXt", "s", 1);
    n = GetLongPathNameW(L"C:\\T_K32_FILE\\short.dir\\abc.txt", out, 300);
    CHECKV(k32t_weq(out, L"C:\\T_K32_FILE\\Short.Dir\\AbC.tXt") && n == 31, "components with an 8.3 shape come back spelled as stored on disk", "n=%u", n);
    n = GetLongPathNameW(L"C:\\T_K32_FILE\\short.dir\\", out, 300);
    CHECK(n == 24 && k32t_weq(out, L"C:\\T_K32_FILE\\Short.Dir\\"), "a trailing backslash is kept");
    n = GetLongPathNameW(L"C:\\T_K32_FILE\\short.dir\\..\\SHORT.DIR", out, 300);
    CHECKV(k32t_weq(out, L"C:\\T_K32_FILE\\Short.Dir\\..\\Short.Dir") && n == 36, "'..' components are kept and the components after them are resolved too", "n=%u", n);
    n = GetLongPathNameW(D L"\\LongDirName\\MixedCase.Txt", out, 5);
    CHECK(n == LONGLEN + 1, "a small buffer yields the required size including the NUL");
    SetLastError(0);
    n = GetLongPathNameW(D L"\\LongDirName\\Nope.Txt", out, 300);
    CHECK(n == 0 && GetLastError() == ERROR_FILE_NOT_FOUND, "a missing file gives ERROR_FILE_NOT_FOUND");
    SetLastError(0);
    n = GetLongPathNameW(D L"\\NoDir\\Nope.Txt", out, 300);
    CHECKV(n == 0 && (GetLastError() == ERROR_FILE_NOT_FOUND || GetLastError() == ERROR_PATH_NOT_FOUND), "a missing directory fails with ERROR_FILE_NOT_FOUND or ERROR_PATH_NOT_FOUND", "err %u", (unsigned)GetLastError());
    n = GetLongPathNameW(D L"\\LongDirName", out, 300);
    CHECK(n == (DWORD)k32t_wlen(D L"\\LongDirName") && k32t_weq(out, D L"\\LongDirName"), "GetLongPathName of a directory");
    n = GetLongPathNameA(DA "\\LongDirName\\MixedCase.Txt", aout, sizeof aout);
    CHECK(n == LONGLEN && aout[LONGLEN - 1] == 't', "GetLongPathNameA");
    n = GetShortPathNameW(D L"\\LongDirName\\MixedCase.Txt", out, 300);
    CHECK(n > 0 && n < 300, "GetShortPathName of an existing path succeeds");
    SetLastError(0);
    CHECK(GetShortPathNameW(D L"\\LongDirName\\Nope.Txt", out, 300) == 0 && GetLastError() == ERROR_FILE_NOT_FOUND, "GetShortPathName of a missing file fails with ERROR_FILE_NOT_FOUND");

    /* temporary path */
    SetEnvironmentVariableW(L"TMP", D);
    n = GetTempPathW(300, out);
    CHECK(n == (DWORD)k32t_wlen(D) + 1 && k32t_weq(out, D L"\\"), "GetTempPath returns %TMP% with a trailing backslash");
    SetEnvironmentVariableW(L"TMP", D L"\\");
    n = GetTempPathW(300, out);
    CHECK(n == (DWORD)k32t_wlen(D) + 1 && k32t_weq(out, D L"\\"), "and does not double an existing trailing backslash");
    SetEnvironmentVariableW(L"TMP", NULL);
    SetEnvironmentVariableW(L"TEMP", D L"\\sub");
    n = GetTempPathW(300, out);
    CHECK(k32t_weq(out, D L"\\sub\\"), "without TMP, TEMP is used");
    CHECK(GetTempPathW(5, out) == n + 1, "a small buffer yields the required size including the NUL");
    n = GetTempPathA(300, aout);
    CHECK(n == (DWORD)k32t_wlen(D L"\\sub\\") && aout[n - 1] == '\\' && aout[0] == 'C', "GetTempPathA");
    SetEnvironmentVariableW(L"TEMP", D);

    /* temporary file names */
    u = GetTempFileNameW(D, L"abcdef", 0, tmp);
    CHECK(u != 0, "GetTempFileName(unique 0) succeeds");
    CHECK(wsub(tmp, D L"\\abc") && wends(tmp, L".tmp") && k32t_wlen(tmp) == k32t_wlen(D) + 1 + 3 + 4 + 4, "the name is <dir>\\<3 chars of the prefix><4 hex digits>.tmp");
    {
        const WCHAR *hex = tmp + k32t_wlen(D) + 4;
        UINT v = 0;
        int k, ok = 1;
        for (k = 0; k < 4; ++k) {
            const WCHAR c = hex[k];
            v <<= 4;
            if (c >= '0' && c <= '9') v |= c - '0';
            else if (c >= 'a' && c <= 'f') v |= c - 'a' + 10;
            else if (c >= 'A' && c <= 'F') v |= c - 'A' + 10;
            else ok = 0;
        }
        CHECK(ok && v == u, "the digits are the hexadecimal form of the returned number");
    }
    CHECK(GetFileAttributesW(tmp) != INVALID_FILE_ATTRIBUTES, "with unique 0 the file is created");
    u2 = GetTempFileNameW(D, L"abc", 0, tmp2);
    CHECK(u2 != 0 && u2 != u && !k32t_weq(tmp, tmp2), "a second call yields a different name");
    DeleteFileW(tmp);
    DeleteFileW(tmp2);
    u = GetTempFileNameW(D L"\\", L"xyz", 0x1234, tmp);
    CHECK(u == 0x1234, "a nonzero unique number is returned as it is");
    CHECK(wieq(tmp, D L"\\xyz1234.tmp"), "and forms the name <dir>\\xyz1234.tmp");
    CHECK(GetFileAttributesW(tmp) == INVALID_FILE_ATTRIBUTES, "with a nonzero unique number no file is created");
    SetLastError(0);
    u = GetTempFileNameW(D L"\\nodir", L"abc", 0, tmp);
    CHECK(u == 0 && GetLastError() == ERROR_DIRECTORY, "GetTempFileName in a missing directory fails with ERROR_DIRECTORY");
    {
        WCHAR longp[300];
        int k;
        for (k = 0; k < 280; ++k) longp[k] = 'a';
        longp[0] = 'C'; longp[1] = ':'; longp[2] = '\\'; longp[280] = 0;
        SetLastError(0);
        CHECK(GetTempFileNameW(longp, L"abc", 0, tmp) == 0, "a directory name longer than MAX_PATH-14 makes GetTempFileName fail");
    }
    n = GetTempFileNameA(DA, "qrs", 0xab12, aout);
    CHECK(n == 0xab12 && aout[0] == 'C' && aout[14] == 'q' && aout[16] == 's' && aout[17] == 'a' && aout[18] == 'b' && aout[19] == '1' && aout[20] == '2',
          "GetTempFileNameA: <dir>\\qrsab12.tmp");
    h = INVALID_HANDLE_VALUE;
    (void)h;
}

int main(void)
{
    WCHAR cwd[300];
    delete_tree(D);
    CHECK(CreateDirectoryW(D, NULL), "create the test directory");
    GetCurrentDirectoryW(300, cwd);
    CHECK(SetCurrentDirectoryW(D), "make it the current directory");
    test_find();
    test_handle_info();
    test_by_name();
    test_replace();
    test_locks_overlapped();
    test_volumes();
    test_second_volume();
    test_paths();
    SetCurrentDirectoryW(cwd);
    delete_tree(D);
    CHECK(GetFileAttributesW(D) == INVALID_FILE_ATTRIBUTES, "the test directory is gone after cleanup");
    return k32t_finish("t_k32_file");
}
