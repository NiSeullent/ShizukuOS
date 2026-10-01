/* SPDX-License-Identifier: GPL-2.0-only
 * Real guest directory creation and independently queried basic attributes.
 * This fixture targets Kernel64's existing SHZFS RAM provider on C:.
 */
#include "k32test.h"

#define ROOT L"C:\\SHZ\\TESTS\\DIRXTEMPL"
#define SOURCE ROOT L"\\SOURCE"
#define COPIED ROOT L"\\COPIED"
#define SOURCE_A "C:\\SHZ\\TESTS\\DIRXTEMPL\\SOURCE"
#define COPIED_A "C:\\SHZ\\TESTS\\DIRXTEMPL\\COPIED"

static void real_remove(LPCWSTR path)
{
    if (GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) {
        CHECK(SetFileAttributesW(path, FILE_ATTRIBUTE_NORMAL), "clear copied attributes before real deletion");
        CHECK(RemoveDirectoryW(path), "remove the actual test directory");
    }
}

static void check_contents_empty(LPCWSTR path)
{
    WCHAR pattern[300];
    WIN32_FIND_DATAW data;
    HANDLE scan;
    BOOL ended, unexpected = FALSE;
    DWORD error;
    int i, n = k32t_wlen(path);
    for (i = 0; i < n; ++i) pattern[i] = path[i];
    pattern[n] = '\\'; pattern[n + 1] = '*'; pattern[n + 2] = 0;
    scan = FindFirstFileW(pattern, &data);
    CHECK(scan != INVALID_HANDLE_VALUE, "enumerate the actual new directory through filesystem handles");
    if (scan == INVALID_HANDLE_VALUE) return;
    do {
        if (!k32t_weq(data.cFileName, L".") && !k32t_weq(data.cFileName, L"..")) unexpected = TRUE;
        ended = !FindNextFileW(scan, &data);
    } while (!ended);
    error = GetLastError();
    CHECK(!unexpected && error == ERROR_NO_MORE_FILES, "only the real directory hierarchy entries exist");
    CHECK(FindClose(scan), "release the actual directory enumeration handle");
}

int main(void)
{
    static const DWORD copied_modes[] = {
        FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_SYSTEM, FILE_ATTRIBUTE_READONLY,
        FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_TEMPORARY, FILE_ATTRIBUTE_OFFLINE,
        FILE_ATTRIBUTE_NOT_CONTENT_INDEXED,
        FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY
    };
    SECURITY_ATTRIBUTES security;
    WCHAR filesystem[16];
    DWORD i, flags = 0, attributes;
    HANDLE file;

    CHECK(GetVolumeInformationW(L"C:\\", NULL, 0, NULL, NULL, &flags, filesystem, 16) &&
          k32t_weq(filesystem, L"SHZFS"), "fixture uses the actual SHZFS RAM attribute provider");
    CHECK(!(flags & (FILE_PERSISTENT_ACLS | FILE_NAMED_STREAMS | FILE_SUPPORTS_EXTENDED_ATTRIBUTES)),
          "the current actual volume does not advertise directory ACL/stream/EA storage");
    CHECK(CreateDirectoryW(ROOT, NULL), "create the actual fixture parent through ordinary creation");
    CHECK(CreateDirectoryW(SOURCE, NULL), "create the actual source template directory");

    SetLastError(0x654321);
    CHECK(CreateDirectoryExW(NULL, COPIED, NULL), "NULL template performs real ordinary W creation");
    CHECK_ERR(0x654321, "successful NULL template retains the caller error value");
    CHECK(GetFileAttributesW(COPIED) == FILE_ATTRIBUTE_DIRECTORY, "ordinary W output is an actual directory");
    check_contents_empty(COPIED); real_remove(COPIED);
    SetLastError(0x654322);
    CHECK(CreateDirectoryExA(NULL, COPIED_A, NULL), "NULL template performs real ordinary A creation");
    CHECK_ERR(0x654322, "successful A call retains the caller error value");
    CHECK(GetFileAttributesA(COPIED_A) == FILE_ATTRIBUTE_DIRECTORY, "ordinary A output exists in the actual filesystem");
    real_remove(COPIED);

    SetLastError(0x654323);
    CHECK(CreateDirectoryExW(SOURCE, COPIED, NULL), "a held real plain template creates an actual directory");
    CHECK_ERR(0x654323, "successful plain template retains LastError");
    CHECK(GetFileAttributesW(COPIED) == FILE_ATTRIBUTE_DIRECTORY, "plain template output has real directory attributes");
    CHECK(!CreateDirectoryExW(SOURCE, COPIED, NULL), "a second creation rejects an actual existing destination");
    CHECK_ERR(ERROR_ALREADY_EXISTS, "native name collision maps to the ordinary directory error");
    real_remove(COPIED);

    for (i = 0; i < sizeof copied_modes / sizeof copied_modes[0]; ++i) {
        CHECK(SetFileAttributesW(SOURCE, copied_modes[i]), "set real source attributes independently of CreateDirectoryEx");
        CHECK(GetFileAttributesW(SOURCE) == (copied_modes[i] | FILE_ATTRIBUTE_DIRECTORY),
              "independently query the actual template attribute value");
        SetLastError(0x7700 + i);
        CHECK(i & 1 ? CreateDirectoryExA(SOURCE_A, COPIED_A, NULL) : CreateDirectoryExW(SOURCE, COPIED, NULL),
              "A/W copies supported basic attributes into the actual RAM directory");
        CHECK_ERR(0x7700 + i, "successful actual attribute copy preserves caller LastError");
        attributes = GetFileAttributesW(COPIED);
        CHECK(attributes == (copied_modes[i] | FILE_ATTRIBUTE_DIRECTORY), "query copied attributes from the actual destination node");
        real_remove(COPIED);
    }
    CHECK(SetFileAttributesW(SOURCE, FILE_ATTRIBUTE_NORMAL), "restore the real template to plain directory attributes");
    CHECK(CreateDirectoryExA(SOURCE_A, "C:\\SHZ\\TESTS\\DIRXTEMPL\\\xeb\xb3\xb5\xec\x82\xac", NULL),
          "A creation uses the actual platform UTF-8 conversion for a Korean path");
    CHECK(GetFileAttributesW(ROOT L"\\\ubcf5\uc0ac") == FILE_ATTRIBUTE_DIRECTORY,
          "the UTF-8 A path and UTF-16 W path identify the same actual directory");
    real_remove(ROOT L"\\\ubcf5\uc0ac");

    CHECK(!CreateDirectoryExW(ROOT L"\\ABSENT", COPIED, NULL), "a nonexistent actual template is rejected");
    CHECK_ERR(ERROR_FILE_NOT_FOUND, "missing template exposes the native missing-name result");
    CHECK(GetFileAttributesW(COPIED) == INVALID_FILE_ATTRIBUTES, "missing template did not create the destination");
    file = CreateFileW(ROOT L"\\FILE", GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(file != INVALID_HANDLE_VALUE && CloseHandle(file), "create a real file to distinguish it from a directory template");
    CHECK(!CreateDirectoryExW(ROOT L"\\FILE", COPIED, NULL), "an actual file cannot be a directory template");
    CHECK_ERR(ERROR_DIRECTORY, "file-as-template reports the real directory type error");
    CHECK(DeleteFileW(ROOT L"\\FILE"), "remove the actual fixture file");
    CHECK(!CreateDirectoryExW(SOURCE, ROOT L"\\ABSENT\\CHILD", NULL), "the new directory's missing parent is not synthesized");
    CHECK_ERR(ERROR_PATH_NOT_FOUND, "absent parent returns the actual path error");
    CHECK(!CreateDirectoryExW(L"", COPIED, NULL), "empty non-NULL template is an invalid path");
    CHECK_ERR(ERROR_PATH_NOT_FOUND, "empty template differs from the explicit NULL extension");
    CHECK(!CreateDirectoryExW(NULL, NULL, NULL), "NULL destination is rejected before native path conversion");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "NULL destination has an explicit parameter error");
    CHECK(!CreateDirectoryExA(NULL, "", NULL), "empty A destination is rejected");
    CHECK_ERR(ERROR_PATH_NOT_FOUND, "A and W empty destination behavior agree");

    memset(&security, 0, sizeof security);
    security.nLength = sizeof security;
    security.bInheritHandle = TRUE;
    CHECK(CreateDirectoryExW(SOURCE, COPIED, &security), "optional security structure without an explicit descriptor uses actual default creation");
    real_remove(COPIED);
    security.lpSecurityDescriptor = &security;
    CHECK(!CreateDirectoryExW(SOURCE, COPIED, &security), "explicit unavailable directory security fails before creation");
    CHECK_ERR(ERROR_NOT_SUPPORTED, "unavailable directory security is reported honestly");
    CHECK(GetFileAttributesW(COPIED) == INVALID_FILE_ATTRIBUTES, "security failure left no newly created destination");
    security.lpSecurityDescriptor = NULL;
    security.nLength = 0;
    CHECK(!CreateDirectoryExW(NULL, COPIED, &security), "invalid optional security structure is rejected before creation");
    CHECK_ERR(ERROR_INVALID_PARAMETER, "invalid security structure length has a parameter error");

    /* If a mounted disk root actually exposes nonzero basic attributes, it can
     * exercise the unsupported copy without inventing or modifying disk data. */
    if (GetDriveTypeW(L"D:\\") != DRIVE_NO_ROOT_DIR && GetFileAttributesW(L"D:\\") != INVALID_FILE_ATTRIBUTES) {
        attributes = GetFileAttributesW(L"D:\\");
        if (attributes & (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM)) {
            CHECK(!CreateDirectoryExW(L"D:\\", L"D:\\DIRXUNSUP", NULL), "a real disk attribute copy is rejected before creating a disk destination");
            CHECK_ERR(ERROR_NOT_SUPPORTED, "disk attribute persistence remains an explicit unsupported operation");
            CHECK(GetFileAttributesW(L"D:\\DIRXUNSUP") == INVALID_FILE_ATTRIBUTES, "unsupported disk copy created no disk directory");
        }
    }
    real_remove(SOURCE); real_remove(ROOT);
    return k32t_finish("T_DIRECTORY_TEMPLATE");
}
