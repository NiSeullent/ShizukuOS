/* SPDX-License-Identifier: GPL-2.0-only
 * Genuine Toolhelp snapshots, shared W/ANSI traversal and actual module data.
 */
#ifdef UNICODE
#undef UNICODE
#endif
#include "k32test.h"
#include <tlhelp32.h>

#define COPY_NAME L"C:\\SHZ\\TESTS\\T_MODAN_\ub3c4\uad6c.dll"
#define COPY_BASENAME "T_MODAN_\xeb\x8f\x84\xea\xb5\xac.dll"

static BOOL bytes_equal(const void *a, const void *b, size_t count) { return !memcmp(a, b, count); }
static BOOL same_record(const MODULEENTRY32 *a, const MODULEENTRY32W *w)
{
    char module[MAX_MODULE_NAME32 + 1], path[MAX_PATH];
    if (!WideCharToMultiByte(CP_UTF8, 0, w->szModule, -1, module, sizeof module, NULL, NULL) ||
        !WideCharToMultiByte(CP_UTF8, 0, w->szExePath, -1, path, sizeof path, NULL, NULL)) return FALSE;
    return a->th32ModuleID == w->th32ModuleID && a->th32ProcessID == w->th32ProcessID &&
           a->GlblcntUsage == w->GlblcntUsage && a->ProccntUsage == w->ProccntUsage &&
           a->modBaseAddr == w->modBaseAddr && a->modBaseSize == w->modBaseSize && a->hModule == w->hModule &&
           !strcmp(a->szModule, module) && !strcmp(a->szExePath, path);
}

static DWORD actual_image_size(HMODULE module)
{
    const BYTE *base = (const BYTE *)module;
    const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)base;
    const IMAGE_NT_HEADERS *nt = (const IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    return dos->e_magic == IMAGE_DOS_SIGNATURE && nt->Signature == IMAGE_NT_SIGNATURE ? nt->OptionalHeader.SizeOfImage : 0;
}

static BOOL snapshot_has(HANDLE snapshot, HMODULE module, BOOL check_korean)
{
    MODULEENTRY32 entry;
    BOOL ok, found = FALSE;
    DWORD count = 0;
    memset(&entry, 0, sizeof entry); entry.dwSize = sizeof entry;
    for (ok = Module32First(snapshot, &entry); ok && count < 128; ok = Module32Next(snapshot, &entry), ++count) {
        if (entry.hModule == module) {
            found = TRUE;
            CHECK(entry.modBaseAddr == (BYTE *)module && entry.modBaseSize == actual_image_size(module),
                  "enumerated copied DLL base and size match its actual loaded PE image");
            if (check_korean) CHECK(!strcmp(entry.szModule, COPY_BASENAME), "actual Korean module name is returned as exact UTF-8 bytes");
        }
    }
    CHECK(!ok && GetLastError() == ERROR_NO_MORE_FILES, "real copied-DLL snapshot scan reaches its actual end");
    return found;
}

int main(void)
{
    HANDLE ansi_snapshot, wide_snapshot, mixed_snapshot, empty_snapshot, ordinary_event, old_snapshot, new_snapshot;
    MODULEENTRY32 ansi, before;
    MODULEENTRY32W wide, baseline[3];
    struct { MODULEENTRY32 entry; BYTE guard[32]; } oversized;
    HMODULE self = GetModuleHandleW(NULL), kernel = GetModuleHandleW(L"kernel32.dll"), copied;
    DWORD count = 0, i;
    BOOL a_ok, w_ok, found_self = FALSE, found_kernel = FALSE, copy_created, may_delete_copy;
    CHECK(GetACP() == CP_UTF8, "the actual platform ANSI code page is UTF-8");
    ansi_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    wide_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    CHECK(ansi_snapshot != INVALID_HANDLE_VALUE && wide_snapshot != INVALID_HANDLE_VALUE, "create two actual module snapshots of this process");
    if (ansi_snapshot == INVALID_HANDLE_VALUE || wide_snapshot == INVALID_HANDLE_VALUE) return 1;
    memset(&ansi, 0, sizeof ansi); ansi.dwSize = sizeof ansi;
    memset(&wide, 0, sizeof wide); wide.dwSize = sizeof wide;
    SetLastError(0x661122);
    a_ok = Module32First(ansi_snapshot, &ansi);
    CHECK(a_ok && GetLastError() == 0x661122, "bare ANSI First succeeds and preserves LastError");
    w_ok = Module32FirstW(wide_snapshot, &wide);
    while (a_ok && w_ok && count < 128) {
        CHECK(same_record(&ansi, &wide), "ANSI scalar/name/path data match the independently traversed actual W record");
        CHECK(ansi.th32ProcessID == GetCurrentProcessId() && ansi.modBaseAddr && ansi.modBaseSize && ansi.dwSize == sizeof ansi,
              "actual module record retains owning process, nonzero mapped image and ANSI buffer size");
        if (count < 3) baseline[count] = wide;
        if (ansi.hModule == self) { found_self = TRUE; CHECK(ansi.modBaseSize == actual_image_size(self), "main image size agrees with its independently read PE header"); }
        if (ansi.hModule == kernel) { found_kernel = TRUE; CHECK(ansi.modBaseSize == actual_image_size(kernel), "kernel32 size agrees with its independently read PE header"); }
        ++count;
        a_ok = Module32Next(ansi_snapshot, &ansi);
        if (!a_ok) CHECK_ERR(ERROR_NO_MORE_FILES, "actual ANSI module list ends with NO_MORE_FILES");
        w_ok = Module32NextW(wide_snapshot, &wide);
    }
    CHECK(!a_ok && !w_ok && count >= 3 && count < 128 && found_self && found_kernel,
          "both actual lists end together and contain real executable/runtime modules");
    if (count < 3) {
        CHECK(CloseHandle(ansi_snapshot) && CloseHandle(wide_snapshot), "close snapshots after a failed baseline");
        return k32t_finish("T_MODULE_ANSI");
    }
    before = ansi;
    CHECK(!Module32Next(ansi_snapshot, &ansi) && GetLastError() == ERROR_NO_MORE_FILES && bytes_equal(&ansi, &before, sizeof ansi),
          "repeated exhaustion leaves actual caller output unchanged");
    CHECK(Module32First(ansi_snapshot, &ansi) && same_record(&ansi, &baseline[0]), "ANSI First restarts the same real snapshot");

    mixed_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    CHECK(mixed_snapshot != INVALID_HANDLE_VALUE, "create an actual snapshot for mixed W/ANSI traversal");
    ansi.dwSize = sizeof ansi;
    CHECK(Module32First(mixed_snapshot, &ansi) && same_record(&ansi, &baseline[0]), "mixed snapshot begins through its bare ANSI entry");
    ansi.dwSize = sizeof ansi - 1; before = ansi;
    CHECK(!Module32Next(mixed_snapshot, &ansi) && GetLastError() == ERROR_BAD_LENGTH && bytes_equal(&ansi, &before, sizeof ansi),
          "short ANSI buffer fails without output mutation");
    wide.dwSize = sizeof wide;
    CHECK(Module32NextW(mixed_snapshot, &wide) && wide.hModule == baseline[1].hModule,
          "bad ANSI buffer did not advance the shared actual W cursor");
    CHECK(!Module32First(mixed_snapshot, &ansi) && GetLastError() == ERROR_BAD_LENGTH,
          "invalid ANSI First does not restart the cursor");
    ansi.dwSize = sizeof ansi;
    CHECK(Module32Next(mixed_snapshot, &ansi) && same_record(&ansi, &baseline[2]),
          "ANSI resumes the same actual cursor after W traversal");
    memset(&oversized, 0xa5, sizeof oversized); oversized.entry.dwSize = sizeof oversized;
    CHECK(Module32First(mixed_snapshot, &oversized.entry) && oversized.entry.dwSize == sizeof oversized,
          "accepted oversized ANSI caller retains its dwSize");
    for (i = 0; i < sizeof oversized.guard; ++i) if (oversized.guard[i] != 0xa5) break;
    CHECK(i == sizeof oversized.guard, "ANSI result writes no bytes beyond its own ABI structure");
    CHECK(!Module32Next(mixed_snapshot, NULL) && GetLastError() == ERROR_BAD_LENGTH, "NULL ANSI output follows existing W buffer error behavior");

    empty_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    CHECK(empty_snapshot != INVALID_HANDLE_VALUE, "create an actual process-only snapshot without module records");
    ansi.dwSize = sizeof ansi; before = ansi;
    CHECK(!Module32First(empty_snapshot, &ansi) && GetLastError() == ERROR_NO_MORE_FILES && bytes_equal(&ansi, &before, sizeof ansi),
          "actual process-only snapshot contains no invented module entries");
    ordinary_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    CHECK(ordinary_event != NULL, "create a real ordinary event that is not a snapshot");
    CHECK(!Module32First(ordinary_event, &ansi) && GetLastError() == ERROR_INVALID_HANDLE, "ordinary event handle cannot masquerade as a module snapshot");
    CHECK(CloseHandle(ordinary_event) && CloseHandle(empty_snapshot) && CloseHandle(mixed_snapshot), "close actual event and snapshot handles");
    CHECK(!Module32First(mixed_snapshot, &ansi) && GetLastError() == ERROR_INVALID_HANDLE,
          "closed actual snapshot is rejected by the shared provider");
    CHECK(CloseHandle(ansi_snapshot) && CloseHandle(wide_snapshot), "release both real baseline snapshots");

    /* Copy real existing DLL bytes, then actually load the copy. The existing
     * snapshot must stay immutable and a new snapshot must contain the image. */
    old_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
    CHECK(old_snapshot != INVALID_HANDLE_VALUE, "freeze an actual module snapshot before loading the Unicode fixture DLL");
    copy_created = CopyFileW(L"C:\\SHZ\\SYS64\\version.dll", COPY_NAME, TRUE);
    CHECK(copy_created, "copy actual runtime DLL bytes to a Korean fixture path without overwriting files");
    may_delete_copy = copy_created;
    copied = copy_created ? LoadLibraryW(COPY_NAME) : NULL;
    if (copy_created) CHECK(copied != NULL, "load the real copied DLL under its Korean filename");
    if (copied) {
        CHECK(!snapshot_has(old_snapshot, copied, FALSE), "old actual snapshot does not invent a later-loaded DLL");
        new_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
        CHECK(new_snapshot != INVALID_HANDLE_VALUE, "take a new actual module snapshot after DLL load");
        if (new_snapshot != INVALID_HANDLE_VALUE) {
            CHECK(snapshot_has(new_snapshot, copied, TRUE), "new actual snapshot contains the real copied Unicode DLL");
            CHECK(CloseHandle(new_snapshot), "release the actual post-load snapshot");
        }
        may_delete_copy = FreeLibrary(copied);
        CHECK(may_delete_copy, "unload the actual copied fixture DLL");
    }
    CHECK(CloseHandle(old_snapshot), "release the actual pre-load snapshot");
    if (may_delete_copy) CHECK(DeleteFileW(COPY_NAME), "delete the owned actual fixture DLL bytes after unloading");
    return k32t_finish("T_MODULE_ANSI");
}
