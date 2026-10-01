/* SPDX-License-Identifier: GPL-2.0-only
 * Actual guest copy/progress/cancel/metadata and measured heap/CPU contracts.
 */
#include "k32test.h"

static const WCHAR directory[] = L"C:\\T_STEAM_IO";
static const WCHAR source[] = L"C:\\T_STEAM_IO\\source.bin";
static const WCHAR target[] = L"C:\\T_STEAM_IO\\target.bin";
static BYTE bytes[200003];
struct progress_state { DWORD action; unsigned calls, faults; LONGLONG last; BOOL *cancel; };

static DWORD CALLBACK progress(LARGE_INTEGER total, LARGE_INTEGER copied, LARGE_INTEGER stream, LARGE_INTEGER streamcopied,
                               DWORD number, DWORD reason, HANDLE input, HANDLE output, LPVOID context)
{
    struct progress_state *p = context;
    if (total.QuadPart != sizeof bytes || stream.QuadPart != total.QuadPart || copied.QuadPart != streamcopied.QuadPart ||
        copied.QuadPart < p->last || copied.QuadPart > total.QuadPart || number != 1 ||
        input == INVALID_HANDLE_VALUE || output == INVALID_HANDLE_VALUE || input == output) ++p->faults;
    if ((!p->calls && (reason != CALLBACK_STREAM_SWITCH || copied.QuadPart)) ||
        (p->calls && (reason != CALLBACK_CHUNK_FINISHED || copied.QuadPart <= p->last))) ++p->faults;
    ++p->calls; p->last = copied.QuadPart;
    if (reason == CALLBACK_CHUNK_FINISHED) {
        if (p->cancel) *p->cancel = TRUE;
        return p->action;
    }
    return PROGRESS_CONTINUE;
}

static BOOL contents(LPCWSTR path, SIZE_T expected)
{
    HANDLE h = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    BYTE chunk[4096]; DWORD got; SIZE_T offset = 0; BOOL correct = TRUE;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    while (offset < expected) {
        if (!ReadFile(h, chunk, sizeof chunk, &got, NULL) || !got || got > expected - offset || memcmp(chunk, bytes + offset, got)) { correct = FALSE; break; }
        offset += got;
    }
    if (correct) correct = ReadFile(h, chunk, 1, &got, NULL) && got == 0;
    CloseHandle(h); return correct;
}

int main(void)
{
    HANDLE file, heap, process = GetCurrentProcess();
    DWORD wrote, mode; SIZE_T returned; BYTE small[4], larger[8]; unsigned i;
    struct progress_state p;
    BY_HANDLE_FILE_INFORMATION original, copied;
    FILETIME creation = { 12345, 0x01d00000 }, access = { 23456, 0x01d00000 }, write = { 34567, 0x01d00000 };
    BOOL cancel = FALSE;
    memset(&original, 0, sizeof original); memset(&copied, 0, sizeof copied);

    CHECK(SetProcessAffinityMask(process, 1), "real single-CPU process accepts CPU0 affinity");
    CHECK(!SetProcessAffinityMask(process, 0) && GetLastError() == ERROR_INVALID_PARAMETER, "empty affinity mask rejected");
    CHECK(!SetProcessAffinityMask(process, 2) && GetLastError() == ERROR_INVALID_PARAMETER, "nonexistent CPU affinity rejected");
    CHECK(!SetProcessAffinityMask(NULL, 1) && GetLastError() == ERROR_INVALID_HANDLE, "affinity validates actual process handle");
    file = CreateEventW(NULL, FALSE, FALSE, NULL);
    CHECK(file && !SetProcessAffinityMask(file, 1) && GetLastError() == ERROR_INVALID_HANDLE, "affinity refuses a real object of wrong type");
    if (file) CloseHandle(file);
    mode = 99; returned = 0;
    CHECK(HeapQueryInformation(GetProcessHeap(), HeapCompatibilityInformation, &mode, sizeof mode, &returned) && mode == 0 && returned == sizeof mode,
          "actual process heap reports standard first-fit allocator mode");
    memset(larger, 0xa5, sizeof larger); returned = 0;
    CHECK(HeapQueryInformation(GetProcessHeap(), HeapCompatibilityInformation, larger, sizeof larger, &returned) &&
          larger[0] == 0 && larger[1] == 0 && larger[2] == 0 && larger[3] == 0 && larger[4] == 0xa5 && larger[5] == 0xa5 &&
          larger[6] == 0xa5 && larger[7] == 0xa5 && returned == sizeof(ULONG), "heap query writes only its actual four-byte result");
    heap = HeapCreate(0, 0, 0); mode = 99;
    CHECK(heap && HeapQueryInformation(heap, HeapCompatibilityInformation, &mode, sizeof mode, NULL) && mode == 0,
          "independent registered heap reports its actual standard mode");
    mode = 2;
    CHECK(!HeapSetInformation(heap, HeapCompatibilityInformation, &mode, sizeof mode) && GetLastError() == ERROR_NOT_SUPPORTED,
          "existing allocator refuses LFH rather than manufacturing that mode");
    mode = 99;
    CHECK(HeapQueryInformation(heap, HeapCompatibilityInformation, &mode, sizeof mode, NULL) && mode == 0, "failed LFH enable leaves measured heap mode unchanged");
    memset(small, 0xa5, sizeof small); returned = 0;
    CHECK(!HeapQueryInformation(heap, HeapCompatibilityInformation, small, 2, &returned) && GetLastError() == ERROR_INSUFFICIENT_BUFFER &&
          returned == sizeof(ULONG) && small[0] == 0xa5 && small[1] == 0xa5 && small[2] == 0xa5 && small[3] == 0xa5,
          "short heap query returns required size without overwriting output");
    CHECK(!HeapQueryInformation(heap, (HEAP_INFORMATION_CLASS)99, &mode, sizeof mode, NULL) && GetLastError() == ERROR_NOT_SUPPORTED,
          "unsupported heap information class fails explicitly");
    CHECK(!HeapQueryInformation(heap, HeapCompatibilityInformation, NULL, sizeof mode, NULL) && GetLastError() == ERROR_INVALID_PARAMETER,
          "heap query rejects NULL output");
    CHECK(HeapDestroy(heap) && !HeapQueryInformation(heap, HeapCompatibilityInformation, &mode, sizeof mode, NULL) && GetLastError() == ERROR_INVALID_HANDLE,
          "query safely rejects an unmapped destroyed heap handle through registry identity");

    CreateDirectoryW(directory, NULL);
    SetFileAttributesW(source, FILE_ATTRIBUTE_NORMAL); SetFileAttributesW(target, FILE_ATTRIBUTE_NORMAL);
    DeleteFileW(source); DeleteFileW(target);
    for (i = 0; i < sizeof bytes; ++i) bytes[i] = (BYTE)(i * 17 + i / 257);
    file = CreateFileW(source, GENERIC_READ | GENERIC_WRITE | FILE_WRITE_ATTRIBUTES, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    CHECK(file != INVALID_HANDLE_VALUE, "actual source file created"); if (file == INVALID_HANDLE_VALUE) return 1;
    CHECK(WriteFile(file, bytes, sizeof bytes, &wrote, NULL) && wrote == sizeof bytes && SetFileTime(file, &creation, &access, &write),
          "actual source bytes and timestamps established");
    CloseHandle(file);
    CHECK(SetFileAttributesW(source, FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_ARCHIVE), "source readonly/archive metadata established");
    file = CreateFileW(source, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(file != INVALID_HANDLE_VALUE && GetFileInformationByHandle(file, &original), "snapshot real source metadata");
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    memset(&p, 0, sizeof p);
    CHECK(CopyFileExW(source, target, progress, &p, NULL, COPY_FILE_FAIL_IF_EXISTS) && p.calls >= 4 && !p.faults && p.last == sizeof bytes && contents(target, sizeof bytes),
          "actual multi-chunk copy has valid increasing progress and exact bytes");
    file = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    CHECK(file != INVALID_HANDLE_VALUE && GetFileInformationByHandle(file, &copied), "read actual copied metadata");
    if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
    CHECK(copied.dwFileAttributes == original.dwFileAttributes &&
          memcmp(&copied.ftCreationTime, &original.ftCreationTime, sizeof(FILETIME)) == 0 &&
          memcmp(&copied.ftLastAccessTime, &original.ftLastAccessTime, sizeof(FILETIME)) == 0 &&
          memcmp(&copied.ftLastWriteTime, &original.ftLastWriteTime, sizeof(FILETIME)) == 0,
          "copy preserves actual ordinary-file attributes and timestamps");
    CHECK(!CopyFileExW(source, target, NULL, NULL, NULL, COPY_FILE_FAIL_IF_EXISTS) && GetLastError() == ERROR_FILE_EXISTS && contents(target, sizeof bytes),
          "existing destination FAIL_IF_EXISTS leaves its bytes intact");
    CHECK(!CopyFileExW(source, target, NULL, NULL, NULL, COPY_FILE_RESTARTABLE) && GetLastError() == ERROR_NOT_SUPPORTED && contents(target, sizeof bytes),
          "unsupported checkpoint mode fails before changing existing destination");
    cancel = TRUE;
    CHECK(!CopyFileExW(source, target, NULL, NULL, &cancel, 0) && GetLastError() == ERROR_REQUEST_ABORTED && contents(target, sizeof bytes),
          "pre-set cancellation leaves existing destination untouched"); cancel = FALSE;
    SetFileAttributesW(target, FILE_ATTRIBUTE_NORMAL); SetFileAttributesW(source, FILE_ATTRIBUTE_ARCHIVE);
    memset(&p, 0, sizeof p); p.action = PROGRESS_CANCEL;
    CHECK(!CopyFileExW(source, target, progress, &p, NULL, 0) && GetLastError() == ERROR_REQUEST_ABORTED && !p.faults &&
          GetFileAttributesW(target) == INVALID_FILE_ATTRIBUTES, "callback CANCEL deletes partial destination");
    memset(&p, 0, sizeof p); p.action = PROGRESS_STOP;
    CHECK(!CopyFileExW(source, target, progress, &p, NULL, 0) && GetLastError() == ERROR_REQUEST_ABORTED && !p.faults &&
          p.last > 0 && p.last < (LONGLONG)sizeof bytes && contents(target, (SIZE_T)p.last), "callback STOP retains exactly the completed partial bytes");
    memset(&p, 0, sizeof p); p.action = PROGRESS_QUIET;
    CHECK(CopyFileExW(source, target, progress, &p, NULL, 0) && p.calls == 2 && !p.faults && contents(target, sizeof bytes),
          "callback QUIET suppresses later notifications while actual copy completes");
    memset(&p, 0, sizeof p); p.cancel = &cancel;
    CHECK(!CopyFileExW(source, target, progress, &p, &cancel, 0) && GetLastError() == ERROR_REQUEST_ABORTED &&
          GetFileAttributesW(target) == INVALID_FILE_ATTRIBUTES, "pbCancel set during a callback cancels and removes partial destination");
    DeleteFileW(target); DeleteFileW(source); RemoveDirectoryW(directory);
    return k32t_finish("T_STEAM_IO");
}
