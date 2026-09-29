/* SPDX-License-Identifier: GPL-2.0-only
 * Wine port glue: read-only file mappings for the Wine modules (DirectWrite maps font files, crypt32 maps signed files).
 *
 * The Shizuku kernel has no section objects yet, so kernel32 does not export CreateFileMappingW / MapViewOfFile.
 * These module-local versions support exactly the case the ported code uses: a mapping of an open file with
 * PAGE_READONLY / PAGE_WRITECOPY (or the EXECUTE variants) and views with FILE_MAP_READ / FILE_MAP_COPY. A view is
 * a private copy of the file range read at MapViewOfFile time (read-only pages for FILE_MAP_READ, writable private
 * pages for FILE_MAP_COPY), which is what those protections mean as long as nobody writes the file while it is mapped.
 * The file position is saved and restored around that read (not atomic against another thread using the same handle).
 * Everything else - page-file backed or named sections, writable shared views - fails with ERROR_NOT_SUPPORTED: that
 * needs kernel support and is not emulated. Mapping handles are closed through CloseHandle as usual.
 */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"

#define MAX_MAPPINGS 256
#define MAX_VIEWS 1024
#define MAPPING_TAG 0x5a4d0000u                      /* handle values 0x5a4d0000 + 4 * index: never kernel handles */

static struct mapping { HANDLE file; ULONGLONG size; DWORD protect; LONG refs; BOOL used; } mappings[MAX_MAPPINGS];
static struct view { void *base; SIZE_T size; int mapping; } views[MAX_VIEWS];
static CRITICAL_SECTION lock;
static LONG lock_init;

static void enter(void)
{
    if (InterlockedCompareExchange(&lock_init, 1, 0) == 0) { InitializeCriticalSection(&lock); lock_init = 2; }
    while (lock_init != 2) Sleep(0);
    EnterCriticalSection(&lock);
}

static int mapping_index(HANDLE h)
{
    ULONG_PTR v = (ULONG_PTR)h;
    if ((v & 0xffff0000u) != MAPPING_TAG || (v & 3)) return -1;
    v = (v & 0xffff) / 4;
    return v < MAX_MAPPINGS && mappings[v].used ? (int)v : -1;
}

static void release_mapping(int i)
{
    if (--mappings[i].refs) return;
    CloseHandle(mappings[i].file);
    mappings[i].used = FALSE;
}

HANDLE WINAPI CreateFileMappingW(HANDLE file, SECURITY_ATTRIBUTES *sa, DWORD protect, DWORD size_high, DWORD size_low,
                                 LPCWSTR name)
{
    DWORD prot = protect & 0xff;
    LARGE_INTEGER fsize;
    ULONGLONG size = ((ULONGLONG)size_high << 32) | size_low;
    HANDLE dup;
    int i;

    if (file == INVALID_HANDLE_VALUE || name || (prot != PAGE_READONLY && prot != PAGE_WRITECOPY &&
        prot != PAGE_EXECUTE_READ && prot != PAGE_EXECUTE_WRITECOPY))
    {
        SetLastError(ERROR_NOT_SUPPORTED);
        return NULL;
    }
    if (!GetFileSizeEx(file, &fsize)) return NULL;
    if (!size) size = fsize.QuadPart;
    if (!size) { SetLastError(ERROR_FILE_INVALID); return NULL; }
    if (size > (ULONGLONG)fsize.QuadPart) { SetLastError(ERROR_NOT_ENOUGH_MEMORY); return NULL; }  /* read-only: cannot grow */
    if (!DuplicateHandle(GetCurrentProcess(), file, GetCurrentProcess(), &dup, 0, FALSE, DUPLICATE_SAME_ACCESS))
        return NULL;
    enter();
    for (i = 0; i < MAX_MAPPINGS && mappings[i].used; i++) { }
    if (i == MAX_MAPPINGS)
    {
        LeaveCriticalSection(&lock);
        CloseHandle(dup);
        SetLastError(ERROR_TOO_MANY_OPEN_FILES);
        return NULL;
    }
    mappings[i].file = dup;
    mappings[i].size = size;
    mappings[i].protect = prot;
    mappings[i].refs = 1;
    mappings[i].used = TRUE;
    LeaveCriticalSection(&lock);
    SetLastError(ERROR_SUCCESS);
    return (HANDLE)(ULONG_PTR)(MAPPING_TAG + 4 * i);
}

HANDLE WINAPI CreateFileMappingA(HANDLE file, SECURITY_ATTRIBUTES *sa, DWORD protect, DWORD size_high, DWORD size_low,
                                 LPCSTR name)
{
    if (name) { SetLastError(ERROR_NOT_SUPPORTED); return NULL; }
    return CreateFileMappingW(file, sa, protect, size_high, size_low, NULL);
}

void *WINAPI MapViewOfFileEx(HANDLE h, DWORD access, DWORD off_high, DWORD off_low, SIZE_T bytes, void *addr)
{
    ULONGLONG off = ((ULONGLONG)off_high << 32) | off_low;
    LARGE_INTEGER pos, zero, saved;
    BOOL have_saved;
    BYTE *base;
    SIZE_T done = 0;
    DWORD old;
    int i, v;

    if (access & (FILE_MAP_WRITE & ~FILE_MAP_READ) && !(access & FILE_MAP_COPY))
    {
        SetLastError(ERROR_ACCESS_DENIED);                       /* read-only mappings only */
        return NULL;
    }
    enter();
    if ((i = mapping_index(h)) < 0) { LeaveCriticalSection(&lock); SetLastError(ERROR_INVALID_HANDLE); return NULL; }
    if (off & 0xffff) { LeaveCriticalSection(&lock); SetLastError(ERROR_MAPPED_ALIGNMENT); return NULL; }
    if (off >= mappings[i].size || (bytes && bytes > mappings[i].size - off))
    {
        LeaveCriticalSection(&lock);
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    if (!bytes) bytes = (SIZE_T)(mappings[i].size - off);
    for (v = 0; v < MAX_VIEWS && views[v].base; v++) { }
    if (v == MAX_VIEWS || !(base = VirtualAlloc(addr, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE)))
    {
        LeaveCriticalSection(&lock);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return NULL;
    }
    /* the duplicated handle shares the file object, hence its position: a real mapping does not move the file
     * pointer (wintrust maps a file and then reads it from where the caller left it), so it is restored */
    zero.QuadPart = 0;
    have_saved = SetFilePointerEx(mappings[i].file, zero, &saved, FILE_CURRENT);
    pos.QuadPart = off;
    if (SetFilePointerEx(mappings[i].file, pos, NULL, FILE_BEGIN))
        while (done < bytes)
        {
            DWORD got = 0, want = bytes - done > 0x1000000 ? 0x1000000 : (DWORD)(bytes - done);
            if (!ReadFile(mappings[i].file, base + done, want, &got, NULL) || !got) break;
            done += got;
        }
    if (have_saved) SetFilePointerEx(mappings[i].file, saved, NULL, FILE_BEGIN);
    if (done != bytes)
    {
        VirtualFree(base, 0, MEM_RELEASE);
        LeaveCriticalSection(&lock);
        SetLastError(ERROR_READ_FAULT);
        return NULL;
    }
    if (!(access & FILE_MAP_COPY)) VirtualProtect(base, bytes, PAGE_READONLY, &old);
    views[v].base = base;
    views[v].size = bytes;
    views[v].mapping = i;
    mappings[i].refs++;
    LeaveCriticalSection(&lock);
    return base;
}

void *WINAPI MapViewOfFile(HANDLE h, DWORD access, DWORD off_high, DWORD off_low, SIZE_T bytes)
{
    return MapViewOfFileEx(h, access, off_high, off_low, bytes, NULL);
}

BOOL WINAPI UnmapViewOfFile(const void *base)
{
    int v;
    enter();
    for (v = 0; v < MAX_VIEWS && views[v].base != base; v++) { }
    if (v == MAX_VIEWS || !base) { LeaveCriticalSection(&lock); SetLastError(ERROR_INVALID_ADDRESS); return FALSE; }
    VirtualFree(views[v].base, 0, MEM_RELEASE);
    release_mapping(views[v].mapping);
    views[v].base = NULL;
    LeaveCriticalSection(&lock);
    return TRUE;
}

BOOL WINAPI FlushViewOfFile(const void *base, SIZE_T bytes) { return TRUE; }   /* views are never dirty file pages */

/* CloseHandle of the Wine modules: mapping handles are released here, everything else goes to kernel32. */
BOOL WINAPI CloseHandle(HANDLE h)
{
    static BOOL (WINAPI *real)(HANDLE);
    int i;
    if (((ULONG_PTR)h & 0xffff0000u) == MAPPING_TAG)
    {
        enter();
        if ((i = mapping_index(h)) >= 0)
        {
            release_mapping(i);
            LeaveCriticalSection(&lock);
            return TRUE;
        }
        LeaveCriticalSection(&lock);
    }
    if (!real) real = (void *)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CloseHandle");
    return real(h);
}

void *__imp_CreateFileMappingW = (void *)CreateFileMappingW;
void *__imp_CreateFileMappingA = (void *)CreateFileMappingA;
void *__imp_MapViewOfFile = (void *)MapViewOfFile;
void *__imp_MapViewOfFileEx = (void *)MapViewOfFileEx;
void *__imp_UnmapViewOfFile = (void *)UnmapViewOfFile;
void *__imp_FlushViewOfFile = (void *)FlushViewOfFile;
void *__imp_CloseHandle = (void *)CloseHandle;
