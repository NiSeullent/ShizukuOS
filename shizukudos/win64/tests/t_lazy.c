/* SPDX-License-Identifier: GPL-2.0-only
 * Lazily mapped (file-backed) images on D:\ (standalone profile, tests/run_k64_disk.py): LoadLibraryW of
 * D:\LAZY\BIGLAZY.DLL (320 MiB blob of known content, loads at its preferred base) and D:\LAZY\BIGRELOC.DLL (16 MiB,
 * preferred base = this executable's, so the kernel relocates it page by page). Measured from user mode:
 *   - resident pages of the whole image (NtQueryVirtualMemory MemoryWorkingSetExInformation, Valid bit) right after
 *     LoadLibrary and after touching a known set of pages;
 *   - free physical memory (GlobalMemoryStatusEx) before and after;
 *   - page_hash(i) of the touched pages (the host recomputes them from the generator);
 *   - check_relocs(): 256 relocated pointers plus one DIR64 fixup straddling a page boundary.
 * Everything is printed as "LAZY-..." lines. Without D:\LAZY the test prints SKIP and exits 0. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "u_check.h"

typedef LONG NTSTATUS;
NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);

typedef unsigned long long (*page_hash_fn)(unsigned long long);
typedef unsigned long long (*blob_pages_fn)(void);
typedef int (*check_relocs_fn)(void);
typedef const void *(*blob_address_fn)(void);

/* Valid pages in [base, base + pages * 4096) according to the kernel's working-set query. */
static long long resident(const unsigned char *base, unsigned long long pages)
{
    static struct { void *va; ULONG_PTR attr; } ws[1024];
    unsigned long long done = 0, n = 0;
    while (done < pages) {
        const unsigned long long chunk = pages - done < 1024 ? pages - done : 1024;
        unsigned long long i;
        SIZE_T ret = 0;
        NTSTATUS st;
        for (i = 0; i < chunk; ++i) { ws[i].va = (void *)(base + (done + i) * 4096); ws[i].attr = 0; }
        st = NtQueryVirtualMemory((HANDLE)-1, 0, 4 /* MemoryWorkingSetExInformation */, ws, chunk * sizeof ws[0], &ret);
        if (st) { printf("FAIL: NtQueryVirtualMemory(MemoryWorkingSetExInformation): %x\n", (unsigned)st); return -1; }
        for (i = 0; i < chunk; ++i) n += ws[i].attr & 1;
        done += chunk;
    }
    return (long long)n;
}

static long long avail_kib(void)
{
    MEMORYSTATUSEX m;
    m.dwLength = sizeof m;
    if (!GlobalMemoryStatusEx(&m)) return -1;
    return (long long)(m.ullAvailPhys / 1024);
}

static unsigned long long image_pages(HMODULE h)
{
    const unsigned char *b = (const unsigned char *)h;
    const unsigned char *nt = b + *(const LONG *)(b + 0x3c);
    return *(const DWORD *)(nt + 24 + 56) / 4096u;            /* OptionalHeader.SizeOfImage */
}

static unsigned long long preferred_base(HMODULE h)
{
    const unsigned char *b = (const unsigned char *)h;
    const unsigned char *nt = b + *(const LONG *)(b + 0x3c);
    return *(const unsigned long long *)(nt + 24 + 24);       /* OptionalHeader.ImageBase (as in the file) */
}

static void run_dll(const wchar_t *path, const char *name, int expect_relocated, unsigned touches)
{
    HMODULE h;
    long long a0, a1, a2, r1, r2;
    unsigned long long pages, blob, i, img;
    page_hash_fn page_hash;
    blob_pages_fn blob_pages;
    check_relocs_fn check_relocs;
    blob_address_fn blob_address;
    const unsigned char *blob_va;
    a0 = avail_kib();
    h = LoadLibraryW(path);
    U_CHECKF("LoadLibraryW of a large DLL on D:", h != 0, "%s: error %u", name, (unsigned)GetLastError());
    if (!h) return;
    a1 = avail_kib();
    img = image_pages(h);
    page_hash = (page_hash_fn)GetProcAddress(h, "page_hash");
    blob_pages = (blob_pages_fn)GetProcAddress(h, "blob_pages");
    check_relocs = (check_relocs_fn)GetProcAddress(h, "check_relocs");
    blob_address = (blob_address_fn)GetProcAddress(h, "blob_address");
    U_CHECK("the DLL's exports resolve", page_hash && blob_pages && check_relocs && blob_address);
    if (!page_hash || !blob_pages || !check_relocs || !blob_address) return;
    r1 = resident((const unsigned char *)h, img);
    printf("LAZY-LOAD %s base %llx preferred %llx image_pages %llu resident %lld avail_delta_kib %lld\n", name,
           (unsigned long long)(ULONG_PTR)h, preferred_base(h), img, r1, a0 - a1);
    U_CHECKF("loaded at the expected kind of base", expect_relocated ? (ULONG_PTR)h != 0x140000000ull : (ULONG_PTR)h == 0x7fe000000000ull,
             "%s at %llx", name, (unsigned long long)(ULONG_PTR)h);
    pages = blob_pages();
    blob_va = blob_address();
    blob = (unsigned long long)(blob_va - (const unsigned char *)h) / 4096u;   /* first blob page within the image */
    for (i = 0; i < touches; ++i) {
        /* first, last and a spread of pages (a multiplicative walk), each touched exactly once */
        const unsigned long long page = i == 0 ? 0 : i == 1 ? pages - 1 : (i * 2654435761ull) % pages;
        printf("LAZY-HASH %s %llu %llx\n", name, page, page_hash(page));
    }
    printf("LAZY-RELOC %s %d\n", name, check_relocs());
    r2 = resident((const unsigned char *)h, img);
    a2 = avail_kib();
    printf("LAZY-TOUCH %s touches %u blob_first_page %llu blob_pages %llu resident %lld avail_delta_kib %lld\n", name, touches,
           blob, pages, r2, a0 - a2);
    U_CHECKF("touched pages became resident, the rest did not", r2 >= r1 && r2 - r1 <= (long long)touches + 16 && r2 < (long long)img / 4,
             "%s: %lld -> %lld of %llu", name, r1, r2, img);
    U_CHECKF("relocations applied (256 table pointers + the page-straddling pointer)", check_relocs() == 1256, "%s: %d", name, check_relocs());
}

int main(void)
{
    if (GetFileAttributesA("D:\\LAZY") == INVALID_FILE_ATTRIBUTES) {
        printf("SKIP: no D:\\LAZY (not the disk test image)\n");
        return 0;
    }
    run_dll(L"D:\\LAZY\\BIGLAZY.DLL", "BIGLAZY.DLL", 0, 64);
    run_dll(L"D:\\LAZY\\BIGRELOC.DLL", "BIGRELOC.DLL", 1, 32);
    return u_finish("t_lazy");
}
