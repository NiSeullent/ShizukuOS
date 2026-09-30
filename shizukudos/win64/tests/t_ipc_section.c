/* SPDX-License-Identifier: GPL-2.0-only
 * File mappings: pagefile-backed and file-backed sections, named/inherited/duplicated sharing across processes, views at
 * offsets, copy-on-write views, read-only views, FlushViewOfFile, error cases, and no leaked sections, views or pages.
 */
#include "ipc_test.h"

#define MB (1024u * 1024u)

static volatile LONG g_av;             /* written by the exception handler: volatile, or the compiler folds the reads */
static LONG CALLBACK av_handler(PEXCEPTION_POINTERS ep)
{
    if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        ++g_av;
        ep->ContextRecord->Rip += 3;                        /* skip poke()'s store and its nop */
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* A store the handler can step over: "mov %al,(%rdx)" (2 bytes) + nop = the 3 bytes it skips. */
static void __attribute__((noinline)) poke(volatile unsigned char *p, unsigned char v)
{
    __asm__ volatile("movb %%al, (%%rdx)\n\tnop" :: "d"(p), "a"(v) : "memory");
}

/* ---------------------------------------------------------------- child: maps what the parent shared */
static int child(int argc, char **argv)
{
    /* argv: child <name> <inherited handle> */
    WCHAR name[64];
    HANDLE hn, hi;
    unsigned char *a, *b;
    int bad = 0;
    if (argc < 4) return 100;
    wcopy(name, argv[2]);
    hn = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, name);
    hi = (HANDLE)(ULONG_PTR)ipc_atoull(argv[3]);
    a = hn ? MapViewOfFile(hn, FILE_MAP_ALL_ACCESS, 0, 0, 0) : 0;
    b = MapViewOfFile(hi, FILE_MAP_WRITE, 0, 0, 4096);
    if (!a || !b) return 101;
    if (memcmp(a, "parent-named", 12)) ++bad;
    if (memcmp(b, "parent-inherited", 16)) ++bad;
    memcpy(a + 4096, "child-was-here", 14);                  /* the parent reads this through its own view */
    b[100] = 0x5a;
    {                                                           /* a handle the parent duplicated into us: value at a+8192 */
        HANDLE hd = *(volatile HANDLE *)(a + 8192);
        unsigned char *c = hd ? MapViewOfFile(hd, FILE_MAP_READ, 0, 0, 0) : 0;
        if (!c || memcmp(c, "duplicated", 10)) bad += 10;
        if (c) UnmapViewOfFile(c);
    }
    UnmapViewOfFile(a);
    UnmapViewOfFile(b);
    CloseHandle(hn);
    return bad;
}

int main(int argc, char **argv)
{
    kstats_t k0, k1;
    HANDLE m, m2, f, hf;
    unsigned char *v1, *v2, *v3;
    MEMORY_BASIC_INFORMATION mbi;
    WCHAR name[64], path[64];
    char args[128], nm[40];
    DWORD n;
    if (argc >= 2 && !strcmp(argv[1], "child")) return child(argc, argv);
    AddVectoredExceptionHandler(1, av_handler);
    CHECK(kstats(&k0), "kernel statistics available");

    /* pagefile-backed, named */
    snprintf(nm, sizeof nm, "Local\\ipcsec_%u", (unsigned)GetCurrentProcessId());
    wcopy(name, nm);
    m = CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 1 * MB, name);
    CHECK(m && GetLastError() == 0, "CreateFileMapping(pagefile, 1 MiB, named)");
    m2 = CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 1 * MB, name);
    CHECK(m2 && m2 != m && GetLastError() == ERROR_ALREADY_EXISTS, "a second create of the name opens it (ERROR_ALREADY_EXISTS)");
    v1 = MapViewOfFile(m, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    v2 = MapViewOfFile(m2, FILE_MAP_ALL_ACCESS, 0, 0, 0);
    CHECK(v1 && v2 && v1 != v2 && ((ULONG_PTR)v1 & 0xffff) == 0, "two views at distinct 64 KiB-aligned addresses");
    CHECK(v1 && v1[0] == 0 && v1[MB - 1] == 0, "a new section reads as zeros");
    if (v1 && v2) {
        memcpy(v1 + 12345, "shared page", 11);
        CHECK(!memcmp(v2 + 12345, "shared page", 11), "a write through one view is visible through the other");
        CHECK(VirtualQuery(v1 + 5000, &mbi, sizeof mbi) && mbi.Type == MEM_MAPPED && mbi.AllocationBase == v1 &&
              mbi.State == MEM_COMMIT && mbi.Protect == PAGE_READWRITE, "VirtualQuery: MEM_MAPPED, committed, read-write");
        CHECK(!VirtualFree(v1, 0, MEM_RELEASE), "VirtualFree refuses a mapped view");
    }
    /* views at an offset, alignment and size errors */
    v3 = MapViewOfFile(m, FILE_MAP_READ, 0, 65536, 8192);
    CHECK(v3 && v1 && (memcpy(v1 + 65536 + 7, "offset", 6), !memcmp(v3 + 7, "offset", 6)), "a view at offset 64 KiB maps that part");
    CHECK(v3 && VirtualQuery(v3, &mbi, sizeof mbi) && mbi.Protect == PAGE_READONLY, "a FILE_MAP_READ view is read-only");
    {
        int it, wrong = 0, last = 0;
        for (it = 0; it < 20 && v3; ++it) {
            g_av = 0;
            poke(v3 + 10 + it, 1);
            if (g_av != 1) { ++wrong; last = (int)g_av; }
        }
        CHECK(v3 && wrong == 0 && v1[65536 + 10] == 's', "a store into a read-only view raises an access violation, 20 of 20 times (%d wrong, last %d)", wrong, last);
    }
    if (v3) UnmapViewOfFile(v3);
    CHECK(!MapViewOfFile(m, FILE_MAP_READ, 0, 4096, 4096) && GetLastError() == ERROR_MAPPED_ALIGNMENT,
          "an offset that is not a multiple of 64 KiB fails with ERROR_MAPPED_ALIGNMENT");
    CHECK(!MapViewOfFile(m, FILE_MAP_READ, 0, 0, 2 * MB), "a view larger than the section fails");
    CHECK(!CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 0, 0) && GetLastError() == ERROR_INVALID_PARAMETER,
          "a pagefile section needs a size");
    /* copy-on-write */
    v3 = MapViewOfFile(m, FILE_MAP_COPY, 0, 0, 0);
    if (v3 && v1) {
        CHECK(!memcmp(v3 + 12345, "shared page", 11), "a copy-on-write view starts with the section's contents");
        v3[12345] = 'S';
        CHECK(v1[12345] == 's' && v3[12345] == 'S', "a write to a copy-on-write view stays private");
        v1[12346] = 'H';
        CHECK(v3[12346] == 'h', "...and that page no longer follows the section");
        CHECK(v3[200000] == 0 && (v1[200000] = 7, v3[200000] == 7), "untouched copy-on-write pages still follow the section");
        UnmapViewOfFile(v3);
    } else CHECK(0, "FILE_MAP_COPY view");
    /* sharing with another process: by name, by inheritance, by duplication */
    {
        SECURITY_ATTRIBUTES sa = { sizeof sa, 0, TRUE };
        HANDLE hinh = CreateFileMappingW(INVALID_HANDLE_VALUE, &sa, PAGE_READWRITE, 0, 65536, 0);
        HANDLE hdup = CreateFileMappingW(INVALID_HANDLE_VALUE, 0, PAGE_READWRITE, 0, 4096, 0);
        unsigned char *vi = hinh ? MapViewOfFile(hinh, FILE_MAP_WRITE, 0, 0, 0) : 0;
        unsigned char *vd = hdup ? MapViewOfFile(hdup, FILE_MAP_WRITE, 0, 0, 0) : 0;
        PROCESS_INFORMATION pi;
        HANDLE ch;
        DWORD code;
        CHECK(vi && vd, "inheritable and private sections mapped");
        if (vi && vd && v1) {
            memcpy(v1, "parent-named", 12);
            memcpy(vi, "parent-inherited", 16);
            memcpy(vd, "duplicated", 10);
            snprintf(args, sizeof args, "child %s %u", nm, (unsigned)(ULONG_PTR)hinh);
            ch = ipc_spawn_self(args, CREATE_SUSPENDED, TRUE, 0, &pi);
            CHECK(ch != 0, "child started suspended with inherited handles");
            if (ch) {
                HANDLE remote = 0;
                CHECK(DuplicateHandle(GetCurrentProcess(), hdup, ch, &remote, FILE_MAP_READ, FALSE, 0) && remote,
                      "DuplicateHandle of a section into the child");
                *(volatile HANDLE *)(v1 + 8192) = remote;
                ResumeThread(pi.hThread);
                CloseHandle(pi.hThread);
                code = ipc_wait_exit(ch, 20000);
                CHECK(code == 0, "the child saw the named, inherited and duplicated sections (exit %u)", (unsigned)code);
                CHECK(!memcmp(v1 + 4096, "child-was-here", 14) && vi[100] == 0x5a, "the child's writes reached the parent's views");
                CloseHandle(ch);
            }
        }
        if (vi) UnmapViewOfFile(vi);
        if (vd) UnmapViewOfFile(vd);
        CloseHandle(hinh);
        CloseHandle(hdup);
    }
    if (v1) CHECK(UnmapViewOfFile(v1), "UnmapViewOfFile");
    CHECK(v1 && VirtualQuery(v1, &mbi, sizeof mbi) && mbi.State == MEM_FREE, "the unmapped range is free again");
    CHECK(!UnmapViewOfFile(v1) && GetLastError() == ERROR_INVALID_ADDRESS, "unmapping it twice fails with ERROR_INVALID_ADDRESS");
    if (v2) UnmapViewOfFile(v2);
    CloseHandle(m);
    CloseHandle(m2);
    CHECK(!OpenFileMappingW(FILE_MAP_READ, FALSE, name) && GetLastError() == ERROR_FILE_NOT_FOUND,
          "the name disappears with the last handle and view");

    /* file-backed */
    snprintf(nm, sizeof nm, "C:\\TEMP\\ipcsec%u.bin", (unsigned)GetCurrentProcessId());
    wcopy(path, nm);
    CreateDirectoryW(L"C:\\TEMP", 0);
    f = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    CHECK(f != INVALID_HANDLE_VALUE && WriteFile(f, "hello mapping", 13, &n, 0) && n == 13, "a 13-byte file");
    CHECK(!CreateFileMappingW(f, 0, PAGE_READONLY, 0, 8192, 0), "a read-only mapping cannot be larger than the file");
    hf = CreateFileMappingW(f, 0, PAGE_READWRITE, 0, 8192, 0);
    CHECK(hf != 0, "a read-write mapping of 8192 bytes");
    CHECK(GetFileSize(f, 0) == 8192, "...extends the file to 8192 bytes (%u)", (unsigned)GetFileSize(f, 0));
    v1 = hf ? MapViewOfFile(hf, FILE_MAP_WRITE, 0, 0, 0) : 0;
    CHECK(v1 && !memcmp(v1, "hello mapping", 13) && v1[13] == 0, "the view shows the file's contents");
    if (v1) {
        char back[8];
        memcpy(v1 + 5000, "WORLD", 5);
        CHECK(FlushViewOfFile(v1 + 5000, 5), "FlushViewOfFile");
        SetFilePointer(f, 5000, 0, FILE_BEGIN);
        CHECK(ReadFile(f, back, 5, &n, 0) && n == 5 && !memcmp(back, "WORLD", 5), "ReadFile sees the flushed view write");
        memcpy(v1 + 6000, "LATER", 5);
        UnmapViewOfFile(v1);
        SetFilePointer(f, 6000, 0, FILE_BEGIN);
        CHECK(ReadFile(f, back, 5, &n, 0) && n == 5 && !memcmp(back, "LATER", 5), "unmapping writes the view back");
    }
    CloseHandle(hf);
    {
        HANDLE ro = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
        CHECK(ro != INVALID_HANDLE_VALUE && !CreateFileMappingW(ro, 0, PAGE_READWRITE, 0, 0, 0) && GetLastError() == ERROR_ACCESS_DENIED,
              "a read-write mapping of a read-only handle fails with ERROR_ACCESS_DENIED");
        hf = CreateFileMappingW(ro, 0, PAGE_READONLY, 0, 0, 0);
        v1 = hf ? MapViewOfFile(hf, FILE_MAP_READ, 0, 0, 0) : 0;
        CHECK(v1 && !memcmp(v1 + 5000, "WORLD", 5), "a read-only mapping (size 0 = the file's size)");
        if (v1) UnmapViewOfFile(v1);
        CloseHandle(hf);
        CloseHandle(ro);
    }
    CloseHandle(f);
    f = CreateFileW(L"C:\\TEMP\\ipcsec_empty.bin", GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
    CHECK(!CreateFileMappingW(f, 0, PAGE_READWRITE, 0, 0, 0) && GetLastError() == ERROR_FILE_INVALID,
          "mapping an empty file with size 0 fails with ERROR_FILE_INVALID");
    CloseHandle(f);
    DeleteFileW(L"C:\\TEMP\\ipcsec_empty.bin");
    CHECK(DeleteFileW(path), "the mapped file can be deleted once its mapping is gone");

    /* leaks */
    CHECK(kstats(&k1), "kernel statistics after");
    CHECK(k1.sections == k0.sections && k1.views == k0.views, "no section or view leaked (%llu/%llu -> %llu/%llu)",
          k0.sections, k0.views, k1.sections, k1.views);
    CHECK(k1.pmm_free + 16 >= k0.pmm_free, "physical pages returned (%llu -> %llu)", k0.pmm_free, k1.pmm_free);
    printf("%s: %d check(s) failed\n", g_bad ? "FAIL" : "PASS", g_bad);
    return g_bad;
}
