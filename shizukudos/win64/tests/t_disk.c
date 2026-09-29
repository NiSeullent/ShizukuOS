/* SPDX-License-Identifier: GPL-2.0-only
 * D:\ (read-only FAT32 volume on the AHCI disk, standalone profile) seen from user mode through kernel32:
 * directory enumeration, file attributes/sizes/times, sequential and random-offset reads, CRC-32 of every file in
 * D:\TESTS. Every value is printed as a "DISK-..." line for tests/run_k64_disk.py, which recomputes it from the
 * files it packed into the image. Without a D: volume (plain run_k64_standalone.py, Supervisor profile) the test
 * prints SKIP and exits 0, so the app list stays green in both runners. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "u_check.h"

/* Native directory enumeration (ntdll): FindFirstFile in this system's kernel32 reads FILE_BOTH_DIR_INFORMATION's
 * FileName at offset 92 instead of the documented 94 (reported to the kernel32 owners); the kernel writes the
 * Windows layout, so this test reads it directly through NtQueryDirectoryFile. */
typedef LONG NTSTATUS;
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } N_USTR;
typedef struct { ULONG Length; HANDLE RootDirectory; N_USTR *ObjectName; ULONG Attributes; PVOID sd, sqos; } N_OA;
typedef struct { ULONG_PTR Status; ULONG_PTR Information; } N_IOSB;
NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, N_OA *, N_IOSB *, ULONG, ULONG);
NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE, HANDLE, PVOID, PVOID, N_IOSB *, PVOID, ULONG, ULONG, BOOLEAN, N_USTR *, BOOLEAN);
NTSTATUS NTAPI NtClose(HANDLE);
#define N_FILE_DIRECTORY_FILE 1
#define N_STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006)

typedef struct { char name[260]; unsigned long long size, mtime; unsigned attrs; } dent_t;

/* Lists one directory ("\\??\\D:\\TESTS") into out[]; returns the count or -1. */
static int list_dir(const wchar_t *ntpath, dent_t *out, int cap)
{
    static unsigned char buf[8192];
    N_USTR us;
    N_OA oa;
    N_IOSB iosb;
    HANDLE h;
    NTSTATUS st;
    int n = 0, first = 1;
    unsigned i;
    for (i = 0; ntpath[i]; ++i) ;
    us.Buffer = (PWSTR)ntpath; us.Length = (USHORT)(i * 2); us.MaximumLength = us.Length + 2;
    memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &us;
    st = NtOpenFile(&h, FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, N_FILE_DIRECTORY_FILE);
    if (st) { printf("FAIL: NtOpenFile directory: %x\n", (unsigned)st); return -1; }
    for (;;) {
        unsigned off = 0;
        st = NtQueryDirectoryFile(h, 0, 0, 0, &iosb, buf, sizeof buf, 3 /* FileBothDirectoryInformation */, FALSE, 0, first);
        first = 0;
        if (st == N_STATUS_NO_MORE_FILES) break;
        if (st) { printf("FAIL: NtQueryDirectoryFile: %x\n", (unsigned)st); NtClose(h); return -1; }
        for (;;) {
            const unsigned char *e = buf + off;
            const ULONG next = *(const ULONG *)e, nlen = *(const ULONG *)(e + 60);
            const WCHAR *w = (const WCHAR *)(e + 94);
            if (n < cap) {
                for (i = 0; i < nlen / 2 && i < 259; ++i) out[n].name[i] = w[i] < 0x80 ? (char)w[i] : '?';
                out[n].name[i] = 0;
                out[n].size = *(const unsigned long long *)(e + 40);
                out[n].mtime = *(const unsigned long long *)(e + 24);
                out[n].attrs = *(const ULONG *)(e + 56);
                ++n;
            }
            if (!next) break;
            off += next;
        }
    }
    NtClose(h);
    return n;
}

static uint32_t crc_update(uint32_t crc, const void *data, size_t n)
{
    const unsigned char *p = data;
    crc = ~crc;
    while (n--) {
        int b;
        crc ^= *p++;
        for (b = 0; b < 8; ++b) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

static uint32_t hash_file(const char *path, unsigned long long *size_out, int *ok)
{
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    static unsigned char buf[65536];
    uint32_t crc = 0;
    DWORD got;
    LARGE_INTEGER sz;
    *ok = 0;
    if (h == INVALID_HANDLE_VALUE) { printf("FAIL: CreateFile %s: %u\n", path, (unsigned)GetLastError()); return 0; }
    if (!GetFileSizeEx(h, &sz)) { printf("FAIL: GetFileSizeEx %s\n", path); CloseHandle(h); return 0; }
    *size_out = (unsigned long long)sz.QuadPart;
    for (;;) {
        if (!ReadFile(h, buf, sizeof buf, &got, 0)) { printf("FAIL: ReadFile %s: %u\n", path, (unsigned)GetLastError()); CloseHandle(h); return 0; }
        if (!got) break;
        crc = crc_update(crc, buf, got);
    }
    /* random-offset read: 3000 bytes from an unaligned offset in the middle */
    if (sz.QuadPart > 8192) {
        LARGE_INTEGER off;
        off.QuadPart = sz.QuadPart / 2 - 1234;
        if (off.QuadPart < 0) off.QuadPart = 1;
        if (SetFilePointerEx(h, off, 0, FILE_BEGIN) && ReadFile(h, buf, 3000, &got, 0))
            printf("DISK-RANGE %s %llu %u %x\n", path, (unsigned long long)off.QuadPart, (unsigned)got, crc_update(0, buf, got));
        else
            printf("FAIL: range read %s\n", path);
    }
    CloseHandle(h);
    *ok = 1;
    return crc;
}

int main(void)
{
    static dent_t ents[64];
    int n, i;
    unsigned entries = 0, hashed = 0;
    uint32_t xor_crc = 0;
    DWORD attrs = GetFileAttributesA("D:\\");
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        printf("SKIP: no D: volume (GetFileAttributes error %u)\n", (unsigned)GetLastError());
        return 0;
    }
    U_CHECK("D:\\ is a directory", attrs & FILE_ATTRIBUTE_DIRECTORY);
    U_CHECK("D:\\TESTS exists", GetFileAttributesA("D:\\TESTS") != INVALID_FILE_ATTRIBUTES);
    U_CHECK("D:\\NOSUCH does not exist", GetFileAttributesA("D:\\NOSUCH") == INVALID_FILE_ATTRIBUTES && GetLastError() == ERROR_FILE_NOT_FOUND);
    U_CHECK("E:\\ is not mounted", GetFileAttributesA("E:\\") == INVALID_FILE_ATTRIBUTES);
    U_CHECK("D: is read-only: CreateFile for writing fails",
            CreateFileA("D:\\TESTS\\new.txt", GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0) == INVALID_HANDLE_VALUE);
    n = list_dir(L"\\??\\D:\\TESTS", ents, 64);
    U_CHECK("NtQueryDirectoryFile on D:\\TESTS", n > 0);
    for (i = 0; i < n; ++i) {
        char path[300];
        ++entries;
        printf("DISK-DIR %s %llu %x %08x%08x\n", ents[i].name, ents[i].size, ents[i].attrs,
               (unsigned)(ents[i].mtime >> 32), (unsigned)ents[i].mtime);
        if (!(ents[i].attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            unsigned long long size = 0;
            int ok;
            uint32_t crc;
            snprintf(path, sizeof path, "D:\\TESTS\\%s", ents[i].name);
            crc = hash_file(path, &size, &ok);
            if (ok) {
                printf("DISK-CRC %s %llu %x\n", ents[i].name, size, crc);
                ++hashed;
                xor_crc ^= crc;
                if (size != ents[i].size) { printf("FAIL: size mismatch for %s\n", ents[i].name); ++u_failures; }
            } else {
                ++u_failures;
            }
        }
    }
    /* a nested directory reached through a long, mixed-case path */
    {
        HANDLE h = CreateFileA("D:\\TESTS\\Sub Directory\\nested file.txt", GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
        char buf[64];
        DWORD got = 0;
        U_CHECK("open D:\\TESTS\\Sub Directory\\nested file.txt (LFN path)", h != INVALID_HANDLE_VALUE);
        if (h != INVALID_HANDLE_VALUE) {
            ReadFile(h, buf, sizeof buf - 1, &got, 0);
            buf[got] = 0;
            printf("DISK-NESTED %u %x\n", (unsigned)got, crc_update(0, buf, got));
            CloseHandle(h);
        }
        U_CHECK("case-insensitive lookup on D:", GetFileAttributesA("d:\\tests\\SUB DIRECTORY\\NESTED FILE.TXT") != INVALID_FILE_ATTRIBUTES);
    }
    printf("DISK-SUMMARY %u %u %x\n", entries, hashed, xor_crc);
    shz_evidence(18, ((unsigned long long)hashed << 32) | xor_crc);   /* user slots are 16..23 */
    return u_finish("t_disk");
}
