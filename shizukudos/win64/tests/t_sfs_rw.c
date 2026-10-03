/* SPDX-License-Identifier: GPL-2.0-only
 * ShizukuFS (ext4-format) volume seen from user mode through kernel32/ntdll: finds the drive holding \SFSTEST
 * (packed by tests/run_k64_sfs.py with mkfs.ext4 -d), lists and hashes every packed file, reads ranges, then
 * writes: directories, new files (odd-sized chunks, a 3 MiB file, a sparse extension), in-place overwrite and
 * append of a host file, truncation, rename within and across directories, rename over an existing file, delete
 * (DeleteFile and delete-on-close), rmdir, 300 small files in one directory (index conversion), deleting a third
 * of them, NtFlushBuffersFile. Every value is printed as an "SFS-..." line; the host recomputes them from its own
 * files and, after QEMU exits, checks the partition with e2fsck -fn and reads every guest-written file back with
 * debugfs. Without a \SFSTEST volume (any other run) the test prints SKIP and exits 0.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "u_check.h"

typedef LONG NTSTATUS;
typedef struct { USHORT Length, MaximumLength; PWSTR Buffer; } N_USTR;
typedef struct { ULONG Length; HANDLE RootDirectory; N_USTR *ObjectName; ULONG Attributes; PVOID sd, sqos; } N_OA;
typedef struct { ULONG_PTR Status; ULONG_PTR Information; } N_IOSB;
NTSTATUS NTAPI NtOpenFile(PHANDLE, ACCESS_MASK, N_OA *, N_IOSB *, ULONG, ULONG);
NTSTATUS NTAPI NtCreateFile(PHANDLE, ACCESS_MASK, N_OA *, N_IOSB *, PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
NTSTATUS NTAPI NtQueryDirectoryFile(HANDLE, HANDLE, PVOID, PVOID, N_IOSB *, PVOID, ULONG, ULONG, BOOLEAN, N_USTR *, BOOLEAN);
NTSTATUS NTAPI NtClose(HANDLE);
NTSTATUS NTAPI NtFlushBuffersFile(HANDLE, N_IOSB *);
#define N_FILE_DIRECTORY_FILE 1
#define N_FILE_NON_DIRECTORY_FILE 0x40
#define N_FILE_DELETE_ON_CLOSE 0x1000
#define N_FILE_CREATE 2
#define N_STATUS_NO_MORE_FILES ((NTSTATUS)0x80000006)

static char drive = 0;

static uint32_t crc_update(uint32_t crc, const void *data, size_t n)
{
    const unsigned char *p = data;
    size_t i;
    int k;
    crc = ~crc;
    for (i = 0; i < n; ++i) {
        crc ^= p[i];
        for (k = 0; k < 8; ++k) crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
    }
    return ~crc;
}

/* The host's pattern(seed, n) (tests/run_k64_sfs.py): an LCG emitting 4 little-endian bytes per step. */
static void pattern(uint32_t seed, unsigned char *out, size_t n)
{
    uint32_t x = seed;
    size_t i;
    for (i = 0; i < n; i += 4) {
        size_t k;
        x = x * 1103515245u + 12345u;
        for (k = 0; k < 4 && i + k < n; ++k) out[i + k] = (unsigned char)(x >> (8 * k));
    }
}

static const char *P(const char *rel)
{
    static char bufs[4][300];
    static int w;
    char *b = bufs[w++ & 3];
    snprintf(b, 300, "%c:\\%s", drive, rel);
    return b;
}

static const wchar_t *NTP(const char *rel)
{
    static wchar_t bufs[2][300];
    static int w;
    wchar_t *b = bufs[w++ & 1];
    const char *pre = "\\??\\";
    unsigned i = 0, j;
    for (j = 0; pre[j]; ++j) b[i++] = (wchar_t)pre[j];
    b[i++] = (wchar_t)drive;
    b[i++] = ':';
    b[i++] = '\\';
    for (j = 0; rel[j] && i < 298; ++j) b[i++] = (wchar_t)(unsigned char)rel[j];
    b[i] = 0;
    return b;
}

typedef struct { char name[260]; unsigned long long size; unsigned attrs; } dent_t;

static int list_dir(const wchar_t *ntpath, dent_t *out, int cap)
{
    static unsigned char buf[16384];
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
                out[n].attrs = *(const ULONG *)(e + 56);
            }
            ++n;
            if (!next) break;
            off += next;
        }
    }
    NtClose(h);
    return n;
}

static int hash_file(const char *path, unsigned long long *size, uint32_t *crc)
{
    static unsigned char buf[65536];
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
    DWORD got;
    *size = 0;
    *crc = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    for (;;) {
        if (!ReadFile(h, buf, sizeof buf, &got, 0)) { CloseHandle(h); return 0; }
        if (!got) break;
        *crc = crc_update(*crc, buf, got);
        *size += got;
    }
    CloseHandle(h);
    return 1;
}

static int write_file(const char *path, const unsigned char *p, DWORD n, int odd_chunks, DWORD disposition)
{
    HANDLE h = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 0, 0, disposition, 0, 0);
    DWORD chunk = 1, done = 0, got;
    if (h == INVALID_HANDLE_VALUE) return 0;
    while (done < n) {
        DWORD c = odd_chunks ? chunk : (n - done > 65536 ? 65536 : n - done);
        if (c > n - done) c = n - done;
        if (!WriteFile(h, p + done, c, &got, 0) || got != c) { CloseHandle(h); return 0; }
        done += c;
        chunk = chunk * 3 + 511;
        if (chunk > 70000) chunk = 1;
    }
    CloseHandle(h);
    return 1;
}

static void read_tests(void)
{
    static dent_t ents[64];
    static unsigned char buf[4096];
    int n, i;
    unsigned hashed = 0;
    n = list_dir(NTP("SFSTEST"), ents, 64);
    U_CHECKF("NtQueryDirectoryFile on \\SFSTEST", n > 0, "%d", n);
    for (i = 0; i < n && i < 64; ++i) {
        printf("SFS-DIR %s %llu %x\n", ents[i].name, ents[i].size, ents[i].attrs);
        if (!(ents[i].attrs & FILE_ATTRIBUTE_DIRECTORY)) {
            char rel[300];
            unsigned long long size;
            uint32_t crc;
            snprintf(rel, sizeof rel, "SFSTEST\\%s", ents[i].name);
            if (hash_file(P(rel), &size, &crc)) {
                printf("SFS-CRC %s %llu %x\n", ents[i].name, size, crc);
                ++hashed;
                if (size != ents[i].size) { printf("FAIL: size mismatch for %s\n", ents[i].name); ++u_failures; }
            } else {
                printf("FAIL: read %s\n", ents[i].name);
                ++u_failures;
            }
        }
    }
    U_CHECK("every packed file read", hashed >= 6);
    {
        unsigned long long size;
        uint32_t crc;
        U_CHECK("nested file via a path with spaces", hash_file(P("SFSTEST\\Sub Dir\\nested file.txt"), &size, &crc));
        printf("SFS-NESTED %llu %x\n", size, crc);
        U_CHECK("case-insensitive lookup", GetFileAttributesA(P("sfstest\\SUB DIR\\NESTED FILE.TXT")) != INVALID_FILE_ATTRIBUTES);
    }
    {
        HANDLE h = CreateFileA(P("SFSTEST\\pattern_1m.bin"), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
        LARGE_INTEGER off;
        DWORD got = 0;
        off.QuadPart = 777777;
        U_CHECK("random-offset read", h != INVALID_HANDLE_VALUE && SetFilePointerEx(h, off, 0, FILE_BEGIN) &&
                ReadFile(h, buf, 3000, &got, 0) && got == 3000);
        printf("SFS-RANGE 777777 %u %x\n", (unsigned)got, crc_update(0, buf, got));
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }
}

static void write_tests(void)
{
    static unsigned char buf[3 << 20];
    static const char *const outs[] = {
        "OUT\\Sub Dir\\renamed small.txt", "OUT\\victim.txt", "OUT\\big_3m.bin", "OUT\\sparse.bin",
        "SFSTEST\\modify.bin", "SFSTEST\\trunc.bin", "OUT\\moved from root.txt",
    };
    HANDLE h;
    DWORD got;
    LARGE_INTEGER off;
    N_IOSB iosb;
    NTSTATUS st;
    unsigned i, n_many = 0, n_del = 0;
    U_CHECK("CreateDirectory OUT", CreateDirectoryA(P("OUT"), 0));
    U_CHECK("CreateDirectory OUT\\Sub Dir", CreateDirectoryA(P("OUT\\Sub Dir"), 0));
    U_CHECK("CreateDirectory OUT again fails", !CreateDirectoryA(P("OUT"), 0) && GetLastError() == ERROR_ALREADY_EXISTS);
    {
        static const char text[] = "written by T_SFS_RW.EXE on ShizukuFS\r\n";
        U_CHECK("write OUT\\small.txt", write_file(P("OUT\\small.txt"), (const unsigned char *)text, sizeof text - 1, 0, CREATE_NEW));
    }
    pattern(21, buf, 300000);
    U_CHECK("write OUT\\pattern_300k.bin in odd chunks", write_file(P("OUT\\pattern_300k.bin"), buf, 300000, 1, CREATE_NEW));
    pattern(22, buf, 3 << 20);
    U_CHECK("write OUT\\big_3m.bin (3 MiB)", write_file(P("OUT\\big_3m.bin"), buf, 3 << 20, 0, CREATE_NEW));
    /* sparse: 4000 bytes at 10 MiB into a new file */
    h = CreateFileA(P("OUT\\sparse.bin"), GENERIC_WRITE, 0, 0, CREATE_NEW, 0, 0);
    U_CHECK("create OUT\\sparse.bin", h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        pattern(23, buf, 4000);
        off.QuadPart = 10 << 20;
        U_CHECK("write 4000 bytes at 10 MiB", SetFilePointerEx(h, off, 0, FILE_BEGIN) && WriteFile(h, buf, 4000, &got, 0) && got == 4000);
        CloseHandle(h);
    }
    /* in place: 100 bytes of 0xAB at 5000 of the 20000-byte host file, then 5000 bytes appended */
    h = CreateFileA(P("SFSTEST\\modify.bin"), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    U_CHECK("open SFSTEST\\modify.bin for writing", h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        memset(buf, 0xAB, 100);
        off.QuadPart = 5000;
        U_CHECK("overwrite 100 bytes at 5000", SetFilePointerEx(h, off, 0, FILE_BEGIN) && WriteFile(h, buf, 100, &got, 0) && got == 100);
        pattern(31, buf, 5000);
        off.QuadPart = 0;
        U_CHECK("append 5000 bytes", SetFilePointerEx(h, off, 0, FILE_END) && WriteFile(h, buf, 5000, &got, 0) && got == 5000);
        CloseHandle(h);
    }
    /* truncation of the 100000-byte host file to 777 bytes */
    h = CreateFileA(P("SFSTEST\\trunc.bin"), GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    U_CHECK("open SFSTEST\\trunc.bin", h != INVALID_HANDLE_VALUE);
    if (h != INVALID_HANDLE_VALUE) {
        off.QuadPart = 777;
        U_CHECK("SetEndOfFile at 777", SetFilePointerEx(h, off, 0, FILE_BEGIN) && SetEndOfFile(h));
        CloseHandle(h);
    }
    /* renames: into a subdirectory with a new name, over an existing file, a host file out of SFSTEST */
    U_CHECK("MoveFile small.txt -> Sub Dir\\renamed small.txt", MoveFileA(P("OUT\\small.txt"), P("OUT\\Sub Dir\\renamed small.txt")));
    U_CHECK("old name gone after rename", GetFileAttributesA(P("OUT\\small.txt")) == INVALID_FILE_ATTRIBUTES);
    {
        static const char v[] = "victim";
        U_CHECK("write OUT\\victim.txt", write_file(P("OUT\\victim.txt"), (const unsigned char *)v, 6, 0, CREATE_NEW));
    }
    U_CHECK("MoveFile without REPLACE onto an existing file fails", !MoveFileA(P("OUT\\pattern_300k.bin"), P("OUT\\victim.txt")));
    {
        wchar_t a[300], b[300];
        U_CHECK("MoveFileEx REPLACE_EXISTING over victim.txt",
                MoveFileExW(u_wide(P("OUT\\pattern_300k.bin"), a, 300), u_wide(P("OUT\\victim.txt"), b, 300), MOVEFILE_REPLACE_EXISTING));
    }
    U_CHECK("MoveFile SFSTEST\\move_me.txt -> OUT\\moved from root.txt", MoveFileA(P("SFSTEST\\move_me.txt"), P("OUT\\moved from root.txt")));
    /* deletes */
    U_CHECK("DeleteFile SFSTEST\\delete_me.bin (host file)", DeleteFileA(P("SFSTEST\\delete_me.bin")));
    U_CHECK("deleted file is gone", GetFileAttributesA(P("SFSTEST\\delete_me.bin")) == INVALID_FILE_ATTRIBUTES);
    {
        /* delete-on-close through NtCreateFile */
        N_USTR us;
        N_OA oa;
        HANDLE hd;
        const wchar_t *np = NTP("OUT\\temp_delete_on_close.tmp");
        unsigned k;
        for (k = 0; np[k]; ++k) ;
        us.Buffer = (PWSTR)np; us.Length = (USHORT)(k * 2); us.MaximumLength = us.Length + 2;
        memset(&oa, 0, sizeof oa); oa.Length = sizeof oa; oa.ObjectName = &us;
        st = NtCreateFile(&hd, GENERIC_WRITE | DELETE | SYNCHRONIZE, &oa, &iosb, 0, 0, 0, N_FILE_CREATE,
                          N_FILE_NON_DIRECTORY_FILE | N_FILE_DELETE_ON_CLOSE, 0, 0);
        U_CHECKF("NtCreateFile FILE_DELETE_ON_CLOSE", st == 0, "%x", (unsigned)st);
        if (!st) {
            WriteFile(hd, "tmp", 3, &got, 0);
            NtClose(hd);
        }
        U_CHECK("delete-on-close file is gone after close", GetFileAttributesA(P("OUT\\temp_delete_on_close.tmp")) == INVALID_FILE_ATTRIBUTES);
    }
    U_CHECK("CreateDirectory OUT\\empty dir", CreateDirectoryA(P("OUT\\empty dir"), 0));
    U_CHECK("RemoveDirectory OUT\\empty dir", RemoveDirectoryA(P("OUT\\empty dir")));
    U_CHECK("RemoveDirectory of a non-empty directory fails", !RemoveDirectoryA(P("OUT\\Sub Dir")));
    /* 300 small files in one directory (the directory index is created and split), a third deleted again */
    U_CHECK("CreateDirectory OUT\\many", CreateDirectoryA(P("OUT\\many"), 0));
    for (i = 0; i < 300; ++i) {
        char rel[64], text[64];
        int len = snprintf(text, sizeof text, "file number %u\r\n", i);
        snprintf(rel, sizeof rel, "OUT\\many\\file_with_a_long_name_%03u.txt", i);
        if (write_file(P(rel), (const unsigned char *)text, (DWORD)len, 0, CREATE_NEW)) ++n_many;
    }
    U_CHECKF("300 files created in OUT\\many", n_many == 300, "%u", n_many);
    for (i = 0; i < 300; i += 3) {
        char rel[64];
        snprintf(rel, sizeof rel, "OUT\\many\\file_with_a_long_name_%03u.txt", i);
        if (DeleteFileA(P(rel))) ++n_del;
    }
    U_CHECKF("100 of them deleted", n_del == 100, "%u", n_del);
    {
        static dent_t ents[8];
        int n = list_dir(NTP("OUT\\many"), ents, 8);
        U_CHECKF("OUT\\many lists 200 entries", n == 200, "%d", n);
        printf("SFS-MANY %d\n", n);
    }
    h = CreateFileA(P("OUT\\big_3m.bin"), GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (h != INVALID_HANDLE_VALUE) {
        st = NtFlushBuffersFile(h, &iosb);
        U_CHECKF("NtFlushBuffersFile (commit, checkpoint, device flush)", st == 0, "status %x", (unsigned)st);
        CloseHandle(h);
    }
    for (i = 0; i < sizeof outs / sizeof outs[0]; ++i) {
        unsigned long long size;
        uint32_t crc;
        int ok = hash_file(P(outs[i]), &size, &crc);
        U_CHECK("read back a written file", ok);
        printf("SFS-WRITE %s %llu %x\n", outs[i], size, crc);
    }
}

/* Real PE fixture; these assertions need run_k64_sfs.py guest execution.
 * Host callback tests and compilation alone do not establish this result. */
static void volume_tests(void)
{
    char label[32] = {0}, filesystem[32] = {0};
    DWORD serial = 0, max_component = 0, flags = 0, spc = 0, bps = 0, free_units = 0, units = 0;
    ULARGE_INTEGER available = {0}, total = {0}, free_bytes = {0};
    U_CHECK("SFS volume metadata query", GetVolumeInformationA(P(""), label, sizeof label, &serial,
            &max_component, &flags, filesystem, sizeof filesystem));
    U_CHECK("SFS filesystem type and on-disk label", !strcmp(filesystem, "SHIZUKUFS") && !strcmp(label, "SHZSFS"));
    U_CHECK("SFS writable fixture reports supported capabilities", max_component == 127 &&
            (flags & (FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK)) ==
            (FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK) && !(flags & (FILE_READ_ONLY_VOLUME | FILE_PERSISTENT_ACLS | FILE_FILE_COMPRESSION)));
    U_CHECK("SFS byte capacity comes from disk, not kernel heap", GetDiskFreeSpaceExA(P(""), &available, &total, &free_bytes) &&
            total.QuadPart > 32u * 1024u * 1024u && available.QuadPart <= free_bytes.QuadPart && free_bytes.QuadPart <= total.QuadPart);
    U_CHECK("SFS allocation-unit query", GetDiskFreeSpaceA(P(""), &spc, &bps, &free_units, &units));
    U_CHECK("SFS allocation units agree with byte capacity", bps == 512 && spc == 8 &&
            (ULONGLONG)units * spc * bps == total.QuadPart && (ULONGLONG)free_units * spc * bps == free_bytes.QuadPart);
}

int main(void)
{
    char l;
    for (l = 'D'; l <= 'Z' && !drive; ++l) {
        char probe[32];
        snprintf(probe, sizeof probe, "%c:\\SFSTEST\\README.TXT", l);
        if (GetFileAttributesA(probe) != INVALID_FILE_ATTRIBUTES) drive = l;
    }
    if (!drive) {
        printf("SKIP: no ShizukuFS test volume (no ?:\\SFSTEST\\README.TXT)\n");
        return 0;
    }
    printf("SFS-DRIVE %c\n", drive);
    volume_tests();
    read_tests();
    write_tests();
    return u_finish("t_sfs_rw");
}
