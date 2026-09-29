/* SPDX-License-Identifier: GPL-2.0-only
 * Shared helpers of the t_blk_*.c raw block-device programs: the native syscalls of kernel64/sysblk.c (ntdll stubs are
 * generated from SYSCALL_LIST_BLK), the NtShzBlkQuery layout, a table CRC-32 (zlib compatible) and the write pattern
 * the host re-generates (tests/blk_images.py: app_pattern). Every check prints PASS:/FAIL:; the exit code is the number
 * of failures, and without NVMe/SDHCI devices (plain runner, Supervisor profile) the programs print SKIP and exit 0. */
#ifndef SHZ_BLKTEST_H
#define SHZ_BLKTEST_H
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "shzcrt.h"

typedef LONG NTSTATUS;

struct shz_blk_info {                                   /* kernel64/sysblk.c (static-asserted 264 bytes there) */
    unsigned long long sectors, start_lba;
    unsigned long long read_sectors, write_sectors, read_ops, write_ops, flushes, discards, errors;
    unsigned sector_size, flags, queue_depth, max_sectors;
    unsigned reg_index, parent, part_index, part_scheme;
    unsigned scan_notes;
    int scan_result;
    char name[16], driver[8], irq_mode[8];
    char model[41], serial[21], part_name[37];
    unsigned char mbr_type;
    unsigned char type_guid[16];
};
typedef char blk_info_size_check[sizeof(struct shz_blk_info) == 264 ? 1 : -1];

struct shz_blk_io {
    unsigned op, count;                                 /* op: 0 read, 1 write; count in sectors */
    unsigned long long lba, buf;
    NTSTATUS status;
    unsigned reserved;
};

#define BLKF_READONLY 1u
#define BLKF_PARTITION 2u
#define BLKF_REMOVABLE 4u
#define BLKF_MOUNTED 8u
#define BLKF_FLUSH 16u
#define BLKF_DISCARD 32u
enum { CTL_RESET = 1, CTL_TIMEOUT_TEST = 2, CTL_IRQ_MODE = 3, CTL_STATS = 4, CTL_SET_TIMEOUT_MS = 5, CTL_XFER_MODE = 6,
       CTL_ERROR_TEST = 7 };

NTSTATUS __stdcall NtShzBlkQuery(ULONG index, struct shz_blk_info *info, ULONG len, PULONG ret);
NTSTATUS __stdcall NtShzBlkRead(ULONG index, ULONG64 lba, ULONG count, PVOID buf);
NTSTATUS __stdcall NtShzBlkWrite(ULONG index, ULONG64 lba, ULONG count, const void *buf);
NTSTATUS __stdcall NtShzBlkFlush(ULONG index);
NTSTATUS __stdcall NtShzBlkBatch(ULONG index, struct shz_blk_io *ios, ULONG n, ULONG flags);
NTSTATUS __stdcall NtShzBlkControl(ULONG index, ULONG op, ULONG64 arg, ULONG64 *out4);
NTSTATUS __stdcall NtShzBlkDiscard(ULONG index, ULONG64 lba, ULONG count);

static int g_bad, g_checks;
#define CHECK(cond, ...) do { ++g_checks; if (cond) { printf("PASS: " __VA_ARGS__); printf("\n"); } \
                              else { printf("FAIL: " __VA_ARGS__); printf("\n"); ++g_bad; } } while (0)

static unsigned crc_tab[256];
static unsigned crc32_update(unsigned crc, const void *data, size_t n)
{
    const unsigned char *p = data;
    if (!crc_tab[1]) {
        unsigned i, j;
        for (i = 0; i < 256; ++i) {
            unsigned c = i;
            for (j = 0; j < 8; ++j) c = (c & 1) ? 0xedb88320u ^ (c >> 1) : c >> 1;
            crc_tab[i] = c;
        }
    }
    crc = ~crc;
    while (n--) crc = crc_tab[(crc ^ *p++) & 0xff] ^ (crc >> 8);
    return ~crc;
}

/* Byte i of the 512-byte unit u (absolute byte offset / 512 on the whole device): ((u ^ tag) * 31 + i * 17 + (i >> 5)). */
static void app_fill(unsigned char *p, unsigned long long unit, unsigned long long bytes, unsigned tag)
{
    unsigned long long s;
    unsigned i;
    for (s = 0; s < bytes / 512; ++s) {
        const unsigned base = (unsigned)(((unit + s) ^ tag) * 31u);
        for (i = 0; i < 512; ++i) p[s * 512 + i] = (unsigned char)(base + i * 17u + (i >> 5));
    }
}

static unsigned long long now_ms(void)
{
    LARGE_INTEGER c, f;
    QueryPerformanceCounter(&c);
    QueryPerformanceFrequency(&f);
    return (unsigned long long)c.QuadPart / ((unsigned long long)f.QuadPart / 1000u);
}

static void *big_alloc(size_t n) { return VirtualAlloc(0, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }
static void big_free(void *p) { if (p) VirtualFree(p, 0, MEM_RELEASE); }

static int blk_list(struct shz_blk_info *out, int cap)
{
    int n = 0;
    ULONG ret = 0;
    while (n < cap && NtShzBlkQuery((ULONG)n, &out[n], sizeof out[n], &ret) == 0) ++n;
    return n;
}

static int is_storage_driver(const struct shz_blk_info *d)
{
    return !strcmp(d->driver, "nvme") || !strcmp(d->driver, "sdhci");
}

static unsigned name_tag(const char *s)
{
    unsigned h = 2166136261u;
    while (*s) h = (h ^ (unsigned char)*s++) * 16777619u;
    return h & 0xff;
}
#endif
