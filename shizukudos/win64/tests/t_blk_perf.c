/* SPDX-License-Identifier: GPL-2.0-only
 * Raw NVMe / SD throughput from user mode (kernel64/sysblk.c), measured with QueryPerformanceCounter (1 ms ticks):
 *   sequential read of 64 MiB from LBA 0 in 1 MiB system calls,
 *   sequential write of 16 MiB (NVMe: 64 MiB) into the device's perf area (1/2 of the device) in 1 MiB calls, then
 *   the write is read back and CRC-checked,
 *   random 4 KiB reads over the first 64 MiB: 1024 at queue depth 1 (one call each) and 4096 at queue depth 32
 *   (NtShzBlkBatch of 32).
 * Each result is a "BLK-PERF <dev> <test> <bytes-or-ops> <ms>" line; tests/run_k64_storage.py turns them into MiB/s and
 * IOPS and checks the written range in the image. The numbers are whatever this run measured (QEMU TCG or KVM on a
 * shared host) and are reported as such. Without NVMe/SDHCI devices it prints SKIP and exits 0. */
#include "blktest.h"

#define MAXDEV 32
#define CHUNK (1u << 20)

static struct shz_blk_info dev[MAXDEV];
static unsigned char *buf;

static void perf_device(int i)
{
    const struct shz_blk_info *d = &dev[i];
    const unsigned ss = d->sector_size, per = CHUNK / ss, tag = name_tag(d->name) ^ 0x77;
    const unsigned long long seq_bytes = 64ull << 20;
    const unsigned long long wr_bytes = !strcmp(d->driver, "nvme") ? 64ull << 20 : 16ull << 20;
    const unsigned long long area = ((d->sectors * ss / 2) >> 20 << 20) / ss;
    unsigned long long t0, t1, lba, done;
    unsigned crc_w = 0, crc_r = 0, x = name_tag(d->name) + 99, k;
    NTSTATUS st = 0;
    if (d->sectors * ss < (128ull << 20)) { printf("%s: smaller than 128 MiB, skipped\n", d->name); return; }
    /* sequential read */
    t0 = now_ms();
    for (done = 0; done < seq_bytes && !st; done += CHUNK) st = NtShzBlkRead((ULONG)i, done / ss, per, buf);
    t1 = now_ms();
    CHECK(st == 0, "%s: sequential read of 64 MiB (%x)", d->name, (unsigned)st);
    printf("BLK-PERF %s seqread %llu %llu\n", d->name, seq_bytes, t1 - t0);
    /* sequential write (pattern units relative to the device), then read back */
    if (!(d->flags & (BLKF_READONLY | BLKF_MOUNTED))) {
        unsigned long long gen = 0;
        st = 0;
        t0 = now_ms();
        for (done = 0; done < wr_bytes && !st; done += CHUNK) {
            const unsigned long long g0 = now_ms();
            lba = area + done / ss;
            app_fill(buf, lba * (ss / 512), CHUNK, tag);
            crc_w = crc32_update(crc_w, buf, CHUNK);
            gen += now_ms() - g0;                       /* pattern generation is not device time */
            st = NtShzBlkWrite((ULONG)i, lba, per, buf);
        }
        if (!st) st = NtShzBlkFlush((ULONG)i);
        t1 = now_ms();
        CHECK(st == 0, "%s: sequential write of %llu MiB + flush (%x)", d->name, wr_bytes >> 20, (unsigned)st);
        printf("BLK-PERF %s seqwrite %llu %llu\n", d->name, wr_bytes, t1 - t0 - gen);
        printf("BLK-W %s %llu %llu %u %u %x\n", d->name, area, wr_bytes / ss, ss, tag, crc_w);
        for (done = 0; done < wr_bytes && !st; done += CHUNK) {
            st = NtShzBlkRead((ULONG)i, area + done / ss, per, buf);
            crc_r = crc32_update(crc_r, buf, CHUNK);
        }
        CHECK(st == 0 && crc_r == crc_w, "%s: the %llu MiB written read back with the same CRC (%x/%x)", d->name, wr_bytes >> 20,
              crc_w, crc_r);
    }
    /* random 4 KiB reads, queue depth 1 */
    st = 0;
    t0 = now_ms();
    for (k = 0; k < 1024 && !st; ++k) {
        x = x * 1103515245u + 12345u;
        st = NtShzBlkRead((ULONG)i, ((x >> 4) % ((64u << 20) / 4096)) * (4096 / ss), 4096 / ss, buf);
    }
    t1 = now_ms();
    CHECK(st == 0, "%s: 1024 random 4 KiB reads at QD1 (%x)", d->name, (unsigned)st);
    printf("BLK-PERF %s randread-qd1 1024 %llu\n", d->name, t1 - t0);
    /* random 4 KiB reads, queue depth 32 */
    {
        struct shz_blk_io io[32];
        unsigned b, j, bad = 0;
        st = 0;
        t0 = now_ms();
        for (b = 0; b < 128 && !st; ++b) {
            for (j = 0; j < 32; ++j) {
                x = x * 1103515245u + 12345u;
                io[j].op = 0; io[j].count = 4096 / ss; io[j].lba = ((x >> 4) % ((64u << 20) / 4096)) * (4096 / ss);
                io[j].buf = (unsigned long long)(buf + j * 4096); io[j].status = -1;
            }
            st = NtShzBlkBatch((ULONG)i, io, 32, 0);
            for (j = 0; j < 32; ++j) bad += io[j].status != 0;
        }
        t1 = now_ms();
        CHECK(st == 0 && !bad, "%s: 4096 random 4 KiB reads at QD32 (%x, %u failed)", d->name, (unsigned)st, bad);
        printf("BLK-PERF %s randread-qd32 4096 %llu\n", d->name, t1 - t0);
    }
}

int main(void)
{
    const int n = blk_list(dev, MAXDEV);
    int i, storage = 0;
    for (i = 0; i < n; ++i) storage += is_storage_driver(&dev[i]) && !(dev[i].flags & BLKF_PARTITION);
    if (!storage) { printf("SKIP: no NVMe/SDHCI block devices\n"); return 0; }
    buf = big_alloc(CHUNK);
    if (!buf) { printf("FAIL: buffer\n"); return 1; }
    for (i = 0; i < n; ++i)
        if (is_storage_driver(&dev[i]) && !(dev[i].flags & BLKF_PARTITION)) perf_device(i);
    big_free(buf);
    printf("t_blk_perf: %d checks, %d failed\n", g_checks, g_bad);
    return g_bad;
}
