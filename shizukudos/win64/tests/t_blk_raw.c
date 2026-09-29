/* SPDX-License-Identifier: GPL-2.0-only
 * Raw NVMe / SD block devices from user mode (kernel64/sysblk.c): enumeration with partitions, CRC-32 of fixed regions
 * of every device and partition, synchronous and batched (queue depth > 1) writes with read-back, a partition-relative
 * write, an odd-sized write, TRIM (NVMe), NVMe completion by MSI-X / INTx / polling, the NVMe timeout -> controller
 * reset path, an out-of-range command on each driver, and SDHCI PIO against ADMA2. Everything the host can recompute
 * is printed as a "BLK-..." line; tests/run_k64_storage.py checks the CRCs against the images and, after QEMU exits,
 * finds every written range in the image files. Devices of other drivers (AHCI) are listed and left alone.
 * Without NVMe/SDHCI devices it prints SKIP and exits 0 (plain runner, Supervisor profile). */
#include "blktest.h"

#define MAXDEV 32
#define BUF_BYTES (4u << 20)

static struct shz_blk_info dev[MAXDEV];
static int ndev;
static unsigned char *buf, *buf2;

static unsigned long long min_u64(unsigned long long a, unsigned long long b) { return a < b ? a : b; }

/* CRC-32 of [lba, lba+count) of device i, read in chunks of up to 1 MiB. Returns 0 on success. */
static int crc_range(int i, unsigned long long lba, unsigned long long count, unsigned *crc_out)
{
    const unsigned ss = dev[i].sector_size, per = (1u << 20) / ss;
    unsigned crc = 0;
    while (count) {
        const unsigned n = (unsigned)min_u64(count, per);
        const NTSTATUS st = NtShzBlkRead((ULONG)i, lba, n, buf);
        if (st) { printf("read %s lba %llu x%u: %x\n", dev[i].name, lba, n, (unsigned)st); return -1; }
        crc = crc32_update(crc, buf, (size_t)n * ss);
        lba += n;
        count -= n;
    }
    *crc_out = crc;
    return 0;
}

static void report_crc(int i, unsigned long long lba, unsigned long long count)
{
    unsigned crc = 0;
    const int rc = crc_range(i, lba, count, &crc);
    CHECK(rc == 0, "%s: read %llu sectors at %llu", dev[i].name, count, lba);
    if (!rc) printf("BLK-CRC %s %llu %llu %x\n", dev[i].name, lba, count, crc);
}

/* Synchronous write of `count` sectors at `lba` (pattern units relative to device i), flush, read back, compare. */
static void write_check(int i, unsigned long long lba, unsigned count, unsigned tag, const char *what)
{
    const unsigned ss = dev[i].sector_size;
    const unsigned long long bytes = (unsigned long long)count * ss;
    NTSTATUS st;
    app_fill(buf, lba * (ss / 512), bytes, tag);
    st = NtShzBlkWrite((ULONG)i, lba, count, buf);
    CHECK(st == 0, "%s: %s write of %u sectors at %llu (%x)", dev[i].name, what, count, lba, (unsigned)st);
    st = NtShzBlkFlush((ULONG)i);
    CHECK(st == 0, "%s: flush after the %s write (%x)", dev[i].name, what, (unsigned)st);
    memset(buf2, 0xa5, (size_t)bytes);
    st = NtShzBlkRead((ULONG)i, lba, count, buf2);
    CHECK(st == 0 && !memcmp(buf, buf2, (size_t)bytes), "%s: %s write reads back identically", dev[i].name, what);
    printf("BLK-W %s %llu %u %u %u %x\n", dev[i].name, lba, count, ss, tag, crc32_update(0, buf, (size_t)bytes));
}

/* 16 writes of 4 KiB in one batch (all in flight together), then one batch reading them back. */
static void batch_check(int i, unsigned long long base_lba, unsigned tag)
{
    struct shz_blk_io io[16];
    const unsigned ss = dev[i].sector_size, per = 4096 / ss;
    static const unsigned order[16] = { 7, 2, 12, 0, 9, 14, 4, 11, 1, 15, 6, 3, 13, 8, 10, 5 };
    NTSTATUS st;
    unsigned k, bad = 0;
    for (k = 0; k < 16; ++k) {
        const unsigned long long lba = base_lba + (unsigned long long)order[k] * 2 * per;   /* 4 KiB data, 4 KiB gap */
        io[k].op = 1; io[k].count = per; io[k].lba = lba; io[k].buf = (unsigned long long)(buf + k * 4096); io[k].status = -1;
        app_fill(buf + k * 4096, lba * (ss / 512), 4096, tag);
    }
    st = NtShzBlkBatch((ULONG)i, io, 16, 0);
    for (k = 0; k < 16; ++k) bad += io[k].status != 0;
    CHECK(st == 0 && !bad, "%s: batch of 16 x 4 KiB writes (%x, %u failed)", dev[i].name, (unsigned)st, bad);
    for (k = 0; k < 16; ++k) {
        printf("BLK-W %s %llu %u %u %u %x\n", dev[i].name, io[k].lba, per, ss, tag, crc32_update(0, buf + k * 4096, 4096));
        io[k].op = 0; io[k].buf = (unsigned long long)(buf2 + k * 4096); io[k].status = -1;
    }
    memset(buf2, 0, 16 * 4096);
    st = NtShzBlkBatch((ULONG)i, io, 16, 0);
    CHECK(st == 0 && !memcmp(buf, buf2, 16 * 4096), "%s: batch read-back of the 16 writes (%x)", dev[i].name, (unsigned)st);
}

static void nvme_extras(int i, unsigned long long area)
{
    const unsigned ss = dev[i].sector_size;
    unsigned long long out[4] = { 0, 0, 0, 0 }, s0[4] = { 0, 0, 0, 0 }, s1[4] = { 0, 0, 0, 0 };
    unsigned ref = 0, crc = 0, k;
    const unsigned long long ref_count = (4ull << 20) / ss;
    static const char *const names[3] = { "msix", "intx", "poll" };
    static const unsigned seq[3] = { 1, 2, 0 };        /* INTx, poll, back to the best mode */
    NTSTATUS st;
    /* completion modes */
    CHECK(crc_range(i, 0, ref_count, &ref) == 0, "%s: reference read of 4 MiB", dev[i].name);
    for (k = 0; k < 3; ++k) {
        unsigned long long mode[4] = { 0, 0, 0, 0 };
        st = NtShzBlkControl((ULONG)i, CTL_IRQ_MODE, seq[k], mode);
        NtShzBlkControl((ULONG)i, CTL_STATS, 0, s0);
        crc = 0;
        if (!st) crc_range(i, 0, ref_count, &crc);
        NtShzBlkControl((ULONG)i, CTL_STATS, 0, s1);
        CHECK(st == 0 && crc == ref, "%s: completion mode %s (switch %x, crc %x vs %x, %llu interrupts)", dev[i].name,
              seq[k] == 0 ? dev[i].irq_mode : names[seq[k]], (unsigned)st, crc, ref, s1[0] - s0[0]);
        printf("BLK-MODE %s %s %llu %d\n", dev[i].name, seq[k] == 0 ? "best" : names[seq[k]], s1[0] - s0[0], crc == ref);
    }
    /* queue depth: the batch above must have had more than one command in flight */
    NtShzBlkControl((ULONG)i, CTL_STATS, 0, out);
    CHECK(out[3] > 1, "%s: more than one command in flight (max %llu)", dev[i].name, out[3]);
    printf("BLK-QD %s %llu\n", dev[i].name, out[3]);
    /* TRIM: write, deallocate, read back */
    {
        const unsigned count = (64u << 10) / ss;
        const unsigned long long lba = area + (3ull << 20) / ss;
        unsigned z = 1, j;
        app_fill(buf, lba * (ss / 512), 64u << 10, name_tag(dev[i].name) ^ 0x55);
        st = NtShzBlkWrite((ULONG)i, lba, count, buf);
        CHECK(st == 0, "%s: write before TRIM (%x)", dev[i].name, (unsigned)st);
        st = NtShzBlkDiscard((ULONG)i, lba, count);
        CHECK(st == 0, "%s: DSM deallocate of 64 KiB (%x)", dev[i].name, (unsigned)st);
        memset(buf2, 0xa5, 64u << 10);
        NtShzBlkRead((ULONG)i, lba, count, buf2);
        for (j = 0; j < (64u << 10); ++j) if (buf2[j]) { z = 0; break; }
        printf("BLK-TRIM %s %llu %u %u %d\n", dev[i].name, lba, count, name_tag(dev[i].name) ^ 0x55, z);
    }
    /* out-of-range command, then the lost-doorbell timeout */
    memset(out, 0, sizeof out);
    st = NtShzBlkControl((ULONG)i, CTL_ERROR_TEST, 0, out);
    CHECK(st == 0, "%s: READ past the end fails with LBA Out of Range and the queue keeps working (status %llx)", dev[i].name, out[0]);
    printf("BLK-ERRTEST %s %d %llx\n", dev[i].name, st == 0, out[0]);
    memset(out, 0, sizeof out);
    st = NtShzBlkControl((ULONG)i, CTL_TIMEOUT_TEST, 64, out);
    CHECK(st == 0 && out[0] >= 1 && out[1] >= 1, "%s: lost command -> timeout -> controller reset -> resubmitted and correct "
          "(%llu timeouts, %llu resets, %llu ms)", dev[i].name, out[0], out[1], out[2]);
    printf("BLK-TIMEOUT %s %d %llu %llu %llu\n", dev[i].name, st == 0, out[0], out[1], out[2]);
    CHECK(crc_range(i, 0, ref_count, &crc) == 0 && crc == ref, "%s: data intact after the reset", dev[i].name);
}

static void sdhci_extras(int i, unsigned long long area)
{
    unsigned long long out[4] = { 0, 0, 0, 0 }, s0[4] = { 0, 0, 0, 0 }, s1[4] = { 0, 0, 0, 0 };
    unsigned a = 0, b = 0;
    NTSTATUS st;
    const unsigned long long count = (512u << 10) / 512;
    st = NtShzBlkControl((ULONG)i, CTL_XFER_MODE, 0, out);
    CHECK(st == 0 && out[0] == 1, "%s: ADMA2 transfers in use", dev[i].name);
    NtShzBlkControl((ULONG)i, CTL_STATS, 0, s0);
    crc_range(i, 0, count, &a);
    st = NtShzBlkControl((ULONG)i, CTL_XFER_MODE, 1, out);
    crc_range(i, 0, count, &b);
    NtShzBlkControl((ULONG)i, CTL_STATS, 0, s1);
    CHECK(st == 0 && a == b && s1[3] > s0[3], "%s: PIO read of 512 KiB equals the ADMA2 read (%x/%x, %llu PIO transfers)",
          dev[i].name, a, b, s1[3] - s0[3]);
    printf("BLK-PIO %s %x %x %llu\n", dev[i].name, a, b, s1[3] - s0[3]);
    write_check(i, area + (2ull << 20) / 512, 64, name_tag(dev[i].name) ^ 0x44, "PIO");
    NtShzBlkControl((ULONG)i, CTL_XFER_MODE, 0, out);
    memset(out, 0, sizeof out);
    st = NtShzBlkControl((ULONG)i, CTL_ERROR_TEST, 0, out);
    CHECK(st == 0, "%s: read past the end fails (rc %lld, R1 %llx) and the card returns to transfer state (status %llx)",
          dev[i].name, (long long)out[0], out[1], out[2]);
    printf("BLK-ERRTEST %s %d %llx\n", dev[i].name, st == 0, out[1]);
}

int main(void)
{
    int i, storage = 0;
    NTSTATUS st;
    ndev = blk_list(dev, MAXDEV);
    for (i = 0; i < ndev; ++i) {
        const struct shz_blk_info *d = &dev[i];
        printf("BLK-DEV %s %s %llu %u %x %u %s %d %u %llu %u %x %s|%s|%s\n", d->name, d->driver, d->sectors, d->sector_size,
               d->flags, d->queue_depth, d->irq_mode, d->parent == 0xffffffffu ? -1 : (int)d->parent, d->part_index,
               d->start_lba, d->part_scheme, d->mbr_type, d->model, d->serial, d->part_name);
        storage += is_storage_driver(d);
    }
    if (!storage) { printf("SKIP: no NVMe/SDHCI block devices\n"); return 0; }
    buf = big_alloc(BUF_BYTES);
    buf2 = big_alloc(BUF_BYTES);
    if (!buf || !buf2) { printf("FAIL: buffers\n"); return 1; }
    /* bounds are enforced by the layer */
    st = NtShzBlkRead(0, dev[0].sectors, 1, buf);
    CHECK(st == (NTSTATUS)0xC000000D, "read at the device end is rejected with STATUS_INVALID_PARAMETER (%x)", (unsigned)st);
    st = NtShzBlkQuery((ULONG)ndev, &dev[0], sizeof dev[0], 0);
    CHECK(st == (NTSTATUS)0x8000001A, "query past the last device returns STATUS_NO_MORE_ENTRIES (%x)", (unsigned)st);
    ndev = blk_list(dev, MAXDEV);
    /* reads: every storage device and partition */
    for (i = 0; i < ndev; ++i) {
        const struct shz_blk_info *d = &dev[i];
        const unsigned long long per_mib = (1u << 20) / d->sector_size;
        unsigned k, x;
        if (!is_storage_driver(d)) continue;
        if (d->flags & BLKF_PARTITION) {
            report_crc(i, 0, min_u64(d->sectors, per_mib));
            if (d->sectors > per_mib) report_crc(i, d->sectors - per_mib / 4, per_mib / 4);
            continue;
        }
        report_crc(i, 0, min_u64(d->sectors, 8 * per_mib));
        report_crc(i, d->sectors - per_mib, per_mib);
        x = name_tag(d->name) * 2654435761u + 1;
        for (k = 0; k < 8; ++k) {                        /* 8 pseudo-random 64 KiB ranges */
            const unsigned long long n = per_mib / 16, span = d->sectors / n - 1;
            x = x * 1103515245u + 12345u;
            report_crc(i, ((x >> 8) % span) * n, n);
        }
    }
    /* writes, batches, driver specifics: whole storage devices only, in their scratch area (3/4 of the device) */
    for (i = 0; i < ndev; ++i) {
        const struct shz_blk_info *d = &dev[i];
        const unsigned ss = d->sector_size, tag = name_tag(d->name);
        unsigned long long area;
        int j;
        if (!is_storage_driver(d) || (d->flags & BLKF_PARTITION)) continue;
        if (d->flags & (BLKF_READONLY | BLKF_MOUNTED)) { printf("%s: read-only or mounted, no write tests\n", d->name); continue; }
        area = ((d->sectors * ss / 4 * 3) >> 20 << 20) / ss;
        write_check(i, area, (256u << 10) / ss, tag ^ 0x11, "256 KiB");
        write_check(i, area + (4ull << 20) / ss + 1, 3, tag ^ 0x66, "odd-sized");
        batch_check(i, area + (1ull << 20) / ss, tag ^ 0x33);
        for (j = 0; j < ndev; ++j)                      /* first partition of this device: partition-relative write */
            if (dev[j].parent == d->reg_index && !(dev[j].flags & BLKF_MOUNTED) && dev[j].sectors > 64) {
                write_check(j, 5, (8192u / ss) ? 8192u / ss : 1, name_tag(dev[j].name) ^ 0x22, "partition");
                break;
            }
        if (!strcmp(d->driver, "nvme")) nvme_extras(i, area);
        else sdhci_extras(i, area);
    }
    ndev = blk_list(dev, MAXDEV);
    for (i = 0; i < ndev; ++i)
        if (is_storage_driver(&dev[i]) && !(dev[i].flags & BLKF_PARTITION))
            printf("BLK-STAT %s reads %llu/%llu writes %llu/%llu flushes %llu discards %llu errors %llu\n", dev[i].name,
                   dev[i].read_ops, dev[i].read_sectors, dev[i].write_ops, dev[i].write_sectors, dev[i].flushes,
                   dev[i].discards, dev[i].errors);
    big_free(buf);
    big_free(buf2);
    printf("t_blk_raw: %d checks, %d failed\n", g_checks, g_bad);
    return g_bad;
}
