/* SPDX-License-Identifier: GPL-2.0-only
 * Raw block-device system calls 0xf0-0xff (sysext.c routes the range here): enumeration, sector read/write/flush,
 * batches kept in flight together (queue depth > 1 through blk_read_async/blk_write_async), discard and driver
 * control. Used by win64/tests/t_blk_*.c; the host checks what they report and what they wrote
 * (tests/run_k64_storage.py). In the Supervisor profile the registry is empty and every call but the query reports
 * STATUS_NO_SUCH_DEVICE.
 *
 * Data moves through kernel windows: SYSBLK_WINDOWS ranges of SYSBLK_WINDOW_BYTES each, pages from the page allocator
 * mapped once at DIRECT_MAP + 256 GiB (inside the direct map's PML4 slot, so every address space sees them), handed
 * to the driver as ordinary kernel virtual buffers and copied to/from user memory with copy_to_user/copy_from_user.
 * Raw writes to a device that a file system has mounted (BLK_F_MOUNTED on it, on its whole disk or on one of its
 * partitions) are refused with STATUS_ACCESS_DENIED.
 */
#include "proc_internal.h"
#include "blk.h"

#define SYSBLK_WINDOWS 4u
#define SYSBLK_WINDOW_BYTES (1024u * 1024u)
#define SYSBLK_WINDOW_VA (DIRECT_MAP + (256ull << 30))
#define SYSBLK_BATCH_MAX 64u
#define STATUS_NO_SUCH_DEVICE ((int32_t)0xC000000E)
#define STATUS_IO_DEVICE_ERROR ((int32_t)0xC0000185)
#define STATUS_MEDIA_WRITE_PROTECTED ((int32_t)0xC00000A2)

/* NtShzBlkQuery layout, shared with win64/tests/blktest.h (keep in step; 64-bit fields first, no implicit padding). */
struct shz_blk_info {
    uint64_t sectors, start_lba;
    uint64_t read_sectors, write_sectors, read_ops, write_ops, flushes, discards, errors;
    uint32_t sector_size, flags, queue_depth, max_sectors;
    uint32_t reg_index, parent, part_index, part_scheme;
    uint32_t scan_notes;
    int32_t scan_result;
    char name[16], driver[8], irq_mode[8];
    char model[41], serial[21], part_name[37];
    uint8_t mbr_type;
    uint8_t type_guid[16];
};
_Static_assert(sizeof(struct shz_blk_info) == 264, "shz_blk_info layout");

/* NtShzBlkBatch element (user memory). */
struct shz_blk_io {
    uint32_t op;                                        /* 0 read, 1 write */
    uint32_t count;                                     /* sectors */
    uint64_t lba;
    uint64_t buf;                                       /* user buffer, count * sector_size bytes */
    int32_t status;                                     /* out: NTSTATUS */
    uint32_t reserved;
};

static uint8_t window_ready[SYSBLK_WINDOWS], window_busy[SYSBLK_WINDOWS];
static ksem_t window_sem;
static int windows_init;

static uint8_t *window_get(void)
{
    unsigned i;
    uint64_t f;
    if (!windows_init) {
        f = irq_save();
        if (!windows_init) { sem_init(&window_sem, (int)SYSBLK_WINDOWS); windows_init = 1; }
        irq_restore(f);
    }
    sem_wait(&window_sem);
    f = irq_save();
    for (i = 0; i < SYSBLK_WINDOWS && window_busy[i]; ++i) ;
    KASSERT(i < SYSBLK_WINDOWS);
    window_busy[i] = 1;
    irq_restore(f);
    if (!window_ready[i]) {
        const uint64_t base = SYSBLK_WINDOW_VA + (uint64_t)i * SYSBLK_WINDOW_BYTES;
        uint64_t off;
        for (off = 0; off < SYSBLK_WINDOW_BYTES; off += PAGE_SIZE) {
            const uint64_t pa = pmm_alloc();
            if (!pa || vm_map(kernel_pml4(), base + off, pa, PT_W | PT_NX)) {
                kprintf("K64 sysblk: window %u: out of memory\n", i);
                f = irq_save(); window_busy[i] = 0; irq_restore(f);
                sem_post(&window_sem);
                return 0;
            }
        }
        window_ready[i] = 1;
    }
    return (uint8_t *)(SYSBLK_WINDOW_VA + (uint64_t)i * SYSBLK_WINDOW_BYTES);
}

static void window_put(uint8_t *w)
{
    const unsigned i = (unsigned)(((uint64_t)w - SYSBLK_WINDOW_VA) / SYSBLK_WINDOW_BYTES);
    const uint64_t f = irq_save();
    window_busy[i] = 0;
    irq_restore(f);
    sem_post(&window_sem);
}

static void copy_str(char *dst, const char *src, unsigned cap)
{
    unsigned i = 0;
    if (src) for (; src[i] && i + 1 < cap; ++i) dst[i] = src[i];
    for (; i < cap; ++i) dst[i] = 0;
}

static int write_refused(blk_dev_t *d)
{
    blk_dev_t *x;
    for (x = blk_first(); x; x = x->next)
        if ((x->flags & BLK_F_MOUNTED) && (x == d || x == blk_whole(d) || blk_whole(x) == d)) return 1;
    return 0;
}

static int32_t op_query(process_t *p, uint64_t index, uint64_t out, uint64_t len, uint64_t pret)
{
    struct shz_blk_info in;
    blk_dev_t *d = blk_get((unsigned)index);
    const uint32_t ret = sizeof in;
    if (index > 0xffff || !d) return STATUS_NO_MORE_ENTRIES;
    if (len < sizeof in) return STATUS_BUFFER_TOO_SMALL;
    memset(&in, 0, sizeof in);
    in.sectors = d->sectors;
    in.start_lba = d->start_lba;
    in.read_sectors = d->reads; in.write_sectors = d->writes; in.read_ops = d->read_ops; in.write_ops = d->write_ops;
    in.flushes = d->flushes; in.discards = d->discards; in.errors = d->errors;
    in.sector_size = d->sector_size;
    in.flags = d->flags | (d->write ? 0 : BLK_F_READONLY);
    in.queue_depth = d->queue_depth ? d->queue_depth : 1;
    in.max_sectors = d->max_sectors;
    in.reg_index = d->reg_index;
    in.parent = d->parent ? d->parent->reg_index : 0xffffffffu;
    in.part_index = d->index;
    in.part_scheme = d->part_scheme;
    in.scan_notes = d->scan_notes;
    in.scan_result = d->scan_result;
    copy_str(in.name, d->name, sizeof in.name);
    copy_str(in.driver, d->driver ? d->driver : "?", sizeof in.driver);
    copy_str(in.irq_mode, blk_whole(d)->irq_mode ? blk_whole(d)->irq_mode : "poll", sizeof in.irq_mode);   /* live mode */
    copy_str(in.model, d->model, sizeof in.model);
    copy_str(in.serial, d->serial, sizeof in.serial);
    copy_str(in.part_name, d->part_name, sizeof in.part_name);
    in.mbr_type = d->mbr_type;
    memcpy(in.type_guid, d->type_guid, 16);
    if (copy_to_user(p, out, &in, sizeof in)) return STATUS_ACCESS_VIOLATION;
    if (pret && copy_to_user(p, pret, &ret, 4)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

static blk_dev_t *dev_of(uint64_t index) { return index <= 0xffff ? blk_get((unsigned)index) : 0; }

static int32_t op_rw(process_t *p, int write, uint64_t index, uint64_t lba, uint64_t count, uint64_t ubuf)
{
    blk_dev_t *d = dev_of(index);
    uint8_t *w;
    uint64_t done = 0;
    int32_t st = STATUS_SUCCESS;
    if (!d) return STATUS_NO_SUCH_DEVICE;
    if (!count || count > 0x100000 || lba >= d->sectors || count > d->sectors - lba) return STATUS_INVALID_PARAMETER;
    if (write && (!d->write || (d->flags & BLK_F_READONLY))) return STATUS_MEDIA_WRITE_PROTECTED;
    if (write && write_refused(d)) return STATUS_ACCESS_DENIED;
    w = window_get();
    if (!w) return STATUS_INSUFFICIENT_RESOURCES;
    while (done < count && st == STATUS_SUCCESS) {
        uint64_t n = SYSBLK_WINDOW_BYTES / d->sector_size;
        const uint64_t bytes = (n = count - done < n ? count - done : n) * d->sector_size;
        const uint64_t uva = ubuf + done * d->sector_size;
        if (write) {
            if (copy_from_user(p, w, uva, bytes)) { st = STATUS_ACCESS_VIOLATION; break; }
            if (blk_write(d, lba + done, (unsigned)n, w)) st = STATUS_IO_DEVICE_ERROR;
        } else {
            if (blk_read(d, lba + done, (unsigned)n, w)) st = STATUS_IO_DEVICE_ERROR;
            else if (copy_to_user(p, uva, w, bytes)) st = STATUS_ACCESS_VIOLATION;
        }
        done += n;
    }
    window_put(w);
    return st;
}

typedef struct {
    ksem_t all_done;
    volatile unsigned remaining;
    int32_t status[SYSBLK_BATCH_MAX];
} batch_t;
typedef struct { batch_t *b; unsigned i; } batch_ref_t;

static void batch_done(void *ctx, int status)
{
    batch_ref_t *r = ctx;
    const uint64_t f = irq_save();
    r->b->status[r->i] = status ? STATUS_IO_DEVICE_ERROR : STATUS_SUCCESS;
    if (--r->b->remaining == 0) sem_post(&r->b->all_done);
    irq_restore(f);
}

/* All requests are issued before the first one is waited for; the driver decides how many run at once. */
static int32_t op_batch(process_t *p, uint64_t index, uint64_t uios, uint64_t n, uint64_t flags)
{
    blk_dev_t *d = dev_of(index);
    struct shz_blk_io io[SYSBLK_BATCH_MAX];
    batch_t *b;
    batch_ref_t ref[SYSBLK_BATCH_MAX];
    uint8_t *w;
    uint64_t off = 0;
    unsigned i, issued = 0;
    int32_t st = STATUS_SUCCESS;
    (void)flags;
    if (!d) return STATUS_NO_SUCH_DEVICE;
    if (!n || n > SYSBLK_BATCH_MAX) return STATUS_INVALID_PARAMETER;
    if (copy_from_user(p, io, uios, n * sizeof io[0])) return STATUS_ACCESS_VIOLATION;
    for (i = 0; i < n; ++i) {
        const uint64_t bytes = (uint64_t)io[i].count * d->sector_size;
        if (io[i].op > 1 || !io[i].count || io[i].lba >= d->sectors || io[i].count > d->sectors - io[i].lba) return STATUS_INVALID_PARAMETER;
        if (io[i].op && (!d->write || (d->flags & BLK_F_READONLY))) return STATUS_MEDIA_WRITE_PROTECTED;
        if (io[i].op && write_refused(d)) return STATUS_ACCESS_DENIED;
        off += bytes;
    }
    if (off > SYSBLK_WINDOW_BYTES) return STATUS_INVALID_PARAMETER;
    b = kzalloc(sizeof *b);
    if (!b) return STATUS_INSUFFICIENT_RESOURCES;
    w = window_get();
    if (!w) { kfree(b); return STATUS_INSUFFICIENT_RESOURCES; }
    sem_init(&b->all_done, 0);
    b->remaining = (unsigned)n;
    off = 0;
    for (i = 0; i < n; ++i) {                           /* stage write data first: no copy while requests fly */
        if (io[i].op && copy_from_user(p, w + off, io[i].buf, (uint64_t)io[i].count * d->sector_size)) { st = STATUS_ACCESS_VIOLATION; break; }
        off += (uint64_t)io[i].count * d->sector_size;
    }
    if (st) { window_put(w); kfree(b); return st; }
    off = 0;
    for (i = 0; i < n; ++i) {
        int rc;
        ref[i].b = b;
        ref[i].i = i;
        rc = io[i].op ? blk_write_async(d, io[i].lba, io[i].count, w + off, batch_done, &ref[i])
                      : blk_read_async(d, io[i].lba, io[i].count, w + off, batch_done, &ref[i]);
        if (rc) batch_done(&ref[i], -1);
        ++issued;
        off += (uint64_t)io[i].count * d->sector_size;
    }
    while (sem_wait_timeout(&b->all_done, 30000))
        kprintf("K64 sysblk: batch on %s still has %u request(s) outstanding after 30 s\n", d->name, b->remaining);
    off = 0;
    for (i = 0; i < n; ++i) {
        io[i].status = b->status[i];
        if (io[i].status) st = STATUS_IO_DEVICE_ERROR;
        else if (!io[i].op && copy_to_user(p, io[i].buf, w + off, (uint64_t)io[i].count * d->sector_size)) st = STATUS_ACCESS_VIOLATION;
        off += (uint64_t)io[i].count * d->sector_size;
    }
    window_put(w);
    kfree(b);
    (void)issued;
    if (copy_to_user(p, uios, io, n * sizeof io[0])) return STATUS_ACCESS_VIOLATION;
    return st;
}

static int32_t op_control(process_t *p, uint64_t index, uint64_t op, uint64_t arg, uint64_t uout)
{
    blk_dev_t *d = dev_of(index);
    uint64_t out[4] = { 0, 0, 0, 0 };
    int rc;
    if (!d) return STATUS_NO_SUCH_DEVICE;
    rc = blk_control(d, (unsigned)op, arg, out);
    if (uout && copy_to_user(p, uout, out, sizeof out)) return STATUS_ACCESS_VIOLATION;
    return rc == 0 ? STATUS_SUCCESS : rc == -2 ? STATUS_NOT_SUPPORTED : STATUS_IO_DEVICE_ERROR;
}

static int32_t op_discard(uint64_t index, uint64_t lba, uint64_t count)
{
    blk_dev_t *d = dev_of(index);
    if (!d) return STATUS_NO_SUCH_DEVICE;
    if (!count || count > 0xffffffffu || lba >= d->sectors || count > d->sectors - lba) return STATUS_INVALID_PARAMETER;
    if (write_refused(d)) return STATUS_ACCESS_DENIED;
    if (!(blk_whole(d)->flags & BLK_F_DISCARD)) return STATUS_NOT_SUPPORTED;
    return blk_discard(d, lba, (unsigned)count) ? STATUS_IO_DEVICE_ERROR : STATUS_SUCCESS;
}

int32_t sys_ext_blk(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    (void)r;
    switch (num) {
    case SYS_NtShzBlkQuery: return op_query(cur, a1, a2, a3, a4);
    case SYS_NtShzBlkRead: return op_rw(cur, 0, a1, a2, a3, a4);
    case SYS_NtShzBlkWrite: return op_rw(cur, 1, a1, a2, a3, a4);
    case SYS_NtShzBlkFlush: {
        blk_dev_t *d = dev_of(a1);
        if (!d) return STATUS_NO_SUCH_DEVICE;
        return blk_flush(d) ? STATUS_IO_DEVICE_ERROR : STATUS_SUCCESS;
    }
    case SYS_NtShzBlkBatch: return op_batch(cur, a1, a2, a3, a4);
    case SYS_NtShzBlkControl: return op_control(cur, a1, a2, a3, a4);
    case SYS_NtShzBlkDiscard: return op_discard(a1, a2, a3);
    default: return STATUS_INVALID_SYSTEM_SERVICE;
    }
}
