/* SPDX-License-Identifier: GPL-2.0-only
 * Actual blk/VFS behavioral witnesses with typed, memory-only dependencies.
 * Each scenario is a separate process. No storage_authority implementation,
 * physical device, installer provider, user object or privileged IRQ executes.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Privileged/process headers are captured unchanged but suppressed here.
 * Actual block and filesystem schemas are included without replacements. */
#define K64_H
#define K64_PROC_INTERNAL_H
#include "project/shizukudos/kernel64/blk.h"
#include "project/shizukudos/kernel64/vfs_mounts.h"

static unsigned checks, failures, irq_depth, irq_misuse;
static uint64_t fake_if = 1;
static uint64_t irq_save(void)
{
    uint64_t saved = fake_if;
    fake_if = 0;
    ++irq_depth;
    return saved;
}
static void irq_restore(uint64_t saved)
{
    if (!irq_depth || saved > 1) ++irq_misuse;
    else --irq_depth;
    fake_if = saved;
}
void kprintf(const char *fmt, ...) { (void)fmt; }

/* These macros only separate two translation-unit-local count identifiers.
 * Literal production C includes are generated from captured source slices. */
#define count fixture_blk_registry_count
#include "production_blk.inc"
#undef count
#define count fixture_vfs_table_count
#include "production_vfs.inc"
#undef count

static void check(int ok, const char *label)
{
    ++checks;
    if (!ok) {
        ++failures;
        fprintf(stderr, "ASSERT %s\n", label);
    }
}
#define CHECK(condition, label) check(!!(condition), label)

#define SECTOR_BYTES 512u
#define DEVICE_SECTORS 128u
struct backend {
    uint8_t bytes[DEVICE_SECTORS * SECTOR_BYTES];
    unsigned reads, writes, flushes, discards, resets, stats, bad_args;
    uint64_t last_lba;
    unsigned last_count, async_mode;
    blk_done_fn pending_done;
    void *pending_ctx;
};
static struct backend backend0, backend1;
static blk_dev_t whole, part, sibling, nested, other;
static fsnode_t root0, root1;
static fsvol_t vol0, vol1;
static fsnode_t *namespace_root[26];
static unsigned mount_attempts, reject_namespace, shutdown_calls;

static struct backend *checked_backend(blk_dev_t *d, uint64_t lba, unsigned n)
{
    struct backend *b = d ? d->priv : NULL;
    if ((b != &backend0 && b != &backend1) || d->parent || !n ||
        lba >= DEVICE_SECTORS || n > DEVICE_SECTORS - lba) {
        if (b == &backend0 || b == &backend1) ++b->bad_args;
        return NULL;
    }
    b->last_lba = lba;
    b->last_count = n;
    return b;
}
static int backend_read(blk_dev_t *d, uint64_t lba, unsigned n, void *buf)
{
    struct backend *b = checked_backend(d, lba, n);
    if (!b || !buf) return -1;
    ++b->reads;
    memcpy(buf, b->bytes + lba * SECTOR_BYTES, n * SECTOR_BYTES);
    return 0;
}
static int backend_write(blk_dev_t *d, uint64_t lba, unsigned n, const void *buf)
{
    struct backend *b = checked_backend(d, lba, n);
    if (!b || !buf) return -1;
    ++b->writes;
    memcpy(b->bytes + lba * SECTOR_BYTES, buf, n * SECTOR_BYTES);
    return 0;
}
static int backend_flush(blk_dev_t *d)
{
    struct backend *b = d ? d->priv : NULL;
    if ((b != &backend0 && b != &backend1) || d->parent) return -1;
    ++b->flushes;
    return 0;
}
static int backend_discard(blk_dev_t *d, uint64_t lba, unsigned n)
{
    struct backend *b = checked_backend(d, lba, n);
    if (!b) return -1;
    ++b->discards;
    memset(b->bytes + lba * SECTOR_BYTES, 0, n * SECTOR_BYTES);
    return 0;
}
static int backend_control(blk_dev_t *d, unsigned op, uint64_t arg, uint64_t *out)
{
    struct backend *b = d ? d->priv : NULL;
    (void)arg;
    if ((b != &backend0 && b != &backend1) || d->parent) return -1;
    if (op == BLK_CTL_RESET) { ++b->resets; if (out) *out = b->resets; return 0; }
    if (op == BLK_CTL_STATS) { ++b->stats; if (out) *out = b->writes; return 0; }
    return -2;
}
static int backend_async_read(blk_dev_t *d, uint64_t lba, unsigned n,
                              void *buf, blk_done_fn done, void *ctx)
{
    struct backend *b = d->priv;
    int rc = backend_read(d, lba, n, buf);
    if (rc) return -1;
    if (b->async_mode == 1) done(ctx, 0);
    else { b->pending_done = done; b->pending_ctx = ctx; }
    return 0;
}
static int backend_async_write(blk_dev_t *d, uint64_t lba, unsigned n,
                               const void *buf, blk_done_fn done, void *ctx)
{
    struct backend *b = d->priv;
    int rc = backend_write(d, lba, n, buf);
    if (rc) return -1;
    if (b->async_mode == 1) done(ctx, 0);
    else { b->pending_done = done; b->pending_ctx = ctx; }
    return 0;
}

/* Namespace dependency only: the actual VFS table/publication is not mocked. */
fsnode_t *fs_root_of(char letter)
{
    return letter >= 'A' && letter <= 'Z' ? namespace_root[letter - 'A'] : NULL;
}
int fs_mount(char letter, fsnode_t *root)
{
    ++mount_attempts;
    if (reject_namespace || letter < 'D' || letter > 'Z' || !root ||
        namespace_root[letter - 'A']) return -1;
    namespace_root[letter - 'A'] = root;
    return 0;
}
static int volume_flush(fsvol_t *v) { return blk_flush(v->priv); }
static int volume_shutdown(fsvol_t *v) { ++shutdown_calls; return volume_flush(v); }

static void make_whole(blk_dev_t *d, const char *name, struct backend *b)
{
    strcpy(d->name, name);
    d->sector_size = SECTOR_BYTES;
    d->sectors = DEVICE_SECTORS;
    d->read = backend_read; d->write = backend_write; d->flush = backend_flush;
    d->discard = backend_discard; d->control = backend_control; d->priv = b;
}
static void make_partition(blk_dev_t *d, const char *name, blk_dev_t *parent,
                           uint64_t start, uint64_t sectors)
{
    strcpy(d->name, name);
    d->sector_size = SECTOR_BYTES; d->sectors = sectors;
    d->start_lba = start; d->parent = parent; d->flags = BLK_F_PARTITION;
    d->read = part_read; d->write = part_write; d->flush = part_flush;
}
static void devices(void)
{
    make_whole(&whole, "fixture0", &backend0);
    make_partition(&part, "fixture0p1", &whole, 16, 32);
    make_partition(&sibling, "fixture0p2", &whole, 64, 32);
    CHECK(blk_register(&whole) == 0, "register-whole");
    CHECK(blk_register(&part) == 0, "register-part");
    CHECK(blk_register(&sibling) == 0, "register-sibling");
}
static char mount_volume(const char *fstype, int fat_flag)
{
    root0.is_dir = 1; root0.backing = FSB_DISK; root0.vol = &vol0;
    vol0.priv = &part; vol0.flush = volume_flush;
    char letter = vfs_mount_next(&root0, &vol0, fstype, part.name, volume_shutdown);
    /* Mirrors disk.c's existing caller-side FAT flag; SFS does not set it. */
    if (letter && fat_flag) part.flags |= BLK_F_MOUNTED;
    return letter;
}
static void red_sfs_busy(void)
{
    devices();
    CHECK(mount_volume("shizukufs", 0) == 'D', "sfs-mounted");
    const vfs_mount_t *published = vfs_mount_by_device(part.name);
    CHECK(vfs_mount_count() == 1 && published && published->root == &root0,
          "sfs-actual-vfs-publication");
    CHECK(blk_user_write_busy(&whole) == 1, "sfs-whole-raw-busy");
    CHECK(blk_user_write_busy(&part) == 1, "sfs-part-raw-busy");
}
static void red_mounted_reset(void)
{
    uint64_t value = 0;
    devices(); part.flags |= BLK_F_MOUNTED;
    CHECK(blk_user_write_busy(&whole) == 1, "mounted-busy-established");
    CHECK(blk_control(&part, BLK_CTL_RESET, 0, &value) != 0, "mounted-reset-refused");
    CHECK(backend0.resets == 0, "mounted-reset-backend-not-called");
}
static void red_global_reset(void)
{
    devices(); part.flags |= BLK_F_MOUNTED;
    make_whole(&other, "fixture1", &backend1);
    CHECK(blk_register(&other) == 0, "register-second-whole");
    CHECK(blk_user_write_busy(&whole) == 1, "global-mounted-busy-established");
    CHECK(blk_control(&other, BLK_CTL_RESET, 0, NULL) != 0, "global-reset-refused");
    CHECK(backend1.resets == 0, "global-reset-backend-not-called");
}
static void legacy_unmounted(void)
{
    uint8_t input[SECTOR_BYTES], output[SECTOR_BYTES]; uint64_t value = 0;
    devices(); memset(input, 0xa7, sizeof input);
    CHECK(blk_user_write_busy(&whole) == 0, "unmounted-not-busy");
    CHECK(blk_write(&whole, 3, 1, input) == 0, "unmounted-write");
    CHECK(blk_read(&whole, 3, 1, output) == 0 && !memcmp(input, output, sizeof input), "unmounted-read-bytes");
    CHECK(blk_flush(&whole) == 0 && backend0.flushes == 1, "unmounted-flush");
    CHECK(blk_control(&whole, BLK_CTL_RESET, 0, &value) == 0 && value == 1 && backend0.resets == 1, "unmounted-reset-allowed");
    CHECK(blk_control(&whole, BLK_CTL_STATS, 0, &value) == 0 && value == 1, "unmounted-stats-allowed");
    CHECK(blk_discard(&whole, 3, 1) == 0 && backend0.discards == 1, "unmounted-discard");
    CHECK(backend0.bytes[3 * SECTOR_BYTES] == 0, "discard-bytes");
}
static void mounted_internal(int fat)
{
    uint8_t bytes[SECTOR_BYTES]; uint64_t value = 0;
    devices(); memset(bytes, 0x58, sizeof bytes);
    CHECK(mount_volume(fat ? "fat32" : "shizukufs", fat) == 'D', "internal-volume-mounted");
    if (fat) CHECK(blk_user_write_busy(&part) == 1, "fat-raw-protected");
    CHECK(blk_write(&part, 2, 1, bytes) == 0, "mounted-internal-write-allowed");
    CHECK(backend0.writes == 1 && backend0.last_lba == 18 && backend0.bytes[18 * SECTOR_BYTES] == 0x58, "internal-partition-bytes");
    CHECK(blk_flush(&part) == 0 && backend0.flushes == 1, "mounted-internal-flush-allowed");
    CHECK(blk_control(&part, BLK_CTL_STATS, 0, &value) == 0 && backend0.stats == 1, "mounted-stats-allowed");
}
static void readonly_range(void)
{
    uint8_t bytes[SECTOR_BYTES] = {0};
    devices();
    CHECK(blk_write(&part, 32, 1, bytes) != 0, "past-partition-refused");
    CHECK(blk_write(&part, 31, 2, bytes) != 0, "cross-end-refused");
    CHECK(blk_write(&part, UINT64_MAX, 1, bytes) != 0, "wrapped-lba-refused");
    CHECK(blk_write(&part, 0, 0, bytes) != 0, "empty-transfer-refused");
    CHECK(blk_read(&part, 0, 1, NULL) != 0, "null-buffer-refused");
    part.flags |= BLK_F_READONLY;
    CHECK(blk_write(&part, 0, 1, bytes) != 0 && blk_discard(&part, 0, 1) != 0, "readonly-refused");
    CHECK(backend0.reads == 0 && backend0.writes == 0 && backend0.discards == 0, "refused-io-no-driver");
}
static void partition_forwarding(void)
{
    uint8_t bytes[SECTOR_BYTES], output[SECTOR_BYTES];
    devices(); make_partition(&nested, "nested", &part, 2, 8);
    CHECK(blk_register(&nested) == 0, "register-nested"); memset(bytes, 0xc3, sizeof bytes);
    CHECK(blk_write(&nested, 1, 1, bytes) == 0 && backend0.last_lba == 19, "nested-write-translation");
    CHECK(blk_read(&nested, 1, 1, output) == 0 && backend0.last_lba == 19 && !memcmp(bytes, output, sizeof bytes), "nested-read-translation");
    CHECK(blk_discard(&nested, 1, 1) == 0 && backend0.last_lba == 19, "nested-discard-translation");
    CHECK(blk_flush(&nested) == 0 && backend0.flushes == 1, "nested-flush-single-dispatch");
    CHECK(whole.writes == 1 && part.writes == 1 && nested.writes == 1 && backend0.writes == 1, "partition-accounting-single-io");
}
struct completion { unsigned calls; int status; };
static void completed(void *ctx, int status)
{
    struct completion *c = ctx; ++c->calls; c->status = status;
}
static void async_case(unsigned mode)
{
    uint8_t bytes[SECTOR_BYTES], output[SECTOR_BYTES]; struct completion c = {0, -99};
    devices(); memset(bytes, 0xd2, sizeof bytes);
    backend0.async_mode = mode;
    if (mode) { whole.read_async = backend_async_read; whole.write_async = backend_async_write; }
    CHECK(blk_write_async(&part, 1, 1, bytes, completed, &c) == 0, "async-write-admitted");
    CHECK(backend0.writes == 1 && backend0.last_lba == 17, "async-write-one-real-backend");
    if (mode == 2) {
        CHECK(c.calls == 0 && backend0.pending_done != NULL, "deferred-before-completion");
        blk_done_fn done = backend0.pending_done; void *ctx = backend0.pending_ctx;
        backend0.pending_done = NULL; backend0.pending_ctx = NULL; done(ctx, 0);
    }
    CHECK(c.calls == 1 && c.status == 0, "async-write-completion-once");
    c.calls = 0; c.status = -99;
    CHECK(blk_read_async(&part, 1, 1, output, completed, &c) == 0, "async-read-admitted");
    if (mode == 2) {
        CHECK(c.calls == 0 && backend0.pending_done != NULL, "deferred-read-before-completion");
        blk_done_fn done = backend0.pending_done; void *ctx = backend0.pending_ctx;
        backend0.pending_done = NULL; backend0.pending_ctx = NULL; done(ctx, 0);
    }
    CHECK(c.calls == 1 && c.status == 0 && !memcmp(bytes, output, sizeof bytes), "async-read-bytes-and-completion");
    CHECK(backend0.reads == 1 && part.read_ops == 1 && part.write_ops == 1, "async-accounting");
}
static void mount_rollback(void)
{
    uint8_t bytes[SECTOR_BYTES] = {0};
    devices(); reject_namespace = 1;
    CHECK(mount_volume("shizukufs", 0) == 0, "failed-mount-not-published");
    CHECK(vfs_mount_count() == 0 && vfs_mount_by_device(part.name) == NULL && vol0.letter == 0, "failed-mount-table-unchanged");
    CHECK(fs_root_of('D') == NULL && mount_attempts == 23, "failed-namespace-no-root");
    CHECK(blk_user_write_busy(&whole) == 0 && !(part.flags & BLK_F_MOUNTED), "failed-mount-no-protection-leak");
    CHECK(blk_write(&part, 0, 1, bytes) == 0 && backend0.writes == 1, "failed-mount-legacy-write-preserved");
}
static void vfs_shutdown_case(void)
{
    devices(); CHECK(mount_volume("fat32", 1) == 'D', "shutdown-mount");
    root1.is_dir = 1; root1.vol = &vol1; vol1.priv = &sibling; vol1.flush = volume_flush;
    CHECK(vfs_mount_next(&root1, &vol1, "shizukufs", sibling.name, NULL) == 'E', "second-volume-letter");
    CHECK(vfs_flush_all() == 0 && backend0.flushes == 2, "vfs-flush-all-real-wrappers");
    vfs_shutdown(); vfs_shutdown();
    CHECK(backend0.flushes == 4 && shutdown_calls == 1, "vfs-shutdown-idempotent");
    CHECK(vfs_mount_count() == 2 && fs_root_of('D') == &root0 && fs_root_of('E') == &root1, "shutdown-is-not-unmount");
}
static void registry_case(void)
{
    devices(); make_whole(&other, "fixture0", &backend1);
    CHECK(blk_register(&other) != 0 && blk_count() == 3, "duplicate-name-no-publication");
    CHECK(blk_get(0) == &whole && blk_get(1) == &part && blk_get(2) == &sibling && blk_get(3) == NULL, "registry-exact-order");
    CHECK(whole.reg_index == 0 && part.reg_index == 1 && sibling.reg_index == 2, "registry-index-order");
    CHECK(blk_whole(&part) == &whole && blk_whole(NULL) == NULL && blk_user_write_busy(NULL) == 1, "null-and-ancestry");
}
int main(int argc, char **argv)
{
    if (argc != 2) return 64;
    const char *scenario = argv[1];
    if (!strcmp(scenario, "red-sfs-busy")) red_sfs_busy();
    else if (!strcmp(scenario, "red-mounted-reset")) red_mounted_reset();
    else if (!strcmp(scenario, "red-global-reset")) red_global_reset();
    else if (!strcmp(scenario, "legacy-unmounted")) legacy_unmounted();
    else if (!strcmp(scenario, "fat-internal")) mounted_internal(1);
    else if (!strcmp(scenario, "sfs-internal")) mounted_internal(0);
    else if (!strcmp(scenario, "readonly-range")) readonly_range();
    else if (!strcmp(scenario, "partition-forwarding")) partition_forwarding();
    else if (!strcmp(scenario, "async-fallback")) async_case(0);
    else if (!strcmp(scenario, "async-inline")) async_case(1);
    else if (!strcmp(scenario, "async-deferred")) async_case(2);
    else if (!strcmp(scenario, "mount-rollback")) mount_rollback();
    else if (!strcmp(scenario, "vfs-shutdown")) vfs_shutdown_case();
    else if (!strcmp(scenario, "registry")) registry_case();
    else return 64;
    CHECK(irq_depth == 0 && fake_if == 1 && irq_misuse == 0, "irq-restore-balanced");
    CHECK(backend0.bad_args == 0 && backend1.bad_args == 0, "backend-argument-contract");
    printf("STORAGE_AUTHORITY_RED_HOST scenario=%s checks=%u failures=%u reset0=%u reset1=%u mounts=%u irq_depth=%u\n",
           scenario, checks, failures, backend0.resets, backend1.resets, vfs_mount_count(), irq_depth);
    return failures ? 1 : 0;
}
