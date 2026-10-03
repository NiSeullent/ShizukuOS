/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 volume mount table (see vfs_mounts.h).
 */
#include "vfs_mounts.h"
#include "blk_authority.h"

static vfs_mount_t table[VFS_MAX_MOUNTS];
static unsigned count;
static int shutting_down;

static void copy_str(char *dst, const char *src, size_t cap)
{
    size_t i = 0;
    if (src)
        for (; src[i] && i + 1 < cap; ++i) dst[i] = src[i];
    dst[i] = 0;
}

char vfs_mount_next(fsnode_t *root, fsvol_t *vol, const char *fstype, const char *device, int (*shutdown)(fsvol_t *))
{
    char l;
    blk_dev_t *backing;
    if (count >= VFS_MAX_MOUNTS || !root || !vol) return 0;
    /* Kernel mount owner resolves its actual registered device before exposing
     * namespace state. A claim or unknown device refuses the mount. */
    backing = device ? blk_find(device) : 0;
    if (blk_authority_enter(backing, 1)) return 0;
    for (l = 'D'; l <= 'Z'; ++l) {
        if (fs_root_of(l)) continue;
        if (fs_mount(l, root)) continue;
        backing->flags |= BLK_F_MOUNTED;
        blk_authority_leave(backing, 0, 0);
        vol->letter = l;
        table[count].letter = l;
        copy_str(table[count].fstype, fstype, sizeof table[count].fstype);
        copy_str(table[count].device, device, sizeof table[count].device);
        table[count].vol = vol;
        table[count].root = root;
        table[count].shutdown = shutdown;
        ++count;
        return l;
    }
    blk_authority_leave(backing, 0, 0);
    return 0;
}

const vfs_mount_t *vfs_mount_by_device(const char *device)
{
    unsigned i;
    for (i = 0; i < count; ++i)
        if (!strcmp(table[i].device, device)) return &table[i];
    return 0;
}

const vfs_mount_t *vfs_mount_at(unsigned index) { return index < count ? &table[index] : 0; }
unsigned vfs_mount_count(void) { return count; }

int vfs_flush_all(void)
{
    unsigned i;
    int bad = 0;
    for (i = 0; i < count; ++i)
        if (table[i].vol->flush && table[i].vol->flush(table[i].vol)) bad++;
    return bad ? -1 : 0;
}

void vfs_shutdown(void)
{
    unsigned i;
    if (shutting_down) return;
    shutting_down = 1;
    for (i = 0; i < count; ++i) {
        int rc = table[i].shutdown ? table[i].shutdown(table[i].vol)
                                   : (table[i].vol->flush ? table[i].vol->flush(table[i].vol) : 0);
        kprintf("K64 vfs: shutdown %c: (%s on %s): rc %d\n", table[i].letter, table[i].fstype, table[i].device, rc);
    }
}
