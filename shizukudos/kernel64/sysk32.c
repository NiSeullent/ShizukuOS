/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 system calls that back kernel32.dll functions with no NT-level equivalent among the earlier system calls (numbers 0x90-0x9f,
 * routed here by sysext.c). Structures use the Windows x64 layouts.
 */
#include "fs.h"

#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((int32_t)0xC0000010)
#endif
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH ((int32_t)0xC0000004)
#endif

#define K64_VOLUME_SERIAL 0x53485a31u         /* "SHZ1": the volume serial number of C: (the RAM file system has no on-disk one) */

extern int64_t filetime_now(void);
extern int disk_volume_info(const fsnode_t *n, uint32_t *serial, char label[12], uint64_t *total_clusters, uint64_t *free_clusters,
                            uint32_t *sectors_per_cluster, int *writable);                  /* disk.c: FAT32 volumes (D:) */

static file_t *k32_file_of(process_t *p, uint64_t h)
{
    kobject_t *o = handle_lookup(p, h, OB_FILE);
    return o ? (file_t *)o->u.file.file : 0;
}

/* Copies `len` bytes of a result into the caller's buffer and reports the size in the IO_STATUS_BLOCK (status + information). */
static int32_t put_result(process_t *p, uint64_t iosb, uint64_t buf, uint64_t buflen, const void *v, uint32_t len, int32_t st)
{
    uint64_t io[2];
    const uint64_t n = len < buflen ? len : buflen;
    if (copy_to_user(p, buf, v, n)) return STATUS_ACCESS_VIOLATION;
    io[0] = (uint64_t)(int64_t)st;
    io[1] = n;
    if (iosb && copy_to_user(p, iosb, io, sizeof io)) return STATUS_ACCESS_VIOLATION;
    return st;
}

static uint32_t put_utf16_ascii(uint8_t *dst, const char *s)
{
    uint32_t n = 0;
    while (s[n]) { dst[n * 2] = (uint8_t)s[n]; dst[n * 2 + 1] = 0; ++n; }
    return n * 2;
}

/* NtQueryVolumeInformationFile(FileHandle, IoStatusBlock, FsInformation, Length, FsInformationClass) */
static int32_t sys_query_volume(process_t *p, struct regs *r, uint64_t handle, uint64_t iosb, uint64_t buf, uint64_t len)
{
    extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);
    const uint32_t cls = (uint32_t)stack_arg(p, r, 5);
    file_t *f = k32_file_of(p, handle);
    uint8_t out[64];
    uint32_t dserial = 0, dspc = 0;
    uint64_t dtotal = 0, dfree = 0;
    char dlabel[12];
    int dwritable = 0, disk;
    if (!f) return STATUS_INVALID_HANDLE;
    memset(out, 0, sizeof out);
    /* A file on a disk volume (disk.c, FAT32) reports that volume: BPB serial number and label, cluster counts, "FAT32". */
    disk = f->node && disk_volume_info(f->node, &dserial, dlabel, &dtotal, &dfree, &dspc, &dwritable) == 0;
    switch (cls) {
    case 1: {                                                   /* FileFsVolumeInformation */
        /* FAT keeps no volume creation time (0 is reported); the RAM volume comes into existence at boot */
        const uint64_t created = disk ? 0 : (uint64_t)filetime_now() - ticks_now() * 10000ull;
        const uint32_t label = put_utf16_ascii(out + 18, disk ? dlabel : "SHIZUKU");
        if (f->console) return STATUS_INVALID_DEVICE_REQUEST;
        if (len < 18) return STATUS_INFO_LENGTH_MISMATCH;
        memcpy(out, &created, 8);
        *(uint32_t *)(out + 8) = disk ? dserial : K64_VOLUME_SERIAL;
        *(uint32_t *)(out + 12) = label;
        out[16] = 0;                                            /* SupportsObjects: no object ids */
        return put_result(p, iosb, buf, len, out, 18 + label, 18 + label <= len ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW);
    }
    case 3: case 7: {                                           /* FileFsSizeInformation / FileFsFullSizeInformation */
        /* File data is allocated from the kernel heap (fs.c reserve -> kmalloc), so the volume's capacity is that heap and its free space
         * is what the heap has left (shared with other kernel allocations). Allocation unit: 4 KiB = 8 sectors of 512 bytes. */
        const uint64_t unit = 4096;
        const uint64_t total_units = kheap_total() / unit;
        const uint64_t used = kheap_used();
        const uint64_t free_units = used < kheap_total() ? (kheap_total() - used) / unit : 0;
        const uint64_t total = disk ? dtotal : total_units, avail = disk ? dfree : free_units;
        const uint32_t spc = disk ? dspc : 8;                   /* a disk volume: its clusters */
        uint32_t n;
        if (f->console) return STATUS_INVALID_DEVICE_REQUEST;
        if (cls == 3) {
            if (len < 24) return STATUS_INFO_LENGTH_MISMATCH;
            memcpy(out, &total, 8); memcpy(out + 8, &avail, 8);
            *(uint32_t *)(out + 16) = spc; *(uint32_t *)(out + 20) = 512;
            n = 24;
        } else {
            if (len < 32) return STATUS_INFO_LENGTH_MISMATCH;
            memcpy(out, &total, 8); memcpy(out + 8, &avail, 8); memcpy(out + 16, &avail, 8);
            *(uint32_t *)(out + 24) = spc; *(uint32_t *)(out + 28) = 512;
            n = 32;
        }
        return put_result(p, iosb, buf, len, out, n, STATUS_SUCCESS);
    }
    case 4: {                                                   /* FileFsDeviceInformation */
        if (len < 8) return STATUS_INFO_LENGTH_MISMATCH;
        *(uint32_t *)out = f->console == 3 ? 0x15 : f->console ? 0x50 : 7;   /* FILE_DEVICE_NULL / FILE_DEVICE_CONSOLE / FILE_DEVICE_DISK */
        *(uint32_t *)(out + 4) = disk && !dwritable ? 0x2 : 0;  /* FILE_READ_ONLY_DEVICE */
        return put_result(p, iosb, buf, len, out, 8, STATUS_SUCCESS);
    }
    case 5: {                                                   /* FileFsAttributeInformation */
        const uint32_t name = put_utf16_ascii(out + 12, disk ? "FAT32" : "SHZFS");
        if (f->console) return STATUS_INVALID_DEVICE_REQUEST;
        if (len < 12) return STATUS_INFO_LENGTH_MISMATCH;
        /* FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK (lookups ignore case); a disk volume that cannot be written adds
         * FILE_READ_ONLY_VOLUME. Longest component: what fsnode.name holds (FS_NAME_MAX UTF-8 bytes with the NUL) on
         * either volume kind (VFAT itself allows 255 UTF-16 units). */
        *(uint32_t *)out = 0x2 | 0x4 | (disk && !dwritable ? 0x80000u : 0);
        *(int32_t *)(out + 4) = FS_NAME_MAX - 1;
        *(uint32_t *)(out + 8) = name;
        return put_result(p, iosb, buf, len, out, 12 + name, 12 + name <= len ? STATUS_SUCCESS : STATUS_BUFFER_OVERFLOW);
    }
    default: return STATUS_INVALID_INFO_CLASS;
    }
}

/* ---------------------------------------------------------------- byte-range locks
 * A lock belongs to a file object (all handles duplicated from one open share it, a second open is a different owner), as on NT.
 * Rules (FsRtlFastLock / FsRtlCheckLockFor{Read,Write}Access):
 *   - an exclusive request conflicts with every overlapping lock; a shared request conflicts with overlapping exclusive locks
 *     (also the owner's own);
 *   - reading conflicts with overlapping exclusive locks of other owners; writing conflicts with overlapping shared locks
 *     (whoever owns them) and with exclusive locks of other owners;
 *   - unlocking needs a lock of the same owner with exactly the same offset and length.
 * Locks may lie beyond the end of the file. The table is fixed-size; when it is full a lock request fails with
 * STATUS_INSUFFICIENT_RESOURCES. Waiting for a conflicting lock is the caller's business (kernel32 polls). */
#ifndef STATUS_LOCK_NOT_GRANTED
#define STATUS_LOCK_NOT_GRANTED ((int32_t)0xC0000055)
#endif
#ifndef STATUS_RANGE_NOT_LOCKED
#define STATUS_RANGE_NOT_LOCKED ((int32_t)0xC000007E)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((int32_t)0xC000009A)
#endif

#define MAX_LOCKS 256
static struct { const file_t *owner; uint64_t node_id, off, len; int excl; } locks[MAX_LOCKS];      /* owner == 0: free slot */

static uint64_t sat_end(uint64_t off, uint64_t len) { return off + len < off ? UINT64_MAX : off + len; }
static int overlaps(uint64_t ao, uint64_t al, uint64_t bo, uint64_t bl)
{
    return al && bl && ao < sat_end(bo, bl) && bo < sat_end(ao, al);
}

int k32_lock_conflict(const file_t *f, uint64_t off, uint64_t len, int write)
{
    int i, hit = 0;
    uint64_t fl;
    if (!f->node) return 0;
    fl = irq_save();
    for (i = 0; i < MAX_LOCKS && !hit; ++i) {
        if (!locks[i].owner || locks[i].node_id != f->node->id || !overlaps(off, len, locks[i].off, locks[i].len)) continue;
        if (write) hit = !locks[i].excl || locks[i].owner != f;
        else hit = locks[i].excl && locks[i].owner != f;
    }
    irq_restore(fl);
    return hit;
}

void k32_locks_release(const file_t *f)
{
    int i;
    const uint64_t fl = irq_save();
    for (i = 0; i < MAX_LOCKS; ++i)
        if (locks[i].owner == f) locks[i].owner = 0;
    irq_restore(fl);
}

/* NtLockFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, ByteOffset, Length, Key, FailImmediately, ExclusiveLock).
 * This implementation never queues a request: a conflict is reported as STATUS_LOCK_NOT_GRANTED whatever FailImmediately says. */
static int32_t sys_lock_file(process_t *p, struct regs *r, uint64_t handle)
{
    extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5), offp = (uint64_t)stack_arg(p, r, 6), lenp = (uint64_t)stack_arg(p, r, 7);
    const int excl = (int)((uint64_t)stack_arg(p, r, 10) & 0xff);
    file_t *f = k32_file_of(p, handle);
    uint64_t off, len, fl;
    int i, slot = -1;
    if (!f) return STATUS_INVALID_HANDLE;
    if (!f->node || f->node->is_dir) return STATUS_INVALID_PARAMETER;
    if (copy_from_user(p, &off, offp, 8) || copy_from_user(p, &len, lenp, 8)) return STATUS_ACCESS_VIOLATION;
    if ((int64_t)off < 0) return STATUS_INVALID_PARAMETER;
    if (len && off + (len - 1) < off) return (int32_t)0xC00001A1;          /* STATUS_INVALID_LOCK_RANGE; a length up to 2^64-1 from 0 is valid */
    if (len == 0) return STATUS_SUCCESS;                                                         /* nothing to lock */
    fl = irq_save();
    for (i = 0; i < MAX_LOCKS; ++i) {
        if (!locks[i].owner) { if (slot < 0) slot = i; continue; }
        if (locks[i].node_id != f->node->id || !overlaps(off, len, locks[i].off, locks[i].len)) continue;
        if (excl || locks[i].excl) { irq_restore(fl); return STATUS_LOCK_NOT_GRANTED; }
    }
    if (slot < 0) { irq_restore(fl); return STATUS_INSUFFICIENT_RESOURCES; }
    locks[slot].owner = f; locks[slot].node_id = f->node->id; locks[slot].off = off; locks[slot].len = len; locks[slot].excl = excl;
    irq_restore(fl);
    if (iosb) { uint64_t io[2] = { 0, 0 }; copy_to_user(p, iosb, io, sizeof io); }
    return STATUS_SUCCESS;
}

/* NtUnlockFile(FileHandle, IoStatusBlock, ByteOffset, Length, Key) */
static int32_t sys_unlock_file(process_t *p, struct regs *r, uint64_t handle, uint64_t iosb, uint64_t offp, uint64_t lenp)
{
    file_t *f = k32_file_of(p, handle);
    uint64_t off, len, fl;
    int i, found = 0;
    (void)r;
    if (!f) return STATUS_INVALID_HANDLE;
    if (!f->node) return STATUS_INVALID_PARAMETER;
    if (copy_from_user(p, &off, offp, 8) || copy_from_user(p, &len, lenp, 8)) return STATUS_ACCESS_VIOLATION;
    fl = irq_save();
    for (i = 0; i < MAX_LOCKS && !found; ++i)
        if (locks[i].owner == f && locks[i].off == off && locks[i].len == len) { locks[i].owner = 0; found = 1; }
    irq_restore(fl);
    if (!found) return STATUS_RANGE_NOT_LOCKED;
    if (iosb) { uint64_t io[2] = { 0, 0 }; copy_to_user(p, iosb, io, sizeof io); }
    return STATUS_SUCCESS;
}

int32_t sys_ext_k32(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    switch (num) {
    case SYS_NtQueryVolumeInformationFile: return sys_query_volume(cur, r, a1, a2, a3, a4);
    case SYS_NtLockFile: return sys_lock_file(cur, r, a1);
    case SYS_NtUnlockFile: return sys_unlock_file(cur, r, a1, a2, a3, a4);
    case SYS_NtShzQueryK32: {                   /* process, thread and memory information: sysk32_proc.c */
        extern int32_t k32_query(process_t *cur, struct regs *r, uint64_t cls, uint64_t h, uint64_t buf, uint64_t len);
        return k32_query(cur, r, a1, a2, a3, a4);
    }
    case SYS_NtShzSetK32: {
        extern int32_t k32_set(process_t *cur, uint64_t cls, uint64_t h, uint64_t buf, uint64_t len);
        return k32_set(cur, a1, a2, a3, a4);
    }
    default: {                                  /* 0x9d-0x9e: access tokens, security descriptors (sysk32_sec.c) */
        extern int32_t sys_ext_k32_obj(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4);
        return sys_ext_k32_obj(cur, r, num, a1, a2, a3, a4);
    }
    }
}
