/* SPDX-License-Identifier: GPL-2.0-only
 * File-related system calls over the Kernel64 file systems (fs.c: RAM C:\, initrd, disk volumes; NT structures and
 * semantics).
 */
#include "fs.h"

struct ustr { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; };
struct objattr { uint32_t length, pad; uint64_t root, name; uint32_t attributes, pad2; uint64_t sd, sqos; };
struct iosb { uint64_t status; uint64_t information; };

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);
extern int k32_lock_conflict(const file_t *f, uint64_t off, uint64_t len, int write);       /* sysk32.c: byte-range locks */
extern void k32_locks_release(const file_t *f);

#define IO_OPENED 1
#define IO_CREATED 2
#define IO_OVERWRITTEN 3
#define IO_SUPERSEDED 0
#define IO_EXISTS 4
#define IO_DOES_NOT_EXIST 5
#define FILE_READ_DATA 1
#define FILE_WRITE_DATA 2
#define FILE_APPEND_DATA 4
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define DELETE_ACCESS 0x10000u
#define FILE_WRITE_ATTRIBUTES 0x100u
#define GENERIC_ALL 0x10000000u
#ifndef STATUS_FILE_LOCK_CONFLICT
#define STATUS_FILE_LOCK_CONFLICT ((int32_t)0xC0000054)
#endif
#ifndef STATUS_MEDIA_WRITE_PROTECTED
#define STATUS_MEDIA_WRITE_PROTECTED ((int32_t)0xC00000A2)
#endif

extern int64_t filetime_now(void);                  /* wall-clock FILETIME (sysx.c, the same clock as NtQuerySystemTime) */

/* File times are kept as the millisecond tick count of the moment they happened; they become FILETIMEs of the real wall clock by adding
 * the wall-clock FILETIME of tick 0, taken from the Supervisor RTC the first time a time is needed. */
static uint64_t ft_of_ticks(uint64_t ticks)
{
    static uint64_t base;
    if (!base) base = (uint64_t)filetime_now() - ticks_now() * 10000ull;
    return base + ticks * 10000ull;
}

/* A node is write-protected if it lives in the read-only initrd or carries FILE_ATTRIBUTE_READONLY. */
static int node_ro(const fsnode_t *n) { return n->readonly || (n->attrs & FILE_ATTRIBUTE_READONLY); }

/* Times explicitly set with FileBasicInformation win; otherwise a disk node reports its directory entry's times (FAT has no
 * separate access time: the write time is reported) and a RAM node the ticks of its creation / last change. */
static uint64_t node_time(const fsnode_t *n, int which)              /* 0 creation, 1 last access, 2 last write */
{
    uint64_t c, w;
    if (which == 0 && n->ft_create) return (uint64_t)n->ft_create;
    if (which == 1 && n->ft_access) return (uint64_t)n->ft_access;
    if (which != 0 && n->ft_write) return (uint64_t)n->ft_write;
    if (n->backing == FSB_DISK) {
        fs_node_times(n, &c, &w);
        return which == 0 ? c : w;
    }
    return ft_of_ticks(which == 0 ? n->ctime : n->mtime);
}

/* FileInternalInformation.IndexNumber and the FileId of the directory classes: the same value for one file. A disk node
 * is identified by where its directory entry lives (stable across mounts); the volume root and RAM nodes by their node id. */
static uint64_t node_file_id(const fsnode_t *n)
{
    if (n->backing == FSB_DISK && n->dir_cluster) return (uint64_t)n->dir_cluster << 32 | n->dir_offset;
    return n->id;
}

static int set_iosb(process_t *p, uint64_t user, int32_t status, uint64_t info)
{
    struct iosb v;
    if (!user) return 0;
    v.status = (uint64_t)(int64_t)status;
    v.information = info;
    return copy_to_user(p, user, &v, sizeof v);
}

static int32_t read_ustr(process_t *p, uint64_t uva, char *out, size_t cap)
{
    struct ustr u;
    uint16_t tmp[260];
    if (copy_from_user(p, &u, uva, sizeof u)) return STATUS_ACCESS_VIOLATION;
    if (u.length & 1 || u.length / 2 >= 260) return STATUS_OBJECT_NAME_INVALID;
    if (u.length && copy_from_user(p, tmp, u.buffer, u.length)) return STATUS_ACCESS_VIOLATION;
    if (utf16_to_utf8(tmp, u.length / 2, out, cap) < 0) return STATUS_OBJECT_NAME_INVALID;
    return STATUS_SUCCESS;
}

/* Console device objects handed out as standard handles. */
kobject_t *console_object(int output)
{
    kobject_t *o = ob_create(OB_FILE, 0);
    file_t *f = kzalloc(sizeof *f);
    if (!o || !f) return 0;
    f->console = output ? 2 : 1;
    f->access = output ? GENERIC_WRITE : GENERIC_READ;
    o->u.file.file = f;
    return o;
}

static file_t *file_of(process_t *p, uint64_t h, kobject_t **obj)
{
    kobject_t *o = handle_lookup(p, h, OB_FILE);
    if (obj) *obj = o;
    return o ? (file_t *)o->u.file.file : 0;
}

void file_object_closed(kobject_t *o)
{
    file_t *f;
    if (o->refs != 1) return;                           /* other handles remain */
    f = o->u.file.file;
    if (!f) return;
    k32_locks_release(f);                               /* closing the last handle drops the byte-range locks of the file object */
    if (f->node) {
        if (f->node->open_count) --f->node->open_count;
        if (f->node->delete_pending && f->node->open_count == 0)
            fs_remove(f->node);
    }
    if (f->dir_pattern) kfree(f->dir_pattern);
    kfree(f);
    o->u.file.file = 0;
}

/* Status for a path that does not exist: STATUS_OBJECT_PATH_NOT_FOUND when its directory is missing (or is not a directory),
 * STATUS_OBJECT_NAME_NOT_FOUND when only the last component is. */
static int32_t missing_status(const char *path)
{
    char dir[300];
    size_t n = strlen(path), cut = n;
    fsnode_t *d;
    if (n >= sizeof dir) return STATUS_OBJECT_PATH_NOT_FOUND;
    while (cut && path[cut - 1] == '\\') --cut;                   /* ignore a trailing separator */
    while (cut && path[cut - 1] != '\\') --cut;
    if (!cut) return STATUS_OBJECT_NAME_NOT_FOUND;
    memcpy(dir, path, cut);
    dir[cut] = 0;
    d = fs_lookup(dir);
    return d && d->is_dir && !d->delete_pending ? STATUS_OBJECT_NAME_NOT_FOUND : STATUS_OBJECT_PATH_NOT_FOUND;
}

/* NtCreateFile(h, access, oa, iosb, alloc_size, attrs, share, disposition, options, ea, ea_len) and
 * NtOpenFile(h, access, oa, iosb, share, options): the open form has no disposition (FILE_OPEN) and its options are
 * the 6th argument (reading NtCreateFile's 9th slot there picked up whatever the caller's stack held). */
static int32_t sys_create_file(process_t *p, struct regs *r, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4, int open_only)
{
    struct objattr oa;
    char path[300];
    const uint32_t disposition = open_only ? FILE_OPEN : (uint32_t)stack_arg(p, r, 8);
    const uint32_t options = (uint32_t)stack_arg(p, r, open_only ? 6 : 9);
    const uint32_t fattrs = open_only ? 0 : (uint32_t)stack_arg(p, r, 6);
    int32_t st;
    fsnode_t *n;
    int created = 0;
    uint64_t info = IO_OPENED;
    file_t *f;
    kobject_t *o;
    uint32_t h;
    (void)fattrs;
    if (copy_from_user(p, &oa, a3, sizeof oa) || oa.length < sizeof oa) return STATUS_ACCESS_VIOLATION;
    if (!oa.name) return STATUS_OBJECT_NAME_INVALID;
    st = read_ustr(p, oa.name, path, sizeof path);
    if (st) return st;
    /* A drive letter without a mounted volume names no device (Windows: the \??\Z: link is missing, so the path is not found). */
    if (path[0] == '\\' && path[1] == '?' && path[2] == '?' && path[3] == '\\' && path[4] && path[5] == ':' && !fs_root_of(path[4]))
        return STATUS_OBJECT_PATH_NOT_FOUND;
    /* console pseudo-devices */
    if (!strcmp(path, "\\??\\CONOUT$") || !strcmp(path, "\\??\\CONIN$")) {
        o = console_object(path[6] == 'O');
        if (!o) return STATUS_NO_MEMORY;
        st = handle_insert(p, o, (uint32_t)a2, &h);
        ob_deref(o);
        if (st) return st;
        if (copy_to_user(p, a1, &(uint64_t){h}, 8)) return STATUS_ACCESS_VIOLATION;
        set_iosb(p, a4, STATUS_SUCCESS, IO_OPENED);
        return STATUS_SUCCESS;
    }
    n = fs_lookup(path);
    if (n && n->delete_pending) n = 0;
    switch (disposition) {
    case FILE_OPEN: if (!n) { st = missing_status(path); set_iosb(p, a4, st, IO_DOES_NOT_EXIST); return st; } break;
    case FILE_CREATE: if (n) { set_iosb(p, a4, STATUS_OBJECT_NAME_COLLISION, IO_EXISTS); return STATUS_OBJECT_NAME_COLLISION; } break;
    case FILE_OVERWRITE: if (!n) return missing_status(path); break;
    case FILE_SUPERSEDE: case FILE_OPEN_IF: case FILE_OVERWRITE_IF: break;
    default: return STATUS_INVALID_PARAMETER;
    }
    if (!n) {
        n = fs_create(path, (options & FILE_DIRECTORY_FILE) != 0, &created);
        if (!n) return fs_lookup("\\") ? STATUS_OBJECT_PATH_NOT_FOUND : STATUS_OBJECT_NAME_INVALID;
        info = IO_CREATED;
    } else {
        if ((options & FILE_DIRECTORY_FILE) && !n->is_dir) return STATUS_NOT_A_DIRECTORY;
        if ((options & FILE_NON_DIRECTORY_FILE) && n->is_dir) return STATUS_FILE_IS_A_DIRECTORY;
        if (!n->is_dir && (disposition == FILE_OVERWRITE || disposition == FILE_OVERWRITE_IF || disposition == FILE_SUPERSEDE)) {
            if (node_ro(n)) return STATUS_ACCESS_DENIED;
            fs_truncate(n, 0);
            info = disposition == FILE_SUPERSEDE ? IO_SUPERSEDED : IO_OVERWRITTEN;
        }
    }
    if ((a2 & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE_ACCESS)) && node_ro(n) && !created)
        return STATUS_ACCESS_DENIED;
    if ((options & FILE_DELETE_ON_CLOSE) && n->backing == FSB_DISK) return STATUS_NOT_SUPPORTED;   /* no delete on disk */
    if (n->is_dir && (a2 & (GENERIC_WRITE | FILE_WRITE_DATA))) return STATUS_FILE_IS_A_DIRECTORY;
    f = kzalloc(sizeof *f);
    o = ob_create(OB_FILE, 0);
    if (!f || !o) return STATUS_NO_MEMORY;
    f->node = n;
    f->access = (uint32_t)a2;
    f->append = (a2 & FILE_APPEND_DATA) && !(a2 & FILE_WRITE_DATA);
    ++n->open_count;
    if (options & FILE_DELETE_ON_CLOSE) n->delete_pending = 1;
    o->u.file.file = f;
    o->u.file.access = (uint32_t)a2;
    st = handle_insert(p, o, (uint32_t)a2, &h);
    ob_deref(o);
    if (st) return st;
    if (copy_to_user(p, a1, &(uint64_t){h}, 8)) return STATUS_ACCESS_VIOLATION;
    set_iosb(p, a4, STATUS_SUCCESS, info);
    return STATUS_SUCCESS;
}

static int32_t sys_rw_file(process_t *p, struct regs *r, uint64_t handle, int write)
{
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5), buf = (uint64_t)stack_arg(p, r, 6);
    const uint64_t len = (uint64_t)(uint32_t)stack_arg(p, r, 7), off_ptr = (uint64_t)stack_arg(p, r, 8);
    file_t *f = file_of(p, handle, 0);
    uint64_t off, done = 0;
    uint8_t *tmp;
    uint64_t chunk;
    if (!f) return STATUS_INVALID_HANDLE;
    if (f->console) {
        if (write) {
            char line[128];
            uint64_t left = len, at = buf;
            const int bridged = p->console_sink != 0;           /* WIN64 subsystem bridge (subsys64.c) */
            while (left) {
                chunk = left > sizeof line - 1 ? sizeof line - 1 : left;
                if (copy_from_user(p, line, at, chunk)) return STATUS_ACCESS_VIOLATION;
                line[chunk] = 0;
                if (bridged && subsys64_console_write(p, handle == 12 ? 2 : 1, line, chunk)) {
                    left -= chunk; at += chunk;
                    continue;
                }
                {
                    /* console output goes to the Supervisor console, tagged with the process */
                    static char pending[256];
                    static unsigned plen;
                    uint64_t i;
                    for (i = 0; i < chunk; ++i) {
                        if (line[i] == '\r') continue;
                        if (line[i] == '\n' || plen >= sizeof pending - 1) {
                            pending[plen] = 0;
                            kprintf("[win64 %s pid %d] %s\n", p->name, p->pid, pending);
                            plen = 0;
                            if (line[i] == '\n') continue;
                        }
                        pending[plen++] = line[i];
                    }
                }
                left -= chunk; at += chunk;
            }
            set_iosb(p, iosb, STATUS_SUCCESS, len);
            return STATUS_SUCCESS;
        }
        if (p->console_sink && len) {                       /* bridged stdin: blocks until data, EOF or termination */
            uint8_t tmp[256];
            uint64_t got = 0;
            if (subsys64_console_read(p, tmp, len > sizeof tmp ? sizeof tmp : len, &got)) {
                if (got && copy_to_user(p, buf, tmp, got)) return STATUS_ACCESS_VIOLATION;
                set_iosb(p, iosb, got ? STATUS_SUCCESS : STATUS_END_OF_FILE, got);
                return got ? STATUS_SUCCESS : STATUS_END_OF_FILE;
            }
        }
        set_iosb(p, iosb, STATUS_END_OF_FILE, 0);          /* no console input source without the bridge */
        return STATUS_END_OF_FILE;
    }
    if (!f->node || f->node->is_dir) return STATUS_INVALID_PARAMETER;
    if (write ? !(f->access & (GENERIC_WRITE | GENERIC_ALL | FILE_WRITE_DATA | FILE_APPEND_DATA)) : !(f->access & (GENERIC_READ | GENERIC_ALL | FILE_READ_DATA)))
        return STATUS_ACCESS_DENIED;
    if (off_ptr) {
        if (copy_from_user(p, &off, off_ptr, 8)) return STATUS_ACCESS_VIOLATION;
        if ((int64_t)off < 0) off = f->append && write ? f->node->size : f->pos;   /* FILE_USE_FILE_POINTER_POSITION */
    } else {
        off = f->pos;
    }
    if (write && f->append) off = f->node->size;
    if (len && k32_lock_conflict(f, off, len, write)) return STATUS_FILE_LOCK_CONFLICT;      /* byte-range locks held through other handles */
    tmp = kmalloc(len > 65536 ? 65536 : len ? len : 1);
    if (!tmp) return STATUS_NO_MEMORY;
    {
        uint64_t left = len, at = buf;
        while (left) {
            chunk = left > 65536 ? 65536 : left;
            if (write) {
                int rc;
                if (copy_from_user(p, tmp, at, chunk)) { kfree(tmp); return STATUS_ACCESS_VIOLATION; }
                rc = fs_write(f->node, off + done, tmp, chunk);
                if (rc) { kfree(tmp); set_iosb(p, iosb, rc == -2 ? STATUS_DISK_FULL : STATUS_ACCESS_DENIED, done);
                          return rc == -2 ? STATUS_DISK_FULL : STATUS_ACCESS_DENIED; }
                done += chunk;
            } else {
                uint64_t got = 0;
                fs_read(f->node, off + done, tmp, chunk, &got);
                if (got && copy_to_user(p, at, tmp, got)) { kfree(tmp); return STATUS_ACCESS_VIOLATION; }
                done += got;
                if (got < chunk) break;
            }
            left -= chunk; at += chunk;
        }
    }
    kfree(tmp);
    f->pos = off + done;
    if (!write && done == 0 && len) {
        set_iosb(p, iosb, STATUS_END_OF_FILE, 0);
        return STATUS_END_OF_FILE;
    }
    set_iosb(p, iosb, STATUS_SUCCESS, done);
    return STATUS_SUCCESS;
}

struct basicinfo { uint64_t create, access, write, change; uint32_t attrs, pad; };
struct stdinfo { int64_t alloc, eof; uint32_t links; uint8_t delete_pending, directory; uint16_t pad; };

static int32_t sys_query_info_file(process_t *p, struct regs *r, uint64_t handle, uint64_t iosb, uint64_t buf, uint64_t len)
{
    const uint32_t cls = (uint32_t)stack_arg(p, r, 5);
    file_t *f = file_of(p, handle, 0);
    if (!f) return STATUS_INVALID_HANDLE;
    switch (cls) {
    case 4: {                                            /* FileBasicInformation */
        struct basicinfo b;
        if (len < sizeof b) return STATUS_BUFFER_TOO_SMALL;
        memset(&b, 0, sizeof b);
        if (f->node) { b.create = node_time(f->node, 0); b.write = node_time(f->node, 2); b.access = node_time(f->node, 1);
                       b.change = b.write; b.attrs = f->node->attrs; }
        else b.attrs = f->console ? 0x40 : FILE_ATTRIBUTE_NORMAL;      /* console pseudo-device: FILE_ATTRIBUTE_DEVICE marks it for GetFileType */
        if (copy_to_user(p, buf, &b, sizeof b)) return STATUS_ACCESS_VIOLATION;
        set_iosb(p, iosb, STATUS_SUCCESS, sizeof b);
        return STATUS_SUCCESS;
    }
    case 5: {                                            /* FileStandardInformation */
        struct stdinfo s;
        if (len < sizeof s) return STATUS_BUFFER_TOO_SMALL;
        memset(&s, 0, sizeof s);
        if (f->node) { s.eof = (int64_t)f->node->size; s.alloc = (int64_t)((f->node->size + 4095) & ~4095ull);
                       s.directory = f->node->is_dir; s.delete_pending = f->node->delete_pending; s.links = 1; }
        if (copy_to_user(p, buf, &s, sizeof s)) return STATUS_ACCESS_VIOLATION;
        set_iosb(p, iosb, STATUS_SUCCESS, sizeof s);
        return STATUS_SUCCESS;
    }
    case 6: {                                            /* FileInternalInformation: {LARGE_INTEGER IndexNumber} */
        int64_t idx = f->node ? (int64_t)node_file_id(f->node) : 0;
        if (len < 8) return STATUS_BUFFER_TOO_SMALL;
        if (copy_to_user(p, buf, &idx, 8)) return STATUS_ACCESS_VIOLATION;
        set_iosb(p, iosb, STATUS_SUCCESS, 8);
        return STATUS_SUCCESS;
    }
    case 9: {                                            /* FileNameInformation: {ULONG FileNameLength; WCHAR FileName[]}, volume-relative */
        uint16_t w[512];
        const fsnode_t *chain[24];
        uint32_t depth = 0, nchars = 0, total, room, copy;
        const fsnode_t *n;
        if (!f->node) return STATUS_INVALID_PARAMETER;
        if (len < 4) return STATUS_BUFFER_TOO_SMALL;
        for (n = f->node; n && n->parent && depth < 24; n = n->parent) chain[depth++] = n;
        if (!depth) { w[nchars++] = '\\'; }
        while (depth) {
            const fsnode_t *c = chain[--depth];
            if (nchars + 1 >= 512) return STATUS_OBJECT_NAME_INVALID;
            w[nchars++] = '\\';
            const int wn = utf8_to_utf16(c->name, w + nchars, 512 - nchars);
            if (wn < 0) return STATUS_OBJECT_NAME_INVALID;
            nchars += (uint32_t)wn;
        }
        total = nchars * 2;
        room = (uint32_t)len - 4;
        copy = total < room ? total : room & ~1u;
        if (copy_to_user(p, buf, &total, 4) || (copy && copy_to_user(p, buf + 4, w, copy))) return STATUS_ACCESS_VIOLATION;
        set_iosb(p, iosb, copy < total ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS, 4 + copy);
        return copy < total ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
    }
    case 58: {                                           /* FileVolumeNameInformation: {ULONG DeviceNameLength; WCHAR DeviceName[]} */
        static const char dev[] = "\\Device\\HarddiskVolume";
        uint16_t w[32];
        uint32_t nchars = 0, total, room, copy, num, div;
        const char l = f->node ? fs_letter_of(f->node) : 0;
        if (!l) return STATUS_INVALID_PARAMETER;             /* console handles and unmounted nodes have no volume */
        if (len < 4) return STATUS_BUFFER_TOO_SMALL;
        for (num = 0; dev[num]; ++num) w[nchars++] = (uint8_t)dev[num];
        num = fs_volume_number(l);
        for (div = 10; div <= num; div *= 10) { }
        for (div /= 10; div; div /= 10) w[nchars++] = (uint16_t)('0' + num / div % 10);
        total = nchars * 2;
        room = (uint32_t)len - 4;
        copy = total < room ? total : room & ~1u;
        if (copy_to_user(p, buf, &total, 4) || (copy && copy_to_user(p, buf + 4, w, copy))) return STATUS_ACCESS_VIOLATION;
        set_iosb(p, iosb, copy < total ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS, 4 + copy);
        return copy < total ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
    }
    case 14: {                                           /* FilePositionInformation */
        int64_t pos = (int64_t)f->pos;
        if (len < 8) return STATUS_BUFFER_TOO_SMALL;
        if (copy_to_user(p, buf, &pos, 8)) return STATUS_ACCESS_VIOLATION;
        set_iosb(p, iosb, STATUS_SUCCESS, 8);
        return STATUS_SUCCESS;
    }
    case 35: {                                           /* FileAttributeTagInformation */
        uint32_t v[2] = { f->node ? f->node->attrs : FILE_ATTRIBUTE_NORMAL, 0 };
        if (len < 8) return STATUS_BUFFER_TOO_SMALL;
        if (copy_to_user(p, buf, v, 8)) return STATUS_ACCESS_VIOLATION;
        set_iosb(p, iosb, STATUS_SUCCESS, 8);
        return STATUS_SUCCESS;
    }
    default: return STATUS_INVALID_INFO_CLASS;
    }
}

static int32_t sys_set_info_file(process_t *p, struct regs *r, uint64_t handle, uint64_t iosb, uint64_t buf, uint64_t len)
{
    const uint32_t cls = (uint32_t)stack_arg(p, r, 5);
    file_t *f = file_of(p, handle, 0);
    if (!f) return STATUS_INVALID_HANDLE;
    switch (cls) {
    case 14: {                                           /* position */
        int64_t pos;
        if (len < 8 || copy_from_user(p, &pos, buf, 8)) return STATUS_ACCESS_VIOLATION;
        if (pos < 0) return STATUS_INVALID_PARAMETER;
        f->pos = (uint64_t)pos;
        set_iosb(p, iosb, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    case 20: {                                           /* FileEndOfFileInformation */
        int64_t eof;
        if (!f->node || len < 8 || copy_from_user(p, &eof, buf, 8)) return STATUS_ACCESS_VIOLATION;
        if (eof < 0) return STATUS_INVALID_PARAMETER;
        if (fs_truncate(f->node, (uint64_t)eof)) return STATUS_ACCESS_DENIED;
        set_iosb(p, iosb, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    case 10: {                                           /* FileRenameInformation: {u8 replace, root, u32 len, WCHAR name[]} */
        uint8_t hdr[20];
        uint16_t w[260];
        char newpath[300];
        fsnode_t *dst, *dir;
        char leaf[96];
        uint32_t chars;
        if (f->node && f->node->backing == FSB_DISK) return STATUS_NOT_SUPPORTED;            /* no rename on disk volumes */
        if (!f->node || node_ro(f->node) || len < 20 || copy_from_user(p, hdr, buf, 20)) return STATUS_ACCESS_DENIED;
        chars = *(uint32_t *)(hdr + 16) / 2;
        if (chars >= 260 || len < 20 + chars * 2ull || copy_from_user(p, w, buf + 20, chars * 2ull)) return STATUS_INVALID_PARAMETER;
        if (utf16_to_utf8(w, chars, newpath, sizeof newpath) < 0) return STATUS_OBJECT_NAME_INVALID;
        {                                                /* the target directory must be on the file's volume (a disk volume refuses renames above) */
            char dpath[300];
            size_t cut = strlen(newpath);
            const fsnode_t *a, *b;
            while (cut && newpath[cut - 1] != '\\') --cut;
            memcpy(dpath, newpath, cut);
            dpath[cut] = 0;
            a = cut ? fs_lookup(dpath) : 0;
            b = f->node;
            if (a) {
                while (a->parent) a = a->parent;
                while (b->parent) b = b->parent;
                if (a != b) return (int32_t)0xC00000D4;              /* STATUS_NOT_SAME_DEVICE */
            }
        }
        dst = fs_lookup(newpath);
        if (dst && dst != f->node) {
            if (!hdr[0] || dst->is_dir || node_ro(dst)) return STATUS_OBJECT_NAME_COLLISION;
            fs_remove(dst);
        }
        fs_notify_suppress = 1;                              /* reported below as one rename (ipc_notify.c) */
        dir = fs_create(newpath, f->node->is_dir, 0);       /* create the destination entry (empty) ... */
        fs_notify_suppress = 0;
        if (!dir) return STATUS_OBJECT_PATH_NOT_FOUND;
        if (dir != f->node) {                                /* ... then move the payload into it */
            fs_notify_rename(f->node, dir);
            dir->data = f->node->data; dir->size = f->node->size; dir->cap = f->node->cap; dir->attrs = f->node->attrs;
            dir->child = f->node->child;
            { fsnode_t *c; for (c = dir->child; c; c = c->sibling) c->parent = dir; }
            dir->open_count = f->node->open_count;
            dir->id = f->node->id;                            /* a rename keeps the file's identity, times and attributes */
            dir->ctime = f->node->ctime; dir->mtime = f->node->mtime;
            dir->ft_create = f->node->ft_create; dir->ft_access = f->node->ft_access; dir->ft_write = f->node->ft_write;
            f->node->data = 0; f->node->size = f->node->cap = 0; f->node->child = 0;
            f->node->delete_pending = 1;
            fs_notify_suppress = 1;
            fs_remove(f->node);
            fs_notify_suppress = 0;
            f->node = dir;
        }
        (void)leaf;
        set_iosb(p, iosb, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    case 4: {                                            /* FileBasicInformation: times (0 and -1 leave a time alone) and attributes (0 = unchanged) */
        struct basicinfo b;
        uint32_t a;
        if (!f->node || len < sizeof b || copy_from_user(p, &b, buf, sizeof b)) return STATUS_ACCESS_VIOLATION;
        if (!(f->access & (FILE_WRITE_ATTRIBUTES | GENERIC_WRITE | GENERIC_ALL))) return STATUS_ACCESS_DENIED;   /* handle lacks FILE_WRITE_ATTRIBUTES */
        if (f->node->readonly) return STATUS_MEDIA_WRITE_PROTECTED;                                 /* initrd files live on read-only media */
        /* The disk volume code (disk.c) has no operation that rewrites a directory entry's attributes or times, and keeping them
         * only in the node would report values the media does not hold: a disk node accepts the request only when it changes nothing. */
        if (f->node->backing == FSB_DISK &&
            (b.attrs || (b.create && b.create != ~0ull) || (b.access && b.access != ~0ull) || (b.write && b.write != ~0ull)))
            return STATUS_NOT_SUPPORTED;
        if (b.attrs) {
            a = b.attrs & (FILE_ATTRIBUTE_READONLY | 0x2 | 0x4 | 0x20 | 0x100 | 0x1000 | 0x2000);   /* readonly, hidden, system, archive, temporary, offline, not indexed */
            if (b.attrs & ~(a | FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_DIRECTORY)) return STATUS_INVALID_PARAMETER;
            f->node->attrs = f->node->is_dir ? (a | FILE_ATTRIBUTE_DIRECTORY) : (a ? a : FILE_ATTRIBUTE_NORMAL);
        }
        if (b.create && b.create != ~0ull) f->node->ft_create = (int64_t)b.create;
        if (b.access && b.access != ~0ull) f->node->ft_access = (int64_t)b.access;
        if (b.write && b.write != ~0ull) f->node->ft_write = (int64_t)b.write;
        set_iosb(p, iosb, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    case 13: {                                           /* FileDispositionInformation */
        uint8_t del;
        if (!f->node || copy_from_user(p, &del, buf, 1)) return STATUS_ACCESS_VIOLATION;
        if (node_ro(f->node)) return STATUS_ACCESS_DENIED;
        if (del && f->node->backing == FSB_DISK) return STATUS_NOT_SUPPORTED;                /* no delete on disk volumes */
        if (del && f->node->is_dir && f->node->child) return STATUS_DIRECTORY_NOT_EMPTY;
        f->node->delete_pending = del != 0;
        set_iosb(p, iosb, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    case 11:                                             /* FileLinkInformation (CreateHardLink) */
        /* A file of this RAM file system is one directory entry with its own payload (fsnode), so a second name for the same
         * file cannot exist. The volume does not report FILE_SUPPORTS_HARD_LINKS (sysk32.c FileFsAttributeInformation) and, like
         * FAT, refuses the request as an invalid device request. */
        if (!f->node) return STATUS_INVALID_PARAMETER;
        return (int32_t)0xC0000010;                      /* STATUS_INVALID_DEVICE_REQUEST */
    default: return STATUS_INVALID_INFO_CLASS;
    }
}

/* NtQueryDirectoryFile information classes and where their fields sit (documented Windows x64 layouts; entries are
 * 8-byte aligned and linked by NextEntryOffset):
 *   1 FileDirectoryInformation        name length @60, FileName @64
 *   2 FileFullDirectoryInformation    name length @60, EaSize @64, FileName @68
 *   3 FileBothDirectoryInformation    ... EaSize @64, ShortNameLength @68 (CCHAR), ShortName[12] @70, FileName @94
 *  12 FileNamesInformation            name length @8, FileName @12
 *  37 FileIdBothDirectoryInformation  as 3 up to ShortName, FileId @96, FileName @104
 *  38 FileIdFullDirectoryInformation  as 2 up to EaSize, FileId @72, FileName @80
 * Classes 1/2/3/37/38 share: FileIndex @4, CreationTime @8, LastAccessTime @16, LastWriteTime @24, ChangeTime @32,
 * EndOfFile @40, AllocationSize @48, FileAttributes @56. (kernel32's FindFirstFile on the lead branch, k32_file.c
 * fill_find, reads FileName at 92 instead of 94: a user-mode bug; the kernel writes the documented layout.) */
static int dir_class_layout(uint32_t cls, unsigned *name_off, unsigned *len_off)
{
    switch (cls) {
    case 1: *name_off = 64; *len_off = 60; return 1;
    case 2: *name_off = 68; *len_off = 60; return 1;
    case 3: *name_off = 94; *len_off = 60; return 1;
    case 12: *name_off = 12; *len_off = 8; return 1;
    case 37: *name_off = 104; *len_off = 60; return 1;
    case 38: *name_off = 80; *len_off = 60; return 1;
    default: return 0;
    }
}

static uint16_t up16(uint16_t c) { return c >= 'a' && c <= 'z' ? (uint16_t)(c - 32) : c; }

/* FsRtlIsNameInExpression-style match, case-insensitive (ASCII folding): '*' any run, '?' one character,
 * DOS_STAR '<' any run up to the last '.', DOS_QM '>' one character or nothing before a '.'/the end,
 * DOS_DOT '"' a '.' or nothing at the end. */
static int wild(const uint16_t *p, const uint16_t *n)
{
    for (;;) {
        const uint16_t c = *p;
        if (!c) return !*n;
        if (c == '*') {
            while (*p == '*') ++p;
            if (!*p) return 1;
            for (; *n; ++n) if (wild(p, n)) return 1;
            return wild(p, n);
        }
        if (c == '<') {                                  /* DOS_STAR: consumes up to (not past) the name's last '.' */
            const uint16_t *last_dot = 0, *q, *limit;
            for (q = n; *q; ++q) if (*q == '.') last_dot = q;
            limit = last_dot ? last_dot : q;
            for (q = n; q <= limit; ++q) if (wild(p + 1, q)) return 1;
            return 0;
        }
        if (c == '>') {                                  /* DOS_QM */
            if (!*n || *n == '.') { ++p; continue; }
            ++p; ++n; continue;
        }
        if (c == '"') {                                  /* DOS_DOT */
            if (*n == '.') { ++p; ++n; continue; }
            if (!*n) { ++p; continue; }
            return 0;
        }
        if (!*n) return 0;
        if (c != '?' && up16(c) != up16(*n)) return 0;
        ++p; ++n;
    }
}

static int32_t sys_query_directory(process_t *p, struct regs *r, uint64_t handle, uint64_t iosb_unused)
{
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5), buf = (uint64_t)stack_arg(p, r, 6);
    const uint64_t len = (uint64_t)(uint32_t)stack_arg(p, r, 7);
    const uint32_t cls = (uint32_t)stack_arg(p, r, 8);
    const int single = (int)(stack_arg(p, r, 9) & 0xff), restart = (int)(stack_arg(p, r, 11) & 0xff);
    const uint64_t name_us = (uint64_t)stack_arg(p, r, 10);
    file_t *f = file_of(p, handle, 0);
    fsnode_t *c;
    uint64_t idx = 0, written = 0, prev_at = 0;
    unsigned name_off, len_off;
    int first_call;
    (void)iosb_unused;
    if (!f || !f->node) return STATUS_INVALID_HANDLE;
    if (!f->node->is_dir) return STATUS_NOT_A_DIRECTORY;
    if (!dir_class_layout(cls, &name_off, &len_off)) return STATUS_INVALID_INFO_CLASS;
    if (restart) f->dir_index = 0;
    first_call = !f->dir_started || restart;
    if (first_call && (name_us || !f->dir_started)) {    /* the pattern is fixed by the first call (or a restart) */
        struct ustr u;
        uint16_t *pat = 0;
        if (name_us) {
            if (copy_from_user(p, &u, name_us, sizeof u)) return STATUS_ACCESS_VIOLATION;
            if (u.length & 1 || u.length > 512) return STATUS_OBJECT_NAME_INVALID;
            if (u.length) {
                pat = kzalloc(u.length + 2u);
                if (!pat) return STATUS_NO_MEMORY;
                if (copy_from_user(p, pat, u.buffer, u.length)) { kfree(pat); return STATUS_ACCESS_VIOLATION; }
            }
        }
        if (f->dir_pattern) kfree(f->dir_pattern);
        f->dir_pattern = pat;
    }
    f->dir_started = 1;
    fs_populate(f->node);                                /* disk directory: enumerate on first use */
    for (c = f->node->child; c; c = c->sibling) {
        uint8_t entry[112 + FS_NAME_MAX * 2 + 8];
        uint16_t wname[FS_NAME_MAX];
        uint32_t nchars = 0, size;
        int wn;
        if (c->delete_pending) continue;
        if (idx++ < f->dir_index) continue;
        wn = utf8_to_utf16(c->name, wname, FS_NAME_MAX);
        nchars = wn < 0 ? 0 : (uint32_t)wn;
        if (f->dir_pattern && !wild(f->dir_pattern, wname)) { ++f->dir_index; continue; }
        memset(entry, 0, name_off);
        *(uint32_t *)(entry + 4) = (uint32_t)idx;                              /* FileIndex */
        *(uint32_t *)(entry + len_off) = nchars * 2;                           /* FileNameLength */
        if (cls != 12) {
            *(uint64_t *)(entry + 8) = node_time(c, 0);
            *(uint64_t *)(entry + 16) = node_time(c, 1);                       /* LastAccessTime */
            *(uint64_t *)(entry + 24) = node_time(c, 2);
            *(uint64_t *)(entry + 32) = node_time(c, 2);                       /* ChangeTime */
            *(uint64_t *)(entry + 40) = c->size;
            *(uint64_t *)(entry + 48) = (c->size + 4095) & ~4095ull;
            *(uint32_t *)(entry + 56) = c->attrs;
        }
        if ((cls == 3 || cls == 37) && c->alias[0]) {                          /* ShortName: the 8.3 alias */
            unsigned k;
            for (k = 0; c->alias[k] && k < 12; ++k) *(uint16_t *)(entry + 70 + 2 * k) = (uint8_t)c->alias[k];
            entry[68] = (uint8_t)(k * 2);
        }
        if (cls == 37 || cls == 38)                                            /* FileId: FileInternalInformation's IndexNumber */
            *(uint64_t *)(entry + (cls == 37 ? 96 : 72)) = node_file_id(c);
        memcpy(entry + name_off, wname, nchars * 2);
        size = (uint32_t)(name_off + nchars * 2);
        size = (size + 7) & ~7u;
        if (written + name_off + nchars * 2 > len) {
            if (!written) {
                set_iosb(p, iosb, STATUS_BUFFER_OVERFLOW, 0);
                return len < name_off ? STATUS_BUFFER_TOO_SMALL : STATUS_BUFFER_OVERFLOW;
            }
            break;
        }
        if (written) {                                   /* patch the previous NextEntryOffset */
            uint32_t next = (uint32_t)(written - prev_at);
            if (copy_to_user(p, buf + prev_at, &next, 4)) return STATUS_ACCESS_VIOLATION;
        }
        if (copy_to_user(p, buf + written, entry, name_off + nchars * 2)) return STATUS_ACCESS_VIOLATION;
        prev_at = written;
        written += size;
        ++f->dir_index;
        if (single) break;
        if (written >= len) break;
    }
    if (!written) {
        const int32_t st = first_call ? STATUS_NO_SUCH_FILE : STATUS_NO_MORE_FILES;
        set_iosb(p, iosb, st, 0);
        return st;
    }
    set_iosb(p, iosb, STATUS_SUCCESS, written);
    return STATUS_SUCCESS;
}

int32_t sysfile_dispatch(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                         int *handled)
{
    *handled = 1;
    switch (num) {
    case SYS_NtCreateFile: return sys_create_file(p, r, a1, a2, a3, a4, 0);
    case SYS_NtOpenFile: return sys_create_file(p, r, a1, a2, a3, a4, 1);
    case SYS_NtReadFile: return sys_rw_file(p, r, a1, 0);
    case SYS_NtWriteFile: return sys_rw_file(p, r, a1, 1);
    case SYS_NtQueryInformationFile: return sys_query_info_file(p, r, a1, a2, a3, a4);
    case SYS_NtSetInformationFile: return sys_set_info_file(p, r, a1, a2, a3, a4);
    case SYS_NtQueryDirectoryFile: return sys_query_directory(p, r, a1, a2);
    case SYS_NtClose:
        if (a1 == CURRENT_PROCESS_HANDLE || a1 == CURRENT_THREAD_HANDLE) return STATUS_SUCCESS;
        return handle_close(p, a1);
    case SYS_NtFlushBuffersFile: {
        file_t *f = file_of(p, a1, 0);
        if (!f) return STATUS_INVALID_HANDLE;
        if (f->node && fs_flush(f->node)) { set_iosb(p, a2, (int32_t)0xC0000185, 0); return (int32_t)0xC0000185; }  /* STATUS_IO_DEVICE_ERROR */
        set_iosb(p, a2, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    case SYS_NtCancelIoFile:                             /* (FileHandle, IoStatusBlock): every request completes before the call returns, so none is pending */
        if (!file_of(p, a1, 0)) return STATUS_INVALID_HANDLE;
        set_iosb(p, a2, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    default: *handled = 0; return 0;
    }
}
