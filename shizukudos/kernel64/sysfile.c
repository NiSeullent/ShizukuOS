/* SPDX-License-Identifier: GPL-2.0-only
 * File-related system calls over the in-memory file system (NT structures and semantics).
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

static uint64_t node_time(const fsnode_t *n, int which)              /* 0 creation, 1 last access, 2 last write */
{
    if (which == 0) return n->ft_create ? (uint64_t)n->ft_create : ft_of_ticks(n->ctime);
    if (which == 1 && n->ft_access) return (uint64_t)n->ft_access;
    return n->ft_write ? (uint64_t)n->ft_write : ft_of_ticks(n->mtime);
}

/* UTF-8 -> UTF-16 (names are stored as UTF-8); returns the number of UTF-16 units written (at most cap). */
static uint32_t utf8_to_utf16(const char *s, uint16_t *w, uint32_t cap)
{
    uint32_t o = 0;
    while (*s) {
        uint32_t c = (uint8_t)*s++;
        if (c >= 0xf0 && s[0] && s[1] && s[2]) { c = ((c & 7) << 18) | ((s[0] & 0x3f) << 12) | ((s[1] & 0x3f) << 6) | (s[2] & 0x3f); s += 3; }
        else if (c >= 0xe0 && s[0] && s[1]) { c = ((c & 15) << 12) | ((s[0] & 0x3f) << 6) | (s[1] & 0x3f); s += 2; }
        else if (c >= 0xc0 && s[0]) { c = ((c & 31) << 6) | (s[0] & 0x3f); s += 1; }
        if (c >= 0x10000) {
            if (o + 2 > cap) break;
            c -= 0x10000;
            w[o++] = (uint16_t)(0xd800 + (c >> 10));
            w[o++] = (uint16_t)(0xdc00 + (c & 0x3ff));
        } else {
            if (o + 1 > cap) break;
            w[o++] = (uint16_t)c;
        }
    }
    return o;
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

static int32_t sys_create_file(process_t *p, struct regs *r, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    struct objattr oa;
    char path[300];
    const uint32_t disposition = (uint32_t)stack_arg(p, r, 8), options = (uint32_t)stack_arg(p, r, 9);
    const uint32_t fattrs = (uint32_t)stack_arg(p, r, 6);
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
    /* Only volume C: exists: another drive letter names no device (Windows: the \??\Z: link is missing, so the path is not found). */
    if (path[0] == '\\' && path[1] == '?' && path[2] == '?' && path[3] == '\\' && path[4] && path[5] == ':' && (path[4] | 32) != 'c')
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
            while (left) {
                chunk = left > sizeof line - 1 ? sizeof line - 1 : left;
                if (copy_from_user(p, line, at, chunk)) return STATUS_ACCESS_VIOLATION;
                line[chunk] = 0;
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
        set_iosb(p, iosb, STATUS_END_OF_FILE, 0);          /* no console input source yet */
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
        int64_t idx = f->node ? (int64_t)f->node->id : 0;
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
            nchars += utf8_to_utf16(c->name, w + nchars, 512 - nchars);
        }
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
        if (!f->node || node_ro(f->node) || len < 20 || copy_from_user(p, hdr, buf, 20)) return STATUS_ACCESS_DENIED;
        chars = *(uint32_t *)(hdr + 16) / 2;
        if (chars >= 260 || len < 20 + chars * 2ull || copy_from_user(p, w, buf + 20, chars * 2ull)) return STATUS_INVALID_PARAMETER;
        if (utf16_to_utf8(w, chars, newpath, sizeof newpath) < 0) return STATUS_OBJECT_NAME_INVALID;
        dst = fs_lookup(newpath);
        if (dst && dst != f->node) {
            if (!hdr[0] || dst->is_dir || node_ro(dst)) return STATUS_OBJECT_NAME_COLLISION;
            fs_remove(dst);
        }
        dir = fs_create(newpath, f->node->is_dir, 0);       /* create the destination entry (empty) ... */
        if (!dir) return STATUS_OBJECT_PATH_NOT_FOUND;
        if (dir != f->node) {                                /* ... then move the payload into it */
            dir->data = f->node->data; dir->size = f->node->size; dir->cap = f->node->cap; dir->attrs = f->node->attrs;
            dir->child = f->node->child;
            { fsnode_t *c; for (c = dir->child; c; c = c->sibling) c->parent = dir; }
            dir->open_count = f->node->open_count;
            dir->id = f->node->id;                            /* a rename keeps the file's identity, times and attributes */
            dir->ctime = f->node->ctime; dir->mtime = f->node->mtime;
            dir->ft_create = f->node->ft_create; dir->ft_access = f->node->ft_access; dir->ft_write = f->node->ft_write;
            f->node->data = 0; f->node->size = f->node->cap = 0; f->node->child = 0;
            f->node->delete_pending = 1;
            fs_remove(f->node);
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

/* FILE_BOTH_DIR_INFORMATION prefix. Packed so that FileName starts at offset 94 as in the documented NT layout (without packing the
 * compiler pads the structure to 96 and user-mode readers of the NT layout would see a name shifted by two characters). */
struct __attribute__((packed)) dirinfo {
    uint32_t next_entry, file_index;
    uint64_t create, access, write, change, eof, alloc;
    uint32_t attrs, name_len, ea_size;
    uint8_t short_len, pad;
    uint16_t short_name[12];
    /* WCHAR FileName[] follows */
};

static int32_t sys_query_directory(process_t *p, struct regs *r, uint64_t handle, uint64_t iosb_unused)
{
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5), buf = (uint64_t)stack_arg(p, r, 6);
    const uint64_t len = (uint64_t)(uint32_t)stack_arg(p, r, 7);
    const uint32_t cls = (uint32_t)stack_arg(p, r, 8);
    const int single = (int)(stack_arg(p, r, 9) & 0xff), restart = (int)(stack_arg(p, r, 11) & 0xff);
    file_t *f = file_of(p, handle, 0);
    fsnode_t *c;
    uint64_t idx = 0, written = 0, prev_at = 0;
    (void)iosb_unused;
    if (!f || !f->node) return STATUS_INVALID_HANDLE;
    if (!f->node->is_dir) return STATUS_NOT_A_DIRECTORY;
    if (cls != 1 && cls != 3 && cls != 12) return STATUS_INVALID_INFO_CLASS;
    if (restart) f->dir_index = 0;
    for (c = f->node->child; c; c = c->sibling) {
        uint8_t entry[sizeof(struct dirinfo) + 96 * 2 + 8];
        struct dirinfo *d = (struct dirinfo *)entry;
        uint16_t *wname = (uint16_t *)(entry + sizeof *d);
        uint32_t nchars = 0, size;
        if (c->delete_pending) continue;
        if (idx++ < f->dir_index) continue;
        nchars = utf8_to_utf16(c->name, wname, 95);
        memset(d, 0, sizeof *d);
        d->file_index = (uint32_t)idx;
        d->create = node_time(c, 0);
        d->write = d->change = node_time(c, 2);
        d->access = node_time(c, 1);
        d->eof = c->size;
        d->alloc = (c->size + 4095) & ~4095ull;
        d->attrs = c->attrs;
        d->name_len = nchars * 2;
        size = (uint32_t)(sizeof *d + nchars * 2);
        size = (size + 7) & ~7u;
        if (written + size > len) {
            if (!written) return STATUS_BUFFER_OVERFLOW;
            break;
        }
        if (written) {                                   /* patch the previous NextEntryOffset */
            uint32_t next = (uint32_t)(written - prev_at);
            if (copy_to_user(p, buf + prev_at, &next, 4)) return STATUS_ACCESS_VIOLATION;
        }
        if (copy_to_user(p, buf + written, entry, sizeof *d + nchars * 2)) return STATUS_ACCESS_VIOLATION;
        prev_at = written;
        written += size;
        ++f->dir_index;
        if (single) break;
    }
    if (!written) {
        set_iosb(p, iosb, STATUS_NO_MORE_FILES, 0);
        return f->dir_index == 0 && idx == 0 ? STATUS_NO_SUCH_FILE : STATUS_NO_MORE_FILES;
    }
    set_iosb(p, iosb, STATUS_SUCCESS, written);
    return STATUS_SUCCESS;
}

int32_t sysfile_dispatch(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                         int *handled)
{
    *handled = 1;
    switch (num) {
    case SYS_NtCreateFile: case SYS_NtOpenFile: return sys_create_file(p, r, a1, a2, a3, a4);
    case SYS_NtReadFile: return sys_rw_file(p, r, a1, 0);
    case SYS_NtWriteFile: return sys_rw_file(p, r, a1, 1);
    case SYS_NtQueryInformationFile: return sys_query_info_file(p, r, a1, a2, a3, a4);
    case SYS_NtSetInformationFile: return sys_set_info_file(p, r, a1, a2, a3, a4);
    case SYS_NtQueryDirectoryFile: return sys_query_directory(p, r, a1, a2);
    case SYS_NtClose:
        if (a1 == CURRENT_PROCESS_HANDLE || a1 == CURRENT_THREAD_HANDLE) return STATUS_SUCCESS;
        return handle_close(p, a1);
    case SYS_NtFlushBuffersFile: return file_of(p, a1, 0) ? STATUS_SUCCESS : STATUS_INVALID_HANDLE;
    case SYS_NtCancelIoFile:                             /* (FileHandle, IoStatusBlock): every request completes before the call returns, so none is pending */
        if (!file_of(p, a1, 0)) return STATUS_INVALID_HANDLE;
        set_iosb(p, a2, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    default: *handled = 0; return 0;
    }
}
