/* SPDX-License-Identifier: GPL-2.0-only
 * File-related system calls over the in-memory file system (NT structures and semantics).
 */
#include "fs.h"

struct ustr { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; };
struct objattr { uint32_t length, pad; uint64_t root, name; uint32_t attributes, pad2; uint64_t sd, sqos; };
struct iosb { uint64_t status; uint64_t information; };

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);

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
    if (f->node) {
        if (f->node->open_count) --f->node->open_count;
        if (f->node->delete_pending && f->node->open_count == 0)
            fs_remove(f->node);
    }
    kfree(f);
    o->u.file.file = 0;
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
    case FILE_OPEN: if (!n) { set_iosb(p, a4, STATUS_OBJECT_NAME_NOT_FOUND, IO_DOES_NOT_EXIST); return STATUS_OBJECT_NAME_NOT_FOUND; } break;
    case FILE_CREATE: if (n) { set_iosb(p, a4, STATUS_OBJECT_NAME_COLLISION, IO_EXISTS); return STATUS_OBJECT_NAME_COLLISION; } break;
    case FILE_OVERWRITE: if (!n) return STATUS_OBJECT_NAME_NOT_FOUND; break;
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
            if (n->readonly) return STATUS_ACCESS_DENIED;
            fs_truncate(n, 0);
            info = disposition == FILE_SUPERSEDE ? IO_SUPERSEDED : IO_OVERWRITTEN;
        }
    }
    if ((a2 & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA | DELETE_ACCESS)) && n->readonly && !created)
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
    if (write ? !(f->access & (GENERIC_WRITE | FILE_WRITE_DATA | FILE_APPEND_DATA)) : !(f->access & (GENERIC_READ | FILE_READ_DATA | 0x120089)))
        return STATUS_ACCESS_DENIED;
    if (off_ptr) {
        if (copy_from_user(p, &off, off_ptr, 8)) return STATUS_ACCESS_VIOLATION;
        if ((int64_t)off < 0) off = f->append && write ? f->node->size : f->pos;   /* FILE_USE_FILE_POINTER_POSITION */
    } else {
        off = f->pos;
    }
    if (write && f->append) off = f->node->size;
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
        if (f->node) { b.create = 132000000000000000ull + f->node->ctime * 10000; b.write = 132000000000000000ull + f->node->mtime * 10000;
                       b.access = b.write; b.change = b.write; b.attrs = f->node->attrs; }
        else b.attrs = FILE_ATTRIBUTE_NORMAL;
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
        if (!f->node || f->node->readonly || len < 20 || copy_from_user(p, hdr, buf, 20)) return STATUS_ACCESS_DENIED;
        chars = *(uint32_t *)(hdr + 16) / 2;
        if (chars >= 260 || len < 20 + chars * 2ull || copy_from_user(p, w, buf + 20, chars * 2ull)) return STATUS_INVALID_PARAMETER;
        if (utf16_to_utf8(w, chars, newpath, sizeof newpath) < 0) return STATUS_OBJECT_NAME_INVALID;
        dst = fs_lookup(newpath);
        if (dst && dst != f->node) {
            if (!hdr[0] || dst->is_dir || dst->readonly) return STATUS_OBJECT_NAME_COLLISION;
            fs_remove(dst);
        }
        dir = fs_create(newpath, f->node->is_dir, 0);       /* create the destination entry (empty) ... */
        if (!dir) return STATUS_OBJECT_PATH_NOT_FOUND;
        if (dir != f->node) {                                /* ... then move the payload into it */
            dir->data = f->node->data; dir->size = f->node->size; dir->cap = f->node->cap; dir->attrs = f->node->attrs;
            dir->child = f->node->child;
            { fsnode_t *c; for (c = dir->child; c; c = c->sibling) c->parent = dir; }
            dir->open_count = f->node->open_count;
            f->node->data = 0; f->node->size = f->node->cap = 0; f->node->child = 0;
            f->node->delete_pending = 1;
            fs_remove(f->node);
            f->node = dir;
        }
        (void)leaf;
        set_iosb(p, iosb, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    case 13: {                                           /* FileDispositionInformation */
        uint8_t del;
        if (!f->node || copy_from_user(p, &del, buf, 1)) return STATUS_ACCESS_VIOLATION;
        if (f->node->readonly) return STATUS_ACCESS_DENIED;
        if (del && f->node->is_dir && f->node->child) return STATUS_DIRECTORY_NOT_EMPTY;
        f->node->delete_pending = del != 0;
        set_iosb(p, iosb, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    default: return STATUS_INVALID_INFO_CLASS;
    }
}

/* NtQueryDirectoryFile information classes, laid out as the Windows ABI defines them (x64 offsets of FileName):
 *   1 FileDirectoryInformation 64, 2 FileFullDirectoryInformation 68, 3 FileBothDirectoryInformation 94,
 *   12 FileNamesInformation 12, 37 FileIdBothDirectoryInformation 104, 38 FileIdFullDirectoryInformation 80.
 * Common prefix (all but 12): NextEntryOffset 0, FileIndex 4, Creation/LastAccess/LastWrite/Change 8..39, EndOfFile 40,
 * AllocationSize 48, FileAttributes 56, FileNameLength 60; EaSize 64 (2,3,37,38); FileId 96 (37) or 72 (38). */
static uint32_t dirinfo_name_offset(uint32_t cls)
{
    switch (cls) {
    case 1: return 64;
    case 2: return 68;
    case 3: return 94;
    case 12: return 12;
    case 37: return 104;
    case 38: return 80;
    default: return 0;
    }
}

static void put32(uint8_t *e, uint32_t off, uint32_t v) { memcpy(e + off, &v, 4); }
static void put64(uint8_t *e, uint32_t off, uint64_t v) { memcpy(e + off, &v, 8); }

static int32_t sys_query_directory(process_t *p, struct regs *r, uint64_t handle, uint64_t iosb_unused)
{
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5), buf = (uint64_t)stack_arg(p, r, 6);
    const uint64_t len = (uint64_t)(uint32_t)stack_arg(p, r, 7);
    const uint32_t cls = (uint32_t)stack_arg(p, r, 8);
    const int single = (int)(stack_arg(p, r, 9) & 0xff), restart = (int)(stack_arg(p, r, 11) & 0xff);
    const uint32_t name_off = dirinfo_name_offset(cls);
    file_t *f = file_of(p, handle, 0);
    fsnode_t *c;
    uint64_t idx = 0, written = 0, prev_at = 0;
    (void)iosb_unused;
    if (!f || !f->node) return STATUS_INVALID_HANDLE;
    if (!f->node->is_dir) return STATUS_NOT_A_DIRECTORY;
    if (!name_off) return STATUS_INVALID_INFO_CLASS;
    if (restart) f->dir_index = 0;
    for (c = f->node->child; c; c = c->sibling) {
        uint8_t entry[104 + 96 * 2 + 8];
        uint16_t wname[96];
        uint32_t nchars = 0, size;
        if (c->delete_pending) continue;
        if (idx++ < f->dir_index) continue;
        {
            const char *s = c->name;
            while (*s && nchars < 95) wname[nchars++] = (uint8_t)*s++;
        }
        memset(entry, 0, name_off);
        put32(entry, 4, (uint32_t)idx);
        if (cls == 12) {
            put32(entry, 8, nchars * 2);
        } else {
            const uint64_t mt = 132000000000000000ull + c->mtime * 10000;
            put64(entry, 8, 132000000000000000ull + c->ctime * 10000);
            put64(entry, 16, mt);
            put64(entry, 24, mt);
            put64(entry, 32, mt);
            put64(entry, 40, c->size);
            put64(entry, 48, (c->size + 4095) & ~4095ull);
            put32(entry, 56, c->attrs);
            put32(entry, 60, nchars * 2);
            if (cls == 37) put64(entry, 96, idx);
            if (cls == 38) put64(entry, 72, idx);
        }
        memcpy(entry + name_off, wname, nchars * 2);
        size = name_off + nchars * 2;
        size = (size + 7) & ~7u;
        if (written + size > len) {
            if (!written) return STATUS_BUFFER_OVERFLOW;
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
    default: *handled = 0; return 0;
    }
}
