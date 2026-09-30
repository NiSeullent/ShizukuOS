/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 directory change notification (NtNotifyChangeDirectoryFile, behind ReadDirectoryChangesW).
 *
 * The first request on a directory handle creates a watch with its completion filter, subtree flag and a change buffer
 * of the request's size (at most 16 KiB). The RAM file system reports every change (fs.c: fs_notify): entries created,
 * removed, renamed, written or resized. A change a watch cares about completes its pending request with
 * FILE_NOTIFY_INFORMATION records (names relative to the watched directory), or - when no request is pending - is kept in
 * the watch's buffer for the next one; a buffer overflow makes the next request complete with STATUS_NOTIFY_ENUM_DIR and no
 * records, as on Windows. Closing the directory's last handle completes a pending request with STATUS_NOTIFY_CLEANUP.
 */
#include "ipc.h"

#define FILE_NOTIFY_CHANGE_FILE_NAME 0x001u
#define FILE_NOTIFY_CHANGE_DIR_NAME 0x002u
#define FILE_NOTIFY_CHANGE_ATTRIBUTES 0x004u
#define FILE_NOTIFY_CHANGE_SIZE 0x008u
#define FILE_NOTIFY_CHANGE_LAST_WRITE 0x010u
#define FILE_NOTIFY_CHANGE_CREATION 0x040u
#define FILE_NOTIFY_VALID 0xfffu
#define STATUS_NOTIFY_ENUM_DIR_L ((int32_t)0x0000010C)
#define MAX_WATCH_BUFFER 16384u
#define FILE_LIST_DIRECTORY_ACCESS 0x0001u

typedef struct dwatch {
    struct dwatch *next;
    kobject_t *fobj;                    /* the directory's file object (no reference; the watch dies with its last handle) */
    fsnode_t *dir;
    uint32_t filter;
    int subtree, overflow;
    irp_t *pending;
    uint8_t *buf;                       /* records kept while no request is pending */
    uint32_t cap, used, last;           /* capacity, bytes used, offset of the last record */
} dwatch_t;

static dwatch_t *g_watches;
int fs_notify_suppress;                 /* sysfile.c renames: the create/remove pair is reported as one rename */

static dwatch_t *watch_of(kobject_t *o)
{
    dwatch_t *w;
    for (w = g_watches; w; w = w->next) if (w->fobj == o) return w;
    return 0;
}

/* UTF-16 path of `n` relative to `dir` (`dir` must be an ancestor); returns chars, 0 when it does not fit. */
static uint32_t rel_name(fsnode_t *dir, fsnode_t *n, uint16_t *out, uint32_t cap)
{
    fsnode_t *chain[16], *c;
    uint32_t depth = 0, len = 0, i;
    for (c = n; c && c != dir; c = c->parent) { if (depth == 16) return 0; chain[depth++] = c; }
    if (c != dir) return 0;
    while (depth--) {
        const uint8_t *s = (const uint8_t *)chain[depth]->name;
        if (len && len < cap) out[len++] = '\\';
        for (i = 0; s[i]; ) {                           /* UTF-8 -> UTF-16 */
            uint32_t cp = s[i];
            if (cp < 0x80) i += 1;
            else if ((cp & 0xe0) == 0xc0 && s[i + 1]) { cp = ((cp & 0x1f) << 6) | (s[i + 1] & 0x3f); i += 2; }
            else if ((cp & 0xf0) == 0xe0 && s[i + 1] && s[i + 2]) { cp = ((cp & 0x0f) << 12) | ((s[i + 1] & 0x3f) << 6) | (s[i + 2] & 0x3f); i += 3; }
            else { cp = '?'; i += 1; }
            if (len >= cap) return 0;
            out[len++] = (uint16_t)cp;
        }
    }
    return len;
}

static int is_ancestor(fsnode_t *a, fsnode_t *n)
{
    for (n = n ? n->parent : 0; n; n = n->parent) if (n == a) return 1;
    return 0;
}

/* Appends one FILE_NOTIFY_INFORMATION record to the watch's buffer (interrupts off). */
static void buffer_record(dwatch_t *w, uint32_t action, const uint16_t *name, uint32_t chars)
{
    const uint32_t size = (12u + chars * 2u + 3u) & ~3u;
    uint32_t hdr[3];
    if (w->overflow) return;
    if (!w->buf || w->used + size > w->cap) { w->overflow = 1; return; }
    if (w->used) {
        const uint32_t next = w->used - w->last;
        memcpy(w->buf + w->last, &next, 4);             /* the previous record now points at this one */
    }
    hdr[0] = 0; hdr[1] = action; hdr[2] = chars * 2u;
    memcpy(w->buf + w->used, hdr, 12);
    memcpy(w->buf + w->used + 12, name, chars * 2u);
    memset(w->buf + w->used + 12 + chars * 2u, 0, size - 12 - chars * 2u);
    w->last = w->used;
    w->used += size;
}

/* Hands the buffered records (or the overflow) to the pending request (interrupts off). */
static void deliver(dwatch_t *w)
{
    irp_t *irp = w->pending;
    if (!irp || (!w->used && !w->overflow)) return;
    w->pending = 0;
    irp->owner = 0;
    if (w->overflow || w->used > irp->len) {
        w->overflow = 0;
        w->used = w->last = 0;
        irp_complete(irp, STATUS_NOTIFY_ENUM_DIR_L, 0);
        return;
    }
    if (copy_to_user(irp->proc, irp->buf, w->buf, w->used)) {
        w->used = w->last = 0;
        irp_complete(irp, STATUS_ACCESS_VIOLATION, 0);
        return;
    }
    irp_complete(irp, STATUS_SUCCESS, w->used);
    w->used = w->last = 0;
}

/* fs.c: `n` changed (FILE_ACTION_* in `action`, FILE_NOTIFY_CHANGE_* in `what`). Runs in the changing thread. */
void fs_notify(fsnode_t *n, uint32_t action, uint32_t what)
{
    dwatch_t *w;
    uint16_t name[260];
    uint64_t f;
    if (fs_notify_suppress || !n || !n->parent) return;
    f = irq_save();
    for (w = g_watches; w; w = w->next) {
        uint32_t chars;
        if (!(w->filter & what)) continue;
        if (n->parent != w->dir && !(w->subtree && is_ancestor(w->dir, n))) continue;
        chars = rel_name(w->dir, n, name, 260);
        if (!chars) continue;
        buffer_record(w, action, name, chars);
        deliver(w);
    }
    irq_restore(f);
}

/* sysfile.c renames: RENAMED_OLD_NAME for `from`, RENAMED_NEW_NAME for `to` (both still linked). */
void fs_notify_rename(fsnode_t *from, fsnode_t *to)
{
    const uint32_t what = from->is_dir ? FILE_NOTIFY_CHANGE_DIR_NAME : FILE_NOTIFY_CHANGE_FILE_NAME;
    const int saved = fs_notify_suppress;
    fs_notify_suppress = 0;
    fs_notify(from, 4 /* FILE_ACTION_RENAMED_OLD_NAME */, what);
    fs_notify(to, 5 /* FILE_ACTION_RENAMED_NEW_NAME */, what);
    fs_notify_suppress = saved;
}

static void cancel_watch_irp(irp_t *irp)
{
    dwatch_t *w = irp->owner;
    if (w && w->pending == irp) w->pending = 0;
    irp->owner = 0;
}

/* The directory's last handle is gone (ipc_core.c). */
void notify_handle_closed(kobject_t *o)
{
    dwatch_t **pp, *w = 0;
    const uint64_t f = irq_save();
    for (pp = &g_watches; *pp; pp = &(*pp)->next)
        if ((*pp)->fobj == o) { w = *pp; *pp = w->next; break; }
    if (w && w->pending) {
        irp_t *irp = w->pending;
        w->pending = 0;
        irp->owner = 0;
        irp_complete(irp, STATUS_NOTIFY_CLEANUP, 0);
    }
    irq_restore(f);
    if (w) { kfree(w->buf); kfree(w); }
}

/* NtNotifyChangeDirectoryFile(Directory, Event, ApcRoutine, ApcContext, IOSB, Buffer, Length, CompletionFilter, WatchTree) */
static int32_t sys_notify(process_t *p, struct regs *r, uint64_t h, uint64_t event, uint64_t apc, uint64_t apc_ctx)
{
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5), buf = (uint64_t)stack_arg(p, r, 6);
    const uint32_t len = (uint32_t)stack_arg(p, r, 7), filter = (uint32_t)stack_arg(p, r, 8);
    const int subtree = (stack_arg(p, r, 9) & 0xff) != 0;
    kobject_t *o;
    file_t *file;
    dwatch_t *w, *fresh = 0;
    irp_t *irp;
    uint32_t access = 0;
    uint64_t f;
    int32_t st;
    if (!filter || (filter & ~FILE_NOTIFY_VALID)) return STATUS_INVALID_PARAMETER;
    st = ipc_ref_handle(p, h, OB_FILE, &o, &access);
    if (st) return st;
    file = o->u.file.file;
    if (!file || !file->node || !file->node->is_dir) { ob_deref(o); return STATUS_INVALID_PARAMETER; }
    if (!(access & (FILE_LIST_DIRECTORY_ACCESS | GENERIC_READ_ACCESS | GENERIC_ALL_ACCESS))) { ob_deref(o); return STATUS_ACCESS_DENIED; }
    f = irq_save();
    w = watch_of(o);
    irq_restore(f);
    if (!w) {                                            /* the first request sets the filter and the buffer size */
        fresh = kzalloc(sizeof *fresh);
        if (fresh) {
            fresh->cap = len < MAX_WATCH_BUFFER ? len : MAX_WATCH_BUFFER;
            fresh->buf = fresh->cap ? kmalloc(fresh->cap) : 0;
        }
        if (!fresh || (fresh->cap && !fresh->buf)) { if (fresh) kfree(fresh->buf); kfree(fresh); ob_deref(o); return STATUS_INSUFFICIENT_RESOURCES; }
        fresh->fobj = o;
        fresh->dir = file->node;
        fresh->filter = filter;
        fresh->subtree = subtree;
    }
    st = irp_prepare(p, o, event, apc, apc_ctx, iosb, IRP_READ, &irp);
    if (st) { if (fresh) { kfree(fresh->buf); kfree(fresh); } ob_deref(o); return st; }
    irp->buf = buf;
    irp->len = len;
    f = irq_save();
    if (fresh) {
        w = watch_of(o);                                 /* another thread may have raced us */
        if (!w) { w = fresh; w->next = g_watches; g_watches = w; fresh = 0; }
    }
    if (w->pending) {                                    /* one request at a time per handle */
        irq_restore(f);
        irp_complete(irp, STATUS_INVALID_PARAMETER, 0);
    } else {
        w->pending = irp;
        irp->owner = w;
        irp->cancel = cancel_watch_irp;
        irp_mark_pending(irp);
        deliver(w);                                      /* changes kept since the last request complete it at once */
        irq_restore(f);
    }
    if (fresh) { kfree(fresh->buf); kfree(fresh); }
    ob_deref(o);
    return irp_finish(irp);
}

int32_t ipc_notify_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                           int *handled)
{
    *handled = num == SYS_NtNotifyChangeDirectoryFile;
    return *handled ? sys_notify(p, r, a1, a2, a3, a4) : 0;
}
