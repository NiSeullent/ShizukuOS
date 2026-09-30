/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 named pipes (\Device\NamedPipe, reached as \??\pipe\NAME): CreateNamedPipe, ConnectNamedPipe,
 * DisconnectNamedPipe, CreateFile on a pipe name, ReadFile/WriteFile (synchronous and overlapped, with completion
 * ports), PeekNamedPipe, TransactNamedPipe, WaitNamedPipe, SetNamedPipeHandleState / GetNamedPipeInfo /
 * GetNamedPipeHandleState, Get(NamedPipe)ClientProcessId / ServerProcessId and CreatePipe (kernel32 builds anonymous
 * pipes from uniquely named ones, as Windows does).
 *
 * Model (NPFS semantics):
 *  - A pipe NAME has 1..MaximumInstances INSTANCES; each instance is a server end (the CreateNamedPipe handle) and at
 *    most one client end (CreateFile). An instance is LISTENING from creation (a client may connect before
 *    ConnectNamedPipe, which then reports STATUS_PIPE_CONNECTED), CONNECTED, CLOSING (the other end was closed: the
 *    remaining data can still be read, then reads fail with STATUS_PIPE_BROKEN and writes with STATUS_PIPE_CLOSING) or
 *    DISCONNECTED (DisconnectNamedPipe: queued data is discarded, the client end is dead, the server may listen again).
 *  - Each direction is a queue of page-sized chunks from the physical page allocator (not the kernel heap), up to
 *    NP_MAX_QUEUE bytes; a write beyond that fails with STATUS_INSUFFICIENT_RESOURCES instead of blocking (the queue
 *    is far larger than any quota a program asks for). Message-type pipes keep message boundaries; a message read into
 *    a smaller buffer returns STATUS_BUFFER_OVERFLOW and leaves the rest of the message for the next read.
 *  - Writes complete immediately. A read with no data waits: on a synchronous handle the thread blocks, on an
 *    overlapped handle the request is queued (STATUS_PENDING) and completed by the writer, a disconnect, a close or
 *    CancelIo(Ex) through io_complete() (IO_STATUS_BLOCK, event, completion port). ConnectNamedPipe waits the same way.
 *  - Security attributes are not enforced; impersonation of the client (ImpersonateNamedPipeClient) is not provided.
 * One mutex serialises all pipe state; data is copied between user buffers with the reader's/writer's own address
 * space (copy_to_user / copy_from_user on the owning process), so a completion may fill a buffer of another process.
 */
#include "fs.h"

#define NP_DATA (PAGE_SIZE - 32)
#define NP_MAX_QUEUE (64ull << 20)

#define STATUS_PIPE_BROKEN ((int32_t)0xC000014B)
#define STATUS_PIPE_DISCONNECTED ((int32_t)0xC00000B0)
#define STATUS_PIPE_CLOSING ((int32_t)0xC00000B1)
#define STATUS_PIPE_CONNECTED ((int32_t)0xC00000B2)
#define STATUS_PIPE_LISTENING ((int32_t)0xC00000B3)
#define STATUS_PIPE_BUSY ((int32_t)0xC00000AE)
#define STATUS_PIPE_NOT_AVAILABLE ((int32_t)0xC00000AC)
#define STATUS_INSTANCE_NOT_AVAILABLE ((int32_t)0xC00000AB)
#define STATUS_INVALID_PIPE_STATE ((int32_t)0xC00000AD)
#define STATUS_INVALID_READ_MODE ((int32_t)0xC00000B4)
#define STATUS_PIPE_EMPTY ((int32_t)0xC00000D9)
#define STATUS_IO_TIMEOUT ((int32_t)0xC00000B5)
#define STATUS_ILLEGAL_FUNCTION ((int32_t)0xC00000AF)
#ifndef STATUS_INVALID_DEVICE_REQUEST
#define STATUS_INVALID_DEVICE_REQUEST ((int32_t)0xC0000010)
#endif
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((int32_t)0xC000009A)
#endif

#define FSCTL_PIPE_DISCONNECT 0x110004u
#define FSCTL_PIPE_LISTEN 0x110008u
#define FSCTL_PIPE_PEEK 0x11400Cu
#define FSCTL_PIPE_WAIT 0x110018u
#define FSCTL_PIPE_IMPERSONATE 0x11001Cu
#define FSCTL_PIPE_TRANSCEIVE 0x11C017u
#define FSCTL_PIPE_QUERY_CLIENT_PROCESS 0x110024u
#define FSCTL_PIPE_GET_PIPE_ATTRIBUTE 0x110030u

enum { NP_LISTENING = 1, NP_CONNECTED = 2, NP_CLOSING = 3, NP_DISCONNECTED = 4 };
enum { IRP_READ = 1, IRP_LISTEN = 2 };
#define NP_ROOT ((void *)1)                         /* file_t.pipe of a handle on \Device\NamedPipe\ itself */

typedef struct npchunk {
    struct npchunk *next;
    uint32_t len, off;                              /* bytes held, bytes already consumed */
    uint32_t msg_end, pad;                          /* this chunk ends a message */
    uint64_t pad2;
    uint8_t data[NP_DATA];
} npchunk_t;

typedef struct npq { npchunk_t *head, *tail; uint64_t bytes; uint32_t msgs; } npq_t;

typedef struct npirp {
    struct npirp *next;
    int kind;
    process_t *p;
    int pid;
    thread_t *thread;                               /* issuer (CancelIo cancels the calling thread's requests only) */
    kobject_t *fo, *event;                          /* referenced */
    uint64_t apc, iosb, buf;
    uint32_t len;
    int sync;                                       /* a thread blocks on `done` and finishes the request itself */
    kobject_t *done;
    int32_t status;
    uint64_t info;
    int completed;
} npirp_t;

struct npname;
typedef struct npinst {
    struct npinst *next;
    struct npname *nm;
    int state;
    kobject_t *end[2];                              /* [0] server, [1] client file objects (not referenced) */
    npq_t q[2];                                     /* q[i]: data end i reads */
    npirp_t *rd[2];                                 /* pending reads of end i */
    npirp_t *listen;
    uint32_t read_msg[2], nowait[2];
    uint64_t pid[2];
} npinst_t;

typedef struct npname {
    struct npname *next;
    char name[OB_NAME_MAX];                         /* lower case (lookups) */
    char display[OB_NAME_MAX];                      /* as created (FileNameInformation) */
    uint32_t max_inst, ninst, msg_type, in_quota, out_quota;
    uint32_t server_access;                         /* access of the first server end: the pipe's direction */
    int64_t default_timeout;
    npinst_t *inst;
    kobject_t *listen_ev;                           /* manual event, set while some instance is listening */
} npname_t;

static npname_t *names;
static kmutex_t np_lock;
static int np_ready;
static uint64_t chunks_live, pipes_created, bytes_moved;

static void lock(void) { if (!np_ready) { mutex_init(&np_lock); np_ready = 1; } mutex_lock(&np_lock); }
static void unlock(void) { mutex_unlock(&np_lock); }

extern void io_complete(process_t *p, int pid, kobject_t *fo, kobject_t *event, uint64_t apc_ctx, uint64_t iosb, int32_t status,
                        uint64_t info, int pending);
extern void io_start(kobject_t *fo, kobject_t *event);
extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);

static int access_reads(uint32_t a) { return (a & (0x80000000u | 0x10000000u | 1u)) != 0; }
static int access_writes(uint32_t a) { return (a & (0x40000000u | 0x10000000u | 2u | 4u)) != 0; }
static int is_sync(const file_t *f) { return (f->options & (FILE_SYNCHRONOUS_IO_ALERT | FILE_SYNCHRONOUS_IO_NONALERT)) != 0; }

/* ---------------------------------------------------------------- data queues */
static npchunk_t *chunk_new(void)
{
    const uint64_t pa = pmm_alloc();
    npchunk_t *c;
    if (!pa) return 0;
    c = (npchunk_t *)p2v(pa);
    c->next = 0; c->len = c->off = c->msg_end = 0;
    ++chunks_live;
    return c;
}
static void chunk_free(npchunk_t *c) { --chunks_live; pmm_free(v2p_direct((uint64_t)c)); }

static void q_clear(npq_t *q)
{
    while (q->head) { npchunk_t *n = q->head->next; chunk_free(q->head); q->head = n; }
    q->tail = 0; q->bytes = 0; q->msgs = 0;
}

/* Appends `len` bytes of process `src` at `uva`. A byte pipe fills the open tail chunk first; a message pipe starts a
 * new chunk and closes the message (a zero-length message is one empty chunk). Nothing is queued when it fails. */
static int32_t q_append(npq_t *q, process_t *src, uint64_t uva, uint64_t len, int message)
{
    npchunk_t *head = 0, *tail = 0, *t = q->tail;
    uint64_t done = 0, into_tail = 0;
    if (q->bytes + len > NP_MAX_QUEUE) return STATUS_INSUFFICIENT_RESOURCES;
    if (!message && t && !t->msg_end && t->len < NP_DATA) {
        into_tail = NP_DATA - t->len;
        if (into_tail > len) into_tail = len;
        if (into_tail && copy_from_user(src, t->data + t->len, uva, into_tail)) return STATUS_ACCESS_VIOLATION;
        done = into_tail;
    }
    while (done < len || (message && !head)) {
        npchunk_t *c = chunk_new();
        const uint64_t n = len - done > NP_DATA ? NP_DATA : len - done;
        if (!c) goto fail;
        if (tail) tail->next = c; else head = c;
        tail = c;
        if (n && copy_from_user(src, c->data, uva + done, n)) {
            while (head) { npchunk_t *nx = head->next; chunk_free(head); head = nx; }
            return STATUS_ACCESS_VIOLATION;
        }
        c->len = (uint32_t)n;
        done += n;
    }
    if (t) t->len += (uint32_t)into_tail;
    if (head) {
        if (q->tail) q->tail->next = head; else q->head = head;
        q->tail = tail;
    }
    if (message) { q->tail->msg_end = 1; ++q->msgs; }
    q->bytes += len;
    return STATUS_SUCCESS;
fail:
    while (head) { npchunk_t *nx = head->next; chunk_free(head); head = nx; }
    return STATUS_INSUFFICIENT_RESOURCES;
}

/* Reads into process `dst` (NULL: discard) at `uva`, consuming from the head (peek: copy only). msgmode: stop at the end of
 * the first message; *more = the message goes on beyond the buffer. Fully consumed chunks are freed. */
static int32_t q_read(npq_t *q, process_t *dst, uint64_t uva, uint64_t len, int msgmode, uint64_t *done, int *more, int peek)
{
    npchunk_t *c = q->head;
    uint64_t got = 0;
    *more = 0;
    while (c) {
        const uint64_t avail = c->len - c->off;
        const uint64_t n = avail < len - got ? avail : len - got;
        const int boundary = (int)c->msg_end;
        npchunk_t *nx = c->next;
        int consumed;
        if (n && dst && copy_to_user(dst, uva + got, c->data + c->off, n)) { *done = got; return STATUS_ACCESS_VIOLATION; }
        got += n;
        consumed = n == avail;
        if (!peek) {
            c->off += (uint32_t)n;
            q->bytes -= n;
            if (consumed) {
                if (boundary) --q->msgs;
                q->head = nx;
                if (!nx) q->tail = 0;
                chunk_free(c);
            }
        }
        if (!consumed) { if (msgmode) *more = 1; break; }        /* the buffer ended inside this chunk */
        if (msgmode && boundary) break;                           /* the whole message was delivered */
        if (got == len) { if (msgmode && nx) *more = 1; break; }
        c = nx;
    }
    *done = got;
    if (!peek) bytes_moved += got;
    return STATUS_SUCCESS;
}

/* Bytes of the first message (message queues) or everything (byte queues). */
static uint64_t q_first_len(const npq_t *q, int msgmode)
{
    const npchunk_t *c;
    uint64_t n = 0;
    if (!msgmode) return q->bytes;
    for (c = q->head; c; c = c->next) {
        n += c->len - c->off;
        if (c->msg_end) break;
    }
    return n;
}

static int q_has_data(const npq_t *q) { return q->head != 0; }

/* ---------------------------------------------------------------- requests */
static void irp_free(npirp_t *r)
{
    if (r->event) ob_deref(r->event);
    if (r->fo) ob_deref(r->fo);
    if (r->done) ob_deref(r->done);
    kfree(r);
}

/* Finishes a request (np_lock held). A synchronous request is handed back to its blocked thread. */
static void irp_finish(npirp_t *r, int32_t st, uint64_t info)
{
    r->status = st;
    r->info = info;
    r->completed = 1;
    if (r->sync) { ob_signal_event(r->done); return; }
    io_complete(r->p, r->pid, r->fo, r->event, r->apc, r->iosb, st, info, 1);
    irp_free(r);
}

static npirp_t *irp_new(int kind, process_t *p, kobject_t *fo, kobject_t *event, uint64_t apc, uint64_t iosb, uint64_t buf,
                        uint32_t len, int sync)
{
    npirp_t *r = kzalloc(sizeof *r);
    if (!r) return 0;
    r->kind = kind; r->p = p; r->pid = p->pid; r->thread = thread_current(); r->fo = fo; r->event = event; r->apc = apc; r->iosb = iosb; r->buf = buf;
    r->len = len; r->sync = sync;
    if (sync) {
        r->done = ob_create(OB_EVENT, 0);
        if (!r->done) { kfree(r); return 0; }
        r->done->u.event.manual = 1;
    }
    ob_ref(fo);
    if (event) ob_ref(event);
    return r;
}

static void irp_append(npirp_t **list, npirp_t *r)
{
    r->next = 0;
    while (*list) list = &(*list)->next;
    *list = r;
}

static int irp_unlink(npirp_t **list, npirp_t *r)
{
    for (; *list; list = &(*list)->next)
        if (*list == r) { *list = r->next; r->next = 0; return 1; }
    return 0;
}

static int proc_alive(process_t *p, int pid) { return p && p->used && p->pid == pid && !p->terminated; }

/* Completes the pending reads of end i that can make progress (np_lock held). */
static void pump_reads(npinst_t *in, int i)
{
    while (in->rd[i] && q_has_data(&in->q[i])) {
        npirp_t *r = in->rd[i];
        uint64_t done = 0;
        int more = 0;
        int32_t st;
        in->rd[i] = r->next;
        r->next = 0;
        st = q_read(&in->q[i], proc_alive(r->p, r->pid) ? r->p : 0, r->buf, r->len, (int)in->read_msg[i], &done, &more, 0);
        irp_finish(r, st ? st : more ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS, done);
    }
    if (in->rd[i] && (in->state == NP_CLOSING || in->state == NP_DISCONNECTED)) {
        const int32_t st = in->state == NP_CLOSING ? STATUS_PIPE_BROKEN : STATUS_PIPE_DISCONNECTED;
        while (in->rd[i]) {
            npirp_t *r = in->rd[i];
            in->rd[i] = r->next;
            irp_finish(r, st, 0);
        }
    }
}

static void name_update_listen(npname_t *nm)
{
    npinst_t *in;
    int any = 0;
    for (in = nm->inst; in; in = in->next) if (in->state == NP_LISTENING && in->end[0]) any = 1;
    if (any) ob_signal_event(nm->listen_ev); else ob_reset_event(nm->listen_ev);
}

static void name_release(npname_t *nm)
{
    npname_t **pp;
    if (nm->inst) return;
    for (pp = &names; *pp; pp = &(*pp)->next)
        if (*pp == nm) { *pp = nm->next; break; }
    ob_deref(nm->listen_ev);
    kfree(nm);
}

static void inst_free(npinst_t *in)
{
    npname_t *nm = in->nm;
    npinst_t **pp;
    for (pp = &nm->inst; *pp; pp = &(*pp)->next)
        if (*pp == in) { *pp = in->next; break; }
    q_clear(&in->q[0]);
    q_clear(&in->q[1]);
    kfree(in);
    name_update_listen(nm);
    name_release(nm);
}

/* ---------------------------------------------------------------- names */
static char lc(char c) { return c >= 'A' && c <= 'Z' ? (char)(c + 32) : c; }

/* "\??\pipe\X" or "\Device\NamedPipe\X" -> "x" (lower case). Returns 1 when `path` is in the pipe name space
 * (*leaf == "" for the root), 0 otherwise. */
int npfs_path(const char *path, char *leaf, size_t cap)
{
    static const char *const pre[] = { "\\??\\pipe\\", "\\device\\namedpipe\\", "\\??\\pipe", "\\device\\namedpipe" };
    unsigned k;
    for (k = 0; k < 4; ++k) {
        const char *a = pre[k], *b = path;
        size_t i;
        while (*a && lc(*b) == *a) { ++a; ++b; }
        if (*a) continue;
        if (k >= 2 && *b) continue;                                  /* the bare root names only */
        for (i = 0; b[i] && i + 1 < cap; ++i) leaf[i] = lc(b[i]);
        if (b[i]) return -1;                                         /* too long */
        leaf[i] = 0;
        return 1;
    }
    return 0;
}

static npname_t *name_find(const char *leaf)
{
    npname_t *nm;
    for (nm = names; nm; nm = nm->next) if (!strcmp(nm->name, leaf)) return nm;
    return 0;
}

static kobject_t *end_object(npinst_t *in, int server, uint32_t access, uint32_t options)
{
    kobject_t *o = ob_create(OB_FILE, 0);
    file_t *f = kzalloc(sizeof *f);
    if (!o || !f) { if (o) ob_deref(o); kfree(f); return 0; }
    f->pipe = in;
    f->pipe_server = server;
    f->access = access;
    f->options = options;
    o->u.file.file = f;
    o->u.file.access = access;
    o->signaled = 1;
    return o;
}

static int32_t give(process_t *p, kobject_t *o, uint32_t access, uint64_t phandle, int inherit)
{
    uint32_t h;
    uint64_t v;
    int32_t st = handle_insert(p, o, access, &h);
    if (st) return st;
    if (inherit) p->handles[h / 4 - 1].inherit = 1;
    v = h;
    if (copy_to_user(p, phandle, &v, 8)) { handle_close(p, h); return STATUS_ACCESS_VIOLATION; }
    return STATUS_SUCCESS;
}

static void set_iosb(process_t *p, uint64_t iosb, int32_t st, uint64_t info)
{
    uint64_t v[2] = { (uint64_t)(int64_t)st, info };
    if (iosb) copy_to_user(p, iosb, v, sizeof v);
}

/* NtCreateNamedPipeFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, CreateDisposition,
 * CreateOptions, NamedPipeType, ReadMode, CompletionMode, MaximumInstances, InboundQuota, OutboundQuota, DefaultTimeout) */
int32_t npfs_create(process_t *p, struct regs *r, uint64_t phandle, uint64_t access, uint64_t oa_va, uint64_t iosb)
{
    struct { uint32_t length, pad; uint64_t root, name; uint32_t attributes, pad2; uint64_t sd, sqos; } oa;
    struct { uint16_t length, maxlen; uint32_t pad; uint64_t buffer; } us;
    uint16_t w[OB_NAME_MAX + 24];
    char path[OB_NAME_MAX + 48], leaf[OB_NAME_MAX];
    const uint32_t disposition = (uint32_t)stack_arg(p, r, 6), options = (uint32_t)stack_arg(p, r, 7);
    const uint32_t type = (uint32_t)stack_arg(p, r, 8), rmode = (uint32_t)stack_arg(p, r, 9), cmode = (uint32_t)stack_arg(p, r, 10);
    const uint32_t maxi = (uint32_t)stack_arg(p, r, 11), inq = (uint32_t)stack_arg(p, r, 12), outq = (uint32_t)stack_arg(p, r, 13);
    const uint64_t pto = (uint64_t)stack_arg(p, r, 14);
    int64_t timeout = -500000000ll;                              /* 50 s, the NPFS default */
    npname_t *nm;
    npinst_t *in;
    kobject_t *o;
    int32_t st;
    int created = 0;
    if (copy_from_user(p, &oa, oa_va, sizeof oa) || !oa.name || copy_from_user(p, &us, oa.name, sizeof us)) return STATUS_ACCESS_VIOLATION;
    if ((us.length & 1) || us.length / 2 >= sizeof w / 2) return STATUS_OBJECT_NAME_INVALID;
    if (us.length && copy_from_user(p, w, us.buffer, us.length)) return STATUS_ACCESS_VIOLATION;
    if (utf16_to_utf8(w, us.length / 2, path, sizeof path) < 0) return STATUS_OBJECT_NAME_INVALID;
    if (npfs_path(path, leaf, sizeof leaf) != 1 || !leaf[0]) return STATUS_OBJECT_NAME_INVALID;
    if (type > 1 || rmode > 1 || cmode > 1 || (rmode == 1 && type == 0)) return STATUS_INVALID_PARAMETER;
    if (!maxi) return STATUS_INVALID_PARAMETER;
    if (disposition != FILE_CREATE && disposition != FILE_OPEN_IF && disposition != FILE_OPEN) return STATUS_INVALID_PARAMETER;
    if (pto && copy_from_user(p, &timeout, pto, 8)) return STATUS_ACCESS_VIOLATION;
    lock();
    nm = name_find(leaf);
    if (nm) {
        if (disposition == FILE_CREATE) { unlock(); return STATUS_ACCESS_DENIED; }          /* FILE_FLAG_FIRST_PIPE_INSTANCE */
        if (nm->ninst >= nm->max_inst) { unlock(); return STATUS_INSTANCE_NOT_AVAILABLE; }
        if (nm->msg_type != type || ((uint32_t)access & 0xC0000003u) != (nm->server_access & 0xC0000003u)) {
            unlock();
            return STATUS_ACCESS_DENIED;                                                    /* a different kind of pipe */
        }
    } else {
        if (disposition == FILE_OPEN) { unlock(); return STATUS_OBJECT_NAME_NOT_FOUND; }
        nm = kzalloc(sizeof *nm);
        if (!nm || !(nm->listen_ev = ob_create(OB_EVENT, 0))) { kfree(nm); unlock(); return STATUS_NO_MEMORY; }
        nm->listen_ev->u.event.manual = 1;
        memcpy(nm->name, leaf, strlen(leaf) + 1);
        memcpy(nm->display, path + strlen(path) - strlen(leaf), strlen(leaf) + 1);
        nm->max_inst = maxi == 0xffffffffu ? 0xffffffffu : maxi;
        nm->msg_type = type;
        nm->in_quota = inq;
        nm->out_quota = outq;
        nm->server_access = (uint32_t)access;
        nm->default_timeout = timeout;
        nm->next = names;
        names = nm;
        created = 1;
    }
    in = kzalloc(sizeof *in);
    o = in ? end_object(in, 1, (uint32_t)access, options) : 0;
    if (!o) { kfree(in); if (created) name_release(nm); unlock(); return STATUS_NO_MEMORY; }
    in->nm = nm;
    in->state = NP_LISTENING;
    in->end[0] = o;
    in->read_msg[0] = rmode;
    in->nowait[0] = cmode;
    in->pid[0] = (uint64_t)p->pid;
    in->next = nm->inst;
    nm->inst = in;
    ++nm->ninst;
    ++pipes_created;
    name_update_listen(nm);
    unlock();
    st = give(p, o, (uint32_t)access, phandle, (oa.attributes & 2) != 0);                  /* OBJ_INHERIT */
    ob_deref(o);
    if (st) return st;
    set_iosb(p, iosb, STATUS_SUCCESS, created ? 2 : 1);                                     /* FILE_CREATED / FILE_OPENED */
    return STATUS_SUCCESS;
}

/* CreateFile on a pipe name (called by NtCreateFile/NtOpenFile for a path in the pipe name space). */
int32_t npfs_open(process_t *p, const char *leaf, uint32_t access, uint32_t options, uint32_t oa_attrs, uint64_t phandle,
                  uint64_t iosb)
{
    npname_t *nm;
    npinst_t *in, *pick = 0;
    kobject_t *o;
    int32_t st;
    if (!leaf[0]) {                                              /* the file system root (WaitNamedPipe) */
        o = end_object(0, -1, access, options);
        if (!o) return STATUS_NO_MEMORY;
        ((file_t *)o->u.file.file)->pipe = NP_ROOT;
        st = give(p, o, access, phandle, (oa_attrs & 2) != 0);
        ob_deref(o);
        if (!st) set_iosb(p, iosb, STATUS_SUCCESS, 1);
        return st;
    }
    lock();
    nm = name_find(leaf);
    if (!nm) { unlock(); return STATUS_OBJECT_NAME_NOT_FOUND; }
    /* the pipe's direction: a client may not read an inbound pipe or write an outbound one */
    if ((access_reads(access) && !access_writes(nm->server_access)) || (access_writes(access) && !access_reads(nm->server_access))) {
        unlock();
        return STATUS_ACCESS_DENIED;
    }
    for (in = nm->inst; in; in = in->next)
        if (in->state == NP_LISTENING && in->end[0] && (!pick || in->listen)) pick = in;   /* prefer a waiting ConnectNamedPipe */
    if (!pick) { unlock(); return STATUS_PIPE_NOT_AVAILABLE; }
    o = end_object(pick, 0, access, options);
    if (!o) { unlock(); return STATUS_NO_MEMORY; }
    pick->state = NP_CONNECTED;
    pick->end[1] = o;
    pick->pid[1] = (uint64_t)p->pid;
    pick->read_msg[1] = 0;                                       /* a client starts in byte read mode */
    pick->nowait[1] = 0;
    if (pick->listen) { npirp_t *l = pick->listen; pick->listen = 0; irp_finish(l, STATUS_SUCCESS, 0); }
    name_update_listen(nm);
    unlock();
    st = give(p, o, access, phandle, (oa_attrs & 2) != 0);
    ob_deref(o);
    if (st) return st;
    set_iosb(p, iosb, STATUS_SUCCESS, 1);
    return STATUS_SUCCESS;
}

/* Blocks the calling thread on a synchronous request until it completes (or the thread must leave). np_lock is not held. */
static int32_t irp_wait(process_t *p, npirp_t *r, npirp_t **list, uint64_t iosb, int alertable)
{
    int32_t st;
    uint64_t info;
    ob_wait(p, &r->done, 1, 0, INT64_MAX, alertable);
    lock();
    if (!r->completed) {                                          /* woken for termination: withdraw the request */
        irp_unlink(list, r);
        r->status = STATUS_CANCELLED;
        r->info = 0;
    }
    st = r->status;
    info = r->info;
    unlock();
    irp_free(r);
    set_iosb(p, iosb, st, info);
    return st;
}

/* ---------------------------------------------------------------- read / write */
static int32_t pipe_read(process_t *p, kobject_t *fo, file_t *f, kobject_t *event, uint64_t apc, uint64_t iosb, uint64_t buf,
                         uint32_t len)
{
    npinst_t *in;
    const int i = f->pipe_server ? 0 : 1;
    npirp_t *r;
    int32_t st;
    lock();
    in = f->pipe;
    if (!in || in == NP_ROOT) { unlock(); return in ? STATUS_INVALID_DEVICE_REQUEST : STATUS_PIPE_DISCONNECTED; }
    if (!access_reads(f->access)) { unlock(); return STATUS_ACCESS_DENIED; }
    if (in->state == NP_LISTENING) { unlock(); return STATUS_PIPE_LISTENING; }
    if (in->state == NP_DISCONNECTED) { unlock(); return STATUS_PIPE_DISCONNECTED; }
    if (q_has_data(&in->q[i]) && !in->rd[i]) {
        uint64_t done = 0;
        int more = 0;
        st = q_read(&in->q[i], p, buf, len, (int)in->read_msg[i], &done, &more, 0);
        unlock();
        if (!st && more) st = STATUS_BUFFER_OVERFLOW;
        if (st == STATUS_ACCESS_VIOLATION) return st;
        if (is_sync(f)) { if (event) ob_signal_event(event); set_iosb(p, iosb, st, done); }
        else io_complete(p, p->pid, fo, event, apc, iosb, st, done, 0);
        return st;
    }
    if (in->state == NP_CLOSING) { unlock(); return STATUS_PIPE_BROKEN; }
    if (in->nowait[i]) { unlock(); return STATUS_PIPE_EMPTY; }
    r = irp_new(IRP_READ, p, fo, event, apc, iosb, buf, len, is_sync(f));
    if (!r) { unlock(); return STATUS_NO_MEMORY; }
    irp_append(&in->rd[i], r);
    if (!r->sync) {
        io_start(fo, event);
        set_iosb(p, iosb, STATUS_PENDING, 0);
        unlock();
        return STATUS_PENDING;
    }
    unlock();
    st = irp_wait(p, r, &in->rd[i], iosb, (f->options & FILE_SYNCHRONOUS_IO_ALERT) != 0);
    if (event) ob_signal_event(event);
    return st;
}

static int32_t pipe_write(process_t *p, kobject_t *fo, file_t *f, kobject_t *event, uint64_t apc, uint64_t iosb, uint64_t buf,
                          uint32_t len)
{
    npinst_t *in;
    const int o = f->pipe_server ? 1 : 0;                         /* the queue the other end reads */
    int32_t st;
    lock();
    in = f->pipe;
    if (!in || in == NP_ROOT) { unlock(); return in ? STATUS_INVALID_DEVICE_REQUEST : STATUS_PIPE_DISCONNECTED; }
    if (!access_writes(f->access)) { unlock(); return STATUS_ACCESS_DENIED; }
    if (in->state == NP_LISTENING) { unlock(); return STATUS_PIPE_LISTENING; }
    if (in->state == NP_DISCONNECTED) { unlock(); return STATUS_PIPE_DISCONNECTED; }
    if (in->state == NP_CLOSING) { unlock(); return STATUS_PIPE_CLOSING; }
    if (!len && !in->nm->msg_type) { unlock(); st = STATUS_SUCCESS; goto done; }        /* nothing to queue on a byte pipe */
    st = q_append(&in->q[o], p, buf, len, (int)in->nm->msg_type);
    if (!st) pump_reads(in, o);
    unlock();
    if (st) return st;
done:
    if (is_sync(f)) { if (event) ob_signal_event(event); set_iosb(p, iosb, STATUS_SUCCESS, len); }
    else io_complete(p, p->pid, fo, event, apc, iosb, STATUS_SUCCESS, len, 0);
    return STATUS_SUCCESS;
}

/* NtReadFile / NtWriteFile on a pipe handle: (handle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ...).
 * Returns 1 when the handle is a pipe (the status in *st). */
int npfs_rw(process_t *p, struct regs *r, uint64_t handle, int write, int32_t *st)
{
    kobject_t *fo = handle_lookup(p, handle, OB_FILE), *event = 0;
    file_t *f = fo ? fo->u.file.file : 0;
    const uint64_t hev = r->rdx, apc = r->r9;
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5), buf = (uint64_t)stack_arg(p, r, 6);
    const uint32_t len = (uint32_t)stack_arg(p, r, 7);
    if (!f || !f->pipe) return 0;
    if (hev && handle_ref(p, hev, OB_EVENT, &event, 0)) { *st = STATUS_INVALID_HANDLE; return 1; }
    ob_ref(fo);
    *st = write ? pipe_write(p, fo, f, event, apc, iosb, buf, len) : pipe_read(p, fo, f, event, apc, iosb, buf, len);
    ob_deref(fo);
    if (event) ob_deref(event);
    return 1;
}

/* ---------------------------------------------------------------- close, cancel */
/* The last handle of a file object went away (objects.c): a pipe end disconnects, its pending requests are cancelled. */
void npfs_end_closed(kobject_t *fo)
{
    file_t *f = fo->u.file.file;
    npinst_t *in;
    int i;
    if (!f || !f->pipe || f->pipe == NP_ROOT) return;
    lock();
    in = f->pipe;
    i = f->pipe_server ? 0 : 1;
    f->pipe = 0;
    while (in->rd[i]) { npirp_t *r = in->rd[i]; in->rd[i] = r->next; irp_finish(r, STATUS_CANCELLED, 0); }
    if (i == 0 && in->listen) { npirp_t *l = in->listen; in->listen = 0; irp_finish(l, STATUS_CANCELLED, 0); }
    in->end[i] = 0;
    if (i == 0) --in->nm->ninst;
    if (in->end[1 - i]) {
        if (in->state == NP_CONNECTED || in->state == NP_LISTENING) in->state = NP_CLOSING;
        pump_reads(in, 1 - i);                                   /* the survivor's waiting reads see the broken pipe */
        name_update_listen(in->nm);                              /* an orphaned client end keeps the name alive */
    } else {
        inst_free(in);
    }
    unlock();
}

/* Cancels the pending requests of a pipe handle: the one whose IO_STATUS_BLOCK is `iosb_match`, or all (`any`), optionally only
 * those issued by the calling thread (CancelIo). Returns how many. */
int npfs_cancel(kobject_t *fo, uint64_t iosb_match, int any, int this_thread)
{
    thread_t *me = thread_current();
    file_t *f = fo->u.file.file;
    npinst_t *in;
    npirp_t **pp;
    int n = 0, i;
    if (!f || !f->pipe || f->pipe == NP_ROOT) return 0;
    lock();
    in = f->pipe;
    i = f->pipe_server ? 0 : 1;
    for (pp = &in->rd[i]; *pp;) {
        npirp_t *r = *pp;
        if (!r->sync && r->fo == fo && (any || r->iosb == iosb_match) && (!this_thread || r->thread == me)) {
            *pp = r->next;
            irp_finish(r, STATUS_CANCELLED, 0);
            ++n;
        }
        else pp = &r->next;
    }
    if (i == 0 && in->listen && !in->listen->sync && in->listen->fo == fo && (any || in->listen->iosb == iosb_match) &&
        (!this_thread || in->listen->thread == me)) {
        npirp_t *l = in->listen;
        in->listen = 0;
        irp_finish(l, STATUS_CANCELLED, 0);
        ++n;
    }
    unlock();
    return n;
}

/* ---------------------------------------------------------------- FSCTLs */
/* NtFsControlFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FsControlCode, InputBuffer, InputBufferLength,
 * OutputBuffer, OutputBufferLength) for pipe handles. Returns 1 when handled. */
int npfs_fsctl(process_t *p, struct regs *r, uint64_t handle, int32_t *st_out)
{
    kobject_t *fo = handle_lookup(p, handle, OB_FILE), *event = 0;
    file_t *f = fo ? fo->u.file.file : 0;
    const uint64_t hev = r->rdx, apc = r->r9;
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5);
    const uint32_t code = (uint32_t)stack_arg(p, r, 6);
    const uint64_t in_buf = (uint64_t)stack_arg(p, r, 7), out_buf = (uint64_t)stack_arg(p, r, 9);
    const uint32_t in_len = (uint32_t)stack_arg(p, r, 8), out_len = (uint32_t)stack_arg(p, r, 10);
    npinst_t *in;
    int32_t st;
    if (!f || !f->pipe) return 0;
    if (hev && handle_ref(p, hev, OB_EVENT, &event, 0)) { *st_out = STATUS_INVALID_HANDLE; return 1; }
    ob_ref(fo);
    switch (code) {
    case FSCTL_PIPE_WAIT: {                                       /* on the root: FILE_PIPE_WAIT_FOR_BUFFER */
        uint8_t hdr[16];
        uint16_t w[OB_NAME_MAX];
        char name[OB_NAME_MAX], leaf[OB_NAME_MAX];
        uint32_t nlen;
        int64_t timeout;
        uint64_t start = ticks_now();
        npname_t *nm;
        if (f->pipe != NP_ROOT) { st = STATUS_INVALID_DEVICE_REQUEST; break; }
        if (in_len < 14 || copy_from_user(p, hdr, in_buf, 14)) { st = STATUS_INVALID_PARAMETER; break; }
        memcpy(&timeout, hdr, 8);
        memcpy(&nlen, hdr + 8, 4);
        if ((nlen & 1) || nlen / 2 >= OB_NAME_MAX || 14 + nlen > in_len || copy_from_user(p, w, in_buf + 14, nlen) ||
            utf16_to_utf8(w, nlen / 2, name, sizeof name) < 0) { st = STATUS_OBJECT_NAME_INVALID; break; }
        {
            size_t i;
            for (i = 0; name[i]; ++i) leaf[i] = lc(name[i]);
            leaf[i] = 0;
        }
        for (;;) {
            npinst_t *it;
            kobject_t *ev;
            int listening = 0;
            uint64_t budget;
            lock();
            nm = name_find(leaf);
            if (!nm) { unlock(); st = STATUS_OBJECT_NAME_NOT_FOUND; break; }
            for (it = nm->inst; it; it = it->next) if (it->state == NP_LISTENING && it->end[0]) listening = 1;
            if (listening) { unlock(); st = STATUS_SUCCESS; break; }
            if (!hdr[12]) timeout = nm->default_timeout;         /* TimeoutSpecified == FALSE: the pipe's default */
            ev = nm->listen_ev;
            ob_ref(ev);
            unlock();
            budget = timeout == INT64_MIN || timeout == INT64_MAX ? UINT64_MAX : timeout < 0 ? (uint64_t)(-timeout) / 10000 : 0;
            if (budget != UINT64_MAX && ticks_now() - start >= budget) { ob_deref(ev); st = STATUS_IO_TIMEOUT; break; }
            st = ob_wait(p, &ev, 1, 0, budget == UINT64_MAX ? INT64_MAX : -(int64_t)((budget - (ticks_now() - start)) * 10000), 0);
            ob_deref(ev);
            if (p->terminated) { st = STATUS_CANCELLED; break; }
        }
        set_iosb(p, iosb, st, 0);
        break;
    }
    case FSCTL_PIPE_LISTEN: {
        npirp_t *l;
        lock();
        in = f->pipe;
        if (in == NP_ROOT || !f->pipe_server) { unlock(); st = STATUS_ILLEGAL_FUNCTION; break; }
        if (in->state == NP_CONNECTED) { unlock(); st = STATUS_PIPE_CONNECTED; break; }
        if (in->state == NP_CLOSING) { unlock(); st = STATUS_PIPE_CLOSING; break; }
        if (in->listen) { unlock(); st = STATUS_INVALID_PIPE_STATE; break; }
        in->state = NP_LISTENING;
        name_update_listen(in->nm);
        if (in->nowait[0]) { unlock(); st = STATUS_PIPE_LISTENING; break; }         /* PIPE_NOWAIT: ConnectNamedPipe polls */
        l = irp_new(IRP_LISTEN, p, fo, event, apc, iosb, 0, 0, is_sync(f));
        if (!l) { unlock(); st = STATUS_NO_MEMORY; break; }
        in->listen = l;
        if (!l->sync) {
            io_start(fo, event);
            set_iosb(p, iosb, STATUS_PENDING, 0);
            unlock();
            st = STATUS_PENDING;
            break;
        }
        unlock();
        {
            npirp_t *list = 0;
            (void)list;
            ob_wait(p, &l->done, 1, 0, INT64_MAX, (f->options & FILE_SYNCHRONOUS_IO_ALERT) != 0);
            lock();
            if (!l->completed) {
                if (f->pipe == in && in->listen == l) in->listen = 0;
                l->status = STATUS_CANCELLED;
            }
            st = l->status;
            unlock();
            irp_free(l);
            set_iosb(p, iosb, st, 0);
            if (event) ob_signal_event(event);
        }
        break;
    }
    case FSCTL_PIPE_DISCONNECT: {
        lock();
        in = f->pipe;
        if (in == NP_ROOT || !f->pipe_server) { unlock(); st = STATUS_ILLEGAL_FUNCTION; break; }
        if (in->state == NP_LISTENING) { unlock(); st = STATUS_PIPE_LISTENING; break; }
        q_clear(&in->q[0]);
        q_clear(&in->q[1]);
        in->state = NP_DISCONNECTED;
        pump_reads(in, 0);
        pump_reads(in, 1);
        if (in->end[1]) {                                          /* the client end is dead from now on */
            file_t *cf = in->end[1]->u.file.file;
            if (cf) cf->pipe = 0;
            in->end[1] = 0;
        }
        unlock();
        st = STATUS_SUCCESS;
        set_iosb(p, iosb, st, 0);
        break;
    }
    case FSCTL_PIPE_PEEK: {
        uint32_t hdr[4];
        uint64_t done = 0;
        int more = 0, i = f->pipe_server ? 0 : 1;
        lock();
        in = f->pipe;
        if (in == NP_ROOT) { unlock(); st = STATUS_INVALID_DEVICE_REQUEST; break; }
        if (out_len < 16) { unlock(); st = STATUS_BUFFER_TOO_SMALL; break; }
        if (in->state == NP_LISTENING) { unlock(); st = STATUS_PIPE_LISTENING; break; }
        if (in->state == NP_DISCONNECTED) { unlock(); st = STATUS_PIPE_DISCONNECTED; break; }
        if (in->state == NP_CLOSING && !q_has_data(&in->q[i])) { unlock(); st = STATUS_PIPE_BROKEN; break; }
        hdr[0] = in->state == NP_CONNECTED ? 3 : 4;                 /* FILE_PIPE_CONNECTED_STATE / FILE_PIPE_CLOSING_STATE */
        hdr[1] = (uint32_t)in->q[i].bytes;
        hdr[2] = in->nm->msg_type ? in->q[i].msgs : 0;
        hdr[3] = in->nm->msg_type ? (uint32_t)q_first_len(&in->q[i], 1) : 0;
        {
            const int msg = (int)in->nm->msg_type;
            st = q_read(&in->q[i], p, out_buf + 16, out_len - 16, msg, &done, &more, 1);
            unlock();
            if (st) break;
            if (copy_to_user(p, out_buf, hdr, 16)) { st = STATUS_ACCESS_VIOLATION; break; }
            st = (msg ? done < hdr[3] : done < hdr[1]) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        }
        set_iosb(p, iosb, st, 16 + done);
        break;
    }
    case FSCTL_PIPE_TRANSCEIVE: {
        int i = f->pipe_server ? 0 : 1;
        lock();
        in = f->pipe;
        if (in == NP_ROOT) { unlock(); st = STATUS_INVALID_DEVICE_REQUEST; break; }
        if (!in->nm->msg_type || !in->read_msg[i]) { unlock(); st = STATUS_INVALID_READ_MODE; break; }
        if (q_has_data(&in->q[i])) { unlock(); st = STATUS_PIPE_BUSY; break; }
        unlock();
        st = pipe_write(p, fo, f, 0, 0, 0, in_buf, in_len);
        if (st) break;
        st = pipe_read(p, fo, f, event, apc, iosb, out_buf, out_len);
        break;
    }
    case FSCTL_PIPE_GET_PIPE_ATTRIBUTE: {
        char attr[20];
        uint64_t v = 0;
        uint32_t k;
        lock();
        in = f->pipe;
        if (in == NP_ROOT) { unlock(); st = STATUS_INVALID_DEVICE_REQUEST; break; }
        memset(attr, 0, sizeof attr);
        if (!in_len || copy_from_user(p, attr, in_buf, in_len < sizeof attr - 1 ? in_len : sizeof attr - 1)) {
            unlock(); st = STATUS_INVALID_PARAMETER; break;
        }
        for (k = 0; k < sizeof attr && attr[k]; ++k) attr[k] = lc(attr[k]);
        if (!strcmp(attr, "clientprocessid")) v = in->end[1] || in->state == NP_CLOSING ? in->pid[1] : 0;
        else if (!strcmp(attr, "serverprocessid")) v = in->pid[0];
        else if (!strcmp(attr, "clientsessionid") || !strcmp(attr, "serversessionid")) v = 1;
        else { unlock(); st = STATUS_INVALID_PARAMETER; break; }
        unlock();
        if (!strcmp(attr, "clientprocessid") && !v) { st = STATUS_PIPE_LISTENING; break; }
        if (out_len < 4) { st = STATUS_BUFFER_TOO_SMALL; break; }
        if (copy_to_user(p, out_buf, &v, out_len >= 8 ? 8 : 4)) { st = STATUS_ACCESS_VIOLATION; break; }
        st = STATUS_SUCCESS;
        set_iosb(p, iosb, st, out_len >= 8 ? 8 : 4);
        break;
    }
    case FSCTL_PIPE_IMPERSONATE:
        st = STATUS_NOT_SUPPORTED;                                 /* no per-user security model to impersonate into */
        break;
    default:
        st = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }
    ob_deref(fo);
    if (event) ob_deref(event);
    *st_out = st;
    return 1;
}

/* ---------------------------------------------------------------- information classes */
/* NtQueryInformationFile for a pipe handle: 23 FilePipeInformation, 24 FilePipeLocalInformation, 5 standard. 1 = handled. */
int npfs_query_info(process_t *p, file_t *f, uint32_t cls, uint64_t buf, uint64_t len, uint64_t iosb, int32_t *st)
{
    npinst_t *in;
    uint32_t v[10];
    uint32_t n;
    if (!f->pipe) {
        if (cls != 23 && cls != 24) return 0;
        *st = STATUS_PIPE_DISCONNECTED;
        return 1;
    }
    if (cls == 9) {                                              /* FileNameInformation: "\NAME" below the NPFS root */
        uint16_t w[OB_NAME_MAX + 2];
        uint32_t nchars = 1, total, room, copy;
        int wn = 0;
        w[0] = '\\';
        lock();
        if (f->pipe != NP_ROOT) wn = utf8_to_utf16(((npinst_t *)f->pipe)->nm->display, w + 1, OB_NAME_MAX);
        unlock();
        if (wn < 0) { *st = STATUS_OBJECT_NAME_INVALID; return 1; }
        nchars += (uint32_t)wn;
        if (len < 4) { *st = STATUS_INFO_LENGTH_MISMATCH; return 1; }
        total = nchars * 2;
        room = (uint32_t)len - 4;
        copy = total < room ? total : room & ~1u;
        if (copy_to_user(p, buf, &total, 4) || (copy && copy_to_user(p, buf + 4, w, copy))) { *st = STATUS_ACCESS_VIOLATION; return 1; }
        *st = copy < total ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        set_iosb(p, iosb, *st, 4 + copy);
        return 1;
    }
    if (f->pipe == NP_ROOT) return 0;
    lock();
    in = f->pipe;
    memset(v, 0, sizeof v);
    switch (cls) {
    case 23:                                                      /* {ReadMode, CompletionMode} */
        v[0] = in->read_msg[f->pipe_server ? 0 : 1];
        v[1] = in->nowait[f->pipe_server ? 0 : 1];
        n = 8;
        break;
    case 24: {
        const int i = f->pipe_server ? 0 : 1;
        const uint32_t sa = in->nm->server_access;
        v[0] = in->nm->msg_type;                                  /* NamedPipeType */
        v[1] = access_reads(sa) && access_writes(sa) ? 2 : access_reads(sa) ? 0 : 1;   /* FILE_PIPE_FULL_DUPLEX/INBOUND/OUTBOUND */
        v[2] = in->nm->max_inst;
        v[3] = in->nm->ninst;
        v[4] = in->nm->in_quota;
        v[5] = (uint32_t)in->q[i].bytes;                          /* ReadDataAvailable */
        v[6] = in->nm->out_quota;
        v[7] = in->nm->out_quota;                                 /* WriteQuotaAvailable: writes never wait here */
        v[8] = in->state == NP_LISTENING ? 2 : in->state == NP_CONNECTED ? 3 : in->state == NP_CLOSING ? 4 : 1;
        v[9] = f->pipe_server ? 1 : 0;                            /* FILE_PIPE_SERVER_END / FILE_PIPE_CLIENT_END */
        n = 40;
        break;
    }
    case 5: {                                                     /* FileStandardInformation: queued bytes as EndOfFile */
        const int i = f->pipe_server ? 0 : 1;
        uint64_t s[3];
        s[0] = in->q[i].bytes; s[1] = in->q[i].bytes; s[2] = 1;   /* alloc, eof, links (delete/dir bytes 0) */
        unlock();
        if (len < 24) { *st = STATUS_INFO_LENGTH_MISMATCH; return 1; }
        *st = copy_to_user(p, buf, s, 24) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
        if (!*st) set_iosb(p, iosb, STATUS_SUCCESS, 24);
        return 1;
    }
    default:
        unlock();
        return 0;
    }
    unlock();
    if (len < n) { *st = STATUS_INFO_LENGTH_MISMATCH; return 1; }
    *st = copy_to_user(p, buf, v, n) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    if (!*st) set_iosb(p, iosb, STATUS_SUCCESS, n);
    return 1;
}

/* NtSetInformationFile(FilePipeInformation 23): {ReadMode, CompletionMode}. 1 = handled. */
int npfs_set_info(process_t *p, file_t *f, uint32_t cls, uint64_t buf, uint64_t len, uint64_t iosb, int32_t *st)
{
    uint32_t v[2];
    npinst_t *in;
    int i;
    if (cls != 23 || !f->pipe || f->pipe == NP_ROOT) return 0;
    if (len < 8) { *st = STATUS_INFO_LENGTH_MISMATCH; return 1; }
    if (copy_from_user(p, v, buf, 8)) { *st = STATUS_ACCESS_VIOLATION; return 1; }
    if (v[0] > 1 || v[1] > 1) { *st = STATUS_INVALID_PARAMETER; return 1; }
    lock();
    in = f->pipe;
    i = f->pipe_server ? 0 : 1;
    if (v[0] == 1 && !in->nm->msg_type) { unlock(); *st = STATUS_INVALID_PARAMETER; return 1; }   /* message reads need a message pipe */
    in->read_msg[i] = v[0];
    in->nowait[i] = v[1];
    unlock();
    set_iosb(p, iosb, STATUS_SUCCESS, 0);
    *st = STATUS_SUCCESS;
    return 1;
}

/* FileFsDeviceInformation of a pipe handle: FILE_DEVICE_NAMED_PIPE. */
int npfs_is_pipe(const file_t *f) { return f && f->pipe != 0; }

void npfs_stats(uint64_t *created, uint64_t *chunks, uint64_t *moved)
{
    *created = pipes_created;
    *chunks = chunks_live;
    *moved = bytes_moved;
}
