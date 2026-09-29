/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 named pipe file system (NPFS): \Device\NamedPipe\<name>, reached as \??\pipe\<name> (\\.\pipe\<name>).
 *
 * A pipe is a name with up to MaximumInstances instances. Every instance has a server end (NtCreateNamedPipeFile) and, once
 * a client opens the name (NtCreateFile), a client end; each end is an OB_NPIPE object. Data flows in two queues per
 * instance (client -> server, server -> client) made of page-sized blocks from the physical allocator, so pipe traffic
 * does not consume the small kernel heap. Byte-type pipes carry a stream; message-type pipes keep message boundaries
 * (a message-mode read returns one message, or STATUS_BUFFER_OVERFLOW with its first part; byte-mode reads of a message
 * pipe ignore the boundaries, as on Windows).
 *
 * I/O is IRP based (ipc_io.c): a read with no data pends until a write arrives, a listen (ConnectNamedPipe) pends until a
 * client connects, a write pends while the peer's queue holds InboundQuota/OutboundQuota bytes or more; synchronous handles
 * (FILE_SYNCHRONOUS_IO_*) wait inside the system call, overlapped ones return STATUS_PENDING and complete through the
 * event, the completion port or an APC. Completing a read copies straight into the reader's buffer in its own process.
 *
 * Instance states follow NPFS: LISTENING (new, or after ConnectNamedPipe) -> CONNECTED (a client opened it) -> CLOSING
 * (the client closed its end) or DISCONNECTED (DisconnectNamedPipe; the client end is orphaned). Reads after the peer is
 * gone drain what is buffered, then fail with STATUS_PIPE_BROKEN; writes then fail with STATUS_PIPE_CLOSING.
 */
#include "ipc.h"

#define FSCTL_PIPE_DISCONNECT 0x110004u
#define FSCTL_PIPE_LISTEN 0x110008u
#define FSCTL_PIPE_PEEK 0x11400Cu
#define FSCTL_PIPE_WAIT 0x110018u
#define FSCTL_PIPE_TRANSCEIVE 0x11C017u
#define FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE 0x110030u
#define FSCTL_PIPE_GET_PIPE_ATTRIBUTE 0x110028u
#define FSCTL_PIPE_IMPERSONATE 0x11001Cu
#define FILE_PIPE_BYTE_STREAM 0u
#define FILE_PIPE_MESSAGE 1u
#define FILE_PIPE_QUEUE_OPERATION 0u
#define FILE_PIPE_COMPLETE_OPERATION 1u
#define FILE_PIPE_INBOUND 0u
#define FILE_PIPE_OUTBOUND 1u
#define FILE_PIPE_FULL_DUPLEX 2u
#define ST_DISCONNECTED 1u                  /* FILE_PIPE_DISCONNECTED_STATE */
#define ST_LISTENING 2u                     /* FILE_PIPE_LISTENING_STATE */
#define ST_CONNECTED 3u                     /* FILE_PIPE_CONNECTED_STATE */
#define ST_CLOSING 4u                       /* FILE_PIPE_CLOSING_STATE */
#define STATUS_NOT_A_REPARSE_POINT_L ((int32_t)0xC0000275)
#define BLK_DATA (4096u - 32u)
#define PIPE_NAME_MAX 96
#define DEFAULT_QUOTA 4096u

typedef struct blk {
    struct blk *next;
    uint32_t len, off;                  /* bytes in data[], bytes already consumed */
    uint32_t msg_end, pad;              /* 1: the last block of a message */
    uint64_t pad2;
    uint8_t data[BLK_DATA];
} blk_t;

typedef struct {
    blk_t *head, *tail;
    uint64_t bytes;                     /* unread bytes */
    uint32_t messages;                  /* complete messages queued (message pipes) */
    irp_t *readers;                     /* pending reads of the end that consumes this queue */
    irp_t *writers;                     /* pending writes waiting for quota */
    uint32_t quota;
} dataq_t;

typedef struct npipe npipe_t;
typedef struct npinst npinst_t;
typedef struct npend {
    uint32_t handles;                   /* first member: handle count (ipc_core.c) */
    kobject_t *obj;                     /* back pointer, no reference */
    npinst_t *inst;                     /* 0 for a pipe-root handle or an orphaned client end */
    int server, root;
    uint32_t read_mode, completion_mode;
    uint64_t pid;                       /* the process that opened this end */
    int orphaned;                       /* client end after DisconnectNamedPipe */
} npend_t;

struct npinst {
    npinst_t *next;
    npipe_t *pipe;
    npend_t *server, *client;           /* ends (their objects hold references on nothing here) */
    uint32_t state;
    dataq_t to_server, to_client;
    irp_t *listeners;                   /* pending FSCTL_PIPE_LISTEN */
    int server_gone;                    /* the server end's last handle is closed */
};

struct npipe {
    npipe_t *next;
    uint16_t name[PIPE_NAME_MAX];       /* upper-cased for comparisons */
    uint32_t name_chars;
    uint32_t type, config, max_instances, instances;
    uint32_t in_quota, out_quota;
    int64_t default_timeout;
    npinst_t *insts;
};

static npipe_t *g_pipes;

/* ---------------------------------------------------------------- names */
static uint16_t up16(uint16_t c) { return c >= 'a' && c <= 'z' ? (uint16_t)(c - 32) : c; }

static int prefix_ci(const uint16_t *s, uint32_t n, const char *pfx)
{
    uint32_t i;
    for (i = 0; pfx[i]; ++i) if (i >= n || up16(s[i]) != up16((uint8_t)pfx[i])) return 0;
    return (int)i;
}

/* Pipe path -> the pipe's own name; returns its length, 0 for the NPFS root itself, -1 when not a pipe path. */
static int pipe_name_of(const uint16_t *s, uint32_t n, const uint16_t **name)
{
    int k = prefix_ci(s, n, "\\??\\pipe\\");
    if (!k) k = prefix_ci(s, n, "\\Device\\NamedPipe\\");
    if (!k) {
        if ((k = prefix_ci(s, n, "\\Device\\NamedPipe")) && (uint32_t)k == n) { *name = s + k; return 0; }
        if ((k = prefix_ci(s, n, "\\??\\pipe")) && (uint32_t)k == n) { *name = s + k; return 0; }
        return -1;
    }
    *name = s + k;
    return (int)(n - (uint32_t)k);
}

int npfs_is_pipe_path(const uint16_t *name, uint32_t chars)
{
    const uint16_t *nm;
    return pipe_name_of(name, chars, &nm) >= 0;
}

static npipe_t *find_pipe(const uint16_t *name, uint32_t n)
{
    npipe_t *pp;
    uint32_t i;
    for (pp = g_pipes; pp; pp = pp->next) {
        if (pp->name_chars != n) continue;
        for (i = 0; i < n && pp->name[i] == up16(name[i]); ++i) { }
        if (i == n) return pp;
    }
    return 0;
}

/* ---------------------------------------------------------------- data queues (interrupts off) */
static void q_free(dataq_t *q)
{
    blk_t *b = q->head, *n;
    for (; b; b = n) { n = b->next; pmm_free(v2p_direct((uint64_t)b)); }
    q->head = q->tail = 0;
    q->bytes = 0;
    q->messages = 0;
}

static blk_t *blk_new(void)
{
    const uint64_t pa = pmm_alloc();
    return pa ? (blk_t *)p2v(pa) : 0;
}

static void blocks_free(blk_t *b)
{
    while (b) { blk_t *n = b->next; pmm_free(v2p_direct((uint64_t)b)); b = n; }
}

/* Copies `len` bytes from `src` in process `from` into a fresh chain of blocks (interrupts on; nothing shared is touched).
 * Returns the first block (*last the last one), or 0 with *st set. */
static blk_t *blocks_build(process_t *from, uint64_t src, uint64_t len, int message, blk_t **last, int32_t *st)
{
    blk_t *first = 0, *tail = 0;
    uint64_t done = 0;
    do {
        blk_t *b = blk_new();
        uint32_t n;
        if (!b) { *st = STATUS_INSUFFICIENT_RESOURCES; blocks_free(first); return 0; }
        n = len - done > BLK_DATA ? BLK_DATA : (uint32_t)(len - done);
        if (n && copy_from_user(from, b->data, src + done, n)) {
            pmm_free(v2p_direct((uint64_t)b));
            blocks_free(first);
            *st = STATUS_ACCESS_VIOLATION;
            return 0;
        }
        b->len = n;
        if (tail) tail->next = b; else first = b;
        tail = b;
        done += n;
    } while (done < len);
    tail->msg_end = message ? 1u : 0u;
    *last = tail;
    *st = STATUS_SUCCESS;
    return first;
}

/* Links a built chain at the end of the queue (interrupts off). */
static void q_link(dataq_t *q, blk_t *first, blk_t *last, uint64_t len, int message)
{
    if (q->tail) q->tail->next = first; else q->head = first;
    q->tail = last;
    q->bytes += len;
    if (message) ++q->messages;
}

/* Bytes of the first queued message (message pipes). */
static uint64_t q_first_message(dataq_t *q)
{
    blk_t *b;
    uint64_t n = 0;
    for (b = q->head; b; b = b->next) { n += b->len - b->off; if (b->msg_end) break; }
    return n;
}

/* Moves up to `len` bytes into `to`'s memory at `dst` (message mode stops at the message end). *overflow is set when a
 * message was longer than the buffer (the rest stays queued). Returns bytes copied; -1 on a fault in the reader. */
static int64_t q_take(dataq_t *q, int message_mode, process_t *to, uint64_t dst, uint64_t len, int *overflow)
{
    uint64_t done = 0;
    *overflow = 0;
    while (q->head) {
        blk_t *b = q->head;
        uint32_t avail = b->len - b->off, n;
        if (done == len && (avail || !message_mode)) {
            if (message_mode) *overflow = 1;
            break;
        }
        n = avail < len - done ? avail : (uint32_t)(len - done);
        if (n && to && copy_to_user(to, dst + done, b->data + b->off, n)) return -1;
        b->off += n;
        done += n;
        q->bytes -= n;
        if (b->off == b->len) {
            const int end = b->msg_end;
            q->head = b->next;
            if (!q->head) q->tail = 0;
            pmm_free(v2p_direct((uint64_t)b));
            if (end) { --q->messages; if (message_mode) break; }
        } else if (message_mode && done == len) {
            *overflow = 1;
            break;
        }
    }
    return (int64_t)done;
}

/* ---------------------------------------------------------------- instance helpers */
static int type_message(npinst_t *in) { return in->pipe->type == FILE_PIPE_MESSAGE; }
static dataq_t *rq(npend_t *e) { return e->server ? &e->inst->to_server : &e->inst->to_client; }   /* queue this end reads */
static dataq_t *wq(npend_t *e) { return e->server ? &e->inst->to_client : &e->inst->to_server; }   /* queue this end writes */

static void irp_unlink(irp_t **list, irp_t *irp)
{
    irp_t **pp;
    for (pp = list; *pp; pp = &(*pp)->next) if (*pp == irp) { *pp = irp->next; return; }
}

static void cancel_in_list(irp_t *irp)
{
    irp_t **list = irp->owner;
    if (list) irp_unlink(list, irp);
    irp->owner = 0;
}

static void pend_on(irp_t **list, irp_t *irp)
{
    irp_t **pp;
    irp->next = 0;
    for (pp = list; *pp; pp = &(*pp)->next) { }
    *pp = irp;
    irp->owner = list;
    irp->cancel = cancel_in_list;
    irp_mark_pending(irp);
}

/* Status a read gets when the queue is empty and nobody can fill it any more (0: it may still be filled). */
static int32_t read_dead_status(npend_t *e)
{
    npinst_t *in = e->inst;
    if (!in) return e->orphaned ? STATUS_PIPE_DISCONNECTED : STATUS_INVALID_PIPE_STATE;
    if (e->server) {
        if (in->state == ST_LISTENING) return STATUS_PIPE_LISTENING;
        if (in->state == ST_DISCONNECTED) return STATUS_PIPE_DISCONNECTED;
        if (in->state == ST_CLOSING) return STATUS_PIPE_BROKEN;
        return 0;
    }
    return in->server_gone ? STATUS_PIPE_BROKEN : 0;
}

static int32_t write_dead_status(npend_t *e)
{
    npinst_t *in = e->inst;
    if (!in) return e->orphaned ? STATUS_PIPE_DISCONNECTED : STATUS_INVALID_PIPE_STATE;
    if (e->server) {
        if (in->state == ST_LISTENING) return STATUS_PIPE_LISTENING;
        if (in->state == ST_DISCONNECTED) return STATUS_PIPE_DISCONNECTED;
        if (in->state == ST_CLOSING) return STATUS_PIPE_CLOSING;
        return 0;
    }
    return in->server_gone ? STATUS_PIPE_CLOSING : 0;
}

/* Satisfies pending reads of queue `q` in order (interrupts off); `dead` != 0 fails the unsatisfiable ones. */
static void serve_readers(dataq_t *q, int message_pipe, int32_t dead)
{
    while (q->readers) {
        irp_t *irp = q->readers;
        const int mm = message_pipe && irp->read_mode == FILE_PIPE_MESSAGE;
        int overflow = 0;
        int64_t got;
        if (!q->head) {
            if (!dead) break;
            q->readers = irp->next;
            irp->owner = 0;
            irp_complete(irp, dead, 0);
            continue;
        }
        q->readers = irp->next;
        irp->owner = 0;
        got = q_take(q, mm, irp->proc, irp->buf, irp->len, &overflow);
        if (got < 0) { irp_complete(irp, STATUS_ACCESS_VIOLATION, 0); continue; }
        irp_complete(irp, overflow ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS, (uint64_t)got);
    }
}

/* After `reader` consumed data: accepts the peer's pending writes while its queue is under quota. The writer's data is
 * copied with interrupts on, then linked after checking that the instance still exists. */
static void serve_writers(npend_t *reader)
{
    for (;;) {
        irp_t *irp;
        npinst_t *in;
        dataq_t *q;
        blk_t *first, *last = 0;
        int32_t st;
        uint64_t f = irq_save();
        in = reader->inst;
        q = in ? rq(reader) : 0;
        irp = q ? q->writers : 0;
        if (!irp || q->bytes >= q->quota) { irq_restore(f); return; }
        q->writers = irp->next;
        irp->owner = 0;
        irq_restore(f);
        first = blocks_build(irp->proc, irp->buf, irp->len, type_message(in), &last, &st);
        f = irq_save();
        if (first && reader->inst != in) { blocks_free(first); first = 0; st = STATUS_PIPE_BROKEN; }
        if (first) {
            q_link(q, first, last, irp->len, type_message(in));
            serve_readers(q, type_message(in), 0);
        }
        irp_complete(irp, st, st ? 0 : irp->len);
        irq_restore(f);
        if (st) return;
    }
}

/* ---------------------------------------------------------------- objects */
static kobject_t *new_end(npinst_t *in, int server, uint32_t sync, uint64_t pid)
{
    kobject_t *o = ob_create(OB_NPIPE, 0);
    npend_t *e = kzalloc(sizeof *e);
    ioctx_t *io;
    if (!o || !e) { kfree(e); if (o) ob_deref(o); return 0; }
    e->obj = o;
    e->inst = in;
    e->server = server;
    e->pid = pid;
    o->u.file.file = e;
    io = ipc_ioctx(o, 1);
    if (!io) { ob_deref(o); return 0; }                 /* npfs_free/ioctx_free release e */
    io->sync = sync != 0;
    ++ipc_stat_pipes;
    return o;
}

static void inst_destroy(npinst_t *in)
{
    npipe_t *pp = in->pipe;
    npinst_t **ip;
    q_free(&in->to_server);
    q_free(&in->to_client);
    for (ip = &pp->insts; *ip; ip = &(*ip)->next) if (*ip == in) { *ip = in->next; break; }
    --pp->instances;
    kfree(in);
    if (!pp->insts) {
        npipe_t **p2;
        for (p2 = &g_pipes; *p2; p2 = &(*p2)->next) if (*p2 == pp) { *p2 = pp->next; break; }
        kfree(pp);
    }
}

/* Last handle of an end closed. */
void npfs_handle_closed(kobject_t *o)
{
    npend_t *e = o->u.file.file;
    npinst_t *in;
    uint64_t f;
    if (!e || e->root) return;
    f = irq_save();
    in = e->inst;
    if (!in) { irq_restore(f); return; }
    {                                                    /* this end's own pending requests end with the handle */
        irp_t *l;
        dataq_t *mine = rq(e), *out = wq(e);
        while ((l = mine->readers)) { mine->readers = l->next; l->owner = 0; irp_complete(l, STATUS_PIPE_BROKEN, 0); }
        while ((l = out->writers)) { out->writers = l->next; l->owner = 0; irp_complete(l, STATUS_PIPE_BROKEN, 0); }
    }
    e->inst = 0;
    if (e->server) {
        irp_t *l;
        in->server = 0;
        in->server_gone = 1;
        while ((l = in->listeners)) { in->listeners = l->next; l->owner = 0; irp_complete(l, STATUS_PIPE_BROKEN, 0); }
        while ((l = in->to_server.writers)) {            /* the client's pending writes can no longer be read */
            in->to_server.writers = l->next; l->owner = 0; irp_complete(l, STATUS_PIPE_CLOSING, 0);
        }
        if (in->client) serve_readers(&in->to_client, type_message(in), STATUS_PIPE_BROKEN);
        if (!in->client) inst_destroy(in);
    } else {
        irp_t *l;
        in->client = 0;
        if (in->state == ST_CONNECTED) in->state = ST_CLOSING;
        while ((l = in->to_client.writers)) {
            in->to_client.writers = l->next; l->owner = 0; irp_complete(l, STATUS_PIPE_CLOSING, 0);
        }
        if (in->server) serve_readers(&in->to_server, type_message(in), STATUS_PIPE_BROKEN);
        if (in->server_gone && !in->server) inst_destroy(in);
    }
    irq_restore(f);
}

void npfs_free(kobject_t *o)
{
    npend_t *e = o->u.file.file;
    if (!e) return;
    if (e->inst) {                                       /* never had a handle (creation failed after new_end) */
        const uint64_t f = irq_save();
        if (e->server) { e->inst->server = 0; e->inst->server_gone = 1; if (!e->inst->client) inst_destroy(e->inst); }
        else e->inst->client = 0;
        irq_restore(f);
    }
    kfree(e);
    o->u.file.file = 0;
    --ipc_stat_pipes;
}

/* ---------------------------------------------------------------- NtCreateNamedPipeFile */
/* (PHANDLE, ACCESS, OA, IOSB, ShareAccess, CreateDisposition, CreateOptions, NamedPipeType, ReadMode, CompletionMode,
 *  MaximumInstances, InboundQuota, OutboundQuota, PLARGE_INTEGER DefaultTimeout) */
static int32_t sys_create_pipe(process_t *p, struct regs *r, uint64_t ph, uint64_t access, uint64_t oa, uint64_t piosb)
{
    const uint32_t share = (uint32_t)stack_arg(p, r, 5), disp = (uint32_t)stack_arg(p, r, 6);
    const uint32_t options = (uint32_t)stack_arg(p, r, 7), type = (uint32_t)stack_arg(p, r, 8);
    const uint32_t read_mode = (uint32_t)stack_arg(p, r, 9), completion = (uint32_t)stack_arg(p, r, 10);
    const uint32_t max_inst = (uint32_t)stack_arg(p, r, 11);
    const uint32_t in_quota = (uint32_t)stack_arg(p, r, 12), out_quota = (uint32_t)stack_arg(p, r, 13);
    const uint64_t pto = (uint64_t)stack_arg(p, r, 14);
    struct ipc_objattr a;
    uint16_t w[PIPE_NAME_MAX + 24];
    const uint16_t *nm;
    uint32_t chars = 0, config;
    int n;
    npipe_t *pp;
    npinst_t *in;
    kobject_t *o;
    int64_t timeout = -500000000ll;                      /* NPFS default: 50 ms */
    uint64_t f;
    int32_t st;
    if (copy_from_user(p, &a, oa, sizeof a) || !a.name) return STATUS_OBJECT_NAME_INVALID;
    st = ipc_read_ustr16(p, a.name, w, PIPE_NAME_MAX + 24, &chars);
    if (st) return st;
    n = pipe_name_of(w, chars, &nm);
    if (n <= 0) return STATUS_OBJECT_NAME_INVALID;
    if (n >= PIPE_NAME_MAX) return STATUS_OBJECT_NAME_INVALID;
    if (type > 1 || read_mode > 1 || completion > 1 || (read_mode == FILE_PIPE_MESSAGE && type != FILE_PIPE_MESSAGE))
        return STATUS_INVALID_PARAMETER;
    if (!max_inst) return STATUS_INVALID_PARAMETER;
    config = (share & 3) == 3 ? FILE_PIPE_FULL_DUPLEX : (share & 1) ? FILE_PIPE_OUTBOUND : FILE_PIPE_INBOUND;
    if (!(share & 3)) return STATUS_INVALID_PARAMETER;
    if (pto && copy_from_user(p, &timeout, pto, 8)) return STATUS_ACCESS_VIOLATION;
    f = irq_save();
    pp = find_pipe(nm, (uint32_t)n);
    if (pp) {
        if (disp == 2 /* FILE_CREATE: FILE_FLAG_FIRST_PIPE_INSTANCE */) { irq_restore(f); return STATUS_ACCESS_DENIED; }
        if (pp->max_instances != 0xffffffffu && pp->instances >= pp->max_instances) { irq_restore(f); return STATUS_INSTANCE_NOT_AVAILABLE; }
        if (pp->config != config || pp->type != type) { irq_restore(f); return STATUS_ACCESS_DENIED; }
    }
    irq_restore(f);
    if (!pp && disp == 1 /* FILE_OPEN */) return STATUS_OBJECT_NAME_NOT_FOUND;
    in = kzalloc(sizeof *in);
    if (!in) return STATUS_INSUFFICIENT_RESOURCES;
    if (!pp) {
        uint32_t i;
        pp = kzalloc(sizeof *pp);
        if (!pp) { kfree(in); return STATUS_INSUFFICIENT_RESOURCES; }
        for (i = 0; i < (uint32_t)n; ++i) pp->name[i] = up16(nm[i]);
        pp->name_chars = (uint32_t)n;
        pp->type = type;
        pp->config = config;
        pp->max_instances = max_inst;
        pp->in_quota = in_quota ? in_quota : DEFAULT_QUOTA;
        pp->out_quota = out_quota ? out_quota : DEFAULT_QUOTA;
        pp->default_timeout = timeout;
        f = irq_save();
        {
            npipe_t *race = find_pipe(nm, (uint32_t)n);     /* another thread created it meanwhile: use that one */
            if (race) { kfree(pp); pp = race; } else { pp->next = g_pipes; g_pipes = pp; }
        }
        irq_restore(f);
    }
    in->pipe = pp;
    in->state = ST_LISTENING;
    in->to_server.quota = pp->in_quota;
    in->to_client.quota = pp->out_quota;
    o = new_end(in, 1, options & 0x30, (uint64_t)p->pid);
    if (!o) { kfree(in); return STATUS_INSUFFICIENT_RESOURCES; }
    ((npend_t *)o->u.file.file)->read_mode = read_mode;
    ((npend_t *)o->u.file.file)->completion_mode = completion;
    f = irq_save();
    in->server = o->u.file.file;
    in->next = pp->insts;
    pp->insts = in;
    ++pp->instances;
    irq_restore(f);
    st = ipc_give_handle(p, o, (uint32_t)access, (a.attributes & OBJ_INHERIT_ATTR) != 0, ph, 0);
    if (!st && piosb) { struct ipc_iosb v = { 0, 2 /* FILE_CREATED */ }; copy_to_user(p, piosb, &v, sizeof v); }
    return st;
}

/* ---------------------------------------------------------------- client open (NtCreateFile / NtOpenFile) */
/* NtCreateFile(PHANDLE, ACCESS, OA, IOSB, AllocationSize, FileAttributes, ShareAccess, Disposition, CreateOptions, ...)
 * NtOpenFile(PHANDLE, ACCESS, OA, IOSB, ShareAccess, OpenOptions) */
static int32_t open_client(process_t *p, struct regs *r, uint32_t num, uint64_t ph, uint64_t access, uint64_t oa, uint64_t piosb,
                           const uint16_t *nm, int n)
{
    const uint32_t options = (uint32_t)stack_arg(p, r, num == SYS_NtOpenFile ? 6 : 9);
    struct ipc_objattr a;
    npipe_t *pp;
    npinst_t *in, *pick = 0;
    kobject_t *o;
    npend_t *e;
    uint64_t f;
    int32_t st;
    if (copy_from_user(p, &a, oa, sizeof a)) return STATUS_ACCESS_VIOLATION;
    if (n == 0) {                                        /* the NPFS root: only FSCTL_PIPE_WAIT is meaningful on it */
        o = new_end(0, 0, 1, (uint64_t)p->pid);
        if (!o) return STATUS_INSUFFICIENT_RESOURCES;
        ((npend_t *)o->u.file.file)->root = 1;
        st = ipc_give_handle(p, o, (uint32_t)access, (a.attributes & OBJ_INHERIT_ATTR) != 0, ph, 0);
        if (!st && piosb) { struct ipc_iosb v = { 0, 1 }; copy_to_user(p, piosb, &v, sizeof v); }
        return st;
    }
    o = new_end(0, 0, options & 0x30, (uint64_t)p->pid);
    if (!o) return STATUS_INSUFFICIENT_RESOURCES;
    e = o->u.file.file;
    f = irq_save();
    pp = find_pipe(nm, (uint32_t)n);
    if (!pp) { irq_restore(f); ob_deref(o); return STATUS_OBJECT_NAME_NOT_FOUND; }
    /* direction: an inbound pipe only accepts writers, an outbound one only readers */
    if ((pp->config == FILE_PIPE_INBOUND && (access & (GENERIC_READ_ACCESS | FILE_READ_DATA_ACCESS))) ||
        (pp->config == FILE_PIPE_OUTBOUND && (access & (GENERIC_WRITE_ACCESS | FILE_WRITE_DATA_ACCESS)))) {
        irq_restore(f);
        ob_deref(o);
        return STATUS_ACCESS_DENIED;
    }
    for (in = pp->insts; in; in = in->next)
        if (in->state == ST_LISTENING && !in->client && in->server) { pick = in; break; }   /* oldest last: fine */
    if (!pick) { irq_restore(f); ob_deref(o); return STATUS_PIPE_NOT_AVAILABLE; }
    e->inst = pick;
    pick->client = e;
    pick->state = ST_CONNECTED;
    while (pick->listeners) {                            /* ConnectNamedPipe completes */
        irp_t *l = pick->listeners;
        pick->listeners = l->next;
        l->owner = 0;
        irp_complete(l, STATUS_SUCCESS, 0);
    }
    irq_restore(f);
    st = ipc_give_handle(p, o, (uint32_t)access, (a.attributes & OBJ_INHERIT_ATTR) != 0, ph, 0);
    if (!st && piosb) { struct ipc_iosb v = { 0, 1 /* FILE_OPENED */ }; copy_to_user(p, piosb, &v, sizeof v); }
    return st;
}

/* ---------------------------------------------------------------- read / write */
static int32_t get_end(process_t *p, uint64_t h, kobject_t **o, npend_t **e, uint32_t *access)
{
    int32_t st = ipc_ref_handle(p, h, OB_NPIPE, o, access);
    if (st) return st;
    *e = (*o)->u.file.file;
    if (!*e) { ob_deref(*o); return STATUS_INVALID_HANDLE; }
    return STATUS_SUCCESS;
}

/* NtReadFile / NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key) */
static int32_t pipe_rw(process_t *p, struct regs *r, uint32_t num, uint64_t h, uint64_t event, uint64_t apc, uint64_t apc_ctx)
{
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5), buf = (uint64_t)stack_arg(p, r, 6);
    const uint64_t len = (uint64_t)(uint32_t)stack_arg(p, r, 7);
    const int write = num == SYS_NtWriteFile;
    kobject_t *o;
    npend_t *e;
    irp_t *irp;
    uint32_t access = 0;
    uint64_t f;
    int32_t st = get_end(p, h, &o, &e, &access);
    if (st) return st;
    if (e->root) { ob_deref(o); return STATUS_INVALID_DEVICE_REQUEST; }
    if (write ? !(access & (GENERIC_WRITE_ACCESS | FILE_WRITE_DATA_ACCESS | GENERIC_ALL_ACCESS))
              : !(access & (GENERIC_READ_ACCESS | FILE_READ_DATA_ACCESS | GENERIC_ALL_ACCESS))) {
        ob_deref(o);
        return STATUS_ACCESS_DENIED;
    }
    st = irp_prepare(p, o, event, apc, apc_ctx, iosb, write ? IRP_WRITE : IRP_READ, &irp);
    if (st) { ob_deref(o); return st; }
    irp->buf = buf;
    irp->len = len;
    irp->read_mode = e->read_mode;
    if (write) {
        dataq_t *q;
        int32_t dead;
        f = irq_save();
        dead = write_dead_status(e);
        if (dead) { irq_restore(f); irp_complete(irp, dead, 0); ob_deref(o); return irp_finish(irp); }
        q = wq(e);
        if (q->bytes >= q->quota || q->writers) {        /* over quota: wait for the reader (or give up, PIPE_NOWAIT) */
            if (e->completion_mode == FILE_PIPE_COMPLETE_OPERATION) {
                irq_restore(f);
                irp_complete(irp, STATUS_SUCCESS, 0);
                ob_deref(o);
                return irp_finish(irp);
            }
            pend_on(&q->writers, irp);
            irq_restore(f);
            ob_deref(o);
            return irp_finish(irp);
        }
        irq_restore(f);
        {
            npinst_t *in = e->inst;
            blk_t *last = 0, *first = in ? blocks_build(p, buf, len, type_message(in), &last, &st) : 0;
            if (!in) st = STATUS_PIPE_DISCONNECTED;
            f = irq_save();
            if (first) {
                dead = e->inst == in ? write_dead_status(e) : STATUS_PIPE_DISCONNECTED;
                if (dead) { blocks_free(first); st = dead; }
                else { q_link(q, first, last, len, type_message(in)); serve_readers(q, type_message(in), 0); }
            }
            irq_restore(f);
        }
        irp_complete(irp, st, st ? 0 : len);
        ob_deref(o);
        return irp_finish(irp);
    }
    /* read */
    f = irq_save();
    {
        npinst_t *in = e->inst;
        dataq_t *q = in ? rq(e) : 0;
        if (q && q->head && !q->readers) {
            int overflow = 0;
            const int64_t got = q_take(q, type_message(in) && e->read_mode == FILE_PIPE_MESSAGE, p, buf, len, &overflow);
            irq_restore(f);
            if (got < 0) irp_complete(irp, STATUS_ACCESS_VIOLATION, 0);
            else irp_complete(irp, overflow ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS, (uint64_t)got);
            serve_writers(e);
        } else {
            const int32_t dead = read_dead_status(e);
            if (dead) { irq_restore(f); irp_complete(irp, dead, 0); }
            else if (e->completion_mode == FILE_PIPE_COMPLETE_OPERATION) { irq_restore(f); irp_complete(irp, STATUS_PIPE_EMPTY, 0); }
            else { pend_on(&q->readers, irp); irq_restore(f); }
        }
    }
    ob_deref(o);
    return irp_finish(irp);
}

/* ---------------------------------------------------------------- FSCTLs */
/* FSCTL_PIPE_WAIT on the root: waits until the named pipe has an instance a client can open. */
static int32_t pipe_wait(process_t *p, uint64_t in_buf, uint64_t in_len)
{
    uint8_t hdr[16];
    uint16_t name[PIPE_NAME_MAX];
    uint32_t chars;
    int64_t timeout;
    uint64_t deadline = 0;
    if (in_len < 14 || copy_from_user(p, hdr, in_buf, 14)) return STATUS_INVALID_PARAMETER;
    chars = *(uint32_t *)(hdr + 8) / 2;
    if (!chars || chars >= PIPE_NAME_MAX || in_len < 14 + chars * 2ull) return STATUS_INVALID_PARAMETER;
    if (copy_from_user(p, name, in_buf + 14, chars * 2ull)) return STATUS_ACCESS_VIOLATION;
    memcpy(&timeout, hdr, 8);
    for (;;) {
        uint64_t f = irq_save();
        npipe_t *pp = find_pipe(name, chars);
        npinst_t *in;
        int avail = 0;
        if (!pp) { irq_restore(f); return STATUS_OBJECT_NAME_NOT_FOUND; }
        if (!hdr[12]) timeout = pp->default_timeout;     /* NMPWAIT_USE_DEFAULT_WAIT */
        for (in = pp->insts; in; in = in->next) if (in->state == ST_LISTENING && !in->client && in->server) avail = 1;
        irq_restore(f);
        if (avail) return STATUS_SUCCESS;
        if (!deadline) {
            if (timeout == INT64_MIN || timeout == INT64_MAX) deadline = ~0ull;   /* NMPWAIT_WAIT_FOREVER */
            else {
                const uint64_t ms = timeout < 0 ? (uint64_t)(-timeout) / 10000 : 0;
                deadline = ticks_now() + (ms * 1000u + TICK_US - 1) / TICK_US + 1;
            }
        }
        if (ticks_now() >= deadline) return STATUS_IO_TIMEOUT;
        if (current_thread_must_die()) return STATUS_THREAD_IS_TERMINATING;
        thread_sleep_ms(2);
    }
}

typedef struct { uint32_t state, avail, messages, msg_len; } peek_hdr_t;

static int32_t pipe_fsctl(process_t *p, struct regs *r, uint64_t h, uint64_t event, uint64_t apc, uint64_t apc_ctx)
{
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5);
    const uint32_t code = (uint32_t)stack_arg(p, r, 6);
    const uint64_t in_buf = (uint64_t)stack_arg(p, r, 7), in_len = (uint64_t)(uint32_t)stack_arg(p, r, 8);
    const uint64_t out_buf = (uint64_t)stack_arg(p, r, 9), out_len = (uint64_t)(uint32_t)stack_arg(p, r, 10);
    kobject_t *o;
    npend_t *e;
    npinst_t *in;
    irp_t *irp;
    uint32_t access;
    uint64_t f;
    int32_t st = get_end(p, h, &o, &e, &access);
    if (st) return st;
    if (e->root) {
        ob_deref(o);
        if (code != FSCTL_PIPE_WAIT) return STATUS_INVALID_DEVICE_REQUEST;
        st = pipe_wait(p, in_buf, in_len);
        if (iosb) { struct ipc_iosb v = { (uint64_t)(int64_t)st, 0 }; copy_to_user(p, iosb, &v, sizeof v); }
        return st;
    }
    switch (code) {
    case FSCTL_PIPE_LISTEN:
        if (!e->server) { ob_deref(o); return STATUS_ILLEGAL_FUNCTION; }
        st = irp_prepare(p, o, event, apc, apc_ctx, iosb, IRP_LISTEN, &irp);
        if (st) { ob_deref(o); return st; }
        f = irq_save();
        in = e->inst;
        if (!in) { irq_restore(f); irp_complete(irp, STATUS_INVALID_PIPE_STATE, 0); }
        else if (in->state == ST_CONNECTED) { irq_restore(f); irp_complete(irp, STATUS_PIPE_CONNECTED, 0); }
        else if (in->state == ST_CLOSING) { irq_restore(f); irp_complete(irp, STATUS_PIPE_CLOSING, 0); }
        else {
            if (in->state == ST_DISCONNECTED) in->state = ST_LISTENING;
            if (e->completion_mode == FILE_PIPE_COMPLETE_OPERATION) { irq_restore(f); irp_complete(irp, STATUS_PIPE_LISTENING, 0); }
            else { pend_on(&in->listeners, irp); irq_restore(f); }
        }
        ob_deref(o);
        return irp_finish(irp);
    case FSCTL_PIPE_DISCONNECT: {
        npend_t *c;
        if (!e->server) { ob_deref(o); return STATUS_ILLEGAL_FUNCTION; }
        f = irq_save();
        in = e->inst;
        if (!in) { irq_restore(f); ob_deref(o); return STATUS_INVALID_PIPE_STATE; }
        if (in->state == ST_DISCONNECTED) { irq_restore(f); ob_deref(o); return STATUS_PIPE_DISCONNECTED; }
        {
            irp_t *l;
            while ((l = in->listeners)) { in->listeners = l->next; l->owner = 0; irp_complete(l, STATUS_PIPE_DISCONNECTED, 0); }
            while ((l = in->to_server.writers)) { in->to_server.writers = l->next; l->owner = 0; irp_complete(l, STATUS_PIPE_DISCONNECTED, 0); }
            while ((l = in->to_client.writers)) { in->to_client.writers = l->next; l->owner = 0; irp_complete(l, STATUS_PIPE_DISCONNECTED, 0); }
        }
        q_free(&in->to_client);
        q_free(&in->to_server);
        c = in->client;
        in->client = 0;
        in->state = ST_DISCONNECTED;
        if (c) { c->inst = 0; c->orphaned = 1; }
        serve_readers(&in->to_client, 0, STATUS_PIPE_DISCONNECTED);
        serve_readers(&in->to_server, 0, STATUS_PIPE_DISCONNECTED);
        irq_restore(f);
        ob_deref(o);
        if (iosb) { struct ipc_iosb v = { 0, 0 }; copy_to_user(p, iosb, &v, sizeof v); }
        return STATUS_SUCCESS;
    }
    case FSCTL_PIPE_PEEK: {
        peek_hdr_t hd;
        uint8_t *tmp = 0;
        uint64_t want = out_len > sizeof hd ? out_len - sizeof hd : 0, copied = 0;
        if (out_len < sizeof hd) { ob_deref(o); return STATUS_INFO_LENGTH_MISMATCH; }
        if (want > 65536) want = 65536;
        if (want && !(tmp = kmalloc(want))) { ob_deref(o); return STATUS_INSUFFICIENT_RESOURCES; }
        f = irq_save();
        in = e->inst;
        memset(&hd, 0, sizeof hd);
        if (!in) { irq_restore(f); kfree(tmp); ob_deref(o); return e->orphaned ? STATUS_PIPE_DISCONNECTED : STATUS_INVALID_PIPE_STATE; }
        {
            dataq_t *q = rq(e);
            blk_t *b;
            const uint64_t first = type_message(in) ? q_first_message(q) : q->bytes;
            hd.state = !e->server && in->server_gone ? ST_CLOSING : in->state;
            hd.avail = (uint32_t)q->bytes;
            hd.messages = type_message(in) ? q->messages : 0;
            hd.msg_len = type_message(in) ? (uint32_t)first : 0;
            for (b = q->head; b && copied < want; b = b->next) {    /* copy without consuming */
                uint32_t n = b->len - b->off;
                if (n > want - copied) n = (uint32_t)(want - copied);
                if (type_message(in) && copied + n > first) n = (uint32_t)(first - copied);
                memcpy(tmp + copied, b->data + b->off, n);
                copied += n;
                if (type_message(in) && (b->msg_end || copied >= first)) break;
            }
            if (!q->bytes && ((e->server && in->state == ST_CLOSING) || (!e->server && in->server_gone))) {
                irq_restore(f); kfree(tmp); ob_deref(o); return STATUS_PIPE_BROKEN;
            }
        }
        irq_restore(f);
        ob_deref(o);
        if (copy_to_user(p, out_buf, &hd, sizeof hd) || (copied && copy_to_user(p, out_buf + sizeof hd, tmp, copied))) {
            kfree(tmp);
            return STATUS_ACCESS_VIOLATION;
        }
        kfree(tmp);
        st = (hd.msg_len > copied && type_message(in)) ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS;
        if (iosb) { struct ipc_iosb v = { (uint64_t)(int64_t)st, sizeof hd + copied }; copy_to_user(p, iosb, &v, sizeof v); }
        return st;
    }
    case FSCTL_PIPE_TRANSCEIVE: {
        /* write the request, then read the reply into the output buffer (message read mode, empty read queue) */
        dataq_t *q;
        int32_t dead;
        if (e->read_mode != FILE_PIPE_MESSAGE || !e->inst || !type_message(e->inst)) { ob_deref(o); return STATUS_INVALID_READ_MODE; }
        st = irp_prepare(p, o, event, apc, apc_ctx, iosb, IRP_TRANSCEIVE, &irp);
        if (st) { ob_deref(o); return st; }
        irp->buf = out_buf;
        irp->len = out_len;
        irp->read_mode = FILE_PIPE_MESSAGE;
        f = irq_save();
        dead = write_dead_status(e);
        if (!dead && rq(e)->bytes) dead = STATUS_PIPE_BUSY;                   /* unread data: the reply would be ambiguous */
        irq_restore(f);
        if (dead) { irp_complete(irp, dead, 0); ob_deref(o); return irp_finish(irp); }
        {
            npinst_t *in0 = e->inst;
            blk_t *last = 0, *first = blocks_build(p, in_buf, in_len, 1, &last, &st);
            if (!first) { irp_complete(irp, st, 0); ob_deref(o); return irp_finish(irp); }
            f = irq_save();
            if (e->inst != in0 || write_dead_status(e)) {
                const int32_t d = e->inst != in0 ? STATUS_PIPE_DISCONNECTED : write_dead_status(e);
                irq_restore(f);
                blocks_free(first);
                irp_complete(irp, d, 0);
                ob_deref(o);
                return irp_finish(irp);
            }
            q = wq(e);
            q_link(q, first, last, in_len, 1);
            serve_readers(q, 1, 0);
        }
        if (!e->inst) { irq_restore(f); irp_complete(irp, STATUS_PIPE_DISCONNECTED, 0); }
        else {
            dataq_t *r2 = rq(e);
            if (r2->head) {
                int overflow = 0;
                const int64_t got = q_take(r2, 1, p, out_buf, out_len, &overflow);
                irq_restore(f);
                irp_complete(irp, got < 0 ? STATUS_ACCESS_VIOLATION : overflow ? STATUS_BUFFER_OVERFLOW : STATUS_SUCCESS,
                             got < 0 ? 0 : (uint64_t)got);
            } else {
                const int32_t d2 = read_dead_status(e);
                if (d2) { irq_restore(f); irp_complete(irp, d2, 0); }
                else { pend_on(&r2->readers, irp); irq_restore(f); }
            }
        }
        ob_deref(o);
        return irp_finish(irp);
    }
    case FSCTL_PIPE_GET_CONNECTION_ATTRIBUTE: case FSCTL_PIPE_GET_PIPE_ATTRIBUTE: {
        char attr[32];
        uint64_t v = 0;
        uint32_t k;
        if (in_len == 0 || in_len >= sizeof attr || copy_from_user(p, attr, in_buf, in_len)) { ob_deref(o); return STATUS_INVALID_PARAMETER; }
        attr[in_len] = 0;
        (void)k;
        f = irq_save();
        in = e->inst;
        if (!strcmp(attr, "ClientProcessId")) {
            if (!in || !in->client) st = STATUS_PIPE_DISCONNECTED; else v = in->client->pid;
        } else if (!strcmp(attr, "ServerProcessId")) {
            if (!in || !in->server) st = STATUS_PIPE_DISCONNECTED; else v = in->server->pid;
        } else if (!strcmp(attr, "ClientSessionId") || !strcmp(attr, "ServerSessionId")) {
            v = 0;
        } else {
            st = STATUS_NOT_FOUND;
        }
        irq_restore(f);
        ob_deref(o);
        if (st) return st;
        if (out_len < 4) return STATUS_BUFFER_TOO_SMALL;
        if (copy_to_user(p, out_buf, &v, out_len >= 8 ? 8 : 4)) return STATUS_ACCESS_VIOLATION;
        if (iosb) { struct ipc_iosb io = { 0, out_len >= 8 ? 8 : 4 }; copy_to_user(p, iosb, &io, sizeof io); }
        return STATUS_SUCCESS;
    }
    case FSCTL_PIPE_IMPERSONATE:
        ob_deref(o);
        return STATUS_NOT_SUPPORTED;                     /* no security tokens in this system */
    default:
        ob_deref(o);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
}

/* ---------------------------------------------------------------- information */
static int32_t pipe_query_info(process_t *p, npend_t *e, uint32_t cls, uint64_t buf, uint64_t len, uint64_t iosb)
{
    uint32_t out[10];
    uint32_t n;
    uint64_t f = irq_save();
    npinst_t *in = e->inst;
    memset(out, 0, sizeof out);
    switch (cls) {
    case 23:                                             /* FilePipeInformation {ReadMode, CompletionMode} */
        out[0] = e->read_mode; out[1] = e->completion_mode; n = 8;
        break;
    case 24: {                                           /* FilePipeLocalInformation */
        npipe_t *pp = in ? in->pipe : 0;
        if (!pp) { irq_restore(f); return e->orphaned ? STATUS_PIPE_DISCONNECTED : STATUS_INVALID_PIPE_STATE; }
        out[0] = pp->type; out[1] = pp->config; out[2] = pp->max_instances; out[3] = pp->instances;
        out[4] = pp->in_quota; out[5] = (uint32_t)rq(e)->bytes; out[6] = pp->out_quota;
        out[7] = wq(e)->bytes >= wq(e)->quota ? 0 : wq(e)->quota - (uint32_t)wq(e)->bytes;
        out[8] = in->state; out[9] = e->server ? 1u : 0u;
        n = 40;
        break;
    }
    case 5: {                                            /* FileStandardInformation: a pipe is a zero-size non-directory */
        irq_restore(f);
        {
            uint8_t s[24];
            memset(s, 0, sizeof s);
            *(uint32_t *)(s + 16) = 1;
            if (len < sizeof s) return STATUS_INFO_LENGTH_MISMATCH;
            if (copy_to_user(p, buf, s, sizeof s)) return STATUS_ACCESS_VIOLATION;
            if (iosb) { struct ipc_iosb v = { 0, sizeof s }; copy_to_user(p, iosb, &v, sizeof v); }
            return STATUS_SUCCESS;
        }
    }
    default:
        irq_restore(f);
        return STATUS_INVALID_PARAMETER;
    }
    irq_restore(f);
    if (len < n) return STATUS_INFO_LENGTH_MISMATCH;
    if (copy_to_user(p, buf, out, n)) return STATUS_ACCESS_VIOLATION;
    if (iosb) { struct ipc_iosb v = { 0, n }; copy_to_user(p, iosb, &v, sizeof v); }
    return STATUS_SUCCESS;
}

static int32_t pipe_set_info(process_t *p, npend_t *e, uint32_t cls, uint64_t buf, uint64_t len, uint64_t iosb)
{
    uint32_t v[2];
    if (cls != 23) return STATUS_INVALID_PARAMETER;
    if (len < 8) return STATUS_INFO_LENGTH_MISMATCH;
    if (copy_from_user(p, v, buf, 8)) return STATUS_ACCESS_VIOLATION;
    if (v[0] > 1 || v[1] > 1) return STATUS_INVALID_PARAMETER;
    if (v[0] == FILE_PIPE_MESSAGE && (!e->inst || !type_message(e->inst))) return STATUS_INVALID_PARAMETER;
    e->read_mode = v[0];
    e->completion_mode = v[1];
    if (iosb) { struct ipc_iosb io = { 0, 0 }; copy_to_user(p, iosb, &io, sizeof io); }
    return STATUS_SUCCESS;
}

/* FlushFileBuffers on a pipe: waits until the peer has read everything this end wrote. */
static int32_t pipe_flush(npend_t *e)
{
    for (;;) {
        const uint64_t f = irq_save();
        npinst_t *in = e->inst;
        const int done = !in || !wq(e)->bytes || (e->server ? !in->client : in->server_gone);
        irq_restore(f);
        if (done) return in || !e->orphaned ? STATUS_SUCCESS : STATUS_PIPE_DISCONNECTED;
        if (current_thread_must_die()) return STATUS_THREAD_IS_TERMINATING;
        thread_sleep_ms(2);
    }
}

/* ---------------------------------------------------------------- routing */
int32_t npfs_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                     int *handled)
{
    *handled = 1;
    switch (num) {
    case SYS_NtCreateNamedPipeFile: return sys_create_pipe(p, r, a1, a2, a3, a4);
    case SYS_NtCreateFile: case SYS_NtOpenFile: {
        struct ipc_objattr a;
        uint16_t w[PIPE_NAME_MAX + 24];
        uint32_t chars = 0;
        const uint16_t *nm;
        int n;
        if (!a3 || copy_from_user(p, &a, a3, sizeof a) || !a.name) break;
        if (ipc_read_ustr16(p, a.name, w, PIPE_NAME_MAX + 24, &chars)) break;
        n = pipe_name_of(w, chars, &nm);
        if (n < 0) break;
        return open_client(p, r, num, a1, a2, a3, a4, nm, n);
    }
    case SYS_NtReadFile: case SYS_NtWriteFile:
        if (!handle_lookup(p, a1 & ~3ull, OB_NPIPE)) break;
        return pipe_rw(p, r, num, a1, a2, a3, a4);
    case SYS_NtFsControlFile: {
        kobject_t *o = handle_lookup(p, a1 & ~3ull, 0);
        if (!o) return STATUS_INVALID_HANDLE;
        if (o->type != OB_NPIPE) break;                  /* files: ipc_io.c */
        return pipe_fsctl(p, r, a1, a2, a3, a4);
    }
    case SYS_NtQueryInformationFile: case SYS_NtSetInformationFile: {
        const uint32_t cls = (uint32_t)stack_arg(p, r, 5);
        kobject_t *o;
        npend_t *e;
        uint32_t access;
        int32_t st;
        if (!handle_lookup(p, a1 & ~3ull, OB_NPIPE)) break;
        if (cls == 30 || cls == 41 || cls == 61) break;  /* completion-port binding: ipc_io.c */
        st = get_end(p, a1, &o, &e, &access);
        if (st) return st;
        st = num == SYS_NtQueryInformationFile ? pipe_query_info(p, e, cls, a3, a4, a2) : pipe_set_info(p, e, cls, a3, a4, a2);
        ob_deref(o);
        return st;
    }
    case SYS_NtFlushBuffersFile: {
        kobject_t *o;
        npend_t *e;
        uint32_t access;
        int32_t st;
        if (!handle_lookup(p, a1 & ~3ull, OB_NPIPE)) break;
        st = get_end(p, a1, &o, &e, &access);
        if (st) return st;
        st = pipe_flush(e);
        ob_deref(o);
        if (!st && a2) { struct ipc_iosb v = { 0, 0 }; copy_to_user(p, a2, &v, sizeof v); }
        return st;
    }
    default: break;
    }
    *handled = 0;
    return 0;
}
