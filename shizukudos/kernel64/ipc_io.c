/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 asynchronous I/O: I/O request packets, their completion, cancellation, I/O completion ports and the overlapped
 * wrapper for RAM-disk file objects.
 *
 * An IRP is issued by one thread on one file object. It completes either during the system call (the request could be
 * satisfied at once) or later, from whichever thread makes it satisfiable (for a pipe: the writer that brings the data).
 * Completion follows the Windows I/O manager:
 *   - the IO_STATUS_BLOCK (the OVERLAPPED's Internal/InternalHigh) receives the final status and byte count,
 *   - the caller's event and the file object itself are signaled (unless FILE_SKIP_SET_EVENT_ON_HANDLE),
 *   - an APC routine (ReadFileEx) is queued to the issuing thread, or a completion packet is posted to the port the file
 *     is associated with (unless the request succeeded at once on a FILE_SKIP_COMPLETION_PORT_ON_SUCCESS file),
 *   - a request that fails at once (NT_ERROR without pending) only fills the IO_STATUS_BLOCK: no event, packet or APC.
 * A synchronous file object makes the issuer wait inside the system call; an asynchronous one returns STATUS_PENDING.
 * RAM-disk files never pend (the file system completes every request at once), but their completion side effects are the
 * same, so overlapped reads with events, completion ports and completion routines behave as on Windows.
 */
#include "ipc.h"

#define NT_ERROR(s) ((uint32_t)(s) >= 0xC0000000u)
#define PORT_USER_PACKET_LIMIT 16384u

static irp_t *all_irps;                 /* every pending IRP */

/* ---------------------------------------------------------------- I/O contexts */
ioctx_t *ipc_ioctx(kobject_t *fobj, int create)
{
    if (!fobj->u.file.io && create) fobj->u.file.io = kzalloc(sizeof(ioctx_t));
    return fobj->u.file.io;
}

void ioctx_free(kobject_t *o)
{
    ioctx_t *c = o->u.file.io;
    if (!c) return;
    o->u.file.io = 0;
    if (c->port) ob_deref(c->port);
    kfree(c);
}

/* ---------------------------------------------------------------- IRPs */
int32_t irp_prepare(process_t *p, kobject_t *fobj, uint64_t event_h, uint64_t apc_routine, uint64_t apc_context,
                    uint64_t iosb, uint32_t major, irp_t **out)
{
    ioctx_t *io = fobj->u.file.io;
    kobject_t *ev = 0;
    irp_t *irp;
    int32_t st;
    if (event_h) {
        st = ipc_ref_handle(p, event_h, OB_EVENT, &ev, 0);
        if (st) return st;
    }
    if (io && io->port && apc_routine) {                /* a file bound to a port cannot also take completion routines */
        if (ev) ob_deref(ev);
        return STATUS_INVALID_PARAMETER;
    }
    irp = kzalloc(sizeof *irp);
    if (!irp) { if (ev) ob_deref(ev); return STATUS_INSUFFICIENT_RESOURCES; }
    irp->proc = p;
    ob_ref(p->object);
    irp->thread = thread_current();
    irp->fobj = fobj;
    ob_ref(fobj);
    irp->major = major;
    irp->iosb = iosb;
    irp->event = ev;
    irp->apc_routine = apc_routine;
    irp->apc_context = apc_context;
    irp->sync = io ? io->sync : 1;
    if (io && io->port && apc_context) {                /* ApcContext is the OVERLAPPED; 0 (hEvent low bit set) = no packet */
        irp->port = io->port;
        ob_ref(irp->port);
        irp->key = io->key;
    }
    if (io && (io->notify & 2)) irp->flags |= IRPF_NO_EVENT_ON_HANDLE;
    if (ev) ob_reset_event(ev);
    if (!(irp->flags & IRPF_NO_EVENT_ON_HANDLE)) fobj->signaled = 0;
    ++ipc_stat_irps;
    *out = irp;
    return STATUS_SUCCESS;
}

void irp_free(irp_t *irp)
{
    if (irp->event) ob_deref(irp->event);
    if (irp->port) ob_deref(irp->port);
    ob_deref(irp->fobj);
    ob_deref(irp->proc->object);
    --ipc_stat_irps;
    kfree(irp);
}

void irp_mark_pending(irp_t *irp)
{
    const uint64_t f = irq_save();
    irp->pended = 1;
    irp->all_next = all_irps;
    all_irps = irp;
    irq_restore(f);
}

static void unlink_all(irp_t *irp)
{
    irp_t **pp;
    for (pp = &all_irps; *pp; pp = &(*pp)->all_next)
        if (*pp == irp) { *pp = irp->all_next; return; }
}

void irp_complete(irp_t *irp, int32_t status, uint64_t info)
{
    const uint64_t f = irq_save();
    const int immediate = !irp->pended;
    const int live = !irp->proc->teardown;
    if (irp->completed) { irq_restore(f); return; }
    irp->completed = 1;
    irp->status = status;
    irp->info = info;
    if (irp->pended) unlink_all(irp);
    if (irp->iosb && live) {
        struct ipc_iosb v = { (uint64_t)(int64_t)status, info };
        copy_to_user(irp->proc, irp->iosb, &v, sizeof v);
    }
    if (!immediate || !NT_ERROR(status)) {
        if (irp->event) ob_signal_event(irp->event);
        if (!(irp->flags & IRPF_NO_EVENT_ON_HANDLE)) {
            irp->fobj->signaled = 1;
            ob_release_check(irp->fobj);
        }
        if (irp->apc_routine && irp->thread && live)
            apc_queue(irp->thread, irp->apc_routine, irp->apc_context, irp->iosb, 0);
        if (irp->port && live) {
            ioctx_t *io = irp->fobj->u.file.io;
            const int skip = immediate && status == STATUS_SUCCESS && io && (io->notify & 1);
            if (!skip) iocp_post(irp->port, irp->key, irp->apc_context, status, info);
        }
    }
    if (irp->sync) {
        thread_t *w = irp->thread;
        if (w && w->state == TS_BLOCKED && irp->pended) thread_wake(w);
    } else if (irp->pended) {
        irp_free(irp);                                  /* nobody waits for an asynchronous pending IRP */
    }
    irq_restore(f);
}

int32_t irp_finish(irp_t *irp)
{
    uint64_t f = irq_save();
    int32_t st;
    if (!irp->completed && !irp->sync) {
        irq_restore(f);
        return STATUS_PENDING;                          /* now owned by its queue; freed by irp_complete */
    }
    if (!irp->completed) {                              /* synchronous file object: wait for the completion */
        thread_t *t = thread_current();
        ipc_thread_t *it = ipc_thread(t, 1);
        while (!irp->completed) {
            if (thread_must_die(t) || !it) {
                if (irp->cancel) irp->cancel(irp);
                irp_complete(irp, STATUS_CANCELLED, irp->done);
                break;
            }
            it->waiting = 1;
            thread_block_current();
            it->waiting = 0;
        }
    }
    st = irp->status;
    irq_restore(f);
    irp_free(irp);
    return st;
}

/* Cancels pending IRPs of process `p` (and thread `t`, file object `fobj`, IO_STATUS_BLOCK `iosb` when nonzero). */
void irp_cancel_matching(process_t *p, thread_t *t, kobject_t *fobj, uint64_t iosb, int *found)
{
    uint64_t f = irq_save();
    irp_t *irp;
    if (found) *found = 0;
restart:
    for (irp = all_irps; irp; irp = irp->all_next) {
        if (irp->proc != p || irp->completed) continue;
        if (t && irp->thread != t) continue;
        if (fobj && irp->fobj != fobj) continue;
        if (iosb && irp->iosb != iosb) continue;
        if (found) *found = 1;
        if (irp->cancel) irp->cancel(irp);
        irp_complete(irp, STATUS_CANCELLED, irp->major == IRP_WRITE ? irp->done : 0);
        goto restart;                                   /* the list changed */
    }
    irq_restore(f);
}

/* The process is gone: drop its pending IRPs without touching its (dying) memory or its ports. */
void ipc_io_teardown(process_t *p)
{
    uint64_t f = irq_save();
    irp_t *irp;
restart:
    for (irp = all_irps; irp; irp = irp->all_next) {
        if (irp->proc != p) continue;
        if (irp->cancel) irp->cancel(irp);
        unlink_all(irp);
        irp->completed = 1;
        irp->pended = 0;
        if (irp->port) { ob_deref(irp->port); irp->port = 0; }
        irp_free(irp);
        goto restart;
    }
    irq_restore(f);
}

/* Windows cancels a thread's I/O when it exits, except on files bound to a completion port (thread-agnostic I/O). */
void ipc_io_thread_exit(thread_t *t)
{
    uint64_t f = irq_save();
    irp_t *irp;
restart:
    for (irp = all_irps; irp; irp = irp->all_next) {
        ioctx_t *io;
        if (irp->thread != t || irp->completed) continue;
        io = irp->fobj->u.file.io;
        irp->thread = 0;                                /* no APC can reach an exited thread */
        if (io && io->port) continue;
        if (irp->cancel) irp->cancel(irp);
        irp_complete(irp, STATUS_CANCELLED, irp->major == IRP_WRITE ? irp->done : 0);
        goto restart;
    }
    irq_restore(f);
}

/* ---------------------------------------------------------------- I/O completion ports */
typedef struct packet {
    struct packet *next;
    uint64_t key, ctx;
    int32_t status;
    uint64_t info;
} packet_t;

typedef struct port_waiter {
    struct port_waiter *next;
    thread_t *t;
    packet_t *got;
} port_waiter_t;

typedef struct {
    uint32_t handles;                   /* first member: handle count (ipc_core.c) */
    uint32_t concurrency;               /* reported; not used to throttle (see the report of this subsystem) */
    packet_t *head, *tail;
    uint32_t count;
    port_waiter_t *waiters;             /* LIFO: the most recent waiter gets the next packet, as on Windows */
    int closed;                         /* last handle closed: waiters return STATUS_ABANDONED_WAIT_0 */
} iocp_t;

int32_t iocp_post(kobject_t *port, uint64_t key, uint64_t apc_context, int32_t status, uint64_t info)
{
    iocp_t *q = port->u.file.file;
    packet_t *pk = kzalloc(sizeof *pk);
    uint64_t f;
    if (!pk) return STATUS_INSUFFICIENT_RESOURCES;
    pk->key = key; pk->ctx = apc_context; pk->status = status; pk->info = info;
    f = irq_save();
    ++ipc_stat_packets;
    if (q->waiters) {
        port_waiter_t *w = q->waiters;
        q->waiters = w->next;
        w->got = pk;
        if (w->t->state == TS_BLOCKED) thread_wake(w->t);
    } else {
        if (q->tail) q->tail->next = pk; else q->head = pk;
        q->tail = pk;
        ++q->count;
    }
    irq_restore(f);
    return STATUS_SUCCESS;
}

static packet_t *port_take(iocp_t *q)
{
    packet_t *pk = q->head;
    if (!pk) return 0;
    q->head = pk->next;
    if (!q->head) q->tail = 0;
    --q->count;
    pk->next = 0;
    return pk;
}

void iocp_handle_closed(kobject_t *o)
{
    iocp_t *q = o->u.file.file;
    const uint64_t f = irq_save();
    port_waiter_t *w;
    q->closed = 1;
    for (w = q->waiters; w; w = w->next)
        if (w->t->state == TS_BLOCKED) thread_wake(w->t);
    irq_restore(f);
}

void iocp_free(kobject_t *o)
{
    iocp_t *q = o->u.file.file;
    packet_t *pk;
    if (!q) return;
    while ((pk = port_take(q))) { --ipc_stat_packets; kfree(pk); }
    kfree(q);
    o->u.file.file = 0;
}

static void waiter_remove(iocp_t *q, port_waiter_t *w)
{
    port_waiter_t **pp;
    for (pp = &q->waiters; *pp; pp = &(*pp)->next)
        if (*pp == w) { *pp = w->next; return; }
}

/* Removes up to `max` packets; blocks for the first. Returns STATUS_SUCCESS, STATUS_TIMEOUT, STATUS_ABANDONED_WAIT_0,
 * STATUS_USER_APC (alertable and an APC is pending: nothing removed) or STATUS_THREAD_IS_TERMINATING. */
static int32_t port_remove(process_t *p, kobject_t *port, packet_t **out, unsigned max, unsigned *n, int64_t timeout,
                           int alertable)
{
    iocp_t *q = port->u.file.file;
    thread_t *t = thread_current();
    ipc_thread_t *it = ipc_thread(t, 1);
    port_waiter_t w;
    uint64_t f, deadline = 0;
    int32_t st = STATUS_SUCCESS;
    (void)p;
    *n = 0;
    if (!it) return STATUS_NO_MEMORY;
    if (timeout != INT64_MAX && timeout != 0) {
        const uint64_t ms = timeout < 0 ? (uint64_t)(-timeout) / 10000 : 0;
        deadline = ticks_now() + (ms * 1000u + TICK_US - 1) / TICK_US + 1;
    }
    f = irq_save();
    for (;;) {
        packet_t *pk;
        if (alertable && apc_pending(t)) { st = STATUS_USER_APC; break; }
        pk = port_take(q);
        if (pk) {
            out[(*n)++] = pk;
            while (*n < max && (pk = port_take(q))) out[(*n)++] = pk;
            break;
        }
        if (q->closed) { st = STATUS_ABANDONED_WAIT_0; break; }
        if (timeout == 0 || (deadline && ticks_now() >= deadline)) { st = STATUS_TIMEOUT; break; }
        if (thread_must_die(t)) { st = STATUS_THREAD_IS_TERMINATING; break; }
        w.t = t;
        w.got = 0;
        w.next = q->waiters;
        q->waiters = &w;
        it->waiting = 1;
        it->alertable = alertable;
        t->wake_tick = deadline;
        thread_block_current();
        t->wake_tick = 0;
        it->waiting = 0;
        it->alertable = 0;
        if (w.got) {
            out[(*n)++] = w.got;
            while (*n < max && (pk = port_take(q))) out[(*n)++] = pk;
            break;
        }
        waiter_remove(q, &w);
    }
    irq_restore(f);
    return st;
}

/* NtCreateIoCompletion(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG NumberOfConcurrentThreads) */
static int32_t sys_create_port(process_t *p, uint64_t ph, uint64_t access, uint64_t oa, uint64_t count)
{
    char name[48];
    uint32_t attrs = 0;
    kobject_t *o;
    iocp_t *q;
    int32_t st = ipc_name_from_oa(p, oa, name, sizeof name, &attrs);
    if (st) return st;
    if (name[0]) return STATUS_NOT_SUPPORTED;           /* named completion ports are not implemented */
    o = ob_create(OB_IOCP, 0);
    q = kzalloc(sizeof *q);
    if (!o || !q) { kfree(q); if (o) ob_deref(o); return STATUS_INSUFFICIENT_RESOURCES; }
    q->concurrency = (uint32_t)count;
    o->u.file.file = q;
    return ipc_give_handle(p, o, (uint32_t)access, (attrs & OBJ_INHERIT_ATTR) != 0, ph, 0);
}

/* NtSetIoCompletion(Port, KeyContext, ApcContext, IoStatus, IoStatusInformation): PostQueuedCompletionStatus */
static int32_t sys_set_port(process_t *p, uint64_t h, uint64_t key, uint64_t ctx, uint64_t status, uint64_t info)
{
    kobject_t *o;
    iocp_t *q;
    int32_t st = ipc_ref_handle(p, h, OB_IOCP, &o, 0);
    if (st) return st;
    q = o->u.file.file;
    st = q->count >= PORT_USER_PACKET_LIMIT ? STATUS_INSUFFICIENT_RESOURCES : iocp_post(o, key, ctx, (int32_t)status, info);
    ob_deref(o);
    return st;
}

/* NtRemoveIoCompletion(Port, PVOID *Key, PVOID *ApcContext, PIO_STATUS_BLOCK, PLARGE_INTEGER Timeout) */
static int32_t sys_remove_port(process_t *p, struct regs *r, uint64_t h, uint64_t pkey, uint64_t pctx, uint64_t piosb)
{
    const uint64_t pto = (uint64_t)stack_arg(p, r, 5);
    kobject_t *o;
    packet_t *pk = 0;
    unsigned n = 0;
    int64_t to = INT64_MAX;
    int32_t st;
    if (pto && copy_from_user(p, &to, pto, 8)) return STATUS_ACCESS_VIOLATION;
    if (to > 0) to = -to;
    st = ipc_ref_handle(p, h, OB_IOCP, &o, 0);
    if (st) return st;
    st = port_remove(p, o, &pk, 1, &n, to, 0);
    ob_deref(o);
    if (n) {
        struct ipc_iosb v = { (uint64_t)(int64_t)pk->status, pk->info };
        int bad = copy_to_user(p, pkey, &pk->key, 8) || copy_to_user(p, pctx, &pk->ctx, 8) || copy_to_user(p, piosb, &v, sizeof v);
        --ipc_stat_packets;
        kfree(pk);
        return bad ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
    }
    return st;
}

/* NtRemoveIoCompletionEx(Port, FILE_IO_COMPLETION_INFORMATION *, ULONG Count, PULONG Removed, PLARGE_INTEGER, BOOLEAN) */
static int32_t sys_remove_port_ex(process_t *p, struct regs *r, uint64_t h, uint64_t info, uint64_t count, uint64_t premoved)
{
    const uint64_t pto = (uint64_t)stack_arg(p, r, 5);
    const int alertable = (stack_arg(p, r, 6) & 0xff) != 0;
    packet_t *pks[64];
    kobject_t *o;
    unsigned n = 0, i;
    int64_t to = INT64_MAX;
    int32_t st;
    int bad = 0;
    uint32_t removed;
    if (!count) return STATUS_INVALID_PARAMETER;
    if (count > 64) count = 64;
    if (pto && copy_from_user(p, &to, pto, 8)) return STATUS_ACCESS_VIOLATION;
    if (to > 0) to = -to;
    st = ipc_ref_handle(p, h, OB_IOCP, &o, 0);
    if (st) return st;
    st = port_remove(p, o, pks, (unsigned)count, &n, to, alertable);
    ob_deref(o);
    for (i = 0; i < n; ++i) {
        uint64_t e[4] = { pks[i]->key, pks[i]->ctx, (uint64_t)(int64_t)pks[i]->status, pks[i]->info };
        bad |= copy_to_user(p, info + i * 32ull, e, sizeof e);
        --ipc_stat_packets;
        kfree(pks[i]);
    }
    removed = n;
    if (premoved) bad |= copy_to_user(p, premoved, &removed, 4);
    if (bad) return STATUS_ACCESS_VIOLATION;
    if (st == STATUS_USER_APC) return apc_deliver(p, r, STATUS_USER_APC);
    return st;
}

/* NtQueryIoCompletion(Port, IoCompletionBasicInformation = 0, { LONG Depth }, Length, ReturnLength) */
static int32_t sys_query_port(process_t *p, uint64_t h, uint64_t cls, uint64_t buf, uint64_t len, uint64_t pret)
{
    kobject_t *o;
    int32_t depth, st;
    if (cls != 0) return STATUS_INVALID_INFO_CLASS;
    if (len < 4) return STATUS_INFO_LENGTH_MISMATCH;
    st = ipc_ref_handle(p, h, OB_IOCP, &o, 0);
    if (st) return st;
    depth = (int32_t)((iocp_t *)o->u.file.file)->count;
    ob_deref(o);
    if (copy_to_user(p, buf, &depth, 4)) return STATUS_ACCESS_VIOLATION;
    if (pret) { const uint32_t n = 4; if (copy_to_user(p, pret, &n, 4)) return STATUS_ACCESS_VIOLATION; }
    return STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- file information: completion port binding */
/* NtSetInformationFile classes FileCompletionInformation (30), FileIoCompletionNotificationInformation (41) and
 * FileReplaceCompletionInformation (61), for RAM-disk files and pipe ends. */
int32_t ipc_set_completion_info(process_t *p, kobject_t *fobj, uint32_t cls, uint64_t buf, uint64_t len)
{
    ioctx_t *io;
    uint64_t v[2];
    kobject_t *port = 0;
    int32_t st;
    if (cls == 41) {
        uint32_t flags;
        if (len < 4) return STATUS_INFO_LENGTH_MISMATCH;
        if (copy_from_user(p, &flags, buf, 4)) return STATUS_ACCESS_VIOLATION;
        if (flags & ~7u) return STATUS_INVALID_PARAMETER;
        io = ipc_ioctx(fobj, 1);
        if (!io) return STATUS_INSUFFICIENT_RESOURCES;
        io->notify |= flags;                            /* modes can be set, never cleared */
        return STATUS_SUCCESS;
    }
    if (len < 16) return STATUS_INFO_LENGTH_MISMATCH;
    if (copy_from_user(p, v, buf, 16)) return STATUS_ACCESS_VIOLATION;
    if (v[0] || cls == 30) {
        st = ipc_ref_handle(p, v[0], OB_IOCP, &port, 0);
        if (st) return st;
    }
    io = ipc_ioctx(fobj, 1);
    if (!io) { if (port) ob_deref(port); return STATUS_INSUFFICIENT_RESOURCES; }
    if (io->sync) { if (port) ob_deref(port); return STATUS_INVALID_PARAMETER; }   /* synchronous handles cannot be bound */
    if (cls == 30 && io->port) { ob_deref(port); return STATUS_INVALID_PARAMETER; }  /* already bound */
    {
        kobject_t *old = io->port;
        const uint64_t f = irq_save();
        io->port = port;
        io->key = v[1];
        irq_restore(f);
        if (old) ob_deref(old);
    }
    return STATUS_SUCCESS;
}

int32_t ipc_query_completion_info(process_t *p, kobject_t *fobj, uint64_t buf, uint64_t len)
{
    ioctx_t *io = fobj->u.file.io;
    const uint32_t flags = io ? io->notify : 0;
    if (len < 4) return STATUS_INFO_LENGTH_MISMATCH;
    return copy_to_user(p, buf, &flags, 4) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}

/* ---------------------------------------------------------------- RAM-disk files: overlapped completion */
/* NtReadFile / NtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key) */
static int32_t file_rw(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5);
    kobject_t *fobj;
    irp_t *irp;
    int handled = 0;
    int32_t st;
    struct ipc_iosb v = { 0, 0 };
    st = ipc_ref_handle(p, a1, OB_FILE, &fobj, 0);
    if (st) return st;
    st = irp_prepare(p, fobj, a2, a3, a4, iosb, num == SYS_NtReadFile ? IRP_READ : IRP_WRITE, &irp);
    ob_deref(fobj);
    if (st) return st;
    st = sysfile_dispatch(p, r, num, a1, a2, a3, a4, &handled);   /* the RAM disk completes every request at once */
    if (iosb) copy_from_user(p, &v, iosb, sizeof v);
    irp->done = v.information;
    irp_complete(irp, st, NT_ERROR(st) ? 0 : v.information);
    return irp_finish(irp);
}

/* ---------------------------------------------------------------- volume / device information, FSCTLs and IOCTLs */
#define FILE_DEVICE_DISK_T 0x07u
#define FILE_DEVICE_NAMED_PIPE_T 0x11u
#define FILE_DEVICE_NETWORK_T 0x12u
#define FILE_DEVICE_CONSOLE_T 0x50u
#define STATUS_NOT_A_REPARSE_POINT_T ((int32_t)0xC0000275)

/* NtQueryVolumeInformationFile(Handle, IOSB, Buffer, Length, Class): FileFsDeviceInformation (4) tells files, consoles,
 * pipes and sockets apart (GetFileType). */
static int32_t sys_query_volume(process_t *p, struct regs *r, uint64_t h, uint64_t piosb, uint64_t buf, uint64_t len)
{
    const uint32_t cls = (uint32_t)stack_arg(p, r, 5);
    kobject_t *o;
    uint32_t v[2] = { 0, 0 };
    int32_t st;
    if (cls != 4) return STATUS_INVALID_INFO_CLASS;
    if (len < 8) return STATUS_INFO_LENGTH_MISMATCH;
    st = ipc_ref_handle(p, h, 0, &o, 0);
    if (st) return st;
    switch (o->type) {
    case OB_FILE: {
        const file_t *f = o->u.file.file;
        v[0] = f && f->console ? FILE_DEVICE_CONSOLE_T : FILE_DEVICE_DISK_T;
        v[1] = f && f->console ? 0 : 0x20u;             /* FILE_DEVICE_IS_MOUNTED */
        break;
    }
    case OB_NPIPE: v[0] = FILE_DEVICE_NAMED_PIPE_T; break;
    case OB_SOCKET: v[0] = FILE_DEVICE_NETWORK_T; break;
    default: st = STATUS_OBJECT_TYPE_MISMATCH; break;
    }
    ob_deref(o);
    if (st) return st;
    if (copy_to_user(p, buf, v, 8)) return STATUS_ACCESS_VIOLATION;
    if (piosb) { struct ipc_iosb io = { 0, 8 }; copy_to_user(p, piosb, &io, sizeof io); }
    return STATUS_SUCCESS;
}

/* NtFsControlFile on RAM-disk files (pipes: npfs.c) and NtDeviceIoControlFile, both (Handle, Event, ApcRoutine, ApcContext,
 * IOSB, Code, InBuffer, InLength, OutBuffer, OutLength). They complete at once, through the normal IRP completion. */
static int32_t file_control(process_t *p, struct regs *r, uint32_t num, uint64_t h, uint64_t event, uint64_t apc, uint64_t apc_ctx)
{
    const uint64_t iosb = (uint64_t)stack_arg(p, r, 5);
    const uint32_t code = (uint32_t)stack_arg(p, r, 6);
    const uint64_t in_buf = (uint64_t)stack_arg(p, r, 7), in_len = (uint64_t)(uint32_t)stack_arg(p, r, 8);
    const uint64_t out_buf = (uint64_t)stack_arg(p, r, 9), out_len = (uint64_t)(uint32_t)stack_arg(p, r, 10);
    kobject_t *o;
    irp_t *irp;
    file_t *f;
    int32_t st = ipc_ref_handle(p, h, 0, &o, 0);
    uint64_t info = 0;
    if (st) return st;
    if (o->type != OB_FILE && o->type != OB_NPIPE && o->type != OB_SOCKET) { ob_deref(o); return STATUS_OBJECT_TYPE_MISMATCH; }
    if (o->type != OB_FILE) { ob_deref(o); return STATUS_INVALID_DEVICE_REQUEST; }   /* no device IOCTLs on pipes/sockets */
    st = irp_prepare(p, o, event, apc, apc_ctx, iosb, IRP_FLUSH, &irp);
    if (st) { ob_deref(o); return st; }
    f = o->u.file.file;
    st = STATUS_INVALID_DEVICE_REQUEST;
    if (num == SYS_NtFsControlFile && f && f->node && !f->console) {
        switch (code) {
        case 0x900a8u: st = STATUS_NOT_A_REPARSE_POINT_T; break;          /* FSCTL_GET_REPARSE_POINT */
        case 0x900c4u: st = STATUS_SUCCESS; break;                         /* FSCTL_SET_SPARSE: every RAM file is sparse-capable */
        case 0x9003cu: {                                                   /* FSCTL_GET_COMPRESSION: COMPRESSION_FORMAT_NONE */
            const uint16_t none = 0;
            if (out_len < 2) { st = STATUS_INVALID_PARAMETER; break; }
            st = copy_to_user(p, out_buf, &none, 2) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
            info = 2;
            break;
        }
        case 0x940cfu: {                                                   /* FSCTL_QUERY_ALLOCATED_RANGES: all of it */
            int64_t q[2], rng[2];
            if (in_len < 16 || out_len < 16 || copy_from_user(p, q, in_buf, 16)) { st = STATUS_INVALID_PARAMETER; break; }
            rng[0] = q[0];
            rng[1] = q[0] < (int64_t)f->node->size ? ((int64_t)f->node->size - q[0] < q[1] ? (int64_t)f->node->size - q[0] : q[1]) : 0;
            if (rng[1] <= 0) { info = 0; st = STATUS_SUCCESS; break; }
            st = copy_to_user(p, out_buf, rng, 16) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
            info = 16;
            break;
        }
        case 0x980c8u: {                                                   /* FSCTL_SET_ZERO_DATA {FileOffset, BeyondFinalZero} */
            int64_t z[2];
            static const uint8_t zeros[512];
            uint64_t at;
            if (in_len < 16 || copy_from_user(p, z, in_buf, 16) || z[0] < 0 || z[1] < z[0]) { st = STATUS_INVALID_PARAMETER; break; }
            if ((uint64_t)z[1] > f->node->size) z[1] = (int64_t)f->node->size;
            for (at = (uint64_t)z[0], st = STATUS_SUCCESS; at < (uint64_t)z[1] && !st; at += sizeof zeros) {
                const uint64_t n = (uint64_t)z[1] - at < sizeof zeros ? (uint64_t)z[1] - at : sizeof zeros;
                if (fs_write(f->node, at, zeros, n)) st = STATUS_ACCESS_DENIED;
            }
            break;
        }
        default: break;
        }
    }
    irp_complete(irp, st, info);
    ob_deref(o);
    return irp_finish(irp);
}

/* A file handle opened for synchronous I/O (FILE_SYNCHRONOUS_IO_*) waits inside its I/O calls and cannot be bound to a
 * completion port; called after NtCreateFile / NtOpenFile created handle `h`. */
void ipc_file_created(process_t *p, uint64_t h, uint32_t options)
{
    kobject_t *o;
    ioctx_t *io;
    if (!(options & 0x30u) || handle_ref(p, h, OB_FILE, &o, 0)) return;
    io = ipc_ioctx(o, 1);
    if (io) io->sync = 1;
    ob_deref(o);
}

/* ---------------------------------------------------------------- routing */
int32_t ipc_io_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                       int *handled)
{
    *handled = 1;
    switch (num) {
    case SYS_NtReadFile: case SYS_NtWriteFile: {
        kobject_t *o = handle_lookup(p, a1 & ~3ull, OB_FILE);
        if (!o) break;
        return file_rw(p, r, num, a1, a2, a3, a4);
    }
    case SYS_NtSetInformationFile: {                    /* (handle, iosb, buffer, length, class) */
        const uint32_t cls = (uint32_t)stack_arg(p, r, 5);
        kobject_t *o;
        int32_t st;
        if (cls != 30 && cls != 41 && cls != 61) break;
        st = ipc_ref_handle(p, a1, 0, &o, 0);
        if (st) return st;
        if (o->type != OB_FILE && o->type != OB_NPIPE) st = STATUS_OBJECT_TYPE_MISMATCH;
        else st = ipc_set_completion_info(p, o, cls, a3, a4);
        ob_deref(o);
        if (!st && a2) { struct ipc_iosb v = { 0, 0 }; copy_to_user(p, a2, &v, sizeof v); }
        return st;
    }
    case SYS_NtQueryInformationFile: {
        const uint32_t cls = (uint32_t)stack_arg(p, r, 5);
        kobject_t *o;
        int32_t st;
        if (cls != 41) break;
        st = ipc_ref_handle(p, a1, 0, &o, 0);
        if (st) return st;
        st = (o->type != OB_FILE && o->type != OB_NPIPE) ? STATUS_OBJECT_TYPE_MISMATCH : ipc_query_completion_info(p, o, a3, a4);
        ob_deref(o);
        if (!st && a2) { struct ipc_iosb v = { 0, 4 }; copy_to_user(p, a2, &v, sizeof v); }
        return st;
    }
    case SYS_NtCancelIoFile: case SYS_NtCancelIoFileEx: {
        /* NtCancelIoFile(FileHandle, IoStatusBlock): this thread's requests. NtCancelIoFileEx(FileHandle, IoRequestToCancel,
         * IoStatusBlock): the process's requests on the file, or only the one using that IO_STATUS_BLOCK. */
        kobject_t *o;
        int found = 0;
        const uint64_t iosb_out = num == SYS_NtCancelIoFile ? a2 : a3;
        int32_t st = ipc_ref_handle(p, a1, 0, &o, 0);
        if (st) return st;
        if (o->type != OB_FILE && o->type != OB_NPIPE) { ob_deref(o); return STATUS_OBJECT_TYPE_MISMATCH; }
        irp_cancel_matching(p, num == SYS_NtCancelIoFile ? thread_current() : 0, o, num == SYS_NtCancelIoFile ? 0 : a2, &found);
        ob_deref(o);
        if (num == SYS_NtCancelIoFileEx && !found) return STATUS_NOT_FOUND;
        if (iosb_out) { struct ipc_iosb v = { 0, 0 }; if (copy_to_user(p, iosb_out, &v, sizeof v)) return STATUS_ACCESS_VIOLATION; }
        return STATUS_SUCCESS;
    }
    case SYS_NtQueryVolumeInformationFile: return sys_query_volume(p, r, a1, a2, a3, a4);
    case SYS_NtFsControlFile: case SYS_NtDeviceIoControlFile: return file_control(p, r, num, a1, a2, a3, a4);
    case SYS_NtCreateIoCompletion: return sys_create_port(p, a1, a2, a3, a4);
    case SYS_NtSetIoCompletion: return sys_set_port(p, a1, a2, a3, a4, (uint64_t)stack_arg(p, r, 5));
    case SYS_NtRemoveIoCompletion: return sys_remove_port(p, r, a1, a2, a3, a4);
    case SYS_NtRemoveIoCompletionEx: return sys_remove_port_ex(p, r, a1, a2, a3, a4);
    case SYS_NtQueryIoCompletion: return sys_query_port(p, a1, a2, a3, a4, (uint64_t)stack_arg(p, r, 5));
    default: break;
    }
    *handled = 0;
    return 0;
}
