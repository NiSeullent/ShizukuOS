/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 I/O completion ports and I/O completion: what CreateIoCompletionPort / GetQueuedCompletionStatus(Ex) /
 * PostQueuedCompletionStatus and overlapped I/O need.
 *
 *  - A port (OB_IOCP) is a FIFO of completion packets {key, ApcContext (the OVERLAPPED), status, information}. It is
 *    signalled while packets are queued, so waiting uses the ordinary object wait (objects.c); a waiter that loses a
 *    race for the last packet waits again with the rest of its timeout. Packets are kernel heap records; the number
 *    queued is bounded (IOCP_MAX_PACKETS) and posting beyond it fails with STATUS_INSUFFICIENT_RESOURCES.
 *  - A file is associated with a port through NtSetInformationFile(FileCompletionInformation) (sysfile.c); every I/O
 *    request on it that completes (asynchronously, or synchronously unless FILE_SKIP_COMPLETION_PORT_ON_SUCCESS is set)
 *    with a non-NULL ApcContext queues a packet with the association's key: io_complete() below is the one place
 *    where requests finish (IO_STATUS_BLOCK, event, file object, port).
 *  - The concurrency value is recorded and reported but the scheduler does not limit running threads by it
 *    (Kernel64 runs one CPU: at most one thread runs at a time anyway).
 */
#include "fs.h"

#define IOCP_MAX_PACKETS 65536u
#ifndef STATUS_INSUFFICIENT_RESOURCES
#define STATUS_INSUFFICIENT_RESOURCES ((int32_t)0xC000009A)
#endif

typedef struct iopkt {
    struct iopkt *next;
    uint64_t key, ctx, info;
    int64_t status;
} iopkt_t;

typedef struct iocp {
    iopkt_t *head, *tail;
    uint32_t count, concurrency;
} iocp_t;

kobject_t *iocp_create(uint32_t concurrency)
{
    iocp_t *q = kzalloc(sizeof *q);
    kobject_t *o = q ? ob_create(OB_IOCP, 0) : 0;
    if (!o) { kfree(q); return 0; }
    q->concurrency = concurrency ? concurrency : 1;
    o->u.iocp.q = q;
    return o;
}

void iocp_object_free(kobject_t *o)
{
    iocp_t *q = o->u.iocp.q;
    if (!q) return;
    while (q->head) { iopkt_t *n = q->head->next; kfree(q->head); q->head = n; }
    kfree(q);
    o->u.iocp.q = 0;
}

/* Queues a packet; callable from any thread context. 0 = queued. */
int32_t iocp_post(kobject_t *o, uint64_t key, uint64_t ctx, int32_t status, uint64_t info)
{
    iocp_t *q = o->u.iocp.q;
    iopkt_t *k;
    uint64_t f;
    if (!q) return STATUS_INVALID_HANDLE;
    if (q->count >= IOCP_MAX_PACKETS) return STATUS_INSUFFICIENT_RESOURCES;
    k = kmalloc(sizeof *k);
    if (!k) return STATUS_INSUFFICIENT_RESOURCES;
    k->next = 0; k->key = key; k->ctx = ctx; k->status = status; k->info = info;
    f = irq_save();
    if (q->tail) q->tail->next = k; else q->head = k;
    q->tail = k;
    ++q->count;
    o->signaled = 1;
    ob_release_check(o);
    irq_restore(f);
    return STATUS_SUCCESS;
}

uint32_t iocp_depth(kobject_t *o) { iocp_t *q = o->u.iocp.q; return q ? q->count : 0; }

/* Removes up to `max` packets into out[] (4 x u64 each: key, ctx, status, info), waiting up to `timeout` (NT units:
 * negative = relative 100 ns, INT64_MAX = forever, 0 = poll). */
int32_t iocp_remove(process_t *p, kobject_t *o, uint64_t *out, unsigned max, unsigned *got, int64_t timeout, int alertable)
{
    iocp_t *q = o->u.iocp.q;
    const uint64_t start = ticks_now();
    const uint64_t budget_ms = timeout == INT64_MAX ? UINT64_MAX : timeout < 0 ? (uint64_t)(-timeout) / 10000 : 0;
    *got = 0;
    if (!q) return STATUS_INVALID_HANDLE;
    for (;;) {
        uint64_t f = irq_save();
        int32_t st;
        if (q->head) {
            unsigned n = 0;
            while (q->head && n < max) {
                iopkt_t *k = q->head;
                q->head = k->next;
                if (!q->head) q->tail = 0;
                --q->count;
                out[n * 4 + 0] = k->key; out[n * 4 + 1] = k->ctx; out[n * 4 + 2] = (uint64_t)k->status; out[n * 4 + 3] = k->info;
                kfree(k);
                ++n;
            }
            o->signaled = q->count > 0;
            irq_restore(f);
            *got = n;
            return STATUS_SUCCESS;
        }
        irq_restore(f);
        if (p->terminated) return STATUS_THREAD_IS_TERMINATING;
        if (budget_ms != UINT64_MAX) {
            const uint64_t spent = ticks_now() - start;          /* ticks are milliseconds */
            if (spent >= budget_ms) return STATUS_TIMEOUT;
            st = ob_wait(p, &o, 1, 0, -(int64_t)((budget_ms - spent) * 10000), alertable);
        } else {
            st = ob_wait(p, &o, 1, 0, INT64_MAX, alertable);
        }
        if (st == STATUS_TIMEOUT && budget_ms != UINT64_MAX && ticks_now() - start >= budget_ms) return STATUS_TIMEOUT;
        if (st < 0 && st != STATUS_TIMEOUT) return st;
    }
}

/* ---------------------------------------------------------------- I/O completion */
static int proc_alive(process_t *p, int pid) { return p && p->used && p->pid == pid && !p->terminated; }

/* Finishes an I/O request of process `p` (pid `pid`) on file object `fo`: writes the IO_STATUS_BLOCK, sets the event
 * (or the file object when there is none), and queues a completion packet when the file is associated with a port.
 * `pending`: the request had returned STATUS_PENDING (a packet is then queued whatever the notification mode). */
void io_complete(process_t *p, int pid, kobject_t *fo, kobject_t *event, uint64_t apc_ctx, uint64_t iosb, int32_t status,
                 uint64_t info, int pending)
{
    file_t *f = fo ? (file_t *)fo->u.file.file : 0;
    if (iosb && proc_alive(p, pid)) {
        uint64_t v[2] = { (uint64_t)(int64_t)status, info };
        copy_to_user(p, iosb, v, sizeof v);
    }
    if (event) ob_signal_event(event);
    if (fo && !(f && (f->notify_modes & 2))) ob_signal_event(fo);              /* FILE_SKIP_SET_EVENT_ON_HANDLE */
    if (f && f->iocp && apc_ctx && (pending || !(f->notify_modes & 1)))           /* FILE_SKIP_COMPLETION_PORT_ON_SUCCESS */
        iocp_post(f->iocp, f->iocp_key, apc_ctx, status, info);
}

/* Start of an I/O request: the event and the file object are reset (NT does this before the request runs). */
void io_start(kobject_t *fo, kobject_t *event)
{
    if (event) ob_reset_event(event);
    if (fo) ob_reset_event(fo);
}
