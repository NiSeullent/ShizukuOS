/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 object manager: reference-counted kernel objects (events, mutants, semaphores,
 * timers, thread and process objects), per-process handle tables (handle values are
 * multiples of 4, as on NT), and the wait machinery with WaitAny/WaitAll and timeouts.
 * A wait blocks the calling thread; a signal satisfies waiters in FIFO order and applies
 * the object's acquire semantics (auto-reset event, mutant ownership, semaphore count).
 */
#include "proc_internal.h"

#define MAX_WAIT 64
typedef struct waitdesc {
    unsigned n;
    int all;
    kobject_t *objs[MAX_WAIT];
    waitblock_t wb[MAX_WAIT];
    int result;                         /* -1 pending; >= 0 index; -2 timeout; -3 terminated */
    int abandoned;
} waitdesc_t;

static kobject_t *named_head;
static kobject_t *timers_head[16];
static unsigned timer_count;

kobject_t *ob_create(uint32_t type, const char *name)
{
    kobject_t *o = kzalloc(sizeof *o);
    unsigned i;
    if (!o) return 0;
    o->type = type;
    o->refs = 1;
    if (name && name[0]) {
        for (i = 0; name[i] && i < sizeof o->name - 1; ++i) o->name[i] = name[i];
        o->next_named = named_head;
        named_head = o;
    }
    return o;
}

/* Reference counts and handle-table slots are updated with interrupts off: the kernel is preemptible, and several threads
 * of one process (or of different processes sharing an object) may race on them. */
void ob_ref(kobject_t *o) { const uint64_t f = irq_save(); ++o->refs; irq_restore(f); }

/* Registry key objects: drop the key node's reference (registry.c). May block on the registry lock, so it runs after the
 * interrupt-off section below and ob_deref() must not be called with irqs disabled or with the registry lock held. */
extern void reg_key_object_free(kobject_t *o);
/* IPC hooks (kernel64/ipc_core.c; no-ops when it is not linked): the last reference of an object is gone / one handle of
 * an object was closed (ipc_handle_closed runs for every type, before the handle's reference is dropped). */
void __attribute__((weak)) ipc_object_free(kobject_t *o) { (void)o; }
void __attribute__((weak)) ipc_handle_closed(process_t *p, kobject_t *o) { (void)p; (void)o; }

void ob_deref(kobject_t *o)
{
    uint64_t f = irq_save();
    int last;
    KASSERT(o->refs > 0);
    last = --o->refs == 0;
    if (last) {
        kobject_t **pp;
        for (pp = &named_head; *pp; pp = &(*pp)->next_named)
            if (*pp == o) { *pp = o->next_named; break; }
        if (o->type == OB_TIMER) {
            unsigned i;
            for (i = 0; i < timer_count; ++i)
                if (timers_head[i] == o) { timers_head[i] = timers_head[--timer_count]; break; }
        }
    }
    irq_restore(f);
    if (last) {
        extern void token_object_free(kobject_t *o);
        if (o->type == OB_KEY) reg_key_object_free(o);
        else if (o->type == OB_TOKEN) token_object_free(o);
        else ipc_object_free(o);                    /* IPC hook: sections, pipes, ports, jobs, thread/process slots */
        kfree(o->sd);                               /* a stored security descriptor (sysk32_sec.c) */
        kfree(o);
    }
}

kobject_t *ob_find_named(uint32_t type, const char *name)
{
    kobject_t *o;
    (void)type;
    for (o = named_head; o; o = o->next_named) {
        unsigned i = 0;
        while (o->name[i] && name[i] && o->name[i] == name[i]) ++i;
        if (!o->name[i] && !name[i]) return o;
    }
    return 0;
}

/* ---------------------------------------------------------------- handles */
int32_t handle_insert(process_t *p, kobject_t *o, uint32_t access, uint32_t *h_out)
{
    const uint64_t f = irq_save();
    unsigned i;
    for (i = 0; i < p->handle_cap; ++i)
        if (!p->handles[i].obj) {
            p->handles[i].obj = o;
            p->handles[i].access = access;
            p->handles[i].inherit = 0;
            ++o->refs;
            ++p->handle_count;
            *h_out = (i + 1) * 4;
            irq_restore(f);
            return STATUS_SUCCESS;
        }
    irq_restore(f);
    return STATUS_NO_MEMORY;
}

kobject_t *handle_lookup(process_t *p, uint64_t handle, uint32_t type)
{
    kobject_t *o;
    if (handle & 3 || !handle || handle > (uint64_t)p->handle_cap * 4ull) return 0;
    o = p->handles[handle / 4 - 1].obj;
    if (!o || (type && o->type != type)) return 0;
    return o;
}

int32_t handle_ref(process_t *p, uint64_t handle, uint32_t type, kobject_t **out, uint32_t *access)
{
    const uint64_t f = irq_save();
    kobject_t *o = 0;
    if (!(handle & 3) && handle && handle <= (uint64_t)p->handle_cap * 4ull)
        o = p->handles[handle / 4 - 1].obj;
    if (!o) { irq_restore(f); return STATUS_INVALID_HANDLE; }
    if (type && o->type != type) { irq_restore(f); return STATUS_OBJECT_TYPE_MISMATCH; }
    ++o->refs;
    if (access) *access = p->handles[handle / 4 - 1].access;
    irq_restore(f);
    *out = o;
    return STATUS_SUCCESS;
}

int32_t handle_close(process_t *p, uint64_t handle)
{
    kobject_t *o;
    const uint64_t f = irq_save();
    o = 0;
    if (!(handle & 3) && handle && handle <= (uint64_t)p->handle_cap * 4ull)
        o = p->handles[handle / 4 - 1].obj;
    if (!o) { irq_restore(f); return STATUS_INVALID_HANDLE; }
    p->handles[handle / 4 - 1].obj = 0;                 /* the slot is free before anything else can look at it */
    --p->handle_count;
    irq_restore(f);
    if (o->type == OB_FILE) {
        extern void file_object_closed(kobject_t *o);
        file_object_closed(o);
    } else if (o->type == OB_SOCKET) {
        extern void net_socket_handle_closing(kobject_t *o);   /* net_sock.c: tears the socket down with its last handle */
        net_socket_handle_closing(o);
    } else if (o->type == 0x50 /* OB_DEVICE */) {
        extern void ntdrv_device_handle_closing(kobject_t *o); /* ntdrv_io.c: IRP_MJ_CLOSE on the last handle */
        ntdrv_device_handle_closing(o);
    }
    ipc_handle_closed(p, o);
    ob_deref(o);
    return STATUS_SUCCESS;
}

void handles_close_all(process_t *p)
{
    unsigned i;
    for (i = 0; i < p->handle_cap; ++i)
        if (p->handles[i].obj)
            handle_close(p, (i + 1) * 4ull);
}

/* ---------------------------------------------------------------- acquire / signal */
static int obj_signaled(kobject_t *o, thread_t *t)
{
    switch (o->type) {
    case OB_EVENT: case OB_THREAD: case OB_PROCESS: case OB_TIMER: return o->signaled;
    case OB_SEMAPHORE: return o->u.sem.count > 0;
    case OB_MUTANT: return o->u.mutant.owner == 0 || o->u.mutant.owner == t;
    default: return OB_IS_IPC(o->type) ? o->signaled : 0;     /* pipe ends: set when an I/O on them completes */
    }
}

/* Applies the side effects of a successful wait on `o`; returns nonzero if it was abandoned. */
static int obj_acquire(kobject_t *o, thread_t *t)
{
    int abandoned = 0;
    switch (o->type) {
    case OB_EVENT: if (!o->u.event.manual) o->signaled = 0; break;
    case OB_TIMER: if (!o->u.timer.manual) o->signaled = 0; break;
    case OB_SEMAPHORE: --o->u.sem.count; o->signaled = o->u.sem.count > 0; break;
    case OB_MUTANT:
        o->u.mutant.owner = t;
        ++o->u.mutant.recursion;
        o->signaled = 0;
        if (o->u.mutant.abandoned) { abandoned = 1; o->u.mutant.abandoned = 0; }
        break;
    default: break;
    }
    return abandoned;
}

static void unlink_waits(waitdesc_t *d)
{
    unsigned i;
    for (i = 0; i < d->n; ++i) {
        waitblock_t **pp;
        for (pp = &d->objs[i]->waiters; *pp; pp = &(*pp)->next)
            if (*pp == &d->wb[i]) { *pp = d->wb[i].next; break; }
    }
}

/* Called with interrupts off after `o` may have become signaled. */
void ob_release_check(kobject_t *o)
{
    waitblock_t *w = o->waiters;
    while (w) {
        waitblock_t *next = w->next;
        thread_t *t = w->thread;
        waitdesc_t *d = t->wait_multi;
        if (d && d->result == -1) {
            if (!d->all) {
                if (obj_signaled(o, t)) {
                    d->abandoned = obj_acquire(o, t);
                    d->result = (int)w->index;
                    unlink_waits(d);
                    thread_wake(t);
                    if (!obj_signaled(o, t) && o->type != OB_THREAD && o->type != OB_PROCESS)
                        break;                      /* consumed: stop at the first satisfied waiter */
                }
            } else {
                unsigned i;
                int ok = 1;
                for (i = 0; i < d->n; ++i) if (!obj_signaled(d->objs[i], t)) { ok = 0; break; }
                if (ok) {
                    for (i = 0; i < d->n; ++i) d->abandoned |= obj_acquire(d->objs[i], t);
                    d->result = 0;
                    unlink_waits(d);
                    thread_wake(t);
                }
            }
        }
        w = next;
    }
}

void ob_signal_event(kobject_t *o)
{
    uint64_t f = irq_save();
    o->signaled = 1;
    ob_release_check(o);
    irq_restore(f);
}

void ob_reset_event(kobject_t *o) { uint64_t f = irq_save(); o->signaled = 0; irq_restore(f); }

/* ---------------------------------------------------------------- waiting */
int32_t ob_wait(process_t *p, kobject_t **objs, unsigned n, int wait_all, int64_t timeout, int alertable)
{
    thread_t *t = thread_current();
    waitdesc_t *d;
    uint64_t f;
    unsigned i;
    int32_t status;
    (void)p; (void)alertable;
    if (!n || n > MAX_WAIT)
        return STATUS_INVALID_PARAMETER;
    f = irq_save();
    /* Fast path: already satisfiable. */
    if (!wait_all) {
        for (i = 0; i < n; ++i)
            if (obj_signaled(objs[i], t)) {
                const int ab = obj_acquire(objs[i], t);
                irq_restore(f);
                return (int32_t)(i + (ab ? STATUS_ABANDONED_WAIT_0 : 0));
            }
    } else {
        int all_ok = 1;
        for (i = 0; i < n; ++i) if (!obj_signaled(objs[i], t)) { all_ok = 0; break; }
        if (all_ok) {
            int ab = 0;
            for (i = 0; i < n; ++i) ab |= obj_acquire(objs[i], t);
            irq_restore(f);
            return ab ? STATUS_ABANDONED_WAIT_0 : STATUS_SUCCESS;
        }
    }
    if (timeout == 0) {
        irq_restore(f);
        return STATUS_TIMEOUT;
    }
    d = kzalloc(sizeof *d);
    if (!d) { irq_restore(f); return STATUS_NO_MEMORY; }
    d->n = n;
    d->all = wait_all;
    d->result = -1;
    for (i = 0; i < n; ++i) {
        d->objs[i] = objs[i];
        d->wb[i].thread = t;
        d->wb[i].obj = objs[i];
        d->wb[i].index = i;
        d->wb[i].next = 0;
        if (!objs[i]->waiters) objs[i]->waiters = &d->wb[i];
        else { waitblock_t *w = objs[i]->waiters; while (w->next) w = w->next; w->next = &d->wb[i]; }
    }
    t->wait_multi = d;
    t->wait_result = 0;
    if (timeout != INT64_MAX) {
        const uint64_t ms = timeout < 0 ? (uint64_t)(-timeout) / 10000 : 0;     /* 100 ns units */
        t->wake_tick = ticks_now() + (ms * 1000u + TICK_US - 1) / TICK_US + 1;
    } else {
        t->wake_tick = 0;
    }
    thread_block_current();
    /* woken by a signal (d->result set) or by the tick when the timeout expired */
    if (d->result == -1) {
        d->result = -2;
        unlink_waits(d);
    }
    t->wait_multi = 0;
    t->wake_tick = 0;
    status = d->result == -2 ? STATUS_TIMEOUT : d->result == -3 ? STATUS_THREAD_IS_TERMINATING
           : (int32_t)((wait_all ? 0 : (unsigned)d->result) + (d->abandoned ? STATUS_ABANDONED_WAIT_0 : 0));
    irq_restore(f);
    kfree(d);
    return status;
}

/* ---------------------------------------------------------------- thread / timer hooks */
void thread_object_signal(thread_t *t)
{
    if (t->object) {
        t->object->signaled = 1;
        ob_release_check(t->object);
    }
}

/* sched.c reclaims an exited user thread (interrupts off): its object keeps the exit status for GetExitCodeThread and
 * waits (it is already signalled), and loses the reference the thread held on it since creation. */
void thread_object_detach(thread_t *t)
{
    kobject_t *o = t->object;
    process_t *p = t->proc;
    if (!o) return;
    o->u.thr.exit_code = t->exit_code;
    o->u.thr.create_tick = t->create_tick;
    o->u.thr.exit_tick = t->exit_tick;
    o->u.thr.user_ticks = t->user_ticks;
    o->u.thr.kernel_ticks = t->kernel_ticks;
    o->u.thr.cycles = t->cycles;
    o->u.thr.t = 0;
    t->object = 0;
    ob_deref(o);
    if (p && p->object) ob_deref(p->object);   /* the process reference the thread took at creation (proc.c): a dead
                                                   process's slot is recycled once no thread or handle refers to it */
}

void ob_register_timer(kobject_t *o)
{
    if (timer_count < 16) timers_head[timer_count++] = o;
}

void __attribute__((weak)) ipc_timer_tick(uint64_t now) { (void)now; }   /* waitable timers (ipc_timer.c) */

void sched_check_timeouts(uint64_t now)
{
    unsigned i;
    ipc_timer_tick(now);
    for (i = 0; i < timer_count; ++i) {
        kobject_t *o = timers_head[i];
        if (o->u.timer.armed && o->u.timer.due_tick <= now) {
            o->signaled = 1;
            if (o->u.timer.period_ms)
                o->u.timer.due_tick = now + o->u.timer.period_ms;
            else
                o->u.timer.armed = 0;
            ob_release_check(o);
        }
    }
}

/* Overridden by the file system layer. */
void __attribute__((weak)) file_object_closed(kobject_t *o) { (void)o; }

/* Diagnostic for the autorun timeout report (autorun.c): the objects a blocked thread waits for. */
void ob_print_wait(thread_t *t)
{
    waitdesc_t *d = t->wait_multi;
    unsigned i;
    if (!d) return;
    kprintf("K64:     waits for %s of %u object(s):", d->all ? "all" : "any", d->n);
    for (i = 0; i < d->n && i < 8; ++i) {
        const kobject_t *o = d->objs[i];
        if (o->type == OB_THREAD) kprintf(" [thread tid %llu signaled %d]", (unsigned long long)o->u.thr.tid, o->signaled);    /* a join: whose exit it waits for */
        else kprintf(" [type %x%s%s signaled %d]", o->type, o->name[0] ? " " : "", o->name, o->signaled);
    }
    kprintf("\n");
}
