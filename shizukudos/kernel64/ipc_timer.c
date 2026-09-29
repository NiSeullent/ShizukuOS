/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 waitable timers (NtCreateTimer / NtOpenTimer / NtSetTimer / NtCancelTimer / NtQueryTimer): the objects behind
 * CreateWaitableTimer(Ex) / SetWaitableTimer(Ex), replacing the stage-0 timers of sysx.c (at most 16, unnamed, relative
 * due times only, no completion routine).
 *
 *   - notification (manual-reset) and synchronization (auto-reset) timers, optionally named (OBJ_OPENIF);
 *   - due times relative (negative, 100 ns) or absolute (positive FILETIME, against the platform's wall clock);
 *   - periodic timers re-arm themselves; setting a timer resets it to non-signaled;
 *   - a completion routine runs as a user APC in the thread that set the timer - routine(context, FILETIME low, FILETIME
 *     high) - in that thread's next alertable wait; if that thread has exited the timer is cancelled instead, as on
 *     Windows.
 * Expiry is checked on every scheduler tick (1 ms) with interrupts off (objects.c: sched_check_timeouts).
 */
#include "ipc.h"

#define TIMER_QUERY_STATE 0x0001u
#define TIMER_MODIFY_STATE 0x0002u

typedef struct ktimer {
    struct ktimer *next;
    kobject_t *obj;                     /* the timer object (no reference: the entry dies with it) */
    uint64_t due_tick, period_ms;
    int armed;
    uint64_t apc_routine, apc_context;
    kobject_t *thread_obj;              /* referenced thread object of the thread that set the timer (APC target) */
} ktimer_t;

static ktimer_t *g_timers;
extern int64_t shz_filetime_now_ipc(void);

static ktimer_t *timer_of(kobject_t *o)
{
    ktimer_t *t;
    for (t = g_timers; t; t = t->next) if (t->obj == o) return t;
    return 0;
}

/* Scheduler tick (interrupts off). */
void ipc_timer_tick(uint64_t now)
{
    ktimer_t *t;
    ipc_kill_sweep_tick();                                              /* victims that blocked after their wake-up */
    for (t = g_timers; t; t = t->next) {
        kobject_t *o = t->obj;
        if (!t->armed || t->due_tick > now) continue;
        if (t->period_ms) {
            while (t->due_tick <= now) t->due_tick += t->period_ms;     /* missed periods collapse into one */
        } else {
            t->armed = 0;
        }
        if (t->apc_routine) {
            thread_t *th = t->thread_obj ? t->thread_obj->u.thr.t : 0;
            if (!th || th->state == TS_ZOMBIE || th->state == TS_FREE || !th->proc || thread_must_die(th)) {
                t->armed = 0;                                           /* its thread is gone: the timer is cancelled */
                continue;
            } else {
                const int64_t ft = shz_filetime_now_ipc();
                apc_queue(th, t->apc_routine, t->apc_context, (uint32_t)ft, (uint64_t)(uint32_t)(ft >> 32));
            }
        }
        o->signaled = 1;
        ob_release_check(o);
    }
}

/* The object is being freed (ipc_core.c). */
void timer_free(kobject_t *o)
{
    ktimer_t **pp, *t = 0;
    const uint64_t f = irq_save();
    for (pp = &g_timers; *pp; pp = &(*pp)->next)
        if ((*pp)->obj == o) { t = *pp; *pp = t->next; break; }
    irq_restore(f);
    if (!t) return;
    if (t->thread_obj) ob_deref(t->thread_obj);
    kfree(t);
}

/* NtCreateTimer(PHANDLE, ACCESS, POBJECT_ATTRIBUTES, TIMER_TYPE: 0 notification, 1 synchronization) */
static int32_t sys_create_timer(process_t *p, uint64_t ph, uint64_t access, uint64_t oa, uint64_t type)
{
    char name[48];
    uint32_t oattrs = 0;
    kobject_t *o;
    ktimer_t *t;
    int32_t st;
    if (type > 1) return STATUS_INVALID_PARAMETER;
    st = ipc_name_from_oa(p, oa, name, sizeof name, &oattrs);
    if (st) return st;
    if (name[0]) {
        const uint64_t f = irq_save();
        kobject_t *ex = ob_find_named(OB_TIMER, name);
        if (ex) ob_ref(ex);
        irq_restore(f);
        if (ex) {
            if (ex->type != OB_TIMER) { ob_deref(ex); return STATUS_OBJECT_TYPE_MISMATCH; }
            if (!(oattrs & 0x80u)) { ob_deref(ex); return STATUS_OBJECT_NAME_COLLISION; }
            st = ipc_give_handle(p, ex, (uint32_t)access, (oattrs & OBJ_INHERIT_ATTR) != 0, ph, 0);
            return st ? st : STATUS_OBJECT_NAME_EXISTS;
        }
    }
    t = kzalloc(sizeof *t);
    o = t ? ob_create(OB_TIMER, name) : 0;
    if (!o) { kfree(t); return STATUS_INSUFFICIENT_RESOURCES; }
    o->u.timer.manual = type == 0;
    t->obj = o;
    {
        const uint64_t f = irq_save();
        t->next = g_timers;
        g_timers = t;
        irq_restore(f);
    }
    return ipc_give_handle(p, o, (uint32_t)access, (oattrs & OBJ_INHERIT_ATTR) != 0, ph, 0);
}

static int32_t get_timer(process_t *p, uint64_t h, uint32_t need, kobject_t **o, ktimer_t **t)
{
    uint32_t access = 0;
    int32_t st = ipc_ref_handle(p, h, OB_TIMER, o, &access);
    if (st) return st;
    if ((access & need) != need && !(access & 0x10000000u)) { ob_deref(*o); return STATUS_ACCESS_DENIED; }
    *t = timer_of(*o);
    if (!*t) { ob_deref(*o); return STATUS_OBJECT_TYPE_MISMATCH; }       /* a timer not made by this file */
    return STATUS_SUCCESS;
}

/* NtSetTimer(Timer, PLARGE_INTEGER DueTime, TimerApcRoutine, TimerContext, BOOLEAN ResumeTimer, LONG Period,
 *            PBOOLEAN PreviousState) */
static int32_t sys_set_timer(process_t *p, struct regs *r, uint64_t h, uint64_t pdue, uint64_t routine, uint64_t context)
{
    const int32_t period = (int32_t)stack_arg(p, r, 6);
    const uint64_t pprev = (uint64_t)stack_arg(p, r, 7);
    kobject_t *o, *old_thread, *new_thread = 0;
    ktimer_t *t;
    int64_t due;
    uint64_t f, ms;
    uint8_t prev;
    int32_t st;
    if (period < 0) return STATUS_INVALID_PARAMETER;
    if (!pdue || copy_from_user(p, &due, pdue, 8)) return STATUS_ACCESS_VIOLATION;
    st = get_timer(p, h, TIMER_MODIFY_STATE, &o, &t);
    if (st) return st;
    if (due < 0) ms = (uint64_t)(-due) / 10000;
    else {
        const int64_t now = shz_filetime_now_ipc();
        ms = due > now ? (uint64_t)(due - now) / 10000 : 0;
    }
    if (routine) { new_thread = thread_current()->object; ob_ref(new_thread); }
    f = irq_save();
    prev = (uint8_t)(o->signaled != 0);
    o->signaled = 0;
    old_thread = t->thread_obj;
    t->thread_obj = new_thread;
    t->apc_routine = routine;
    t->apc_context = context;
    t->period_ms = (uint64_t)period;
    t->due_tick = ticks_now() + (ms * 1000u + TICK_US - 1) / TICK_US + (ms ? 1 : 0);
    if (t->due_tick <= ticks_now()) t->due_tick = ticks_now() + 1;
    t->armed = 1;
    irq_restore(f);
    if (old_thread) ob_deref(old_thread);
    ob_deref(o);
    if (pprev && copy_to_user(p, pprev, &prev, 1)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

/* NtCancelTimer(Timer, PBOOLEAN CurrentState) */
static int32_t sys_cancel_timer(process_t *p, uint64_t h, uint64_t pcur)
{
    kobject_t *o, *old_thread;
    ktimer_t *t;
    uint8_t cur;
    uint64_t f;
    int32_t st = get_timer(p, h, TIMER_MODIFY_STATE, &o, &t);
    if (st) return st;
    f = irq_save();
    t->armed = 0;
    cur = (uint8_t)(o->signaled != 0);
    old_thread = t->thread_obj;
    t->thread_obj = 0;
    t->apc_routine = 0;
    irq_restore(f);
    if (old_thread) ob_deref(old_thread);
    ob_deref(o);
    if (pcur && copy_to_user(p, pcur, &cur, 1)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

/* NtQueryTimer(Timer, TimerBasicInformation = 0, {LARGE_INTEGER RemainingTime; BOOLEAN TimerState}, Length, PULONG) */
static int32_t sys_query_timer(process_t *p, struct regs *r, uint64_t h, uint64_t cls, uint64_t buf, uint64_t len)
{
    const uint64_t pret = (uint64_t)stack_arg(p, r, 5);
    struct { int64_t remaining; uint8_t state, pad[7]; } b;
    const uint32_t n = 9;
    kobject_t *o;
    ktimer_t *t;
    int32_t st;
    if (cls != 0) return STATUS_INVALID_INFO_CLASS;
    if (len < 9) return STATUS_INFO_LENGTH_MISMATCH;
    st = get_timer(p, h, TIMER_QUERY_STATE, &o, &t);
    if (st) return st;
    memset(&b, 0, sizeof b);
    {
        const uint64_t f = irq_save(), now = ticks_now();
        b.remaining = t->armed && t->due_tick > now ? (int64_t)((t->due_tick - now) * TICK_US * 10u) : 0;
        b.state = (uint8_t)(o->signaled != 0);
        irq_restore(f);
    }
    ob_deref(o);
    if (copy_to_user(p, buf, &b, 9)) return STATUS_ACCESS_VIOLATION;
    if (pret && copy_to_user(p, pret, &n, 4)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

int32_t ipc_timer_syscall(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                          int *handled)
{
    *handled = 1;
    switch (num) {
    case SYS_NtCreateTimer: return sys_create_timer(p, a1, a2, a3, a4);
    case SYS_NtOpenTimer: return ipc_open_named(p, OB_TIMER, a1, a2, a3);
    case SYS_NtSetTimer: return sys_set_timer(p, r, a1, a2, a3, a4);
    case SYS_NtCancelTimer: return sys_cancel_timer(p, a1, a2);
    case SYS_NtQueryTimer: return sys_query_timer(p, r, a1, a2, a3, a4);
    default: break;
    }
    *handled = 0;
    return 0;
}
