/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 existing scheduler with bounded perCPU FIFO/state ownership.
 * Native execution remains UP until architecture/Supervisor/shared resources
 * support AP activation. Local IRQ masking precedes short ticket admission;
 * no ticket survives a context switch, allocation or wait.
 */
#include "k32.h"
#include "sched_cpu.h"
#include "smp_native.h"
#include "../abi/shz_sched_deadline.h"

_Static_assert(TICK_US > 0, "finite deadlines require a positive tick interval");
extern void switch_stacks(uint32_t *save_esp, uint32_t new_esp);
#define MAX_THREADS K32_THREAD_MAX
#define STACK_BYTES 16384
/* ALLOCATING prevents observing an unpublished or being-reclaimed stack. */
enum { TS_FREE, TS_READY, TS_RUNNING, TS_BLOCKED, TS_ZOMBIE, TS_ALLOCATING };
static thread_t threads[MAX_THREADS];
static k32_runqueues_t runqueues;
static uint32_t next_id = 1;
static volatile uint64_t jiffies;
static uint64_t switches;
extern uint32_t proc_page_directory(uint32_t proc_id);
extern uint32_t kernel_space(void);

typedef struct { uint32_t flags, ticket; } sched_guard_t;
static sched_guard_t guard_enter(void)
{
    sched_guard_t g;
    g.flags = irq_save();
    g.ticket = k32_rq_lock(&runqueues);
    return g;
}
static void guard_leave(sched_guard_t g)
{
    k32_rq_unlock(&runqueues, g.ticket);
    irq_restore(g.flags);
}
static k32_cpu_sched_t *cpu_context(void)
{
    uint32_t c = arch_cpu_id();
    return k32_rq_cpu_online(&runqueues, c) ? &runqueues.cpu[c] : 0;
}
thread_t *thread_current(void)
{
    k32_cpu_sched_t *c = cpu_context();
    return c ? c->current : 0;
}
uint64_t ticks_now(void)
{
    sched_guard_t g = guard_enter();
    uint64_t v = jiffies;
    guard_leave(g);
    return v;
}
uint64_t sched_switch_count(void)
{
    sched_guard_t g = guard_enter();
    uint64_t v = switches;
    guard_leave(g);
    return v;
}
uint32_t sched_cpu_online_mask(void)
{
    sched_guard_t g = guard_enter();
    uint32_t v = runqueues.online_mask;
    guard_leave(g);
    return v;
}
int sched_cpu_register(uint32_t cpu)
{
    /* Do not expose an AP as online from metadata, CPUID, or a parked state.
     * Requires perCPU arch resources, trusted identity + IRQ/IPI and shared MM,
     * process/allocator/wait synchronization. No such domain ABI exists yet. */
    if (cpu >= K32_CPU_MAX) return -1;
    return cpu == 0 && arch_cpu_id() == 0 && runqueues.online_mask == 1 ? 0 : -2;
}
uint32_t thread_get_affinity(thread_t *t)
{
    sched_guard_t g = guard_enter();
    uint32_t v = cpu_context() && k32_rq_valid(&runqueues, t) && t->state != TS_FREE ? t->affinity_mask : 0;
    guard_leave(g);
    return v;
}
int thread_set_affinity(thread_t *t, uint32_t mask)
{
    sched_guard_t g = guard_enter();
    int rc = cpu_context() && k32_rq_valid(&runqueues,t) &&
        ((!t->native_tag && mask==1) || (t->native_tag==K32_AP_TAG && !t->proc && mask==t->affinity_mask))
        ? k32_rq_affinity_locked(&runqueues, t, mask) : -1;
    guard_leave(g);
    return rc;
}
int sched_validate(void)
{
    sched_guard_t g = guard_enter();
    int rc = k32_rq_validate_locked(&runqueues);
    for (unsigned c = 0; !rc && c < K32_CPU_MAX; ++c) {
        k32_cpu_sched_t *cpu = &runqueues.cpu[c];
        if (!k32_rq_cpu_online(&runqueues, c)) {
            if (cpu->current || cpu->idle || cpu->outgoing) rc = -1;
        } else if (!k32_rq_valid(&runqueues, cpu->current) || cpu->current->on_cpu != c ||
                   cpu->current->state != TS_RUNNING || cpu->current->ready_queued) rc = -1;
    }
    for (unsigned i = 0; !rc && i < MAX_THREADS; ++i) {
        thread_t *t = &threads[i];
        if (t->on_cpu != K32_CPU_NONE) {
            if (!k32_rq_cpu_online(&runqueues, t->on_cpu)) rc = -1;
            else {
                k32_cpu_sched_t *c = &runqueues.cpu[t->on_cpu];
                if ((t != c->current && t != c->outgoing) || t->ready_queued) rc = -1;
            }
        } else if (t->state == TS_RUNNING) rc = -1;
        else if (t->state == TS_READY && !t->ready_queued) {
            uint32_t c = k32_rq_choose_locked(&runqueues, t->affinity_mask);
            if (c == K32_CPU_NONE || t != runqueues.cpu[c].idle) rc = -1;
        }
    }
    guard_leave(g);
    return rc;
}
/* Wakeup can mark a blocked outgoing thread READY but cannot enqueue the live
 * stack. Completion publishes it exactly once after CPU ownership is released. */
static void make_ready_locked(thread_t *t)
{
    t->state = TS_READY;
    if (t->on_cpu == K32_CPU_NONE && !t->ready_queued) {
        uint32_t c = k32_rq_choose_locked(&runqueues, t->affinity_mask);
        KASSERT(c != K32_CPU_NONE);
        if (t != runqueues.cpu[c].idle)
            KASSERT(k32_rq_enqueue_locked(&runqueues, t, c) == 0);
    }
}
/* Non-consuming observation used by production selection and publication tests. */
static thread_t *pick_next(void)
{
    k32_cpu_sched_t *c = cpu_context();
    if (!c) return 0;
    if (c->head) return c->head;
    if (c->current && (c->current->state == TS_RUNNING || c->current->state == TS_READY) && c->current != c->idle)
        return c->current;
    return c->idle;
}
/* IRQs are disabled. Outgoing stack ownership remains until the assembly hook. */
static void schedule(void)
{
    uint32_t ticket = k32_rq_lock(&runqueues), cpu = arch_cpu_id();
    KASSERT(k32_rq_cpu_online(&runqueues, cpu));
    k32_cpu_sched_t *c = &runqueues.cpu[cpu];
    thread_t *prev = c->current, *next = pick_next();
    KASSERT(prev && next && !c->outgoing);
    if (next == prev) {
        prev->state = TS_RUNNING;
        k32_rq_unlock(&runqueues, ticket);
        return;
    }
    if (next->ready_queued) KASSERT(k32_rq_remove_locked(&runqueues, next) == 0);
    KASSERT(next->on_cpu == K32_CPU_NONE);
    if (prev->state == TS_RUNNING) prev->state = TS_READY;
    next->state = TS_RUNNING;
    next->on_cpu = cpu;
    c->current = next;
    c->outgoing = prev;
    ++switches;
    k32_rq_unlock(&runqueues, ticket);
    tss_set_kernel_stack(next->stack_base + STACK_BYTES);
    const uint32_t pd = cpu ? 0 : proc_page_directory(next->proc), want = pd ? pd : kernel_space();
    if(cpu) KASSERT(next->native_tag==K32_AP_TAG && !next->proc);
    if (read_cr3() != want) write_cr3(want);
    switch_stacks(&prev->esp, next->esp);
}
void sched_switch_complete(void)
{
    /* Runs on destination stack before POPFD. No outgoing-stack local is used. */
    uint32_t ticket = k32_rq_lock(&runqueues), cpu = arch_cpu_id();
    KASSERT(k32_rq_cpu_online(&runqueues, cpu));
    k32_cpu_sched_t *c = &runqueues.cpu[cpu];
    thread_t *prev = c->outgoing;
    KASSERT(prev && prev != c->current && prev->on_cpu == cpu);
    c->outgoing = 0;
    prev->on_cpu = K32_CPU_NONE;
    if (prev->state == TS_READY) make_ready_locked(prev);
    k32_rq_unlock(&runqueues, ticket);
}
void sched_tick(void)
{
    /* BSP alone owns this UP clock. Unknown/unsupported IRQ owners fail closed. */
    if (arch_cpu_id() != 0 || !cpu_context()) return;
    sched_guard_t g = guard_enter();
    ++jiffies;
    thread_current()->run_ticks++;
    for (unsigned i = 0; i < MAX_THREADS; ++i) {
        thread_t *t = &threads[i];
        if (t->state == TS_BLOCKED && t->wake_tick && t->wake_tick <= jiffies) {
            t->wake_tick = 0;
            if (t->wait_sem) {
                ksem_t *s = t->wait_sem;
                thread_t **pp;
                for (pp = &s->waiters; *pp; pp = &(*pp)->next)
                    if (*pp == t) { *pp = t->next; break; }
                t->next = 0;
                t->wait_sem = 0;
                t->exit_code = -1;
            }
            make_ready_locked(t);
        }
    }
    k32_rq_unlock(&runqueues, g.ticket);
    schedule();
    irq_restore(g.flags);
}
static void thread_trampoline(void (*fn)(void *), void *arg)
{
    sti();
    fn(arg);
    thread_exit(0);
}
static thread_t *create_internal(const char *name, void (*fn)(void *), void *arg, unsigned cpu, int staged)
{
    sched_guard_t g = guard_enter();
    thread_t *t = 0;
    if (!cpu_context()) { guard_leave(g); return 0; }
    for (unsigned i = 0; i < MAX_THREADS; ++i)
        if (threads[i].state == TS_FREE) { t = &threads[i]; break; }
    if (!t) { guard_leave(g); return 0; }
    memset(t, 0, sizeof *t);
    t->state = TS_ALLOCATING;
    t->ready_cpu = t->on_cpu = K32_CPU_NONE;
    t->affinity_mask = 1u<<cpu;
    t->native_tag = staged ? K32_AP_TAG : 0;
    k32_rq_unlock(&runqueues, g.ticket);
    /* BSP stages allocation outside the scheduler ticket, before INIT. */
    uint32_t base = (uint32_t)kmalloc(STACK_BYTES);
    g.ticket = k32_rq_lock(&runqueues);
    if (!base) { t->state = TS_FREE; guard_leave(g); return 0; }
    t->stack_base = base;
    t->id = next_id++;
    for (unsigned k = 0; name[k] && k < sizeof t->name - 1; ++k) t->name[k] = name[k];
    uint32_t *sp = (uint32_t *)(base + STACK_BYTES);
    *--sp = (uint32_t)arg;
    *--sp = (uint32_t)fn;
    *--sp = 0;
    *--sp = (uint32_t)thread_trampoline;
    *--sp = 0x202;
    *--sp = 0; /* ebp */
    *--sp = 0; /* ebx */
    *--sp = 0; /* esi */
    *--sp = 0; /* edi */
    t->esp = (uint32_t)sp;
    if(!staged) make_ready_locked(t);
    guard_leave(g);
    return t;
}
thread_t *thread_create(const char *name, void (*fn)(void *), void *arg)
{
    if(arch_cpu_id()!=0 || k32_ap_active()) return 0;
    return create_internal(name,fn,arg,0,0);
}
void thread_yield(void)
{
    uint32_t f = irq_save();
    schedule();
    irq_restore(f);
}
void thread_exit(int code)
{
    sched_guard_t g = guard_enter();
    thread_t *t = thread_current();
    KASSERT(t);
    t->exit_code = code;
    t->state = TS_ZOMBIE;
    k32_rq_unlock(&runqueues, g.ticket);
    for (;;) { schedule(); cli(); }
}
int thread_join(thread_t *t)
{
    if(arch_cpu_id()!=0)k32_ap_fault(arch_cpu_id(),0x704);
    for (;;) {
        sched_guard_t g = guard_enter();
        KASSERT(k32_rq_valid(&runqueues, t) && t != thread_current());
        if (k32_rq_reapable_locked(&runqueues, t)) {
            int code = t->exit_code;
            uint32_t base = t->stack_base;
            t->state = TS_ALLOCATING; /* reserve until allocator released stack */
            k32_rq_unlock(&runqueues, g.ticket);
            kfree((void *)base);
            g.ticket = k32_rq_lock(&runqueues);
            memset(t, 0, sizeof *t);
            t->ready_cpu = t->on_cpu = K32_CPU_NONE;
            guard_leave(g);
            return code;
        }
        k32_rq_unlock(&runqueues, g.ticket);
        schedule();
        irq_restore(g.flags);
    }
}
void thread_sleep_ms(uint32_t ms)
{
    if(arch_cpu_id()!=0)k32_ap_fault(arch_cpu_id(),0x703);
    sched_guard_t g = guard_enter();
    thread_t *t = thread_current();
    KASSERT(t);
    t->wake_tick = shz_sched_finite_deadline_ms(jiffies, ms, TICK_US);
    t->state = TS_BLOCKED;
    k32_rq_unlock(&runqueues, g.ticket);
    schedule();
    irq_restore(g.flags);
}
void sem_init(ksem_t *s, int count) { if(arch_cpu_id()!=0)k32_ap_fault(arch_cpu_id(),0x705); s->count = count; s->waiters = 0; }
static int sem_wait_common(ksem_t *s, uint32_t ms)
{
    if(arch_cpu_id()!=0)k32_ap_fault(arch_cpu_id(),0x703);
    sched_guard_t g = guard_enter();
    thread_t *t = thread_current();
    KASSERT(t);
    if (s->count > 0) { --s->count; guard_leave(g); return 0; }
    t->next = 0;
    if (!s->waiters) s->waiters = t;
    else { thread_t *w = s->waiters; while (w->next) w = w->next; w->next = t; }
    t->wait_sem = s;
    t->wake_tick = ms ? shz_sched_finite_deadline_ms(jiffies, ms, TICK_US) : 0;
    t->exit_code = 0;
    t->state = TS_BLOCKED;
    k32_rq_unlock(&runqueues, g.ticket);
    schedule();
    g.ticket = k32_rq_lock(&runqueues);
    int rc = ms && t->exit_code == -1 ? -1 : 0;
    t->exit_code = 0;
    guard_leave(g);
    return rc;
}
void sem_wait(ksem_t *s) { sem_wait_common(s, 0); }
int sem_wait_timeout(ksem_t *s, uint32_t ms) { return sem_wait_common(s, ms ? ms : 1); }
void sem_post(ksem_t *s)
{
    if(arch_cpu_id()!=0)k32_ap_fault(arch_cpu_id(),0x703);
    sched_guard_t g = guard_enter();
    thread_t *w = s->waiters;
    if (w) {
        s->waiters = w->next;
        w->next = 0;
        w->wait_sem = 0;
        w->wake_tick = 0;
        make_ready_locked(w);
    } else ++s->count;
    guard_leave(g);
}
void mutex_init(kmutex_t *m) { if(arch_cpu_id()!=0)k32_ap_fault(arch_cpu_id(),0x706); m->locked = 0; m->owner = 0; m->waiters = 0; m->depth = 0; }
void mutex_lock(kmutex_t *m)
{
    if(arch_cpu_id()!=0)k32_ap_fault(arch_cpu_id(),0x703);
    for (;;) {
        sched_guard_t g = guard_enter();
        thread_t *t = thread_current();
        KASSERT(t);
        if (!m->locked) { m->locked = 1; m->owner = t; guard_leave(g); return; }
        KASSERT(m->owner != t);
        t->next = 0;
        if (!m->waiters) m->waiters = t;
        else { thread_t *w = m->waiters; while (w->next) w = w->next; w->next = t; }
        t->state = TS_BLOCKED;
        k32_rq_unlock(&runqueues, g.ticket);
        schedule();
        irq_restore(g.flags);
    }
}
void mutex_unlock(kmutex_t *m)
{
    if(arch_cpu_id()!=0)k32_ap_fault(arch_cpu_id(),0x703);
    sched_guard_t g = guard_enter();
    KASSERT(m->locked && m->owner == thread_current());
    m->locked = 0;
    m->owner = 0;
    thread_t *w = m->waiters;
    if (w) { m->waiters = w->next; w->next = 0; make_ready_locked(w); }
    guard_leave(g);
}
static void idle_loop(void *arg)
{
    (void)arg;
    for (;;) __asm__ volatile("sti; hlt");
}
void sched_init(void)
{
    KASSERT(arch_cpu_id() == 0);
    memset(threads, 0, sizeof threads);
    k32_rq_init(&runqueues, threads, MAX_THREADS, 1);
    for (unsigned i = 0; i < MAX_THREADS; ++i) threads[i].ready_cpu = threads[i].on_cpu = K32_CPU_NONE;
    thread_t *main = &threads[0];
    main->id = next_id++;
    main->state = TS_RUNNING;
    main->affinity_mask = 1;
    main->on_cpu = 0;
    main->name[0] = 'm'; main->name[1] = 'a'; main->name[2] = 'i'; main->name[3] = 'n';
    runqueues.cpu[0].current = main;
    thread_t *idle = thread_create("idle", idle_loop, 0);
    KASSERT(idle);
    sched_guard_t g = guard_enter();
    KASSERT(k32_rq_remove_locked(&runqueues, idle) == 0);
    runqueues.cpu[0].idle = idle;
    guard_leave(g);
}
void sched_start_idle(void) { }

/* Private native-only staged admission; public CPU registration stays closed. */
static void staged_idle(void *unused) { (void)unused; k32_ap_fault(arch_cpu_id(),0x701); }
int k32_ap_sched_prepare(unsigned cpu,void (*worker)(void *))
{
    if(arch_cpu_id()!=0 || (k32_flags()&0x200) || k32_ap_started() || !worker ||
       !cpu || cpu>=k32_ap_count() || cpu>=K32_AP_MAX || k32_ap_cpus[cpu].idle) return -1;
    k32_ap_cpu_t *c=&k32_ap_cpus[cpu];
    c->idle=create_internal("ap-idle",staged_idle,0,cpu,1);
    if(!c->idle)return -1;
    c->idle_base=c->idle->stack_base;
    for(unsigned i=0;i<2;i++) {
        c->worker[i]=create_internal("ap-worker",worker,(void *)(uintptr_t)(cpu*2+i),cpu,1);
        if(!c->worker[i])return -1;
    }
    return 0;
}
int k32_ap_sched_online(unsigned cpu,uint32_t esp)
{
    if(!cpu || cpu>=k32_ap_count() || cpu>=K32_AP_MAX || arch_cpu_id()!=cpu ||
       (k32_flags()&0x200) || !k32_ap_active() || !k32_ap_started() || !k32_ap_root_owned())return -1;
    k32_ap_cpu_t *ap=&k32_ap_cpus[cpu];uint32_t actual=k32_stack_pointer();
    if(ap->phase!=1 || esp<ap->idle_base || esp>=ap->idle_base+K32_AP_STACK ||
       actual<ap->idle_base || actual>=ap->idle_base+K32_AP_STACK)return -1;
    sched_guard_t g=guard_enter();k32_cpu_sched_t *c=&runqueues.cpu[cpu];int ok=1;
    thread_t *list[3]={ap->idle,ap->worker[0],ap->worker[1]};
    if(k32_rq_cpu_online(&runqueues,cpu) || c->current || c->idle || c->head || c->outgoing)ok=0;
    for(unsigned i=0;i<3;i++) {
        thread_t *t=list[i];
        if(!k32_rq_valid(&runqueues,t) || t->native_tag!=K32_AP_TAG || t->proc ||
           t->state!=TS_ALLOCATING || t->on_cpu!=K32_CPU_NONE || t->ready_queued ||
           t->affinity_mask!=(1u<<cpu))ok=0;
        for(unsigned j=0;j<i;j++)if(t==list[j])ok=0;
    }
    if(ok) {
        ap->idle_sp=actual;
        c->idle=c->current=ap->idle;ap->idle->state=TS_RUNNING;ap->idle->on_cpu=cpu;
        runqueues.online_mask|=1u<<cpu;
        for(unsigned i=0;i<2;i++)make_ready_locked(ap->worker[i]);
        __atomic_add_fetch(&ap->request,1,__ATOMIC_RELEASE);__atomic_store_n(&ap->phase,2,__ATOMIC_RELEASE);
    }
    guard_leave(g);return ok?0:-1;
}
void k32_ap_sched_tick(unsigned cpu,int ipi)
{
    if(!cpu || cpu!=arch_cpu_id() || cpu>=k32_ap_count() || !cpu_context()) return;
    sched_guard_t g=guard_enter();
    thread_t *t=thread_current();
    if(!t || t->native_tag!=K32_AP_TAG || t->proc) { guard_leave(g);k32_ap_fault(cpu,0x702); }
    if(!ipi)++t->run_ticks;
    else __atomic_store_n(&k32_ap_cpus[cpu].ack,__atomic_load_n(&k32_ap_cpus[cpu].request,__ATOMIC_ACQUIRE),__ATOMIC_RELEASE);
    k32_rq_unlock(&runqueues,g.ticket);schedule();irq_restore(g.flags);
}
int k32_ap_sched_terminal(unsigned cpu)
{
    if(!cpu || cpu>=k32_ap_count())return 0;
    sched_guard_t g=guard_enter();int ok=1;
    for(unsigned i=0;i<2;i++) {
        thread_t *t=k32_ap_cpus[cpu].worker[i];
        if(!k32_rq_reapable_locked(&runqueues,t))ok=0;
    }
    guard_leave(g);return ok;
}
int k32_ap_sched_withdraw(unsigned cpu,uint32_t esp)
{
    if(!cpu || cpu>=k32_ap_count() || arch_cpu_id()!=cpu || (k32_flags()&0x200) ||
       !k32_ap_active() || !k32_ap_started())return -1;
    k32_ap_cpu_t *ap=&k32_ap_cpus[cpu];const uint32_t actual=k32_stack_pointer();
    if(esp<ap->boot || esp>=ap->boot+K32_AP_STACK || actual<ap->boot ||
       actual>=ap->boot+K32_AP_STACK || ap->phase!=3)return -1;
    sched_guard_t g=guard_enter();k32_cpu_sched_t *c=&runqueues.cpu[cpu];int ok=0;
    if(k32_rq_cpu_online(&runqueues,cpu) && c->current==ap->idle && c->idle==ap->idle &&
       !c->outgoing && !c->head && ap->idle->on_cpu==cpu) {
        ok=1;for(unsigned i=0;i<2;i++)if(!k32_rq_reapable_locked(&runqueues,ap->worker[i]))ok=0;
        if(ok) {
            ap->idle->state=TS_ZOMBIE;ap->idle->on_cpu=K32_CPU_NONE;
            c->current=c->idle=0;runqueues.online_mask&=~(1u<<cpu);
            ap->withdraw_sp=actual;
            __atomic_store_n(&ap->withdrawn,1,__ATOMIC_RELEASE);
        }
    }
    guard_leave(g);return ok?0:-1;
}
int k32_ap_sched_discard(unsigned cpu)
{
    if(arch_cpu_id()!=0 || !cpu || cpu>=k32_ap_count())return -1;
    k32_ap_cpu_t *ap=&k32_ap_cpus[cpu];
    if(k32_ap_started() && !__atomic_load_n(&ap->withdrawn,__ATOMIC_ACQUIRE))return -1;
    thread_t *list[3]={ap->idle,ap->worker[0],ap->worker[1]};
    uint32_t bases[3]={0};sched_guard_t g=guard_enter();
    /* Validate the WHOLE set before changing any state or allocator account. */
    for(unsigned i=0;i<3;i++)if(list[i]) {
        thread_t *t=list[i];
        if(!k32_rq_valid(&runqueues,t) || t->native_tag!=K32_AP_TAG || t->on_cpu!=K32_CPU_NONE ||
           t->ready_queued || (t->state!=TS_ALLOCATING && t->state!=TS_ZOMBIE)) { guard_leave(g);return -1; }
        for(unsigned j=0;j<i;j++)if(t==list[j]) { guard_leave(g);return -1; }
        bases[i]=t->stack_base;
    }
    for(unsigned i=0;i<3;i++)if(list[i])list[i]->state=TS_ALLOCATING;
    k32_rq_unlock(&runqueues,g.ticket);
    for(unsigned i=0;i<3;i++)if(bases[i])kfree((void *)bases[i]);
    g.ticket=k32_rq_lock(&runqueues);
    for(unsigned i=0;i<3;i++)if(list[i]) {
        memset(list[i],0,sizeof *list[i]);list[i]->on_cpu=list[i]->ready_cpu=K32_CPU_NONE;
    }
    ap->idle=ap->worker[0]=ap->worker[1]=0;guard_leave(g);return 0;
}
