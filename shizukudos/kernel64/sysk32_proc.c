/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 support for kernel32 process, thread and memory information (system calls NtShzQueryK32 0x93 and NtShzSetK32 0x94,
 * routed through sysk32.c, plus NtGetContextThread). Everything reported here is measured by the kernel:
 *
 *  - CPU time: sched.c charges every 1 ms timer tick to the thread it interrupted, as user time when the tick came from ring 3
 *    and kernel time otherwise; cycles are TSC deltas between switching a thread in and out. A process adds up its live threads
 *    and the totals of the threads that already exited (thread_account_exit).
 *  - Working set: the present user pages of the address space (page-table walk). Private bytes: committed non-image memory of
 *    the descriptors. Both peaks are exact: a working set / commit only shrinks when memory is unmapped, and the value is
 *    measured right before every unmap (k32_before_unmap) and at every query, so no maximum is missed.
 *  - VirtualLock: pages are made present and recorded per process; freeing the memory unlocks them. Nothing is ever paged out
 *    by Kernel64, so a locked page stays resident as documented.
 *  - Process and module lists come from the process table and the loader's module list.
 */
#include "ipc.h"
#include "../kcommon/nt_sched_policy.h"

extern int64_t stack_arg(process_t *p, struct regs *r, unsigned n);
extern int64_t filetime_now(void);
extern int ldr_module_at(process_t *p, unsigned index, uint64_t *base, uint64_t *size, const char **name, const char **path);

#ifndef STATUS_NOT_LOCKED
#define STATUS_NOT_LOCKED ((int32_t)0xC000002A)
#endif
#ifndef STATUS_WORKING_SET_QUOTA
#define STATUS_WORKING_SET_QUOTA ((int32_t)0xC00000A1)
#endif

#define TICK_100NS ((uint64_t)TICK_US * 10u)

/* query classes (NtShzQueryK32) and set classes (NtShzSetK32); the same numbers are in win64/include/nt.h */
enum { K32Q_THREAD_TIMES = 1, K32Q_PROCESS_TIMES = 2, K32Q_PROCESS_INFO = 3, K32Q_PROCESS_LIST = 4, K32Q_MODULE_LIST = 5,
       K32Q_SYSTEM_PERF = 7, K32Q_PROCESS_MEMORY = 8, K32Q_WORKING_SET_EX = 9, K32Q_IMAGE_PATH = 10, K32Q_FIRMWARE = 11,
       K32Q_THREAD_SETTINGS = 12, K32Q_PROCESS_SETTINGS = 13, K32Q_CPU_CLOCK = 14, K32Q_SAME_OBJECT = 15, K32Q_THREAD_NAME = 16 };
enum { K32S_PRIORITY_CLASS = 1, K32S_THREAD_BOOST = 2, K32S_THREAD_MEM_PRIORITY = 3, K32S_DISCARD = 4, K32S_LOCK = 5,
       K32S_UNLOCK = 6, K32S_PREFETCH = 7, K32S_THREAD_POWER = 8, K32S_PROCESS_MEM_PRIORITY = 9, K32S_PROCESS_POWER = 10,
       K32S_SUSPEND_PROCESS = 11, K32S_RESUME_PROCESS = 12, K32S_THREAD_NAME = 13, K32S_PROCESS_AFFINITY = 14 };
#define THREAD_NAME_MAX_BYTES 65534u            /* SetThreadDescription: a UNICODE_STRING length (USHRT_MAX, as Windows/Wine bound it) */

/* FILETIME of a scheduler tick: the wall clock at the first query minus the ticks counted by then gives the boot instant once,
 * so a thread's creation or exit time reads the same on every query. */
static uint64_t prepare_time_epoch(void)
{
    static uint64_t boot_ft;
    static int initialized;
    uint64_t f = irq_save(), base = boot_ft;
    const int ready = initialized;
    irq_restore(f);
    if (!ready) {
        /* WALLTIME may hypercall. Prepare outside the snapshot/publication guard. */
        const uint64_t candidate = (uint64_t)filetime_now() - ticks_now() * TICK_100NS;
        f = irq_save();
        if (!initialized) { boot_ft = candidate; initialized = 1; }
        base = boot_ft;
        irq_restore(f);
    }
    return base;
}

static uint64_t tick_to_filetime(uint64_t tick)
{
    return prepare_time_epoch() + tick * TICK_100NS;
}

/* A zero alternative mask preserves the legacy settings query's access policy. */
static int32_t ref_query_object(process_t *cur, uint64_t h, uint32_t type, uint32_t alternatives, kobject_t **out)
{
    kobject_t *o;
    uint32_t access = 0;
    int32_t st = ipc_ref_handle(cur, h, type, &o, &access);
    if (st) return st;
    if (alternatives && !(access & alternatives)) { ob_deref(o); return STATUS_ACCESS_DENIED; }
    *out = o;
    return STATUS_SUCCESS;
}

static process_t *proc_of_handle(process_t *cur, uint64_t h)
{
    kobject_t *o;
    process_t *t;
    if (h == CURRENT_PROCESS_HANDLE) return cur;
    o = handle_lookup(cur, h, OB_PROCESS);
    if (!o) return 0;
    t = o->u.proc.p;
    return t && t->used && t->object == o ? t : 0;            /* the slot of a reaped process may already be reused */
}

/* ---------------------------------------------------------------- CPU accounting */
void thread_account_exit(thread_t *t)
{
    process_t *p = t->proc;
    /* The last thread of a process can be preempted between process_thread_gone() and thread_exit(); by then proc_wait() may
     * have released the process slot and a new process may own it: only charge the process the thread was created in. */
    if (!p || !p->used || !t->object || t->object->u.thr.pid != (uint64_t)p->pid) return;
    p->dead_user_ticks += t->user_ticks;
    p->dead_kernel_ticks += t->kernel_ticks;
    p->dead_cycles += t->cycles;
}

struct times { uint64_t create_ft, exit_ft, kernel_100ns, user_100ns, cycles; };

static int32_t thread_times(process_t *cur, uint64_t h, struct times *out, uint32_t *settings, uint32_t alternatives)
{
    thread_t *t = 0;
    kobject_t *o = 0;
    uint64_t f, create, exit_tick = 0, ut, kt, cyc;
    int32_t st = ref_query_object(cur, h, OB_THREAD, alternatives, &o);
    if (st) return st;
    f = irq_save();                                             /* an exited thread may be reclaimed at any preemption */
    t = o->u.thr.t;
    if (t && (t->object != o || t->state == TS_FREE)) {
        irq_restore(f); ob_deref(o); return STATUS_INVALID_HANDLE;
    }
    if (t) {
        create = t->create_tick; ut = t->user_ticks; kt = t->kernel_ticks; cyc = thread_cycles_now(t);
        if (t->state == TS_ZOMBIE) exit_tick = t->exit_tick;
        if (settings) { settings[0] = (uint32_t)t->boost_disabled; settings[1] = t->mem_priority; settings[2] = t->power_control;
                        settings[3] = t->power_state; }
    } else {
        create = o->u.thr.create_tick; ut = o->u.thr.user_ticks; kt = o->u.thr.kernel_ticks; cyc = o->u.thr.cycles;
        exit_tick = o->u.thr.exit_tick;
        if (settings) { settings[0] = 0; settings[1] = 5; settings[2] = 0; settings[3] = 0; }
    }
    irq_restore(f);
    ob_deref(o);
    if (out) {
        out->create_ft = tick_to_filetime(create);
        out->exit_ft = exit_tick ? tick_to_filetime(exit_tick) : 0;
        out->kernel_100ns = kt * TICK_100NS;
        out->user_100ns = ut * TICK_100NS;
        out->cycles = cyc;
    }
    return STATUS_SUCCESS;
}

static unsigned live_threads(process_t *p, uint64_t *ut, uint64_t *kt, uint64_t *cyc)
{
    unsigned i, n = 0;
    thread_t *t;
    const uint64_t f = irq_save();
    for (i = 0; (t = thread_slot(i)) != 0; ++i) {
        if (t->state == TS_FREE || t->state == TS_ZOMBIE || (p && t->proc != p)) continue;
        ++n;
        if (ut) { *ut += t->user_ticks; *kt += t->kernel_ticks; *cyc += thread_cycles_now(t); }
    }
    irq_restore(f);
    return n;
}

/* ---------------------------------------------------------------- memory statistics */
static uint64_t private_commit(process_t *p)
{
    uint64_t n = 0;
    unsigned i;
    for (i = 0; i < p->vads.count; ++i)
        if (p->vads.v[i].state == VAD_COMMITTED && p->vads.v[i].kind != VK_IMAGE) n += p->vads.v[i].end - p->vads.v[i].start;
    return n;
}

static uint64_t all_commit(process_t *p)
{
    uint64_t n = 0;
    unsigned i;
    for (i = 0; i < p->vads.count; ++i)
        if (p->vads.v[i].state == VAD_COMMITTED) n += p->vads.v[i].end - p->vads.v[i].start;
    return n;
}

static uint64_t g_peak_system_commit;

static uint64_t system_commit(void)
{
    uint64_t n = 0;
    unsigned i;
    process_t *q;
    for (i = 1; (q = process_slot(i)) != 0; ++i)
        if (q->used && !q->teardown && q->vads.v) n += all_commit(q);   /* a dead process still referenced by handles owns no memory */
    return n;
}

/* Interrupts off: descriptor arrays and page tables of any process may change under a preempted walk (another thread growing its
 * descriptor array, a process being torn down). The walks are short. */
static void sample_peaks(process_t *p)
{
    const uint64_t f = irq_save();
    const uint64_t ws = vm_count_user_pages(p->pml4), pc = private_commit(p), sc = system_commit();
    if (ws > p->peak_ws_pages) p->peak_ws_pages = ws;
    if (pc > p->peak_commit) p->peak_commit = pc;
    if (sc > g_peak_system_commit) g_peak_system_commit = sc;
    irq_restore(f);
}

/* NtQuerySystemInformation(SystemProcessInformation = 5): one SYSTEM_PROCESS_INFORMATION (0x100 bytes on x64) per live
 * process, followed by one SYSTEM_THREAD_INFORMATION (0x50 bytes) per live thread and the image name (UTF-16, NUL
 * terminated); NextEntryOffset chains them, 0 in the last. A buffer that is too small gets STATUS_INFO_LENGTH_MISMATCH
 * and the needed size in ReturnLength. Counters Kernel64 does not keep (I/O transfer counts, pool quotas) are 0. */
#define SPI_SIZE 0x100u
#define STI_SIZE 0x50u
static void put32(uint8_t *b, unsigned off, uint32_t v) { memcpy(b + off, &v, 4); }
static void put64v(uint8_t *b, unsigned off, uint64_t v) { memcpy(b + off, &v, 8); }

static uint32_t spi_entry_size(process_t *q, unsigned threads)
{
    return (uint32_t)((SPI_SIZE + threads * STI_SIZE + (strlen(q->name) + 1) * 2 + 7) & ~7u);
}

int32_t k32_system_process_information(process_t *cur, uint64_t buf, uint64_t len, uint64_t retlen)
{
    enum { MAXP = 64 };
    process_t *list[MAXP];
    unsigned counts[MAXP];
    unsigned i, n = 0, k;
    uint64_t need = 0, off = 0, largest = 0;
    process_t *q;
    uint8_t *e;
    int32_t st = STATUS_SUCCESS;
    for (i = 1; (q = process_slot(i)) != 0 && n < MAXP; ++i) {
        if (!q->used || q->teardown || q->threads_alive <= 0) continue;
        list[n] = q;
        counts[n] = live_threads(q, 0, 0, 0);
        need += spi_entry_size(q, counts[n]);
        if (spi_entry_size(q, counts[n]) > largest) largest = spi_entry_size(q, counts[n]);
        ++n;
    }
    if (retlen) { uint32_t rl = (uint32_t)need; if (copy_to_user(cur, retlen, &rl, 4)) return STATUS_ACCESS_VIOLATION; }
    if (len < need || !n) return n ? (int32_t)0xC0000004 : STATUS_SUCCESS;          /* STATUS_INFO_LENGTH_MISMATCH */
    e = kmalloc(largest);
    if (!e) return STATUS_NO_MEMORY;
    for (k = 0; k < n && !st; ++k) {
        uint64_t ut = 0, kt = 0, cyc = 0, f;
        unsigned t_i, nt = 0;
        const uint32_t size = spi_entry_size(list[k], counts[k]);
        thread_t *t;
        q = list[k];
        memset(e, 0, size);
        f = irq_save();                                     /* thread slots change under preemption: one consistent pass */
        for (t_i = 0; (t = thread_slot(t_i)) != 0 && nt < counts[k]; ++t_i) {
            uint8_t *ti = e + SPI_SIZE + nt * STI_SIZE;
            uint32_t state, reason = 0;
            if (t->proc != q || t->state == TS_FREE || t->state == TS_ZOMBIE) continue;
            ut += t->user_ticks; kt += t->kernel_ticks; cyc += thread_cycles_now(t);
            put64v(ti, 0x00, t->kernel_ticks * TICK_100NS);
            put64v(ti, 0x08, t->user_ticks * TICK_100NS);
            put64v(ti, 0x10, tick_to_filetime(t->create_tick));
            put64v(ti, 0x20, t->user_rip);                  /* StartAddress: the thread's initial user RIP */
            put64v(ti, 0x28, (uint64_t)q->pid);
            put64v(ti, 0x30, t->tid);
            put32(ti, 0x38, 8); put32(ti, 0x3c, 8);         /* Priority, BasePriority: normal */
            /* KTHREAD_STATE: 1 Ready, 2 Running, 5 Waiting, 0 Initialized; KWAIT_REASON 5 Suspended, 6 UserRequest */
            if (t->state == TS_RUNNING) state = 2;
            else if (t->state == TS_READY) state = 1;
            else if (t->state == TS_NEW) state = 0;
            else { state = 5; reason = t->suspended ? 5 : 6; }
            put32(ti, 0x44, state);
            put32(ti, 0x48, reason);
            ++nt;
        }
        irq_restore(f);
        ut += q->dead_user_ticks; kt += q->dead_kernel_ticks; cyc += q->dead_cycles;
        put32(e, 0x00, k + 1 < n ? size : 0);
        put32(e, 0x04, nt);
        put64v(e, 0x18, cyc);
        put64v(e, 0x20, tick_to_filetime(q->create_tick));
        put64v(e, 0x28, ut * TICK_100NS);
        put64v(e, 0x30, kt * TICK_100NS);
        {
            const size_t nl = strlen(q->name);
            uint8_t *name = e + SPI_SIZE + nt * STI_SIZE;
            size_t c;
            for (c = 0; c < nl; ++c) { name[c * 2] = (uint8_t)q->name[c]; name[c * 2 + 1] = 0; }
            *(uint16_t *)(e + 0x38) = (uint16_t)(nl * 2);
            *(uint16_t *)(e + 0x3a) = (uint16_t)(nl * 2 + 2);
            put64v(e, 0x40, buf + off + SPI_SIZE + nt * STI_SIZE);
        }
        put32(e, 0x48, 8);                                  /* BasePriority */
        put64v(e, 0x50, (uint64_t)q->pid);
        put64v(e, 0x58, q->parent_pid);
        put32(e, 0x60, q->handle_count);
        put32(e, 0x64, 1);                                  /* SessionId: the interactive session (token.c reports 1) */
        put64v(e, 0x68, (uint64_t)q->pid);                  /* UniqueProcessKey */
        {
            const uint64_t ws = vm_count_user_pages(q->pml4) * PAGE_SIZE;
            const uint64_t commit = private_commit(q) * PAGE_SIZE;
            put64v(e, 0x70, commit); put64v(e, 0x78, commit);   /* Peak/VirtualSize: committed private memory */
            put32(e, 0x80, (uint32_t)q->page_faults);
            put64v(e, 0x88, q->peak_ws_pages * PAGE_SIZE > ws ? q->peak_ws_pages * PAGE_SIZE : ws);
            put64v(e, 0x90, ws);
            put64v(e, 0xb8, commit); put64v(e, 0xc0, q->peak_commit * PAGE_SIZE > commit ? q->peak_commit * PAGE_SIZE : commit);
            put64v(e, 0xc8, commit);
        }
        if (copy_to_user(cur, buf + off, e, size)) st = STATUS_ACCESS_VIOLATION;
        off += size;
    }
    kfree(e);
    return st;
}

/* VirtualLock records: one entry per locked page. The table comes from the kernel heap on the first VirtualLock (it is not
 * part of .bss, which must stay small: link.ld), so systems that never lock memory do not pay for it. */
#define MAX_VLOCKS 2048
typedef struct { const process_t *p; int pid; uint64_t page; } vlock_t;                   /* p == 0: free */
static vlock_t *vlocks;

static int vlock_find(const process_t *p, uint64_t page)
{
    int i;
    if (!vlocks) return -1;
    for (i = 0; i < MAX_VLOCKS; ++i)
        if (vlocks[i].p == p && vlocks[i].pid == p->pid && vlocks[i].page == page) return i;
    return -1;
}

static void vlocks_drop(const process_t *p, uint64_t start, uint64_t end)
{
    int i;
    if (!vlocks) return;
    for (i = 0; i < MAX_VLOCKS; ++i)
        if (vlocks[i].p == p && (vlocks[i].pid != p->pid || (vlocks[i].page >= start && vlocks[i].page < end))) vlocks[i].p = 0;
}

void k32_before_unmap(process_t *p, uint64_t start, uint64_t end, int released)
{
    sample_peaks(p);
    if (released) vlocks_drop(p, start, end);
}

static int32_t range_committed(process_t *p, uint64_t start, uint64_t end, int need_access)
{
    uint64_t a = start;
    while (a < end) {
        vad_t *v = vad_find(p, a);
        if (!v || v->state != VAD_COMMITTED) return STATUS_INVALID_PARAMETER;
        if (need_access && ((v->prot & 0xff) == PAGE_NOACCESS || (v->prot & 0x100))) return STATUS_ACCESS_VIOLATION;
        a = v->end;
    }
    return STATUS_SUCCESS;
}

static int32_t mem_op(process_t *p, uint32_t cls, uint64_t base, uint64_t size)
{
    const uint64_t start = base & ~(PAGE_SIZE - 1), end = (base + size + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);
    uint64_t a;
    int32_t st;
    if (!size || end <= start || start < USER_MIN || end > USER_TOP) return STATUS_INVALID_PARAMETER;
    switch (cls) {
    case K32S_DISCARD:                                          /* contents become undefined: the pages go, the commitment stays */
        st = range_committed(p, start, end, 0);
        if (st) return st;
        sample_peaks(p);
        vlocks_drop(p, start, end);
        for (a = start; a < end; a += PAGE_SIZE) {
            uint64_t pa;
            if (vm_unmap(p->pml4, a, &pa) == 0) pmm_free(pa);
        }
        return STATUS_SUCCESS;
    case K32S_PREFETCH:                                         /* bring committed, accessible pages in; skip everything else */
        for (a = start; a < end; a += PAGE_SIZE) {
            vad_t *v = vad_find(p, a);
            if (v && v->state == VAD_COMMITTED && (v->prot & 0xff) != PAGE_NOACCESS && !(v->prot & 0x100))
                user_fault_in(p, a, 0, 0);
        }
        return STATUS_SUCCESS;
    case K32S_LOCK: {
        unsigned need = 0, free_slots = 0;
        int i;
        st = range_committed(p, start, end, 1);
        if (st) return st;
        if (!vlocks) {
            vlock_t *t = kzalloc(MAX_VLOCKS * sizeof *t);
            if (!t) return STATUS_NO_MEMORY;
            if (vlocks) kfree(t); else vlocks = t;                  /* another thread may have won the race meanwhile */
        }
        for (a = start; a < end; a += PAGE_SIZE) if (vlock_find(p, a) < 0) ++need;
        for (i = 0; i < MAX_VLOCKS; ++i) if (!vlocks[i].p) ++free_slots;
        if (need > free_slots) return STATUS_WORKING_SET_QUOTA;
        for (a = start; a < end; a += PAGE_SIZE) {
            if (user_fault_in(p, a, 0, 0)) return STATUS_NO_MEMORY;
            if (vlock_find(p, a) >= 0) continue;
            for (i = 0; i < MAX_VLOCKS && vlocks[i].p; ++i) { }
            vlocks[i].p = p; vlocks[i].pid = p->pid; vlocks[i].page = a;
        }
        return STATUS_SUCCESS;
    }
    case K32S_UNLOCK:
        for (a = start; a < end; a += PAGE_SIZE)
            if (vlock_find(p, a) < 0) return STATUS_NOT_LOCKED;
        for (a = start; a < end; a += PAGE_SIZE) vlocks[vlock_find(p, a)].p = 0;
        return STATUS_SUCCESS;
    default:
        return STATUS_INVALID_PARAMETER;
    }
}

/* ---------------------------------------------------------------- queries */
struct proc_entry { uint32_t pid, ppid, threads, priority_class; char name[32]; };
struct mod_entry { uint64_t base, size; char name[48]; char path[128]; };

static void copy_str(char *dst, const char *src, unsigned cap)
{
    unsigned i;
    for (i = 0; src[i] && i + 1 < cap; ++i) dst[i] = src[i];
    dst[i] = 0;
}

static int32_t put_out(process_t *cur, uint64_t buf, uint64_t len, uint64_t retlen, const void *v, uint64_t n)
{
    if (retlen) { uint32_t r = (uint32_t)n; if (copy_to_user(cur, retlen, &r, 4)) return STATUS_ACCESS_VIOLATION; }
    if (len < n) return STATUS_BUFFER_TOO_SMALL;
    return copy_to_user(cur, buf, v, n) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}

/* The index-th module of p copied out with interrupts off: the loader records of another process are freed when that process
 * is reaped (ldr_release_modules), which can happen at any preemption of the caller. 0 = copied, -1 = no such module. */
static int module_copy(process_t *p, unsigned index, struct mod_entry *e)
{
    uint64_t base, size;
    const char *name, *path;
    const uint64_t f = irq_save();
    int rc = p->used ? ldr_module_at(p, index, &base, &size, &name, &path) : -1;
    if (!rc) {
        memset(e, 0, sizeof *e);
        e->base = base; e->size = size;
        copy_str(e->name, name, sizeof e->name);
        copy_str(e->path, path, sizeof e->path);
    }
    irq_restore(f);
    return rc;
}

static int32_t query_modules(process_t *cur, process_t *p, uint64_t buf, uint64_t len, uint64_t retlen)
{
    unsigned count = 0, i, k;
    struct mod_entry e;
    while (module_copy(p, count, &e) == 0) ++count;
    if (retlen) { uint32_t r = count * (uint32_t)sizeof e; if (copy_to_user(cur, retlen, &r, 4)) return STATUS_ACCESS_VIOLATION; }
    if (len < count * sizeof e) return STATUS_BUFFER_TOO_SMALL;
    /* the executable first (as in the PEB load-order list), then the others in load order */
    for (i = 0, k = 0; i < count; ++i) {
        if (module_copy(p, i, &e)) break;
        if (e.base != p->image_base) continue;
        if (copy_to_user(cur, buf + (uint64_t)k++ * sizeof e, &e, sizeof e)) return STATUS_ACCESS_VIOLATION;
    }
    for (i = 0; i < count; ++i) {
        if (module_copy(p, i, &e)) break;
        if (e.base == p->image_base) continue;
        if (copy_to_user(cur, buf + (uint64_t)k++ * sizeof e, &e, sizeof e)) return STATUS_ACCESS_VIOLATION;
    }
    return STATUS_SUCCESS;
}

/* NtShzQueryK32(ULONG class, HANDLE handle, PVOID buffer, ULONG length, PULONG return_length) */
int32_t k32_query(process_t *cur, struct regs *r, uint64_t cls, uint64_t h, uint64_t buf, uint64_t len)
{
    const uint64_t retlen = (uint64_t)stack_arg(cur, r, 5);
    switch (cls) {
    case K32Q_THREAD_TIMES: {
        struct times t;
        int32_t st = thread_times(cur, h, &t, 0, THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION);
        return st ? st : put_out(cur, buf, len, retlen, &t, sizeof t);
    }
    case K32Q_THREAD_SETTINGS: {
        uint32_t s[4];
        int32_t st = thread_times(cur, h, 0, s, 0);
        return st ? st : put_out(cur, buf, len, retlen, s, sizeof s);
    }
    case K32Q_PROCESS_TIMES: {
        process_t *p;
        kobject_t *o;
        struct times t;
        uint64_t ut, kt, cyc, create, exit_tick, f;
        int32_t st = ref_query_object(cur, h, OB_PROCESS, PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, &o);
        if (st) return st;
        f = irq_save();
        p = o->u.proc.p;
        if (!p || !p->used || p->object != o) {
            irq_restore(f); ob_deref(o); return STATUS_INVALID_HANDLE;
        }
        ut = p->dead_user_ticks; kt = p->dead_kernel_ticks; cyc = p->dead_cycles;
        live_threads(p, &ut, &kt, &cyc);
        create = p->create_tick;
        exit_tick = p->terminated ? p->exit_tick : 0;
        irq_restore(f);
        ob_deref(o);
        t.create_ft = tick_to_filetime(create);
        t.exit_ft = exit_tick ? tick_to_filetime(exit_tick) : 0;
        t.kernel_100ns = kt * TICK_100NS; t.user_100ns = ut * TICK_100NS; t.cycles = cyc;
        return put_out(cur, buf, len, retlen, &t, sizeof t);
    }
    case K32Q_PROCESS_INFO: {                                   /* {handles, threads, pid, ppid, priority class, reserved} */
        process_t *p;
        kobject_t *o;
        uint32_t v[6];
        int32_t st = ref_query_object(cur, h, OB_PROCESS, PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, &o);
        uint64_t f;
        if (st) return st;
        f = irq_save();
        p = o->u.proc.p;
        if (!p || !p->used || p->object != o) {
            irq_restore(f); ob_deref(o); return STATUS_INVALID_HANDLE;
        }
        v[0] = p->handle_count; v[1] = live_threads(p, 0, 0, 0); v[2] = (uint32_t)p->pid; v[3] = (uint32_t)p->parent_pid;
        v[4] = p->priority_class ? p->priority_class : 0x20; v[5] = 0;
        irq_restore(f);
        ob_deref(o);
        return put_out(cur, buf, len, retlen, v, sizeof v);
    }
    case K32Q_PROCESS_SETTINGS: {                               /* {memory priority, power throttling control, state} */
        process_t *p = proc_of_handle(cur, h);
        uint32_t v[3];
        if (!p) return STATUS_INVALID_HANDLE;
        v[0] = p->mem_priority ? p->mem_priority : 5; v[1] = p->power_control; v[2] = p->power_state;
        return put_out(cur, buf, len, retlen, v, sizeof v);
    }
    case K32Q_PROCESS_LIST: {
        unsigned i, n = 0;
        process_t *q;
        struct proc_entry e;
        for (i = 1; (q = process_slot(i)) != 0; ++i) if (q->used && !q->terminated) ++n;
        if (retlen) { uint32_t rl = n * (uint32_t)sizeof e; if (copy_to_user(cur, retlen, &rl, 4)) return STATUS_ACCESS_VIOLATION; }
        if (len < n * sizeof e) return STATUS_BUFFER_TOO_SMALL;
        for (i = 1, n = 0; (q = process_slot(i)) != 0; ++i) {
            if (!q->used || q->terminated) continue;
            memset(&e, 0, sizeof e);
            e.pid = (uint32_t)q->pid; e.ppid = (uint32_t)q->parent_pid; e.threads = live_threads(q, 0, 0, 0);
            e.priority_class = q->priority_class ? q->priority_class : 0x20;
            copy_str(e.name, q->name, sizeof e.name);
            if (copy_to_user(cur, buf + (uint64_t)n++ * sizeof e, &e, sizeof e)) return STATUS_ACCESS_VIOLATION;
        }
        return STATUS_SUCCESS;
    }
    case K32Q_MODULE_LIST: {                                    /* handle = process id, 0 = the caller */
        process_t *p = h ? process_by_pid((int)h) : cur;
        if (!p || p->terminated) return STATUS_INVALID_CID;
        return query_modules(cur, p, buf, len, retlen);
    }
    case K32Q_SYSTEM_PERF: {
        struct { uint64_t total_pages, free_pages, commit_bytes, peak_commit_bytes, kheap_total, kheap_used;
                 uint32_t processes, threads, handles, pad; } s;
        unsigned i;
        process_t *q;
        uint64_t f;
        memset(&s, 0, sizeof s);
        /* PhysicalTotal: the RAM the machine has, as GlobalMemoryStatusEx reports it (NtQuerySystemInformation 0x100), not
         * only the page allocator's pool (which starts above the kernel image and heap) */
        s.total_pages = mem_ram_top() / 4096; s.free_pages = pmm_free_count();
        f = irq_save();
        s.commit_bytes = system_commit();
        irq_restore(f);
        if (s.commit_bytes > g_peak_system_commit) g_peak_system_commit = s.commit_bytes;
        s.peak_commit_bytes = g_peak_system_commit;
        s.kheap_total = kheap_total(); s.kheap_used = kheap_used();
        for (i = 1; (q = process_slot(i)) != 0; ++i)
            if (q->used && !q->terminated) { ++s.processes; s.handles += q->handle_count; }
        s.threads = live_threads(0, 0, 0, 0);
        return put_out(cur, buf, len, retlen, &s, sizeof s);
    }
    case K32Q_PROCESS_MEMORY: {
        process_t *p = proc_of_handle(cur, h);
        uint64_t m[5], f;
        if (!p) return STATUS_INVALID_HANDLE;
        sample_peaks(p);
        f = irq_save();
        m[0] = p->page_faults; m[1] = vm_count_user_pages(p->pml4) * PAGE_SIZE; m[2] = p->peak_ws_pages * PAGE_SIZE;
        m[3] = private_commit(p); m[4] = p->peak_commit;
        irq_restore(f);
        return put_out(cur, buf, len, retlen, m, sizeof m);
    }
    case K32Q_WORKING_SET_EX: {                                 /* in/out array of {VirtualAddress, attributes} */
        process_t *p = proc_of_handle(cur, h);
        uint64_t n = len / 16, i;
        if (!p) return STATUS_INVALID_HANDLE;
        if (!n || len % 16) return STATUS_INFO_LENGTH_MISMATCH;
        for (i = 0; i < n; ++i) {
            uint64_t e[2], flags = 0;
            vad_t *v;
            if (copy_from_user(cur, e, buf + i * 16, 16)) return STATUS_ACCESS_VIOLATION;
            e[1] = 0;
            v = e[0] < USER_TOP ? vad_find(p, e[0] & ~(PAGE_SIZE - 1)) : 0;
            if (v && vm_lookup(p->pml4, e[0], &flags) && (flags & PT_U)) {
                e[1] = 1ull                                        /* Valid */
                     | (1ull << 1)                                 /* ShareCount 1: only this process maps the page */
                     | ((uint64_t)(v->prot & 0x7ff) << 4);         /* Win32Protection */
                if (vlock_find(p, e[0] & ~(PAGE_SIZE - 1)) >= 0) e[1] |= 1ull << 22;       /* Locked */
            }
            if (copy_to_user(cur, buf + i * 16, e, 16)) return STATUS_ACCESS_VIOLATION;
        }
        if (retlen) { uint32_t rl = (uint32_t)len; copy_to_user(cur, retlen, &rl, 4); }
        return STATUS_SUCCESS;
    }
    case K32Q_IMAGE_PATH: {                                     /* the executable's path: "\SHZ\TESTS\T_X.EXE" (C:) or "D:\..." */
        process_t *p = proc_of_handle(cur, h);
        unsigned i;
        struct mod_entry e;
        if (!p) return STATUS_INVALID_HANDLE;
        for (i = 0; module_copy(p, i, &e) == 0; ++i)
            if (e.base == p->image_base) return put_out(cur, buf, len, retlen, e.path, strlen(e.path) + 1);
        return STATUS_INVALID_HANDLE;                             /* not a Win64 process (no executable image) */
    }
    case K32Q_THREAD_NAME: {                                    /* GetThreadDescription: the UTF-16 text, ReturnLength = its bytes (0: none) */
        thread_t *t = 0;
        kobject_t *o = 0;
        uint16_t *copy = 0;
        uint32_t bytes = 0;
        uint64_t f;
        int32_t st;
        if (h == CURRENT_THREAD_HANDLE) t = thread_current();
        else if (!(o = handle_lookup(cur, h, OB_THREAD))) return STATUS_INVALID_HANDLE;
        f = irq_save();                                         /* the owner may replace or free the text at any preemption */
        if (o) t = o->u.thr.t;
        if (t && t->desc && t->desc_bytes) {
            copy = kmalloc(t->desc_bytes);
            if (copy) { memcpy(copy, t->desc, t->desc_bytes); bytes = t->desc_bytes; }
        }
        irq_restore(f);
        if (t && t->desc_bytes && !copy) return STATUS_NO_MEMORY;
        st = put_out(cur, buf, len, retlen, copy, bytes);
        kfree(copy);
        return st;
    }
    case K32Q_SAME_OBJECT: {                                    /* CompareObjectHandles (NtCompareObjects) */
        uint64_t h2 = 0;
        kobject_t *o1 = 0, *o2 = 0;
        int32_t st;
        if (len < 8 || copy_from_user(cur, &h2, buf, 8)) return STATUS_ACCESS_VIOLATION;
        if (h == CURRENT_PROCESS_HANDLE) { o1 = cur->object; ob_ref(o1); }
        else if (h == CURRENT_THREAD_HANDLE) { o1 = thread_current()->object; ob_ref(o1); }
        else if ((st = handle_ref(cur, h, 0, &o1, 0))) return st;
        if (h2 == CURRENT_PROCESS_HANDLE) { o2 = cur->object; ob_ref(o2); }
        else if (h2 == CURRENT_THREAD_HANDLE) { o2 = thread_current()->object; ob_ref(o2); }
        else if ((st = handle_ref(cur, h2, 0, &o2, 0))) { ob_deref(o1); return st; }
        st = o1 == o2 ? STATUS_SUCCESS : (int32_t)0xC00001AC;     /* STATUS_NOT_SAME_OBJECT */
        ob_deref(o1);
        ob_deref(o2);
        return st;
    }
    case K32Q_CPU_CLOCK: {
        /* ULONG64 time-stamp counter rate in Hz, measured once against the scheduler tick over 50 ms (the boot stub's value is
         * only nominal). The processor's own clock is not known to the kernel; the TSC rate is its best available measure. */
        static uint64_t hz;
        if (!hz) {
            uint64_t t0, t1, k0, k1;
            uint32_t lo, hi;
            k0 = ticks_now();
            while (ticks_now() == k0) thread_yield();           /* start on a tick boundary */
            k0 = ticks_now();
            __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); t0 = ((uint64_t)hi << 32) | lo;
            thread_sleep_ms(50);
            k1 = ticks_now();
            __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi)); t1 = ((uint64_t)hi << 32) | lo;
            if (k1 > k0) hz = (t1 - t0) * 1000000ull / ((k1 - k0) * TICK_US);
        }
        if (!hz) return STATUS_NOT_SUPPORTED;
        return put_out(cur, buf, len, retlen, &hz, sizeof hz);
    }
    case K32Q_FIRMWARE: {
        /* Kernel64 is started by the Supervisor or by a boot stub; neither reports which firmware interface (BIOS or UEFI) the
         * machine has, so the honest answer is FirmwareTypeUnknown (0). */
        const uint32_t v = 0;
        return put_out(cur, buf, len, retlen, &v, sizeof v);
    }
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
}

/* Retarget published user threads, including initialized TS_NEW threads.
 * The bounded native slot table and the entire two-pass operation share one
 * IRQ guard: every possible refusal precedes the first policy mutation. */
int32_t ipc_set_process_priority_class(process_t *p, kobject_t *o, uint32_t cls)
{
    uint64_t f;
    unsigned pass, i;
    thread_t *t;
    int32_t st;
    shz_nt_sched_projection_t projection;
    shz_nt_sched_result_t result;
    sched_policy_t policy;
    result = shz_nt_sched_from_win32(cls, 0, &projection);
    if (result != SHZ_NT_SCHED_OK) {
        return result == SHZ_NT_SCHED_UNSUPPORTED ? STATUS_NOT_SUPPORTED : STATUS_INVALID_PARAMETER;
    }
    f = irq_save();
    if (!p || !o || o->type != OB_PROCESS || o->u.proc.p != p ||
        !p->used || p->object != o || p->terminated || p->teardown || p->exit_owner) {
        st = STATUS_PROCESS_IS_TERMINATING;
        goto out;
    }
    for (pass = 0; pass < 2; ++pass) {
        for (i = 0; (t = thread_slot(i)) != 0; ++i) {
            kobject_t *to = t->object;
            if (t->proc != p || !to || to->type != OB_THREAD || to->u.thr.t != t ||
                to->u.thr.pid != (uint64_t)p->pid || t->state == TS_FREE || t->state == TS_ZOMBIE || thread_must_die(t))
                continue;                        /* kernel, unpublished, foreign or terminating thread */
            result = shz_nt_sched_from_base_increment(cls, to->u.thr.nt_base_increment, &projection);
            if (result != SHZ_NT_SCHED_OK || thread_get_sched_policy(t, &policy) ||
                policy.priority >= SCHED_PRIORITY_LEVELS || !policy.quantum_ticks ||
                policy.quantum_ticks > SCHED_MAX_QUANTUM_TICKS || policy.cpu_mask != 1) {
                st = result == SHZ_NT_SCHED_UNSUPPORTED ? STATUS_NOT_SUPPORTED : STATUS_INVALID_PARAMETER;
                goto out;
            }
            if (pass) {
                /* Pass 0 proves these native user TCBs are valid and their
                 * quantum/mask are supported. IRQ exclusion keeps those
                 * preconditions stable; the native setter cannot refuse. */
                (void)thread_set_sched_policy(t, projection.absolute_priority, policy.quantum_ticks, policy.cpu_mask);
                to->u.thr.last_sched_priority = projection.absolute_priority;
            }
        }
    }
    p->priority_class = cls;
    st = STATUS_SUCCESS;
out:
    irq_restore(f);
    return st;
}

static int32_t set_process_priority_class(process_t *cur, uint64_t h, uint64_t buf, uint64_t len)
{
    process_t *p;
    kobject_t *o;
    uint32_t cls;
    int32_t st;
    if (len != sizeof cls) return STATUS_INFO_LENGTH_MISMATCH;
    st = ipc_ref_process(cur, h, PROCESS_SET_INFORMATION, &p, &o);
    if (st) return st;
    st = copy_from_user(cur, &cls, buf, sizeof cls) ? STATUS_ACCESS_VIOLATION :
         ipc_set_process_priority_class(p, o, cls);
    ob_deref(o);
    return st;
}

/* CPU0 is the immutable affinity of every existing and future user thread.
 * Accept its idempotent setting with SET rights; no wider CPU mask is supported. */
static int32_t set_process_affinity_mask(process_t *cur, uint64_t h, uint64_t buf, uint64_t len)
{
    process_t *p;
    kobject_t *o;
    uint64_t mask, f;
    int32_t st;
    if (len != sizeof mask) return STATUS_INFO_LENGTH_MISMATCH;
    st = ipc_ref_process(cur, h, PROCESS_SET_INFORMATION, &p, &o);
    if (st) return st;
    if (copy_from_user(cur, &mask, buf, sizeof mask)) { ob_deref(o); return STATUS_ACCESS_VIOLATION; }
    if (mask != 1) { ob_deref(o); return STATUS_INVALID_PARAMETER; }
    f = irq_save();
    if (!p || !p->used || p->object != o || o->u.proc.p != p) st = STATUS_INVALID_HANDLE;
    else if (p->terminated || p->teardown || p->exit_owner) st = STATUS_PROCESS_IS_TERMINATING;
    else st = STATUS_SUCCESS;
    irq_restore(f);
    ob_deref(o);
    return st;
}

/* NtShzSetK32(ULONG class, HANDLE handle, PVOID buffer, ULONG length) */
int32_t k32_set(process_t *cur, uint64_t cls, uint64_t h, uint64_t buf, uint64_t len)
{
    switch (cls) {
    case K32S_SUSPEND_PROCESS: case K32S_RESUME_PROCESS: {
        /* NtSuspendProcess / NtResumeProcess: every thread's suspend count moves by one, as NtSuspendThread/NtResumeThread
         * (ipc_proc.c) move one thread's: a suspended thread stops at its next return to user mode (check_kill), the
         * caller's own thread when it leaves this call. */
        process_t *p = proc_of_handle(cur, h);
        thread_t *t;
        unsigned i;
        uint64_t f;
        (void)buf; (void)len;
        if (!p) return STATUS_INVALID_HANDLE;
        if (p->terminated || p->teardown) return STATUS_PROCESS_IS_TERMINATING;
        f = irq_save();
        for (i = 0; (t = thread_slot(i)) != 0; ++i) {
            if (t->proc != p || t->state == TS_FREE || t->state == TS_ZOMBIE || thread_must_die(t)) continue;
            if (cls == K32S_SUSPEND_PROCESS) { if (t->suspend_count < 127) ++t->suspend_count; }
            else if (t->suspend_count > 0 && --t->suspend_count == 0) {
                if (t->state == TS_NEW) thread_resume(t);
                else if (t->state == TS_BLOCKED && t->suspended) thread_wake(t);
            }
        }
        irq_restore(f);
        return STATUS_SUCCESS;
    }
    case K32S_PRIORITY_CLASS: return set_process_priority_class(cur, h, buf, len);
    case K32S_PROCESS_AFFINITY: return set_process_affinity_mask(cur, h, buf, len);
    case K32S_PROCESS_MEM_PRIORITY: case K32S_PROCESS_POWER: {
        process_t *p = proc_of_handle(cur, h);
        uint32_t v[2] = { 0, 0 };
        if (!p) return STATUS_INVALID_HANDLE;
        if (len < (cls == K32S_PROCESS_POWER ? 8u : 4u) || copy_from_user(cur, v, buf, cls == K32S_PROCESS_POWER ? 8 : 4))
            return STATUS_ACCESS_VIOLATION;
        if (cls == K32S_PROCESS_MEM_PRIORITY) {
            if (v[0] < 1 || v[0] > 5) return STATUS_INVALID_PARAMETER;
            p->mem_priority = v[0];
        } else {
            p->power_control = v[0]; p->power_state = v[1];
        }
        return STATUS_SUCCESS;
    }
    case K32S_THREAD_BOOST: case K32S_THREAD_MEM_PRIORITY: case K32S_THREAD_POWER: {
        thread_t *t = 0;
        kobject_t *o = 0;
        uint32_t v, v2 = 0;
        uint64_t f;
        if (len < 4 || copy_from_user(cur, &v, buf, 4)) return STATUS_ACCESS_VIOLATION;
        if (cls == K32S_THREAD_POWER && (len < 8 || copy_from_user(cur, &v2, buf + 4, 4))) return STATUS_ACCESS_VIOLATION;
        if (cls == K32S_THREAD_MEM_PRIORITY && (v < 1 || v > 5)) return STATUS_INVALID_PARAMETER;
        if (h == CURRENT_THREAD_HANDLE) t = thread_current();
        else if (!(o = handle_lookup(cur, h, OB_THREAD))) return STATUS_INVALID_HANDLE;
        f = irq_save();
        if (o) t = o->u.thr.t;
        if (t && t->state != TS_ZOMBIE) {
            if (cls == K32S_THREAD_BOOST) t->boost_disabled = v != 0;
            else if (cls == K32S_THREAD_MEM_PRIORITY) t->mem_priority = v;
            else { t->power_control = v; t->power_state = v2; }
        }
        irq_restore(f);
        return t ? STATUS_SUCCESS : STATUS_THREAD_IS_TERMINATING;
    }
    case K32S_THREAD_NAME: {                                    /* SetThreadDescription: buf/len = the UTF-16 text (len 0 clears) */
        thread_t *t = 0;
        kobject_t *o = 0;
        uint16_t *text = 0, *old;
        uint64_t f;
        if (len > THREAD_NAME_MAX_BYTES || (len & 1)) return STATUS_INVALID_PARAMETER;
        if (h == CURRENT_THREAD_HANDLE) t = thread_current();
        else if (!(o = handle_lookup(cur, h, OB_THREAD))) return STATUS_INVALID_HANDLE;
        if (len) {
            text = kmalloc(len);
            if (!text) return STATUS_NO_MEMORY;
            if (copy_from_user(cur, text, buf, len)) { kfree(text); return STATUS_ACCESS_VIOLATION; }
        }
        f = irq_save();
        if (o) t = o->u.thr.t;
        if (!t || t->state == TS_ZOMBIE) { irq_restore(f); kfree(text); return STATUS_THREAD_IS_TERMINATING; }
        old = t->desc;
        t->desc = text;
        t->desc_bytes = (uint32_t)len;
        irq_restore(f);
        kfree(old);
        return STATUS_SUCCESS;
    }
    case K32S_DISCARD: case K32S_LOCK: case K32S_UNLOCK: case K32S_PREFETCH: {
        process_t *p = proc_of_handle(cur, h);
        uint64_t range[2];
        if (!p) return STATUS_INVALID_HANDLE;
        if (len < sizeof range || copy_from_user(cur, range, buf, sizeof range)) return STATUS_ACCESS_VIOLATION;
        if (p != cur && cls != K32S_PREFETCH) return STATUS_ACCESS_DENIED;          /* these act on the caller's own memory only */
        return mem_op(p, (uint32_t)cls, range[0], range[1]);
    }
    default:
        return STATUS_INVALID_INFO_CLASS;
    }
}

/* ---------------------------------------------------------------- NtGetContextThread(ThreadHandle, PCONTEXT) */
#define CTX_SIZE 0x4d0
#define CTX_AMD64 0x100000u

static void put64(uint8_t *c, unsigned off, uint64_t v) { memcpy(c + off, &v, 8); }

int32_t k32_get_context_thread(process_t *p, uint64_t handle, uint64_t context_va)
{
    uint8_t ctx[CTX_SIZE];
    struct regs frame;
    uint8_t fx[512] __attribute__((aligned(16)));
    thread_t *t = 0;
    kobject_t *o = 0;
    uint32_t flags;
    uint64_t f;
    int have_frame;
    if (handle == CURRENT_THREAD_HANDLE) t = thread_current();
    else if (!(o = handle_lookup(p, handle, OB_THREAD))) return STATUS_INVALID_HANDLE;
    if (copy_from_user(p, ctx, context_va, sizeof ctx)) return STATUS_ACCESS_VIOLATION;
    flags = *(uint32_t *)(ctx + 0x30);
    if ((flags & CTX_AMD64) != CTX_AMD64) return STATUS_INVALID_PARAMETER;
    f = irq_save();
    if (o) t = o->u.thr.t;
    if (!t || t->state == TS_ZOMBIE || !t->teb) { irq_restore(f); return STATUS_THREAD_IS_TERMINATING; }
    /* A thread that has run is inside the kernel whenever it is not running (a system call or an interrupt from ring 3), and its
     * user-mode register frame sits at the top of its kernel stack; the current thread is in this very system call. A thread that
     * never ran has no frame yet: its context is the initial one the kernel will enter user mode with. */
    memcpy(&frame, (const void *)(t->stack_base + KSTACK_BYTES - sizeof frame), sizeof frame);
    have_frame = (t == thread_current() || t->cycles) && frame.cs == 0x23 && frame.ss == 0x1b;
    if (t == thread_current()) __asm__ volatile("fxsave (%0)" :: "r"(fx) : "memory");       /* live user FPU state */
    else memcpy(fx, t->fx, sizeof fx);
    if (!have_frame) {
        memset(&frame, 0, sizeof frame);
        frame.rip = t->user_rip; frame.rsp = t->user_rsp; frame.rcx = t->user_arg; frame.rdx = t->user_arg2; frame.rflags = 0x202;
    }
    irq_restore(f);
    if ((flags & (CTX_AMD64 | 1)) == (CTX_AMD64 | 1)) {           /* CONTEXT_CONTROL */
        *(uint16_t *)(ctx + 0x38) = 0x23; *(uint16_t *)(ctx + 0x42) = 0x1b;
        *(uint32_t *)(ctx + 0x44) = (uint32_t)frame.rflags;
        put64(ctx, 0x98, frame.rsp); put64(ctx, 0xf8, frame.rip);
    }
    if ((flags & (CTX_AMD64 | 2)) == (CTX_AMD64 | 2)) {           /* CONTEXT_INTEGER */
        put64(ctx, 0x78, frame.rax); put64(ctx, 0x80, frame.rcx); put64(ctx, 0x88, frame.rdx); put64(ctx, 0x90, frame.rbx);
        put64(ctx, 0xa0, frame.rbp); put64(ctx, 0xa8, frame.rsi); put64(ctx, 0xb0, frame.rdi);
        put64(ctx, 0xb8, frame.r8); put64(ctx, 0xc0, frame.r9); put64(ctx, 0xc8, frame.r10); put64(ctx, 0xd0, frame.r11);
        put64(ctx, 0xd8, frame.r12); put64(ctx, 0xe0, frame.r13); put64(ctx, 0xe8, frame.r14); put64(ctx, 0xf0, frame.r15);
    }
    if ((flags & (CTX_AMD64 | 4)) == (CTX_AMD64 | 4)) {           /* CONTEXT_SEGMENTS: flat user data selectors */
        *(uint16_t *)(ctx + 0x3a) = 0x1b; *(uint16_t *)(ctx + 0x3c) = 0x1b; *(uint16_t *)(ctx + 0x3e) = 0x1b; *(uint16_t *)(ctx + 0x40) = 0x1b;
    }
    if ((flags & (CTX_AMD64 | 8)) == (CTX_AMD64 | 8)) {           /* CONTEXT_FLOATING_POINT */
        *(uint32_t *)(ctx + 0x34) = *(uint32_t *)(fx + 24);
        memcpy(ctx + 0x100, fx, 512);
    }
    if ((flags & (CTX_AMD64 | 0x10)) == (CTX_AMD64 | 0x10))       /* CONTEXT_DEBUG_REGISTERS: none are ever armed */
        memset(ctx + 0x48, 0, 6 * 8);
    return copy_to_user(p, context_va, ctx, sizeof ctx) ? STATUS_ACCESS_VIOLATION : STATUS_SUCCESS;
}
