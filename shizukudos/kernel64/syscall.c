/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 system-call dispatcher (Windows x64 register convention, see ntsys.h).
 */
#include "proc_internal.h"

extern void count_syscall(void);
extern void check_kill(void);
extern void process_thread_gone(process_t *p);

int64_t stack_arg(process_t *p, struct regs *r, unsigned n)   /* n >= 5: 5th, 6th ... */
{
    uint64_t v = 0;
    if (copy_from_user(p, &v, r->rsp + 0x28 + (uint64_t)(n - 5) * 8, 8))
        return 0;
    return (int64_t)v;
}

static int32_t sys_debug_print(process_t *p, uint64_t buf, uint64_t len)
{
    char tmp[200];
    if (len > 190) len = 190;
    if (copy_from_user(p, tmp, buf, len)) return STATUS_ACCESS_VIOLATION;
    tmp[len] = 0;
    kprintf("[user %s pid %d] %s", p->name, p->pid, tmp);
    return STATUS_SUCCESS;
}

static process_t *proc_from_handle(process_t *cur, uint64_t h)
{
    if (h == CURRENT_PROCESS_HANDLE) return cur;
    {
        kobject_t *o = handle_lookup(cur, h, OB_PROCESS);
        return o && !o->u.proc.p->teardown ? o->u.proc.p : 0;     /* a dead process has no address space left */
    }
}

/* NtAllocateVirtualMemory(ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize,
 *                         ULONG AllocationType, ULONG Protect) */
static int32_t sys_allocate_vm(process_t *cur, uint64_t hproc, uint64_t pbase, uint64_t zero_bits, uint64_t psize,
                               uint64_t type, uint64_t prot)
{
    process_t *p = proc_from_handle(cur, hproc);
    uint64_t base, size;
    int32_t st;
    (void)zero_bits;
    if (!p) return STATUS_INVALID_HANDLE;
    if (copy_from_user(cur, &base, pbase, 8) || copy_from_user(cur, &size, psize, 8)) return STATUS_ACCESS_VIOLATION;
    st = vad_alloc(p, &base, &size, (uint32_t)type, (uint32_t)prot, VK_PRIVATE);
    if (st) return st;
    if (copy_to_user(cur, pbase, &base, 8) || copy_to_user(cur, psize, &size, 8)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

static int32_t sys_free_vm(process_t *cur, uint64_t hproc, uint64_t pbase, uint64_t psize, uint64_t type)
{
    process_t *p = proc_from_handle(cur, hproc);
    uint64_t base, size;
    int32_t st;
    if (!p) return STATUS_INVALID_HANDLE;
    if (copy_from_user(cur, &base, pbase, 8) || copy_from_user(cur, &size, psize, 8)) return STATUS_ACCESS_VIOLATION;
    st = vad_free(p, &base, &size, (uint32_t)type);
    if (st) return st;
    if (copy_to_user(cur, pbase, &base, 8) || copy_to_user(cur, psize, &size, 8)) return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

static int32_t sys_protect_vm(process_t *cur, uint64_t hproc, uint64_t pbase, uint64_t psize, uint64_t prot,
                              uint64_t pold)
{
    process_t *p = proc_from_handle(cur, hproc);
    uint64_t base, size;
    uint32_t old = 0;
    int32_t st;
    if (!p) return STATUS_INVALID_HANDLE;
    if (copy_from_user(cur, &base, pbase, 8) || copy_from_user(cur, &size, psize, 8)) return STATUS_ACCESS_VIOLATION;
    st = vad_protect(p, &base, &size, (uint32_t)prot, &old);
    if (st) return st;
    if (copy_to_user(cur, pbase, &base, 8) || copy_to_user(cur, psize, &size, 8) || copy_to_user(cur, pold, &old, 4))
        return STATUS_ACCESS_VIOLATION;
    return STATUS_SUCCESS;
}

/* MEMORY_BASIC_INFORMATION (class 0) */
struct mbi { uint64_t base, alloc_base; uint32_t alloc_prot, pad1; uint64_t size; uint32_t state, prot, type, pad2; };

static int32_t sys_query_vm(process_t *cur, uint64_t hproc, uint64_t addr, uint64_t cls, uint64_t buf, uint64_t len,
                            uint64_t pret)
{
    process_t *p = proc_from_handle(cur, hproc);
    struct mbi m;
    int32_t st;
    if (!p) return STATUS_INVALID_HANDLE;
    if (cls == 4) {                                     /* MemoryWorkingSetExInformation: {VirtualAddress, attributes}[] */
        uint64_t i, n = len / 16;
        if (!n) return STATUS_INFO_LENGTH_MISMATCH;
        for (i = 0; i < n; ++i) {
            uint64_t va, attr = 0, flags = 0;
            if (copy_from_user(cur, &va, buf + i * 16, 8)) return STATUS_ACCESS_VIOLATION;
            if (va >= USER_MIN && va < USER_TOP && vm_lookup(p->pml4, va, &flags) && (flags & PT_U)) {
                const vad_t *v = vad_find(p, va & ~(PAGE_SIZE - 1));
                attr = 1 | (1ull << 1);                     /* Valid, ShareCount 1 (pages are private) */
                if (v) attr |= (uint64_t)(v->prot & 0x7ff) << 4;   /* Win32Protection */
            }
            if (copy_to_user(cur, buf + i * 16 + 8, &attr, 8)) return STATUS_ACCESS_VIOLATION;
        }
        if (pret) { uint64_t r = n * 16; if (copy_to_user(cur, pret, &r, 8)) return STATUS_ACCESS_VIOLATION; }
        return STATUS_SUCCESS;
    }
    if (cls != 0) return STATUS_INVALID_INFO_CLASS;
    if (len < sizeof m) return STATUS_BUFFER_TOO_SMALL;
    memset(&m, 0, sizeof m);
    st = vad_query(p, addr, &m.base, &m.alloc_base, &m.alloc_prot, &m.size, &m.state, &m.prot, &m.type);
    if (st) return st;
    if (copy_to_user(cur, buf, &m, sizeof m)) return STATUS_ACCESS_VIOLATION;
    if (pret) { uint64_t n = sizeof m; if (copy_to_user(cur, pret, &n, 8)) return STATUS_ACCESS_VIOLATION; }
    return STATUS_SUCCESS;
}

static int32_t sys_delay(process_t *cur, uint64_t alertable, uint64_t pinterval)
{
    int64_t iv;
    (void)alertable;
    if (copy_from_user(cur, &iv, pinterval, 8)) return STATUS_ACCESS_VIOLATION;
    if (iv < 0) {
        uint64_t ms = (uint64_t)(-iv) / 10000;
        thread_sleep_ms(ms ? ms : 1);
    } else {
        thread_yield();
    }
    return STATUS_SUCCESS;
}

extern int32_t sys_extended(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2, uint64_t a3,
                            uint64_t a4);
/* IPC hook (kernel64/ipc_core.c): may take over a system call of the base list (pipe/overlapped I/O on NtReadFile, alertable
 * waits, cross-process NtDuplicateObject, ...). Returns nonzero and sets *st when it handled the call. */
int __attribute__((weak)) ipc_syscall_override(process_t *p, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2,
                                               uint64_t a3, uint64_t a4, int32_t *st)
{
    (void)p; (void)r; (void)num; (void)a1; (void)a2; (void)a3; (void)a4; (void)st;
    return 0;
}

/* `shz.systrace` on the kernel command line (tests/run_k64_chromium.py passes it): every system call that returns an error status
 * (severity bits 11) is recorded. The first SYSTRACE_PER_PAIR occurrences of each (call, status) pair are printed as they happen;
 * all of them enter a ring of the last SYSTRACE_RING failures that k64_systrace_dump() prints (exc.c calls it at the first
 * breakpoint exception of a process, which is where Chromium's CHECK/NOTREACHED end up), so the failing call that led to a
 * fatal check is visible even when the same pair was printed earlier. Nothing changes without the flag. */
#define SYSTRACE_PER_PAIR 3
#define SYSTRACE_RING 48
#define SYSTRACE_PAIRS 256
static struct { uint32_t num, st, pid; uint64_t tid, a1, a2; } systrace_ring[SYSTRACE_RING];
static unsigned systrace_head, systrace_total;
static struct { uint32_t num, st, count; } systrace_pairs[SYSTRACE_PAIRS];
static int systrace_on = -1;

/* `shz.systrace.all` (implies shz.systrace): additionally every system call of every thread, success or not, goes into a ring of
 * the last SYSALL_RING calls; k64_systrace_dump() prints the last SYSALL_SHOW of the thread that took the breakpoint, so the
 * operations that preceded a CHECK failure are visible, with their arguments and the tick they happened at. */
#define SYSALL_RING 4096
#define SYSALL_SHOW 70
static struct { uint32_t num, st; uint64_t tid, a1, a2, a3, tick; } sysall[SYSALL_RING];
static unsigned sysall_head;
static int sysall_on = -1;

static const char *syscall_name(uint32_t num)
{
    static const struct { const char *name; uint32_t num; } tbl[] = {
#define X(n, v) { #n, v },
        SYSCALL_LIST(X) SYSCALL_LIST_REGISTRY(X) SYSCALL_LIST_GRAPHICS(X) SYSCALL_LIST_NET(X) SYSCALL_LIST_K32(X) SYSCALL_LIST_MISC(X)
        SYSCALL_LIST_GPU(X) SYSCALL_LIST_SETUP(X) SYSCALL_LIST_BLK(X) SYSCALL_LIST_NTDRV(X) SYSCALL_LIST_IPC_MISC(X) SYSCALL_LIST_IPC(X)
#undef X
    };
    unsigned i;
    for (i = 0; i < sizeof tbl / sizeof tbl[0]; ++i) if (tbl[i].num == num) return tbl[i].name;
    return "?";
}

static void systrace_record(process_t *p, uint32_t num, int32_t st, uint64_t a1, uint64_t a2)
{
    unsigned i, slot = SYSTRACE_PAIRS;
    uint32_t seen = 0;
    const uint64_t f = irq_save();
    for (i = 0; i < SYSTRACE_PAIRS; ++i) {
        if (systrace_pairs[i].count && systrace_pairs[i].num == num && systrace_pairs[i].st == (uint32_t)st) { slot = i; break; }
        if (!systrace_pairs[i].count && slot == SYSTRACE_PAIRS) slot = i;
    }
    if (slot < SYSTRACE_PAIRS) {
        if (!systrace_pairs[slot].count) { systrace_pairs[slot].num = num; systrace_pairs[slot].st = (uint32_t)st; }
        seen = systrace_pairs[slot].count++;
    }
    {
        const unsigned at = systrace_head++ % SYSTRACE_RING;
        systrace_ring[at].num = num; systrace_ring[at].st = (uint32_t)st; systrace_ring[at].pid = (uint32_t)p->pid;
        systrace_ring[at].tid = thread_current()->tid; systrace_ring[at].a1 = a1; systrace_ring[at].a2 = a2;
        ++systrace_total;
    }
    irq_restore(f);
    if (seen < SYSTRACE_PER_PAIR)
        kprintf("K64 systrace: pid %d tid %llu %s(%x) -> %x a1=%llx a2=%llx\n", p->pid, thread_current()->tid, syscall_name(num), num,
                (uint32_t)st, a1, a2);
}

/* The ring, oldest first (called with the process stopped at a breakpoint; exc.c). */
void k64_systrace_dump(void)
{
    unsigned n = systrace_total < SYSTRACE_RING ? systrace_total : SYSTRACE_RING, i;
    if (systrace_on != 1) return;
    if (sysall_on > 0) {
        const uint64_t me = thread_current()->tid;
        unsigned shown = 0, back;
        const unsigned total = sysall_head < SYSALL_RING ? sysall_head : SYSALL_RING;
        unsigned first = total;                               /* scan backwards for this thread's last SYSALL_SHOW calls */
        for (back = 0; back < total && shown < SYSALL_SHOW; ++back) {
            const unsigned at = (sysall_head - 1 - back) % SYSALL_RING;
            if (sysall[at].tid == me) { ++shown; first = back; }
        }
        kprintf("K64 systrace: the last %u system calls of tid %llu (of %u recorded), oldest first\n", shown, me, sysall_head);
        for (back = first + 1; back-- > 0; ) {
            const unsigned at = (sysall_head - 1 - back) % SYSALL_RING;
            if (sysall[at].tid != me) continue;
            kprintf("K64 systrace:   t=%llu %s(%x) a1=%llx a2=%llx a3=%llx -> %x\n", sysall[at].tick, syscall_name(sysall[at].num), sysall[at].num,
                    sysall[at].a1, sysall[at].a2, sysall[at].a3, sysall[at].st);
        }
    }
    kprintf("K64 systrace: last %u failing system calls of %u, oldest first\n", n, systrace_total);
    for (i = 0; i < n; ++i) {
        const unsigned at = (systrace_head - n + i) % SYSTRACE_RING;
        kprintf("K64 systrace:   pid %u tid %llu %s(%x) -> %x a1=%llx a2=%llx\n", systrace_ring[at].pid, systrace_ring[at].tid,
                syscall_name(systrace_ring[at].num), systrace_ring[at].num, systrace_ring[at].st, systrace_ring[at].a1, systrace_ring[at].a2);
    }
}

int syscall_dispatch(struct regs *r)
{
    process_t *p = current_process();
    const uint32_t num = (uint32_t)r->rax;
    const uint64_t a1 = r->r10, a2 = r->rdx, a3 = r->r8, a4 = r->r9;
    int32_t st;
    count_syscall();
    if (!p) { r->rax = (uint64_t)(int64_t)STATUS_INVALID_SYSTEM_SERVICE; return 0; }
    sti();                                              /* SFMASK cleared IF; kernel work is preemptible */
    if (ipc_syscall_override(p, r, num, a1, a2, a3, a4, &st))
        goto done;
    switch (num) {
    case SYS_NtShzDebugPrint: st = sys_debug_print(p, a1, a2); break;
    case SYS_NtShzEvidence:
        if (a1 >= 16 && a1 < 24) { shz_evidence(a1, a2); st = STATUS_SUCCESS; } else st = STATUS_INVALID_PARAMETER;
        break;
    case SYS_NtTerminateProcess:
        if (a1 == 0) st = process_terminate_others(p, (int32_t)a2);   /* NULL: every thread but the caller (ExitProcess) */
        else st = process_terminate_handle(p, a1, (int32_t)a2);  /* ipc_proc.c; does not return when it ends the caller */
        break;
    case SYS_NtTerminateThread:
        if (a1 == 0 || a1 == CURRENT_THREAD_HANDLE) {
            thread_current()->exit_code = (int32_t)a2;
            process_thread_gone(p);
            thread_exit((int32_t)a2);
        }
        st = sys_extended(p, r, num, a1, a2, a3, a4);
        break;
    case SYS_NtAllocateVirtualMemory:
        st = sys_allocate_vm(p, a1, a2, a3, a4, (uint64_t)stack_arg(p, r, 5), (uint64_t)stack_arg(p, r, 6));
        break;
    case SYS_NtFreeVirtualMemory: st = sys_free_vm(p, a1, a2, a3, a4); break;
    case SYS_NtProtectVirtualMemory: st = sys_protect_vm(p, a1, a2, a3, a4, (uint64_t)stack_arg(p, r, 5)); break;
    case SYS_NtQueryVirtualMemory:
        st = sys_query_vm(p, a1, a2, a3, a4, (uint64_t)stack_arg(p, r, 5), (uint64_t)stack_arg(p, r, 6));
        break;
    case SYS_NtDelayExecution: st = sys_delay(p, a1, a2); break;
    case SYS_NtYieldExecution: thread_yield(); st = STATUS_NO_YIELD_PERFORMED; break;
    case SYS_NtQueryPerformanceCounter: {
        uint64_t v = rdmsr(0x10) ? 0 : 0, freq = 0;
        __asm__ volatile("rdtsc; shl $32, %%rdx; or %%rdx, %%rax" : "=a"(v) :: "rdx");
        freq = 1000000000ull;                            /* 1 tick == 1 ns of the Supervisor clock */
        v = shz_time_ns();
        if (copy_to_user(p, a1, &v, 8) || (a2 && copy_to_user(p, a2, &freq, 8))) st = STATUS_ACCESS_VIOLATION;
        else st = STATUS_SUCCESS;
        break;
    }
    default:
        if (num < SYS_MAX) st = sys_extended(p, r, num, a1, a2, a3, a4);
        else st = STATUS_INVALID_SYSTEM_SERVICE;
    }
done:
    cli();
    if (st == (int32_t)0x7fff0001) {                    /* NtContinue already rewrote the whole frame */
        check_kill();
        return 1;
    }
    r->rax = (uint64_t)(int64_t)st;
    if (systrace_on < 0) {
        sysall_on = k64_cmdline_has("shz.systrace.all");
        systrace_on = sysall_on || k64_cmdline_has("shz.systrace");
    }
    if (sysall_on > 0) {
        const uint64_t f = irq_save();
        const unsigned at = sysall_head++ % SYSALL_RING;
        sysall[at].num = num; sysall[at].st = (uint32_t)st; sysall[at].tid = thread_current()->tid;
        sysall[at].a1 = a1; sysall[at].a2 = a2; sysall[at].a3 = a3; sysall[at].tick = ticks_now();
        irq_restore(f);
    }
    if (systrace_on > 0 && ((uint32_t)st >> 30) == 3u) systrace_record(p, num, st, a1, a2);
    check_kill();
    return 0;
}

/* Filled in by later stages (objects, files, threads); default: not implemented. */
int32_t __attribute__((weak)) sys_extended(process_t *cur, struct regs *r, uint32_t num, uint64_t a1, uint64_t a2,
                                           uint64_t a3, uint64_t a4)
{
    (void)cur; (void)r; (void)num; (void)a1; (void)a2; (void)a3; (void)a4;
    return STATUS_NOT_IMPLEMENTED;
}
