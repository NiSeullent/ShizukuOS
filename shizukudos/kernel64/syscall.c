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
        return o ? o->u.proc.p : 0;
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

int syscall_dispatch(struct regs *r)
{
    process_t *p = current_process();
    const uint32_t num = (uint32_t)r->rax;
    const uint64_t a1 = r->r10, a2 = r->rdx, a3 = r->r8, a4 = r->r9;
    int32_t st;
    count_syscall();
    if (!p) { r->rax = (uint64_t)(int64_t)STATUS_INVALID_SYSTEM_SERVICE; return 0; }
    sti();                                              /* SFMASK cleared IF; kernel work is preemptible */
    switch (num) {
    case SYS_NtShzDebugPrint: st = sys_debug_print(p, a1, a2); break;
    case SYS_NtShzEvidence:
        if (a1 >= 16 && a1 < 24) { shz_evidence(a1, a2); st = STATUS_SUCCESS; } else st = STATUS_INVALID_PARAMETER;
        break;
    case SYS_NtTerminateProcess: {
        process_t *t = a1 == 0 ? p : proc_from_handle(p, a1);
        if (!t) { st = STATUS_INVALID_HANDLE; break; }
        process_terminate(t, (int64_t)(int32_t)a2, 0);
        if (t == p) {
            process_thread_gone(p);
            thread_exit((int32_t)a2);
        }
        st = STATUS_SUCCESS;
        break;
    }
    case SYS_NtTerminateThread:
        if (a1 == 0 || a1 == CURRENT_THREAD_HANDLE) {
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
    cli();
    if (st == (int32_t)0x7fff0001) {                    /* NtContinue already rewrote the whole frame */
        check_kill();
        return 1;
    }
    r->rax = (uint64_t)(int64_t)st;
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
