/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 user-mode exception delivery (Windows x64 model).
 *
 * A CPU exception raised in ring 3 is converted into an EXCEPTION_RECORD plus a CONTEXT
 * (both in the documented Windows x64 layouts) on the faulting thread's user stack, and the
 * thread is redirected to ntdll!KiUserExceptionDispatcher. That user-mode code walks the
 * .pdata unwind tables, runs handlers and finally resumes with NtContinue, which restores a
 * validated CONTEXT through IRETQ. Unhandled exceptions end the process.
 */
#include "proc_internal.h"

#define CONTEXT_SIZE 0x4d0
#define RECORD_SIZE 0x98
#define CONTEXT_AMD64 0x100000u
#define CONTEXT_CONTROL (CONTEXT_AMD64 | 1)
#define CONTEXT_INTEGER (CONTEXT_AMD64 | 2)
#define CONTEXT_SEGMENTS (CONTEXT_AMD64 | 4)
#define CONTEXT_FLOATING_POINT (CONTEXT_AMD64 | 8)

static void put64(uint8_t *c, unsigned off, uint64_t v) { memcpy(c + off, &v, 8); }
static uint64_t get64(const uint8_t *c, unsigned off) { uint64_t v; memcpy(&v, c + off, 8); return v; }

static uint64_t canonical_user(uint64_t a) { return a < USER_TOP; }

int user_exception_dispatch(struct regs *r, uint32_t code, uint64_t info0, uint64_t info1)
{
    process_t *p = current_process();
    thread_t *t = thread_current();
    uint8_t ctx[CONTEXT_SIZE], rec[RECORD_SIZE];
    uint64_t sp, ctx_va, rec_va;
    if (!p || !p->ntdll_exception_dispatcher)
        return 0;
    memset(ctx, 0, sizeof ctx);
    memset(rec, 0, sizeof rec);
    *(uint32_t *)(ctx + 0x30) = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT;
    *(uint32_t *)(ctx + 0x34) = *(uint32_t *)(t->fx + 24);                    /* MxCsr */
    *(uint16_t *)(ctx + 0x38) = 0x23;                                         /* SegCs */
    *(uint16_t *)(ctx + 0x3a) = 0x1b;                                         /* SegDs */
    *(uint16_t *)(ctx + 0x3c) = 0x1b;                                         /* SegEs */
    *(uint16_t *)(ctx + 0x42) = 0x1b;                                         /* SegSs */
    *(uint32_t *)(ctx + 0x44) = (uint32_t)r->rflags;
    put64(ctx, 0x78, r->rax); put64(ctx, 0x80, r->rcx); put64(ctx, 0x88, r->rdx); put64(ctx, 0x90, r->rbx);
    put64(ctx, 0x98, r->rsp); put64(ctx, 0xa0, r->rbp); put64(ctx, 0xa8, r->rsi); put64(ctx, 0xb0, r->rdi);
    put64(ctx, 0xb8, r->r8);  put64(ctx, 0xc0, r->r9);  put64(ctx, 0xc8, r->r10); put64(ctx, 0xd0, r->r11);
    put64(ctx, 0xd8, r->r12); put64(ctx, 0xe0, r->r13); put64(ctx, 0xe8, r->r14); put64(ctx, 0xf0, r->r15);
    put64(ctx, 0xf8, r->rip);
    memcpy(ctx + 0x100, t->fx, 512);                                          /* XMM_SAVE_AREA32 == FXSAVE image */

    *(uint32_t *)(rec + 0) = code;
    *(uint32_t *)(rec + 4) = 0;                                               /* continuable */
    put64(rec, 0x10, r->rip);                                                 /* ExceptionAddress */
    if (code == (uint32_t)STATUS_ACCESS_VIOLATION || code == (uint32_t)STATUS_IN_PAGE_ERROR ||
        code == (uint32_t)STATUS_GUARD_PAGE_VIOLATION) {
        *(uint32_t *)(rec + 0x18) = 2;                                        /* NumberParameters */
        put64(rec, 0x20, info0);                                              /* 0 read, 1 write, 8 execute */
        put64(rec, 0x28, info1);                                              /* faulting address */
    }
    /* Faults that resume at the same RIP after the handler runs (breakpoint reports the next RIP already). */

    sp = (r->rsp - 0x80) & ~0xfull;                                           /* stay clear of the interrupted frame */
    sp -= CONTEXT_SIZE;
    sp &= ~0xfull;
    ctx_va = sp;
    sp -= RECORD_SIZE;
    sp &= ~0xfull;
    rec_va = sp;
    sp -= 0x28;                                                               /* shadow space + fake return address slot */
    sp &= ~0xfull;
    sp -= 8;
    if (!canonical_user(sp) || copy_to_user(p, ctx_va, ctx, sizeof ctx) || copy_to_user(p, rec_va, rec, sizeof rec)) {
        return 0;                                                             /* cannot build the frame: caller kills the process */
    }
    {
        const uint64_t zero = 0;
        if (copy_to_user(p, sp, &zero, 8)) return 0;
    }
    r->rip = p->ntdll_exception_dispatcher;
    r->rcx = rec_va;
    r->rdx = ctx_va;
    r->rsp = sp;
    r->rflags = 0x202;
    return 1;
}

/* NtContinue(PCONTEXT, BOOLEAN TestAlert) and NtRaiseException(PEXCEPTION_RECORD, PCONTEXT, BOOLEAN FirstChance) */
int32_t user_exception_continue(process_t *p, struct regs *r, uint64_t context_va, uint64_t record_va, int is_raise)
{
    uint8_t ctx[CONTEXT_SIZE];
    thread_t *t = thread_current();
    uint32_t flags;
    if (is_raise) {
        /* Unhandled after the user-mode search: terminate the process with the exception code.
         * (The first-chance variant is not offered: user mode dispatches those itself.) */
        uint8_t rec[RECORD_SIZE];
        if (copy_from_user(p, rec, context_va, sizeof rec)) return STATUS_ACCESS_VIOLATION;
        kprintf("K64: unhandled exception %x at %llx in %s (pid %d); process terminated\n", *(uint32_t *)rec,
                get64(rec, 0x10), p->name, p->pid);
        (void)record_va;
        process_terminate(p, (int64_t)(int32_t)*(uint32_t *)rec, 1);
        process_thread_gone(p);
        thread_exit((int32_t)*(uint32_t *)rec);
    }
    if (copy_from_user(p, ctx, context_va, sizeof ctx)) return STATUS_ACCESS_VIOLATION;
    flags = *(uint32_t *)(ctx + 0x30);
    if ((flags & CONTEXT_AMD64) != CONTEXT_AMD64) return STATUS_INVALID_PARAMETER;
    if (!canonical_user(get64(ctx, 0xf8)) || !canonical_user(get64(ctx, 0x98))) return STATUS_ACCESS_VIOLATION;
    if ((flags & CONTEXT_INTEGER) == CONTEXT_INTEGER) {
        r->rax = get64(ctx, 0x78); r->rcx = get64(ctx, 0x80); r->rdx = get64(ctx, 0x88); r->rbx = get64(ctx, 0x90);
        r->rbp = get64(ctx, 0xa0); r->rsi = get64(ctx, 0xa8); r->rdi = get64(ctx, 0xb0);
        r->r8 = get64(ctx, 0xb8); r->r9 = get64(ctx, 0xc0); r->r10 = get64(ctx, 0xc8); r->r11 = get64(ctx, 0xd0);
        r->r12 = get64(ctx, 0xd8); r->r13 = get64(ctx, 0xe0); r->r14 = get64(ctx, 0xe8); r->r15 = get64(ctx, 0xf0);
    }
    if ((flags & CONTEXT_CONTROL) == CONTEXT_CONTROL) {
        r->rip = get64(ctx, 0xf8);
        r->rsp = get64(ctx, 0x98);
        /* Only arithmetic flags, DF and IF may be set from user mode; never IOPL, NT, TF, VM. */
        r->rflags = (*(uint32_t *)(ctx + 0x44) & 0xcd5u) | 0x202;
    }
    if ((flags & CONTEXT_FLOATING_POINT) == CONTEXT_FLOATING_POINT) {
        uint32_t mxcsr = *(uint32_t *)(ctx + 0x100 + 24);
        memcpy(t->fx, ctx + 0x100, 512);
        *(uint32_t *)(t->fx + 24) = mxcsr & 0xffbf;                           /* reserved bits must stay clear */
        __asm__ volatile("fxrstor (%0)" :: "r"(t->fx) : "memory");
    }
    r->cs = 0x23;
    r->ss = 0x1b;
    return (int32_t)0x7fff0001;                                               /* frame rewritten: leave through IRETQ */
}
