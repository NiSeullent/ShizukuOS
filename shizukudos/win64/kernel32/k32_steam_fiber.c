/* SPDX-License-Identifier: GPL-2.0-only
 * Cooperative AMD64 fibers required by the actual Valve Steam desktop client.
 * Original implementation against Microsoft's fiber/x64 ABI contracts. Reviewed
 * Wine db11d0fe6a169c457e23d007e20404643d067aa8 dlls/kernelbase/thread.c and
 * ReactOS f06eace89e11b6513afcf65b653f2d360db7ba77
 * dll/win32/kernel32/client/fiber.c for TEB state, conversion and rundown; no
 * upstream code copied. Kernel64 has demand-zero commitment, but no automatic
 * stack guard growth: the requested reservation is committed lazily in full,
 * with a permanent PAGE_NOACCESS low page. That is a documented limitation.
 * Slot free/reuse and thread-exit rundown still inherit k32_core.c's FLS limits.
 */
#ifdef SHZ_STEAM_FIBER_HOST_TEST
#include "../tests/steam_fiber_host.h"
#else
#include "k32.h"
#endif
#include <stddef.h>

#define TEB_STACK_BASE 0x08
#define TEB_STACK_LIMIT 0x10
#define TEB_FIBER_DATA 0x20
#define TEB_ACTCTX_STACK 0x2c8
#define TEB_DEALLOCATION_STACK 0x1478
#define TEB_GUARANTEED_STACK 0x1748
#define TEB_FLS_DATA 0x17c8
#define TEB_SAME_FLAGS 0x17ee
#define HAS_FIBER_DATA 4
#define FIBER_MAGIC 0x53485a4649424552ull

typedef struct __attribute__((aligned(16))) {
    uint64_t rsp, rbx, rbp, rsi, rdi, r12, r13, r14, r15, padding;
    unsigned char fp[512];
} fiber_context;

typedef struct __attribute__((aligned(16))) {
    PVOID parameter;                         /* GetFiberData dereferences this first word */
    uint64_t magic;
    PVOID stack_base, stack_limit, stack_allocation, actctx;
    PVOID *fls;
    DWORD guaranteed_stack;
    volatile LONG deleting;
    BOOL owns_stack;                         /* only CreateFiber owns an independently allocated VAD */
    DWORD converted_owner;                   /* original stack lifetime is tied to this kernel thread */
    LPFIBER_START_ROUTINE start;
    fiber_context context;
} shz_fiber;

_Static_assert(offsetof(fiber_context, fp) == 80, "fiber assembly FP offset");
_Static_assert(sizeof(fiber_context) == 592, "fiber assembly context size");
_Static_assert(offsetof(shz_fiber, parameter) == 0, "GetFiberData ABI");
_Static_assert(offsetof(shz_fiber, context) % 16 == 0, "FXSAVE requires 16-byte alignment");

/* Win64 ABI: RCX = old context, RDX = target context. Saving the actual RSP
 * retains the caller's return address. The target resumes via RET; a new fiber
 * gets the same normal-entry alignment and 32-byte caller home area. FXSAVE64
 * preserves XMM6-15, MXCSR, x87 control/status/tags and the x87 register stack.
 * This leaf touches no temporary stack and has no frame to unwind. */
static void __attribute__((naked, noinline)) WINAPI switch_context(fiber_context *old, fiber_context *next)
{
    __asm__ volatile(
        "movq %rsp, 0(%rcx)\n\t"
        "movq %rbx, 8(%rcx)\n\t"
        "movq %rbp, 16(%rcx)\n\t"
        "movq %rsi, 24(%rcx)\n\t"
        "movq %rdi, 32(%rcx)\n\t"
        "movq %r12, 40(%rcx)\n\t"
        "movq %r13, 48(%rcx)\n\t"
        "movq %r14, 56(%rcx)\n\t"
        "movq %r15, 64(%rcx)\n\t"
        "fxsave64 80(%rcx)\n\t"
        "fxrstor64 80(%rdx)\n\t"
        "movq 8(%rdx), %rbx\n\t"
        "movq 16(%rdx), %rbp\n\t"
        "movq 24(%rdx), %rsi\n\t"
        "movq 32(%rdx), %rdi\n\t"
        "movq 40(%rdx), %r12\n\t"
        "movq 48(%rdx), %r13\n\t"
        "movq 56(%rdx), %r14\n\t"
        "movq 64(%rdx), %r15\n\t"
        "movq 0(%rdx), %rsp\n\t"
        "ret\n\t");
}

static shz_fiber *current_fiber(void)
{
    if (!(*(USHORT *)(shz_teb() + TEB_SAME_FLAGS) & HAS_FIBER_DATA)) return 0;
    return *(shz_fiber **)(shz_teb() + TEB_FIBER_DATA);
}

static void save_teb(shz_fiber *fiber)
{
    const uint64_t teb = shz_teb();
    fiber->stack_base = *(PVOID *)(teb + TEB_STACK_BASE);
    fiber->stack_limit = *(PVOID *)(teb + TEB_STACK_LIMIT);
    fiber->actctx = *(PVOID *)(teb + TEB_ACTCTX_STACK);
    fiber->fls = *(PVOID **)(teb + TEB_FLS_DATA);
    fiber->guaranteed_stack = *(DWORD *)(teb + TEB_GUARANTEED_STACK);
}

static void restore_teb(shz_fiber *fiber)
{
    const uint64_t teb = shz_teb();
    *(PVOID *)(teb + TEB_STACK_BASE) = fiber->stack_base;
    *(PVOID *)(teb + TEB_STACK_LIMIT) = fiber->stack_limit;
    *(PVOID *)(teb + TEB_DEALLOCATION_STACK) = fiber->stack_allocation;
    *(PVOID *)(teb + TEB_ACTCTX_STACK) = fiber->actctx;
    *(PVOID **)(teb + TEB_FLS_DATA) = fiber->fls;
    *(DWORD *)(teb + TEB_GUARANTEED_STACK) = fiber->guaranteed_stack;
    *(shz_fiber **)(teb + TEB_FIBER_DATA) = fiber;
}

static void WINAPI __attribute__((noreturn)) fiber_entry(void)
{
    shz_fiber *fiber = current_fiber();
    fiber->start(fiber->parameter);
    /* A returning FiberProc terminates the executing thread, as on Windows. */
    ExitThread(0);
    __builtin_unreachable();
}

K32API LPVOID WINAPI ConvertThreadToFiberEx(LPVOID parameter, DWORD flags)
{
    shz_fiber *fiber;
    if (flags & ~FIBER_FLAG_FLOAT_SWITCH) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (current_fiber()) { shz_set_last_error(ERROR_ALREADY_FIBER); return 0; }
    fiber = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, sizeof *fiber);
    if (!fiber) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    fiber->parameter = parameter;
    fiber->magic = FIBER_MAGIC;
    fiber->converted_owner = shz_tid();
    fiber->stack_allocation = *(PVOID *)(shz_teb() + TEB_DEALLOCATION_STACK);
    save_teb(fiber);                          /* existing FLS belongs to the converted fiber */
    *(shz_fiber **)(shz_teb() + TEB_FIBER_DATA) = fiber;
    *(USHORT *)(shz_teb() + TEB_SAME_FLAGS) |= HAS_FIBER_DATA;
    return fiber;
}

K32API LPVOID WINAPI ConvertThreadToFiber(LPVOID parameter)
{
    return ConvertThreadToFiberEx(parameter, 0);
}

K32API BOOL WINAPI ConvertFiberToThread(void)
{
    shz_fiber *fiber = current_fiber();
    if (!fiber) { shz_set_last_error(ERROR_ALREADY_THREAD); return FALSE; }
    /* The current stack and FLS array continue to belong to the thread. Never
     * destroy values or free its executing stack during reverse conversion.
     * Kernel64 releases its original thread stack at thread exit; a created
     * fiber converted here retains that extra stack until process teardown. */
    *(PVOID *)(shz_teb() + TEB_FIBER_DATA) = 0;
    *(USHORT *)(shz_teb() + TEB_SAME_FLAGS) &= ~HAS_FIBER_DATA;
    fiber->magic = 0;
    RtlFreeHeap(ShzProcessHeap(), 0, fiber);
    return TRUE;
}

K32API LPVOID WINAPI CreateFiberEx(SIZE_T commit, SIZE_T reserve, DWORD flags,
                                  LPFIBER_START_ROUTINE start, LPVOID parameter)
{
    shz_fiber *fiber;
    PVOID memory;
    SIZE_T bytes;
    DWORD old;
    if ((flags & ~FIBER_FLAG_FLOAT_SWITCH) || !start) { shz_set_last_error(ERROR_INVALID_PARAMETER); return 0; }
    if (!reserve) {
        const IMAGE_DOS_HEADER *dos = (const IMAGE_DOS_HEADER *)GetModuleHandleW(0);
        const IMAGE_NT_HEADERS64 *nt = (const IMAGE_NT_HEADERS64 *)((const char *)dos + dos->e_lfanew);
        reserve = nt->OptionalHeader.SizeOfStackReserve;
        if (!commit) commit = nt->OptionalHeader.SizeOfStackCommit;
    }
    if (!reserve) reserve = 0x100000;
    if (commit < 8192) commit = 8192;
    if (commit > (SIZE_T)-1 - 0x10000 || reserve > (SIZE_T)-1 - 0x10000) {
        shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0;
    }
    if (reserve < commit + 4096) reserve = commit + 4096;
    bytes = (reserve + 0xffff) & ~(SIZE_T)0xffff;
    fiber = RtlAllocateHeap(ShzProcessHeap(), HEAP_ZERO_MEMORY, sizeof *fiber);
    if (!fiber) { shz_set_last_error(ERROR_NOT_ENOUGH_MEMORY); return 0; }
    memory = VirtualAlloc(0, bytes, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!memory) { RtlFreeHeap(ShzProcessHeap(), 0, fiber); return 0; }
    if (!VirtualProtect(memory, 4096, PAGE_NOACCESS, &old)) {
        DWORD error = shz_last_error();
        VirtualFree(memory, 0, MEM_RELEASE);
        RtlFreeHeap(ShzProcessHeap(), 0, fiber);
        shz_set_last_error(error);
        return 0;
    }
    fiber->parameter = parameter;
    fiber->magic = FIBER_MAGIC;
    fiber->start = start;
    fiber->owns_stack = TRUE;
    fiber->stack_allocation = memory;
    fiber->stack_base = (char *)memory + bytes;
    fiber->stack_limit = (char *)memory + 4096;
    fiber->context.rsp = (uint64_t)fiber->stack_base - 48;
    *(uint64_t *)(ULONG_PTR)fiber->context.rsp = (uint64_t)(ULONG_PTR)fiber_entry;
    *(uint64_t *)(ULONG_PTR)(fiber->context.rsp + 8) = 0;  /* fiber_entry never returns */
    *(USHORT *)(fiber->context.fp + 0) = 0x027f;          /* masked exceptions, Win64 default control */
    *(DWORD *)(fiber->context.fp + 24) = 0x1f80;          /* MXCSR, round to nearest */
    return fiber;
}

K32API LPVOID WINAPI CreateFiber(SIZE_T stack, LPFIBER_START_ROUTINE start, LPVOID parameter)
{
    return CreateFiberEx(stack, 0, 0, start, parameter);
}

K32API VOID WINAPI SwitchToFiber(LPVOID target)
{
    shz_fiber *old = current_fiber(), *next = target;
    if (!old || !next || old->magic != FIBER_MAGIC || next->magic != FIBER_MAGIC || next->deleting) {
        shz_set_last_error(ERROR_INVALID_PARAMETER); return;
    }
    if (!next->owns_stack && next->converted_owner != shz_tid()) {
        /* Created fibers may migrate under caller synchronization. Original
         * thread stacks cannot: the owning kernel thread would release that
         * live stack on exit. Reject until kernel stack ownership can transfer. */
        k32_unsupported("SwitchToFiber", "converted original stack cannot migrate between kernel threads", ERROR_NOT_SUPPORTED);
        return;
    }
    if (old == next) return;                   /* unspecified by Windows; avoid corrupting a live stack */
    save_teb(old);
    restore_teb(next);
    switch_context(&old->context, &next->context);
    /* Created fibers are unbound to a creator thread. Caller synchronization
     * permits migration; TLS/LastError remain properties of the executing thread. */
}

K32API VOID WINAPI DeleteFiber(LPVOID pointer)
{
    shz_fiber *fiber = pointer;
    if (!fiber) return;
    if (fiber->magic != FIBER_MAGIC) { shz_set_last_error(ERROR_INVALID_PARAMETER); return; }
    if (!__sync_bool_compare_and_swap(&fiber->deleting, 0, 1)) return;  /* callback recursive deletion */
    if (fiber == current_fiber()) {
        /* The current stack stays mapped while exit/loader callbacks run. */
        PVOID *data = *(PVOID **)(shz_teb() + TEB_FLS_DATA);
        *(PVOID **)(shz_teb() + TEB_FLS_DATA) = 0;
        k32_fls_destroy_data(data);
        ExitThread(1);
        __builtin_unreachable();
    }
    k32_fls_destroy_data(fiber->fls);
    /* A converted thread's original stack remains owned by thread_t.user_stack.
     * Freeing it here would leave a stale kernel owner which could later free a
     * new VAD at the same address. Defer that original allocation to thread exit.
     * Independently created stacks have no thread_t owner and can be freed now. */
    if (fiber->owns_stack) VirtualFree(fiber->stack_allocation, 0, MEM_RELEASE);
    fiber->magic = 0;
    RtlFreeHeap(ShzProcessHeap(), 0, fiber);
}
