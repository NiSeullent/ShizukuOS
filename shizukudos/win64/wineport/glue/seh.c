/* SPDX-License-Identifier: GPL-2.0-only
 * Wine port glue: __TRY / __EXCEPT / __FINALLY of include/wine/exception.h on the Shizuku runtime.
 *
 * Wine code built with GCC (no compiler SEH) registers __WINE_FRAME records in the TEB exception list
 * (NtCurrentTeb()->Tib.ExceptionList) and saves its registers with __wine_setjmpex. On x86_64 Windows that list is not
 * consulted by the exception dispatcher; Wine's own ntdll walks it as a special case. The Shizuku ntdll does not, so this
 * module installs one vectored exception handler per module on first use that does the same walk:
 *   - each registered frame that is still live (above the faulting RSP, inside the thread's stack) is offered the
 *     exception through its Handler, innermost first (the Handler functions below keep Wine's calling protocol);
 *   - when a frame's filter answers EXCEPTION_EXECUTE_HANDLER, the __FINALLY frames registered after it are run with
 *     AbnormalTermination() == TRUE, the frame is popped and the thread resumes at the frame's saved registers with
 *     __wine_setjmpex returning 1 (the CONTEXT of the exception is rewritten; no RtlUnwind is involved).
 * Limitation (documented): a vectored handler runs before frame-based SEH handlers, so a real SEH handler of foreign
 * code called from inside a Wine __TRY block does not see the exception first when the Wine filter accepts it.
 */
#include <stdarg.h>
#include "windef.h"
#include "winbase.h"
#include "winternl.h"
#include "wine/exception.h"

#define SHZW_EXECUTE_HANDLER 0x53485a31u        /* private Handler result: "unwind to this frame" */

/* __wine_jmp_buf layout used here (same order as the CRT _JUMP_BUFFER):
 *   0 Frame 8 Rbx 16 Rsp 24 Rbp 32 Rsi 40 Rdi 48 R12 56 R13 64 R14 72 R15 80 Rip 88 MxCsr 92 FpCsr 96.. Xmm6-15 */
__asm__(".text\n\t"
        ".globl __wine_setjmpex\n\t"
        ".def __wine_setjmpex; .scl 2; .type 32; .endef\n"
        "__wine_setjmpex:\n\t"
        "movq %rdx,0(%rcx)\n\t"
        "movq %rbx,8(%rcx)\n\t"
        "leaq 8(%rsp),%rax\n\t"
        "movq %rax,16(%rcx)\n\t"
        "movq %rbp,24(%rcx)\n\t"
        "movq %rsi,32(%rcx)\n\t"
        "movq %rdi,40(%rcx)\n\t"
        "movq %r12,48(%rcx)\n\t"
        "movq %r13,56(%rcx)\n\t"
        "movq %r14,64(%rcx)\n\t"
        "movq %r15,72(%rcx)\n\t"
        "movq (%rsp),%rax\n\t"
        "movq %rax,80(%rcx)\n\t"
        "stmxcsr 88(%rcx)\n\t"
        "fnstcw 92(%rcx)\n\t"
        "movdqa %xmm6,96(%rcx)\n\t"
        "movdqa %xmm7,112(%rcx)\n\t"
        "movdqa %xmm8,128(%rcx)\n\t"
        "movdqa %xmm9,144(%rcx)\n\t"
        "movdqa %xmm10,160(%rcx)\n\t"
        "movdqa %xmm11,176(%rcx)\n\t"
        "movdqa %xmm12,192(%rcx)\n\t"
        "movdqa %xmm13,208(%rcx)\n\t"
        "movdqa %xmm14,224(%rcx)\n\t"
        "movdqa %xmm15,240(%rcx)\n\t"
        "subq $40,%rsp\n\t"
        "call shzw_seh_install\n\t"            /* once per module; preserves nothing we need */
        "addq $40,%rsp\n\t"
        "xorl %eax,%eax\n\t"
        "ret\n\t"
        ".globl __wine_longjmp\n\t"
        ".def __wine_longjmp; .scl 2; .type 32; .endef\n"
        "__wine_longjmp:\n\t"
        "movl %edx,%eax\n\t"
        "movq 8(%rcx),%rbx\n\t"
        "movq 24(%rcx),%rbp\n\t"
        "movq 32(%rcx),%rsi\n\t"
        "movq 40(%rcx),%rdi\n\t"
        "movq 48(%rcx),%r12\n\t"
        "movq 56(%rcx),%r13\n\t"
        "movq 64(%rcx),%r14\n\t"
        "movq 72(%rcx),%r15\n\t"
        "ldmxcsr 88(%rcx)\n\t"
        "fnclex\n\t"
        "fldcw 92(%rcx)\n\t"
        "movdqa 96(%rcx),%xmm6\n\t"
        "movdqa 112(%rcx),%xmm7\n\t"
        "movdqa 128(%rcx),%xmm8\n\t"
        "movdqa 144(%rcx),%xmm9\n\t"
        "movdqa 160(%rcx),%xmm10\n\t"
        "movdqa 176(%rcx),%xmm11\n\t"
        "movdqa 192(%rcx),%xmm12\n\t"
        "movdqa 208(%rcx),%xmm13\n\t"
        "movdqa 224(%rcx),%xmm14\n\t"
        "movdqa 240(%rcx),%xmm15\n\t"
        "movq 16(%rcx),%rsp\n\t"
        "jmpq *80(%rcx)\n\t");

/* ---------------------------------------------------------------- Handler functions (Wine protocol) */
static DWORD filter_result(LONG r)
{
    switch (r) {
    case EXCEPTION_CONTINUE_SEARCH: return ExceptionContinueSearch;
    case EXCEPTION_CONTINUE_EXECUTION: return ExceptionContinueExecution;
    default: return SHZW_EXECUTE_HANDLER;
    }
}

DWORD __cdecl __wine_exception_handler(EXCEPTION_RECORD *record, EXCEPTION_REGISTRATION_RECORD *frame,
                                       CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **pdispatcher)
{
    __WINE_FRAME *wf = (__WINE_FRAME *)frame;
    EXCEPTION_POINTERS ptrs = { record, context };
    if (record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | EXCEPTION_NESTED_CALL))
        return ExceptionContinueSearch;
    return filter_result(wf->u.filter(&ptrs));
}

DWORD __cdecl __wine_exception_ctx_handler(EXCEPTION_RECORD *record, EXCEPTION_REGISTRATION_RECORD *frame,
                                           CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **pdispatcher)
{
    __WINE_FRAME *wf = (__WINE_FRAME *)frame;
    EXCEPTION_POINTERS ptrs = { record, context };
    if (record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | EXCEPTION_NESTED_CALL))
        return ExceptionContinueSearch;
    return filter_result(wf->u.filter_ctx(&ptrs, wf->ctx));
}

DWORD __cdecl __wine_exception_handler_page_fault(EXCEPTION_RECORD *record, EXCEPTION_REGISTRATION_RECORD *frame,
                                                  CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **pdispatcher)
{
    if (record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | EXCEPTION_NESTED_CALL))
        return ExceptionContinueSearch;
    return record->ExceptionCode == STATUS_ACCESS_VIOLATION ? SHZW_EXECUTE_HANDLER : ExceptionContinueSearch;
}

DWORD __cdecl __wine_exception_handler_all(EXCEPTION_RECORD *record, EXCEPTION_REGISTRATION_RECORD *frame,
                                           CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **pdispatcher)
{
    if (record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND | EXCEPTION_NESTED_CALL))
        return ExceptionContinueSearch;
    return SHZW_EXECUTE_HANDLER;
}

DWORD __cdecl __wine_finally_handler(EXCEPTION_RECORD *record, EXCEPTION_REGISTRATION_RECORD *frame,
                                     CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **pdispatcher)
{
    if (record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND))
        ((__WINE_FRAME *)frame)->u.finally_func(FALSE);
    return ExceptionContinueSearch;
}

DWORD __cdecl __wine_finally_ctx_handler(EXCEPTION_RECORD *record, EXCEPTION_REGISTRATION_RECORD *frame,
                                         CONTEXT *context, EXCEPTION_REGISTRATION_RECORD **pdispatcher)
{
    if (record->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
        __WINE_FRAME *wf = (__WINE_FRAME *)frame;
        wf->u.finally_func_ctx(FALSE, wf->ctx);
    }
    return ExceptionContinueSearch;
}

/* ---------------------------------------------------------------- dispatcher */
static BOOL frame_live(const EXCEPTION_REGISTRATION_RECORD *f, const CONTEXT *ctx)
{
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    ULONG_PTR p = (ULONG_PTR)f;
    if (!f || p == ~(ULONG_PTR)0 || (p & 7)) return FALSE;
    if (p <= ctx->Rsp) return FALSE;
    if (tib->StackBase && p >= (ULONG_PTR)tib->StackBase) return FALSE;
    return TRUE;
}

static void resume_at_frame(__WINE_FRAME *wf, CONTEXT *ctx)
{
    const ULONG64 *r = (const ULONG64 *)&wf->jmp;
    ctx->Rbx = r[1]; ctx->Rsp = r[2]; ctx->Rbp = r[3]; ctx->Rsi = r[4]; ctx->Rdi = r[5];
    ctx->R12 = r[6]; ctx->R13 = r[7]; ctx->R14 = r[8]; ctx->R15 = r[9]; ctx->Rip = r[10];
    ctx->MxCsr = (DWORD)r[11];
    ctx->FltSave.MxCsr = ctx->MxCsr;
    memcpy(&ctx->Xmm6, (const char *)&wf->jmp + 96, 10 * 16);
    ctx->Rax = 1;                                       /* __wine_setjmpex returns 1 */
}

static LONG CALLBACK shzw_teb_frames_veh(EXCEPTION_POINTERS *ptrs)
{
    NT_TIB *tib = (NT_TIB *)NtCurrentTeb();
    EXCEPTION_RECORD *rec = ptrs->ExceptionRecord;
    CONTEXT *ctx = ptrs->ContextRecord;
    EXCEPTION_REGISTRATION_RECORD *f, *dispatcher = NULL;
    for (f = tib->ExceptionList; frame_live(f, ctx); f = f->Prev) {
        DWORD r = ((DWORD (__cdecl *)(EXCEPTION_RECORD *, EXCEPTION_REGISTRATION_RECORD *, CONTEXT *,
                                      EXCEPTION_REGISTRATION_RECORD **))f->Handler)(rec, f, ctx, &dispatcher);
        if (r == ExceptionContinueExecution) return EXCEPTION_CONTINUE_EXECUTION;
        if (r == SHZW_EXECUTE_HANDLER) {
            __WINE_FRAME *target = (__WINE_FRAME *)f;
            EXCEPTION_REGISTRATION_RECORD *g;
            DWORD saved = rec->ExceptionFlags;
            rec->ExceptionFlags |= EXCEPTION_UNWINDING;          /* run the __FINALLY blocks being left */
            for (g = tib->ExceptionList; g && g != f; g = g->Prev)
                ((DWORD (__cdecl *)(EXCEPTION_RECORD *, EXCEPTION_REGISTRATION_RECORD *, CONTEXT *,
                                    EXCEPTION_REGISTRATION_RECORD **))g->Handler)(rec, g, ctx, &dispatcher);
            rec->ExceptionFlags = saved;
            target->ExceptionCode = rec->ExceptionCode;         /* GetExceptionCode() inside __EXCEPT */
            target->ExceptionRecord = target;
            tib->ExceptionList = f->Prev;                       /* pop the frame, as the unwind target would */
            resume_at_frame(target, ctx);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

static LONG installed;

void shzw_seh_install(void)
{
    if (installed == 1) return;
    if (InterlockedCompareExchange(&installed, 2, 0) == 0) {
        AddVectoredExceptionHandler(0, shzw_teb_frames_veh);
        installed = 1;
    }
}
