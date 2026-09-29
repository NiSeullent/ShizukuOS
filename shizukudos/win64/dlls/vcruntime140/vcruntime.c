/* SPDX-License-Identifier: GPL-2.0-only
 * vcruntime140.dll for the Shizuku Win64 runtime: C++ exception handling for the Microsoft x64 ABI (_CxxThrowException,
 * __CxxFrameHandler3), structured exception handling for C (__C_specific_handler, _local_unwind), setjmp/longjmp with
 * unwinding, RTTI (typeid, dynamic_cast), the std::exception / std::type_info helpers the STL headers call, and the
 * small runtime services (purecall, uncaught exceptions, ...). The string functions are forwarded to ucrtbase.dll
 * (module.json). Own implementation; the exception engine is ehengine.h, shared with vcruntime140_1.dll (FH4).
 */
#define VCR_LOCAL_THROW
#include "ehengine.h"
DLLAPI VCR_NORETURN void __stdcall _CxxThrowException(void *obj, const eh_throwinfo *ti);
#include "cxxclass.h"

/* ------------------------------------------------------------------ per-thread state */
static DWORD g_tls = TLS_OUT_OF_INDEXES;
static PVOID g_veh;

static vcr_ptd *vcr_ptd_get(void)
{
    vcr_ptd *t;
    DWORD err;
    if (g_tls == TLS_OUT_OF_INDEXES) return 0;
    err = GetLastError();
    t = TlsGetValue(g_tls);
    if (!t && (t = vcr_zalloc(sizeof *t)) != 0) {
        t->magic = VCR_PTD_MAGIC;
        TlsSetValue(g_tls, t);
    }
    SetLastError(err);
    return t;
}
static void vcr_ptd_free(void)
{
    vcr_ptd *t;
    if (g_tls == TLS_OUT_OF_INDEXES || !(t = TlsGetValue(g_tls))) return;
    while (t->catches) {
        vcr_catchrec *r = t->catches;
        t->catches = r->next;
        vcr_free(r);
    }
    TlsSetValue(g_tls, 0);
    vcr_free(t);
}

/* Every dispatch passes here first: note the context the exception was raised in (the frame handlers unwind from it)
 * and drop catch records the thread can no longer be inside. */
static LONG WINAPI vcr_veh(EXCEPTION_POINTERS *ep)
{
    const DWORD err = GetLastError();
    vcr_ptd *t = vcr_ptd_get();
    if (t && ep && ep->ExceptionRecord && ep->ContextRecord) {
        prune_stale(t, ep->ContextRecord->Rsp);
        t->seen[t->seen_next % VCR_SEEN].rec = ep->ExceptionRecord;
        t->seen[t->seen_next % VCR_SEEN].ctx = ep->ContextRecord;
        ++t->seen_next;
    }
    SetLastError(err);
    return EXCEPTION_CONTINUE_SEARCH;
}

static void rtti_init(void);

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID reserved)
{
    (void)inst; (void)reserved;
    switch (reason) {
    case DLL_PROCESS_ATTACH:
        g_tls = TlsAlloc();
        if (g_tls == TLS_OUT_OF_INDEXES) return FALSE;
        g_veh = AddVectoredExceptionHandler(1, vcr_veh);
        rtti_init();
        break;
    case DLL_THREAD_DETACH:
        vcr_ptd_free();
        break;
    case DLL_PROCESS_DETACH:
        if (g_veh) RemoveVectoredExceptionHandler(g_veh);
        vcr_ptd_free();
        break;
    default:
        break;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ FH3 tables */
static const fh3_funcinfo *fh3(const eh_func *f) { return (const fh3_funcinfo *)f->info; }
static int fh3_state(const eh_func *f, uint64_t pc)
{
    const fh3_funcinfo *fi = fh3(f);
    const int32_t *m = (const int32_t *)(f->base + (uint32_t)fi->ip_map);
    int st = -1;
    uint32_t i;
    if (!fi->ip_map) return -1;
    for (i = 0; i < fi->nip; ++i) {                  /* last entry at or below pc (return addresses included) */
        if (pc < f->base + (uint32_t)m[2 * i]) break;
        st = m[2 * i + 1];
    }
    return st;
}
static int fh3_to_state(const eh_func *f, int s)
{
    const fh3_funcinfo *fi = fh3(f);
    if (s < 0 || s >= fi->max_state || !fi->unwind_map) return -1;
    return ((const int32_t *)(f->base + (uint32_t)fi->unwind_map))[2 * s];
}
static void fh3_unwind(const eh_func *f, uint64_t frame, int from, int to)
{
    const fh3_funcinfo *fi = fh3(f);
    const int32_t *um = (const int32_t *)(f->base + (uint32_t)fi->unwind_map);
    int s = from, steps = 0;
    if (!fi->unwind_map) return;
    while (s > to && s < fi->max_state && steps++ <= fi->max_state) {
        const int32_t action = um[2 * s + 1];
        s = um[2 * s];
        if (action) vcr_call_guarded(f->base + (uint32_t)action, frame, frame, 0);    /* cleanup funclet(_, frame) */
    }
}
static unsigned fh3_ntry(const eh_func *f) { return fh3(f)->try_map ? fh3(f)->ntry : 0; }
static void fh3_get_try(const eh_func *f, unsigned i, eh_try *t)
{
    const fh3_try *tb = (const fh3_try *)(f->base + (uint32_t)fh3(f)->try_map) + i;
    t->low = tb->low;
    t->high = tb->high;
    t->catch_high = tb->catch_high;
    t->ncatch = (uint32_t)tb->ncatch;
    t->catches = (const uint8_t *)(f->base + (uint32_t)tb->handlers);
}
static void fh3_get_catch(const eh_func *f, const eh_try *t, unsigned j, eh_catch *c)
{
    const fh3_handler *h = (const fh3_handler *)t->catches + j;
    (void)f;
    c->adjectives = h->adjectives;
    c->type = h->type;
    c->catch_obj = h->catch_obj;
    c->handler = h->handler;
    c->frame = h->frame;
    c->ncont = 0;
    c->cont[0] = c->cont[1] = 0;
}
static int fh3_is_cleanup(const eh_func *f, uint32_t rva)
{
    const fh3_funcinfo *fi = fh3(f);
    const int32_t *um = (const int32_t *)(f->base + (uint32_t)fi->unwind_map);
    int s;
    for (s = 0; fi->unwind_map && s < fi->max_state; ++s)
        if (um[2 * s + 1] && (uint32_t)um[2 * s + 1] == rva) return 1;
    return 0;
}
static const eh_ops fh3_ops = { fh3_state, fh3_to_state, fh3_unwind, fh3_ntry, fh3_get_try, fh3_get_catch, fh3_is_cleanup };

DLLAPI EXCEPTION_DISPOSITION __CxxFrameHandler3(EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc)
{
    const fh3_funcinfo *fi = (const fh3_funcinfo *)(dc->ImageBase + *(const uint32_t *)dc->HandlerData);
    const uint32_t magic = fi->magic & 0x1fffffffu;
    eh_func f;
    if (magic < EH_MAGIC_1 || magic > EH_MAGIC_3) return ExceptionContinueSearch;
    memset(&f, 0, sizeof f);
    f.ops = &fh3_ops;
    f.info = fi;
    f.base = dc->ImageBase;
    f.flags = magic >= EH_MAGIC_3 ? (uint32_t)fi->flags : 0;
    return cxx_frame_handler(&f, rec, (uint64_t)frame, ctx, dc);
}

/* ------------------------------------------------------------------ throwing */
DLLAPI VCR_NORETURN void __stdcall _CxxThrowException(void *obj, const eh_throwinfo *ti)
{
    vcr_ptd *t = vcr_ptd_get();
    ULONG_PTR args[4];
    if (t) prune_stale(t, (uint64_t)__builtin_frame_address(0));
    if (!ti) {                                       /* throw; : the exception of the innermost running catch */
        vcr_catchrec *r = t ? t->catches : 0;
        while (r && r->done) r = r->next;
        if (!r) terminate();
        if (!r->is_cxx)                              /* a structured exception caught by catch(...) under /EHa */
            RaiseException(r->rec.ExceptionCode, r->rec.ExceptionFlags, r->rec.NumberParameters, r->rec.ExceptionInformation);
        args[0] = r->rec.ExceptionInformation[0];
        args[1] = r->rec.ExceptionInformation[1];
        args[2] = r->rec.ExceptionInformation[2];
        args[3] = r->rec.ExceptionInformation[3];
    } else {
        PVOID base = 0;
        RtlPcToFileHeader((PVOID)ti, &base);
        args[0] = (ti->attributes & TI_PURE) ? EH_PURE_MAGIC : EH_MAGIC_1;
        args[1] = (ULONG_PTR)obj;
        args[2] = (ULONG_PTR)ti;
        args[3] = (ULONG_PTR)base;
    }
    if (t) ++t->processing_throw;
    RaiseException(EH_EXCEPTION_CODE, EXCEPTION_NONCONTINUABLE, 4, args);
    for (;;) terminate();
}

/* ------------------------------------------------------------------ structured exception handling (C) */
typedef struct { uint32_t count; struct { uint32_t begin, end, handler, target; } e[1]; } scope_table;

static VCR_NORETURN void seh_execute(vcr_ptd *t, EXCEPTION_RECORD *rec, uint64_t frame, uint64_t target_ip, const CONTEXT *frame_ctx)
{
    EXCEPTION_RECORD urec = *rec;
    CONTEXT *start = vcr_zalloc(sizeof(CONTEXT) * 2), *out;
    if (!start || !t) terminate();
    out = start + 1;
    if (!origin_context(t, rec, start)) RtlCaptureContext(start);
    if (!vcr_unwind(t, start, &urec, frame, 0, target_ip, 1, out)) *out = *frame_ctx;
    pop_done(t);
    {
        CONTEXT resume = *out;
        vcr_free(start);
        resume.Rip = target_ip;
        resume.Rax = rec->ExceptionCode;             /* GetExceptionCode() in the __except block */
        resume.ContextFlags = CONTEXT_RESUME_;
        RtlRestoreContext(&resume, 0);
    }
    for (;;) terminate();
}

DLLAPI EXCEPTION_DISPOSITION __C_specific_handler(EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc)
{
    const scope_table *st = (const scope_table *)dc->HandlerData;
    const uint64_t base = dc->ImageBase, pc = dc->ControlPc - base;
    vcr_ptd *t = vcr_ptd_get();
    uint32_t i;
    if (t && in_dead_zone(t, (uint64_t)frame)) return ExceptionContinueSearch;
    if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
        const uint64_t tpc = dc->TargetIp - base;
        for (i = dc->ScopeIndex; i < st->count; ++i) {
            if (pc < st->e[i].begin || pc >= st->e[i].end) continue;
            if (rec->ExceptionFlags & EXCEPTION_TARGET_UNWIND) {
                uint32_t k;                          /* the target lies inside this same scope: stop */
                for (k = 0; k < st->count; ++k)
                    if (tpc >= st->e[k].begin && tpc < st->e[k].end && st->e[k].target == st->e[i].target &&
                        st->e[k].handler == st->e[i].handler) break;
                if (k != st->count) break;
            }
            if (st->e[i].target) {
                if ((rec->ExceptionFlags & EXCEPTION_TARGET_UNWIND) && tpc == st->e[i].target) break;
            } else {                                 /* __finally: abnormal termination */
                dc->ScopeIndex = i + 1;
                ((void (*)(BOOLEAN, uint64_t))(base + st->e[i].handler))(TRUE, (uint64_t)frame);
            }
        }
        return ExceptionContinueSearch;
    }
    for (i = dc->ScopeIndex; i < st->count; ++i) {
        LONG r;
        CONTEXT *orig = origin_ptr(t, rec);
        if (pc < st->e[i].begin || pc >= st->e[i].end || !st->e[i].target) continue;
        if (st->e[i].handler == 1) {
            r = EXCEPTION_EXECUTE_HANDLER;
        } else {
            EXCEPTION_POINTERS ep;
            ep.ExceptionRecord = rec;
            ep.ContextRecord = orig ? orig : ctx;
            r = ((LONG (*)(EXCEPTION_POINTERS *, uint64_t))(base + st->e[i].handler))(&ep, (uint64_t)frame);
        }
        if (r < 0) {                                 /* EXCEPTION_CONTINUE_EXECUTION: resume the (filtered) origin */
            if (orig && !(rec->ExceptionFlags & EXCEPTION_NONCONTINUABLE)) RtlRestoreContext(orig, 0);
            return ExceptionContinueExecution;
        }
        if (r > 0) seh_execute(t, rec, (uint64_t)frame, base + st->e[i].target, ctx);
    }
    return ExceptionContinueSearch;
}

DLLAPI EXCEPTION_DISPOSITION __C_specific_handler_noexcept(EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc)
{
    const EXCEPTION_DISPOSITION d = __C_specific_handler(rec, frame, ctx, dc);
    if (d == ExceptionContinueSearch && !(rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) &&
        is_cxx_exception(rec)) terminate();          /* a C++ exception leaves a noexcept function */
    return d;
}

/* goto / return out of a __try with __finally: run the termination handlers between here and `target` in `frame` */
DLLAPI void _local_unwind(void *frame, void *target)
{
    vcr_ptd *t = vcr_ptd_get();
    EXCEPTION_RECORD rec;
    CONTEXT *c = vcr_zalloc(sizeof(CONTEXT) * 2);
    if (!c || !t) terminate();
    memset(&rec, 0, sizeof rec);
    rec.ExceptionCode = STATUS_UNWIND_;
    RtlCaptureContext(c);
    if (vcr_unwind(t, c, &rec, (uint64_t)frame, 0, (uint64_t)target, 1, c + 1)) {
        CONTEXT resume = c[1];
        vcr_free(c);
        pop_done(t);
        resume.Rip = (uint64_t)target;
        resume.Rax = 0;
        resume.ContextFlags = CONTEXT_RESUME_;
        RtlRestoreContext(&resume, 0);
    }
    vcr_free(c);
}

/* ------------------------------------------------------------------ setjmp / longjmp */
DLLAPI int __intrinsic_setjmp(vcr_jmpbuf *jb, void *frame);
DLLAPI int __intrinsic_setjmpex(vcr_jmpbuf *jb, void *frame);
VCR_NORETURN void vcr_longjmp_restore(vcr_jmpbuf *jb, int value);
#define SETJMP_BODY(frame_insn)                                                        \
    frame_insn                                                                         \
    "    movq %rbx, 8(%rcx)\n"                                                         \
    "    leaq 8(%rsp), %rax\n"                                                         \
    "    movq %rax, 16(%rcx)\n"                                                        \
    "    movq %rbp, 24(%rcx)\n"                                                        \
    "    movq %rsi, 32(%rcx)\n"                                                        \
    "    movq %rdi, 40(%rcx)\n"                                                        \
    "    movq %r12, 48(%rcx)\n"                                                        \
    "    movq %r13, 56(%rcx)\n"                                                        \
    "    movq %r14, 64(%rcx)\n"                                                        \
    "    movq %r15, 72(%rcx)\n"                                                        \
    "    movq (%rsp), %rax\n"                                                          \
    "    movq %rax, 80(%rcx)\n"                                                        \
    "    stmxcsr 88(%rcx)\n"                                                           \
    "    fnstcw 92(%rcx)\n"                                                            \
    "    movdqu %xmm6, 96(%rcx)\n"                                                     \
    "    movdqu %xmm7, 112(%rcx)\n"                                                    \
    "    movdqu %xmm8, 128(%rcx)\n"                                                    \
    "    movdqu %xmm9, 144(%rcx)\n"                                                    \
    "    movdqu %xmm10, 160(%rcx)\n"                                                   \
    "    movdqu %xmm11, 176(%rcx)\n"                                                   \
    "    movdqu %xmm12, 192(%rcx)\n"                                                   \
    "    movdqu %xmm13, 208(%rcx)\n"                                                   \
    "    movdqu %xmm14, 224(%rcx)\n"                                                   \
    "    movdqu %xmm15, 240(%rcx)\n"                                                   \
    "    xorl %eax, %eax\n"                                                            \
    "    ret\n"
__asm__(
    ".text\n"
    ".globl __intrinsic_setjmp\n"
    ".def __intrinsic_setjmp; .scl 2; .type 32; .endef\n"
    "__intrinsic_setjmp:\n"
    SETJMP_BODY("    movq $0, (%rcx)\n")               /* no Frame: longjmp restores registers only */
    ".globl __intrinsic_setjmpex\n"
    ".def __intrinsic_setjmpex; .scl 2; .type 32; .endef\n"
    "__intrinsic_setjmpex:\n"
    SETJMP_BODY("    movq %rdx, (%rcx)\n")             /* Frame: longjmp unwinds to it */
    ".globl vcr_longjmp_restore\n"
    ".def vcr_longjmp_restore; .scl 2; .type 32; .endef\n"
    "vcr_longjmp_restore:\n"
    "    movl %edx, %eax\n"
    "    movq 8(%rcx), %rbx\n"
    "    movq 24(%rcx), %rbp\n"
    "    movq 32(%rcx), %rsi\n"
    "    movq 40(%rcx), %rdi\n"
    "    movq 48(%rcx), %r12\n"
    "    movq 56(%rcx), %r13\n"
    "    movq 64(%rcx), %r14\n"
    "    movq 72(%rcx), %r15\n"
    "    ldmxcsr 88(%rcx)\n"
    "    fnclex\n"
    "    fldcw 92(%rcx)\n"
    "    movdqu 96(%rcx), %xmm6\n"
    "    movdqu 112(%rcx), %xmm7\n"
    "    movdqu 128(%rcx), %xmm8\n"
    "    movdqu 144(%rcx), %xmm9\n"
    "    movdqu 160(%rcx), %xmm10\n"
    "    movdqu 176(%rcx), %xmm11\n"
    "    movdqu 192(%rcx), %xmm12\n"
    "    movdqu 208(%rcx), %xmm13\n"
    "    movdqu 224(%rcx), %xmm14\n"
    "    movdqu 240(%rcx), %xmm15\n"
    "    movq 16(%rcx), %rsp\n"
    "    jmpq *80(%rcx)\n");

DLLAPI VCR_NORETURN void longjmp(vcr_jmpbuf *jb, int value)
{
    if (!value) value = 1;
    if (jb->Frame) {                                 /* run __finally blocks and destructors up to the setjmp frame */
        vcr_ptd *t = vcr_ptd_get();
        EXCEPTION_RECORD rec;
        CONTEXT *c = vcr_zalloc(sizeof(CONTEXT) * 2);
        if (t && c) {
            memset(&rec, 0, sizeof rec);
            rec.ExceptionCode = STATUS_LONGJUMP_;
            rec.NumberParameters = 1;
            rec.ExceptionInformation[0] = (ULONG_PTR)jb;
            RtlCaptureContext(c);
            vcr_unwind(t, c, &rec, 0, jb->Rsp, jb->Rip, 1, c + 1);
            pop_done(t);
        }
        vcr_free(c);
    }
    vcr_longjmp_restore(jb, value);
}

/* ------------------------------------------------------------------ exception state */
DLLAPI void **__current_exception(void)
{
    vcr_ptd *t = vcr_ptd_get();
    return t ? &t->cur_exception : 0;
}
DLLAPI void **__current_exception_context(void)
{
    vcr_ptd *t = vcr_ptd_get();
    return t ? &t->cur_context : 0;
}
DLLAPI int *__processing_throw(void)
{
    vcr_ptd *t = vcr_ptd_get();
    return t ? &t->processing_throw : 0;
}
DLLAPI BOOL __uncaught_exception(void)
{
    vcr_ptd *t = vcr_ptd_get();
    return t && t->processing_throw != 0;
}
DLLAPI int __uncaught_exceptions(void)
{
    vcr_ptd *t = vcr_ptd_get();
    return t ? t->processing_throw : 0;
}
typedef void (*vcr_se_translator)(unsigned, EXCEPTION_POINTERS *);
DLLAPI vcr_se_translator _set_se_translator(vcr_se_translator fn)
{
    vcr_ptd *t = vcr_ptd_get();
    vcr_se_translator old = t ? (vcr_se_translator)t->se_translator : 0;
    if (t) t->se_translator = (void *)fn;
    return old;
}
typedef void (*vcr_unexpected_fn)(void);
DLLAPI vcr_unexpected_fn set_unexpected(vcr_unexpected_fn fn)
{
    vcr_ptd *t = vcr_ptd_get();
    vcr_unexpected_fn old = t ? (vcr_unexpected_fn)t->unexpected : 0;
    if (t) t->unexpected = (void *)fn;
    return old;
}
DLLAPI vcr_unexpected_fn _get_unexpected(void)
{
    vcr_ptd *t = vcr_ptd_get();
    return t ? (vcr_unexpected_fn)t->unexpected : 0;
}
DLLAPI VCR_NORETURN void unexpected(void)
{
    vcr_unexpected_fn fn = _get_unexpected();
    if (fn) fn();
    terminate();
}
DLLAPI VCR_NORETURN void __std_terminate(void) { terminate(); }

/* Exception objects registered by code that handles them outside a catch block (the STL's exception_ptr, C++/CLI). */
typedef struct { void *prev_exception, *prev_context; } vcr_exc_registration;
DLLAPI int __CxxQueryExceptionSize(void) { return (int)sizeof(vcr_exc_registration); }
DLLAPI int __CxxRegisterExceptionObject(EXCEPTION_POINTERS *ep, void *storage)
{
    vcr_ptd *t = vcr_ptd_get();
    vcr_exc_registration *reg = storage;
    if (!t || !ep || !reg) return 0;
    reg->prev_exception = t->cur_exception;
    reg->prev_context = t->cur_context;
    t->cur_exception = ep->ExceptionRecord;
    t->cur_context = ep->ContextRecord;
    return 1;
}
DLLAPI BOOL _IsExceptionObjectToBeDestroyed(void *obj)
{
    vcr_ptd *t = vcr_ptd_get();
    const vcr_catchrec *r;
    for (r = t ? t->catches : 0; r; r = r->next)
        if (!r->done && r->is_cxx && (void *)r->rec.ExceptionInformation[1] == obj) return FALSE;
    return TRUE;
}
DLLAPI void __DestructExceptionObject(EXCEPTION_RECORD *rec)
{
    if (is_cxx_exception(rec)) release_object(rec);
}
DLLAPI void __CxxUnregisterExceptionObject(void *storage, int rethrow)
{
    vcr_ptd *t = vcr_ptd_get();
    vcr_exc_registration *reg = storage;
    EXCEPTION_RECORD *cur;
    if (!t || !reg) return;
    cur = t->cur_exception;
    if (!rethrow && is_cxx_exception(cur) && _IsExceptionObjectToBeDestroyed((void *)cur->ExceptionInformation[1]))
        release_object(cur);
    t->cur_exception = reg->prev_exception;
    t->cur_context = reg->prev_context;
}
DLLAPI int __CxxDetectRethrow(EXCEPTION_POINTERS *ep)
{
    return ep && is_cxx_exception(ep->ExceptionRecord) && !ep->ExceptionRecord->ExceptionInformation[2];
}
DLLAPI void *__AdjustPointer(void *obj, const eh_pmd *pmd) { return adjust_pointer(obj, pmd); }

/* ------------------------------------------------------------------ std::exception data, std::type_info */
static void vcr_exc_copy_data(const vcr_exc_data *from, vcr_exc_data *to)
{
    if (!from->do_free || !from->what) {
        to->what = from->what;
        to->do_free = 0;
        return;
    } else {
        const size_t n = vcr_strlen(from->what) + 1;
        char *p = malloc(n);
        if (!p) return;
        vcr_memcpy(p, from->what, n);
        to->what = p;
        to->do_free = 1;
    }
}
static void vcr_exc_free_data(vcr_exc_data *d)
{
    if (d->do_free) free((void *)d->what);
    d->what = 0;
    d->do_free = 0;
}
DLLAPI void __std_exception_copy(const vcr_exc_data *from, vcr_exc_data *to) { vcr_exc_copy_data(from, to); }
DLLAPI void __std_exception_destroy(vcr_exc_data *d) { vcr_exc_free_data(d); }

typedef struct { const char *undecorated; char decorated[1]; } vcr_type_info_data;
DLLAPI int __std_type_info_compare(const vcr_type_info_data *a, const vcr_type_info_data *b)
{
    if (a == b) return 0;
    return vcr_strcmp(a->decorated + 1, b->decorated + 1);
}
DLLAPI size_t __std_type_info_hash(const vcr_type_info_data *d)
{
    uint64_t h = 14695981039346656037ull;            /* FNV-1a over the decorated name */
    const unsigned char *p = (const unsigned char *)d->decorated + 1;
    while (*p) { h ^= *p++; h *= 1099511628211ull; }
    return (size_t)h;
}

/* ---- name undecoration (type names and qualified symbol names; see CRT.md for the covered grammar) */
#define UND_CAP 1024
typedef struct {
    const char *p;
    char *names[10];                                 /* back-reference table of name fragments */
    unsigned nnames;
    char *types[10];                                 /* back-reference table of template argument types */
    unsigned ntypes;
    int bad;
} und_state;
typedef struct { char s[UND_CAP]; size_t n; } und_buf;

static void ub_put(und_buf *b, const char *s)
{
    while (*s && b->n + 1 < UND_CAP) b->s[b->n++] = *s++;
    b->s[b->n] = 0;
}
static char *und_strdup(const char *s)
{
    const size_t n = vcr_strlen(s) + 1;
    char *p = vcr_zalloc(n);
    if (p) vcr_memcpy(p, s, n);
    return p;
}
static void und_release(und_state *u)
{
    unsigned i;
    for (i = 0; i < u->nnames; ++i) vcr_free(u->names[i]);
    for (i = 0; i < u->ntypes; ++i) vcr_free(u->types[i]);
    u->nnames = u->ntypes = 0;
}
static int und_type(und_state *u, und_buf *out);
static int und_qname(und_state *u, und_buf *out);

/* one name fragment (identifier@, ?$template@args@, or a back-reference digit) */
static int und_fragment(und_state *u, und_buf *out)
{
    const char *p = u->p;
    if (*p >= '0' && *p <= '9') {
        const unsigned k = (unsigned)(*p - '0');
        if (k >= u->nnames) return 0;
        ub_put(out, u->names[k]);
        u->p = p + 1;
        return 1;
    }
    if (p[0] == '?' && p[1] == '$') {                /* template instance: own back-reference scope */
        und_state sub;
        und_buf name;
        int first = 1;
        memset(&sub, 0, sizeof sub);
        name.n = 0; name.s[0] = 0;
        sub.p = p + 2;
        while (*sub.p && *sub.p != '@') {            /* template name */
            char ch[2] = { *sub.p++, 0 };
            ub_put(&name, ch);
        }
        if (*sub.p != '@') { und_release(&sub); return 0; }
        ++sub.p;
        sub.names[sub.nnames++] = und_strdup(name.s);
        ub_put(&name, "<");
        while (*sub.p && *sub.p != '@') {
            und_buf a;
            a.n = 0; a.s[0] = 0;
            if (sub.p[0] == '$' && sub.p[1] == '0') {             /* integral constant */
                const char *q = sub.p + 2;
                int neg = 0;
                uint64_t v = 0;
                char num[24];
                int k = 0;
                if (*q == '?') { neg = 1; ++q; }
                if (*q >= '0' && *q <= '9') { v = (uint64_t)(*q - '0') + 1; ++q; }
                else {
                    while (*q >= 'A' && *q <= 'P') v = v * 16 + (uint64_t)(*q++ - 'A');
                    if (*q != '@') { und_release(&sub); return 0; }
                    ++q;
                }
                if (neg) a.s[a.n++] = '-';
                do { num[k++] = (char)('0' + v % 10); v /= 10; } while (v);
                while (k) a.s[a.n++] = num[--k];
                a.s[a.n] = 0;
                sub.p = q;
            } else if (*sub.p >= '0' && *sub.p <= '9') {         /* repeated argument type */
                const unsigned k = (unsigned)(*sub.p - '0');
                if (k >= sub.ntypes) { und_release(&sub); return 0; }
                ub_put(&a, sub.types[k]);
                ++sub.p;
            } else {
                const char *start = sub.p;
                if (!und_type(&sub, &a)) { und_release(&sub); return 0; }
                if (sub.p - start > 1 && sub.ntypes < 10) sub.types[sub.ntypes++] = und_strdup(a.s);
            }
            if (!first) ub_put(&name, ",");
            first = 0;
            ub_put(&name, a.s);
        }
        if (*sub.p != '@') { und_release(&sub); return 0; }
        ++sub.p;
        if (name.n && name.s[name.n - 1] == '>') ub_put(&name, " ");
        ub_put(&name, ">");
        u->p = sub.p;
        und_release(&sub);
        if (u->nnames < 10) u->names[u->nnames++] = und_strdup(name.s);
        ub_put(out, name.s);
        return 1;
    }
    {
        und_buf id;
        id.n = 0; id.s[0] = 0;
        while (*p && *p != '@') {
            char ch[2] = { *p++, 0 };
            ub_put(&id, ch);
        }
        if (*p != '@' || !id.n) return 0;
        u->p = p + 1;
        if (u->nnames < 10) u->names[u->nnames++] = und_strdup(id.s);
        ub_put(out, id.s);
        return 1;
    }
}
/* scope-qualified name "frag@frag@...@" -> "outer::inner" */
static int und_qname(und_state *u, und_buf *out)
{
    und_buf *parts = vcr_zalloc(sizeof(und_buf) * 8);
    unsigned n = 0, i;
    if (!parts) return 0;
    while (*u->p && *u->p != '@') {
        if (n == 8 || !und_fragment(u, &parts[n])) { vcr_free(parts); return 0; }
        ++n;
    }
    if (*u->p != '@' || !n) { vcr_free(parts); return 0; }
    ++u->p;
    for (i = n; i-- > 0;) {
        ub_put(out, parts[i].s);
        if (i) ub_put(out, "::");
    }
    vcr_free(parts);
    return 1;
}
static const char *und_basic(char c)
{
    switch (c) {
    case 'C': return "signed char";
    case 'D': return "char";
    case 'E': return "unsigned char";
    case 'F': return "short";
    case 'G': return "unsigned short";
    case 'H': return "int";
    case 'I': return "unsigned int";
    case 'J': return "long";
    case 'K': return "unsigned long";
    case 'M': return "float";
    case 'N': return "double";
    case 'O': return "long double";
    case 'X': return "void";
    case 'Z': return "...";
    default: return 0;
    }
}
static const char *und_basic_ext(char c)
{
    switch (c) {
    case 'J': return "__int64";
    case 'K': return "unsigned __int64";
    case 'N': return "bool";
    case 'W': return "wchar_t";
    case 'S': return "char16_t";
    case 'U': return "char32_t";
    case 'Q': return "char8_t";
    default: return 0;
    }
}
static const char *und_cv(char c)
{
    switch (c) {
    case 'A': return "";
    case 'B': return " const";
    case 'C': return " volatile";
    case 'D': return " const volatile";
    default: return 0;
    }
}
static int und_type(und_state *u, und_buf *out)
{
    const char c = *u->p;
    const char *s;
    if ((s = und_basic(c)) != 0) { ub_put(out, s); ++u->p; return 1; }
    if (c == '_' && (s = und_basic_ext(u->p[1])) != 0) { ub_put(out, s); u->p += 2; return 1; }
    if (c == 'V' || c == 'U' || c == 'T') {
        ub_put(out, c == 'V' ? "class " : c == 'U' ? "struct " : "union ");
        ++u->p;
        return und_qname(u, out);
    }
    if (c == 'W' && u->p[1] >= '0' && u->p[1] <= '7') {
        ub_put(out, "enum ");
        u->p += 2;
        return und_qname(u, out);
    }
    if (c == 'P' || c == 'Q' || c == 'R' || c == 'S' || c == 'A' || (c == '$' && u->p[1] == '$' && u->p[2] == 'Q')) {
        const int ref = c == 'A' || c == '$';
        const char *self_cv = c == 'Q' ? " const" : c == 'R' ? " volatile" : c == 'S' ? " const volatile" : "";
        const char *cv;
        u->p += c == '$' ? 3 : 1;
        if (*u->p != 'E') return 0;                  /* __ptr64 */
        ++u->p;
        if (!(cv = und_cv(*u->p))) return 0;
        ++u->p;
        if (!und_type(u, out)) return 0;
        ub_put(out, cv);
        ub_put(out, c == 'A' ? " & __ptr64" : c == '$' ? " && __ptr64" : " * __ptr64");
        if (!ref) ub_put(out, self_cv);
        return 1;
    }
    return 0;
}
/* Undecorate `mangled` into out: ".<type>" (RTTI type names) or "?name@scope@@..." (qualified name only). */
static int vcr_undecorate(const char *mangled, und_buf *out)
{
    und_state u;
    int ok = 0;
    memset(&u, 0, sizeof u);
    out->n = 0;
    out->s[0] = 0;
    if (mangled[0] == '.') {
        u.p = mangled + 1;
        if (u.p[0] == '?' && u.p[1] == 'A') u.p += 2;                 /* "?A" + class-kind: a named type */
        ok = und_type(&u, out) && !*u.p;
    } else if (mangled[0] == '?' && mangled[1] != '?') {
        u.p = mangled + 1;
        ok = und_qname(&u, out);
    } else if (mangled[0] == '?' && mangled[1] == '?' && (mangled[2] == '0' || mangled[2] == '1')) {
        und_buf cls;                                 /* ??0 constructor / ??1 destructor */
        const int dtor = mangled[2] == '1';
        cls.n = 0; cls.s[0] = 0;
        u.p = mangled + 3;
        if (und_qname(&u, &cls)) {
            const char *last = cls.s, *q;
            for (q = cls.s; *q; ++q) if (q[0] == ':' && q[1] == ':') last = q + 2;
            ub_put(out, cls.s);
            ub_put(out, dtor ? "::~" : "::");
            ub_put(out, last);
            ok = 1;
        }
    }
    und_release(&u);
    return ok;
}

typedef void *(*vcr_alloc_fn)(size_t);
typedef void (*vcr_free_fn)(void *);
DLLAPI char *__unDNameEx(char *buffer, const char *mangled, int buflen, vcr_alloc_fn alloc, vcr_free_fn freefn, void *get_param, unsigned flags)
{
    und_buf *b;
    size_t n;
    (void)freefn; (void)get_param; (void)flags;
    if (!mangled) return 0;
    if (!(b = vcr_zalloc(sizeof *b))) return 0;
    if (!vcr_undecorate(mangled, b)) {               /* not covered: the name as given, like undname for plain names */
        b->n = 0;
        ub_put(b, mangled);
    }
    n = b->n + 1;
    if (!buffer) {
        if (!alloc || !(buffer = alloc(n))) { vcr_free(b); return 0; }
        buflen = (int)n;
    }
    if (buflen <= 0) { vcr_free(b); return 0; }
    if ((size_t)buflen < n) n = (size_t)buflen;
    vcr_memcpy(buffer, b->s, n - 1);
    buffer[n - 1] = 0;
    vcr_free(b);
    return buffer;
}
DLLAPI char *__unDName(char *buffer, const char *mangled, int buflen, vcr_alloc_fn alloc, vcr_free_fn freefn, unsigned flags)
{
    return __unDNameEx(buffer, mangled, buflen, alloc, freefn, 0, flags);
}

/* type_info::name(): undecorated once, cached in the type_info, the string chained on the module's list */
typedef struct vcr_name_node { struct vcr_name_node *next; char name[1]; } vcr_name_node;
DLLAPI const char *__std_type_info_name(vcr_type_info_data *d, void *root)
{
    und_buf *b;
    vcr_name_node *node;
    size_t n;
    const char *cached = __atomic_load_n(&d->undecorated, __ATOMIC_ACQUIRE);
    if (cached) return cached;
    if (!(b = vcr_zalloc(sizeof *b))) return 0;
    if (!vcr_undecorate(d->decorated, b)) { b->n = 0; ub_put(b, d->decorated + 1); }
    n = b->n;
    while (n && b->s[n - 1] == ' ') b->s[--n] = 0;
    node = malloc(sizeof(vcr_name_node) + n);
    if (!node) { vcr_free(b); return 0; }
    vcr_memcpy(node->name, b->s, n + 1);
    vcr_free(b);
    {
        const char *expected = 0;
        if (!__atomic_compare_exchange_n(&d->undecorated, &expected, node->name, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE)) {
            free(node);                              /* another thread won */
            return expected;
        }
    }
    if (root) {
        vcr_name_node **head = (vcr_name_node **)root, *old = __atomic_load_n(head, __ATOMIC_ACQUIRE);
        do node->next = old;
        while (!__atomic_compare_exchange_n(head, &old, node, 0, __ATOMIC_ACQ_REL, __ATOMIC_ACQUIRE));
    }
    return node->name;
}
DLLAPI void __std_type_info_destroy_list(void *root)
{
    vcr_name_node *n = root ? __atomic_exchange_n((vcr_name_node **)root, (vcr_name_node *)0, __ATOMIC_ACQ_REL) : 0;
    while (n) {
        vcr_name_node *next = n->next;
        free(n);
        n = next;
    }
}

/* ------------------------------------------------------------------ RTTI */
static cxx_class g_exception, g_bad_cast, g_bad_typeid, g_non_rtti;
CXX_COPY_CTOR(exception)
CXX_COPY_CTOR(bad_cast)
CXX_COPY_CTOR(bad_typeid)
CXX_COPY_CTOR(non_rtti)
static void rtti_init(void)
{
    cxx_class_init(&g_exception, ".?AVexception@std@@", 0, cxx_copy_exception);
    cxx_class_init(&g_bad_cast, ".?AVbad_cast@std@@", &g_exception, cxx_copy_bad_cast);
    cxx_class_init(&g_bad_typeid, ".?AVbad_typeid@std@@", &g_exception, cxx_copy_bad_typeid);
    cxx_class_init(&g_non_rtti, ".?AV__non_rtti_object@std@@", &g_bad_typeid, cxx_copy_non_rtti);
}

static const rtti_col *rtti_locator(const void *obj, uint64_t *base)
{
    const rtti_col *col = (*(const rtti_col *const *const *)obj)[-1];
    if (col->signature) *base = (uint64_t)col - (uint32_t)col->self;
    else {
        PVOID b = 0;
        RtlPcToFileHeader((PVOID)col, &b);
        *base = (uint64_t)b;
    }
    return col;
}
static char *rtti_complete(const void *obj, const rtti_col *col)
{
    int64_t off = col->offset;
    if (col->cd_offset) off += *(const int32_t *)((const char *)obj - col->cd_offset);
    return (char *)obj - off;
}
static ptrdiff_t rtti_where(const char *complete, const eh_pmd *pmd)
{
    ptrdiff_t off = pmd->mdisp;
    if (pmd->pdisp >= 0) off += pmd->pdisp + *(const int32_t *)(*(const char *const *)(complete + pmd->pdisp) + pmd->vdisp);
    return off;
}
static int rtti_same(const eh_typedesc *a, const eh_typedesc *b)
{
    return a == b || !vcr_strcmp(a->name, b->name);
}

DLLAPI void *__RTtypeid(void *obj)
{
    uint64_t base;
    const rtti_col *col;
    if (!obj) cxx_throw(&g_bad_typeid, "Attempted a typeid of nullptr pointer!");
    col = rtti_locator(obj, &base);
    return (void *)(base + (uint32_t)col->type);
}
DLLAPI void *__RTCastToVoid(void *obj)
{
    uint64_t base;
    if (!obj) return 0;
    return rtti_complete(obj, rtti_locator(obj, &base));
}
/* dynamic_cast<Target>(src): the target must be a public, unambiguous base of the complete object (with repeated
 * bases, the instance at or below the source subobject). vf_delta: offset of the vfptr in the source subobject. */
DLLAPI void *__RTDynamicCast(void *inptr, long vf_delta, void *src_type, void *target_type, BOOL is_reference)
{
    uint64_t base;
    const rtti_col *col;
    const rtti_chd *chd;
    const int32_t *bases;
    char *complete, *src, *best = 0;
    uint32_t i;
    int found = 0;
    (void)src_type;
    if (!inptr) return 0;
    col = rtti_locator(inptr, &base);
    complete = rtti_complete(inptr, col);
    src = (char *)inptr - vf_delta;
    chd = (const rtti_chd *)(base + (uint32_t)col->hierarchy);
    bases = (const int32_t *)(base + (uint32_t)chd->bases);
    for (i = 0; i < chd->nbases; ++i) {
        const rtti_bcd *bcd = (const rtti_bcd *)(base + (uint32_t)bases[i]);
        char *at;
        if (!rtti_same((const eh_typedesc *)(base + (uint32_t)bcd->type), (const eh_typedesc *)target_type)) continue;
        if (bcd->attributes & BCD_NOTVISIBLE) continue;
        at = complete + rtti_where(complete, &bcd->where);
        if (!found || (at <= src && (best > src || at > best))) best = at;
        ++found;
        if (!(bcd->attributes & BCD_AMBIGUOUS) && !(chd->attributes & CHD_MULTINH)) break;
    }
    if (best) return best;
    if (is_reference) cxx_throw(&g_bad_cast, "Bad dynamic_cast!");
    return 0;
}
DLLAPI int _is_exception_typeof(const eh_typedesc *type, EXCEPTION_POINTERS *ep)
{
    const EXCEPTION_RECORD *rec = ep ? ep->ExceptionRecord : 0;
    const eh_throwinfo *ti;
    const eh_catchable_array *arr;
    uint64_t tbase;
    int32_t k;
    if (!is_cxx_exception(rec) || !(ti = (const eh_throwinfo *)rec->ExceptionInformation[2])) return 0;
    tbase = rec->ExceptionInformation[3];
    arr = (const eh_catchable_array *)(tbase + (uint32_t)ti->catchables);
    for (k = 0; k < arr->count; ++k) {
        const eh_catchable *ct = (const eh_catchable *)(tbase + (uint32_t)arr->types[k]);
        if (rtti_same((const eh_typedesc *)(tbase + (uint32_t)ct->type), type)) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ small runtime services */
typedef void (*vcr_purecall_fn)(void);
static vcr_purecall_fn g_purecall;
DLLAPI vcr_purecall_fn _set_purecall_handler(vcr_purecall_fn fn) { return __atomic_exchange_n(&g_purecall, fn, __ATOMIC_ACQ_REL); }
DLLAPI vcr_purecall_fn _get_purecall_handler(void) { return __atomic_load_n(&g_purecall, __ATOMIC_ACQUIRE); }
DLLAPI VCR_NORETURN int _purecall(void)
{
    vcr_purecall_fn fn = _get_purecall_handler();
    if (fn) fn();
    abort();
}
static void *g_winrt_oom;
DLLAPI void _SetWinRTOutOfMemoryExceptionCallback(void *fn) { g_winrt_oom = fn; }
DLLAPI VCR_NORETURN void __report_gsfailure(uintptr_t cookie)
{
    (void)cookie;
    TerminateProcess(GetCurrentProcess(), 0xC0000409u);                /* STATUS_STACK_BUFFER_OVERRUN */
    for (;;) abort();
}
DLLAPI void __telemetry_main_invoke_trigger(HINSTANCE inst) { (void)inst; }
DLLAPI void __telemetry_main_return_trigger(HINSTANCE inst) { (void)inst; }
DLLAPI DWORD __vcrt_GetModuleFileNameW(HMODULE m, LPWSTR name, DWORD size) { return GetModuleFileNameW(m, name, size); }
DLLAPI HMODULE __vcrt_GetModuleHandleW(LPCWSTR name) { return GetModuleHandleW(name); }
DLLAPI HMODULE __vcrt_LoadLibraryExW(LPCWSTR name, HANDLE file, DWORD flags) { return LoadLibraryExW(name, file, flags); }
DLLAPI BOOL __vcrt_InitializeCriticalSectionEx(CRITICAL_SECTION *cs, DWORD spin, DWORD flags)
{
    return InitializeCriticalSectionEx(cs, spin, flags);
}

/* Debugger notification points (the debugger sets breakpoints on them); they do nothing. */
DLLAPI void _NLG_Dispatch2(void);
DLLAPI void _NLG_Return(void);
DLLAPI void _NLG_Return2(void);
DLLAPI void __NLG_Dispatch2(void);
DLLAPI void __NLG_Return2(void);
__asm__(".text\n"
        ".globl _NLG_Dispatch2\n.def _NLG_Dispatch2; .scl 2; .type 32; .endef\n_NLG_Dispatch2:\n"
        ".globl _NLG_Return\n.def _NLG_Return; .scl 2; .type 32; .endef\n_NLG_Return:\n"
        ".globl _NLG_Return2\n.def _NLG_Return2; .scl 2; .type 32; .endef\n_NLG_Return2:\n"
        ".globl __NLG_Dispatch2\n.def __NLG_Dispatch2; .scl 2; .type 32; .endef\n__NLG_Dispatch2:\n"
        ".globl __NLG_Return2\n.def __NLG_Return2; .scl 2; .type 32; .endef\n__NLG_Return2:\n"
        "    ret\n");
