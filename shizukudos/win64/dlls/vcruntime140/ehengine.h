/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku C++ / SEH exception engine, compiled into vcruntime140.dll (FH3, __C_specific_handler, longjmp) and into
 * vcruntime140_1.dll (FH4). The including file defines vcr_ptd_get() first.
 *
 * Model. The system dispatcher (ntdll) walks the frames and calls each language handler (phase 1). When a frame handler
 * finds a catch it does the rest itself, without RtlUnwindEx (the Shizuku ntdll has no STATUS_UNWIND_CONSOLIDATE):
 *   1. build the catch object in the function frame;
 *   2. walk the stack from the exception's origin context up to the catching frame, calling every frame's language
 *      handler with EXCEPTION_UNWINDING (destructors, __finally blocks);
 *   3. unwind the catching frame's own state to the try's entry;
 *   4. call the catch funclet from the current (deep) stack through vcr_call_catch, whose frame carries a handler: the
 *      frames between that call and the catching frame are dead but physically intact (the exception object lives in
 *      one of them), exactly as with Windows' consolidation callback;
 *   5. resume the catching frame's context at the continuation address the funclet returned.
 * While a catch runs, a record (vcr_catchrec) describes it. Exceptions raised inside the catch see the dead zone
 * (frames between the invoker and the catching frame) and skip it; in the catching frame itself the search restarts
 * below the try being handled. The origin context of an exception comes from a vectored handler that notes every
 * dispatch (vcruntime140 registers it); without one the walk starts from the handler's own context.
 */
#ifndef SHZ_EHENGINE_H
#define SHZ_EHENGINE_H
#include "vcrint.h"

static vcr_ptd *vcr_ptd_get(void);

uint64_t vcr_call_catch(uint64_t funclet, uint64_t parent, vcr_catchrec *r);
uint64_t vcr_call_guarded(uint64_t fn, uint64_t a, uint64_t b, uint64_t c);
EXCEPTION_DISPOSITION vcr_catch_guard(EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc);
EXCEPTION_DISPOSITION vcr_terminate_guard(EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc);

/* vcr_call_catch(funclet, parent, record): the catch funclet gets the function's establisher frame in RDX (and RCX) and
 * returns the continuation address in RAX. The thunk's establisher (RSP after its prologue) goes to record->invoker_est
 * and the record pointer to [establisher + 32], where vcr_catch_guard finds it.
 * vcr_call_guarded(fn, a, b, c): fn(a, b, c) with a handler that terminates the process when an exception escapes
 * (C++: an exception leaving a destructor during unwinding, or a catch-object copy constructor). */
__asm__(
    ".text\n"
    ".globl vcr_call_catch\n"
    ".def vcr_call_catch; .scl 2; .type 32; .endef\n"
    ".seh_proc vcr_call_catch\n"
    "vcr_call_catch:\n"
    "    .seh_handler vcr_catch_guard, @unwind, @except\n"
    "    subq $40, %rsp\n"
    "    .seh_stackalloc 40\n"
    "    .seh_endprologue\n"
    "    movq %r8, 32(%rsp)\n"
    "    movq %rsp, 8(%r8)\n"
    "    movq %rcx, %rax\n"
    "    movq %rdx, %rcx\n"
    "    callq *%rax\n"
    "    nop\n"
    "    addq $40, %rsp\n"
    "    ret\n"
    ".seh_endproc\n"
    ".globl vcr_call_guarded\n"
    ".def vcr_call_guarded; .scl 2; .type 32; .endef\n"
    ".seh_proc vcr_call_guarded\n"
    "vcr_call_guarded:\n"
    "    .seh_handler vcr_terminate_guard, @except\n"
    "    subq $40, %rsp\n"
    "    .seh_stackalloc 40\n"
    "    .seh_endprologue\n"
    "    movq %rcx, %rax\n"
    "    movq %rdx, %rcx\n"
    "    movq %r8, %rdx\n"
    "    movq %r9, %r8\n"
    "    callq *%rax\n"
    "    nop\n"
    "    addq $40, %rsp\n"
    "    ret\n"
    ".seh_endproc\n");

_Static_assert(offsetof(vcr_catchrec, invoker_est) == 8, "vcr_call_catch stores the invoker frame at offset 8");

#define CONTEXT_RESUME_ (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)

static void *vcr_zalloc(size_t n)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, n);
}
static void vcr_free(void *p)
{
    if (p) HeapFree(GetProcessHeap(), 0, p);
}
static size_t vcr_strlen(const char *s)
{
    size_t n = 0;
    while (s[n]) ++n;
    return n;
}
static int vcr_strcmp(const char *a, const char *b)
{
    while (*a && *a == *b) ++a, ++b;
    return (unsigned char)*a - (unsigned char)*b;
}
static void vcr_memcpy(void *d, const void *s, size_t n)
{
    unsigned char *o = d;
    const unsigned char *i = s;
    while (n--) *o++ = *i++;
}

static int is_cxx_exception(const EXCEPTION_RECORD *rec)
{
    if (!rec || rec->ExceptionCode != EH_EXCEPTION_CODE || rec->NumberParameters != 4) return 0;
    return rec->ExceptionInformation[0] == EH_MAGIC_1 || rec->ExceptionInformation[0] == EH_MAGIC_2 ||
           rec->ExceptionInformation[0] == EH_MAGIC_3 || rec->ExceptionInformation[0] == EH_PURE_MAGIC;
}

/* ------------------------------------------------------------------ catch records */
static void release_object(const EXCEPTION_RECORD *rec)
{
    const eh_throwinfo *ti = (const eh_throwinfo *)rec->ExceptionInformation[2];
    if (ti && ti->destructor && rec->ExceptionInformation[1])
        vcr_call_guarded(rec->ExceptionInformation[3] + (uint32_t)ti->destructor, rec->ExceptionInformation[1], 0, 0);
}

/* A catch is over (normally, or left by an unwind carrying `next`): restore the handled-exception pointers and destroy
 * the exception object, unless `next` rethrows that very object. */
static void leave_catch(vcr_ptd *t, vcr_catchrec *r, const EXCEPTION_RECORD *next)
{
    if (r->done) return;
    r->done = 1;
    t->cur_exception = r->prev_exception;
    t->cur_context = r->prev_context;
    if (r->is_cxx && !(is_cxx_exception(next) && next->ExceptionInformation[1] == r->rec.ExceptionInformation[1]))
        release_object(&r->rec);
}
static void pop_done(vcr_ptd *t)
{
    while (t->catches && t->catches->done) {
        vcr_catchrec *r = t->catches;
        t->catches = r->next;
        vcr_free(r);
    }
}
/* Records whose invoker frame lies below `sp` belong to catches the thread has already left (for example through a
 * foreign unwinder); their stack ranges are being reused, so they go. */
static void prune_stale(vcr_ptd *t, uint64_t sp)
{
    while (t->catches && t->catches->invoker_est < sp) {
        vcr_catchrec *r = t->catches;
        t->catches = r->next;
        if (!r->done) { t->cur_exception = r->prev_exception; t->cur_context = r->prev_context; }
        vcr_free(r);
    }
}
static int in_dead_zone(const vcr_ptd *t, uint64_t est)
{
    const vcr_catchrec *r;
    for (r = t->catches; r; r = r->next)
        if (est > r->invoker_est && est < r->target_rsp) return 1;
    return 0;
}
static vcr_catchrec *record_by_invoker(const vcr_ptd *t, uint64_t est)
{
    vcr_catchrec *r;
    for (r = t->catches; r; r = r->next)
        if (r->invoker_est == est) return r;
    return 0;
}
static vcr_catchrec *record_for_target(const vcr_ptd *t, uint64_t est, const void *info)
{
    vcr_catchrec *r;
    for (r = t->catches; r; r = r->next)
        if (r->target_est == est && r->info == info) return r;
    return 0;
}
/* The catch whose funclet runs in the frame at `est`: the innermost record invoked above it. */
static vcr_catchrec *record_of_funclet(const vcr_ptd *t, uint64_t est, uint32_t funclet_rva, uint64_t base)
{
    vcr_catchrec *r;
    for (r = t->catches; r; r = r->next)
        if (r->invoker_est > est) return r->base == base && (uint32_t)r->handler_rva == funclet_rva ? r : 0;
    return 0;
}

EXCEPTION_DISPOSITION vcr_catch_guard(EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc)
{
    (void)ctx; (void)dc;
    if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
        /* an unwinder other than ours leaves the catch: release it (the record stays listed until pruned) */
        vcr_ptd *t = vcr_ptd_get();
        vcr_catchrec *r = *(vcr_catchrec **)((char *)frame + 32);
        if (t && r) leave_catch(t, r, rec);
    }
    return ExceptionContinueSearch;
}
EXCEPTION_DISPOSITION vcr_terminate_guard(EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc)
{
    (void)frame; (void)ctx; (void)dc;
    if (!(rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND))) terminate();
    return ExceptionContinueSearch;
}

/* ------------------------------------------------------------------ the unwinder */
/* The context an exception was raised in, as the vectored handler saw it (0: not seen). */
static CONTEXT *origin_ptr(const vcr_ptd *t, const EXCEPTION_RECORD *rec)
{
    unsigned i;
    for (i = 0; t && i < VCR_SEEN; ++i) {
        const unsigned k = (t->seen_next - 1 - i) % VCR_SEEN;
        if (t->seen[k].rec == rec && t->seen[k].ctx) return t->seen[k].ctx;
    }
    return 0;
}
static int origin_context(const vcr_ptd *t, const EXCEPTION_RECORD *rec, CONTEXT *out)
{
    const CONTEXT *c = origin_ptr(t, rec);
    if (c) *out = *c;
    return c != 0;
}

/* Walk from `start` to the target frame (the one whose establisher is `target_est`, or when target_rsp is given the one
 * whose stack pointer at its call site is target_rsp, as setjmp saw it), calling the unwind handlers of the frames in
 * between with EXCEPTION_UNWINDING (and the target's with EXCEPTION_TARGET_UNWIND when call_target). Frames an active
 * catch has already unwound are skipped by jumping from its invoker to its resume frame. On success *out is the target
 * frame's context (Rip at its call site or fault point). */
static int vcr_unwind(vcr_ptd *t, const CONTEXT *start, EXCEPTION_RECORD *rec, uint64_t target_est, uint64_t target_rsp,
                      uint64_t target_ip, int call_target, CONTEXT *out)
{
    CONTEXT c = *start, prev;
    unsigned depth = 0;
    rec->ExceptionFlags |= EXCEPTION_UNWINDING;
    while (depth++ < 100000) {
        DWORD64 base = 0, est = 0;
        PRUNTIME_FUNCTION fe;
        PVOID hdata = 0;
        PEXCEPTION_ROUTINE h;
        vcr_catchrec *r;
        int final;
        if (!c.Rip || (c.Rsp & 7)) return 0;
        fe = RtlLookupFunctionEntry(c.Rip, &base, 0);
        if (!fe) {                                   /* leaf function: the return address is at RSP */
            c.Rip = *(DWORD64 *)c.Rsp;
            c.Rsp += 8;
            continue;
        }
        prev = c;
        h = RtlVirtualUnwind(UNW_FLAG_UHANDLER, base, c.Rip, fe, &c, &hdata, &est, 0);
        if (target_rsp ? prev.Rsp > target_rsp : est > target_est) return 0;   /* passed the target: not on this stack */
        if ((r = record_by_invoker(t, est)) != 0) {                    /* leaving a catch handler */
            leave_catch(t, r, rec);
            c = r->ctx;
            continue;
        }
        final = target_rsp ? prev.Rsp == target_rsp : est == target_est;
        if (h && (!final || call_target) && !in_dead_zone(t, est)) {
            DISPATCHER_CONTEXT dc;
            memset(&dc, 0, sizeof dc);
            dc.ControlPc = prev.Rip;
            dc.ImageBase = base;
            dc.FunctionEntry = fe;
            dc.EstablisherFrame = est;
            dc.TargetIp = target_ip;
            dc.ContextRecord = &prev;
            dc.LanguageHandler = h;
            dc.HandlerData = hdata;
            if (final) rec->ExceptionFlags |= EXCEPTION_TARGET_UNWIND;
            h(rec, (PVOID)est, &prev, &dc);
            rec->ExceptionFlags &= ~EXCEPTION_TARGET_UNWIND;
        }
        if (final) {
            *out = prev;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ type matching and catch objects */
static void *adjust_pointer(void *obj, const eh_pmd *pmd)
{
    char *p = (char *)obj + pmd->mdisp;
    if (pmd->pdisp >= 0) {
        const char *vbtable = *(const char *const *)((char *)obj + pmd->pdisp);
        p += *(const int32_t *)(vbtable + pmd->vdisp) + pmd->pdisp;
    }
    return p;
}

static const eh_catchable g_catch_all;               /* match marker for catch(...) */

static int catch_is_all(const eh_catch *cb, uint64_t base)
{
    const eh_typedesc *td = cb->type ? (const eh_typedesc *)(base + (uint32_t)cb->type) : 0;
    return !td || !td->name[0];
}

/* The CatchableType of the thrown object that `cb` accepts, &g_catch_all for catch(...), or 0. */
static const eh_catchable *match_catch(const EXCEPTION_RECORD *rec, const eh_catch *cb, uint64_t base)
{
    const eh_throwinfo *ti = (const eh_throwinfo *)rec->ExceptionInformation[2];
    const uint64_t tbase = rec->ExceptionInformation[3];
    const eh_typedesc *want;
    const eh_catchable_array *arr;
    int32_t k;
    if (catch_is_all(cb, base)) return &g_catch_all;
    if (!ti || !ti->catchables) return 0;
    want = (const eh_typedesc *)(base + (uint32_t)cb->type);
    arr = (const eh_catchable_array *)(tbase + (uint32_t)ti->catchables);
    for (k = 0; k < arr->count; ++k) {
        const eh_catchable *ct = (const eh_catchable *)(tbase + (uint32_t)arr->types[k]);
        const eh_typedesc *have = (const eh_typedesc *)(tbase + (uint32_t)ct->type);
        if (have != want && vcr_strcmp(have->name, want->name)) continue;
        if ((ct->properties & CT_BYREF_ONLY) && !(cb->adjectives & HT_REFERENCE)) continue;
        if ((ti->attributes & TI_CONST) && !(cb->adjectives & HT_CONST)) continue;
        if ((ti->attributes & TI_VOLATILE) && !(cb->adjectives & HT_VOLATILE)) continue;
        if ((ti->attributes & TI_UNALIGNED) && !(cb->adjectives & HT_UNALIGNED)) continue;
        return ct;
    }
    return 0;
}

/* Copy (or bind) the thrown object into the handler's catch variable at parent + catch_obj. */
static void build_catch_object(const EXCEPTION_RECORD *rec, uint64_t parent, const eh_catch *cb, const eh_catchable *ct, uint64_t base)
{
    void *obj = (void *)rec->ExceptionInformation[1];
    const uint64_t tbase = rec->ExceptionInformation[3];
    char *dst;
    if (ct == &g_catch_all || !cb->catch_obj || catch_is_all(cb, base)) return;
    dst = (char *)(parent + cb->catch_obj);
    if (cb->adjectives & HT_REFERENCE) {
        *(void **)dst = adjust_pointer(obj, &ct->this_disp);
    } else if (ct->properties & CT_SIMPLE) {
        vcr_memcpy(dst, obj, (size_t)ct->size);
        if (ct->size == (int32_t)sizeof(void *) && *(void **)dst) *(void **)dst = adjust_pointer(*(void **)dst, &ct->this_disp);
    } else if (!ct->copy_ctor) {
        vcr_memcpy(dst, adjust_pointer(obj, &ct->this_disp), (size_t)ct->size);
    } else {
        vcr_call_guarded(tbase + (uint32_t)ct->copy_ctor, (uint64_t)dst, (uint64_t)adjust_pointer(obj, &ct->this_disp),
                         (ct->properties & CT_VIRTUAL_BASE) ? 1 : 0);
    }
}

/* ------------------------------------------------------------------ catching */
#pragma GCC diagnostic ignored "-Wclobbered"
/* Execute catch `cb` of try `tb` (index ti) found in the frame at `est` (function frame `parent`, current state `state`). */
static VCR_NORETURN void cxx_catch(vcr_ptd *t, const eh_func *f, EXCEPTION_RECORD *rec, uint64_t est, const CONTEXT *frame_ctx,
                                   uint64_t parent, unsigned ti, const eh_try *tb, const eh_catch *cb, const eh_catchable *ct,
                                   int state)
{
    vcr_catchrec *r = vcr_zalloc(sizeof *r);
    EXCEPTION_RECORD urec;
    CONTEXT target;
    uint64_t cont;
    const int cxx = is_cxx_exception(rec);
    if (!r) terminate();
    if (cxx) build_catch_object(rec, parent, cb, ct, f->base);
    /* the frames below the catching one */
    urec = *rec;
    if (!origin_context(t, rec, &r->ctx)) RtlCaptureContext(&r->ctx);
    if (!vcr_unwind(t, &r->ctx, &urec, est, 0, 0, 0, &target)) target = *frame_ctx;
    /* the catching frame's own state, down to the try's entry */
    f->ops->unwind(f, parent, state, tb->low);
    pop_done(t);
    /* run the handler */
    r->target_est = est;
    r->target_rsp = target.Rsp;
    r->info = f->info;
    r->base = f->base;
    r->handler_rva = cb->handler;
    r->try_index = (int)ti;
    r->base_state = f->ops->to_state(f, tb->low);
    r->is_cxx = cxx;
    r->rec = *rec;
    r->rec.ExceptionFlags &= ~(EXCEPTION_UNWINDING | EXCEPTION_TARGET_UNWIND);
    r->ctx = target;
    r->prev_exception = t->cur_exception;
    r->prev_context = t->cur_context;
    r->next = t->catches;
    t->catches = r;
    t->cur_exception = &r->rec;
    t->cur_context = &r->ctx;
    if (cxx && t->processing_throw > 0) --t->processing_throw;
    cont = vcr_call_catch(f->base + (uint32_t)cb->handler, parent, r);
    if (cb->ncont && cont < cb->ncont) cont = cb->cont[cont];
    /* the handler completed: release the exception and resume the catching frame */
    leave_catch(t, r, 0);
    target = r->ctx;
    pop_done(t);
    target.Rip = cont;
    target.ContextFlags = CONTEXT_RESUME_;
    RtlRestoreContext(&target, 0);
    for (;;) terminate();
}

/* The frame handler proper, shared by __CxxFrameHandler3 and __CxxFrameHandler4. */
static EXCEPTION_DISPOSITION cxx_frame_handler(eh_func *f, EXCEPTION_RECORD *rec, uint64_t est, CONTEXT *ctx, DISPATCHER_CONTEXT *dc)
{
    vcr_ptd *t = vcr_ptd_get();
    const uint32_t fn_rva = dc->FunctionEntry ? dc->FunctionEntry->BeginAddress : 0;
    const int cxx = is_cxx_exception(rec);
    uint64_t parent = est;
    eh_try home;                                     /* the try whose catch funclet this frame is (FH3) */
    int in_funclet = 0, has_home = 0, state, floor = -1;
    vcr_catchrec *own, *fr = 0;
    unsigned i, j, n;
    if (!t) return ExceptionContinueSearch;
    f->func_start = dc->ImageBase + fn_rva;
    if (f->ops->is_cleanup(f, fn_rva)) return ExceptionContinueSearch;   /* destructor funclet: guarded elsewhere */
    /* catch funclet? then the function's frame is stored in the funclet frame */
    if (f->fh4) {
        if (f->is_catch) {
            in_funclet = 1;
            parent = *(const uint64_t *)(est + f->frame_disp);
            fr = record_of_funclet(t, est, fn_rva, f->base);
            if (fr && fr->info == f->info) {
                f->ops->get_try(f, (unsigned)fr->try_index, &home);
                has_home = 1;
            }
            if (fr) floor = fr->base_state;
        }
    } else {
        n = f->ops->ntry(f);
        for (i = 0; i < n && !in_funclet; ++i) {
            eh_try tb;
            f->ops->get_try(f, i, &tb);
            for (j = 0; j < tb.ncatch; ++j) {
                eh_catch cb;
                f->ops->get_catch(f, &tb, j, &cb);
                if ((uint32_t)cb.handler == fn_rva) {
                    in_funclet = has_home = 1;
                    home = tb;
                    parent = *(const uint64_t *)(est + cb.frame);
                    floor = f->ops->to_state(f, tb.low);
                    break;
                }
            }
        }
    }
    own = record_for_target(t, est, f->info);
    state = own ? own->base_state : f->ops->state(f, dc->ControlPc);

    if (rec->ExceptionFlags & (EXCEPTION_UNWINDING | EXCEPTION_EXIT_UNWIND)) {
        int to = floor;
        if (in_dead_zone(t, est)) return ExceptionContinueSearch;
        if (rec->ExceptionFlags & EXCEPTION_TARGET_UNWIND) {
            const int ts = f->ops->state(f, dc->TargetIp);
            if (ts > to) to = ts;
        }
        f->ops->unwind(f, parent, state, to);
        return ExceptionContinueSearch;
    }
    if (in_dead_zone(t, est)) return ExceptionContinueSearch;
    if (!cxx) {
        if (f->flags & FI_EHS) return ExceptionContinueSearch;          /* /EHs: SEH exceptions pass through */
        if (t->se_translator && rec->ExceptionCode != STATUS_LONGJUMP_ && rec->ExceptionCode != STATUS_UNWIND_) {
            EXCEPTION_POINTERS ep;
            CONTEXT *oc = origin_ptr(t, rec);
            ep.ExceptionRecord = rec;
            ep.ContextRecord = oc ? oc : ctx;
            ((void (*)(unsigned, EXCEPTION_POINTERS *))t->se_translator)(rec->ExceptionCode, &ep);   /* throws a C++ exception */
        }
    }
    n = f->ops->ntry(f);
    for (i = 0; i < n; ++i) {
        eh_try tb;
        f->ops->get_try(f, i, &tb);
        if (state < tb.low || state > tb.high) continue;
        if (has_home && !(tb.low > home.high && tb.high <= home.catch_high)) continue;  /* only trys inside this catch */
        for (j = 0; j < tb.ncatch; ++j) {
            eh_catch cb;
            const eh_catchable *ct;
            f->ops->get_catch(f, &tb, j, &cb);
            if (cxx) ct = match_catch(rec, &cb, f->base);
            else ct = catch_is_all(&cb, f->base) && !(cb.adjectives & HT_STDDOTDOT) ? &g_catch_all : 0;
            if (ct) cxx_catch(t, f, rec, est, ctx, parent, i, &tb, &cb, ct, state);
        }
    }
    if (cxx && (f->flags & FI_NOEXCEPT) && !in_funclet) terminate();  /* an exception leaves a noexcept function */
    return ExceptionContinueSearch;
}

#endif
