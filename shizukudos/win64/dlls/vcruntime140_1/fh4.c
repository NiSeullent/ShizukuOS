/* SPDX-License-Identifier: GPL-2.0-only
 * vcruntime140_1.dll for the Shizuku Win64 runtime: __CxxFrameHandler4, the frame handler for MSVC's compressed
 * ("FH4", /d2FH4, default since Visual Studio 2019) C++ exception tables. The tables are decoded here and handed to the
 * exception engine shared with vcruntime140.dll (ehengine.h); the per-thread state is vcruntime140's, reached through
 * its __current_exception() export as the real DLL pair does.
 *
 * FH4 encoding (all offsets image-relative):
 *   FuncInfo4: header byte {isCatch 0x01, isSeparated 0x02, BBT 0x04, UnwindMap 0x08, TryBlockMap 0x10, EHs 0x20,
 *     NoExcept 0x40}; [bbtFlags: U] [unwind map: I] [try map: I] ip map: I [dispFrame: U if isCatch]
 *   U = compressed unsigned (low bits of the first byte give the length: x0 1 byte, 01 2, 011 3, 0111 4, 1111 5),
 *   I = 32-bit little-endian integer.
 *   unwind map: count U, entries { U (nextOffset << 2 | type); type 1/2: action I, object U; type 3: action I }
 *     type 1 = destructor of the object at frame+object, 2 = destructor of *(frame+object), 3 = cleanup funclet;
 *     nextOffset counts bytes back from the entry to the entry of its parent state, 0 meaning state -1.
 *   try map: count U, entries { tryLow U, tryHigh U, catchHigh U, handlers I }
 *   handler array: count U, entries { header byte {adjectives 0x01, type 0x02, catchObj 0x04, contIsRVA 0x08,
 *     contCount 0x30}; [adjectives U] [type I] [catchObj U] handler I; contCount x (contIsRVA ? I : U from function) }
 *   ip map: count U, entries { ip delta U (from the function start), state + 1 U }; with isSeparated the map is
 *     { count U, { function start I, ip map I } } and the entry for the frame's function (or funclet) is used.
 */
#include "../vcruntime140/ehengine.h"

__declspec(dllimport) void **__current_exception(void);

static vcr_ptd *vcr_ptd_get(void)
{
    vcr_ptd *t = (vcr_ptd *)__current_exception();
    return t && t->magic == VCR_PTD_MAGIC ? t : 0;
}

static uint32_t rd_u(const uint8_t **pp)
{
    const uint8_t *p = *pp;
    uint32_t v;
    if (!(p[0] & 1)) { v = p[0] >> 1; *pp = p + 1; }
    else if (!(p[0] & 2)) { v = ((uint32_t)p[0] | (uint32_t)p[1] << 8) >> 2; *pp = p + 2; }
    else if (!(p[0] & 4)) { v = ((uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16) >> 3; *pp = p + 3; }
    else if (!(p[0] & 8)) { v = ((uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24) >> 4; *pp = p + 4; }
    else { v = (uint32_t)p[1] | (uint32_t)p[2] << 8 | (uint32_t)p[3] << 16 | (uint32_t)p[4] << 24; *pp = p + 5; }
    return v;
}
static int32_t rd_i(const uint8_t **pp)
{
    const uint8_t *p = *pp;
    *pp = p + 4;
    return (int32_t)((uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24);
}

/* ---- unwind map */
typedef struct { uint32_t offset; uint32_t type; int32_t action; uint32_t object; int to_state; } uw_entry;
/* Decode the whole unwind map (heap array, caller frees); returns the entry count. */
static uint32_t uw_decode(const eh_func *f, uw_entry **out)
{
    const uint8_t *start, *p;
    uint32_t n, i, *next;
    uw_entry *e;
    *out = 0;
    if (!f->unwind_map) return 0;
    start = p = f->unwind_map;
    n = rd_u(&p);
    if (!n || n > 1u << 20) return 0;
    e = vcr_zalloc(sizeof *e * n);
    next = vcr_zalloc(sizeof *next * n);
    if (!e || !next) { vcr_free(e); vcr_free(next); return 0; }
    for (i = 0; i < n; ++i) {
        const uint32_t v = (e[i].offset = (uint32_t)(p - start), rd_u(&p));
        e[i].type = v & 3;
        next[i] = v >> 2;
        if (e[i].type == 1 || e[i].type == 2) { e[i].action = rd_i(&p); e[i].object = rd_u(&p); }
        else if (e[i].type == 3) e[i].action = rd_i(&p);
    }
    for (i = 0; i < n; ++i) {
        uint32_t k;
        e[i].to_state = -1;
        if (!next[i] || next[i] > e[i].offset) continue;
        for (k = 0; k < i; ++k)
            if (e[k].offset == e[i].offset - next[i]) { e[i].to_state = (int)k; break; }
    }
    vcr_free(next);
    *out = e;
    return n;
}

static int fh4_state(const eh_func *f, uint64_t pc)
{
    const uint8_t *p = f->ip_map;
    uint32_t n, i;
    uint64_t ip = f->func_start;
    int st = -1;
    if (!p) return -1;
    if (f->flags & 0x80000000u) {                    /* separated: pick this function's (or funclet's) own map */
        const uint32_t segs = rd_u(&p), rva = (uint32_t)(f->func_start - f->base);
        const uint8_t *map = 0;
        for (i = 0; i < segs; ++i) {
            const int32_t fstart = rd_i(&p), mrva = rd_i(&p);
            if ((uint32_t)fstart == rva) { map = (const uint8_t *)(f->base + (uint32_t)mrva); break; }
        }
        if (!map) return -1;
        p = map;
    }
    n = rd_u(&p);
    for (i = 0; i < n; ++i) {
        const uint32_t delta = rd_u(&p);
        const int s = (int)rd_u(&p) - 1;
        if (pc < ip + delta) break;
        ip += delta;
        st = s;
    }
    return st;
}
static int fh4_to_state(const eh_func *f, int s)
{
    uw_entry *e;
    const uint32_t n = uw_decode(f, &e);
    const int r = s >= 0 && (uint32_t)s < n ? e[s].to_state : -1;
    vcr_free(e);
    return r;
}
static void fh4_unwind(const eh_func *f, uint64_t frame, int from, int to)
{
    uw_entry *e;
    const uint32_t n = uw_decode(f, &e);
    int s = from;
    uint32_t steps = 0;
    while (s > to && (uint32_t)s < n && steps++ <= n) {
        const uw_entry *u = &e[s];
        s = u->to_state;
        if (u->type == 1) vcr_call_guarded(f->base + (uint32_t)u->action, frame + u->object, frame, 0);
        else if (u->type == 2) vcr_call_guarded(f->base + (uint32_t)u->action, *(const uint64_t *)(frame + u->object), frame, 0);
        else if (u->type == 3) vcr_call_guarded(f->base + (uint32_t)u->action, frame, frame, 0);
    }
    vcr_free(e);
}
static int fh4_is_cleanup(const eh_func *f, uint32_t rva)
{
    uw_entry *e;
    const uint32_t n = uw_decode(f, &e);
    uint32_t i;
    int r = 0;
    for (i = 0; i < n && !r; ++i) r = e[i].type == 3 && (uint32_t)e[i].action == rva;
    vcr_free(e);
    return r;
}

/* ---- try map and handlers */
static unsigned fh4_ntry(const eh_func *f)
{
    const uint8_t *p = f->try_map;
    return p ? rd_u(&p) : 0;
}
static void fh4_get_try(const eh_func *f, unsigned idx, eh_try *t)
{
    const uint8_t *p = f->try_map, *h;
    unsigned i;
    int32_t handlers = 0;
    rd_u(&p);
    for (i = 0; i <= idx; ++i) {
        t->low = (int32_t)rd_u(&p);
        t->high = (int32_t)rd_u(&p);
        t->catch_high = (int32_t)rd_u(&p);
        handlers = rd_i(&p);
    }
    h = (const uint8_t *)(f->base + (uint32_t)handlers);
    t->ncatch = handlers ? rd_u(&h) : 0;
    t->catches = h;
}
static void fh4_get_catch(const eh_func *f, const eh_try *t, unsigned idx, eh_catch *c)
{
    const uint8_t *p = t->catches;
    unsigned i, k;
    for (i = 0; i <= idx; ++i) {
        const uint8_t h = *p++;
        c->adjectives = (h & 0x01) ? rd_u(&p) : 0;
        c->type = (h & 0x02) ? rd_i(&p) : 0;
        c->catch_obj = (h & 0x04) ? (int32_t)rd_u(&p) : 0;
        c->handler = rd_i(&p);
        c->frame = 0;
        c->ncont = (h >> 4) & 3;
        if (c->ncont > 2) c->ncont = 2;
        c->cont[0] = c->cont[1] = 0;
        for (k = 0; k < c->ncont; ++k)
            c->cont[k] = (h & 0x08) ? f->base + (uint32_t)rd_i(&p) : f->func_start + rd_u(&p);
    }
}

static const eh_ops fh4_ops = { fh4_state, fh4_to_state, fh4_unwind, fh4_ntry, fh4_get_try, fh4_get_catch, fh4_is_cleanup };

/* Decode the FuncInfo4 header into f (exposed for the table tests through the frame handler itself). */
static void fh4_decode(eh_func *f, const uint8_t *p, uint64_t base)
{
    const uint8_t h = *p++;
    memset(f, 0, sizeof *f);
    f->ops = &fh4_ops;
    f->info = p - 1;
    f->base = base;
    f->fh4 = 1;
    if (h & 0x04) rd_u(&p);                          /* BBT flags */
    if (h & 0x08) f->unwind_map = (const uint8_t *)(base + (uint32_t)rd_i(&p));
    if (h & 0x10) f->try_map = (const uint8_t *)(base + (uint32_t)rd_i(&p));
    {
        const int32_t ip = rd_i(&p);
        f->ip_map = ip ? (const uint8_t *)(base + (uint32_t)ip) : 0;
    }
    if (h & 0x01) { f->is_catch = 1; f->frame_disp = rd_u(&p); }
    if (h & 0x20) f->flags |= FI_EHS;
    if (h & 0x40) f->flags |= FI_NOEXCEPT;
    if (h & 0x02) f->flags |= 0x80000000u;           /* separated ip-to-state maps */
}

DLLAPI EXCEPTION_DISPOSITION __CxxFrameHandler4(EXCEPTION_RECORD *rec, void *frame, CONTEXT *ctx, DISPATCHER_CONTEXT *dc)
{
    eh_func f;
    fh4_decode(&f, (const uint8_t *)(dc->ImageBase + *(const uint32_t *)dc->HandlerData), dc->ImageBase);
    return cxx_frame_handler(&f, rec, (uint64_t)frame, ctx, dc);
}

/* Debugger notification points. */
DLLAPI void __NLG_Dispatch2(void);
DLLAPI void __NLG_Return2(void);
__asm__(".text\n"
        ".globl __NLG_Dispatch2\n.def __NLG_Dispatch2; .scl 2; .type 32; .endef\n__NLG_Dispatch2:\n"
        ".globl __NLG_Return2\n.def __NLG_Return2; .scl 2; .type 32; .endef\n__NLG_Return2:\n"
        "    ret\n");
