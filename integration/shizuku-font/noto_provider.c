/* SPDX-License-Identifier: GPL-2.0-only. Links FreeType (FTL/GPLv2). See noto_provider.h.
 * Repair of integration/shizuku-shell/font23/noto_provider.c (historical first epoch, unchanged). */
#include <stdlib.h>
#include <string.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MULTIPLE_MASTERS_H
#if defined(__has_include) && !__has_include(<freetype/ftmodapi.h>)
FT_BEGIN_HEADER
FT_EXPORT(FT_Error) FT_New_Library(FT_Memory memory, FT_Library *alibrary);
FT_EXPORT(FT_Error) FT_Done_Library(FT_Library library);
FT_EXPORT(void) FT_Add_Default_Modules(FT_Library library);
FT_END_HEADER
#else
#include FT_MODULE_H
#endif
#include FT_SYSTEM_H
#include "noto_provider.h"
#include "hashes.h"   /* shizukudos/win64/dlls/bcrypt/hashes.[ch]: portable SHA-256 */

#if defined(NOTO_MALLOC) != defined(NOTO_FREE)
#error NOTO_MALLOC and NOTO_FREE must be defined together
#endif
#ifndef NOTO_MALLOC
#define NOTO_MALLOC(n) malloc(n)
#define NOTO_FREE(p) free(p)
#endif

typedef struct NotoHeap {
    size_t used, limit;
    void *(*alloc)(void *, size_t); void (*free)(void *, void *); void *ctx;
} NotoHeap;
#define HDR 16u
static void *heap_alloc(FT_Memory m, long n)
{
    NotoHeap *h = m->user; unsigned char *b;
    if (n <= 0 || (size_t)n > h->limit || h->used > h->limit - (size_t)n) return NULL;
    b = h->alloc(h->ctx, (size_t)n + HDR);
    if (!b) return NULL;
    *(size_t *)b = (size_t)n; h->used += (size_t)n;
    return b + HDR;
}
static void heap_free(FT_Memory m, void *p)
{
    NotoHeap *h = m->user; unsigned char *b;
    if (!p) return;
    b = (unsigned char *)p - HDR; h->used -= *(size_t *)b; h->free(h->ctx, b);
}
static void *heap_realloc(FT_Memory m, long cur, long n, void *p)
{
    void *q;
    if (!p) return heap_alloc(m, n);
    if (n <= 0) { heap_free(m, p); return NULL; }
    q = heap_alloc(m, n);
    if (!q) return NULL;
    memcpy(q, p, (size_t)(cur < n ? cur : n));
    heap_free(m, p);
    return q;
}
static void *def_alloc(void *c, size_t n) { (void)c; return NOTO_MALLOC(n); }
static void def_free(void *c, void *p) { (void)c; NOTO_FREE(p); }

struct NotoProvider {
    NotoHeap heap; struct FT_MemoryRec_ mem; FT_Library lib;
    FT_Face face[2]; NotoFontSource src[2]; char family[2][64]; int pixels; volatile int busy;
};

const char *noto_status_str(NotoStatus st)
{
    switch (st) {
    case NOTO_OK: return "ok"; case NOTO_E_PARAM: return "bad parameter"; case NOTO_E_BUSY: return "busy";
    case NOTO_E_NOMEM: return "out of memory"; case NOTO_E_FONT: return "bad font data";
    case NOTO_E_FAMILY: return "wrong font family"; case NOTO_E_FREETYPE: return "freetype error";
    case NOTO_E_RANGE: return "out of range"; case NOTO_E_ABORT: return "aborted by callback";
    case NOTO_E_BITMAP: return "bad glyph bitmap"; case NOTO_E_UNAVAILABLE: return "noto unavailable";
    case NOTO_E_HASH: return "font hash mismatch"; case NOTO_E_COVERAGE: return "font coverage missing";
    }
    return "unknown";
}

void noto_sha256(const void *data, size_t n, uint8_t out[NOTO_SHA256_LEN])
{
    shz_hash_ctx c; shz_hash_init(&c, SHZ_H_SHA256);
    shz_hash_update(&c, data, n); shz_hash_final(&c, out);
}

NotoStatus noto_pin_from_hex(const char *hex, uint8_t out[NOTO_SHA256_LEN])
{
    int i;
    if (!hex || !out) return NOTO_E_PARAM;
    for (i = 0; i < 64; ++i) {
        char c = hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return NOTO_E_PARAM;
    }
    if (hex[64]) return NOTO_E_PARAM;
    for (i = 0; i < 32; ++i) {
        int v = 0, k;
        for (k = 0; k < 2; ++k) {
            char c = hex[2 * i + k];
            v = v * 16 + (c <= '9' ? c - '0' : (c | 32) - 'a' + 10);
        }
        out[i] = (uint8_t)v;
    }
    return NOTO_OK;
}

static void release(NotoFontSource *s)
{
    if (s->release && s->data) s->release(s->ctx, s->data);
    s->data = NULL;
}

static int enter(NotoProvider *p) { return !__sync_lock_test_and_set(&p->busy, 1); }
static void leave(NotoProvider *p) { __sync_lock_release(&p->busy); }

static void destroy_unlocked(NotoProvider *p)
{
    int i; NotoHeap h = p->heap;
    for (i = 0; i < 2; ++i) if (p->face[i]) FT_Done_Face(p->face[i]);
    if (p->lib) FT_Done_Library(p->lib);
    for (i = 0; i < 2; ++i) release(&p->src[i]);
    h.free(h.ctx, p);
}

NotoStatus noto_destroy(NotoProvider *p)
{
    if (!p) return NOTO_OK;
    if (!enter(p)) return NOTO_E_BUSY;   /* in-flight call or a callback: stay alive */
    destroy_unlocked(p);
    return NOTO_OK;
}

static int set_wght400(NotoProvider *p, FT_Face f)
{
    FT_MM_Var *mm = NULL; FT_Fixed c[16]; FT_UInt i; int found = 0, ok;
    if (!(f->face_flags & FT_FACE_FLAG_MULTIPLE_MASTERS)) return 1;
    if (FT_Get_MM_Var(f, &mm) || !mm) return 0;
    if (mm->num_axis > 16) { FT_Done_MM_Var(p->lib, mm); return 0; }
    for (i = 0; i < mm->num_axis; ++i) {
        c[i] = mm->axis[i].def;
        if (mm->axis[i].tag == FT_MAKE_TAG('w', 'g', 'h', 't')) { c[i] = 400L << 16; found = 1; }
    }
    ok = found && !FT_Set_Var_Design_Coordinates(f, mm->num_axis, c);
    FT_Done_MM_Var(p->lib, mm);
    return ok;
}

static int family_ok(int kr, const char *fam)
{
    if (!kr) return strcmp(fam, "Noto Sans") == 0;
    return strcmp(fam, "Noto Sans KR") == 0 || strcmp(fam, "Noto Sans CJK KR") == 0;
}

static int cover_range(FT_Face f, uint32_t a, uint32_t b)
{
    for (; a <= b; ++a) if (!FT_Get_Char_Index(f, a)) return 0;
    return 1;
}

static int coverage_ok(int kr, FT_Face f)
{
    if (!kr)
        return cover_range(f, 'A', 'Z') && cover_range(f, 'a', 'z') && cover_range(f, '0', '9');
    return cover_range(f, 0xAC00, 0xD7A3) &&                       /* all 11172 syllables */
           cover_range(f, 0x1100, 0x1112) && cover_range(f, 0x1161, 0x1175) && cover_range(f, 0x11A8, 0x11C2);
}

static int overlaps(const NotoFontSource *a, const NotoFontSource *b)
{
    uintptr_t x = (uintptr_t)a->data, y = (uintptr_t)b->data;   /* integer compare: no pointer-arithmetic UB */
    size_t as = a->size, bs = b->size;
    if (!x || !y || !as || !bs) return 0;
    if (as > UINTPTR_MAX - x || bs > UINTPTR_MAX - y) return 1;   /* range wraps the address space: reject as aliasing */
    return x < y + bs && y < x + as;
}

NotoStatus noto_create(NotoFontSource *latin, NotoFontSource *kr, NotoProvider **out)
{
    return noto_create_ex(NULL, latin, kr, out);
}

NotoStatus noto_create_ex(const NotoConfig *cfg, NotoFontSource *latin, NotoFontSource *kr, NotoProvider **out)
{
    NotoProvider *p; NotoStatus st = NOTO_OK; int i;
    void *(*al)(void *, size_t) = def_alloc; void (*fr)(void *, void *) = def_free; void *actx = NULL;
    size_t limit = NOTO_MAX_FT_BYTES; uint8_t pin[2][NOTO_SHA256_LEN];
    if (out) *out = NULL;
    if (!latin || !kr || !out) { if (latin) release(latin); if (kr && kr != latin) release(kr); return NOTO_E_PARAM; }
    /* alias rejection: same struct, same pointer or overlapping images: release each distinct image once */
    if (latin == kr) { release(latin); return NOTO_E_PARAM; }
    if (overlaps(latin, kr)) {
        if (latin->data == kr->data) kr->data = NULL;   /* one allocation: release once */
        release(latin); release(kr); return NOTO_E_PARAM;
    }
    if (cfg) {
        if ((cfg->alloc != NULL) != (cfg->free != NULL) || (cfg->max_ft_bytes > NOTO_MAX_FT_BYTES)) {
            release(latin); release(kr); return NOTO_E_PARAM;
        }
        if (cfg->alloc) { al = cfg->alloc; fr = cfg->free; actx = cfg->ctx; }
        if (cfg->max_ft_bytes) limit = cfg->max_ft_bytes;
    }
    if (!latin->expected_sha256 || !kr->expected_sha256) { release(latin); release(kr); return NOTO_E_PARAM; }
    memcpy(pin[0], latin->expected_sha256, NOTO_SHA256_LEN); memcpy(pin[1], kr->expected_sha256, NOTO_SHA256_LEN);
    p = al(actx, sizeof *p);
    if (!p) { release(latin); release(kr); return NOTO_E_NOMEM; }
    memset(p, 0, sizeof *p);
    p->src[0] = *latin; p->src[1] = *kr; latin->data = kr->data = NULL;   /* ownership moved */
    p->src[0].expected_sha256 = p->src[1].expected_sha256 = NULL;
    p->heap.limit = limit; p->heap.alloc = al; p->heap.free = fr; p->heap.ctx = actx;
    p->mem.user = &p->heap; p->mem.alloc = heap_alloc; p->mem.free = heap_free; p->mem.realloc = heap_realloc;
    for (i = 0; i < 2; ++i)
        if (!p->src[i].data || !p->src[i].size || p->src[i].size > NOTO_MAX_FONT_BYTES || p->src[i].face_index < 0)
            st = NOTO_E_FONT;
    for (i = 0; st == NOTO_OK && i < 2; ++i) {      /* identity before any parse */
        uint8_t d[NOTO_SHA256_LEN];
        noto_sha256(p->src[i].data, p->src[i].size, d);
        if (memcmp(d, pin[i], NOTO_SHA256_LEN) != 0) st = NOTO_E_HASH;
    }
    if (st == NOTO_OK && FT_New_Library(&p->mem, &p->lib)) { p->lib = NULL; st = NOTO_E_FREETYPE; }
    if (st == NOTO_OK) FT_Add_Default_Modules(p->lib);
    for (i = 0; st == NOTO_OK && i < 2; ++i) {
        const char *fam;
        if (FT_New_Memory_Face(p->lib, p->src[i].data, (FT_Long)p->src[i].size, p->src[i].face_index, &p->face[i])) {
            p->face[i] = NULL; st = NOTO_E_FONT; break;
        }
        fam = p->face[i]->family_name ? p->face[i]->family_name : "";
        if (!family_ok(i, fam) || strlen(fam) >= sizeof p->family[i]) { st = NOTO_E_FAMILY; break; }
        strcpy(p->family[i], fam);
        if (FT_Select_Charmap(p->face[i], FT_ENCODING_UNICODE)) { st = NOTO_E_FONT; break; }
        if (!set_wght400(p, p->face[i])) { st = NOTO_E_FONT; break; }
        if (!coverage_ok(i, p->face[i])) { st = NOTO_E_COVERAGE; break; }
    }
    if (st != NOTO_OK) { destroy_unlocked(p); return st; }
    *out = p;
    return NOTO_OK;
}

const char *noto_family(const NotoProvider *p, int kr_face)
{
    return p && p->family[kr_face ? 1 : 0][0] ? p->family[kr_face ? 1 : 0] : NULL;
}
size_t noto_ft_bytes_in_use(const NotoProvider *p) { return p ? p->heap.used : 0; }

NotoStatus noto_decode(const uint16_t *text, size_t len, size_t *cursor, uint32_t *scalar, int *replaced)
{
    uint32_t u;
    if (!text || !cursor || !scalar || len > NOTO_MAX_TEXT || *cursor >= len) return NOTO_E_PARAM;
    u = text[(*cursor)++];
    if (replaced) *replaced = 0;
    if (u >= 0xD800 && u <= 0xDBFF) {
        if (*cursor < len && text[*cursor] >= 0xDC00 && text[*cursor] <= 0xDFFF) {
            u = 0x10000u + ((u - 0xD800u) << 10) + (text[*cursor] - 0xDC00u); ++*cursor;
        } else { u = 0xFFFD; if (replaced) *replaced = 1; }
    } else if (u >= 0xDC00 && u <= 0xDFFF) { u = 0xFFFD; if (replaced) *replaced = 1; }
    *scalar = u;
    return NOTO_OK;
}

static int scalar_ok(uint32_t s) { return s <= 0x10FFFFu && !(s >= 0xD800u && s <= 0xDFFFu); }

static NotoStatus size_to(NotoProvider *p, int px)
{
    int i;
    if (px < NOTO_MIN_PIXELS || px > NOTO_MAX_PIXELS) return NOTO_E_RANGE;
    if (p->pixels == px) return NOTO_OK;
    for (i = 0; i < 2; ++i) if (FT_Set_Pixel_Sizes(p->face[i], 0, (FT_UInt)px)) { p->pixels = 0; return NOTO_E_FREETYPE; }
    p->pixels = px;
    return NOTO_OK;
}
static int scale_px(int scale) { return scale >= 1 && scale <= NOTO_MAX_SCALE ? NOTO_BASE_PIXELS * scale : 0; }

NotoStatus noto_query_glyph(NotoProvider *p, uint32_t s, int *present)
{
    if (!p) return NOTO_E_UNAVAILABLE;
    if (!present || !scalar_ok(s)) return NOTO_E_PARAM;
    if (!enter(p)) return NOTO_E_BUSY;
    *present = FT_Get_Char_Index(p->face[0], s) || FT_Get_Char_Index(p->face[1], s);
    leave(p);
    return NOTO_OK;
}
int noto_has_glyph(NotoProvider *p, uint32_t s)
{
    int present = 0;
    return noto_query_glyph(p, s, &present) == NOTO_OK && present;
}

static NotoStatus load(NotoProvider *p, uint32_t s, int render, NotoGlyph *g)
{
    int f; FT_UInt gi = 0; FT_GlyphSlot sl;
    for (f = 0; f < 2 && !gi; ++f) gi = FT_Get_Char_Index(p->face[f], s);
    f = gi ? f - 1 : 0;
    g->scalar = s; g->glyph_index = gi; g->kr_face = f; g->missing = !gi;
    if (FT_Load_Glyph(p->face[f], gi, FT_LOAD_NO_HINTING | FT_LOAD_NO_BITMAP)) return NOTO_E_FREETYPE;
    sl = p->face[f]->glyph;
    if (sl->advance.x < 0 || sl->advance.x > ((long)NOTO_COORD_LIMIT << 6)) return NOTO_E_RANGE;
    g->advance = (int32_t)sl->advance.x;
    g->bearing_x = (int32_t)sl->metrics.horiBearingX; g->bearing_y = (int32_t)sl->metrics.horiBearingY;
    g->width = (int32_t)sl->metrics.width; g->height = (int32_t)sl->metrics.height;
    g->abc_a = g->bearing_x; g->abc_b = g->width; g->abc_c = g->advance - g->bearing_x - g->width;
    if (render && FT_Render_Glyph(sl, FT_RENDER_MODE_NORMAL)) return NOTO_E_FREETYPE;
    return NOTO_OK;
}

NotoStatus noto_glyph_px(NotoProvider *p, uint32_t s, int px, NotoGlyph *g)
{
    NotoStatus st;
    if (!p) return NOTO_E_UNAVAILABLE;
    if (!g || !scalar_ok(s)) return NOTO_E_PARAM;
    if (!enter(p)) return NOTO_E_BUSY;
    st = size_to(p, px);
    if (st == NOTO_OK) st = load(p, s, 0, g);
    leave(p);
    return st;
}
NotoStatus noto_glyph(NotoProvider *p, uint32_t s, int scale, NotoGlyph *g)
{
    return noto_glyph_px(p, s, scale_px(scale), g);
}

static int ceil64(int64_t v) { return (int)((v + 63) >> 6); }

static NotoStatus metrics_locked(NotoProvider *p, int px, NotoMetrics *m)
{
    int i; int64_t asc = 0, desc = 0; NotoStatus st = size_to(p, px);
    if (st != NOTO_OK) return st;
    for (i = 0; i < 2; ++i) {
        FT_Size_Metrics *s = &p->face[i]->size->metrics;
        if ((int64_t)s->ascender > asc) asc = s->ascender;
        if (-(int64_t)s->descender > desc) desc = -(int64_t)s->descender;
    }
    if (asc > ((int64_t)NOTO_COORD_LIMIT << 6) || desc > ((int64_t)NOTO_COORD_LIMIT << 6)) return NOTO_E_RANGE;
    m->ascent = (int32_t)asc; m->descent = (int32_t)desc; m->height = (int32_t)(asc + desc);
    return NOTO_OK;
}

NotoStatus noto_metrics_px(NotoProvider *p, int px, NotoMetrics *m)
{
    NotoStatus st;
    if (!p) return NOTO_E_UNAVAILABLE;
    if (!m) return NOTO_E_PARAM;
    if (!enter(p)) return NOTO_E_BUSY;
    st = metrics_locked(p, px, m);
    leave(p);
    return st;
}
NotoStatus noto_metrics(NotoProvider *p, int scale, NotoMetrics *m) { return noto_metrics_px(p, scale_px(scale), m); }

NotoStatus noto_measure_px(NotoProvider *p, const uint16_t *text, size_t len, int px, NotoExtent *e)
{
    NotoMetrics m; size_t cur = 0; NotoStatus st;
    if (!p) return NOTO_E_UNAVAILABLE;
    if (!e || (len && !text) || len > NOTO_MAX_TEXT) return NOTO_E_PARAM;
    memset(e, 0, sizeof *e);
    if (!enter(p)) return NOTO_E_BUSY;
    if ((st = metrics_locked(p, px, &m)) != NOTO_OK) goto done;
    while (cur < len) {
        uint32_t s; int rep; NotoGlyph g;
        noto_decode(text, len, &cur, &s, &rep);
        if ((st = load(p, s, 0, &g)) != NOTO_OK) goto done;
        e->width26 += g.advance; ++e->glyphs; e->missing += (unsigned)g.missing; e->replaced += (unsigned)rep;
        if (e->width26 > ((int64_t)NOTO_COORD_LIMIT << 6)) { st = NOTO_E_RANGE; goto done; }
    }
    e->cx = ceil64(e->width26); e->cy = ceil64(m.height); e->ascent = ceil64(m.ascent);
    st = NOTO_OK;
done:
    if (st != NOTO_OK) memset(e, 0, sizeof *e);
    leave(p);
    return st;
}
NotoStatus noto_measure(NotoProvider *p, const uint16_t *text, size_t len, int scale, NotoExtent *e)
{
    return noto_measure_px(p, text, len, scale_px(scale), e);
}

static int64_t clampc(int64_t v)
{
    const int64_t L = NOTO_COORD_LIMIT;
    return v < -L ? -L : (v > L ? L : v);
}

NotoStatus noto_draw_px(NotoProvider *p, const uint16_t *text, size_t len, int px, int x, int y,
                        const NotoRect *clip, NotoCoverageFn fn, void *ctx, NotoPen *pen)
{
    NotoMetrics m; NotoStatus st; NotoPen local; int64_t base, cl = 0, ct = 0, cr = 0, cb = 0;
    const int64_t XMAX = (int64_t)NOTO_COORD_LIMIT << 6;
    if (!p) return NOTO_E_UNAVAILABLE;
    if (!fn || (len && !text) || len > NOTO_MAX_TEXT) return NOTO_E_PARAM;
    memset(&local, 0, sizeof local);
    if (!pen) pen = &local;
    if (pen->cursor > len || pen->x26 < 0 || pen->x26 > XMAX || pen->row < 0 || pen->row > 4096 ||
        (pen->pixel_size && (pen->pixel_size != px)) || (pen->cursor == len && pen->row)) return NOTO_E_PARAM;
    if (px < NOTO_MIN_PIXELS || px > NOTO_MAX_PIXELS) return NOTO_E_RANGE;
    if (x < -NOTO_COORD_LIMIT || x > NOTO_COORD_LIMIT || y < -NOTO_COORD_LIMIT || y > NOTO_COORD_LIMIT) return NOTO_E_RANGE;
    if (clip) { cl = clampc(clip->left); ct = clampc(clip->top); cr = clampc(clip->right); cb = clampc(clip->bottom); }
    if (!enter(p)) return NOTO_E_BUSY;
    if ((st = metrics_locked(p, px, &m)) != NOTO_OK) goto done;
    pen->pixel_size = px;
    base = (int64_t)y + ceil64(m.ascent);
    while (pen->cursor < len) {
        size_t cur = pen->cursor; uint32_t s; int rep, row; int64_t gx, gy; NotoGlyph g; FT_GlyphSlot sl; FT_Bitmap *bm;
        noto_decode(text, len, &cur, &s, &rep);
        if ((st = load(p, s, 1, &g)) != NOTO_OK) goto done;
        sl = p->face[g.kr_face]->glyph; bm = &sl->bitmap;
        if (bm->width && bm->rows) {
            int64_t ap = bm->pitch < 0 ? -(int64_t)bm->pitch : (int64_t)bm->pitch;   /* widen BEFORE negation (long is 32-bit on Win64) */
            if (bm->pixel_mode != FT_PIXEL_MODE_GRAY || bm->num_grays != 256 || !bm->buffer ||
                bm->width > 4096 || bm->rows > 4096 || ap < (int64_t)bm->width) { st = NOTO_E_BITMAP; goto done; }
        }
        if (pen->x26 + g.advance > XMAX) { st = NOTO_E_RANGE; goto done; }
        if (pen->row > (int)bm->rows) { st = NOTO_E_PARAM; goto done; }
        gx = (int64_t)x + ((pen->x26 + 32) >> 6) + sl->bitmap_left;
        gy = base - sl->bitmap_top;
        for (row = pen->row; row < (int)bm->rows; ++row) {
            const uint8_t *src;
            int64_t pxl = gx, n = (int64_t)bm->width, yy = gy + row;
            if (clip) {   /* skip fully clipped rows/columns BEFORE deriving any pointer from them */
                if (yy < ct || yy >= cb) { pen->row = row + 1; continue; }
                if (pxl < cl && cl - pxl >= n) { pen->row = row + 1; continue; }
            }
            src = bm->buffer + (ptrdiff_t)row * bm->pitch;   /* row < rows: inside the bitmap; signed pitch */
            if (clip) {
                if (pxl < cl) { src += (ptrdiff_t)(cl - pxl); n -= cl - pxl; pxl = cl; }   /* 0 < skip < width */
                if (pxl + n > cr) n = cr - pxl;
            }
            if (n > 0 && pxl >= -(int64_t)(1 << 30) && pxl + n <= (int64_t)(1 << 30) && yy >= -(int64_t)(1 << 30) && yy <= (int64_t)(1 << 30)) {
                if (fn(ctx, (int)pxl, (int)yy, src, (int)n)) { pen->row = row; st = NOTO_E_ABORT; goto done; }
            }
            pen->row = row + 1;
        }
        pen->cursor = cur; pen->x26 += g.advance; pen->row = 0;
        pen->missing += (unsigned)g.missing; pen->replaced += (unsigned)rep;
    }
    st = NOTO_OK;
done:
    leave(p);
    return st;
}
NotoStatus noto_draw(NotoProvider *p, const uint16_t *text, size_t len, int scale, int x, int y,
                     const NotoRect *clip, NotoCoverageFn fn, void *ctx, NotoPen *pen)
{
    return noto_draw_px(p, text, len, scale_px(scale), x, y, clip, fn, ctx, pen);
}
