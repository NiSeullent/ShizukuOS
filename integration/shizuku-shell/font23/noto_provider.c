/* SPDX-License-Identifier: GPL-2.0-only. Links FreeType (FTL/GPLv2). See noto_provider.h. */
#include <stdlib.h>
#include <string.h>
#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MULTIPLE_MASTERS_H
#if defined(__has_include) && !__has_include(<freetype/ftmodapi.h>)
/* build/font23-inputs-74b0 stages minimal headers without ftmodapi.h; these three public FreeType 2.13.3
 * functions are exported by the staged archive (verified with nm), so declare them with their real signatures. */
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

#ifndef NOTO_MALLOC
#define NOTO_MALLOC malloc
#define NOTO_FREE free
#endif

typedef struct { size_t used, limit; } NotoHeap;
#define HDR 16u
static void *heap_alloc(FT_Memory m, long n)
{
    NotoHeap *h = m->user; unsigned char *b;
    if (n <= 0 || (size_t)n > h->limit || h->used > h->limit - (size_t)n) return NULL;
    b = NOTO_MALLOC((size_t)n + HDR);
    if (!b) return NULL;
    *(size_t *)b = (size_t)n; h->used += (size_t)n;
    return b + HDR;
}
static void heap_free(FT_Memory m, void *p)
{
    NotoHeap *h = m->user; unsigned char *b;
    if (!p) return;
    b = (unsigned char *)p - HDR; h->used -= *(size_t *)b; NOTO_FREE(b);
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

struct NotoProvider {
    NotoHeap heap; struct FT_MemoryRec_ mem; FT_Library lib;
    FT_Face face[2]; NotoFontSource src[2]; int pixels; volatile int busy;
};

static void release(NotoFontSource *s)
{
    if (s->release && s->data) s->release(s->ctx, s->data);
    s->data = NULL;
}

void noto_destroy(NotoProvider *p)
{
    int i;
    if (!p) return;
    for (i = 0; i < 2; ++i) if (p->face[i]) FT_Done_Face(p->face[i]);
    if (p->lib) FT_Done_Library(p->lib);
    for (i = 0; i < 2; ++i) release(&p->src[i]);
    NOTO_FREE(p);
}

static int set_wght400(NotoProvider *p, FT_Face f)
{
    FT_MM_Var *mm = NULL; FT_Fixed c[16]; FT_UInt i; int found = 0, ok;
    if (!(f->face_flags & FT_FACE_FLAG_MULTIPLE_MASTERS)) return 1;     /* static face */
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

NotoStatus noto_create(NotoFontSource *latin, NotoFontSource *kr, NotoProvider **out)
{
    NotoProvider *p; NotoStatus st = NOTO_OK; int i;
    if (out) *out = NULL;
    if (!latin || !kr || !out) { if (latin) release(latin); if (kr) release(kr); return NOTO_E_PARAM; }
    p = NOTO_MALLOC(sizeof *p);
    if (!p) { release(latin); release(kr); return NOTO_E_NOMEM; }
    memset(p, 0, sizeof *p);
    p->src[0] = *latin; p->src[1] = *kr; latin->data = kr->data = NULL;   /* ownership moved */
    p->heap.limit = NOTO_MAX_FT_BYTES;
    p->mem.user = &p->heap; p->mem.alloc = heap_alloc; p->mem.free = heap_free; p->mem.realloc = heap_realloc;
    for (i = 0; i < 2; ++i)
        if (!p->src[i].data || !p->src[i].size || p->src[i].size > NOTO_MAX_FONT_BYTES || p->src[i].face_index < 0)
            st = NOTO_E_FONT;
    if (st == NOTO_OK && FT_New_Library(&p->mem, &p->lib)) { p->lib = NULL; st = NOTO_E_FREETYPE; }
    if (st == NOTO_OK) FT_Add_Default_Modules(p->lib);
    for (i = 0; st == NOTO_OK && i < 2; ++i) {
        const char *fam;
        if (FT_New_Memory_Face(p->lib, p->src[i].data, (FT_Long)p->src[i].size, p->src[i].face_index, &p->face[i])) {
            p->face[i] = NULL; st = NOTO_E_FONT; break;
        }
        fam = p->face[i]->family_name ? p->face[i]->family_name : "";
        if (strncmp(fam, "Noto Sans", 9) != 0 || (i == 0 && strstr(fam, "CJK"))) { st = NOTO_E_FAMILY; break; }
        if (FT_Select_Charmap(p->face[i], FT_ENCODING_UNICODE)) { st = NOTO_E_FONT; break; }
        if (!set_wght400(p, p->face[i])) { st = NOTO_E_FONT; break; }
    }
    if (st != NOTO_OK) { noto_destroy(p); return st; }
    *out = p;
    return NOTO_OK;
}

const char *noto_family(const NotoProvider *p, int kr_face)
{
    return p && p->face[kr_face ? 1 : 0] ? p->face[kr_face ? 1 : 0]->family_name : NULL;
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

static int enter(NotoProvider *p) { return !__sync_lock_test_and_set(&p->busy, 1); }
static void leave(NotoProvider *p) { __sync_lock_release(&p->busy); }

static NotoStatus size_to(NotoProvider *p, int scale)
{
    int px, i;
    if (scale < 1 || scale > NOTO_MAX_SCALE) return NOTO_E_RANGE;
    px = NOTO_BASE_PIXELS * scale;
    if (p->pixels == px) return NOTO_OK;
    for (i = 0; i < 2; ++i) if (FT_Set_Pixel_Sizes(p->face[i], 0, (FT_UInt)px)) { p->pixels = 0; return NOTO_E_FREETYPE; }
    p->pixels = px;
    return NOTO_OK;
}

int noto_has_glyph(NotoProvider *p, uint32_t s)
{
    return p && (FT_Get_Char_Index(p->face[0], s) || FT_Get_Char_Index(p->face[1], s));
}

static NotoStatus load(NotoProvider *p, uint32_t s, int render, NotoGlyph *g)
{
    int f; FT_UInt gi = 0; FT_GlyphSlot sl;
    for (f = 0; f < 2 && !gi; ++f) gi = FT_Get_Char_Index(p->face[f], s);
    f = gi ? f - 1 : 0;
    g->scalar = s; g->glyph_index = gi; g->kr_face = f; g->missing = !gi;
    if (FT_Load_Glyph(p->face[f], gi, FT_LOAD_NO_HINTING | FT_LOAD_NO_BITMAP)) return NOTO_E_FREETYPE;
    sl = p->face[f]->glyph;
    g->advance = (int32_t)sl->advance.x;
    g->bearing_x = (int32_t)sl->metrics.horiBearingX; g->bearing_y = (int32_t)sl->metrics.horiBearingY;
    g->width = (int32_t)sl->metrics.width; g->height = (int32_t)sl->metrics.height;
    g->abc_a = g->bearing_x; g->abc_b = g->width; g->abc_c = g->advance - g->bearing_x - g->width;
    if (g->advance < 0 || g->advance > (NOTO_COORD_LIMIT << 6)) return NOTO_E_RANGE;
    if (render && FT_Render_Glyph(sl, FT_RENDER_MODE_NORMAL)) return NOTO_E_FREETYPE;
    return NOTO_OK;
}

NotoStatus noto_glyph(NotoProvider *p, uint32_t s, int scale, NotoGlyph *g)
{
    NotoStatus st;
    if (!p || !g) return NOTO_E_PARAM;
    if (!enter(p)) return NOTO_E_BUSY;
    st = size_to(p, scale);
    if (st == NOTO_OK) st = load(p, s, 0, g);
    leave(p);
    return st;
}

static int ceil64(int64_t v) { return (int)((v + 63) >> 6); }

static NotoStatus metrics_locked(NotoProvider *p, int scale, NotoMetrics *m)
{
    int i; NotoStatus st = size_to(p, scale);
    if (st != NOTO_OK) return st;
    m->ascent = m->descent = 0;
    for (i = 0; i < 2; ++i) {
        FT_Size_Metrics *s = &p->face[i]->size->metrics;
        if (s->ascender > m->ascent) m->ascent = (int32_t)s->ascender;
        if (-s->descender > m->descent) m->descent = (int32_t)-s->descender;
    }
    m->height = m->ascent + m->descent;
    return NOTO_OK;
}

NotoStatus noto_metrics(NotoProvider *p, int scale, NotoMetrics *m)
{
    NotoStatus st;
    if (!p || !m) return NOTO_E_PARAM;
    if (!enter(p)) return NOTO_E_BUSY;
    st = metrics_locked(p, scale, m);
    leave(p);
    return st;
}

NotoStatus noto_measure(NotoProvider *p, const uint16_t *text, size_t len, int scale, NotoExtent *e)
{
    NotoMetrics m; size_t cur = 0; NotoStatus st;
    if (!p || !e || (len && !text) || len > NOTO_MAX_TEXT) return NOTO_E_PARAM;
    memset(e, 0, sizeof *e);
    if (!enter(p)) return NOTO_E_BUSY;
    if ((st = metrics_locked(p, scale, &m)) != NOTO_OK) goto done;
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
    leave(p);
    return st;
}

NotoStatus noto_draw(NotoProvider *p, const uint16_t *text, size_t len, int scale, int x, int y,
                     const NotoRect *clip, NotoCoverageFn fn, void *ctx, NotoPen *pen)
{
    NotoMetrics m; NotoStatus st; NotoPen local = {0, 0}; int base;
    if (!p || !fn || (len && !text) || len > NOTO_MAX_TEXT) return NOTO_E_PARAM;
    if (!pen) pen = &local;
    if (pen->cursor > len || pen->x26 < 0) return NOTO_E_PARAM;
    if (x < -NOTO_COORD_LIMIT || x > NOTO_COORD_LIMIT || y < -NOTO_COORD_LIMIT || y > NOTO_COORD_LIMIT) return NOTO_E_RANGE;
    if (!enter(p)) return NOTO_E_BUSY;
    if ((st = metrics_locked(p, scale, &m)) != NOTO_OK) goto done;
    base = y + ceil64(m.ascent);
    while (pen->cursor < len) {
        size_t cur = pen->cursor; uint32_t s; int rep, row, gx, gy; NotoGlyph g; FT_GlyphSlot sl; FT_Bitmap *bm;
        noto_decode(text, len, &cur, &s, &rep);
        if ((st = load(p, s, 1, &g)) != NOTO_OK) goto done;
        sl = p->face[g.kr_face]->glyph; bm = &sl->bitmap;
        if (bm->width && bm->rows &&
            (bm->pixel_mode != FT_PIXEL_MODE_GRAY || bm->num_grays != 256 || !bm->buffer ||
             bm->width > 4096 || bm->rows > 4096)) { st = NOTO_E_BITMAP; goto done; }
        if (pen->x26 + g.advance > ((int64_t)NOTO_COORD_LIMIT << 6)) { st = NOTO_E_RANGE; goto done; }
        gx = x + (int)((pen->x26 + 32) >> 6) + sl->bitmap_left;
        gy = base - sl->bitmap_top;
        for (row = 0; row < (int)bm->rows; ++row) {
            const uint8_t *src = bm->buffer + (ptrdiff_t)row * bm->pitch;   /* signed pitch */
            int px = gx, n = (int)bm->width, yy = gy + row;
            if (clip) {
                if (yy < clip->top || yy >= clip->bottom) continue;
                if (px < clip->left) { src += clip->left - px; n -= clip->left - px; px = clip->left; }
                if (px + n > clip->right) n = clip->right - px;
            }
            if (n <= 0) continue;
            if (fn(ctx, px, yy, src, n)) { st = NOTO_E_ABORT; goto done; }   /* pen stays: resumable */
        }
        pen->cursor = cur; pen->x26 += g.advance;
    }
    st = NOTO_OK;
done:
    leave(p);
    return st;
}
