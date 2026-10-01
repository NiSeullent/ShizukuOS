/* SPDX-License-Identifier: GPL-2.0-only
 * Opt-in observations of the actual Chromium software raster route. Existing
 * SHZ_K32TRACE=1 enables these bounded lines. No pixels, clips or API results
 * are modified; omitted lines and sampled hashes are not rendering proof. */
#include "gdi_internal.h"
#include "gdi_render_trace.h"

static unsigned trace_state, dib_count, blit_count, present_count;

static int enabled(void)
{
    if (!trace_state) {
        WCHAR value[2];
        DWORD saved = shz_last_error();
        DWORD n = GetEnvironmentVariableW(L"SHZ_K32TRACE",value,2);
        trace_state = n == 1 && value[0] == '1' ? 2 : 1;
        shz_set_last_error(saved);
    }
    return trace_state == 2;
}
/* First 16, then every 64th up to 4096 per operation/process (at most 80
 * lines). All counters are protected by the existing GDI lock. */
static unsigned ticket(unsigned *counter)
{
    unsigned n;
    if (!enabled()) return 0;
    if (*counter >= 4096) return 0;
    n = ++*counter;
    return n <= 16 || (n <= 4096 && !(n & 63)) ? n : 0;
}
typedef struct { char text[640]; unsigned used; } line_t;
static void literal(line_t *line, const char *s)
{
    while (*s && line->used + 2 < sizeof line->text) line->text[line->used++] = *s++;
}
static void field(line_t *line, const char *label, uint64_t value)
{
    char digits[16]; unsigned n = 0;
    literal(line," "); literal(line,label); literal(line,"=");
    do { digits[n++] = "0123456789abcdef"[value & 15]; value >>= 4; } while(value && n < sizeof digits);
    while (n && line->used + 2 < sizeof line->text) line->text[line->used++] = digits[--n];
}
static void emit(line_t *line, DWORD saved)
{
    line->text[line->used++] = '\n';
    NtShzDebugPrint(line->text,line->used);
    shz_set_last_error(saved);
}
void gdi_render_trace_dib(bitmap_t *b, HBITMAP handle)
{
    unsigned n = ticket(&dib_count); line_t line = {{0},0}; DWORD saved;
    if (!n) return;
    saved = shz_last_error(); literal(&line,"GDI raster: DIB");
    field(&line,"seq",n); field(&line,"bitmap",(uintptr_t)handle);
    field(&line,"width",b->w); field(&line,"height",b->h); field(&line,"topdown",b->topdown);
    field(&line,"section",(uintptr_t)b->section); field(&line,"offset",b->section_offset);
    /* Do not sample freshly allocated pixels: shared pages may be concurrently
     * produced, and creation alone is not a submitted frame. */
    emit(&line,saved);
}
void gdi_render_trace_blit(dc_t *dst, const bitmap_t *source, const gctx_t *ctx,
    int x, int y, int w, int h, int sx, int sy, int sw, int sh, DWORD rop)
{
    unsigned n = ticket(&blit_count); line_t line = {{0},0}; DWORD saved;
    if (!n) return;
    saved = shz_last_error(); literal(&line,"GDI raster: blit");
    field(&line,"seq",n); field(&line,"hwnd",(uintptr_t)dst->hwnd); field(&line,"memdc",dst->memdc);
    field(&line,"x",(uint32_t)x); field(&line,"y",(uint32_t)y); field(&line,"w",(uint32_t)w); field(&line,"h",(uint32_t)h);
    field(&line,"rop",rop); field(&line,"clips",ctx->clip ? ctx->clip->n : 0); field(&line,"dirty",ctx->has_dirty);
    field(&line,"sx",(uint32_t)sx); field(&line,"sy",(uint32_t)sy);
    field(&line,"sw",(uint32_t)sw); field(&line,"sh",(uint32_t)sh);
    if (source) {
        field(&line,"source_w",source->w); field(&line,"source_h",source->h);
        field(&line,"source_topdown",source->topdown); field(&line,"source_section",(uintptr_t)source->section);
    }
    /* Do not read user-mode bitmap pixels here. Clipping may consume only
     * part of a source rectangle; its unused pages may be inaccessible. The
     * kernel samples only its successfully staged, owned pixel buffer. */
    emit(&line,saved);
}
void gdi_render_trace_present(backing_t *b, const RECT *rect, int32_t status)
{
    unsigned n = ticket(&present_count); line_t line = {{0},0}; DWORD saved;
    if (!n) return;
    saved = shz_last_error(); literal(&line,"GDI raster: present");
    field(&line,"seq",n); field(&line,"hwnd",(uintptr_t)b->hwnd); field(&line,"status",(uint32_t)status);
    field(&line,"left",rect->left); field(&line,"top",rect->top); field(&line,"right",rect->right); field(&line,"bottom",rect->bottom);
    field(&line,"backing_w",b->bmp.w); field(&line,"backing_h",b->bmp.h);
    emit(&line,saved);
}
