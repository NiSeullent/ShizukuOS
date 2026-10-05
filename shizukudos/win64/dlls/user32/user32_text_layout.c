/* SPDX-License-Identifier: GPL-2.0-only
 * user32 text layout: portable measure-callback driven core of DrawTextW. See user32_text_layout.h for the contract. */
#include "user32_text_layout.h"
#include <limits.h>
#include <string.h>

#define CHUNK 512                               /* units handed to one fit callback call (bounds per-call work) */
#define TAB_DEFAULT_CHARS 8

static const uint16_t g_dots[3] = { '.', '.', '.' };
static const uint16_t g_alpha[52] = {
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z' };

/* ---------------------------------------------------------------- checked arithmetic */
int shz_tl_mul_size(size_t a, size_t b, size_t *out)
{
    if (a && b > (size_t)-1 / a) return 0;
    *out = a * b;
    return 1;
}

int shz_tl_add_size(size_t a, size_t b, size_t *out)
{
    if (a > (size_t)-1 - b) return 0;
    *out = a + b;
    return 1;
}

int shz_tl_text_bytes(int n, size_t *bytes)
{
    size_t units;
    if (n < 0 || (size_t)n > SHZ_TL_MAX_CHARS) return 0;
    if (!shz_tl_add_size((size_t)n, 1, &units)) return 0;
    return shz_tl_mul_size(units, sizeof(uint16_t), bytes);
}

static int sat_add(int a, int b)
{
    int64_t v = (int64_t)a + b;
    return v > INT_MAX ? INT_MAX : v < INT_MIN ? INT_MIN : (int)v;
}

static int sat_mul(int a, int b)
{
    int64_t v = (int64_t)a * b;
    return v > INT_MAX ? INT_MAX : v < INT_MIN ? INT_MIN : (int)v;
}

static int is_high(uint16_t c) { return c >= 0xD800 && c <= 0xDBFF; }
static int is_low(uint16_t c) { return c >= 0xDC00 && c <= 0xDFFF; }

int shz_tl_is_wide(uint16_t c)
{
    return (c >= 0x1100 && c <= 0x115F) || (c >= 0x2E80 && c <= 0xA4CF) || (c >= 0xAC00 && c <= 0xD7A3) ||
           (c >= 0xF900 && c <= 0xFAFF) || (c >= 0xFE30 && c <= 0xFE6F) || (c >= 0xFF00 && c <= 0xFF60) ||
           (c >= 0xFFE0 && c <= 0xFFE6) || (c >= 0xD840 && c <= 0xD87F);   /* high surrogates of the CJK extension planes */
}

/* ---------------------------------------------------------------- measuring */
static int meas(const shz_tl_layout_t *L, const uint16_t *s, int n, int *w)
{
    int v = 0;
    if (n <= 0) { *w = 0; return 1; }
    if (!L->p.measure(L->p.ctx, s, n, &v) || v < 0) return 0;
    *w = v;
    return 1;
}

static int fit_raw(const shz_tl_layout_t *L, const uint16_t *s, int n, int maxw, int *f, int *w)
{
    int lo, hi, v = 0;
    if (maxw < 0 || n <= 0) { *f = 0; *w = 0; return 1; }
    if (L->p.fit) {
        int fc = 0, fw = 0;
        if (!L->p.fit(L->p.ctx, s, n, maxw, &fc, &fw) || fc < 0 || fc > n || fw < 0) return 0;
        *f = fc; *w = fw;
        return 1;
    }
    lo = 0; hi = n;                                 /* largest f with width(f) <= maxw, widths are monotone */
    while (lo < hi) {
        const int mid = lo + (hi - lo + 1) / 2;
        if (!meas(L, s, mid, &v)) return 0;
        if (v <= maxw) lo = mid; else hi = mid - 1;
    }
    if (!meas(L, s, lo, &v)) return 0;
    *f = lo; *w = v;
    return 1;
}

/* How many of the n tab-free units fit into maxw; never ends inside a surrogate pair. */
static int seg_fit(const shz_tl_layout_t *L, const uint16_t *s, int n, int maxw, int *f, int *w)
{
    int done = 0, used = 0;
    while (done < n) {
        int c = n - done, fc = 0, fw = 0;
        if (c > CHUNK) c = CHUNK;
        if (done + c < n && is_high(s[done + c - 1]) && is_low(s[done + c])) --c;
        if (!fit_raw(L, s + done, c, maxw - used, &fc, &fw)) return 0;
        if (fc < c) {
            if (fc > 0 && is_high(s[done + fc - 1]) && is_low(s[done + fc])) {
                --fc;
                if (!meas(L, s + done, fc, &fw)) return 0;
            }
            *f = done + fc; *w = sat_add(used, fw);
            return 1;
        }
        done += c; used = sat_add(used, fw);
    }
    *f = n; *w = used;
    return 1;
}

static int next_stop(const shz_tl_layout_t *L, int x)
{
    return sat_mul(x / L->tab_px + 1, L->tab_px);
}

/* Largest k such that buf[a, a + k) (tabs honoured, origin x = 0) fits into maxw. */
static int line_fit(const shz_tl_layout_t *L, int a, int b, int maxw, int *k)
{
    int pos = a, x = 0;
    while (pos < b) {
        int e = pos, f = 0, w = 0;
        while (e < b && L->buf[e] != '\t') ++e;
        if (e > pos) {
            if (!seg_fit(L, L->buf + pos, e - pos, maxw - x, &f, &w)) return 0;
            if (f < e - pos) { *k = pos + f - a; return 1; }
            x = sat_add(x, w);
            pos = e;
        }
        if (pos < b) {                              /* a tab */
            const int nx = next_stop(L, x);
            if (nx > maxw) { *k = pos - a; return 1; }
            x = nx; ++pos;
        }
    }
    *k = b - a;
    return 1;
}

/* ---------------------------------------------------------------- run iteration */
void shz_tl_iter_begin(const shz_tl_layout_t *L, int line, shz_tl_iter_t *it)
{
    it->L = L; it->ln = &L->lines[line];
    it->part = 0; it->pos = -1; it->x = it->ln->x;
}

int shz_tl_iter_next(shz_tl_iter_t *it, shz_tl_run_t *run)
{
    const shz_tl_layout_t *L = it->L;
    const shz_tl_line_t *ln = it->ln;
    for (;;) {
        int a, b, e, w;
        if (it->part > 2) return 0;
        if (it->part == 1) {
            it->part = 2; it->pos = -1;
            if (ln->dots) {
                if (!meas(L, g_dots, 3, &w)) return SHZ_TL_E_MEASURE;
                run->p = g_dots; run->n = 3; run->x = it->x; run->w = w; run->is_dots = 1; run->buf_off = -1;
                it->x = sat_add(it->x, w);
                return 1;
            }
            continue;
        }
        a = it->part == 0 ? ln->start : ln->tail_off;
        b = a + (it->part == 0 ? ln->head_len : ln->tail_len);
        if (it->pos < 0) it->pos = a;
        if (it->pos >= b) { ++it->part; it->pos = -1; continue; }
        if (L->buf[it->pos] == '\t' && L->tab_px > 0) {
            it->x = next_stop(L, it->x - ln->x) + ln->x;
            ++it->pos;
            continue;
        }
        e = it->pos;
        while (e < b && L->buf[e] != '\t') ++e;
        if (!meas(L, L->buf + it->pos, e - it->pos, &w)) return SHZ_TL_E_MEASURE;
        run->p = L->buf + it->pos; run->n = e - it->pos; run->x = it->x; run->w = w; run->is_dots = 0; run->buf_off = it->pos;
        it->x = sat_add(it->x, w);
        it->pos = e;
        return 1;
    }
}

static int line_width(const shz_tl_layout_t *L, shz_tl_line_t *ln, int *w)
{
    shz_tl_iter_t it;
    shz_tl_run_t r;
    int st, saved = ln->x;
    ln->x = 0;
    it.L = L; it.ln = ln; it.part = 0; it.pos = -1; it.x = 0;
    while ((st = shz_tl_iter_next(&it, &r)) > 0) { }
    ln->x = saved;
    if (st < 0) return 0;
    *w = it.x;
    return 1;
}

int shz_tl_underline(const shz_tl_layout_t *L, int line, int *x, int *w)
{
    shz_tl_iter_t it;
    shz_tl_run_t r;
    int st;
    if (L->ul_index < 0 || line < 0 || line >= L->nlines) return 0;
    shz_tl_iter_begin(L, line, &it);
    while ((st = shz_tl_iter_next(&it, &r)) > 0) {
        if (!r.is_dots && L->ul_index >= r.buf_off && L->ul_index < r.buf_off + r.n) {
            const int rel = L->ul_index - r.buf_off;
            int pre = 0, cw = 0, cn = 1;
            if (is_high(r.p[rel]) && rel + 1 < r.n && is_low(r.p[rel + 1])) cn = 2;
            if (!meas(L, r.p, rel, &pre) || !meas(L, r.p + rel, cn, &cw)) return 0;
            *x = sat_add(r.x, pre); *w = cw;
            return 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- layout construction */
static int emit(shz_tl_layout_t *L, int start, int len, int para_end)
{
    shz_tl_line_t *ln;
    if ((size_t)L->nlines >= L->lines_cap) {
        size_t ncap, bytes;
        shz_tl_line_t *nl;
        if (L->lines_cap >= SHZ_TL_MAX_LINES) return SHZ_TL_E_TOOBIG;
        ncap = L->lines_cap ? L->lines_cap * 2 : 8;
        if (ncap > SHZ_TL_MAX_LINES) ncap = SHZ_TL_MAX_LINES;
        if (!shz_tl_mul_size(ncap, sizeof *nl, &bytes)) return SHZ_TL_E_TOOBIG;
        nl = L->p.alloc(L->p.ctx, bytes);
        if (!nl) return SHZ_TL_E_NOMEM;
        if (L->nlines) memcpy(nl, L->lines, (size_t)L->nlines * sizeof *nl);
        if (L->lines) L->p.release(L->p.ctx, L->lines);
        L->lines = nl; L->lines_cap = ncap;
    }
    ln = &L->lines[L->nlines++];
    memset(ln, 0, sizeof *ln);
    ln->start = start; ln->head_len = len; ln->tail_off = start + len; ln->para_end = para_end;
    return SHZ_TL_OK;
}

/* split the hard line buf[a, b) into display lines for a rect_w wide rectangle */
static int wrap_paragraph(shz_tl_layout_t *L, int a, int b, int rect_w, int word_ell)
{
    int s = a, st;
    const int nofw = (L->fmt & SHZ_TL_DT_NOFULLWIDTHCHARBREAK) != 0;
    if (a == b) return emit(L, a, 0, b);
    while (s < b) {
        int k = 0, e, q, found = 0, len;
        if (!line_fit(L, s, b, rect_w < 0 ? 0 : rect_w, &k)) return SHZ_TL_E_MEASURE;
        e = s + k;
        if (e >= b) return emit(L, s, b - s, b);
        for (q = e; q > s; --q) {
            const int sp = L->buf[q] == ' ';
            int wide = 0;
            if (!sp && !nofw && !(is_high(L->buf[q - 1]) && is_low(L->buf[q])))
                wide = shz_tl_is_wide(L->buf[q - 1]) || shz_tl_is_wide(L->buf[q]);
            if (sp || wide) {
                len = q - s;
                if (sp) while (len > 0 && L->buf[s + len - 1] == ' ') --len;   /* blanks at the wrap do not count */
                if ((st = emit(L, s, len, b)) != SHZ_TL_OK) return st;
                s = sp ? q + 1 : q;
                found = 1;
                break;
            }
        }
        if (found) continue;
        if (word_ell) {                             /* WORD_ELLIPSIS: the over-long word is truncated, not broken */
            int w = e;
            while (w < b && L->buf[w] != ' ') ++w;
            if ((st = emit(L, s, w - s, b)) != SHZ_TL_OK) return st;
            s = w < b ? w + 1 : b;
            continue;
        }
        if (e == s) e = s + ((is_high(L->buf[s]) && s + 1 < b && is_low(L->buf[s + 1])) ? 2 : 1);   /* always progress */
        if ((st = emit(L, s, e - s, b)) != SHZ_TL_OK) return st;
        s = e;
    }
    return SHZ_TL_OK;
}

static int apply_ellipsis(shz_tl_layout_t *L, shz_tl_line_t *ln, int rect_w, int forced, int path)
{
    const int a = ln->start, b = ln->start + ln->head_len;
    int W, D = 0, k = 0, i;
    if (!line_width(L, ln, &W)) return SHZ_TL_E_MEASURE;
    if (!forced && W <= rect_w) return SHZ_TL_OK;
    if (!meas(L, g_dots, 3, &D)) return SHZ_TL_E_MEASURE;
    if (path && !forced) {
        int bs = -1;
        for (i = b - 1; i >= a; --i) if (L->buf[i] == '\\') { bs = i; break; }
        if (bs > a) {
            int Wt = 0, tabs = 0;
            for (i = bs; i < b; ++i) if (L->buf[i] == '\t') tabs = 1;
            if (!tabs) {
                if (!meas(L, L->buf + bs, b - bs, &Wt)) return SHZ_TL_E_MEASURE;
                if (sat_add(D, Wt) <= rect_w) {
                    if (!line_fit(L, a, bs, rect_w - D - Wt, &k)) return SHZ_TL_E_MEASURE;
                    ln->head_len = k; ln->dots = 1; ln->tail_off = bs; ln->tail_len = b - bs;
                    L->modified = 1;
                    return SHZ_TL_OK;
                }
            }
        }                                           /* no usable backslash or the tail alone does not fit: end ellipsis */
    }
    if (rect_w - D > 0 && !line_fit(L, a, b, rect_w - D, &k)) return SHZ_TL_E_MEASURE;
    if (rect_w - D <= 0) k = 0;
    ln->head_len = k; ln->dots = 1; ln->tail_off = a + k; ln->tail_len = 0;
    L->modified = 1;
    return SHZ_TL_OK;
}

void shz_tl_free(shz_tl_layout_t *L)
{
    if (L->p.release) {
        if (L->buf) L->p.release(L->p.ctx, L->buf);
        if (L->lines) L->p.release(L->p.ctx, L->lines);
    }
    memset(L, 0, sizeof *L);
}

static int build(shz_tl_layout_t *L, const uint16_t *text, int n, int rect_w, int rect_h)
{
    const uint32_t fmt = L->fmt;
    const int single = (fmt & SHZ_TL_DT_SINGLELINE) != 0;
    const int wrap = (fmt & SHZ_TL_DT_WORDBREAK) && !single;
    const int ell = (fmt & (SHZ_TL_DT_END_ELLIPSIS | SHZ_TL_DT_PATH_ELLIPSIS | SHZ_TL_DT_WORD_ELLIPSIS)) &&
                    !(fmt & SHZ_TL_DT_CALCRECT);
    int i = 0, o = 0, para = 0, st, ul = -1, li;
    while (i < n) {
        const uint16_t c = text[i];
        if (!(fmt & SHZ_TL_DT_NOPREFIX) && c == '&') {
            if (i + 1 < n && text[i + 1] == '&') { L->buf[o++] = '&'; i += 2; continue; }
            if (i + 1 < n && (single || (text[i + 1] != '\r' && text[i + 1] != '\n')) && ul < 0) ul = o;
            ++i;                                    /* the '&' itself never appears; a trailing one is dropped */
            continue;
        }
        if (!single && (c == '\r' || c == '\n')) {
            if (wrap) st = wrap_paragraph(L, para, o, rect_w, (fmt & SHZ_TL_DT_WORD_ELLIPSIS) != 0 && ell);
            else st = emit(L, para, o - para, o);
            if (st != SHZ_TL_OK) return st;
            ++i;
            if (i < n && (text[i] == '\r' || text[i] == '\n') && text[i] != c) ++i;
            para = o;
            continue;
        }
        if (c == '\r' || c == '\n') L->buf[o++] = ' ';
        else if (c == '\t' && L->tab_px <= 0) L->buf[o++] = ' ';
        else L->buf[o++] = c;
        ++i;
    }
    L->buf_len = o;
    if (wrap) st = wrap_paragraph(L, para, o, rect_w, (fmt & SHZ_TL_DT_WORD_ELLIPSIS) != 0 && ell);
    else st = emit(L, para, o - para, o);
    if (st != SHZ_TL_OK) return st;
    if ((fmt & SHZ_TL_DT_HIDEPREFIX) && !(fmt & SHZ_TL_DT_PREFIXONLY)) ul = -1;
    L->ul_index = ul;

    if (ell) {
        const int path = (fmt & SHZ_TL_DT_PATH_ELLIPSIS) != 0;
        if (wrap && !(fmt & SHZ_TL_DT_NOCLIP)) {
            int maxvis = L->line_h > 0 ? rect_h / L->line_h : 1;
            if (maxvis < 1) maxvis = 1;
            if (L->nlines > maxvis) {               /* the last visible line absorbs the remaining text of its paragraph */
                shz_tl_line_t *last;
                L->nlines = maxvis;
                last = &L->lines[maxvis - 1];
                last->head_len = last->para_end - last->start;
                last->tail_off = last->start + last->head_len; last->tail_len = 0; last->dots = 0;
                if ((st = apply_ellipsis(L, last, rect_w, 1, 0)) != SHZ_TL_OK) return st;
            }
        }
        for (li = 0; li < L->nlines; ++li)
            if (!L->lines[li].dots && (st = apply_ellipsis(L, &L->lines[li], rect_w, 0, path)) != SHZ_TL_OK) return st;
    }

    for (li = 0; li < L->nlines; ++li) {
        shz_tl_line_t *ln = &L->lines[li];
        int w = 0, y;
        if (!line_width(L, ln, &w)) return SHZ_TL_E_MEASURE;
        ln->width = w;
        if (w > L->max_width) L->max_width = w;
        ln->x = (fmt & 3u) == SHZ_TL_DT_CENTER ? (rect_w - w) / 2 : (fmt & SHZ_TL_DT_RIGHT) ? rect_w - w : 0;
        y = sat_mul(li, L->line_h);
        if (single && L->nlines == 1) {
            if (fmt & SHZ_TL_DT_VCENTER) y = (rect_h - L->line_h) / 2;
            else if (fmt & SHZ_TL_DT_BOTTOM) y = rect_h - L->line_h;
        }
        ln->y = y;
        if (fmt & SHZ_TL_DT_NOCLIP) ln->visible = 1;
        else {
            const int bottom = sat_add(y, L->line_h);
            ln->visible = y < rect_h && bottom > 0;
            if ((fmt & SHZ_TL_DT_EDITCONTROL) && bottom > rect_h) ln->visible = 0;   /* no partially visible last line */
        }
    }
    L->height = sat_mul(L->nlines, L->line_h);
    return SHZ_TL_OK;
}

int shz_tl_layout(const shz_tl_params_t *p, const uint16_t *text, int len, int rect_w, int rect_h, uint32_t fmt,
                  shz_tl_layout_t *L)
{
    size_t bytes;
    int n, st, tab_chars = 0;
    memset(L, 0, sizeof *L);
    if (!p || !L || !p->measure || !p->alloc || !p->release || p->line_height <= 0 || (!text && len != 0))
        return SHZ_TL_E_PARAM;
    if (fmt & SHZ_TL_DT_RTLREADING) return SHZ_TL_E_UNSUPPORTED;
    if (fmt & 0xFFC00000u) return SHZ_TL_E_UNSUPPORTED;
    if (len < 0) {
        n = 0;
        while ((size_t)n <= SHZ_TL_MAX_CHARS && text[n]) ++n;
    } else n = len;
    if (!shz_tl_text_bytes(n, &bytes)) return SHZ_TL_E_TOOBIG;

    L->p = *p;
    if (fmt & SHZ_TL_DT_TABSTOP) {                  /* bits 15..8 are the tab length, not flags (documented by Windows) */
        tab_chars = (int)((fmt >> 8) & 0xFFu);
        if (!tab_chars) tab_chars = TAB_DEFAULT_CHARS;
        fmt &= ~0xFF00u;
    } else if (fmt & SHZ_TL_DT_EXPANDTABS) tab_chars = TAB_DEFAULT_CHARS;
    L->fmt = fmt;
    L->ul_index = -1;
    L->line_h = p->line_height;
    if (fmt & SHZ_TL_DT_EXTERNALLEADING) {
        if (p->external_leading < 0 || p->external_leading > INT_MAX - p->line_height) return SHZ_TL_E_PARAM;
        L->line_h += p->external_leading;
    }
    if (tab_chars) {
        int avg = p->avg_char_width;
        if (fmt & SHZ_TL_DT_EDITCONTROL) {          /* edit control: ((width of a-zA-Z) / 26 + 1) / 2 */
            int w52 = 0;
            if (!p->measure(p->ctx, g_alpha, 52, &w52) || w52 < 0) { memset(L, 0, sizeof *L); return SHZ_TL_E_MEASURE; }
            avg = (w52 / 26 + 1) / 2;
        }
        L->tab_px = sat_mul(avg > 0 ? avg : 1, tab_chars);
    }
    L->buf = p->alloc(p->ctx, bytes);
    if (!L->buf) { memset(L, 0, sizeof *L); return SHZ_TL_E_NOMEM; }
    st = build(L, text, n, rect_w, rect_h);
    if (st != SHZ_TL_OK) { shz_tl_free(L); return st; }
    return SHZ_TL_OK;
}

int shz_tl_displayed_text(const shz_tl_layout_t *L, uint16_t *out, int cap)
{
    const shz_tl_line_t *ln;
    int total = 0;
    if (!L || L->nlines != 1) return SHZ_TL_E_PARAM;
    ln = &L->lines[0];
    {
        const uint16_t *parts[3] = { L->buf + ln->start, g_dots, L->buf + ln->tail_off };
        const int counts[3] = { ln->head_len, ln->dots ? 3 : 0, ln->tail_len };
        int i, j;
        for (i = 0; i < 3; ++i)
            for (j = 0; j < counts[i]; ++j, ++total)
                if (out && total < cap) out[total] = parts[i][j];
    }
    return total;
}
