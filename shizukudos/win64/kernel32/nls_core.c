/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku NLS core (see nls_core.h). Collation model, documented because it is NOT Windows' sort-key data:
 *
 * Every string is turned into a sequence of collation elements (primary, secondary, tertiary [, special]) after
 * canonical decomposition:
 *   primary    class << 24 | key: whitespace < punctuation/symbols (Unicode DUCET order for ASCII: _ - , ; : ! ? . ' " ( ) [ ]
 *              { } @ * / \ & # % ` ^ + < = > | ~ then other punctuation, other symbols, currency) < digits (by decimal
 *              value in every script) < Latin a..z < every other letter (by lowercase code point) < ideographs (by code
 *              point). Controls and format characters carry no weight. Nonspacing marks carry no primary weight.
 *   secondary  0x20 for a base character; a nonspacing mark adds an element whose weight follows the DUCET order for the
 *              common Latin diacritics (acute < grave < breve < circumflex < caron < ring < diaeresis < ...), by code point
 *              otherwise. So "resume" < "resume" + accent.
 *   tertiary   lowercase (2) < uppercase (8); bit flags for fullwidth forms, hiragana vs katakana, expansions (ss/ae/oe/ij
 *              ligatures) and non-ASCII digits. Compared lowercase-first, as Windows does.
 * A fourth level exists only in "word sort" (SORT_STRINGSORT not set): hyphen-minus and apostrophe carry no weight at the
 * first three levels and only break ties (the string with more of them sorts later), which keeps "co-op" beside "coop".
 * Not modelled: language tailorings (only one locale exists), contractions, Hangul jamo/CJK stroke or radical order, kana
 * vs. halfwidth-kana equivalence, and Windows' exact weights: results agree with Windows for the ordinary Latin/Greek/
 * Cyrillic/digit/ASCII cases that the tests cover and may differ for exotic characters.
 */
#include "nls_core.h"
#define UNI_DEFINE_TABLES
#include "unidata.h"

/* ---------------------------------------------------------------- properties */
uint32_t nls_attr(uint32_t cp)
{
    int lo = 0, hi = UNI_NRUNS - 1;
    if (cp > 0x10FFFF) return GC_Cn;
    while (lo < hi) {
        const int mid = (lo + hi + 1) >> 1;
        if (uni_runs[mid].start <= cp) lo = mid; else hi = mid - 1;
    }
    return uni_runs[lo].attr;
}

static const uni_case_t *case_find(uint32_t cp)
{
    int lo = 0, hi = UNI_NCASE - 1;
    while (lo <= hi) {
        const int mid = (lo + hi) >> 1;
        if (uni_case[mid].cp == cp) return &uni_case[mid];
        if (uni_case[mid].cp < cp) lo = mid + 1; else hi = mid - 1;
    }
    return 0;
}
uint32_t nls_upper(uint32_t cp) { const uni_case_t *c = case_find(cp); return c ? (uint32_t)((int32_t)cp + c->up) : cp; }
uint32_t nls_lower(uint32_t cp) { const uni_case_t *c = case_find(cp); return c ? (uint32_t)((int32_t)cp + c->lo) : cp; }

static int is_hex_digit(uint32_t cp)
{
    return (cp >= '0' && cp <= '9') || (cp >= 'A' && cp <= 'F') || (cp >= 'a' && cp <= 'f') || (cp >= 0xFF10 && cp <= 0xFF19) ||
           (cp >= 0xFF21 && cp <= 0xFF26) || (cp >= 0xFF41 && cp <= 0xFF46);
}

unsigned nls_ctype1(uint32_t cp)
{
    const uint32_t a = nls_attr(cp);
    const unsigned gc = NLS_GC(a);
    unsigned r = 0;
    if (gc == GC_Cs || gc == GC_Cn) return 0;
    r |= 0x200;                                                        /* C1_DEFINED */
    if (gc == GC_Lu || gc == GC_Lt) r |= 0x01 | 0x100;                 /* C1_UPPER | C1_ALPHA */
    else if (gc == GC_Ll) r |= 0x02 | 0x100;                           /* C1_LOWER | C1_ALPHA */
    else if (gc <= GC_Lo) r |= 0x100;                                  /* C1_ALPHA: caseless letters */
    if (gc == GC_Nd) r |= 0x04;                                        /* C1_DIGIT */
    if (NLS_WS(a)) r |= 0x08;                                          /* C1_SPACE */
    if ((gc >= GC_Pc && gc <= GC_Po) || (gc >= GC_Sm && gc <= GC_So)) r |= 0x10;   /* C1_PUNCT: punctuation and symbols */
    if (gc == GC_Cc) r |= 0x20;                                        /* C1_CNTRL */
    if (cp == 9 || gc == GC_Zs) r |= 0x40;                             /* C1_BLANK */
    if (is_hex_digit(cp)) r |= 0x80;                                   /* C1_XDIGIT */
    return r;
}

unsigned nls_ctype2(uint32_t cp)
{
    static const uint8_t map[14] = { 1, 2, 2, 3, 4, 5, 6, 7, 0, 0, 8, 9, 10, 11 };   /* Unicode bidi class -> C2_* */
    const uint32_t a = nls_attr(cp);
    const unsigned gc = NLS_GC(a), b = NLS_BIDI(a);
    if (gc == GC_Cs || gc == GC_Cn) return 0;
    return b < 14 ? map[b] : 0;                                        /* embedding/isolate controls: C2_NOTAPPLICABLE */
}

unsigned nls_ctype3(uint32_t cp)
{
    const uint32_t a = nls_attr(cp);
    const unsigned gc = NLS_GC(a);
    unsigned r = 0;
    if (cp >= 0xD800 && cp < 0xDC00) return 0x0800;                    /* C3_HIGHSURROGATE */
    if (cp >= 0xDC00 && cp < 0xE000) return 0x1000;                    /* C3_LOWSURROGATE */
    if (gc == GC_Mn || gc == GC_Me) r |= 0x0001;                       /* C3_NONSPACING */
    if (gc >= GC_Sm && gc <= GC_So) r |= 0x0008;                       /* C3_SYMBOL */
    if (NLS_KATA(a)) r |= 0x0010;
    if (NLS_HIRA(a)) r |= 0x0020;
    if (NLS_HALF(a)) r |= 0x0040;
    if (NLS_FULL(a)) r |= 0x0080;
    if (NLS_IDEO(a)) r |= 0x0100;
    if (cp == 0x0640) r |= 0x0200;                                     /* C3_KASHIDA: ARABIC TATWEEL */
    if (gc <= GC_Lo) r |= 0x8000;                                      /* C3_ALPHA: letters, syllabaries, ideographs */
    return r;
}

/* ---------------------------------------------------------------- UTF-16 */
uint32_t nls_next_cp(const nls_w *s, int n, int *i)
{
    uint32_t c = s[(*i)++];
    if (c >= 0xD800 && c < 0xDC00 && *i < n && s[*i] >= 0xDC00 && s[*i] < 0xE000) {
        c = 0x10000 + ((c - 0xD800) << 10) + (uint32_t)(s[(*i)++] - 0xDC00);
    }
    return c;
}

int nls_put_cp(nls_w *d, int cap, int at, uint32_t cp)
{
    if (cp < 0x10000) {
        if (d) { if (at + 1 > cap) return 0; d[at] = (nls_w)cp; }
        return 1;
    }
    if (d) {
        if (at + 2 > cap) return 0;
        cp -= 0x10000;
        d[at] = (nls_w)(0xD800 + (cp >> 10));
        d[at + 1] = (nls_w)(0xDC00 + (cp & 0x3FF));
    }
    return 2;
}

/* ---------------------------------------------------------------- decomposition */
int nls_decompose(uint32_t cp, uint32_t out[3])
{
    int lo = 0, hi = UNI_NDECOMP - 1;
    if (cp > 0xFFFF) return 0;
    while (lo <= hi) {
        const int mid = (lo + hi) >> 1;
        if (uni_decomp[mid].cp == cp) {
            int k;
            for (k = 0; k < uni_decomp[mid].n; ++k) out[k] = uni_decomp[mid].d[k];
            return uni_decomp[mid].n;
        }
        if (uni_decomp[mid].cp < cp) lo = mid + 1; else hi = mid - 1;
    }
    return 0;
}

uint32_t nls_compose(uint32_t a, uint32_t b)
{
    int lo = 0, hi = UNI_NPAIRS - 1;
    while (lo <= hi) {
        const int mid = (lo + hi) >> 1;
        const uni_pair_t *p = &uni_pairs[mid];
        if (p->a == a && p->b == b) return p->c;
        if (p->a < a || (p->a == a && p->b < b)) lo = mid + 1; else hi = mid - 1;
    }
    return 0;
}

/* ---------------------------------------------------------------- collation elements */
typedef struct { uint32_t p, s, t, sp; } elem_t;

#define T_LOWER 2u
#define T_UPPER 8u
#define T_CASEBITS 0x0Au
#define T_NUMSCRIPT 0x10u
#define T_EXPAND 0x20u
#define T_WIDTH 0x40u
#define T_KANA 0x80u

enum { G_WS = 1, G_PUNCT = 2, G_DIGIT = 3, G_LATIN = 4, G_LETTER = 5, G_IDEO = 6, G_MISC = 7 };
#define PW(g, k) (((uint32_t)(g) << 24) | (uint32_t)(k))

static const char punct_order[] = "_-,;:!?.'\"()[]{}@*/\\&#%`^+<=>|~";

/* secondary weights of common combining marks, in DUCET order */
static uint32_t mark_weight(uint32_t cp)
{
    switch (cp) {
    case 0x301: return 0x24; case 0x300: return 0x25; case 0x306: return 0x26; case 0x302: return 0x27;
    case 0x30C: return 0x28; case 0x30A: return 0x29; case 0x308: return 0x2B; case 0x30B: return 0x2C;
    case 0x303: return 0x2D; case 0x307: return 0x2E; case 0x338: return 0x2F; case 0x327: return 0x30;
    case 0x328: return 0x31; case 0x304: return 0x32; case 0x131: return 0x33;
    default: return 0x100 + (cp & 0xFFFFF);
    }
}

static const struct { uint16_t cp; const char *letters; uint8_t upper; } expansions[] = {
    { 0x00DF, "ss", 0 }, { 0x1E9E, "ss", 1 }, { 0x00E6, "ae", 0 }, { 0x00C6, "ae", 1 }, { 0x0153, "oe", 0 }, { 0x0152, "oe", 1 },
    { 0x0133, "ij", 0 }, { 0x0132, "ij", 1 }, { 0xFB00, "ff", 0 }, { 0xFB01, "fi", 0 }, { 0xFB02, "fl", 0 }, { 0xFB03, "ffi", 0 },
    { 0xFB04, "ffl", 0 }, { 0xFB05, "st", 0 }, { 0xFB06, "st", 0 },
};
/* letters with a stroke or dot: a base letter plus a secondary difference */
static const struct { uint16_t cp; char base; uint8_t upper; uint16_t mark; } overlays[] = {
    { 0x00F8, 'o', 0, 0x338 }, { 0x00D8, 'o', 1, 0x338 }, { 0x0111, 'd', 0, 0x338 }, { 0x0110, 'd', 1, 0x338 },
    { 0x0127, 'h', 0, 0x338 }, { 0x0126, 'h', 1, 0x338 }, { 0x0142, 'l', 0, 0x338 }, { 0x0141, 'l', 1, 0x338 },
    { 0x0167, 't', 0, 0x338 }, { 0x0166, 't', 1, 0x338 }, { 0x0180, 'b', 0, 0x338 }, { 0x0131, 'i', 0, 0x131 },
};

static int is_mark_gc(unsigned gc) { return gc == GC_Mn || gc == GC_Mc || gc == GC_Me; }

/* Builds the element of one non-mark, non-expanding code point. */
static void make_elem(elem_t *e, uint32_t cp, uint32_t fl)
{
    uint32_t g = cp, tflags = 0, a;
    unsigned gc;
    e->p = e->s = e->t = e->sp = 0;
    if (cp >= 0xFF01 && cp <= 0xFF5E) { g = cp - 0xFEE0; tflags |= T_WIDTH; }         /* fullwidth ASCII */
    else if (cp == 0x3000) { g = 0x20; tflags |= T_WIDTH; }
    else if ((cp >= 0x3041 && cp <= 0x3096) || cp == 0x309D || cp == 0x309E) g = cp + 0x60;     /* hiragana: katakana primary */
    a = nls_attr(g);
    gc = NLS_GC(a);
    if (NLS_KATA(a) && g == cp) tflags |= T_KANA;                                            /* katakana sorts after hiragana */
    if (NLS_WS(a)) {
        if (fl & NLS_IGNORESYMBOLS) return;
        e->p = PW(G_WS, g == 0x20 ? 0x20 : g < 0x20 ? g : 0x100 + g);
        e->s = 0x20; e->t = T_LOWER | tflags;
        return;
    }
    switch (gc) {
    case GC_Cc: case GC_Cf: return;                                                  /* no weight */
    case GC_Lu: case GC_Ll: case GC_Lt: case GC_Lm: case GC_Lo: {
        const uint32_t lo = nls_lower(g);
        const int upper = gc == GC_Lt || lo != g;
        if (lo >= 'a' && lo <= 'z') e->p = PW(G_LATIN, 0x100 + (lo - 'a') * 4);
        else if (NLS_IDEO(a)) e->p = PW(G_IDEO, g);
        else e->p = PW(G_LETTER, lo);
        e->s = 0x20;
        e->t = (upper ? T_UPPER : T_LOWER) | tflags;
        return;
    }
    case GC_Nd:
        if (NLS_HASDIG(a)) {
            e->p = PW(G_DIGIT, NLS_DIGIT(a));
            e->s = 0x20;
            e->t = T_LOWER | (g >= 0x80 ? T_NUMSCRIPT : 0) | tflags;
            return;
        }
        /* fallthrough */
    case GC_Nl: case GC_No:
        e->p = PW(G_DIGIT, 0x1000 + g); e->s = 0x20; e->t = T_LOWER | tflags;
        return;
    case GC_Mn: case GC_Mc: case GC_Me:
        e->s = mark_weight(g); e->t = T_LOWER;
        return;
    case GC_Pc: case GC_Pd: case GC_Ps: case GC_Pe: case GC_Pi: case GC_Pf: case GC_Po:
    case GC_Sm: case GC_Sc: case GC_Sk: case GC_So: {
        if (fl & NLS_IGNORESYMBOLS) return;
        if (!(fl & NLS_STRINGSORT) && (g == '-' || g == '\'')) { e->sp = g; return; }   /* word sort: ties only */
        if (g < 0x80) {
            unsigned k;
            for (k = 0; punct_order[k]; ++k)
                if ((unsigned char)punct_order[k] == g) { e->p = PW(G_PUNCT, k + 1); break; }
            if (!e->p) e->p = PW(G_PUNCT, 0x400000);                                  /* '$' is the last of the ASCII order */
        } else if (gc == GC_Sc) e->p = PW(G_PUNCT, 0x400001 + g);
        else if (gc >= GC_Sm) e->p = PW(G_PUNCT, 0x200000 + g);
        else e->p = PW(G_PUNCT, 0x1000 + g);
        e->s = 0x20; e->t = T_LOWER | tflags;
        return;
    }
    default:
        e->p = PW(G_MISC, g); e->s = 0x20; e->t = T_LOWER;                            /* unassigned, private use, lone surrogates */
        return;
    }
}

#define CIT_MAX 24
typedef struct {
    const nls_w *s;
    int n, i;
    uint32_t fl;
    elem_t buf[CIT_MAX];
    int nb, ib;
    int run_pos, run_end;                    /* digit run being emitted (SORT_DIGITSASNUMBERS) */
} cit_t;

static void cit_init(cit_t *it, const nls_w *s, int n, uint32_t fl)
{
    it->s = s; it->n = n; it->i = 0; it->fl = fl; it->nb = it->ib = 0; it->run_pos = it->run_end = 0;
}

static void cit_add(cit_t *it, const elem_t *e)
{
    if (!e->p && !e->s && !e->t && !e->sp) return;
    if (it->nb < CIT_MAX) it->buf[it->nb++] = *e;
}

static void cit_add_char(cit_t *it, uint32_t cp, int upper_hint)
{
    unsigned k;
    elem_t e;
    for (k = 0; k < sizeof expansions / sizeof expansions[0]; ++k)
        if (expansions[k].cp == cp) {
            const char *l = expansions[k].letters;
            for (; *l; ++l) {
                make_elem(&e, (uint32_t)(unsigned char)*l, it->fl);
                if (expansions[k].upper) e.t = (e.t & ~T_CASEBITS) | T_UPPER;
                e.t |= T_EXPAND;
                cit_add(it, &e);
            }
            return;
        }
    for (k = 0; k < sizeof overlays / sizeof overlays[0]; ++k)
        if (overlays[k].cp == cp) {
            make_elem(&e, overlays[k].base, it->fl);
            if (overlays[k].upper) e.t = (e.t & ~T_CASEBITS) | T_UPPER;
            cit_add(it, &e);
            if (!(it->fl & NLS_IGNORENONSPACE)) {
                e.p = 0; e.s = mark_weight(overlays[k].mark); e.t = T_LOWER; e.sp = 0;
                cit_add(it, &e);
            }
            return;
        }
    (void)upper_hint;
    make_elem(&e, cp, it->fl);
    if (is_mark_gc(NLS_GC(nls_attr(cp))) && (it->fl & NLS_IGNORENONSPACE)) return;
    cit_add(it, &e);
}

static int is_dec_digit(uint32_t cp) { const uint32_t a = nls_attr(cp); return NLS_GC(a) == GC_Nd && NLS_HASDIG(a); }

/* Returns the next non-empty element or 0 at the end of the string. */
static int cit_next(cit_t *it, elem_t *out)
{
    for (;;) {
        if (it->ib < it->nb) { *out = it->buf[it->ib++]; return 1; }
        it->ib = it->nb = 0;
        if (it->run_pos < it->run_end) {
            int j = it->run_pos;
            const uint32_t cp = nls_next_cp(it->s, it->n, &j);
            elem_t e;
            it->run_pos = j;
            make_elem(&e, cp, it->fl);
            e.t = T_LOWER;
            cit_add(it, &e);
            continue;
        }
        if (it->i >= it->n) return 0;
        {
            int start = it->i;
            const uint32_t cp = nls_next_cp(it->s, it->n, &it->i);
            uint32_t d[3];
            int nd;
            if ((it->fl & NLS_DIGITSASNUMBERS) && is_dec_digit(cp)) {
                int j = start, sig = -1, count = 0, end;
                elem_t e;
                for (;;) {                                       /* scan the whole digit run */
                    int before = j;
                    uint32_t c;
                    if (j >= it->n) break;
                    c = nls_next_cp(it->s, it->n, &j);
                    if (!is_dec_digit(c)) { j = before; break; }
                    if (sig < 0 && NLS_DIGIT(nls_attr(c)) != 0) sig = before;
                    if (sig >= 0) ++count;
                }
                end = j;
                it->i = end;
                e.p = PW(G_DIGIT, 0x10000 + (uint32_t)count); e.s = 0x20; e.t = T_LOWER; e.sp = 0;
                cit_add(it, &e);                                 /* the digit count orders runs by magnitude */
                if (sig >= 0) { it->run_pos = sig; it->run_end = end; }
                continue;
            }
            nd = nls_decompose(cp, d);
            if (nd) {
                int k;
                for (k = 0; k < nd; ++k) cit_add_char(it, d[k], 0);
            } else {
                cit_add_char(it, cp, 0);
            }
        }
    }
}

static uint32_t weight_at(const elem_t *e, int level, uint32_t tmask)
{
    switch (level) {
    case 0: return e->p;
    case 1: return e->s;
    case 2: return e->t & tmask;
    default: return e->sp;
    }
}

static uint32_t tertiary_mask(uint32_t fl)
{
    uint32_t m = 0xFFFFFFFFu;
    if (fl & NLS_IGNORECASE) m &= ~T_CASEBITS;
    if (fl & NLS_IGNOREWIDTH) m &= ~T_WIDTH;
    if (fl & NLS_IGNOREKANATYPE) m &= ~T_KANA;
    return m;
}

static int next_at_level(cit_t *it, int level, uint32_t tmask, uint32_t *w)
{
    elem_t e;
    while (cit_next(it, &e)) {
        *w = weight_at(&e, level, tmask);
        if (*w) return 1;
    }
    return 0;
}

int nls_compare(const nls_w *a, int an, const nls_w *b, int bn, uint32_t fl)
{
    const uint32_t tmask = tertiary_mask(fl);
    int level;
    for (level = 0; level < 4; ++level) {
        cit_t x, y;
        cit_init(&x, a, an, fl);
        cit_init(&y, b, bn, fl);
        for (;;) {
            uint32_t wx = 0, wy = 0;
            const int gx = next_at_level(&x, level, tmask, &wx), gy = next_at_level(&y, level, tmask, &wy);
            if (!gx && !gy) break;
            if (!gx) return -1;
            if (!gy) return 1;
            if (wx != wy) return wx < wy ? -1 : 1;
        }
    }
    return 0;
}

/* ---------------------------------------------------------------- sort keys */
typedef struct { uint8_t *out; int cap, len; } kbuf_t;
static void kput(kbuf_t *k, unsigned v) { if (k->len < k->cap) k->out[k->len] = (uint8_t)v; ++k->len; }

int nls_sortkey(const nls_w *s, int n, uint32_t fl, uint8_t *out, int cap)
{
    const uint32_t tmask = tertiary_mask(fl);
    kbuf_t k;
    int level, z;
    k.out = out; k.cap = out ? cap : 0; k.len = 0;
    for (level = 0; level < 4; ++level) {
        cit_t it;
        uint32_t w;
        const int width = level == 0 ? 4 : level == 2 ? 1 : 3;
        cit_init(&it, s, n, fl);
        while (next_at_level(&it, level, tmask, &w)) {
            if (width == 4) kput(&k, w >> 24);
            if (width >= 3) { kput(&k, (w >> 16) & 0xFF); kput(&k, (w >> 8) & 0xFF); }
            kput(&k, w & 0xFF);
        }
        for (z = 0; z < width; ++z) kput(&k, 0);                 /* level terminator, smaller than any weight */
    }
    return k.len;
}

/* ---------------------------------------------------------------- mapping */
static uint32_t map_cp(uint32_t cp, uint32_t flags)
{
    if (flags & NLS_MAP_UPPER) cp = nls_upper(cp);
    else if (flags & NLS_MAP_LOWER) cp = nls_lower(cp);
    if (flags & NLS_MAP_FULLWIDTH) {
        if (cp >= 0x21 && cp <= 0x7E) cp += 0xFEE0;
        else if (cp == 0x20) cp = 0x3000;
        else switch (cp) {
            case 0xA2: cp = 0xFFE0; break; case 0xA3: cp = 0xFFE1; break; case 0xAC: cp = 0xFFE2; break;
            case 0xAF: cp = 0xFFE3; break; case 0xA6: cp = 0xFFE4; break; case 0xA5: cp = 0xFFE5; break;
            case 0x20A9: cp = 0xFFE6; break; default: break;
        }
    } else if (flags & NLS_MAP_HALFWIDTH) {
        if (cp >= 0xFF01 && cp <= 0xFF5E) cp -= 0xFEE0;
        else if (cp == 0x3000) cp = 0x20;
        else switch (cp) {
            case 0xFFE0: cp = 0xA2; break; case 0xFFE1: cp = 0xA3; break; case 0xFFE2: cp = 0xAC; break;
            case 0xFFE3: cp = 0xAF; break; case 0xFFE4: cp = 0xA6; break; case 0xFFE5: cp = 0xA5; break;
            case 0xFFE6: cp = 0x20A9; break; default: break;
        }
    }
    if (flags & NLS_MAP_HIRAGANA) { if ((cp >= 0x30A1 && cp <= 0x30F6) || cp == 0x30FD || cp == 0x30FE) cp -= 0x60; }
    else if (flags & NLS_MAP_KATAKANA) { if ((cp >= 0x3041 && cp <= 0x3096) || cp == 0x309D || cp == 0x309E) cp += 0x60; }
    return cp;
}

int nls_map(const nls_w *src, int n, nls_w *dst, int cap, uint32_t flags)
{
    int i = 0, o = 0;
    while (i < n) {
        const uint32_t cp = nls_next_cp(src, n, &i);
        uint32_t d[3];
        int nd = 0, k;
        if (flags & NLS_MAP_STRIPMARKS) nd = nls_decompose(cp, d);       /* precomposed letters lose their marks */
        if (!nd) { d[0] = cp; nd = 1; }
        for (k = 0; k < nd; ++k) {
            const uint32_t a = nls_attr(d[k]);
            const unsigned gc = NLS_GC(a);
            int w;
            if ((flags & NLS_MAP_STRIPMARKS) && is_mark_gc(gc)) continue;
            if ((flags & NLS_MAP_STRIPSYMBOLS) &&
                (NLS_WS(a) || (gc >= GC_Pc && gc <= GC_Po) || (gc >= GC_Sm && gc <= GC_So) || gc == GC_Cc)) continue;
            w = nls_put_cp(dst, cap, o, map_cp(d[k], flags));
            if (!w) return -1;
            o += w;
        }
    }
    return o;
}
