/* SPDX-License-Identifier: GPL-2.0-only
 * Shizuku NLS core: Unicode character properties, case mapping, character types, collation and sort keys.
 * Pure functions over UTF-16 strings; no Windows types, no allocation, no kernel calls, so the same code is
 * exercised natively by tests/host/nls_host_test.c and inside kernel32.dll.
 *
 * The data is Unicode (see UNI_VERSION in unidata.h), NOT Windows' NLS tables. Windows' own tables differ in details
 * (Unicode version, tailoring); everything that follows from this is documented in k32_nls.c.
 */
#ifndef SHZ_NLS_CORE_H
#define SHZ_NLS_CORE_H
#include <stdint.h>

typedef uint16_t nls_w;

/* attribute word (see gen_unidata.py) */
#define NLS_GC(a) ((unsigned)((a) & 31))
#define NLS_BIDI(a) ((unsigned)(((a) >> 5) & 31))
#define NLS_DIGIT(a) ((unsigned)(((a) >> 10) & 15))
#define NLS_HASDIG(a) (((a) >> 14) & 1)
#define NLS_WS(a) (((a) >> 15) & 1)
#define NLS_KATA(a) (((a) >> 16) & 1)
#define NLS_HIRA(a) (((a) >> 17) & 1)
#define NLS_HALF(a) (((a) >> 18) & 1)
#define NLS_FULL(a) (((a) >> 19) & 1)
#define NLS_IDEO(a) (((a) >> 20) & 1)
#define NLS_SCRIPT(a) ((unsigned)(((a) >> 21) & 7))
/* general category indices */
enum { GC_Lu, GC_Ll, GC_Lt, GC_Lm, GC_Lo, GC_Mn, GC_Mc, GC_Me, GC_Nd, GC_Nl, GC_No, GC_Pc, GC_Pd, GC_Ps, GC_Pe, GC_Pi, GC_Pf,
       GC_Po, GC_Sm, GC_Sc, GC_Sk, GC_So, GC_Zs, GC_Zl, GC_Zp, GC_Cc, GC_Cf, GC_Cs, GC_Co, GC_Cn };
enum { BD_L, BD_R, BD_AL, BD_EN, BD_ES, BD_ET, BD_AN, BD_CS, BD_NSM, BD_BN, BD_B, BD_S, BD_WS, BD_ON };

/* Windows flag values used by the core (same numbers as winnls.h) */
#define NLS_IGNORECASE 0x00000001u
#define NLS_IGNORENONSPACE 0x00000002u
#define NLS_IGNORESYMBOLS 0x00000004u
#define NLS_DIGITSASNUMBERS 0x00000008u
#define NLS_STRINGSORT 0x00001000u
#define NLS_IGNOREKANATYPE 0x00010000u
#define NLS_IGNOREWIDTH 0x00020000u

uint32_t nls_attr(uint32_t cp);
uint32_t nls_upper(uint32_t cp);
uint32_t nls_lower(uint32_t cp);
unsigned nls_ctype1(uint32_t cp);                       /* C1_* */
unsigned nls_ctype2(uint32_t cp);                       /* C2_* */
unsigned nls_ctype3(uint32_t cp);                       /* C3_* */

/* Next code point of a UTF-16 string; an unpaired surrogate is returned as itself. Advances *i. */
uint32_t nls_next_cp(const nls_w *s, int n, int *i);
int nls_put_cp(nls_w *d, int cap, int at, uint32_t cp);  /* returns units written (0 if it does not fit) */

/* Canonical (NFD) decomposition of a BMP code point: returns the number of code points (0 = none), fills out[3]. */
int nls_decompose(uint32_t cp, uint32_t out[3]);
/* Canonical composition of a pair: returns the composite or 0. */
uint32_t nls_compose(uint32_t a, uint32_t b);

/* Collation. weights: primary/secondary/tertiary, see nls_core.c. Returns -1, 0, 1. */
int nls_compare(const nls_w *a, int an, const nls_w *b, int bn, uint32_t flags);
/* Sort key: returns the key length in bytes; writes at most cap bytes (cap = 0: length only). Two keys compare with
 * memcmp/length exactly like nls_compare compares the strings. */
int nls_sortkey(const nls_w *s, int n, uint32_t flags, uint8_t *out, int cap);

/* Mapping flags (winnls.h values) understood by nls_map */
#define NLS_MAP_LOWER 0x00000100u
#define NLS_MAP_UPPER 0x00000200u
#define NLS_MAP_HIRAGANA 0x00100000u
#define NLS_MAP_KATAKANA 0x00200000u
#define NLS_MAP_HALFWIDTH 0x00400000u
#define NLS_MAP_FULLWIDTH 0x00800000u
#define NLS_MAP_STRIPMARKS 0x40000000u       /* internal: canonical-decompose and drop nonspacing marks (NORM_IGNORENONSPACE) */
#define NLS_MAP_STRIPSYMBOLS 0x20000000u     /* internal: drop symbols, punctuation and white space (NORM_IGNORESYMBOLS) */
/* Maps `n` UTF-16 units. dst may be NULL (length only). Returns the number of units produced or -1 if `cap` is too small. */
int nls_map(const nls_w *src, int n, nls_w *dst, int cap, uint32_t flags);
#endif
