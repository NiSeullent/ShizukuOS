/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - Windows layer common header (core): engine.h + the portable core, type bridges, the per-
 * document glue data, and the DLL-wide state other win/ modules use.
 */
#ifndef SHZ_WINGLUE_H
#define SHZ_WINGLUE_H

#include "../../engine.h"
#include "../core/dom.h"

/* WCHAR and shz_char are both 16-bit code units */
typedef char shz_wchar_size_check[sizeof(WCHAR) == sizeof(shz_char) ? 1 : -1];
static inline const shz_char *shz_from_w(const WCHAR *s) { return (const shz_char *)s; }
static inline shz_char *shz_from_w_mut(WCHAR *s) { return (shz_char *)s; }
static inline WCHAR *shz_to_w(shz_char *s) { return (WCHAR *)s; }
static inline const WCHAR *shz_to_wc(const shz_char *s) { return (const WCHAR *)s; }

/* Per-document glue data (doc->platform): the engine.h host callbacks and the core hook adaptor. */
typedef struct shz_win_doc {
    const shzeng_host *host;            /* may be NULL */
    void *ctx;
    shz_doc_hooks hooks;                /* doc->hooks points here */
} shz_win_doc;

static inline const shzeng_host *shz_win_host(shz_doc *doc)
{
    return doc && doc->platform ? ((shz_win_doc *)doc->platform)->host : NULL;
}
static inline void *shz_win_ctx(shz_doc *doc)
{
    return doc && doc->platform ? ((shz_win_doc *)doc->platform)->ctx : NULL;
}

/* the DLL module handle (DllMain) */
extern HINSTANCE shz_win_instance;

/* win/glue.c */
const shzeng_vtbl *shz_win_vtbl(void);

static inline void shz_rect_to_win(const shz_irect *in, RECT *out)
{
    out->left = in->left;
    out->top = in->top;
    out->right = in->right;
    out->bottom = in->bottom;
}

static inline void shz_rect_from_win(const RECT *in, shz_irect *out)
{
    out->left = in->left;
    out->top = in->top;
    out->right = in->right;
    out->bottom = in->bottom;
}

#endif /* SHZ_WINGLUE_H */
