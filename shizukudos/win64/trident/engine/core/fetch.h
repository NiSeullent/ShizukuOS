/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - sub-resource loading (core), shared by style sheets (L1) and images (L2).
 *
 * shz_fetch() resolves nothing: pass an absolute URL (shz_doc_resolve_url). It asks the host (hooks->fetch, i.e.
 * engine.h shzeng_host.fetch) and collects the bytes; without a host fetch callback, file: URLs are read directly
 * through the platform (shz_platform_read_file) and completed SYNCHRONOUSLY, before shz_fetch returns. Other URLs
 * then fail (SHZ_E_NOTIMPL delivered to the callback).
 *
 * Load blocking: with blocks_load set the fetch counts in doc->fetch_pending until it completes; when the count drops
 * to 0 the loader is told (shz_load_check_complete, L2) so it can fire window "load" once parsing is done too.
 */
#ifndef SHZ_FETCH_H
#define SHZ_FETCH_H

#include "dom.h"

/* resource kinds: engine.h shzeng_fetch_kind values */
enum { SHZ_FETCH_STYLESHEET = 0, SHZ_FETCH_IMAGE, SHZ_FETCH_SCRIPT, SHZ_FETCH_FRAME, SHZ_FETCH_OTHER };

/* The sink the host feeds (the glue wraps it into an engine.h shzeng_sink). done() is called exactly once. */
struct shz_fetch_sink {
    void (*start)(shz_fetch_sink *sink, const shz_char *final_url, const shz_char *mime, const shz_char *charset);
    void (*data)(shz_fetch_sink *sink, const void *bytes, size_t len);
    void (*done)(shz_fetch_sink *sink, shz_res status);
};

typedef struct shz_fetch shz_fetch;

/* Completion callback: status SHZ_OK with the whole body, or a failure (data NULL). final_url / mime / charset may be
 * NULL. Called at most once; not called after shz_fetch_cancel. */
typedef void (*shz_fetch_done_fn)(void *ctx, shz_doc *doc, shz_res status, const uint8_t *data, size_t len,
                                  const shz_char *final_url, const shz_char *mime, const shz_char *charset);

/* Start a fetch. *handle (optional) receives a handle valid until the callback ran or shz_fetch_cancel was called;
 * it is set to NULL when the fetch already completed synchronously. A failure return means the callback will not be
 * called. */
shz_res shz_fetch_start(shz_doc *doc, const shz_char *url, int kind, int blocks_load, shz_fetch_done_fn fn, void *ctx,
                        shz_fetch **handle);
/* Forget the callback (the requester goes away); the transfer itself finishes in the background. */
void    shz_fetch_cancel(shz_fetch *f);

#endif /* SHZ_FETCH_H */
