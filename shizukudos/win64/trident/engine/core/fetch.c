/* SPDX-License-Identifier: GPL-2.0-only
 *
 * ShizukuTrident Lite - sub-resource loading (see fetch.h).
 */
#include "fetch.h"
#include "loader.h"
#include "platform.h"
#include "url.h"

struct shz_fetch {
    shz_fetch_sink sink;                /* first member: the sink pointer is the fetch */
    shz_doc *doc;                       /* document reference (shz_doc_addref) */
    shz_fetch_done_fn fn;
    void *ctx;
    shz_bytes data;
    shz_char *final_url, *mime, *charset;
    int blocks_load;
    int done;
    shz_fetch **handle;                 /* the requester's handle variable while shz_fetch_start runs */
};

static void complete(shz_fetch *f, shz_res status)
{
    shz_doc *doc = f->doc;
    if (f->done) return;
    f->done = 1;
    if (f->handle) *f->handle = NULL;
    if (f->fn) {
        shz_fetch_done_fn fn = f->fn;
        f->fn = NULL;
        if (SHZ_SUCCEEDED(status) && f->data.oom) status = SHZ_E_OUTOFMEMORY;
        fn(f->ctx, doc, status, SHZ_SUCCEEDED(status) ? f->data.p : NULL, SHZ_SUCCEEDED(status) ? f->data.len : 0,
           f->final_url, f->mime, f->charset);
    }
    if (f->blocks_load && doc->fetch_pending) {
        --doc->fetch_pending;
        if (!doc->fetch_pending) shz_load_check_complete(doc);
    }
    shz_bytes_free(&f->data);
    shz_free(f->final_url);
    shz_free(f->mime);
    shz_free(f->charset);
    shz_free(f);
    shz_doc_release(doc);
}

static void sink_start(shz_fetch_sink *sink, const shz_char *final_url, const shz_char *mime, const shz_char *charset)
{
    shz_fetch *f = (shz_fetch *)sink;
    if (final_url) { shz_free(f->final_url); f->final_url = shz_strdup(final_url); }
    if (mime) { shz_free(f->mime); f->mime = shz_strdup(mime); }
    if (charset) { shz_free(f->charset); f->charset = shz_strdup(charset); }
}

static void sink_data(shz_fetch_sink *sink, const void *bytes, size_t len)
{
    shz_fetch *f = (shz_fetch *)sink;
    if (f->fn) shz_bytes_put(&f->data, bytes, len);
}

static void sink_done(shz_fetch_sink *sink, shz_res status)
{
    complete((shz_fetch *)sink, status);
}

shz_res shz_fetch_start(shz_doc *doc, const shz_char *url, int kind, int blocks_load, shz_fetch_done_fn fn, void *ctx,
                        shz_fetch **handle)
{
    shz_fetch *f;
    shz_res hr;
    if (handle) *handle = NULL;
    if (!url || !*url) return SHZ_E_INVALIDARG;
    f = shz_alloc(sizeof(*f));
    if (!f) return SHZ_E_OUTOFMEMORY;
    f->sink.start = sink_start;
    f->sink.data = sink_data;
    f->sink.done = sink_done;
    f->doc = doc;
    shz_doc_addref(doc);
    f->fn = fn;
    f->ctx = ctx;
    shz_bytes_init(&f->data);
    f->final_url = shz_strdup(url);
    f->blocks_load = blocks_load;
    if (blocks_load) ++doc->fetch_pending;
    if (handle) {
        *handle = f;
        f->handle = handle;
    }
    if (doc->hooks && doc->hooks->fetch) {
        hr = doc->hooks->fetch(doc->hooks_ctx, doc, url, kind, &f->sink);
        if (SHZ_FAILED(hr)) {
            /* the sink will not be called: finish without running the callback */
            f->fn = NULL;
            complete(f, hr);
            if (handle) *handle = NULL;
            return hr;
        }
        if (handle && *handle) f->handle = NULL;     /* asynchronous from here on */
        return SHZ_OK;
    }
    {
        shz_char *path = shz_url_file_path(url);
        uint8_t *bytes = NULL;
        size_t len = 0;
        hr = path ? shz_platform_read_file(path, &bytes, &len) : SHZ_E_NOTIMPL;
        shz_free(path);
        if (SHZ_SUCCEEDED(hr)) {
            shz_bytes_put(&f->data, bytes, len);
            shz_free(bytes);
        }
        complete(f, hr);
    }
    return SHZ_OK;
}

void shz_fetch_cancel(shz_fetch *f)
{
    if (!f) return;
    f->fn = NULL;
    f->handle = NULL;
}
