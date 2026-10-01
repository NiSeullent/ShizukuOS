/* SPDX-License-Identifier: GPL-2.0-only
 *
 * Host tests: sub-resource fetch plumbing (core/fetch.c) against the engine.h contract: without a host fetch callback
 * file: URLs are read directly and complete synchronously, other URLs fail; with one, the host drives the sink
 * (start/data/done exactly once), a failing host call means no callback; blocking fetches delay "load" (load_done)
 * until they complete; a cancelled fetch never calls back.
 */
#include "host_test.h"
#include "../core/fetch.h"

typedef struct result {
    int calls;
    shz_res status;
    char data[256];
    size_t len;
    char mime[64];
} result;

static void on_done(void *ctx, shz_doc *doc, shz_res status, const uint8_t *data, size_t len, const shz_char *final_url,
                    const shz_char *mime, const shz_char *charset)
{
    result *r = ctx;
    (void)doc; (void)final_url; (void)charset;
    ++r->calls;
    r->status = status;
    r->len = len;
    if (data && len < sizeof(r->data)) memcpy(r->data, data, len);
    r->data[len < sizeof(r->data) ? len : 0] = 0;
    snprintf(r->mime, sizeof(r->mime), "%s", mime ? U8(mime) : "");
}

/* a host whose fetch keeps the sink for later */
static shz_fetch_sink *pending_sink;
static shz_res fetch_result = SHZ_OK;
static int fetch_calls;

static shz_res host_fetch(void *ctx, shz_doc *doc, const shz_char *url, int kind, shz_fetch_sink *sink)
{
    (void)ctx; (void)doc; (void)url; (void)kind;
    ++fetch_calls;
    if (SHZ_FAILED(fetch_result)) return fetch_result;
    pending_sink = sink;
    return SHZ_OK;
}

static int loads;
static void host_load_done(void *ctx, shz_doc *doc)
{
    (void)ctx; (void)doc;
    ++loads;
}

static const shz_doc_hooks fetch_hooks = {
    NULL, NULL, NULL, NULL, NULL, host_fetch, host_load_done, NULL, NULL, NULL, NULL, NULL
};

int main(void)
{
    shz_doc *doc = t_new_doc(NULL);
    result r;
    shz_fetch *handle = (shz_fetch *)1;
    char path[1024], url[1100];
    const char *tmp = getenv("SHZ_TEST_TMP");
    FILE *f;

    /* ---- no host fetch: file: read directly, synchronously */
    snprintf(path, sizeof(path), "%s/fetch_test.txt", tmp ? tmp : "/tmp");
    f = fopen(path, "wb");
    fputs("hello fetch", f);
    fclose(f);
    snprintf(url, sizeof(url), "file://%s", path);
    memset(&r, 0, sizeof(r));
    T_INTEQ("file: fetch starts", shz_fetch_start(doc, T(url), SHZ_FETCH_OTHER, 1, on_done, &r, &handle), SHZ_OK);
    T_INTEQ("completed synchronously: callback ran once", r.calls, 1);
    T_INTEQ("handle cleared after synchronous completion", handle == NULL, 1);
    T_INTEQ("status OK", r.status, SHZ_OK);
    T_STREQ("file bytes", r.data, "hello fetch");
    T_INTEQ("nothing pending", doc->fetch_pending, 0);
    memset(&r, 0, sizeof(r));
    snprintf(url, sizeof(url), "file://%s/does-not-exist", tmp ? tmp : "/tmp");
    shz_fetch_start(doc, T(url), SHZ_FETCH_IMAGE, 1, on_done, &r, NULL);
    T_INTEQ("missing file: callback with a failure", r.calls == 1 && SHZ_FAILED(r.status), 1);
    memset(&r, 0, sizeof(r));
    shz_fetch_start(doc, T("http://example.com/x.css"), SHZ_FETCH_STYLESHEET, 0, on_done, &r, NULL);
    T_INTEQ("http without a host fetch: E_NOTIMPL", r.calls == 1 && r.status == SHZ_E_NOTIMPL, 1);
    shz_doc_release(doc);

    /* ---- host fetch: asynchronous sink; a blocking fetch delays load_done */
    shz_doc_create(&fetch_hooks, NULL, T("http://example.com/"), NULL, &doc);
    loads = 0;
    shz_parser_begin(doc, NULL);
    memset(&r, 0, sizeof(r));
    T_INTEQ("host fetch accepted", shz_fetch_start(doc, T("http://example.com/a.png"), SHZ_FETCH_IMAGE, 1, on_done, &r,
                                                   &handle), SHZ_OK);
    T_INTEQ("the host got the request", fetch_calls == 1 && pending_sink != NULL, 1);
    T_INTEQ("pending handle", handle != NULL, 1);
    T_INTEQ("counted as pending", doc->fetch_pending, 1);
    shz_parser_feed(doc, (const uint8_t *)"<p>x", 4);
    shz_parser_end(doc);
    T_INTEQ("parsing done but load waits for the fetch", loads, 0);
    pending_sink->start(pending_sink, T("http://example.com/a.png"), T("image/png"), NULL);
    pending_sink->data(pending_sink, "ab", 2);
    pending_sink->data(pending_sink, "cd", 2);
    T_INTEQ("no callback before done", r.calls, 0);
    pending_sink->done(pending_sink, SHZ_OK);
    pending_sink = NULL;
    T_INTEQ("callback once at done", r.calls, 1);
    T_STREQ("data accumulated", r.data, "abcd");
    T_STREQ("mime from start()", r.mime, "image/png");
    T_INTEQ("load_done after the blocking fetch completed", loads, 1);
    T_INTEQ("nothing pending", doc->fetch_pending, 0);

    /* a failing host fetch: no callback, error returned, count restored */
    fetch_result = SHZ_E_FAIL;
    memset(&r, 0, sizeof(r));
    T_INTEQ("host refuses", shz_fetch_start(doc, T("http://example.com/b.png"), SHZ_FETCH_IMAGE, 1, on_done, &r, NULL),
            SHZ_E_FAIL);
    T_INTEQ("no callback after a refused fetch", r.calls, 0);
    T_INTEQ("pending count restored", doc->fetch_pending, 0);
    fetch_result = SHZ_OK;

    /* cancel: the transfer finishes but the requester is not called */
    memset(&r, 0, sizeof(r));
    shz_fetch_start(doc, T("http://example.com/c.png"), SHZ_FETCH_IMAGE, 0, on_done, &r, &handle);
    shz_fetch_cancel(handle);
    pending_sink->data(pending_sink, "zz", 2);
    pending_sink->done(pending_sink, SHZ_OK);
    pending_sink = NULL;
    T_INTEQ("cancelled fetch: no callback", r.calls, 0);

    /* the document stays alive while a fetch is in flight, even after the host released it */
    memset(&r, 0, sizeof(r));
    shz_fetch_start(doc, T("http://example.com/d.png"), SHZ_FETCH_IMAGE, 1, on_done, &r, NULL);
    shz_doc_release(doc);
    T_INTEQ("document open while the fetch is pending", doc->refs == 1 && !doc->closed, 1);
    pending_sink->done(pending_sink, SHZ_E_ABORT);      /* frees the document (LeakSanitizer checks) */
    T_INTEQ("aborted fetch reported", r.calls == 1 && r.status == SHZ_E_ABORT, 1);
    remove(path);
    return t_finish("t_fetch");
}
