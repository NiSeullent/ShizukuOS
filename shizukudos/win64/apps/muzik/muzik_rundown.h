/* SPDX-License-Identifier: GPL-2.0-only
 * Muzik stream rundown, injectable so the failure boundary can be checked without winmm.
 * Returns 1 only when every header was unprepared AND the stream handle closed: the only state in which headers and PCM may
 * be freed. Otherwise returns 0 and the caller must retain BOTH header array and PCM (winmm keeps header addresses). */
#ifndef MUZIK_RUNDOWN_H
#define MUZIK_RUNDOWN_H
typedef struct {
    int (*reset)(void *stream);                       /* nonzero = failure */
    int (*unprepare)(void *stream, void *hdr);        /* nonzero = failure */
    int (*close)(void *stream);                       /* nonzero = failure */
} mz_ops;
static int mz_rundown(const mz_ops *o, void *stream, void **hdrs, int (*is_prepared)(void *), unsigned n)
{
    unsigned i; int ok = 1;
    if (o->reset(stream)) ok = 0;                     /* a failed reset leaves headers in queue: unprepare below will fail */
    for (i = 0; i < n; ++i)
        if (is_prepared(hdrs[i]) && o->unprepare(stream, hdrs[i])) ok = 0;
    if (o->close(stream)) ok = 0;
    return ok;
}
#endif
