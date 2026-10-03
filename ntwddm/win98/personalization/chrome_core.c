/* SPDX-License-Identifier: GPL-2.0-only */
#include "chrome_core.h"
const char *const szc_names[SZC_COUNT] = {"Border", "CaptionW", "CaptionH", "SmCaptionW", "SmCaptionH",
                                          "MenuW", "MenuH", "ScrollW", "ScrollH"};
static const int32_t modern_target[SZC_COUNT] = {1, 24, 24, 20, 20, 22, 22, 18, 18};
int szc_valid(const szc_metrics *m)
{
    unsigned i;
    if (!m) return 0;
    for (i = 0; i < SZC_COUNT; i++) {
        int32_t floor = i == SZC_BORDER ? 1 : 8;
        if (m->v[i] < floor || m->v[i] > 64) return 0;
    }
    return 1;
}
int szc_modern(const szc_metrics *cur, szc_metrics *out)
{
    unsigned i; szc_metrics r;
    if (!out || !szc_valid(cur)) return 0;
    for (i = 0; i < SZC_COUNT; i++)
        r.v[i] = i == SZC_BORDER ? cur->v[i] : (cur->v[i] > modern_target[i] ? cur->v[i] : modern_target[i]);
    *out = r; return 1;
}
int szc_equal(const szc_metrics *a, const szc_metrics *b)
{
    unsigned i;
    for (i = 0; i < SZC_COUNT; i++) if (a->v[i] != b->v[i]) return 0;
    return 1;
}
