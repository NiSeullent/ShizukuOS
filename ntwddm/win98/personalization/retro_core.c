/* SPDX-License-Identifier: GPL-2.0-only */
#include <stddef.h>
#include "retro_core.h"
static int style_is(const szr_ops *o, uint32_t want)
{
    uint32_t now = 99;
    return o->get_style(o->ctx, &now) && now == want;
}
static int metrics_is(const szr_ops *o, int want) { return (o->metrics_applied(o->ctx) != 0) == (want != 0); }
static int done(szr_result *r, enum szr_status st, int step, int undone)
{
    r->status = st; r->failed_step = step; r->undone = undone; return st == SZR_OK;
}
int szr_apply(const szr_ops *o, int modern, szr_result *r)
{
    uint32_t prior_style = 99, target_style = modern ? SZR_STYLE_SHIZUKUOS : SZR_STYLE_CLASSIC;
    int prior_metrics;
    szr_result local;
    if (!r) r = &local;
    done(r, SZR_REFUSED, 0, 0);
    if (!o || !o->get_style || !o->set_style || !o->metrics_applied || !o->apply_metrics || !o->restore_metrics) return 0;
    if (!o->get_style(o->ctx, &prior_style)) return 0;
    if (prior_style != SZR_STYLE_CLASSIC && prior_style != SZR_STYLE_SHIZUKUOS) return 0;  /* custom: no exact undo */
    prior_metrics = o->metrics_applied(o->ctx) != 0;
    if (modern) {
        if (prior_style != target_style && !o->set_style(o->ctx, target_style))
            return done(r, SZR_FAILED_ROLLED_BACK, 1, 0);  /* theme backend rolls itself back; verify below */
        if (!prior_metrics && !o->apply_metrics(o->ctx)) {
            int ok = prior_style == target_style || (o->set_style(o->ctx, prior_style) && style_is(o, prior_style));
            return done(r, ok && metrics_is(o, 0) ? SZR_FAILED_ROLLED_BACK : SZR_FAILED_ROLLBACK_FAILED, 2, 1);
        }
    } else {
        if (prior_metrics && !o->restore_metrics(o->ctx))
            return done(r, metrics_is(o, 1) ? SZR_FAILED_ROLLED_BACK : SZR_FAILED_ROLLBACK_FAILED, 2, 0);
        if (prior_style != target_style && !o->set_style(o->ctx, target_style)) {
            int ok = !prior_metrics || (o->apply_metrics(o->ctx) && metrics_is(o, 1));
            return done(r, ok && style_is(o, prior_style) ? SZR_FAILED_ROLLED_BACK : SZR_FAILED_ROLLBACK_FAILED, 1, 1);
        }
    }
    if (!style_is(o, target_style) || !metrics_is(o, modern)) return done(r, SZR_FAILED_ROLLBACK_FAILED, 0, 0);
    return done(r, SZR_OK, 0, 0);
}
