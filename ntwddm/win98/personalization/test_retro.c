/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <string.h>
#include "retro_core.h"
typedef struct fake { uint32_t style; int metrics; int fail_style, fail_apply, fail_restore; int calls; } fake;
static int gs(void *c, uint32_t *s) { *s = ((fake *)c)->style; return 1; }
static int ss(void *c, uint32_t s) { fake *f = c; f->calls++; if (f->fail_style == (int)s + 1) return 0; f->style = s; return 1; }
static int ma(void *c) { return ((fake *)c)->metrics; }
static int am(void *c) { fake *f = c; f->calls++; if (f->fail_apply) return 0; f->metrics = 1; return 1; }
static int rm(void *c) { fake *f = c; f->calls++; if (f->fail_restore) return 0; f->metrics = 0; return 1; }
static int failures;
#define CHECK(x) do { if (!(x)) { printf("FAIL line %d: %s\n", __LINE__, #x); failures++; } } while (0)
int main(void)
{
    fake f; szr_result r; szr_ops o = {&f, gs, ss, ma, am, rm};
    memset(&f, 0, sizeof f);
    CHECK(szr_apply(&o, 1, &r) && r.status == SZR_OK && f.style == 1 && f.metrics == 1);
    f.calls = 0; CHECK(szr_apply(&o, 1, &r) && r.status == SZR_OK && f.calls == 0);          /* idempotent */
    CHECK(szr_apply(&o, 0, &r) && f.style == 0 && f.metrics == 0);
    /* metrics step fails after colours changed: colours rolled back */
    memset(&f, 0, sizeof f); f.fail_apply = 1;
    CHECK(!szr_apply(&o, 1, &r) && r.status == SZR_FAILED_ROLLED_BACK && r.failed_step == 2 && r.undone && f.style == 0 && f.metrics == 0);
    /* colour step fails: nothing else touched */
    memset(&f, 0, sizeof f); f.fail_style = 2;
    CHECK(!szr_apply(&o, 1, &r) && r.status == SZR_FAILED_ROLLED_BACK && r.failed_step == 1 && f.metrics == 0 && f.style == 0);
    /* metrics fail and the colour undo also fails: reported as rollback failure, never success */
    memset(&f, 0, sizeof f); f.fail_apply = 1; f.fail_style = 1;
    CHECK(!szr_apply(&o, 1, &r) && r.status == SZR_FAILED_ROLLBACK_FAILED && f.style == 1);
    /* classic: colours fail after metrics restored -> metrics re-applied */
    memset(&f, 0, sizeof f); f.style = 1; f.metrics = 1; f.fail_style = 1;
    CHECK(!szr_apply(&o, 0, &r) && r.status == SZR_FAILED_ROLLED_BACK && r.failed_step == 1 && f.style == 1 && f.metrics == 1);
    /* classic: metrics restore fails first -> colours untouched */
    memset(&f, 0, sizeof f); f.style = 1; f.metrics = 1; f.fail_restore = 1;
    CHECK(!szr_apply(&o, 0, &r) && r.failed_step == 2 && f.style == 1 && f.metrics == 1 && r.status == SZR_FAILED_ROLLED_BACK);
    /* classic: colours fail and metrics cannot be re-applied -> rollback failure */
    memset(&f, 0, sizeof f); f.style = 1; f.metrics = 1; f.fail_style = 1; f.fail_apply = 1;
    CHECK(!szr_apply(&o, 0, &r) && r.status == SZR_FAILED_ROLLBACK_FAILED && f.metrics == 0);
    /* custom colours or bad ops: refused, untouched */
    memset(&f, 0, sizeof f); f.style = 2;
    CHECK(!szr_apply(&o, 1, &r) && r.status == SZR_REFUSED && f.calls == 0 && f.style == 2);
    o.apply_metrics = NULL; CHECK(!szr_apply(&o, 1, &r) && r.status == SZR_REFUSED);
    CHECK(!szr_apply(NULL, 1, NULL));
    puts(failures ? "retro core FAILED" : "retro core ok");
    return failures != 0;
}
