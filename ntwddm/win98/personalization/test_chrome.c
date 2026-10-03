/* SPDX-License-Identifier: GPL-2.0-only */
#include <assert.h>
#include <stdio.h>
#include "chrome_core.h"
int main(void)
{
    szc_metrics classic = {{1, 18, 18, 12, 15, 18, 18, 16, 16}}, m, big, bad;
    assert(szc_valid(&classic));
    assert(szc_modern(&classic, &m) && szc_valid(&m));
    assert(m.v[SZC_CAPTION_H] == 24 && m.v[SZC_MENU_H] == 22 && m.v[SZC_SCROLL_W] == 18 && m.v[SZC_BORDER] == 1);
    big = classic; big.v[SZC_CAPTION_H] = 40; big.v[SZC_BORDER] = 3;
    assert(szc_modern(&big, &m) && m.v[SZC_CAPTION_H] == 40 && m.v[SZC_BORDER] == 3);  /* never shrinks */
    assert(szc_modern(&m, &bad) && szc_equal(&m, &bad));                                /* idempotent */
    bad = classic; bad.v[SZC_MENU_H] = 7; assert(!szc_valid(&bad));
    bad = classic; bad.v[SZC_SCROLL_W] = 65; assert(!szc_valid(&bad));
    bad = classic; bad.v[SZC_BORDER] = 0; assert(!szc_valid(&bad));
    m = classic; assert(!szc_modern(&bad, &m) && szc_equal(&m, &classic));              /* invalid: out unchanged */
    assert(!szc_valid(0) && !szc_modern(&classic, 0));
    puts("chrome core ok");
    return 0;
}
