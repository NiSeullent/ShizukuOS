/* SPDX-License-Identifier: GPL-2.0-only
 * Existing default constructor regression must never enter these opt-in-only
 * privileged boundaries. Retain its original fixture without source edits.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "../../src/domain.h"
static void forbidden(void){fputs("FAIL default profile entered VGA-only boundary\n",stderr);abort();}
int platform_vga_uc(uint64_t b,uint64_t n){(void)b;(void)n;forbidden();return -1;}
void video_native_vga_own(void){forbidden();}
int ept_remap_page(ept_t *e,uint64_t g,uint64_t h,uint64_t p){(void)e;(void)g;(void)h;(void)p;forbidden();return -1;}
void ept_invalidate(void){forbidden();}
void dom_fail(domain_t *d,const char *f,...){(void)d;(void)f;forbidden();}
