/* SPDX-License-Identifier: GPL-2.0-only */
#include "../win64/apps/elevate/secret.h"
#include <assert.h>
#include <stdio.h>
int main(void){shz_secret s;uint16_t mask[129];shz_secret_reset(&s);
 assert(!shz_secret_key(&s,1));assert(!s.length);
 for(unsigned i=0;i<128;i++)assert(shz_secret_key(&s,(uint16_t)('a'+i%26)));
 assert(!shz_secret_key(&s,'x'));assert(s.length==128);
 shz_secret_mask(&s,mask);for(unsigned i=0;i<128;i++)assert(mask[i]=='*');assert(!mask[128]);
 assert(shz_secret_key(&s,8));assert(s.length==127&&!s.chars[127]);
 shz_secret_reset(&s);assert(!s.length);for(unsigned i=0;i<129;i++)assert(!s.chars[i]);
 puts("credential input: bounds, controls, masked rendering and erase PASS");}
