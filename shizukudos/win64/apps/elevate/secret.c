/* SPDX-License-Identifier: GPL-2.0-only */
#include "secret.h"
void shz_secret_reset(shz_secret *s){volatile unsigned char *p=(volatile unsigned char *)s;unsigned n=sizeof *s;while(n--)*p++=0;}
int shz_secret_key(shz_secret *s,uint16_t c){if(c==8){if(!s->length)return 0;s->chars[--s->length]=0;return 1;}if(c<32||c==127||s->length==128)return 0;s->chars[s->length++]=c;s->chars[s->length]=0;return 1;}
void shz_secret_mask(const shz_secret *s,uint16_t out[129]){unsigned i;for(i=0;i<s->length;i++)out[i]='*';out[i]=0;}
