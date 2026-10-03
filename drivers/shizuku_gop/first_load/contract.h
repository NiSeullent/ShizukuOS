/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZGOP_FIRST_LOAD_CONTRACT_H
#define SHZGOP_FIRST_LOAD_CONTRACT_H
#include <stdint.h>
#define SHZGUARD_QUERY 0x53470001u
#define SHZGUARD_BYTES 352u
/* 0..31 source provider identity;32..191 HC14 words;192..195 anchor;
 *196..199 descriptor address;200..247 locator;248..343 descriptor;344..351 zero. */
static int shzguard_epoch_valid(const uint32_t *w)
{
    unsigned n=0,c=0,r=0,i;
    if(w[0]!=0x31455047u || w[1]!=1 || w[2]!=40 || w[3]!=5 || !w[4] ||
       w[5]>=256 || w[6]!=3 || w[7]>=256 || w[8]!=0x11111234u || w[9]!=0x030000u)return 0;
    for(i=0;i<8;i++){n|=w[16+i];c|=w[24+i];r|=w[32+i];}
    return n && c && r;
}
#endif
