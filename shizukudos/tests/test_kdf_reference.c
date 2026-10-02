/* SPDX-License-Identifier: GPL-2.0-only */
#include "../accounts/kdf.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned decode(const char *s,unsigned char out[128]) {
    unsigned n=(unsigned)strlen(s),i;assert(!(n&1)&&n<=256);
    for(i=0;i<n/2;i++){unsigned v;assert(sscanf(s+2*i,"%2x",&v)==1);out[i]=(unsigned char)v;}
    return n/2;
}
int main(int argc,char **argv) {
    unsigned char pw[128],salt[128],out[32];unsigned pn,sn,i;unsigned long rounds;
    assert(argc==4);pn=decode(argv[1],pw);sn=decode(argv[2],salt);rounds=strtoul(argv[3],0,10);
    assert(rounds&&rounds<=UINT32_MAX&&!shz_pbkdf2(pw,pn,salt,sn,(uint32_t)rounds,out));
    for(i=0;i<32;i++){printf("%02x",out[i]);}
    puts("");
    shz_secret_clear(pw,sizeof pw);shz_secret_clear(salt,sizeof salt);shz_secret_clear(out,sizeof out);
    return 0;
}
