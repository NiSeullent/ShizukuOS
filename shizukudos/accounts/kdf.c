/* SPDX-License-Identifier: GPL-2.0-only */
#include "kdf.h"
#include "sha256.h"
#include <string.h>
void shz_secret_clear(void *p,size_t n) { volatile uint8_t *v=p; while(n--) *v++=0; }
static void hmac(const void *key,size_t kn,const void *a,size_t an,const void *b,size_t bn,uint8_t out[32]) {
 uint8_t pad[64]={0},inner[32]; sha256_ctx c; unsigned i;
 if(kn>64) {sha256_init(&c);sha256_update(&c,key,kn);sha256_final(&c,pad);} else if(kn) memcpy(pad,key,kn);
 for(i=0;i<64;i++)pad[i]^=0x36;
 sha256_init(&c);sha256_update(&c,pad,64);if(an)sha256_update(&c,a,an);if(bn)sha256_update(&c,b,bn);sha256_final(&c,inner);
 for(i=0;i<64;i++)pad[i]^=0x36^0x5c;
 sha256_init(&c);sha256_update(&c,pad,64);sha256_update(&c,inner,32);sha256_final(&c,out);
 shz_secret_clear(pad,sizeof pad);shz_secret_clear(inner,sizeof inner);shz_secret_clear(&c,sizeof c);
}
int shz_pbkdf2(const void *pw,size_t pn,const void *salt,size_t sn,uint32_t rounds,uint8_t out[32]) {
 uint8_t u[32],t[32];const uint8_t one[4]={0,0,0,1};unsigned i;uint32_t j;
 if(!out||!rounds||pn>128||sn>64||(!pw&&pn)||(!salt&&sn))return -1;
 hmac(pw,pn,salt,sn,one,4,u);memcpy(t,u,32);
 for(j=1;j<rounds;j++){hmac(pw,pn,u,32,0,0,u);for(i=0;i<32;i++)t[i]^=u[i];}
 memcpy(out,t,32);shz_secret_clear(u,32);shz_secret_clear(t,32);return 0;
}
