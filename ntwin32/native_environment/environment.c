/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded interpretation of two UCRT field-load chains. The host remains
 * Windows 98; these models expose only the explicitly represented fields.
 */
#include "environment.h"
static const uint8_t verifier[]={0x64,0xa1,0x18,0,0,0,0x8b,0x40,0x30,0x8b,0x40,0x68,0xc1,0xe8,8,0x24,1,0xc3};
static const uint8_t secure[]={0x64,0xa1,0x18,0,0,0,0x8b,0x40,0x30,0x8b,0x40,0x10,0x8b,0x40,8,0xc1,0xe8,0x1f,0xc3};
static int same(const uint8_t *a,const uint8_t *b,size_t n){size_t i;for(i=0;i<n;i++)if(a[i]!=b[i])return 0;return 1;}
static int span(size_t n,size_t at,size_t bytes){return at<=n&&bytes<=n-at;}
static uint16_t u16(const uint8_t *p){return (uint16_t)(p[0]|(uint16_t)p[1]<<8);}
static uint32_t u32(const uint8_t *p){return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24;}
int env_decode(const uint8_t *p,size_t n,uint32_t *kind,uint32_t *skip){
 if(!p||!kind||!skip)return 0;
 if(n==sizeof(verifier)&&same(p,verifier,n)){*kind=ENV_VERIFIER;*skip=12;return 1;}
 if(n==sizeof(secure)&&same(p,secure,n)){*kind=ENV_SECURE;*skip=15;return 1;}
 return 0;
}
int env_model_make(uint32_t scope,uint32_t major,uint32_t minor,uint32_t build,uint32_t platform,env_model *m){
 if(!m||major!=4||minor!=10||build!=2222||platform!=1)return 0;
 if(scope!=ENV_DESKTOP&&scope!=ENV_OWNED_FIXTURE)return 0;
 m->scope=scope;
 /* Ordinary Win98 desktop creation supplies no NT secure-process attribute
  * and this helper does not install/register the NT application verifier.
  * Nonzero values are reserved for the separately hashed owned test image.
  */
 m->nt_global_flags=scope==ENV_OWNED_FIXTURE?0x13570100u:0;
 m->process_flags=scope==ENV_OWNED_FIXTURE?0x80000023u:0;
 return 1;
}
int env_emulate(const env_model *m,uint32_t base,uint32_t image,uint32_t entry,uint32_t dr6,const uint8_t *code,size_t n,env_context *c){
 uint32_t kind,skip,bit;
 if(!m||!c||(m->scope!=ENV_DESKTOP&&m->scope!=ENV_OWNED_FIXTURE)||!env_decode(code,n,&kind,&skip))return 0;
 if(m->scope==ENV_DESKTOP&&(m->nt_global_flags||m->process_flags))return 0;
 if(m->scope==ENV_OWNED_FIXTURE&&(m->nt_global_flags!=0x13570100u||m->process_flags!=0x80000023u))return 0;
 bit=kind==ENV_VERIFIER?1:2;
 if((dr6&0xe00fu)!=bit||!image||base>UINT32_MAX-image||entry>=image||n>image-entry||c->eip!=base+entry)return 0;
 /* MOV does not affect flags. Original SHR/AND/RET execute in the guest. */
 c->eax=kind==ENV_VERIFIER?m->nt_global_flags:m->process_flags;
 c->eip+=skip;
 return 1;
}
static int exec_chain(const uint8_t *p,size_t n,size_t sections,unsigned count,uint32_t rva,unsigned bytes,uint32_t want){
 unsigned i,hits=0;uint32_t kind,skip;
 for(i=0;i<count;i++){
  const uint8_t *s=p+sections+40u*i;uint32_t va=u32(s+12),vs=u32(s+8),raw=u32(s+20),rn=u32(s+16),flags=u32(s+36),off;
  if((flags&0x60000000u)!=0x60000000u||rva<va||rva-va>rn||bytes>rn-(rva-va)||rva-va>vs||bytes>vs-(rva-va))continue;
  off=rva-va;if(!span(n,raw,rn)||!span(n,(size_t)raw+off,bytes))return 0;
  if(!env_decode(p+raw+off,bytes,&kind,&skip)||kind!=want)return 0;hits++;
 }
 return hits==1;
}
int env_pe_gate(const uint8_t *p,size_t n,const env_profile *profile,uint32_t *image){
 size_t nt,opt,sections;unsigned count,os;env_sha h;uint8_t digest[32];uint32_t size;
 if(!p||!profile||!image||n!=profile->bytes||n<128||n>32u*1024u*1024u)return 0;
 env_sha_init(&h);env_sha_update(&h,p,n);env_sha_final(&h,digest);if(!same(digest,profile->digest,32))return 0;
 if(u16(p)!=0x5a4d)return 0;nt=u32(p+60);
 if(!span(n,nt,24)||u32(p+nt)!=0x4550||u16(p+nt+4)!=0x14c||(u16(p+nt+22)&0x2000))return 0;
 count=u16(p+nt+6);os=u16(p+nt+20);if(!count||count>32||os<96)return 0;
 opt=nt+24;if(!span(n,opt,os)||u16(p+opt)!=0x10b)return 0;
 size=u32(p+opt+56);if(!size||size>64u*1024u*1024u)return 0;
 sections=opt+os;if(!span(n,sections,40u*count)||profile->verifier_rva>=size||profile->secure_rva>=size)return 0;
 if(!exec_chain(p,n,sections,count,profile->verifier_rva,18,ENV_VERIFIER)||!exec_chain(p,n,sections,count,profile->secure_rva,19,ENV_SECURE))return 0;
 *image=size;return 1;
}
static uint32_t rr(uint32_t x,unsigned n){return (x>>n)|(x<<(32-n));}
static const uint32_t k[64]={
 0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
 0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
 0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
 0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
 0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
 0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
 0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
 0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static void transform(env_sha *h){
 uint32_t w[64],a,b,c,d,e,f,g,z,t1,t2;unsigned i;
 for(i=0;i<16;i++)w[i]=(uint32_t)h->block[4*i]<<24|(uint32_t)h->block[4*i+1]<<16|(uint32_t)h->block[4*i+2]<<8|h->block[4*i+3];
 for(i=16;i<64;i++)w[i]=w[i-16]+(rr(w[i-15],7)^rr(w[i-15],18)^(w[i-15]>>3))+w[i-7]+(rr(w[i-2],17)^rr(w[i-2],19)^(w[i-2]>>10));
 a=h->state[0];b=h->state[1];c=h->state[2];d=h->state[3];e=h->state[4];f=h->state[5];g=h->state[6];z=h->state[7];
 for(i=0;i<64;i++){t1=z+(rr(e,6)^rr(e,11)^rr(e,25))+((e&f)^(~e&g))+k[i]+w[i];t2=(rr(a,2)^rr(a,13)^rr(a,22))+((a&b)^(a&c)^(b&c));z=g;g=f;f=e;e=d+t1;d=c;c=b;b=a;a=t1+t2;}
 h->state[0]+=a;h->state[1]+=b;h->state[2]+=c;h->state[3]+=d;h->state[4]+=e;h->state[5]+=f;h->state[6]+=g;h->state[7]+=z;
}
void env_sha_init(env_sha *h){static const uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};unsigned i;h->bytes=0;h->used=0;for(i=0;i<8;i++)h->state[i]=s[i];}
void env_sha_update(env_sha *h,const uint8_t *p,size_t n){size_t i;h->bytes+=n;for(i=0;i<n;i++){h->block[h->used++]=p[i];if(h->used==64){transform(h);h->used=0;}}}
void env_sha_final(env_sha *h,uint8_t out[32]){uint64_t bits=h->bytes*8;unsigned i;h->block[h->used++]=0x80;if(h->used>56){while(h->used<64)h->block[h->used++]=0;transform(h);h->used=0;}while(h->used<56)h->block[h->used++]=0;for(i=0;i<8;i++)h->block[63-i]=(uint8_t)(bits>>(8*i));transform(h);for(i=0;i<32;i++)out[i]=(uint8_t)(h->state[i/4]>>(24-8*(i%4)));}
