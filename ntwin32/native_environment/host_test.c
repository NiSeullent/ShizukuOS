/* SPDX-License-Identifier: GPL-2.0-only */
#include "environment.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL %u line %u: %s\n",checks,__LINE__,#x);return 1;}}while(0)
static const uint8_t verifier[]={0x64,0xa1,0x18,0,0,0,0x8b,0x40,0x30,0x8b,0x40,0x68,0xc1,0xe8,8,0x24,1,0xc3};
static const uint8_t secure[]={0x64,0xa1,0x18,0,0,0,0x8b,0x40,0x30,0x8b,0x40,0x10,0x8b,0x40,8,0xc1,0xe8,0x1f,0xc3};
static void p16(uint8_t *p,uint16_t x){p[0]=(uint8_t)x;p[1]=(uint8_t)(x>>8);}
static void p32(uint8_t *p,uint32_t x){unsigned i;for(i=0;i<4;i++)p[i]=(uint8_t)(x>>(8*i));}
static void bind(env_profile *profile,const uint8_t *p,size_t n){env_sha h;profile->bytes=(uint32_t)n;env_sha_init(&h);env_sha_update(&h,p,n);env_sha_final(&h,profile->digest);}
static void synthetic(uint8_t *p,env_profile *profile){memset(p,0,2048);p16(p,0x5a4d);p32(p+60,0x80);p32(p+0x80,0x4550);p16(p+0x84,0x14c);p16(p+0x86,1);p16(p+0x94,0xe0);p16(p+0x96,0x102);p16(p+0x98,0x10b);p32(p+0x98+56,0x3000);p32(p+0x178+8,512);p32(p+0x178+12,0x1000);p32(p+0x178+16,512);p32(p+0x178+20,0x400);p32(p+0x178+36,0x60000020);memcpy(p+0x400,verifier,sizeof(verifier));memcpy(p+0x440,secure,sizeof(secure));profile->verifier_rva=0x1000;profile->secure_rva=0x1040;bind(profile,p,2048);}
int main(int argc,char **argv){uint32_t kind,skip,image;size_t i,n;uint8_t code[20],digest[32],pe[2048],saved[2048];env_model model;env_context c,before;env_profile profile;env_sha sha;FILE *f;uint8_t *npp;
 static const uint8_t abc[32]={0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad};
 static const uint8_t empty[32]={0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55};
 env_sha_init(&sha);env_sha_update(&sha,(const uint8_t *)"abc",3);env_sha_final(&sha,digest);CHECK(!memcmp(digest,abc,32));
 env_sha_init(&sha);env_sha_update(&sha,(const uint8_t *)"a",1);env_sha_update(&sha,(const uint8_t *)"bc",2);env_sha_final(&sha,digest);CHECK(!memcmp(digest,abc,32));
 env_sha_init(&sha);env_sha_final(&sha,digest);CHECK(!memcmp(digest,empty,32));
 CHECK(env_decode(verifier,sizeof(verifier),&kind,&skip)&&kind==ENV_VERIFIER&&skip==12);
 CHECK(env_decode(secure,sizeof(secure),&kind,&skip)&&kind==ENV_SECURE&&skip==15);
 for(i=0;i<sizeof(verifier);i++){memcpy(code,verifier,sizeof(verifier));code[i]^=1;CHECK(!env_decode(code,sizeof(verifier),&kind,&skip));}
 for(i=0;i<sizeof(secure);i++){memcpy(code,secure,sizeof(secure));code[i]^=1;CHECK(!env_decode(code,sizeof(secure),&kind,&skip));}
 for(i=0;i<sizeof(verifier);i++)CHECK(!env_decode(verifier,i,&kind,&skip));
 for(i=0;i<sizeof(secure);i++)CHECK(!env_decode(secure,i,&kind,&skip));
 CHECK(!env_decode(verifier,19,&kind,&skip));CHECK(!env_decode(NULL,18,&kind,&skip));
 CHECK(!env_model_make(ENV_DESKTOP,10,0,2222,2,&model));CHECK(!env_model_make(ENV_DESKTOP,4,10,1998,1,&model));CHECK(!env_model_make(3,4,10,2222,1,&model));
 CHECK(env_model_make(ENV_DESKTOP,4,10,2222,1,&model)&&!model.nt_global_flags&&!model.process_flags);
 CHECK(env_model_make(ENV_OWNED_FIXTURE,4,10,2222,1,&model));c.eax=0x12345678;c.eip=0x401000;c.eflags=0x246;
 CHECK(env_emulate(&model,0x400000,0x3000,0x1000,0xffff0ff1,verifier,sizeof(verifier),&c)&&c.eax==0x13570100&&c.eip==0x40100c&&c.eflags==0x246);
 c.eip=0x401040;CHECK(env_emulate(&model,0x400000,0x3000,0x1040,2,secure,sizeof(secure),&c)&&c.eax==0x80000023&&c.eip==0x40104f&&c.eflags==0x246);
 for(i=0;i<16;i++){c.eip=0x401000;before=c;CHECK((env_emulate(&model,0x400000,0x3000,0x1000,(uint32_t)i,verifier,sizeof(verifier),&c)!=0)==(i==1));if(i!=1)CHECK(!memcmp(&c,&before,sizeof(c)));}
 c.eip=0x401000;CHECK(!env_emulate(&model,0x400000,0x3000,0x1000,0x4001,verifier,sizeof(verifier),&c));
 CHECK(!env_emulate(&model,0xfffff000,0x3000,0x1000,1,verifier,sizeof(verifier),&c));CHECK(!env_emulate(&model,0x400000,0x1008,0x1000,1,verifier,sizeof(verifier),&c));
 model.process_flags=1;CHECK(!env_emulate(&model,0x400000,0x3000,0x1000,1,verifier,sizeof(verifier),&c));
 synthetic(pe,&profile);memcpy(saved,pe,sizeof(pe));CHECK(env_pe_gate(pe,sizeof(pe),&profile,&image)&&image==0x3000);
 pe[0x400]^=1;CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));bind(&profile,pe,sizeof(pe));CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));
 memcpy(pe,saved,sizeof(pe));p32(pe+0x178+36,0x40000000);bind(&profile,pe,sizeof(pe));CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));
 memcpy(pe,saved,sizeof(pe));p32(pe+0x178+20,0xfffffff0);bind(&profile,pe,sizeof(pe));CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));
 memcpy(pe,saved,sizeof(pe));p16(pe+0x86,2);memcpy(pe+0x178+40,pe+0x178,40);bind(&profile,pe,sizeof(pe));CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));
 memcpy(pe,saved,sizeof(pe));p16(pe+0x86,33);bind(&profile,pe,sizeof(pe));CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));
 memcpy(pe,saved,sizeof(pe));p16(pe+0x84,0x8664);bind(&profile,pe,sizeof(pe));CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));
 memcpy(pe,saved,sizeof(pe));p16(pe+0x96,0x2102);bind(&profile,pe,sizeof(pe));CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));
 memcpy(pe,saved,sizeof(pe));p32(pe+60,0xfffffff0);bind(&profile,pe,sizeof(pe));CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));
 synthetic(pe,&profile);profile.secure_rva=0x3000;CHECK(!env_pe_gate(pe,sizeof(pe),&profile,&image));
 CHECK(argc==2);f=fopen(argv[1],"rb");CHECK(f!=NULL);CHECK(!fseek(f,0,SEEK_END));n=(size_t)ftell(f);CHECK(n==7752688);CHECK(!fseek(f,0,SEEK_SET));npp=malloc(n);CHECK(npp!=NULL);CHECK(fread(npp,1,n,f)==n);fclose(f);
 {const char *hex="986ffd50fb51e4b08737d1c47a4aca8e681adb628789228e5f538bfb954d2eb5";for(i=0;i<32;i++){unsigned x;CHECK(sscanf(hex+2*i,"%2x",&x)==1);profile.digest[i]=(uint8_t)x;}}
 profile.bytes=(uint32_t)n;profile.verifier_rva=0x38a901;profile.secure_rva=0x38a913;CHECK(env_pe_gate(npp,n,&profile,&image)&&image==0x769000);npp[n-1]^=1;CHECK(!env_pe_gate(npp,n,&profile,&image));free(npp);
 printf("ENV_HOST_CHECKS=%u\nSTATUS=PASS\n",checks);return 0;
}
