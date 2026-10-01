/* SPDX-License-Identifier: GPL-2.0-only */
#include "observer.h"
#include "../native_environment/environment.h"
#include "profiles.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned checks;
#define CHECK(x) do{checks++;if(!(x)){fprintf(stderr,"FAIL line %u: %s\n",__LINE__,#x);exit(1);}}while(0)
typedef struct {rpc_context c[RPC_THREADS];uint8_t image[0x60000];uint32_t base;unsigned reads,writes,resumes;int no_read,no_write,corrupt_write,no_memory;} mock;
static mock m;
static rpc_runtime runtime;
static uint32_t u32(const uint8_t *p){return p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);}
static void p32(uint8_t *p,uint32_t n){unsigned i;for(i=0;i<4;i++)p[i]=(uint8_t)(n>>(i*8));}
static int read_ctx(void *v,uintptr_t h,rpc_context *c){mock *a=v;a->reads++;if(a->no_read||!h||h>RPC_THREADS)return 0;*c=a->c[h-1];return 1;}
static int write(void *v,uintptr_t h,const rpc_context *c,int resume){mock *a=v;unsigned i;a->writes++;if(a->no_write||!h||h>RPC_THREADS)return 0;
 for(i=R_DR0;i<R_COUNT;i++)a->c[h-1].v[i]=c->v[i];if(resume){a->c[h-1].v[R_FLAGS]=c->v[R_FLAGS];a->resumes++;}
 if(a->corrupt_write)a->c[h-1].v[R_EAX]^=1;return 1;
}
static int write_debug(void *v,uintptr_t h,const rpc_context *c){return write(v,h,c,0);}
static int write_resume(void *v,uintptr_t h,const rpc_context *c){return write(v,h,c,1);}
static int read_mem(void *v,uint32_t p,void *out,uint32_t n){mock *a=v;if(a->no_memory||p<a->base||p-a->base>sizeof(a->image)||n>sizeof(a->image)-(p-a->base))return 0;memcpy(out,a->image+p-a->base,n);return 1;}
static rpc_ops ops={&m,read_ctx,write_debug,write_resume,read_mem};
static void reset(void){unsigned i,j;memset(&runtime,0,sizeof(runtime));memset(&m,0,sizeof(m));m.base=0x71000000;
 for(i=0;i<RPC_THREADS;i++){for(j=0;j<R_COUNT;j++)m.c[i].v[j]=0x24680000u+j+i;m.c[i].v[R_DR7]=0x400;m.c[i].v[R_DR6]=0;m.c[i].v[R_FLAGS]=0x202;}
 for(i=0;i<2;i++){uint8_t b[32];CHECK(rpc_expected_code(&native_rpc_profile,i,m.base,b));memcpy(m.image+(i?native_rpc_profile.store_rva:native_rpc_profile.entry_rva),b,native_rpc_profile.length[i]);}
}
static uint8_t *load(const char *name,size_t *n){FILE *f=fopen(name,"rb");long size;uint8_t *p;CHECK(f!=NULL);CHECK(!fseek(f,0,SEEK_END));size=ftell(f);CHECK(size>0);CHECK(!fseek(f,0,SEEK_SET));p=malloc((size_t)size);CHECK(p!=NULL);CHECK(fread(p,1,(size_t)size,f)==(size_t)size);CHECK(!fclose(f));*n=(size_t)size;return p;}
static void digest(rpc_profile *p,const uint8_t *b,size_t n){env_sha h;env_sha_init(&h);env_sha_update(&h,b,n);env_sha_final(&h,p->sha256);}
static void file_controls(const char *name,const char *fixture){size_t n,fn;uint8_t *b=load(name,&n),*copy=malloc(n),*f=load(fixture,&fn);rpc_profile p;uint32_t table=native_rpc_profile.pe_offset+248;
 CHECK(copy!=NULL);CHECK(rpc_file_gate(b,n,&native_rpc_profile));CHECK(rpc_file_gate(f,fn,&fixture_profile));CHECK(!rpc_file_gate(b,n-1,&native_rpc_profile));
 memcpy(copy,b,n);copy[n-1]^=1;CHECK(!rpc_file_gate(copy,n,&native_rpc_profile));
 /* Rehash malformed images, so these exercise parsing instead of only SHA. */
 memcpy(copy,b,n);copy[0]=0;p=native_rpc_profile;digest(&p,copy,n);CHECK(!rpc_file_gate(copy,n,&p));
 memcpy(copy,b,n);p32(copy+60,UINT32_MAX-1);p=native_rpc_profile;digest(&p,copy,n);CHECK(!rpc_file_gate(copy,n,&p));
 memcpy(copy,b,n);copy[native_rpc_profile.pe_offset+4]=0x64;p=native_rpc_profile;digest(&p,copy,n);CHECK(!rpc_file_gate(copy,n,&p));
 memcpy(copy,b,n);p32(copy+native_rpc_profile.pe_offset+8,p.timestamp+1);p=native_rpc_profile;digest(&p,copy,n);CHECK(!rpc_file_gate(copy,n,&p));
 memcpy(copy,b,n);p32(copy+table+20,(uint32_t)n-1);p=native_rpc_profile;digest(&p,copy,n);CHECK(!rpc_file_gate(copy,n,&p));
 memcpy(copy,b,n);p32(copy+table+40+12,u32(copy+table+12));p=native_rpc_profile;digest(&p,copy,n);CHECK(!rpc_file_gate(copy,n,&p));
 memcpy(copy,b,n);p32(copy+table+40+20,u32(copy+table+20));p=native_rpc_profile;digest(&p,copy,n);CHECK(!rpc_file_gate(copy,n,&p));
 memcpy(copy,b,n);p32(copy+native_rpc_profile.pe_offset+24+60,64);p=native_rpc_profile;p.size_headers=64;digest(&p,copy,n);CHECK(!rpc_file_gate(copy,n,&p));
 for(unsigned i=0;i<native_rpc_profile.sections;i++){uint8_t *s=copy+table+40*i;if(native_rpc_profile.state_rva>=u32(s+12)&&native_rpc_profile.state_rva-u32(s+12)<u32(s+16)){
  memcpy(copy,b,n);s=copy+table+40*i;p32(s+36,u32(s+36)|0x10000000);p=native_rpc_profile;digest(&p,copy,n);CHECK(!rpc_file_gate(copy,n,&p));break;}}
 free(copy);free(b);free(f);
}
static void relocation_controls(void){rpc_profile p=native_rpc_profile;uint8_t b[32];uint32_t delta=0x100000;
 CHECK(rpc_expected_code(&p,0,p.preferred_base,b));CHECK(!memcmp(b,p.code[0],p.length[0]));
 CHECK(rpc_expected_code(&p,1,p.preferred_base+delta,b));CHECK(u32(b+2)==u32(p.code[1]+2)+delta);
 CHECK(rpc_expected_code(&p,1,p.preferred_base-delta,b));CHECK(u32(b+2)==u32(p.code[1]+2)-delta);
 CHECK(!rpc_expected_code(&p,0,UINT32_MAX-p.image_bytes+1,b));CHECK(!rpc_expected_code(&p,2,0,b));
 p.relocations[1][3]=1;CHECK(!rpc_expected_code(&p,1,0,b));p=native_rpc_profile;p.relocations[1][31]=1;CHECK(!rpc_expected_code(&p,1,0,b));
 p=native_rpc_profile;p.relocations[1][2]=2;CHECK(!rpc_expected_code(&p,1,0,b));
}
static void lifecycle_controls(void){rpc_context original,observed,before,after;unsigned i,writes;
 reset();original=m.c[0];CHECK(rpc_add_thread(&runtime,11,1,&ops)==1);CHECK(m.writes==0);CHECK(rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops)==1);CHECK(runtime.arms==1);
 CHECK(rpc_add_thread(&runtime,12,2,&ops)==1);CHECK(runtime.arms==2);CHECK(!rpc_add_thread(&runtime,12,2,&ops));CHECK(runtime.incomplete);runtime.incomplete=0;
 m.c[0].v[R_EIP]=m.base+native_rpc_profile.entry_rva;m.c[0].v[R_DR6]=1;before=m.c[0];
 CHECK(rpc_observe(&runtime,11,0x80000004,1,before.v[R_EIP],&ops,&observed)==RPC_ENTRY);CHECK(rpc_context_equal(&observed,&before));after=before;after.v[R_FLAGS]|=RPC_RF;after.v[R_DR6]=0;CHECK(rpc_context_equal(&m.c[0],&after));CHECK(m.resumes==1);
 m.c[1].v[R_EIP]=m.base+native_rpc_profile.store_rva;m.c[1].v[R_DR6]=2;m.c[1].v[R_EDI]=0xaabbccdd;before=m.c[1];
 CHECK(rpc_observe(&runtime,12,0x80000004,1,before.v[R_EIP],&ops,&observed)==RPC_STORE);CHECK(observed.v[R_EDI]==0xaabbccdd);CHECK(m.c[1].v[R_EDI]==before.v[R_EDI]&&m.c[1].v[R_EIP]==before.v[R_EIP]);
 writes=m.writes;CHECK(rpc_observe(&runtime,12,0xc0000005,1,before.v[R_EIP],&ops,&observed)==RPC_PASS);CHECK(rpc_observe(&runtime,12,0x80000004,0,before.v[R_EIP],&ops,&observed)==RPC_PASS);
 m.c[1].v[R_DR6]=3;CHECK(rpc_observe(&runtime,12,0x80000004,1,before.v[R_EIP],&ops,&observed)==RPC_PASS);m.c[1].v[R_DR6]=0x4002;CHECK(rpc_observe(&runtime,12,0x80000004,1,before.v[R_EIP],&ops,&observed)==RPC_PASS);CHECK(m.writes==writes);
 /* Feed a clean subsequent OS context for the normal unload/reload case.
  * Unrelated status preservation has its own control below. This does not
  * assert that the native OS clears it after an unhandled exception. */
 m.c[1].v[R_DR6]=0;
 CHECK(rpc_unbind_module(&runtime,&ops)==1);CHECK(runtime.restores==2&&runtime.base==0);for(i=R_DR0;i<R_COUNT;i++)CHECK(m.c[0].v[i]==original.v[i]);CHECK(m.c[0].v[R_EIP]==after.v[R_EIP]);
 CHECK(rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops)==1);CHECK(runtime.generations==2&&runtime.arms==4);
 CHECK(!rpc_complete(&runtime));CHECK(rpc_retire_thread(&runtime,12));CHECK(runtime.exit_threads==1);rpc_retire_process(&runtime);CHECK(runtime.process_retired==1);CHECK(rpc_complete(&runtime));
 reset();for(i=0;i<RPC_THREADS;i++)CHECK(rpc_add_thread(&runtime,i+1,i+1,&ops)==1);CHECK(!rpc_add_thread(&runtime,RPC_THREADS+1,1,&ops));CHECK(runtime.incomplete);
 reset();runtime.created=UINT32_MAX;CHECK(rpc_add_thread(&runtime,1,1,&ops)==1);CHECK(runtime.counter_overflow&&runtime.created==UINT32_MAX&&!rpc_complete(&runtime));
}
static void failure_controls(void){rpc_context c;unsigned i;
 for(i=0;i<4;i++){reset();CHECK(rpc_add_thread(&runtime,1,1,&ops)==1);if(i==0)m.c[0].v[R_DR7]|=1;if(i==1)m.c[0].v[R_DR7]|=0x2000;if(i==2)m.c[0].v[R_FLAGS]|=0x100;if(i==3)m.c[0].v[R_DR6]|=0x4000;
  CHECK(!rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops));CHECK(runtime.incomplete&&!runtime.unsafe&&m.writes==0);}
 reset();CHECK(rpc_add_thread(&runtime,1,1,&ops));m.no_read=1;CHECK(!rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops));CHECK(runtime.incomplete&&!runtime.unsafe);
 reset();CHECK(rpc_add_thread(&runtime,1,1,&ops));m.no_write=1;CHECK(rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops)==RPC_UNSAFE);CHECK(runtime.unsafe&&!rpc_complete(&runtime));
 reset();CHECK(rpc_add_thread(&runtime,1,1,&ops));m.corrupt_write=1;CHECK(rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops)==RPC_UNSAFE);CHECK(runtime.unsafe&&!rpc_complete(&runtime));
 reset();CHECK(rpc_add_thread(&runtime,1,1,&ops));m.image[native_rpc_profile.entry_rva]^=1;CHECK(!rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops));CHECK(m.writes==0&&!runtime.base);
 reset();CHECK(rpc_add_thread(&runtime,1,1,&ops));CHECK(rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops));m.c[0].v[R_EIP]=m.base+native_rpc_profile.entry_rva;m.c[0].v[R_DR6]=1;m.no_write=1;
 CHECK(rpc_observe(&runtime,1,0x80000004,1,m.c[0].v[R_EIP],&ops,&c)==RPC_UNSAFE);CHECK(runtime.unsafe);
 reset();CHECK(rpc_add_thread(&runtime,1,1,&ops));CHECK(rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops));m.no_read=1;CHECK(rpc_unbind_module(&runtime,&ops)==RPC_UNSAFE);CHECK(runtime.unsafe);
 reset();CHECK(rpc_add_thread(&runtime,1,0,&ops));CHECK(!rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops));CHECK(runtime.incomplete);
 reset();CHECK(!rpc_bind_module(&runtime,&native_rpc_profile,UINT32_MAX,&ops));CHECK(m.writes==0);
 reset();rpc_gap(&runtime);CHECK(!rpc_complete(&runtime));
}
static void ownership_controls(void){rpc_context initial,before;unsigned i,writes;
 /* A disabled foreign slot's type/address and reserved DR6 bits survive arm. */
 reset();m.c[0].v[R_DR7]|=0xab000000;m.c[0].v[R_DR6]=0xffff0ff0;initial=m.c[0];
 CHECK(rpc_add_thread(&runtime,1,1,&ops));CHECK(rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops));
 CHECK(m.c[0].v[R_DR2]==initial.v[R_DR2]&&m.c[0].v[R_DR3]==initial.v[R_DR3]);CHECK((m.c[0].v[R_DR7]&~RPC_DR_MASK)==(initial.v[R_DR7]&~RPC_DR_MASK));CHECK(m.c[0].v[R_DR6]==initial.v[R_DR6]);
 /* Foreign changes after arm are retained, while our original slots return. */
 m.c[0].v[R_DR2]^=0x1234;m.c[0].v[R_DR3]^=0x5678;m.c[0].v[R_DR7]^=0x01000000;m.c[0].v[R_DR7]|=0x10;m.c[0].v[R_DR6]|=0x4004;before=m.c[0];
 CHECK(rpc_unbind_module(&runtime,&ops)==1);CHECK(m.c[0].v[R_DR0]==initial.v[R_DR0]&&m.c[0].v[R_DR1]==initial.v[R_DR1]);
 CHECK(m.c[0].v[R_DR2]==before.v[R_DR2]&&m.c[0].v[R_DR3]==before.v[R_DR3]);CHECK((m.c[0].v[R_DR7]&~RPC_DR_MASK)==(before.v[R_DR7]&~RPC_DR_MASK));CHECK((m.c[0].v[R_DR6]&~3u)==(before.v[R_DR6]&~3u));
 for(i=0;i<R_DR0;i++)CHECK(m.c[0].v[i]==before.v[i]);
 /* Each stolen address/type/enable field blocks restoration before a write. */
 for(i=0;i<4;i++){reset();CHECK(rpc_add_thread(&runtime,1,1,&ops));CHECK(rpc_bind_module(&runtime,&native_rpc_profile,m.base,&ops));
  if(i==0)m.c[0].v[R_DR0]++;if(i==1)m.c[0].v[R_DR1]++;if(i==2)m.c[0].v[R_DR7]|=0x10000;if(i==3)m.c[0].v[R_DR7]&=~1u;
  writes=m.writes;before=m.c[0];CHECK(rpc_unbind_module(&runtime,&ops)==RPC_UNSAFE);CHECK(m.writes==writes);CHECK(rpc_context_equal(&before,&m.c[0]));CHECK(runtime.unsafe&&!rpc_complete(&runtime));
 }
}
int main(int argc,char **argv){CHECK(argc==3);CHECK(fixture_target_bytes&&vlc_target_bytes&&kernel_debugbreak_rva&&fixture_target_sha[0]+vlc_target_sha[0]!=0);
 file_controls(argv[1],argv[2]);relocation_controls();lifecycle_controls();failure_controls();ownership_controls();printf("PASS actual portable RPC core: %u checks; no native target executed\n",checks);return 0;}
