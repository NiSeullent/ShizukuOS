/* SPDX-License-Identifier: GPL-2.0-only
 * Actual provider + installer + pure relocation against owned regular files.
 * The prior producer/device roles remain explicit fixture models. No guest. */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmisleading-indentation"
#define main fixture_legacy_main
#include "native_install_host.c"
#undef main
#pragma GCC diagnostic pop
#include "../../win64/setup/native_provider.h"
static unsigned legacy_io, provider_io, guards, guard_failures, failed_dispatch;
static int fail_write(void *c,void *h,const native_setup_target_v1_t *t,uint64_t l,uint32_t n,const void *b)
{(void)c;(void)h;(void)t;(void)l;(void)n;(void)b;failed_dispatch++;return -1;}
static int partial_claim(void *c,const native_setup_target_v1_t *t,void *const src[2],void **h)
{int rc=claim(c,t,src,h);return !rc && !strcmp(fault,"partial_claim_fail")?-1:rc;}
#define CHECK(x) do { guards++; if(!(x)) { guard_failures++; fprintf(stderr,"PROVIDER_FAIL %u: %s\n",(unsigned)__LINE__,#x); } } while(0)
static int forbidden_read(void *c,unsigned i,uint64_t l,uint32_t n,void *b)
{(void)c;(void)i;(void)l;(void)n;(void)b;legacy_io++;return -1;}
static int forbidden_write(void *c,unsigned i,uint64_t l,uint32_t n,const void *b)
{(void)c;(void)i;(void)l;(void)n;(void)b;legacy_io++;return -1;}
static int forbidden_flush(void *c,unsigned i){(void)c;(void)i;legacy_io++;return -1;}
static int atomic_info(void *c,void *h,const native_setup_target_v1_t *t,plat_disk_t *d)
{if(target_check(c,h,t))return -1;return info(c,t->index,d);}
static int atomic_read(void *c,void *h,const native_setup_target_v1_t *t,uint64_t l,uint32_t n,void *b)
{provider_io++;if(target_check(c,h,t))return -1;return read_disk(c,t->index,l,n,b);}
static int atomic_write(void *c,void *h,const native_setup_target_v1_t *t,uint64_t l,uint32_t n,const void *b)
{provider_io++;if(!strcmp(fault,"backend_generation"))claimed_target.generation=2;
 if(target_check(c,h,&claimed_target)||target_check(c,h,t))return -1;
 return write_disk(c,t->index,l,n,b);}
static int atomic_flush(void *c,void *h,const native_setup_target_v1_t *t)
{provider_io++;if(target_check(c,h,t))return -1;return flush_disk(c,t->index);}
static void init_guards(const plat_t *p,const shz_native_provider_backend_v1_t *b)
{
 shz_native_provider_t v,z;shz_native_provider_backend_v1_t bad;uint8_t block[512];
 memset(&z,0,sizeof z);v=z;bad=*b;bad.target_write=0;
 CHECK(shz_native_provider_init(&v,p,&bad)!=0);CHECK(!memcmp(&v,&z,sizeof v));
 bad=*b;bad.authority.admit_source=0;CHECK(shz_native_provider_init(&v,p,&bad)!=0);CHECK(!memcmp(&v,&z,sizeof v));
 #define MISSING(member) do { bad=*b; bad.member=0; v=z; CHECK(shz_native_provider_init(&v,p,&bad)!=0); CHECK(!memcmp(&v,&z,sizeof v)); } while(0)
 MISSING(authority.check_source);MISSING(authority.close_source);MISSING(authority.sha_begin);
 MISSING(authority.sha_update);MISSING(authority.sha_end);MISSING(authority.sha_abort);
 MISSING(authority.review_target);MISSING(authority.claim_target);MISSING(authority.check_target);
 MISSING(authority.release_target);MISSING(target_info);MISSING(target_read);MISSING(target_flush);
#undef MISSING
 v=z;CHECK(shz_native_provider_init(&v,p,b)==0);
 CHECK(v.platform.disk_write(v.platform.ctx,0,0,1,block)!=0);
 CHECK(v.platform.disk_read(v.platform.ctx,0,0,1,block)!=0);
 CHECK(v.platform.disk_flush(v.platform.ctx,0)!=0);
 CHECK(legacy_io==0 && provider_io==0);
 v.started=1;v.claim=&v;v.target.index=0;v.target.disk.sectors=8;
 CHECK(v.platform.disk_write(v.platform.ctx,1,0,1,block)!=0);
 CHECK(v.platform.disk_write(v.platform.ctx,0,8,1,block)!=0);
 CHECK(v.platform.disk_write(v.platform.ctx,0,7,2,block)!=0);
 CHECK(v.platform.disk_write(v.platform.ctx,0,0,0,block)!=0);
 CHECK(v.platform.disk_write(v.platform.ctx,0,0,2049,block)!=0);
 CHECK(v.platform.disk_write(v.platform.ctx,0,0,1,0)!=0);
 { native_setup_target_v1_t changed=v.target; changed.generation++;
   CHECK(v.ops.check_target(v.ops.ctx,v.claim,&changed)!=0); }
 CHECK(legacy_io==0 && provider_io==0);
 v.backend.target_write=fail_write;
 CHECK(v.platform.disk_write(v.platform.ctx,0,0,1,block)!=0);
 CHECK(v.io_failed && failed_dispatch==1);
 CHECK(v.platform.disk_write(v.platform.ctx,0,0,1,block)!=0 && failed_dispatch==1);
 v.claim=0;
 { uint8_t a[512]={0}, bpb[512]={0}, f[512]={0}, g[512]={0};
   native_setup_overlay_v1_t overlay[2], saved[2];
   memset(overlay,0xa5,sizeof overlay);memcpy(saved,overlay,sizeof saved);
   CHECK(shz_native_provider_relocation(0,a,bpb,f,g,67108864,2048,133119,overlay)!=0);
   CHECK(!memcmp(saved,overlay,sizeof saved));
   CHECK(shz_native_provider_relocation(0,a,bpb,f,g,67108864,2048,133119,(native_setup_overlay_v1_t *)(void *)(a+16))!=0);
   CHECK(!a[16]);
 }
 CHECK(shz_native_provider_init(&v,p,b)!=0);
}
int main(int argc,char **argv)
{
 plat_t p={0,out,al,fr,source_open,source_read,source_close,sha_begin,sha_update,sha_end,random_bytes,now,count,info,forbidden_read,forbidden_write,forbidden_flush,2048};
 native_setup_ops_v1_t a={NATIVE_SETUP_VERSION,sizeof a,0,admit,input_check,checked_close,sha_begin,checked_update,checked_end,sha_abort,review,partial_claim,target_check,release,0};
 shz_native_provider_backend_v1_t b={SHZ_NATIVE_PROVIDER_VERSION,sizeof b,a,atomic_info,atomic_read,atomic_write,atomic_flush};
 shz_native_provider_t v;native_setup_request_v1_t q;native_setup_result_v1_t r,repeated;unsigned i;struct sigaction sa;
 if(argc!=6)return 2;
 fault=argv[5];memset(&sa,0,sizeof sa);sa.sa_handler=sigio;sigemptyset(&sa.sa_mask);if(sigaction(SIGIO,&sa,0))return 2;
 init_guards(&p,&b);
 for(i=0;i<2;i++){target_paths[i]=argv[3+i];disks[i]=open(argv[3+i],O_RDWR|O_NOFOLLOW|O_CLOEXEC);
  if(disks[i]<0||fstat(disks[i],&original_targets[i])||!S_ISREG(original_targets[i].st_mode)||original_targets[i].st_nlink!=1||(original_targets[i].st_mode&0777)!=0600)return 2;
  capacities[i]=(uint64_t)original_targets[i].st_size/512;
 }
 memset(&q,0,sizeof q);q.version=NATIVE_SETUP_VERSION;q.bytes=sizeof q;q.manifest_path=argv[1];q.sim_path=argv[2];
 if(parse_sha(getenv("MODEL_ADMITTED_MANIFEST_SHA256"),q.admitted_manifest_sha256))return 2;
 q.confirmation=!strcmp(fault,"bad_confirm")?"ERASE-TARGET":"ERASE";
 q.reviewed_target.index=0;info(0,0,&q.reviewed_target.disk);whole(0,q.reviewed_target.whole_id);q.reviewed_target.generation=1;
 memset(&v,0,sizeof v);if(shz_native_provider_init(&v,&p,&b))return 2;
 shz_native_provider_run(&v,&q,&r);
 { unsigned before=writes;shz_native_provider_run(&v,&q,&repeated);CHECK(!repeated.ok && writes==before); }
 CHECK(!v.claim && !v.source[0] && !v.source[1]);CHECK(!legacy_io);
 printf("PROVIDER_GUARDS checks=%u failures=%u legacy_io=%u provider_io=%u\n",guards,guard_failures,legacy_io,provider_io);
 printf("HOST_RESULT ok=%d writes=%u reads=%u flushes=%u opened=%u closed=%u releases=%u claimed=%d checked=%u readback=%d gpt=%d windows=%d vm=%d\n",r.ok,writes,reads,flushes,opened,closed,releases,claimed,checked,r.target_readback_verified,r.GPT_readback_verified,r.Windows98_boot_verified,r.VM_executed);
 for(i=0;i<2;i++)if(close(disks[i]))return 3;
 return guard_failures?3:r.ok?0:1;
}
