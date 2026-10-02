/* SPDX-License-Identifier: GPL-2.0-only
 * Actual C installer host boundary. Only fresh private regular fixture files.
 * Prior native lineage and device roles are modeled; Linux FD/SHA/I/O are real.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "../../win64/setup/native_install.h"
typedef struct { uint32_t h[8]; uint64_t len; uint8_t b[64]; unsigned n; } sha_t;
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01,
    0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08,
    0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
static void sha_block(sha_t *s, const uint8_t *p)
{
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    int i;
    for (i = 0; i < 16; ++i) w[i] = (uint32_t)p[4 * i] << 24 | (uint32_t)p[4 * i + 1] << 16 | (uint32_t)p[4 * i + 2] << 8 | p[4 * i + 3];
    for (i = 16; i < 64; ++i)
        w[i] = (ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10)) + w[i - 7] + (ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3)) + w[i - 16];
    a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3]; e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + (ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
        t2 = (ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d; s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}
static void *sha_begin(void *ctx)
{
    static const uint32_t iv[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    sha_t *s = calloc(1, sizeof *s);
    (void)ctx;
    memcpy(s->h, iv, sizeof iv);
    return s;
}
static void sha_update(void *ctx, void *v, const void *buf, uint32_t len)
{
    sha_t *s = v;
    const uint8_t *p = buf;
    (void)ctx;
    s->len += len;
    while (len) {
        if (s->n == 0 && len >= 64) { sha_block(s, p); p += 64; len -= 64; continue; }
        s->b[s->n++] = *p++;
        --len;
        if (s->n == 64) { sha_block(s, s->b); s->n = 0; }
    }
}
static void sha_end(void *ctx, void *v, uint8_t out[32])
{
    sha_t *s = v;
    const uint64_t bits = s->len * 8;
    uint8_t pad = 0x80, z = 0, L[8];
    int i;
    sha_update(ctx, s, &pad, 1);
    while (s->n != 56) sha_update(ctx, s, &z, 1);
    for (i = 0; i < 8; ++i) L[i] = (uint8_t)(bits >> (56 - 8 * i));
    sha_update(ctx, s, L, 8);
    for (i = 0; i < 8; ++i) { out[4 * i] = (uint8_t)(s->h[i] >> 24); out[4 * i + 1] = (uint8_t)(s->h[i] >> 16); out[4 * i + 2] = (uint8_t)(s->h[i] >> 8); out[4 * i + 3] = (uint8_t)s->h[i]; }
    free(s);
}



typedef struct input { int fd, leased; char path[4096]; struct stat original; } input_t;
static input_t inputs[2];
static int disks[2], claimed, input_count;
static uint64_t capacities[2];
static struct stat original_targets[2];
static const char *target_paths[2], *fault;
static volatile sig_atomic_t broken;
static unsigned writes, reads, flushes, opened, closed, releases, checked, random_count;
static int injected;
static native_setup_overlay_v1_t *mutable_plan;
static native_setup_target_v1_t claimed_target;
static void sigio(int sig) { (void)sig; broken=1; }
static int ancestry(const char *path) {
 char b[4096];size_t i,n=strlen(path);struct stat s;
 if(n>=sizeof b||path[0]!='/')return -1;
 memcpy(b,path,n+1);
 for(i=1;i<=n;i++)if(b[i]=='/'||!b[i]){
  char old=b[i];b[i]=0;
  if(lstat(b,&s)||S_ISLNK(s.st_mode)||(!old&&!S_ISREG(s.st_mode))||(old&&!S_ISDIR(s.st_mode)))return -1;
  b[i]=old;
 }return 0;
}
static int identity(const struct stat *a,const struct stat *b,int full) {
 return a->st_dev==b->st_dev&&a->st_ino==b->st_ino&&a->st_size==b->st_size&&
 a->st_mode==b->st_mode&&a->st_uid==b->st_uid&&a->st_nlink==b->st_nlink&&
 (!full||(a->st_mtim.tv_sec==b->st_mtim.tv_sec&&a->st_mtim.tv_nsec==b->st_mtim.tv_nsec&&
 a->st_ctim.tv_sec==b->st_ctim.tv_sec&&a->st_ctim.tv_nsec==b->st_ctim.tv_nsec));
}
static int input_check(void *ctx,void *v) {
 input_t *f=v;struct stat a,b;(void)ctx;
 return broken||!f||!f->leased||fcntl(f->fd,F_GETLEASE)!=F_RDLCK||ancestry(f->path)||
 fstat(f->fd,&a)||lstat(f->path,&b)||!identity(&a,&b,1)||!identity(&a,&f->original,1)?-1:0;
}
static void out(void *ctx,const char *s){(void)ctx;fputs(s,stdout);}
static void *al(void *ctx,size_t n){(void)ctx;return calloc(1,n?n:1);}
static void fr(void *ctx,void *p){(void)ctx;free(p);}
static int source_open(void *ctx,const char *path,void **h,uint64_t *size){
 input_t *f;struct stat s;(void)ctx;
 if(input_count>=2||ancestry(path)||strlen(path)>=sizeof inputs[0].path)return -1;
 f=&inputs[input_count];f->fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
 if(f->fd<0)return -1;
 if(fstat(f->fd,&s)||!S_ISREG(s.st_mode)||s.st_nlink!=1||s.st_uid!=getuid()||(s.st_mode&0777)!=0600){close(f->fd);return -1;}
 strcpy(f->path,path);f->original=s;*h=f;*size=(uint64_t)s.st_size;input_count++;opened++;return 0;
}
static int source_read(void *ctx,void *h,uint64_t off,void *buf,uint32_t n){
 input_t *f=h;uint8_t *p=buf;(void)ctx;
 if(!strcmp(fault,"source_eio"))return -1;
 while(n){uint32_t take=!strcmp(fault,"short_io")&&n>997?997:n;ssize_t got;
  if(input_check(ctx,h))return -1;
  got=pread(f->fd,p,take,(off_t)off);
  if(got<0&&errno==EINTR)continue;
  if(got<=0||(!strcmp(fault,"source_eof")&&off))return -1;
  p+=got;off+=(uint64_t)got;n-=(uint32_t)got;
  if(input_check(ctx,h))return -1;
 }return 0;
}
static void source_close(void *ctx,void *h){input_t *f=h;(void)ctx;if(f)close(f->fd);}
static int checked_update(void *ctx,void *h,const void *b,uint32_t n){
 if(!strcmp(fault,"sha_update"))return -1;
 sha_update(ctx,h,b,n);return 0;
}
static int checked_end(void *ctx,void *h,uint8_t b[32]){sha_end(ctx,h,b);return !strcmp(fault,"sha_end")?-1:0;}
static void sha_abort(void *ctx,void *h){(void)ctx;free(h);}
static int admit(void *ctx,void *h,const char *path,uint64_t bytes,const uint8_t want[32]){
 input_t *f=h;uint8_t b[65536],got[32];uint64_t off=0;void *v;
 if(strcmp(path,f->path)||bytes!=(uint64_t)f->original.st_size||!strcmp(fault,"missing_source_authority"))return -1;
 if(fcntl(f->fd,F_SETOWN,getpid())||fcntl(f->fd,F_SETLEASE,F_RDLCK))return -1;
 f->leased=1;if(input_check(ctx,h))return -1;
 v=sha_begin(ctx);if(!v)return -1;
 while(off<bytes){uint32_t n=bytes-off<sizeof b?(uint32_t)(bytes-off):sizeof b;
  if(source_read(ctx,h,off,b,n)){free(v);return -1;}
  sha_update(ctx,v,b,n);off+=n;
 }sha_end(ctx,v,got);return memcmp(got,want,32)||input_check(ctx,h)?-1:0;
}
static int checked_close(void *ctx,void *h){
 input_t *f=h;int bad=f->leased?input_check(ctx,h):0;
 if(f->leased&&fcntl(f->fd,F_SETLEASE,F_UNLCK))bad=1;
 if(close(f->fd))bad=1;
 f->fd=-1;f->leased=0;closed++;
 if(!strcmp(fault,"source_close"))bad=1;
 return bad?-1:0;
}
static int random_bytes(void *ctx,void *buf,uint32_t n){uint32_t i;(void)ctx;random_count++;
 for(i=0;i<n;i++)((uint8_t *)buf)[i]=(uint8_t)(17+i+random_count*29);
 if(!strcmp(fault,"random_alias")){memset(buf,1,n);if(n>6)((uint8_t *)buf)[6]=(uint8_t)(random_count<<4);}
 return 0;}
static uint64_t now(void *ctx){(void)ctx;return 1785283200;}
static unsigned count(void *ctx){(void)ctx;return 2;}
static int info(void *ctx,unsigned i,plat_disk_t *o){
 (void)ctx;if(i>=2||(!strcmp(fault,"enumeration_fail")&&i==1))return -1;memset(o,0,sizeof *o);
 strcpy(o->name,i?"fixture1":"fixture0");strcpy(o->serial,i?"OWN-FIXTURE-B":"OWN-FIXTURE-A");
 if(i&&!strcmp(fault,"duplicate"))strcpy(o->serial,"OWN-FIXTURE-A");
 if(i&&!strcmp(fault,"case_alias"))strcpy(o->name,"FiXtUrE0");
 o->sectors=capacities[i];o->sector_size=!i&&!strcmp(fault,"sector4k")?4096:512;
 if(!i&&!strcmp(fault,"partition"))o->flags=PLAT_DISK_PARTITION;
 if(!i&&!strcmp(fault,"readonly"))o->flags=PLAT_DISK_READONLY;
 if(!i&&!strcmp(fault,"small_target"))o->sectors=4096;
 return 0;
}
static void whole(unsigned i,uint8_t b[16]){memset(b,0,16);memcpy(b,&original_targets[i].st_dev,8);memcpy(b+8,&original_targets[i].st_ino,8);}
static int review(void *ctx,unsigned i,void *const src[2],native_setup_target_v1_t *o){
 unsigned j;(void)ctx;if(i>=2||!src[0]||!src[1])return -1;
 /* Prior physical source/boot/current-OS role admission is explicitly modeled.
  * Actual source-handle and target inode exclusion below is not modeled. */
 if(!strcmp(fault,"unknown_boot_whole")||!strcmp(fault,"source_whole")||!strcmp(fault,"current_os_whole"))return -1;
 for(j=0;j<2;j++){input_t *f=src[j];if(input_check(ctx,f)||
 (f->original.st_dev==original_targets[i].st_dev&&f->original.st_ino==original_targets[i].st_ino))return -1;}
 memset(o,0,sizeof *o);o->index=i;info(ctx,i,&o->disk);whole(i,o->whole_id);o->generation=!strcmp(fault,"stale_generation")?2:1;return 0;
}
static int target_check(void *ctx,void *claim,const native_setup_target_v1_t *o){
 struct stat a,b;uint8_t id[16];(void)ctx;checked++;
 if(!claim||!claimed||o->index>=2||broken)return -1;
 whole(o->index,id);if(memcmp(id,o->whole_id,16)||o->generation!=1)return -1;
 if(ancestry(target_paths[o->index])||fstat(disks[o->index],&a)||lstat(target_paths[o->index],&b)||
 !identity(&a,&b,1)||!identity(&a,&original_targets[o->index],0)||
 fcntl(disks[o->index],F_GETLEASE)!=F_WRLCK)return -1;
 return 0;
}
static int claim(void *ctx,const native_setup_target_v1_t *o,void *const src[2],void **v){
 native_setup_target_v1_t actual;
 if(review(ctx,o->index,src,&actual)||!strcmp(fault,"claim_denied"))return -1;
 if(fcntl(disks[o->index],F_SETOWN,getpid())||fcntl(disks[o->index],F_SETLEASE,F_WRLCK))return -1;
 claimed=1;claimed_target=*o;*v=(void *)(intptr_t)(o->index+1);return target_check(ctx,*v,o);
}
static int release(void *ctx,void *v){unsigned i=(unsigned)(intptr_t)v-1;int bad;(void)ctx;
 bad=!claimed||i>=2;if(!bad&&fcntl(disks[i],F_SETLEASE,F_UNLCK))bad=1;claimed=0;releases++;
 if(!strcmp(fault,"release_fail"))bad=1;return bad?-1:0;
}
static int alias_file(const char *path){char b[4096];if(snprintf(b,sizeof b,"%s.alias",path)>=(int)sizeof b)return -1;return rename(b,path);}
static int alias_ancestor(const char *path){char d[4096],m[4096],*s;
 strcpy(d,path);s=strrchr(d,'/');if(!s||s==d)return -1;*s=0;
 if(snprintf(m,sizeof m,"%s.moved",d)>=(int)sizeof m||rename(d,m)||symlink(m,d))return -1;return 0;
}
static uint32_t le32(const uint8_t *b){return b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
static int relocate(void *ctx,const uint8_t a[512],const uint8_t b[512],const uint8_t f[512],const uint8_t g[512],
 uint64_t bytes,uint64_t first,uint64_t last,native_setup_overlay_v1_t o[2]){
 unsigned i,k;uint16_t backup=(uint16_t)(a[50]|a[51]<<8);(void)ctx;(void)f;(void)g;
 /* Explicit test adapter model, NOT the unadopted peer implementation. Core
  * independently validates all four actual sector snapshots and outputs. */
 if(!bytes||last-first+1!=bytes/512||le32(a+28)||le32(b+28))return -1;
 memset(o,0,2*sizeof *o);for(i=0;i<2;i++){o[i].offset=(i?(uint64_t)backup*512:0)+28;
 memcpy(o[i].original,i?b+28:a+28,4);for(k=0;k<4;k++)o[i].replacement[k]=(uint8_t)(first>>(k*8));}
 if(!strcmp(fault,"bad_overlay"))o[1].offset++;
 if(!strcmp(fault,"changed_snapshot"))((uint8_t *)a)[28]=1;
 mutable_plan=o;
 if(!strcmp(fault,"source_alias")){if(alias_file(inputs[0].path))return -1;}
 if(!strcmp(fault,"source_ancestor")){if(alias_ancestor(inputs[0].path))return -1;}
 if(!strcmp(fault,"target_alias")){if(alias_file(target_paths[0]))return -1;}
 if(!strcmp(fault,"target_ancestor")){if(alias_ancestor(target_paths[0]))return -1;}
 if(!strcmp(fault,"lease_break")){pid_t child=fork();int status;
  if(child<0)return -1;if(!child){int fd=open(inputs[0].path,O_WRONLY|O_NONBLOCK|O_CLOEXEC);
   if(fd>=0){close(fd);_exit(4);}_exit(errno==EWOULDBLOCK?0:5);}
  while(waitpid(child,&status,0)<0)if(errno!=EINTR)return -1;
  if(!WIFEXITED(status)||WEXITSTATUS(status))return -1;
 }
 return 0;
}
static int exact_target(unsigned i,uint64_t lba,uint32_t n,void *b,int write){
 size_t length=(size_t)n*512,done=0;uint8_t *p=b;
 if(i>=2||!claimed||lba>=capacities[i]||n>capacities[i]-lba)return -1;
 while(done<length){ssize_t got;size_t take=length-done;
  if(!strcmp(fault,"short_io")&&take>4093)take=4093;
  if(target_check(0,(void *)(intptr_t)(i+1),&claimed_target))return -1;
  got=write?pwrite(disks[i],p+done,take,(off_t)(lba*512+done)):pread(disks[i],p+done,take,(off_t)(lba*512+done));
  if(got<0&&errno==EINTR)continue;if(got<=0)return -1;done+=(size_t)got;
  if(target_check(0,(void *)(intptr_t)(i+1),&claimed_target))return -1;
 }return 0;
}
static int read_disk(void *ctx,unsigned i,uint64_t lba,uint32_t n,void *b){(void)ctx;reads++;
 if(!strcmp(fault,"readback_eio"))return -1;
 if(exact_target(i,lba,n,b,0))return -1;
 if(!strcmp(fault,"readback_corrupt")&&lba>=2048)((uint8_t *)b)[0]^=1;
 return 0;
}
static int write_disk(void *ctx,unsigned i,uint64_t lba,uint32_t n,const void *b){(void)ctx;writes++;
 if(!strcmp(fault,"write_zero"))return -1;
 if(!strcmp(fault,"late_plan")&&!injected){injected=1;mutable_plan[1].offset++;}
 return exact_target(i,lba,n,(void *)b,1);
}
static int flush_disk(void *ctx,unsigned i){(void)ctx;flushes++;if(!strcmp(fault,"flush_fail"))return -1;return fsync(disks[i]);}
static int parse_sha(const char *s,uint8_t b[32]){unsigned i;if(!s||strlen(s)!=64)return -1;
 for(i=0;i<32;i++){unsigned x,y;if(sscanf(s+2*i,"%1x%1x",&x,&y)!=2)return -1;b[i]=(uint8_t)(x*16+y);}return 0;}
int main(int argc,char **argv){
 plat_t p={0,out,al,fr,source_open,source_read,source_close,sha_begin,sha_update,sha_end,random_bytes,now,count,info,read_disk,write_disk,flush_disk,2048};
 native_setup_ops_v1_t ops={NATIVE_SETUP_VERSION,sizeof ops,0,admit,input_check,checked_close,sha_begin,checked_update,checked_end,sha_abort,review,claim,target_check,release,relocate};
 native_setup_request_v1_t q;native_setup_result_v1_t r;unsigned i;struct sigaction sa;
 if(argc!=6)return 2;fault=argv[5];memset(&sa,0,sizeof sa);sa.sa_handler=sigio;sigemptyset(&sa.sa_mask);if(sigaction(SIGIO,&sa,0))return 2;
 for(i=0;i<2;i++){target_paths[i]=argv[3+i];disks[i]=open(argv[3+i],O_RDWR|O_NOFOLLOW|O_CLOEXEC);
  if(disks[i]<0||fstat(disks[i],&original_targets[i])||!S_ISREG(original_targets[i].st_mode)||
    original_targets[i].st_nlink!=1||(original_targets[i].st_mode&0777)!=0600)return 2;
  capacities[i]=(uint64_t)original_targets[i].st_size/512;
 }
 memset(&q,0,sizeof q);q.version=NATIVE_SETUP_VERSION;q.bytes=sizeof q;q.manifest_path=argv[1];q.sim_path=argv[2];
 if(parse_sha(getenv("MODEL_ADMITTED_MANIFEST_SHA256"),q.admitted_manifest_sha256))return 2;
 q.confirmation=!strcmp(fault,"bad_confirm")?"ERASE-TARGET":"ERASE";
 q.reviewed_target.index=0;info(0,0,&q.reviewed_target.disk);whole(0,q.reviewed_target.whole_id);q.reviewed_target.generation=1;
 setup_run_native(&p,!strcmp(fault,"missing_ops")?0:&ops,&q,&r);
 printf("HOST_RESULT ok=%d writes=%u reads=%u flushes=%u opened=%u closed=%u releases=%u claimed=%d checked=%u readback=%d gpt=%d windows=%d vm=%d\n",
 r.ok,writes,reads,flushes,opened,closed,releases,claimed,checked,r.target_readback_verified,r.GPT_readback_verified,r.Windows98_boot_verified,r.VM_executed);
 for(i=0;i<2;i++)if(close(disks[i]))return 3;
 return r.ok?0:1;
}
