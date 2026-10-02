/* SPDX-License-Identifier: GPL-2.0-only
 * Literal synthetic BPB controls: no media, filesystem or disk execution.
 * Breaks caught: absent/wrong relocation; incomplete validation; mutation on
 * refusal; stale/tampered plan; wrong byte offsets/endianness/split windows.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "../../win64/setup/native_fat32_relocate.h"

typedef struct fixture { uint8_t p[512], b[512], f[512], bf[512]; } fixture_t;
typedef struct guarded { uint8_t pre[32]; shz_native_fat32_relocate_t q; uint8_t post[32]; } guarded_t;
static unsigned checks, failures;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; if (failures <= 100) \
    fprintf(stderr, "FAIL line %u: %s\n", (unsigned)__LINE__, #x); } } while (0)
static void p16(uint8_t *p, uint16_t x) { p[0]=(uint8_t)x; p[1]=(uint8_t)(x>>8); }
static void p32(uint8_t *p, uint32_t x) { for(unsigned i=0;i<4;++i)p[i]=(uint8_t)(x>>(8*i)); }

/* Explicit legacy BEHAVIOR MODEL, not an existing b144 helper or install run.
 * Copy source snapshots, publish geometry, and leave all stream bytes alone.
 * It compiles and executes ordinary relocation assertions instead of failing
 * at missing symbols. Basic pointer/size checks keep negative tests bounded.
 */
#ifdef NATIVE_FAT32_LEGACY_CONTROL
static uint16_t g16(const uint8_t *p) { return (uint16_t)(p[0]|(uint16_t)p[1]<<8); }
static uint32_t g32(const uint8_t *p) { return (uint32_t)p[0]|(uint32_t)p[1]<<8|(uint32_t)p[2]<<16|(uint32_t)p[3]<<24; }
static int intersects(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    if(an>UINTPTR_MAX-x || bn>UINTPTR_MAX-y)return 1;
    return an && bn && x<y+bn && y<x+an;
}
static int legacy_stage(const uint8_t *p,size_t pn,const uint8_t *b,size_t bn,
 const uint8_t *f,size_t fn,const uint8_t *bf,size_t bfn,uint64_t sf,uint64_t bytes,
 uint64_t first,uint64_t last,shz_native_fat32_relocate_t *out,size_t n)
{
    shz_native_fat32_relocate_t q;
    uint64_t data;
    (void)sf;
    if(!p||!b||!f||!bf||!out||pn!=512||bn!=512||fn!=512||bfn!=512||n!=sizeof q ||
       intersects(out,n,p,pn)||intersects(out,n,b,bn)||intersects(out,n,f,fn)||intersects(out,n,bf,bfn))return -1;
    memset(&q,0,sizeof q);q.source_bytes=bytes;q.target_first_lba=first;q.target_last_lba=last;
    q.backup_boot_offset=(uint64_t)g16(p+50)*512;q.fsinfo_offset=(uint64_t)g16(p+48)*512;
    q.backup_fsinfo_offset=q.backup_boot_offset+q.fsinfo_offset;q.total_sectors=g32(p+32);
    data=(uint64_t)g16(p+14)+2ull*g32(p+36);
    q.cluster_count=(p[13] && data<q.total_sectors)?(uint32_t)((q.total_sectors-data)/p[13]):0;
    memcpy(q.primary,p,512);memcpy(q.backup,b,512);memcpy(q.fsinfo,f,512);memcpy(q.backup_fsinfo,bf,512);
    memcpy(out,&q,sizeof q);return 0;
}
static int legacy_overlay(const shz_native_fat32_relocate_t *q,size_t n,uint64_t off,uint8_t *w,size_t wn)
{
    if(!q||n!=sizeof *q||(!w&&wn)||n>UINTPTR_MAX-(uintptr_t)q||wn>UINTPTR_MAX-(uintptr_t)w||
       off>q->source_bytes||wn>q->source_bytes-off||intersects(q,n,w,wn))return -1;
    return 0;
}
#define shz_native_fat32_relocate_stage legacy_stage
#define shz_native_fat32_relocate_overlay legacy_overlay
#endif

static void literal(fixture_t *x)
{
    memset(x,0,sizeof *x);
    x->p[0]=0xeb;x->p[1]=0x58;x->p[2]=0x90;memcpy(x->p+3,"NATIVE  ",8);
    p16(x->p+11,512);x->p[13]=1;p16(x->p+14,32);x->p[16]=2;x->p[21]=0xf8;
    p16(x->p+24,63);p16(x->p+26,255);p32(x->p+32,131072);p32(x->p+36,1024);
    p32(x->p+44,2);p16(x->p+48,1);p16(x->p+50,6);
    x->p[64]=0x80;x->p[66]=0x29;p32(x->p+67,0x01234567);
    memcpy(x->p+71,"NATIVE TEST",11);memcpy(x->p+82,"FAT32   ",8);
    for(unsigned i=90;i<510;++i)x->p[i]=(uint8_t)(i*37u+11u);
    x->p[510]=0x55;x->p[511]=0xaa;memcpy(x->b,x->p,512);
    p32(x->f,0x41615252);p32(x->f+484,0x61417272);p32(x->f+488,0xffffffff);
    p32(x->f+492,0xffffffff);p32(x->f+508,0xaa550000);x->f[100]=0x61;
    memcpy(x->bf,x->f,512);x->bf[100]=0x72; /* valid snapshots need not equal */
}
static int stage(const fixture_t *x,shz_native_fat32_relocate_t *q,uint64_t bytes,uint64_t first)
{
    return shz_native_fat32_relocate_stage(x->p,512,x->b,512,x->f,512,x->bf,512,0,bytes,first,first+bytes/512-1,q,sizeof *q);
}
static void expected_hidden(uint8_t p[512],const uint8_t bytes[4]) { memcpy(p+28,bytes,4); }
static void valid(const fixture_t *x,uint64_t bytes,uint64_t first,uint32_t clusters,const uint8_t hidden[4],
                  uint64_t boot,uint64_t info,uint64_t binfo)
{
    fixture_t original=*x,expected=*x;guarded_t g;uint8_t guard[32];
    memset(&g,0xa5,sizeof g);memset(guard,0xa5,sizeof guard);
    expected_hidden(expected.p,hidden);expected_hidden(expected.b,hidden);
    CHECK(stage(x,&g.q,bytes,first)==0);
    CHECK(!memcmp(x,&original,sizeof original));
    CHECK(!memcmp(g.pre,guard,32)&&!memcmp(g.post,guard,32));
    CHECK(!memcmp(g.q.primary,expected.p,512));CHECK(!memcmp(g.q.backup,expected.b,512));
    CHECK(!memcmp(g.q.fsinfo,x->f,512)&&!memcmp(g.q.backup_fsinfo,x->bf,512));
    CHECK(g.q.source_bytes==bytes&&g.q.target_first_lba==first&&g.q.target_last_lba==first+bytes/512-1);
    CHECK(g.q.total_sectors==bytes/512&&g.q.cluster_count==clusters);
    CHECK(g.q.backup_boot_offset==boot&&g.q.fsinfo_offset==info&&g.q.backup_fsinfo_offset==binfo);
}
static void refuse(const fixture_t *x,uint64_t source_first,uint64_t bytes,uint64_t first,uint64_t last)
{
    fixture_t original=*x;guarded_t g,before;memset(&g,0xa5,sizeof g);before=g;
    int st=shz_native_fat32_relocate_stage(x->p,512,x->b,512,x->f,512,x->bf,512,
                                         source_first,bytes,first,last,&g.q,sizeof g.q);
    CHECK(st!=0);CHECK(!memcmp(&g,&before,sizeof g));CHECK(!memcmp(x,&original,sizeof original));
}
static void geometries(void)
{
    fixture_t f,good;const uint8_t want[]={0x78,0x56,0x34,0x12},one[]={1,0,0,0},max[]={255,255,255,255};
    literal(&good);valid(&good,67108864,0x12345678,128992,want,3072,512,3584);
    valid(&good,67108864,1,128992,one,3072,512,3584);valid(&good,67108864,UINT32_MAX,128992,max,3072,512,3584);
    f=good;p32(f.p+32,131073);memcpy(f.b,f.p,512);valid(&f,67109376,0x12345678,128993,want,3072,512,3584);
    f=good;p16(f.p+48,3);p16(f.p+50,10);memcpy(f.b,f.p,512);valid(&f,67108864,0x12345678,128992,want,5120,1536,6656);
    f=good;p16(f.p+14,64523);p32(f.p+36,512);memcpy(f.b,f.p,512);valid(&f,67108864,0x12345678,65525,want,3072,512,3584);
    /*512 FAT sectors contain65536 entries, including the two reserved entries.*/
    f=good;p16(f.p+14,64514);p32(f.p+36,512);memcpy(f.b,f.p,512);valid(&f,67108864,0x12345678,65534,want,3072,512,3584);
    f=good;p16(f.p+14,64513);p32(f.p+36,512);memcpy(f.b,f.p,512);refuse(&f,0,67108864,2048,133119);
    f=good;p32(f.p+32,4718592);p32(f.p+36,65536);memcpy(f.b,f.p,512);
    valid(&f,2415919104ull,0x12345678,4587488,want,3072,512,3584);
    f=good;p32(f.p+32,4718592);p32(f.p+36,36864);f.p[13]=64;memcpy(f.b,f.p,512);
    valid(&f,2415919104ull,0x12345678,72575,want,3072,512,3584);
    f=good;p32(f.f+488,0);p32(f.f+492,2);p32(f.bf+488,128992);p32(f.bf+492,128993);
    valid(&f,67108864,0x12345678,128992,want,3072,512,3584);
    struct mutation { unsigned off,width;uint32_t value; } bad[]={
      {11,2,0},{11,2,1024},{13,1,0},{13,1,3},{13,1,129},{14,2,0},{14,2,1},
      {16,1,0},{16,1,1},{16,1,3},{17,2,1},{19,2,1},{21,1,0xf0},{22,2,1},
      {28,4,1},{32,4,0},{32,4,131071},{36,4,0},{36,4,512},{36,4,65536},
      {40,2,0x80},{40,2,1},{42,2,1},{44,4,0},{44,4,1},{44,4,128994},
      {48,2,0},{48,2,6},{48,2,26},{48,2,32},{50,2,0},{50,2,1},{50,2,31},{50,2,32},
      {52,1,1},{63,1,1},{510,2,0}};
    for(unsigned i=0;i<sizeof bad/sizeof bad[0];++i){
        f=good;if(bad[i].width==1)f.p[bad[i].off]=(uint8_t)bad[i].value;
        else if(bad[i].width==2)p16(f.p+bad[i].off,(uint16_t)bad[i].value);else p32(f.p+bad[i].off,bad[i].value);
        memcpy(f.b,f.p,512);refuse(&f,0,67108864,2048,133119);
    }
    f=good;f.b[90]^=1;refuse(&f,0,67108864,2048,133119);
    f=good;p16(f.p+14,64524);p32(f.p+36,512);memcpy(f.b,f.p,512);refuse(&f,0,67108864,2048,133119);
    f=good;p32(f.p+32,4718592);p32(f.p+36,65537);memcpy(f.b,f.p,512);refuse(&f,0,2415919104ull,2048,4720639);
    for(unsigned sector=0;sector<2;++sector){
        struct mutation fb[]={{0,4,0},{484,4,0},{508,4,0},{488,4,128993},{492,4,0},{492,4,1},{492,4,128994}};
        for(unsigned i=0;i<sizeof fb/sizeof fb[0];++i){f=good;p32((sector?f.bf:f.f)+fb[i].off,fb[i].value);refuse(&f,0,67108864,2048,133119);}
    }
    const uint64_t lengths[]={0,511,512,67108863,67108865,2415919616ull,UINT64_MAX};
    for(unsigned i=0;i<sizeof lengths/sizeof lengths[0];++i)refuse(&good,0,lengths[i],2048,133119);
    refuse(&good,1,67108864,2048,133119);refuse(&good,UINT64_MAX,67108864,2048,133119);
    refuse(&good,0,67108864,0,131071);refuse(&good,0,67108864,UINT32_MAX+1ull,UINT32_MAX+131072ull);
    refuse(&good,0,67108864,2048,2047);refuse(&good,0,67108864,2048,133118);
    refuse(&good,0,67108864,2048,133120);refuse(&good,0,67108864,2048,UINT64_MAX);
}
static void arguments(void)
{
    fixture_t f,original;guarded_t g,before;literal(&f);original=f;
    for(unsigned which=0;which<5;++which)for(unsigned k=0;k<4;++k){
        const uint8_t *p[]={f.p,f.b,f.f,f.bf};size_t n[]={512,512,512,512};
        size_t on=sizeof g.q;const size_t bad[]={0,511,513,SIZE_MAX};
        if(which<4)n[which]=bad[k];else on=(k==0?0:k==1?sizeof g.q-1:k==2?sizeof g.q+1:SIZE_MAX);
        memset(&g,0xa5,sizeof g);before=g;
        CHECK(shz_native_fat32_relocate_stage(p[0],n[0],p[1],n[1],p[2],n[2],p[3],n[3],0,67108864,2048,133119,&g.q,on)!=0);
        CHECK(!memcmp(&g,&before,sizeof g));CHECK(!memcmp(&f,&original,sizeof f));
    }
    for(unsigned which=0;which<5;++which){
        const uint8_t *p[]={f.p,f.b,f.f,f.bf};shz_native_fat32_relocate_t *o=&g.q;
        if(which<4)p[which]=NULL;else o=NULL;
        memset(&g,0xa5,sizeof g);before=g;
        CHECK(shz_native_fat32_relocate_stage(p[0],512,p[1],512,p[2],512,p[3],512,0,67108864,2048,133119,o,sizeof g.q)!=0);
        CHECK(!memcmp(&g,&before,sizeof g));CHECK(!memcmp(&f,&original,sizeof f));
    }
    for(unsigned which=0;which<4;++which){
        const uint8_t *p[]={f.p,f.b,f.f,f.bf};uint8_t *inside[]={g.q.primary,g.q.backup,g.q.fsinfo,g.q.backup_fsinfo};
        memset(&g,0xa5,sizeof g);memcpy(inside[which],p[which],512);p[which]=inside[which];before=g;
        CHECK(shz_native_fat32_relocate_stage(p[0],512,p[1],512,p[2],512,p[3],512,0,67108864,2048,133119,&g.q,sizeof g.q)!=0);
        CHECK(!memcmp(&g,&before,sizeof g));CHECK(!memcmp(&f,&original,sizeof f));
    }
    union { max_align_t a;uint8_t bytes[4096]; } space,saved;
    memset(&space,0xa5,sizeof space);memcpy(space.bytes+256,f.p,512);saved=space;
    CHECK(shz_native_fat32_relocate_stage(space.bytes+256,512,f.b,512,f.f,512,f.bf,512,0,67108864,2048,133119,
          (shz_native_fat32_relocate_t *)(void *)(space.bytes+512),sizeof g.q)!=0);
    CHECK(!memcmp(&space,&saved,sizeof space));CHECK(!memcmp(&f,&original,sizeof f));
    /* Read-only sources may alias each other; output alone must be disjoint. */
    CHECK(shz_native_fat32_relocate_stage(f.p,512,f.p,512,f.f,512,f.f,512,0,67108864,2048,133119,&g.q,sizeof g.q)==0);
    CHECK(!memcmp(&f,&original,sizeof f));
    /* Linux host integer-to-pointer wrap probes: never dereference them. */
    const uint8_t *wrapped=(const uint8_t *)(uintptr_t)(UINTPTR_MAX-100u);
    memset(&g,0xa5,sizeof g);before=g;
    CHECK(shz_native_fat32_relocate_stage(wrapped,512,f.b,512,f.f,512,f.bf,512,0,67108864,2048,133119,&g.q,sizeof g.q)==SHZ_NATIVE_FAT32_ARGUMENT);
    CHECK(!memcmp(&g,&before,sizeof g));CHECK(!memcmp(&f,&original,sizeof f));
    CHECK(shz_native_fat32_relocate_stage(f.p,512,f.b,512,f.f,512,f.bf,512,0,67108864,2048,133119,
          (shz_native_fat32_relocate_t *)(uintptr_t)(UINTPTR_MAX-100u),sizeof g.q)==SHZ_NATIVE_FAT32_ARGUMENT);
    CHECK(!memcmp(&f,&original,sizeof f));
}
static void prefix(const fixture_t *f,uint8_t v[8192],unsigned backup,unsigned info)
{
    for(unsigned i=0;i<8192;++i)v[i]=(uint8_t)(i*13u+7u);
    memcpy(v,f->p,512);memcpy(v+backup*512,f->b,512);memcpy(v+info*512,f->f,512);memcpy(v+(backup+info)*512,f->bf,512);
}
static void overlays(const fixture_t *f,unsigned backup,unsigned info)
{
    shz_native_fat32_relocate_t q,before;uint8_t original[8192],want[8192],got[8192];
    const uint8_t hidden[]={0x78,0x56,0x34,0x12};memset(&q,0,sizeof q);
    CHECK(stage(f,&q,67108864,0x12345678)==0);before=q;
    prefix(f,original,backup,info);memcpy(want,original,sizeof want);
    memcpy(want+28,hidden,4);memcpy(want+backup*512+28,hidden,4);
    const unsigned steps[]={1,2,3,7,31,511,512,4093,4096,8192};
    for(unsigned k=0;k<sizeof steps/sizeof steps[0];++k){
        int ok=1;memcpy(got,original,sizeof got);
        for(unsigned off=0;off<sizeof got;){unsigned n=steps[k];if(n>sizeof got-off)n=(unsigned)sizeof got-off;
            if(shz_native_fat32_relocate_overlay(&q,sizeof q,off,got+off,n))ok=0;
            off+=n;}
        CHECK(ok);CHECK(!memcmp(got,want,sizeof got));CHECK(!memcmp(&q,&before,sizeof q));
    }
    const unsigned positions[]={28,backup*512+28};
    for(unsigned p=0;p<2;++p)for(unsigned start=positions[p]-2;start<=positions[p]+4;++start)for(unsigned n=0;n<=8;++n){
        uint8_t w[24],expected[24];memset(w,0xa5,sizeof w);memcpy(w+8,original+start,n);memcpy(expected,w,sizeof w);
        memcpy(expected+8,want+start,n);CHECK(shz_native_fat32_relocate_overlay(&q,sizeof q,start,w+8,n)==0);
        CHECK(!memcmp(w,expected,sizeof w));CHECK(!memcmp(&q,&before,sizeof q));
    }
    uint8_t w[32],saved[32];memset(w,0xa5,sizeof w);memcpy(saved,w,sizeof w);
    CHECK(shz_native_fat32_relocate_overlay(&q,sizeof q,67108864-32,w,32)==0);CHECK(!memcmp(w,saved,sizeof w));
    CHECK(shz_native_fat32_relocate_overlay(&q,sizeof q,0,NULL,0)==0);
    CHECK(shz_native_fat32_relocate_overlay(&q,sizeof q,67108864,NULL,0)==0);
    CHECK(!memcmp(&q,&before,sizeof q));
    /* A consistent manually restaged plan is not an authenticated issue token. */
    q.target_first_lba=2048;q.target_last_lba=133119;p32(q.primary+28,2048);p32(q.backup+28,2048);
    memset(w,0xa5,sizeof w);memcpy(saved,w,sizeof w);saved[28]=0;saved[29]=8;saved[30]=0;saved[31]=0;
    CHECK(shz_native_fat32_relocate_overlay(&q,sizeof q,0,w,32)==0);CHECK(!memcmp(w,saved,sizeof w));
}
static void bad_plan(const shz_native_fat32_relocate_t *q,size_t qn,uint64_t off,size_t n)
{
    uint8_t w[96],before[96];memset(w,0xa5,sizeof w);memcpy(before,w,sizeof w);
    CHECK(shz_native_fat32_relocate_overlay(q,qn,off,w+16,n)!=0);CHECK(!memcmp(w,before,sizeof w));
}
static void plan_refusals(void)
{
    fixture_t f;shz_native_fat32_relocate_t good,q,saved;literal(&f);memset(&good,0,sizeof good);
    CHECK(stage(&f,&good,67108864,0x12345678)==0);
    for(unsigned i=0;i<16;++i){q=good;
        switch(i){case 0:q.source_bytes+=512;break;case 1:q.target_first_lba++;break;case 2:q.target_last_lba--;break;
        case 3:q.backup_boot_offset+=512;break;case 4:q.fsinfo_offset+=512;break;case 5:q.backup_fsinfo_offset+=512;break;
        case 6:q.total_sectors--;break;case 7:q.cluster_count--;break;case 8:q.primary[28]^=1;break;case 9:q.backup[28]^=1;break;
        case 10:q.primary[90]^=1;break;case 11:q.backup[510]=0;break;case 12:p32(q.fsinfo+488,128993);break;
        case 13:p32(q.backup_fsinfo+492,1);break;case 14:q.primary[52]=q.backup[52]=1;break;default:q.target_first_lba=0;break;}
        saved=q;bad_plan(&q,sizeof q,26,8);CHECK(!memcmp(&q,&saved,sizeof q));
        bad_plan(&q,sizeof q,0,0);CHECK(!memcmp(&q,&saved,sizeof q));
    }
    bad_plan(NULL,sizeof good,0,0);bad_plan(&good,0,26,8);bad_plan(&good,sizeof good-1,26,8);
    bad_plan(&good,sizeof good+1,26,8);bad_plan(&good,SIZE_MAX,26,8);
    bad_plan(&good,sizeof good,67108865,0);bad_plan(&good,sizeof good,67108864,1);
    bad_plan(&good,sizeof good,67108860,5);bad_plan(&good,sizeof good,UINT64_MAX,1);
    bad_plan(&good,sizeof good,0,SIZE_MAX);
    CHECK(shz_native_fat32_relocate_overlay(&good,sizeof good,28,NULL,4)!=0);
    saved=good;CHECK(shz_native_fat32_relocate_overlay(&good,sizeof good,28,good.primary+28,4)!=0);
    CHECK(!memcmp(&good,&saved,sizeof good));
    uint8_t *last=(uint8_t *)&good+sizeof good-1;
    CHECK(shz_native_fat32_relocate_overlay(&good,sizeof good,0,last,1)!=0);CHECK(!memcmp(&good,&saved,sizeof good));
    bad_plan((const shz_native_fat32_relocate_t *)(uintptr_t)(UINTPTR_MAX-100u),sizeof good,26,8);
    CHECK(shz_native_fat32_relocate_overlay(&good,sizeof good,0,
          (uint8_t *)(uintptr_t)(UINTPTR_MAX-1u),4)==SHZ_NATIVE_FAT32_ARGUMENT);
    CHECK(!memcmp(&good,&saved,sizeof good));
}
static void vectors(const char *dir)
{
    fixture_t f;shz_native_fat32_relocate_t q;uint8_t original[8192],result[8192];char path[4096];
    for(unsigned k=0;k<2;++k){literal(&f);unsigned backup=k?10:6,info=k?3:1;
        p16(f.p+48,(uint16_t)info);p16(f.p+50,(uint16_t)backup);memcpy(f.b,f.p,512);
        memset(&q,0,sizeof q);CHECK(stage(&f,&q,67108864,0x12345678)==0);
        prefix(&f,original,backup,info);memcpy(result,original,sizeof result);
        CHECK(shz_native_fat32_relocate_overlay(&q,sizeof q,0,result,sizeof result)==0);
        for(unsigned side=0;side<2;++side){int n=snprintf(path,sizeof path,"%s/%u-%s.bin",dir,k,side?"relocated":"source");
            CHECK(n>0&&(size_t)n<sizeof path);if(n<0||(size_t)n>=sizeof path)continue;
            FILE *o=fopen(path,"wb");CHECK(o!=NULL);if(!o)continue;
            CHECK(fwrite(side?result:original,1,sizeof result,o)==sizeof result);CHECK(fclose(o)==0);
        }
    }
}
int main(int argc,char **argv)
{
    fixture_t f;geometries();arguments();literal(&f);overlays(&f,6,1);
    p16(f.p+48,3);p16(f.p+50,10);memcpy(f.b,f.p,512);overlays(&f,10,3);plan_refusals();
    if(argc==2)vectors(argv[1]);else CHECK(argc==1);
    printf("native-fat32 checks=%u failures=%u\n",checks,failures);
    return failures?1:0;
}
