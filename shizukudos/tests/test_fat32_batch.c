/* SPDX-License-Identifier: GPL-2.0-only
 * Production FAT32 read-path contracts with deliberately fragmented extents
 * and a callback that corrupts its own failed-batch output before returning.
 */
#include "../kernel64/fat32.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned assertions;
#define CHECK(x) do { ++assertions; if (!(x)) { fprintf(stderr,"line %u: %s\n",(unsigned)__LINE__,#x); exit(1); } } while(0)
struct model { unsigned calls, singles, batches, fail_call; uint64_t lba[16]; unsigned count[16]; };
static uint8_t pattern(uint64_t lba,unsigned byte) { return (uint8_t)(lba*7u+byte*13u); }
static int single(void *ctx,uint64_t lba,void *buf)
{
    struct model *m=ctx;unsigned i;
    CHECK(m->calls<16);m->lba[m->calls]=lba;m->count[m->calls]=1;++m->calls;++m->singles;
    if(m->fail_call==m->calls)return -1;
    for(i=0;i<512;++i)((uint8_t *)buf)[i]=pattern(lba,i);
    return 0;
}
static int batch(void *ctx,uint64_t lba,unsigned count,void *buf)
{
    struct model *m=ctx;unsigned i,s;
    CHECK(count>=2 && count<=FAT32_READ_MAX_SECTORS && m->calls<16);
    m->lba[m->calls]=lba;m->count[m->calls]=count;++m->calls;++m->batches;
    for(s=0;s<count;++s)for(i=0;i<512;++i)((uint8_t *)buf)[s*512u+i]=pattern(lba+s,i);
    /* Partial DMA must never escape FAT32's private staging on error. */
    return m->fail_call==m->calls?-1:0;
}
static void reset(fat32_vol_t *v,struct model *m,int many)
{
    memset(v,0,sizeof(*v));memset(m,0,sizeof(*m));v->read=single;v->read_many=many?batch:0;
    v->ctx=m;v->disk_sectors=4096;v->part_lba=100;v->first_data=32;
    v->spc=1;v->bytes_per_cluster=512;v->cluster_count=1000;v->sector_lba=~UINT64_C(0);
}
static uint64_t file_lba(uint64_t off)
{
    const uint64_t sector=off/512;
    return 132u+(sector<4?10u+sector:40u+sector-4u)-2u;
}
static void check_bytes(const uint8_t *out,uint64_t off,unsigned bytes)
{ unsigned i;for(i=0;i<bytes;++i)CHECK(out[i]==pattern(file_lba(off+i),(unsigned)((off+i)%512u))); }
int main(void)
{
    fat32_vol_t v;struct model m;fat32_run_t runs[2]={{10,4,0},{40,5,4}};
    const fat32_chain_t c={runs,2,2,9};uint8_t out[4609];uint64_t done;unsigned i;
    reset(&v,&m,1);memset(out,0xa5,sizeof(out));
    CHECK(fat32_read(&v,&c,4113,0,out,4096,&done)==0 && done==4096);
    CHECK(m.calls==2 && m.batches==2 && v.sector_reads==8);
    CHECK(m.lba[0]==140 && m.count[0]==4 && m.lba[1]==170 && m.count[1]==4);
    check_bytes(out,0,4096);CHECK(out[4096]==0xa5);
    reset(&v,&m,0);CHECK(fat32_read(&v,&c,4113,0,out,4096,&done)==0 && done==4096);
    CHECK(m.calls==8 && !m.batches && v.sector_reads==8);check_bytes(out,0,4096);
    reset(&v,&m,1);memset(out,0xa5,sizeof(out));
    CHECK(fat32_read(&v,&c,4113,1024,out,3072,&done)==0 && done==3072);
    CHECK(m.calls==2 && m.count[0]==2 && m.count[1]==4);check_bytes(out,1024,3072);CHECK(out[3072]==0xa5);
    reset(&v,&m,1);memset(out,0xa5,sizeof(out));
    CHECK(fat32_read(&v,&c,4113,511,out,1538,&done)==0 && done==1538);
    CHECK(m.calls==3 && m.singles==2 && m.batches==1 && m.count[1]==3);
    check_bytes(out,511,1538);CHECK(out[1538]==0xa5);
    reset(&v,&m,1);memset(out,0xa5,sizeof(out));
    CHECK(fat32_read(&v,&c,4113,3584,out,1024,&done)==0 && done==529);
    CHECK(m.calls==2 && m.singles==2 && !m.batches);check_bytes(out,3584,529);CHECK(out[529]==0xa5);
    CHECK(fat32_read(&v,&c,4113,4113,out,1024,&done)==0 && !done && m.calls==2);
    for(i=1;i<=2;++i) {
        reset(&v,&m,1);m.fail_call=i;memset(out,0xa5,sizeof(out));
        CHECK(fat32_read(&v,&c,4113,0,out,4096,&done)==FAT32_E_IO && done==(uint64_t)(i-1)*2048u);
        check_bytes(out,0,(i-1)*2048u);
        for(unsigned j=(i-1)*2048u;j<sizeof(out);++j)CHECK(out[j]==0xa5);
    }
    reset(&v,&m,0);m.fail_call=3;memset(out,0xa5,sizeof(out));
    CHECK(fat32_read(&v,&c,4113,0,out,4096,&done)==FAT32_E_IO && done==1024);
    check_bytes(out,0,1024);CHECK(out[1024]==0xa5);
    reset(&v,&m,1);v.disk_sectors=143;memset(out,0xa5,sizeof(out));
    CHECK(fat32_read(&v,&c,4113,0,out,2048,&done)==FAT32_E_RANGE && !done && !m.calls);
    for(i=0;i<sizeof(out);++i)CHECK(out[i]==0xa5);
    puts("4 KiB file request: 8 single-sector callbacks -> 2 actual four-sector callbacks; fragmented/EOF/error output preserved");
    printf("PASS: FAT32 batch contracts %u assertions\n",assertions);return 0;
}
