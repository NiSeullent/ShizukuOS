/* SPDX-License-Identifier: GPL-2.0-only
 * Four literal sectors only; no volume allocation or installer/device I/O.
 * SHZ_BRIDGE_LEGACY is a synthetic unrelocated adapter, not historical code.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "native_fat32_install_bridge.h"
#include "native_fat32_relocate.h"

static unsigned checks, failures;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr, "FAIL line %u: %s\n", __LINE__, #x); } } while (0)
#define IMAGE_BYTES (64ull * 1024 * 1024)
static uint8_t sectors[4][512], before[4][512];

static void w16(uint8_t *p, uint16_t v) { p[0]=(uint8_t)v; p[1]=(uint8_t)(v>>8); }
static void w32(uint8_t *p, uint32_t v) { unsigned i; for(i=0;i<4;i++) p[i]=(uint8_t)(v>>(8*i)); }
static void init(unsigned backup)
{
    unsigned i;
    memset(sectors,0,sizeof sectors);
    sectors[0][0]=0xeb; sectors[0][1]=0x58; sectors[0][2]=0x90;
    memcpy(sectors[0]+3,"BRIDGETS",8);
    w16(sectors[0]+11,512); sectors[0][13]=1; w16(sectors[0]+14,32);
    sectors[0][16]=2; sectors[0][21]=0xf8;
    w32(sectors[0]+32,131072); w32(sectors[0]+36,1024); w32(sectors[0]+44,2);
    w16(sectors[0]+48,1); w16(sectors[0]+50,(uint16_t)backup);
    for(i=90;i<510;i++) sectors[0][i]=(uint8_t)(i*17+3);
    sectors[0][510]=0x55; sectors[0][511]=0xaa;
    memcpy(sectors[1],sectors[0],512);
    for(i=2;i<4;i++) {
        w32(sectors[i],0x41615252); w32(sectors[i]+484,0x61417272);
        w32(sectors[i]+488,i==2?123:0xffffffffu);
        w32(sectors[i]+492,i==2?17:0xffffffffu);
        w32(sectors[i]+508,0xaa550000); sectors[i][100]=(uint8_t)(i*31);
    }
}

#ifdef SHZ_BRIDGE_LEGACY
/* Existing stage supplies geometry validation; this explicit adapter model
 * emits unchanged hidden DWORDs. It has no real installer lineage. */
static int selected(void *ctx,const uint8_t *a,const uint8_t *b,const uint8_t *f,const uint8_t *g,
                    uint64_t bytes,uint64_t first,uint64_t last,native_setup_overlay_v1_t *out)
{
    shz_native_fat32_relocate_t plan;
    native_setup_overlay_v1_t staged[2]={0};
    const uint8_t *in[4]={a,b,f,g}; unsigned i; int rc;
    (void)ctx;
    if(!out || (uintptr_t)out>UINTPTR_MAX-(sizeof staged-1)) return SHZ_NATIVE_FAT32_ARGUMENT;
    for(i=0;i<4;i++) {
        uintptr_t x=(uintptr_t)out,y=(uintptr_t)in[i];
        if(!in[i] || y>UINTPTR_MAX-511 || (x<=y?y-x<sizeof staged:x-y<512)) return SHZ_NATIVE_FAT32_ARGUMENT;
    }
    rc=shz_native_fat32_relocate_stage(a,512,b,512,f,512,g,512,0,bytes,first,last,&plan,sizeof plan);
    if(rc) return rc;
    staged[0].offset=28; staged[1].offset=plan.backup_boot_offset+28;
    for(i=0;i<2;i++) { memcpy(staged[i].original,in[i]+28,4); memcpy(staged[i].replacement,in[i]+28,4); }
    memcpy(out,staged,sizeof staged); return 0;
}
#else
#define selected shz_native_fat32_install_prepare_relocation
#endif

static void success(unsigned backup,uint64_t first,const uint8_t literal[4])
{
    struct { uint64_t left; native_setup_overlay_v1_t out[2]; uint64_t right; } guarded;
    native_setup_overlay_v1_t expected[2]; native_setup_ops_v1_t ops={0};
    memset(&guarded,0xa5,sizeof guarded); memset(expected,0,sizeof expected);
    init(backup); memcpy(before,sectors,sizeof before);
    expected[0].offset=28; expected[1].offset=(backup==6?3100:5148);
    memcpy(expected[0].replacement,literal,4); memcpy(expected[1].replacement,literal,4);
    ops.prepare_relocation=selected; /* actual header assignment, no cast */
    CHECK(ops.prepare_relocation((void *)(uintptr_t)1,sectors[0],sectors[1],sectors[2],sectors[3],
                                IMAGE_BYTES,first,first+131071,guarded.out)==0);
    CHECK(!memcmp(guarded.out,expected,sizeof expected));
    CHECK(!memcmp(before,sectors,sizeof before));
    CHECK(guarded.left==0xa5a5a5a5a5a5a5a5ull && guarded.right==0xa5a5a5a5a5a5a5a5ull);
    memset(guarded.out,0x39,sizeof guarded.out);
    CHECK(selected(0,sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,first,first+131071,guarded.out)==0);
    CHECK(!memcmp(guarded.out,expected,sizeof expected));
}

static void refuse(const uint8_t *a,const uint8_t *b,const uint8_t *f,const uint8_t *g,
                   uint64_t bytes,uint64_t first,uint64_t last,int status)
{
    native_setup_overlay_v1_t out[2],poison[2];
    memset(out,0x5a,sizeof out); memcpy(poison,out,sizeof out); memcpy(before,sectors,sizeof before);
    CHECK(selected(0,a,b,f,g,bytes,first,last,out)==status);
    CHECK(!memcmp(out,poison,sizeof out)); CHECK(!memcmp(before,sectors,sizeof before));
}

int main(void)
{
    static const uint8_t target[]={0x78,0x56,0x34,0x12}, one[]={1,0,0,0}, maximum[]={0xff,0xff,0xff,0xff};
    unsigned i; uint8_t saved[sizeof sectors];
    struct { uint8_t input[4][512]; native_setup_overlay_v1_t output[2]; } adjacent;
    success(6,0x12345678,target); success(10,0x12345678,target);
    success(6,1,one); success(10,UINT32_MAX,maximum);
    init(6);
    refuse(0,sectors[1],sectors[2],sectors[3],IMAGE_BYTES,1,131072,-1);
    refuse(sectors[0],0,sectors[2],sectors[3],IMAGE_BYTES,1,131072,-1);
    refuse(sectors[0],sectors[1],0,sectors[3],IMAGE_BYTES,1,131072,-1);
    refuse(sectors[0],sectors[1],sectors[2],0,IMAGE_BYTES,1,131072,-1);
    for(i=0;i<4;i++) {
        const uint8_t *p[4]={sectors[0],sectors[1],sectors[2],sectors[3]};
        p[i]=(const uint8_t *)(UINTPTR_MAX-100);
        refuse(p[0],p[1],p[2],p[3],IMAGE_BYTES,1,131072,-1);
        memcpy(saved,sectors,sizeof saved);
        CHECK(selected(0,sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,1,131072,
                       (native_setup_overlay_v1_t *)(void *)sectors[i])==-1);
        CHECK(!memcmp(saved,sectors,sizeof saved));
        CHECK(selected(0,sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,1,131072,
                       (native_setup_overlay_v1_t *)(void *)(sectors[i]+500))==-1);
        CHECK(!memcmp(saved,sectors,sizeof saved));
    }
    memcpy(before,sectors,sizeof before);
    CHECK(selected(0,sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,1,131072,0)==-1);
    CHECK(selected(0,sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,1,131072,
                   (native_setup_overlay_v1_t *)(UINTPTR_MAX-10))==-1);
    CHECK(!memcmp(before,sectors,sizeof before));
    refuse(sectors[0],sectors[1],sectors[2],sectors[3],0,1,131072,-2);
    refuse(sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES+1,1,131072,-2);
    refuse(sectors[0],sectors[1],sectors[2],sectors[3],SHZ_NATIVE_FAT32_MAX_SOURCE_BYTES+512,1,131072,-2);
    refuse(sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,0,131071,-3);
    refuse(sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,UINT32_MAX+1ull,UINT32_MAX+131072ull,-3);
    refuse(sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,1,1,-3);
    refuse(sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,2,1,-3);
    refuse(sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,1,UINT64_MAX,-3);
    for(i=0;i<8;i++) {
        init(6);
        if(i==0) sectors[1][90]^=1;
        if(i==1) sectors[0][28]=sectors[1][28]=1;
        if(i==2) sectors[0][13]=sectors[1][13]=3;
        if(i==3) sectors[0][52]=sectors[1][52]=1;
        if(i==4) sectors[2][0]^=1;
        if(i==5) w32(sectors[3]+492,1);
        if(i==6) w16(sectors[0]+50,31),w16(sectors[1]+50,31);
        if(i==7) w32(sectors[0]+36,1),w32(sectors[1]+36,1);
        refuse(sectors[0],sectors[1],sectors[2],sectors[3],IMAGE_BYTES,1,131072,-2);
    }
    /* Adjacent but disjoint storage is valid; no blanket same-allocation ban. */
    init(10);
    memcpy(adjacent.input,sectors,sizeof sectors);
    CHECK(selected(0,adjacent.input[0],adjacent.input[1],adjacent.input[2],adjacent.input[3],
                   IMAGE_BYTES,1,131072,adjacent.output)==0);
    CHECK(adjacent.output[0].offset==28 && adjacent.output[1].offset==5148);
    CHECK(!memcmp(adjacent.input,sectors,sizeof sectors));
    printf("BRIDGE checks=%u failures=%u\n",checks,failures);
    return failures?1:0;
}
