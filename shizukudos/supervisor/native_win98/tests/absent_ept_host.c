/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the actual production EPT mapper with a bounded host pool.
 * No VMX operation is called; bus contents are tested by constructor_host.c.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../src/ept.c"
static uint8_t pages[80][4096] __attribute__((aligned(4096)));
static unsigned allocated,checks;
static int fail_at=-1;
#define CHECK(v) do { ++checks;if(!(v)){fprintf(stderr,"FAIL %u: %s\n",__LINE__,#v);exit(2);} } while(0)
void *pool_alloc_pages(unsigned count)
{
    CHECK(count==1 && allocated<80);
    if((int)allocated==fail_at)return NULL;
    memset(pages[allocated],0,4096);return pages[allocated++];
}
static uint64_t leaf(const ept_t *e,uint64_t gpa)
{
    uint64_t *table=e->pml4,entry;
    for(int shift=39;shift>=21;shift-=9) {
        entry=table[(gpa>>shift)&511];if(!(entry&EPT_RWX))return 0;
        CHECK(!(entry&LARGE));table=(uint64_t *)(uintptr_t)(entry&ADDR_MASK);
    }
    return table[(gpa>>12)&511];
}
int main(void)
{
    ept_t e;const uint64_t bus=0xfee00000ull,host=0x30000000ull;
    CHECK(ept_init(&e)==0);
    CHECK(ept_map(&e,0,0x10000000ull,128ull<<20,EPT_RWX|EPT_WB,1)==0);
    CHECK(ept_map(&e,0xfffc0000ull,0x20000000ull,256ull<<10,EPT_R|EPT_X|EPT_WB,1)==0);
    CHECK(ept_map(&e,bus,host,4096,EPT_R|EPT_UC,1)==0);
    CHECK(leaf(&e,bus)==(host|EPT_R));CHECK(leaf(&e,bus+4095)==(host|EPT_R));
    CHECK(!(leaf(&e,bus)&(EPT_W|EPT_X|LARGE)) && !(leaf(&e,bus)&(7ull<<3)));
    CHECK(!leaf(&e,bus-4096) && !leaf(&e,bus+4096) && !leaf(&e,0xfec00000ull));
    CHECK(leaf(&e,0)==(0x10000000ull|EPT_RWX|EPT_WB));
    CHECK(leaf(&e,0xfffc0000ull)==(0x20000000ull|EPT_R|EPT_X|EPT_WB));
    CHECK(e.mapped_bytes==((128ull<<20)+(256ull<<10)+4096));
    uint64_t mapped=e.mapped_bytes;
    CHECK(ept_map(&e,bus,host,4096,EPT_R,1)==-1 && e.mapped_bytes==mapped);
    CHECK(ept_map(&e,bus+1,host,4096,EPT_R,1)==-1);
    CHECK(ept_map(&e,bus,host+1,4096,EPT_R,1)==-1);
    CHECK(ept_map(&e,bus,host,4095,EPT_R,1)==-1);
    /* Exhaust each actual table allocation; no successful leaf appears. */
    for(int failure=0;failure<4;++failure) {
        allocated=0;fail_at=failure;memset(&e,0,sizeof e);
        int rc=ept_init(&e);
        if(!failure){CHECK(rc==-1 && !e.pml4);continue;}
        CHECK(rc==0 && ept_map(&e,bus,host,4096,EPT_R|EPT_UC,1)==-1);
        CHECK(!e.mapped_bytes && !leaf(&e,bus));
    }
    printf("PASS %u production EPT exact absent-page permissions/bounds/allocation host checks; no VM\n",checks);
    return 0;
}
