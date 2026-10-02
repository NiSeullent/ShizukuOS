/* SPDX-License-Identifier: GPL-2.0-only */
#define main old_absent_ept_main
#include "absent_ept_host.c"
#undef main
int main(void){ept_t e;CHECK(ept_init(&e)==0);CHECK(ept_map(&e,0,0x10000000,128ull<<20,EPT_RWX|EPT_WB,1)==0);
 for(unsigned n=0;n<32;++n)CHECK(ept_remap_page(&e,0xa0000+(n<<12),0xa0000+(n<<12),EPT_R|EPT_W|EPT_UC)==0);
 CHECK(leaf(&e,0xa0000)==(0xa0000|EPT_R|EPT_W));CHECK(leaf(&e,0xbffff)==(0xbf000|EPT_R|EPT_W));CHECK(leaf(&e,0x9ffff)==(0x1009f000|EPT_RWX|EPT_WB));CHECK(leaf(&e,0xc0000)==(0x100c0000|EPT_RWX|EPT_WB));
 for(unsigned n=0;n<4096;++n)CHECK(ept_remap_page(&e,0xe0000000u+(n<<12),0xe0000000u+(n<<12),EPT_R|EPT_W|EPT_UC)==0);
 CHECK(leaf(&e,0xe0000000)==(0xe0000000|EPT_R|EPT_W));CHECK(leaf(&e,0xe0fff000)==(0xe0fff000|EPT_R|EPT_W));CHECK(!leaf(&e,0xe1000000));
 CHECK(ept_map(&e,0xfb000000,0x20000000,65536,EPT_R|EPT_X|EPT_WB,1)==0);CHECK(leaf(&e,0xfb000000)==(0x20000000|EPT_R|EPT_X|EPT_WB));
 for(unsigned n=0;n<32;++n)CHECK(ept_remap_page(&e,0x1a0000+(n<<12),0xa0000+(n<<12),EPT_R|EPT_W|EPT_UC)==0);
 CHECK(leaf(&e,0x1a0000)==leaf(&e,0xa0000));
 for(unsigned n=0;n<4096;++n)CHECK(ept_remap_page(&e,0xe0000000u+(n<<12),0xe0000000u+((n<<12)&~0x100000u),EPT_R|EPT_W|EPT_UC)==0);
 CHECK(leaf(&e,0xe0100000)==leaf(&e,0xe0000000));
 for(unsigned n=0;n<4096;++n)CHECK(ept_remap_page(&e,0xe0000000u+(n<<12),0,0)==0);
 CHECK(!(leaf(&e,0xe0000000)&EPT_RWX)&&!(leaf(&e,0xe0fff000)&EPT_RWX));fail_at=(int)allocated;CHECK(ept_remap_page(&e,0x40000000,0xa0000,EPT_R|EPT_W)==-1);CHECK(!leaf(&e,0x40000000));
 printf("PASS %u actual EPT VGA permission/alias/revoke/allocation checks, no VM\n",checks);return 0;}
