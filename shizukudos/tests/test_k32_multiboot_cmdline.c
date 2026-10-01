/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../kernel64/standalone/k32_cmdline.h"
#include "../kernel32/service_policy.h"
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)){fprintf(stderr,"FAIL %u: %s\n",__LINE__,#x);exit(1);} } while(0)
static shz_bootinfo_t bi;
static int prepare(const char *line,int prefix)
{
    memset(&bi,0,sizeof bi);
    bi.magic=SHZ_BOOTINFO_MAGIC;bi.abi_major=SHZ_ABI_MAJOR;bi.abi_minor=SHZ_ABI_MINOR;
    bi.size=sizeof bi;bi.domain_id=SHZ_DOM_KERNEL32;bi.generation=1;
    const int n=shz_mb1_k32_cmdline(bi.cmdline,sizeof bi.cmdline,line,prefix);
    if(n<0)return -2;
    bi.cmdline_size=(uint32_t)n;
    return k32_boot_service_mode(&bi);
}
int main(void)
{
    char dst[8], longline[SHZ_CMDLINE_MAX];
    CHECK(shz_mb1_loader_is_qemu("qemu"));
    CHECK(!shz_mb1_loader_is_qemu("qemux"));
    CHECK(!shz_mb1_loader_is_qemu("GRUB 2"));
    CHECK(!shz_mb1_loader_is_qemu(NULL));
    CHECK(prepare("/root/build/kernel32s/boot.elf ",1)==0);
    CHECK(prepare("/root/build/kernel32s/boot.elf",1)==0);
    CHECK(prepare("boot.elf \t   ",1)==0);
    CHECK(prepare("",1)==0);
    CHECK(prepare("",0)==0);
    CHECK(prepare("/root/build/kernel32s/boot.elf",0)==-1);
    CHECK(prepare("boot.elf unknown=argument",1)==-1);
    CHECK(prepare("boot.elf shz.k32-service=win98",1)==-1); /* standalone has no owned channel */
    CHECK(!strcmp(bi.cmdline,K32_WIN98_SERVICE_CMDLINE));
    bi.channel_count=1;bi.channel[0].peer_domain=SHZ_DOM_KERNEL64;bi.channel[0].channel_id=0;
    bi.channel[0].gpa=SHZ_IPC_GPA_BASE;bi.channel[0].size=SHZ_IPC_REGION_SIZE;
    CHECK(k32_boot_service_mode(&bi)==1);
    bi.flags=1;CHECK(k32_boot_service_mode(&bi)<0);
    CHECK(prepare(K32_WIN98_SERVICE_CMDLINE,0)==-1); /* generic-loader raw request is preserved */
    CHECK(!strcmp(bi.cmdline,K32_WIN98_SERVICE_CMDLINE));
    CHECK(prepare("boot.elf shz.k32-service=win98-extra",1)==-1);
    CHECK(prepare("boot.elf shz.k32-service=win98 extra",1)==-1);
    CHECK(prepare("boot.elf shz.k32-service=win98 ",1)==-1);
    CHECK(prepare("boot.elf bad\x7f",1)==-2);
    CHECK(prepare(" boot.elf",1)==-2);
    CHECK(shz_mb1_k32_cmdline(NULL,8,"boot.elf",1)<0);
    CHECK(shz_mb1_k32_cmdline(dst,0,"boot.elf",1)<0);
    CHECK(shz_mb1_k32_cmdline(dst,sizeof dst,NULL,1)<0);
    CHECK(shz_mb1_k32_cmdline(dst,sizeof dst,"file arg",1)==3 && !strcmp(dst,"arg"));
    CHECK(shz_mb1_k32_cmdline(dst,3,"file arg",1)<0 && !dst[0]);
    memset(longline,'a',sizeof longline);
    CHECK(shz_mb1_k32_cmdline(dst,sizeof dst,longline,1)<0);
    CHECK(shz_mb1_k32_cmdline(dst,sizeof dst,longline,0)<0);
    printf("K32 Multiboot provider/service boundary: %u checks passed\n",checks);
}
