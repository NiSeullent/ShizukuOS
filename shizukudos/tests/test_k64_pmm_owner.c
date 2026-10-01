/* SPDX-License-Identifier: GPL-2.0-only
 * Execute the actual PMM ownership observer against the real bitmap and
 * reservation state. Unused privileged kernel functions are linker-discarded.
 */
#include <stdio.h>
#include <stdlib.h>
#define SHZ_STANDALONE 1
#include "../kernel64/k64.h"
extern int shz_cpu_pmm_page_owned(uint64_t,const shz_bootinfo_t *) __attribute__((weak));
#include "../kernel64/mem.c"
static unsigned checks;
#define CHECK(x) do { ++checks; if(!(x)) { fprintf(stderr,"FAIL line%u: %s\n",__LINE__,#x); exit(1); } } while(0)
int main(void)
{
    int (*volatile owned)(uint64_t,const shz_bootinfo_t *)=shz_cpu_pmm_page_owned;
    shz_bootinfo_t bi={0};
    CHECK(owned!=0); /* Missing implementation is runtime RED, not a link failure. */
    pmm_pages=64; ram_top=PMM_BASE+pmm_pages*PAGE_SIZE;
    memset(page_map,0,sizeof page_map); hole_count=0;
    CHECK(!owned(PMM_BASE,&bi));
    bit_set(0); CHECK(owned(PMM_BASE,&bi));
    bit_clr(0); CHECK(!owned(PMM_BASE,&bi));
    bit_set(0); CHECK(!owned(PMM_BASE,0));
    CHECK(!owned(PMM_BASE-4096,&bi)); CHECK(!owned(PMM_BASE+1,&bi));
    CHECK(!owned(ram_top,&bi)); CHECK(!owned(UINT64_MAX-4095,&bi));
    bit_set(63); CHECK(owned(ram_top-4096,&bi));
    hole_count=1; hole_gpa[0]=PMM_BASE; hole_end[0]=PMM_BASE+4096;
    CHECK(!owned(PMM_BASE,&bi)); CHECK(owned(ram_top-4096,&bi));
    hole_gpa[0]=PMM_BASE+4095; hole_end[0]=PMM_BASE+8192;
    CHECK(!owned(PMM_BASE,&bi));
    hole_count=0;
    bi.initrd_gpa=PMM_BASE; bi.initrd_size=4096;
    CHECK(!owned(PMM_BASE,&bi)); CHECK(owned(ram_top-4096,&bi));
    bi.initrd_gpa=PMM_BASE+4095; bi.initrd_size=1;
    CHECK(!owned(PMM_BASE,&bi));
    bi.initrd_gpa=PMM_BASE-1; bi.initrd_size=2;
    CHECK(!owned(PMM_BASE,&bi));
    bi.initrd_gpa=UINT64_MAX-1; bi.initrd_size=4;
    CHECK(!owned(PMM_BASE,&bi));
    bi.initrd_gpa=PMM_BASE; bi.initrd_size=0;
    CHECK(owned(PMM_BASE,&bi));
    bit_clr(63); CHECK(!owned(ram_top-4096,&bi));
    printf("PASS actual PMM allocation/reservation ownership: %u checks\n",checks);
    return 0;
}
