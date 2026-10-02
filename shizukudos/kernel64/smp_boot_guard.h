/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef SHZ_K64_SMP_BOOT_GUARD_H
#define SHZ_K64_SMP_BOOT_GUARD_H
#include "smp_acpi.h"
#include "standalone/memholes.h"
#define SHZ_SMP_RETIRED_PML4_PA 0x1000u
enum shz_smp_boot_guard_status {
    SHZ_SMP_BOOT_GUARD_OK=0,SHZ_SMP_BOOT_GUARD_INVALID=-1,
    SHZ_SMP_BOOT_GUARD_UNREADABLE=-2,SHZ_SMP_BOOT_GUARD_DEPENDENCY=-3,
    SHZ_SMP_BOOT_GUARD_LIMIT=-4
};
static inline uint64_t shz_smp_guard_u64(const uint8_t *b)
{
    unsigned i; uint64_t v=0;
    for(i=0;i<8;i++) v|=(uint64_t)b[i]<<(i*8);
    return v;
}
/* The native Multiboot stub's three retired root pages have exact, checked
 * shapes. Accessed bits may have been set by the CPU; no other software entry
 * or foreign loader contract is inferred. These pages are never written here. */
static inline int shz_smp_guard_old_root(shz_smp_phys_read_fn read,void *ctx,
                                       uint64_t pa,unsigned slot,uint64_t child,
                                       int has_high)
{
    uint8_t b[64]; unsigned at,i;
    for(at=0;at<512;at+=8) {
        if(read(ctx,pa+at*8,b,sizeof b)) return SHZ_SMP_BOOT_GUARD_UNREADABLE;
        for(i=0;i<8;i++) {
            const unsigned index=at+i;
            const uint64_t expected=index==slot ? child|3 : has_high && index==511 ? 0x4003 : 0;
            const uint64_t actual=shz_smp_guard_u64(b+i*8);
            if(actual!=expected && (!expected || actual!=(expected|0x20))) return SHZ_SMP_BOOT_GUARD_INVALID;
        }
    }
    return 0;
}
static inline int shz_smp_guard_walk(shz_smp_phys_read_fn read,void *ctx,
                                   uint64_t pa,unsigned level,uint64_t ram,
                                   uint64_t path[4],unsigned *budget)
{
    uint8_t b[64]; unsigned at,i,j;
    if(level<1 || level>4) return SHZ_SMP_BOOT_GUARD_INVALID;
    if(pa<SHZ_K64_PMM_GPA || pa>ram || 4096>ram-pa || (pa&4095))
        return SHZ_SMP_BOOT_GUARD_DEPENDENCY;
    for(j=0;j<4-level;j++) if(path[j]==pa) return SHZ_SMP_BOOT_GUARD_DEPENDENCY;
    if(!*budget) return SHZ_SMP_BOOT_GUARD_LIMIT;
    --*budget; path[4-level]=pa;
    for(at=0;at<512;at+=8) {
        if(read(ctx,pa+at*8,b,sizeof b)) return SHZ_SMP_BOOT_GUARD_UNREADABLE;
        /* PT pages are table nodes too: validate every byte through the ownership reader. */
        if(level==1) continue;
        for(i=0;i<8;i++) {
            const uint64_t entry=shz_smp_guard_u64(b+i*8);
            int rc;
            if(!(entry&1)) continue;
            if(entry&0x80) {
                if(level==4) return SHZ_SMP_BOOT_GUARD_INVALID;
                continue; /*1GiB/2MiB leaves are data aliases, not table roots. */
            }
            rc=shz_smp_guard_walk(read,ctx,entry&0x000ffffffffff000ull,level-1,ram,path,budget);
            if(rc) return rc;
        }
    }
    return 0;
}
/* Caller captures actual initialCR3 before replacing the native Multiboot boot
 * tables and supplies a reader bounded by retained usableRAM/firmware records.
 * Caller establishes actual allocator ownership and excludes firmware holes.
 * This guard proves only the PMM address-range fence and absence of non-leaf
 * dependencies on retired low pages; readable firmware data is not ownership.
 * A direct-map data alias is intentionally legal.
 * This authorizes only page0x1000 retirement; UEFI has a separate loader contract.
 * Bounded reads and depth/budget keep malformed/cyclic roots fail-closed. */
static inline int shz_smp_boot_pages_safe(shz_smp_phys_read_fn read,void *ctx,
                                        uint64_t initial,uint64_t current,
                                        uint64_t final,uint64_t ram)
{
    uint64_t path[4]; unsigned budget=4096; int rc;
    if(!read || initial!=SHZ_SMP_RETIRED_PML4_PA || current!=final || final<SHZ_K64_PMM_GPA ||
       (final&4095) || ram>(1ull<<32) || (ram&4095) || final>ram || 4096>ram-final)
        return SHZ_SMP_BOOT_GUARD_INVALID;
    rc=shz_smp_guard_old_root(read,ctx,0x1000,0,0x2000,1);
    if(rc) return rc;
    rc=shz_smp_guard_old_root(read,ctx,0x2000,0,0x3000,0);
    if(rc) return rc;
    rc=shz_smp_guard_old_root(read,ctx,0x4000,510,0x3000,0);
    if(rc) return rc;
    return shz_smp_guard_walk(read,ctx,final,4,ram,path,&budget);
}
#endif
