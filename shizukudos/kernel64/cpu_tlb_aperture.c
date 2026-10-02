/* SPDX-License-Identifier: GPL-2.0-only
 * Exclusive pre-INIT 4KiB aperture. Does not change the generic VM walker.
 */
#include "cpu_tlb_aperture.h"
#define TLB_PA_MASK 0x000ffffffffff000ull
/* This bounded owner has exactly one lifetime, and never frees a published
 * table or payload. Reject a forged descriptor before any physical dereference. */
static shz_tlb_aperture_t retained_aperture;
int shz_tlb_aperture_valid(const shz_tlb_aperture_t *a)
{
    if(!a || a->prepared!=1 || a->va!=SHZ_TLB_APERTURE_VA || !a->root ||
       (a->root&~TLB_PA_MASK) || !a->frame[0] || !a->frame[1] || a->frame[0]==a->frame[1] ||
       (a->frame[0]&~TLB_PA_MASK) || (a->frame[1]&~TLB_PA_MASK)) return 0;
    if(!retained_aperture.prepared || a->root!=retained_aperture.root || a->leaf!=retained_aperture.leaf ||
       a->frame[0]!=retained_aperture.frame[0] || a->frame[1]!=retained_aperture.frame[1]) return 0;
    for(unsigned i=0;i<4;i++) if(a->table[i]!=retained_aperture.table[i]) return 0;
    uint64_t pa=a->root;
    for(unsigned i=0;i<4;i++) {
        if(pa!=a->table[i] || !pa || (pa&~TLB_PA_MASK)) return 0;
        for(unsigned j=0;j<i;j++) if(pa==a->table[j]) return 0;
        if(pa==a->frame[0] || pa==a->frame[1]) return 0;
        uint64_t *t=(uint64_t *)p2v(pa);
        const unsigned shift=12+9*(3-i),index=(a->va>>shift)&511;
        if(i==3) return a->leaf==&t[index];
        const uint64_t entry=__atomic_load_n(&t[index],__ATOMIC_ACQUIRE);
        if(!(entry&PT_P) || (entry&(0x80ull|PT_U))) return 0;
        pa=entry&TLB_PA_MASK;
    }
    return 0;
}
int shz_tlb_aperture_prepare(shz_tlb_aperture_t *out,uint64_t root,shz_tlb_owned_fn owns,void *ctx)
{
    shz_tlb_aperture_t a={0};uint64_t new_tables[2]={0},*parent=0,parent_value=0;
    unsigned allocated=0;
    if(!out || out->prepared || retained_aperture.prepared || !owns || !root ||
       (root&~TLB_PA_MASK) || !owns(ctx,root,PAGE_SIZE)) return -1;
    a.root=root;a.va=SHZ_TLB_APERTURE_VA;a.table[0]=root;
    for(unsigned level=0;level<3;level++) {
        const uint64_t pa=a.table[level];
        if(!owns(ctx,pa,PAGE_SIZE)) goto fail;
        uint64_t *t=(uint64_t *)p2v(pa);const unsigned index=(a.va>>(12+9*(3-level)))&511;
        uint64_t entry=__atomic_load_n(&t[index],__ATOMIC_ACQUIRE);
        if(entry&PT_P) {
            if(entry&(0x80ull|PT_U)) goto fail;
        } else {
            /* The PML4 entry must preexist, so all future process clones share
             * this PDPT. Nonzero nonpresent metadata is also a collision. */
            if(!level || entry || allocated==2) goto fail;
            uint64_t next=pmm_alloc();if(!next) goto fail;
            new_tables[allocated++]=next;
            if(!owns(ctx,next,PAGE_SIZE)) goto fail;
            entry=next|PT_P|PT_W;
            if(!parent) { parent=&t[index];parent_value=entry; }
            else t[index]=entry; /* Private, unpublished newly allocated table. */
        }
        a.table[level+1]=entry&TLB_PA_MASK;
        for(unsigned j=0;j<=level;j++) if(a.table[level+1]==a.table[j]) goto fail;
    }
    if(!owns(ctx,a.table[3],PAGE_SIZE)) goto fail;
    a.leaf=&((uint64_t *)p2v(a.table[3]))[(a.va>>12)&511];
    if(__atomic_load_n(a.leaf,__ATOMIC_ACQUIRE)) goto fail;
    for(unsigned i=0;i<2;i++) {
        a.frame[i]=pmm_alloc();if(!a.frame[i] || !owns(ctx,a.frame[i],PAGE_SIZE)) goto fail;
    }
    a.prepared=1;a.added_tables=allocated;
    /* No AP or process exists yet. Publish only after every allocation and
     * ownership check succeeds; failure above left all shared entries intact. */
    __atomic_store_n(a.leaf,a.frame[0]|PT_P|PT_W|PT_NX,__ATOMIC_RELEASE);
    if(parent) __atomic_store_n(parent,parent_value,__ATOMIC_RELEASE);
    retained_aperture=a;*out=a;return 0;
fail:
    for(unsigned i=0;i<2;i++) if(a.frame[i]) pmm_free(a.frame[i]);
    for(unsigned i=0;i<allocated;i++) pmm_free(new_tables[i]);
    return -1;
}
