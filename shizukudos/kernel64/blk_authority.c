/* SPDX-License-Identifier: GPL-2.0-only */
#include "blk_authority.h"
struct blk_authority_claim {
    blk_dev_t *device;
    blk_authority_identity_t identity;
    blk_dev_t snapshot;
    void *owner;
    blk_authority_source_t sources[2];
    int poisoned;
};
static struct blk_authority_claim entries[BLK_MAX_DEVICES];
static unsigned used;
static uint64_t epoch;
static kmutex_t lock;
static volatile unsigned lock_state;
static blk_authority_source_t boot_role, system_role;
static void acquire(void)
{
    unsigned expected=0;
    if(__atomic_compare_exchange_n(&lock_state,&expected,1,0,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        mutex_init(&lock);__atomic_store_n(&lock_state,2,__ATOMIC_RELEASE);
    }
    while(__atomic_load_n(&lock_state,__ATOMIC_ACQUIRE)!=2)__asm__ volatile("pause");
    mutex_lock(&lock);
}
static struct blk_authority_claim *entry(blk_dev_t *d)
{
    unsigned i;
    if(!d || d->parent || (d->flags&BLK_F_PARTITION))return 0;
    for(i=0;i<used;i++)if(entries[i].device==d)return &entries[i];
    return 0;
}
static blk_dev_t *whole(blk_dev_t *d)
{
    unsigned n=0;
    while(d && d->parent && n++<BLK_MAX_DEVICES)d=d->parent;
    return d && !d->parent?d:0;
}
static int observed(struct blk_authority_claim *e)
{
    blk_dev_t *d=e?e->device:0,*s=e?&e->snapshot:0;
    return d && !d->parent && !(d->flags&BLK_F_PARTITION) &&
      d->sector_size==s->sector_size && d->sectors==s->sectors && d->start_lba==s->start_lba &&
      d->priv==s->priv && d->read==s->read && d->write==s->write && d->flush==s->flush &&
      d->read_async==s->read_async && d->write_async==s->write_async &&
      d->discard==s->discard && d->control==s->control &&
      ((d->flags^s->flags)&~BLK_F_MOUNTED)==0;
}
static int equal(const blk_authority_identity_t *a,const blk_authority_identity_t *b)
{
    return a && b && !memcmp(a->whole_id,b->whole_id,16) && a->generation==b->generation &&
      a->sectors==b->sectors && a->sector_size==b->sector_size && a->flags==b->flags;
}
static int pin_ok(const blk_authority_source_t *p)
{
    struct blk_authority_claim *e=p?entry(p->whole):0;
    return observed(e) && !e->owner && !e->poisoned && equal(&p->identity,&e->identity);
}
static int bump(struct blk_authority_claim *e)
{
    if(epoch==UINT64_MAX){e->poisoned=1;return -1;}
    e->identity.generation=++epoch;return 0;
}
int blk_authority_register(blk_dev_t *d)
{
    struct blk_authority_claim *e;unsigned n,i,any;int collision;
    if(!d || d->parent || (d->flags&BLK_F_PARTITION))return -1;
    acquire();
    if(used==BLK_MAX_DEVICES || entry(d) || epoch==UINT64_MAX){mutex_unlock(&lock);return -1;}
    e=&entries[used];memset(e,0,sizeof *e);
    for(n=0;n<8;n++) {
        krandom_get(e->identity.whole_id,16);any=0;collision=0;
        for(i=0;i<16;i++)any|=e->identity.whole_id[i];
        for(i=0;i<used;i++)if(!memcmp(entries[i].identity.whole_id,e->identity.whole_id,16))collision=1;
        if(any && !collision)break;
    }
    if(n==8){mutex_unlock(&lock);return -1;}
    e->device=d;e->snapshot=*d;e->identity.sectors=d->sectors;
    e->identity.sector_size=d->sector_size;e->identity.flags=d->flags&~BLK_F_MOUNTED;
    bump(e);used++;mutex_unlock(&lock);return 0;
}
int blk_authority_enter(blk_dev_t *d,int mutation)
{
    struct blk_authority_claim *e;unsigned i;
    acquire();e=entry(whole(d));
    if(!observed(e) || e->owner || e->poisoned){mutex_unlock(&lock);return -1;}
    if(mutation)for(i=0;i<used;i++)if(entries[i].owner &&
      (entries[i].sources[0].whole==e->device || entries[i].sources[1].whole==e->device)) {
        mutex_unlock(&lock);return -1;
    }
    return 0;
}
int blk_authority_mark_mounted(blk_dev_t *d)
{
    if(blk_authority_enter(d,1))return -1;
    d->flags|=BLK_F_MOUNTED;blk_authority_leave(d,0,0);return 0;
}
void blk_authority_leave(blk_dev_t *d,int result,int changed_epoch)
{
    struct blk_authority_claim *e=entry(whole(d));
    if(e && (result || changed_epoch))bump(e);
    /* Ordinary unclaimed errors invalidate pinned observations, but preserve
     * legacy retry semantics. Claimed driver uncertainty is quarantined by
     * io()/flush(); no claimed target can enter this ordinary path. */
    mutex_unlock(&lock);
}
int blk_authority_bind_boot_roles(blk_dev_t *boot,blk_dev_t *system)
{
    struct blk_authority_claim *a,*b;unsigned i;int rc=-1;
    acquire();a=entry(whole(boot));b=entry(whole(system));
    for(i=0;i<used;i++)if(entries[i].owner)goto done;
    if(!observed(a)||!observed(b))goto done;
    boot_role.whole=a->device;boot_role.identity=a->identity;
    system_role.whole=b->device;system_role.identity=b->identity;rc=0;
done:mutex_unlock(&lock);return rc;
}
int blk_authority_pin_source(blk_dev_t *d,blk_authority_source_t *out)
{
    struct blk_authority_claim *e;int rc=-1;
    if(!out)return -1;
    acquire();e=entry(whole(d));
    if(observed(e)&&!e->owner&&!e->poisoned){out->whole=e->device;out->identity=e->identity;rc=0;}
    mutex_unlock(&lock);return rc;
}
static int protected_source(blk_dev_t *d)
{
    unsigned i;
    for(i=0;i<used;i++)if(entries[i].owner &&
      (entries[i].sources[0].whole==d || entries[i].sources[1].whole==d))return 1;
    return 0;
}
static int eligible(struct blk_authority_claim *e,const blk_authority_source_t s[2])
{
    blk_dev_t *d=e?e->device:0;
    return observed(e)&&!e->owner&&!e->poisoned&&!protected_source(d)&&d->sector_size==512&&d->write&&d->flush&&(d->flags&BLK_F_FLUSH)&&
      !(d->flags&(BLK_F_READONLY|BLK_F_PARTITION|BLK_F_REMOVABLE))&&!d->start_lba&&
      !d->read_async&&!d->write_async&&!blk_user_write_busy(d)&&
      pin_ok(&boot_role)&&pin_ok(&system_role)&&s&&pin_ok(&s[0])&&pin_ok(&s[1])&&
      d!=boot_role.whole&&d!=system_role.whole&&d!=s[0].whole&&d!=s[1].whole&&
      !s[0].whole->read_async&&!s[0].whole->write_async&&!s[1].whole->read_async&&!s[1].whole->write_async;
}
int blk_authority_review(blk_dev_t *d,const blk_authority_source_t s[2],blk_authority_identity_t *out)
{
    struct blk_authority_claim *e;int rc=-1;
    if(!out)return -1;
    acquire();e=entry(d);if(eligible(e,s)){*out=e->identity;rc=0;}
    mutex_unlock(&lock);return rc;
}
int blk_authority_claim_target(void *owner,blk_dev_t *d,const blk_authority_identity_t *review,
                               const blk_authority_source_t s[2],blk_authority_claim_t **out)
{
    struct blk_authority_claim *e;int rc=-1;
    if(!owner||!out)return -1;
    acquire();e=entry(d);
    if(eligible(e,s)&&equal(review,&e->identity)){e->owner=owner;memcpy(e->sources,s,sizeof e->sources);*out=e;rc=0;}
    mutex_unlock(&lock);return rc;
}
static int held(void *owner,blk_authority_claim_t *c,const blk_authority_identity_t *id)
{
    unsigned i;
    for(i=0;i<used;i++)if(c==&entries[i])break;
    if(i==used||!owner||c->owner!=owner||c->poisoned||!observed(c)||!equal(id,&c->identity))return 0;
    return pin_ok(&boot_role)&&pin_ok(&system_role)&&pin_ok(&c->sources[0])&&pin_ok(&c->sources[1])&&
      c->device!=boot_role.whole&&c->device!=system_role.whole&&!blk_user_write_busy(c->device);
}
int blk_authority_check(void *owner,blk_authority_claim_t *c,const blk_authority_identity_t *id)
{int ok;acquire();ok=held(owner,c,id);mutex_unlock(&lock);return ok?0:-1;}
static int io(void *owner,blk_authority_claim_t *c,const blk_authority_identity_t *id,
              uint64_t lba,unsigned n,void *buf,int write)
{
    int rc=-1;
    acquire();
    if(!held(owner,c,id)||!buf||!n||n>2048||lba>=c->device->sectors||n>c->device->sectors-lba)goto done;
    rc=write?c->device->write(c->device,lba,n,buf):c->device->read(c->device,lba,n,buf);
    if(rc)c->poisoned=1;
    if(!observed(c)){c->poisoned=1;rc=-1;}
done:mutex_unlock(&lock);return rc;
}
int blk_authority_read(void *o,blk_authority_claim_t *c,const blk_authority_identity_t *i,uint64_t l,unsigned n,void *b)
{return io(o,c,i,l,n,b,0);}
int blk_authority_write(void *o,blk_authority_claim_t *c,const blk_authority_identity_t *i,uint64_t l,unsigned n,const void *b)
{return io(o,c,i,l,n,(void *)b,1);}
int blk_authority_flush(void *owner,blk_authority_claim_t *c,const blk_authority_identity_t *id)
{
    int rc=-1;acquire();
    if(held(owner,c,id)){rc=c->device->flush(c->device);if(rc||!observed(c)){c->poisoned=1;rc=-1;}}
    mutex_unlock(&lock);return rc;
}
int blk_authority_release(void *owner,blk_authority_claim_t *c,const blk_authority_identity_t *id)
{
    unsigned i;int rc=-1;acquire();
    for(i=0;i<used;i++)if(c==&entries[i])break;
    if(i<used&&owner&&c->owner==owner&&!c->poisoned&&observed(c)&&equal(id,&c->identity)&&!bump(c)){c->owner=0;rc=0;}
    mutex_unlock(&lock);return rc;
}
