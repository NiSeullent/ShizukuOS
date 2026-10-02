/* SPDX-License-Identifier: GPL-2.0-only
 * Supervisor-owned modern virtio-blk, one bounded polled split queue. See
 * VIRTIO 1.2 sections 3.1,4.1,5.2. No legacy/DMA/PCI passthrough to Win98.
 * Queue storage must survive until actual reset acknowledgment. A failed or
 * timed-out operation can have modified backing storage; no rollback claim.
 */
#include "virtio_blk.h"
#include <string.h>
#define POLLS 1000000u
#define FEATURE_FLUSH (1u<<9)
#define FEATURE_BLKSIZE (1u<<6)
#define FEATURE_RO (1u<<5)
static int range(uint64_t base,uint64_t size,uint64_t at,uint64_t bytes)
{return size && bytes && at>=base && at-base<size && bytes<=size-(at-base);}
static int config_valid(const w98_persist_config_t *c,uint64_t bytes)
{
    unsigned i,j,mem=0;
    if(!c || bytes!=sizeof *c || c->magic!=W98_PERSIST_CONFIG_MAGIC || c->version!=1 || c->reserved16 || c->reserved32 || c->reserved64 || c->vendor!=0x1af4 || (c->device!=0x1042 && c->device!=0x1001) || c->esp_bytes!=(uint64_t)W98_PERSIST_ESP_SECTORS*512 || c->member_bytes!=(2ull<<30) || c->volume_id!=W98_PERSIST_VOLUME_ID)return 0;
    for(i=0;i<6;i++){
        const w98_persist_bar_t *b=&c->bar[i];
        if(b->reserved || b->kind>W98_PERSIST_BAR_IO)return 0;
        if(!b->kind){if(b->base || b->bytes)return 0;continue;}
        if(!b->bytes || (b->bytes&(b->bytes-1)) || !b->base || b->base&(b->bytes-1) || b->base>UINT64_MAX-b->bytes)return 0;
        if(b->kind==W98_PERSIST_BAR_IO){if(b->base+b->bytes>65536)return 0;}
        else {if(b->bytes<16 || b->base+b->bytes>(64ull<<30))return 0;++mem;}
        if(b->kind==W98_PERSIST_BAR_MEM32 && b->base+b->bytes>(1ull<<32))return 0;
        if(b->kind==W98_PERSIST_BAR_MEM64 && (i==5 || c->bar[i+1].kind || c->bar[i+1].base || c->bar[i+1].bytes || c->bar[i+1].reserved))return 0;
        for(j=0;j<i;j++)if(c->bar[j].kind && (c->bar[j].kind==W98_PERSIST_BAR_IO)==(b->kind==W98_PERSIST_BAR_IO) && b->base<c->bar[j].base+c->bar[j].bytes && c->bar[j].base<b->base+b->bytes)return 0;
    }
    return mem!=0;
}
static int pr(w98_vblk_t *v,unsigned off,uint32_t *out)
{return v->io.pci_read(v->io.opaque,v->config.bdf,off,out);}
static int pw(w98_vblk_t *v,unsigned off,uint32_t value)
{return v->io.pci_write(v->io.opaque,v->config.bdf,off,value);}
static int command(w98_vblk_t *v,uint32_t value)
{uint32_t actual;value&=0xffffu;return pw(v,4,value) || pr(v,4,&actual) || (actual&0xffffu)!=value?-1:0;}
static int mr(w98_vblk_t *v,uint64_t address,unsigned bytes,uint64_t *out)
{return v->io.mmio_read(v->io.opaque,address,bytes,out);}
static int mw(w98_vblk_t *v,uint64_t address,unsigned bytes,uint64_t value)
{return v->io.mmio_write(v->io.opaque,address,bytes,value);}
static int read64(w98_vblk_t *v,uint64_t address,uint64_t *out)
{uint64_t lo,hi;if(mr(v,address,4,&lo) || mr(v,address+4,4,&hi))return -1;*out=(uint32_t)lo|hi<<32;return 0;}
static int write64(w98_vblk_t *v,uint64_t address,uint64_t value)
{return mw(v,address,4,(uint32_t)value) || mw(v,address+4,4,value>>32)?-1:0;}
static uint64_t deadline(w98_vblk_t *v,unsigned seconds)
{uint64_t now=v->io.ticks(v->io.opaque),span=v->io.ticks_per_second*seconds;return now>UINT64_MAX-span?0:now+span;}
static int expired(w98_vblk_t *v,uint64_t end)
{uint64_t now=v->io.ticks(v->io.opaque);return !end || now>=end || (!v->sealed && now>=v->admission_deadline);}
static int disable_dma(w98_vblk_t *v)
{uint32_t cmd;v->memory_decoded=0;if(pr(v,4,&cmd) || command(v,((cmd&0xffffu)&~4u)|1024u))return -1;v->memory_decoded=(cmd&2)!=0;return 0;}
static int reset(w98_vblk_t *v)
{
    unsigned n;uint64_t state,end=deadline(v,2);int rc=disable_dma(v);
    v->ready=0;v->reset_acknowledged=0;
    if(rc || !v->common || !v->registers_admitted || !v->memory_decoded || mw(v,v->common+20,1,0))return -1;
    /* Cleanup has its own finite reset bound even after admission expires. */
    for(n=0;n<POLLS;n++){
        if(!end || v->io.ticks(v->io.opaque)>=end || mr(v,v->common+20,1,&state) || v->io.ticks(v->io.opaque)>=end)return -1;
        if(!state){v->reset_acknowledged=1;return rc?-1:0;}
        v->io.pause(v->io.opaque);
    }
    return -1;
}
static int fail(w98_vblk_t *v)
{v->failed=1;(void)reset(v);return -1;}
static int probe_bars(w98_vblk_t *v)
{
    unsigned i;uint32_t original,hi,mask,mhi;uint64_t base,bytes,bits;unsigned kind;
    for(i=0;i<6;i++){
        const w98_persist_bar_t *expected=&v->config.bar[i];
        if(pr(v,16+i*4,&original))return -1;
        kind=(original&1)?W98_PERSIST_BAR_IO:((original&6)==4?W98_PERSIST_BAR_MEM64:W98_PERSIST_BAR_MEM32);
        if(!(original&1) && (original&6)!=0 && (original&6)!=4)return -1;
        hi=0;mhi=0;
        if(kind==W98_PERSIST_BAR_MEM64 && (i==5 || pr(v,20+i*4,&hi)))return -1;
        if(pw(v,16+i*4,0xffffffffu))return -1;
        if(kind==W98_PERSIST_BAR_MEM64 && pw(v,20+i*4,0xffffffffu)){(void)pw(v,16+i*4,original);return -1;}
        /* Restore every saved BAR even when the mask read fails. */
        {int rc=pr(v,16+i*4,&mask);if(kind==W98_PERSIST_BAR_MEM64)rc|=pr(v,20+i*4,&mhi);rc|=pw(v,16+i*4,original);if(kind==W98_PERSIST_BAR_MEM64)rc|=pw(v,20+i*4,hi);if(rc)return -1;}
        if(kind==W98_PERSIST_BAR_IO){bits=mask&~3u;base=original&~3u;bytes=bits?(uint32_t)(~(uint32_t)bits+1):0;}
        else if(kind==W98_PERSIST_BAR_MEM64){bits=(uint64_t)mhi<<32|(mask&~15u);base=(uint64_t)hi<<32|(original&~15u);bytes=bits?~bits+1:0;}
        else {bits=mask&~15u;base=original&~15u;bytes=bits?(uint32_t)(~(uint32_t)bits+1):0;}
        if(!bytes){if(original || hi || expected->kind || expected->base || expected->bytes)return -1;}
        else if(expected->kind!=kind || expected->base!=base || expected->bytes!=bytes)return -1;
        if(kind==W98_PERSIST_BAR_MEM64)++i;
    }
    return 0;
}
static int capabilities(w98_vblk_t *v)
{
    uint32_t raw,next,off,len,bar,header;uint8_t seen[64]={0};unsigned count=0,found=0;
    uint64_t start[5]={0},extent[5]={0};
    if(pr(v,0x34,&raw))return -1;
    next=raw&255;
    while(next){
        uint64_t address;unsigned type;
        if(next<0x40 || next>0xfc || (next&3) || seen[next/4] || ++count>48 || pr(v,next,&header))return -1;
        seen[next/4]=1;
        if((header&255)==9){
            type=header>>24;len=(header>>16)&255;
            if(len<16 || len>256-next || pr(v,next+4,&raw) || pr(v,next+8,&off) || pr(v,next+12,&len))return -1;
            bar=raw&255;
            if(type>=1 && type<=4){
                const w98_persist_bar_t *b;unsigned other;
                if(bar>=6 || (found&(1u<<type)))return -1;
                b=&v->config.bar[bar];
                if((b->kind!=W98_PERSIST_BAR_MEM32 && b->kind!=W98_PERSIST_BAR_MEM64) || !range(0,b->bytes,off,len) || !v->io.mmio_allowed(v->io.opaque,b->base+off,len))return -1;
                address=b->base+off;
                for(other=1;other<=4;other++)if(extent[other] && address<start[other]+extent[other] && start[other]<address+len)return -1;
                start[type]=address;extent[type]=len;found|=1u<<type;
                if(type==1){if(len<56 || address&3)return -1;v->common=address;}
                if(type==2){if(((header>>16)&255)<20 || len<2 || pr(v,next+16,&raw))return -1;v->notify=address;v->notify_bytes=len;v->notify_multiplier=raw;}
                if(type==3){if(len<1)return -1;v->isr=address;}
                if(type==4){if(len<24 || address&3)return -1;v->device_config=address;}
            }
        }
        next=(header>>8)&255;
    }
    return found==30?0:-1;
}
static int capacity(w98_vblk_t *v,uint64_t *sectors)
{
    unsigned n;uint64_t before,after,block;
    for(n=0;n<8;n++){
        if(mr(v,v->common+21,1,&before) || read64(v,v->device_config,sectors) || mr(v,v->device_config+20,4,&block) || mr(v,v->common+21,1,&after))return -1;
        if(before==after)return *sectors==W98_PERSIST_ESP_SECTORS && block==512?0:-1;
    }
    return -1;
}
static int status(w98_vblk_t *v,unsigned state)
{uint64_t actual;return mw(v,v->common+20,1,state) || mr(v,v->common+20,1,&actual) || actual!=state?-1:0;}
int w98_vblk_init(w98_vblk_t *v,const w98_persist_config_t *c,uint64_t bytes,const w98_vblk_io_t *io)
{
    uint32_t id,cls,header,cmd;uint64_t low,high,q,size,offset,pa;unsigned i;
    if(!v || v->owned || !config_valid(c,bytes) || !io || !io->pci_read || !io->pci_write || !io->mmio_read || !io->mmio_write || !io->mmio_allowed || !io->dma_address || !io->ticks || !io->pause || !io->ticks_per_second || io->ticks_per_second>1000000000000ull)return -1;
    memset(v,0,sizeof *v);v->io=*io;v->config=*c;v->admission_deadline=deadline(v,10);
    /* Only the bound PCI function may be observed or mutated. */
    if(pr(v,0,&id) || id!=((uint32_t)c->device<<16|c->vendor) || pr(v,8,&cls) || (cls>>8)!=0x010000 || pr(v,12,&header) || (header&0x7f0000) || pr(v,4,&cmd) || !(cmd&(1u<<20)))return -1;
    v->owned=1;v->command_original=cmd&0xffff;
    if(command(v,((cmd&0xffff)&~7u)|1024u) || probe_bars(v) || capabilities(v))return fail(v);
    v->registers_admitted=1;
    if(command(v,((cmd&0xffff)&~5u)|2u|1024u))return fail(v);
    v->memory_decoded=1;
    if(reset(v) || expired(v,v->admission_deadline))return fail(v);
    if(status(v,1) || status(v,3) || mw(v,v->common,4,0) || mr(v,v->common+4,4,&low) || mw(v,v->common,4,1) || mr(v,v->common+4,4,&high))return fail(v);
    /* FLUSH and VERSION_1 are mandatory. BLK_SIZE is negotiated as 512B.
     * Reject RO and do not negotiate indirect/packed/event-index/DMA cache. */
    if(!(high&1) || !(low&FEATURE_FLUSH) || !(low&FEATURE_BLKSIZE) || (low&FEATURE_RO))return fail(v);
    low=FEATURE_FLUSH|FEATURE_BLKSIZE;
    if(mw(v,v->common+8,4,0) || mw(v,v->common+12,4,low) || mw(v,v->common+8,4,1) || mw(v,v->common+12,4,1) || status(v,11) || capacity(v,&v->sectors) || mr(v,v->common+18,2,&q) || !q || mw(v,v->common+22,2,0) || mr(v,v->common+24,2,&size) || mr(v,v->common+28,2,&q) || q || size<W98_VBLK_QUEUE || mw(v,v->common+24,2,W98_VBLK_QUEUE) || mw(v,v->common+26,2,0xffff) || mr(v,v->common+30,2,&offset))return fail(v);
    if(offset && v->notify_multiplier>UINT64_MAX/offset)return fail(v);
    offset*=v->notify_multiplier;
    if(!range(0,v->notify_bytes,offset,2) || (v->notify+offset)&1)return fail(v);
    v->notify_address=v->notify+offset;v->avail.flags=1;
    /* Native DMA validation requires all storage inside the owned Supervisor
     * object/pages. No caller or guest pointer is submitted to the device. */
    if(io->dma_address(io->opaque,v,sizeof *v,&pa))return fail(v);
    for(i=0;i<3;i++){
        const void *p=i==0?(const void *)v->desc:i==1?(const void *)&v->avail:(const void *)&v->used;
        const unsigned n=i==0?sizeof v->desc:i==1?sizeof v->avail:sizeof v->used;
        if(io->dma_address(io->opaque,p,n,&pa) || (pa&(i==0?15:i==1?1:3)) || write64(v,v->common+32+i*8,pa))return fail(v);
    }
    if(mw(v,v->common+28,2,1) || command(v,((cmd&0xffff)&~1u)|6u|1024u) || status(v,15))return fail(v);
    v->ready=1;v->reset_acknowledged=0;return 0;
}
static int member_lba(const w98_vblk_t *v,uint64_t lba)
{unsigned i;for(i=0;i<v->sealed_extents;i++)if(range(v->extent[i].device_lba,v->extent[i].count,lba,1))return 1;return 0;}
static int submit(w98_vblk_t *v,unsigned type,uint64_t lba,const uint8_t *data,uint8_t *out)
{
    uint64_t actual,state,pa,end;uint32_t id;unsigned n;uint16_t index;int rc=-1;
    if(!v || !v->ready || v->failed || (type!=4 && lba>=v->sectors) || (type==1 && (!data || !v->sealed || !member_lba(v,lba))) || (type==0 && !out) || __atomic_exchange_n(&v->busy,1,__ATOMIC_ACQUIRE))return -1;
    end=deadline(v,2);
    if(pr(v,0,&id) || id!=((uint32_t)v->config.device<<16|v->config.vendor) || mr(v,v->common+20,1,&state) || state!=15 || capacity(v,&actual) || actual!=v->sectors || expired(v,end))goto bad;
    index=__atomic_load_n(&v->used.index,__ATOMIC_ACQUIRE);
    if(index!=v->last_used)goto bad;
    v->request.type=type;v->request.reserved=0;v->request.sector=type==4?0:lba;v->status=0xff;
    if(type==1)memcpy(v->data,data,512);
    if(v->io.dma_address(v->io.opaque,&v->request,sizeof v->request,&pa))goto bad;
    v->desc[0]=(w98_vblk_desc_t){pa,16,1,1};
    if(type==4){if(v->io.dma_address(v->io.opaque,&v->status,1,&pa))goto bad;v->desc[1]=(w98_vblk_desc_t){pa,1,2,0};}
    else{
        if(v->io.dma_address(v->io.opaque,v->data,512,&pa))goto bad;
        v->desc[1]=(w98_vblk_desc_t){pa,512,(uint16_t)(type==0?3:1),2};
        if(v->io.dma_address(v->io.opaque,&v->status,1,&pa))goto bad;
        v->desc[2]=(w98_vblk_desc_t){pa,1,2,0};
    }
    v->avail.ring[v->avail.index%W98_VBLK_QUEUE]=0;
    __atomic_thread_fence(__ATOMIC_RELEASE);
    __atomic_store_n(&v->avail.index,(uint16_t)(v->avail.index+1),__ATOMIC_RELEASE);
    if(mw(v,v->notify_address,2,0))goto bad;
    for(n=0;n<POLLS;n++){
        if(expired(v,end))goto bad;
        index=__atomic_load_n(&v->used.index,__ATOMIC_ACQUIRE);
        if(index!=v->last_used)break;
        v->io.pause(v->io.opaque);
    }
    if(n==POLLS || (uint16_t)(index-v->last_used)!=1 || v->used.ring[v->last_used%W98_VBLK_QUEUE].id!=0 || v->used.ring[v->last_used%W98_VBLK_QUEUE].length!=(type==0?513u:1u) || __atomic_load_n(&v->status,__ATOMIC_ACQUIRE) || mr(v,v->common+20,1,&state) || state!=15 || expired(v,end))goto bad;
    v->last_used=index;
    if(type==0)memcpy(out,v->data,512);
    rc=0;goto done;
bad:rc=fail(v);
done:__atomic_store_n(&v->busy,0,__ATOMIC_RELEASE);return rc;
}
static int read_block(void *ctx,uint64_t lba,unsigned count,void *data)
{return count==1?submit(ctx,0,lba,0,data):-1;}
static int write_block(void *ctx,uint64_t lba,unsigned count,const void *data)
{return count==1?submit(ctx,1,lba,data,0):-1;}
static int flush_block(void *ctx)
{w98_vblk_t *v=ctx;return v && v->sealed?submit(v,4,0,0,0):-1;}
int w98_vblk_block(w98_vblk_t *v,w98_owned_block_t *out)
{if(!v || !out || !v->ready || v->failed)return -1;*out=(w98_owned_block_t){v->sectors,v,read_block,write_block,flush_block};return 0;}
int w98_vblk_seal_member(w98_vblk_t *v,const w98_persist_disk_t *m)
{
    unsigned i,j;uint32_t logical=0;
    if(!v || !m || !v->ready || v->failed || v->sealed || m->failed || !m->admitted || !m->extents || m->extents>W98_PERSIST_MAX_EXTENTS || m->block.opaque!=v || m->block.read!=read_block || m->block.write!=write_block || m->block.flush!=flush_block || m->block.sectors!=v->sectors || expired(v,v->admission_deadline))return -1;
    for(i=0;i<m->extents;i++){
        const w98_disk_extent_t *e=&m->extent[i];
        if(e->first!=logical || !e->count || e->count>W98_PERSIST_DISK_SECTORS-logical || !range(0,v->sectors,e->device_lba,e->count))return -1;
        for(j=0;j<i;j++)if(e->device_lba<m->extent[j].device_lba+m->extent[j].count && m->extent[j].device_lba<e->device_lba+e->count)return -1;
        logical+=e->count;
    }
    if(logical!=W98_PERSIST_DISK_SECTORS)return -1;
    memcpy(v->extent,m->extent,m->extents*sizeof m->extent[0]);v->sealed_extents=m->extents;v->sealed=1;return 0;
}
int w98_vblk_close(w98_vblk_t *v)
{int rc;if(!v || !v->owned || __atomic_exchange_n(&v->busy,1,__ATOMIC_ACQUIRE))return -1;rc=reset(v);v->failed=1;__atomic_store_n(&v->busy,0,__ATOMIC_RELEASE);return rc;}
