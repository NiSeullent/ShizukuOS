/* SPDX-License-Identifier: GPL-2.0-only -- original bounded xHCI command path. */
#include "xhci.h"

enum { USBCMD=0, USBSTS=4, PAGESIZE=8, CRCR=24, DCBAAP=48, CONFIG=56,
       IMAN=32, ERSTSZ=40, ERSTBA=48, ERDP=56, HALT_US=16000,
       LEGACY_US=1000000, EVENT_LIMIT=256 };
enum { CMD_RUN=1, CMD_RESET=2, ST_HALT=1, ST_HSE=4, ST_CNR=2048, ST_HCE=4096 };
struct deadline { uint64_t start,last; uint32_t polls; };
static void zero(void *p,size_t n)
{ uint8_t *b=p;while(n--) *b++=0; }
static void copy(void *out,const void *in,size_t n)
{ uint8_t *d=out;const uint8_t *s=in;while(n--) *d++=*s++; }
static uint32_t get32(const void *address)
{
    const volatile uint8_t *p=address;
    return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24);
}
static void put32(void *address,uint32_t value)
{
    volatile uint8_t *p=address;
    p[0]=(uint8_t)value;p[1]=(uint8_t)(value>>8);
    p[2]=(uint8_t)(value>>16);p[3]=(uint8_t)(value>>24);
}
static void put64(void *p,uint64_t value)
{ put32(p,(uint32_t)value);put32((uint8_t *)p+4,(uint32_t)(value>>32)); }
static int range(const struct xhci_device *x,uint32_t offset,uint32_t bytes)
{ return offset<=x->mmio_bytes && bytes<=x->mmio_bytes-offset; }
static int rd(struct xhci_device *x,uint32_t offset,uint32_t *value)
{
    if ((offset&3u) || !range(x,offset,4)) return XHCI_INVALID;
    return x->ops.read32(x->ops.context,offset,value)?XHCI_OK:XHCI_IO;
}
static int wr(struct xhci_device *x,uint32_t offset,uint32_t value)
{
    if ((offset&3u) || !range(x,offset,4)) return XHCI_INVALID;
    return x->ops.write32(x->ops.context,offset,value)?XHCI_OK:XHCI_IO;
}
static int address_reg(struct xhci_device *x,uint32_t offset,uint64_t value)
{
    int result=wr(x,offset,(uint32_t)value);
    if (result || !(x->hccparams1&1u)) return result;
    /* i486 cannot issue a Qword MMIO write; xHCI defines low then high. */
    return wr(x,offset+4,(uint32_t)(value>>32));
}
static int sync_area(struct xhci_device *x,size_t offset,size_t bytes,int to_device)
{ return x->ops.sync(x->ops.context,&x->dma,offset,bytes,to_device)?XHCI_OK:XHCI_IO; }
static void begin(struct xhci_device *x,struct deadline *d)
{ d->start=x->ops.now_us(x->ops.context);d->last=d->start;d->polls=0; }
static int expired(struct xhci_device *x,struct deadline *d,uint32_t timeout)
{
    uint64_t now=x->ops.now_us(x->ops.context);
    if(now<d->last) return XHCI_CLOCK;
    d->last=now;
    if(now-d->start>=timeout || ++d->polls>=XHCI_POLL_LIMIT) return XHCI_TIMEOUT;
    x->ops.relax(x->ops.context);return XHCI_OK;
}
static int wait_bits(struct xhci_device *x,uint32_t offset,uint32_t mask,uint32_t expected,uint32_t us)
{
    struct deadline d;uint32_t value;int result;begin(x,&d);
    for(;;) {
        if((result=rd(x,offset,&value))!=0) return result;
        if((value&mask)==expected) return XHCI_OK;
        if((result=expired(x,&d,us))!=0) return result;
    }
}
static int halt_reset(struct xhci_device *x)
{
    uint32_t value;int result;
    if((result=wait_bits(x,x->op_base+USBSTS,ST_CNR,0,x->timeout_us))!=0 ||
       (result=rd(x,x->op_base+USBCMD,&value))!=0) return result;
    if(value&CMD_RESET) return XHCI_CONTROLLER_ERROR;
    /* Preserve reserved/configuration fields while clearing running/interrupts.
     * Reject inherited state-save/restore requests instead of replaying them. */
    if(value&0x380u) return XHCI_UNSUPPORTED;
    if((result=wr(x,x->op_base+USBCMD,value&~0xdu))!=0 ||
       (result=wait_bits(x,x->op_base+USBSTS,ST_HALT,ST_HALT,HALT_US))!=0 ||
       (result=wr(x,x->op_base+USBCMD,(value&~0xdu)|CMD_RESET))!=0 ||
       (result=wait_bits(x,x->op_base+USBCMD,CMD_RESET,0,x->timeout_us))!=0 ||
       (result=wait_bits(x,x->op_base+USBSTS,ST_CNR|ST_HALT,ST_HALT,x->timeout_us))!=0)
        return result;
    return XHCI_OK;
}
static int legacy_byte(struct xhci_device *x,int owned)
{
    uint32_t value;int result=rd(x,x->legacy_base,&value);
    uint8_t byte;
    if(result) return result;
    byte=(uint8_t)(value>>24);
    byte=owned?(uint8_t)(byte|1u):(uint8_t)(byte&0xfeu);
    return x->ops.write8(x->ops.context,x->legacy_base+3,byte)?XHCI_OK:XHCI_IO;
}
static int legacy_handoff(struct xhci_device *x)
{
    uint32_t offset=(x->hccparams1>>16)*4u,header,next,count=0,legacy=0,value;
    int result;
    /* Relative positive DWORD links cannot cycle without wrapping or moving
     * backwards. Range/overflow and a fixed traversal bound reject both. */
    while(offset) {
        if(++count>256 || offset<0x20 || (result=rd(x,offset,&header))!=0)
            return count>256 || offset<0x20?XHCI_INVALID:result;
        if(!(header&255u)) return XHCI_INVALID;
        if((header&255u)==1) {
            if(legacy || !range(x,offset,8) ||
               (offset>=x->op_base && offset-x->op_base<0x400u+x->max_ports*16u) ||
               (offset<x->op_base && x->op_base-offset<8u) ||
               (offset>=x->runtime_base && offset-x->runtime_base<32u+x->max_interrupters*32u) ||
               (offset<x->runtime_base && x->runtime_base-offset<8u) ||
               (offset>=x->doorbell_base && offset-x->doorbell_base<(x->max_slots+1u)*4u) ||
               (offset<x->doorbell_base && x->doorbell_base-offset<8u)) return XHCI_INVALID;
            legacy=offset;
        }
        next=((header>>8)&255u)*4u;
        if(!next) break;
        if(offset>UINT32_MAX-next) return XHCI_INVALID;
        if(legacy==offset && next<8) return XHCI_INVALID;
        offset+=next;
    }
    if(!legacy) return XHCI_OK;
    if(!x->ops.write8) return XHCI_UNSUPPORTED;
    x->legacy_base=legacy;x->legacy_owned=1; /* write failure can have side effects */
    if((result=legacy_byte(x,1))!=0 ||
       (result=wait_bits(x,legacy,0x01010000u,0x01000000u,LEGACY_US))!=0 ||
       (result=rd(x,legacy+4,&value))!=0) return result;
    /* Preserve RsvdP, disable known SMI enables; no RW1C status is echoed. */
    value&=0x000e1feeu;
    return wr(x,legacy+4,value);
}
int xhci_close(struct xhci_device *x)
{
    int result;
    if(!x) return XHCI_INVALID;
    if(x->state==XHCI_EMPTY || x->state==XHCI_CLOSED) return XHCI_OK;
    if(x->state!=XHCI_STARTING && x->state!=XHCI_READY && x->state!=XHCI_RETAINED)
        return XHCI_INVALID;
    if(x->dma_published) {
        if((result=halt_reset(x))!=0) {
            x->last_error=result;x->state=XHCI_RETAINED;return XHCI_QUARANTINED;
        }
        /* Reset terminates DMA and clears hardware ring state. Explicitly
         * detach all addresses as well; ambiguous writes retain the memory. */
        if((result=address_reg(x,x->op_base+CRCR,0))!=0 ||
           (result=address_reg(x,x->op_base+DCBAAP,0))!=0 ||
           (result=wr(x,x->runtime_base+ERSTSZ,0))!=0 ||
           (result=address_reg(x,x->runtime_base+ERSTBA,0))!=0 ||
           (result=address_reg(x,x->runtime_base+ERDP,0))!=0) {
            x->last_error=result;x->state=XHCI_RETAINED;return XHCI_QUARANTINED;
        }
        x->dma_published=0;
    }
    if(x->dma_owned) {
        x->ops.release(x->ops.context,&x->dma);x->dma_owned=0;zero(&x->dma,sizeof(x->dma));
    }
    if(x->legacy_owned) {
        if((result=legacy_byte(x,0))!=0) {
            x->last_error=result;x->state=XHCI_RETAINED;return XHCI_QUARANTINED;
        }
        x->legacy_owned=0;
    }
    x->state=XHCI_CLOSED;return XHCI_OK;
}
static int fail(struct xhci_device *x,int error)
{
    int result=xhci_close(x);
    if(result==XHCI_QUARANTINED) return result;
    x->last_error=error;return error;
}
static int overlap(uint32_t a,uint32_t an,uint32_t b,uint32_t bn)
{ return a<=b?b-a<an:a-b<bn; }
int xhci_open(struct xhci_device *x,const struct xhci_ops *ops,const struct xhci_config *cfg)
{
    struct xhci_ops callbacks;struct xhci_config config;
    uint32_t first,hcs1,hcs2,db,rt,pages,op_bytes,rt_bytes,db_bytes;
    uint64_t limit;uint8_t *memory;int result;
    if(!x || !ops || !cfg || (x->state!=XHCI_EMPTY && x->state!=XHCI_CLOSED) ||
       !ops->read32 || !ops->write32 || !ops->allocate || !ops->release || !ops->sync ||
       !ops->now_us || !ops->relax || cfg->pci_class!=0x0c0330 || (cfg->pci_command&6u)!=6u ||
       cfg->exclusive!=1 || cfg->mmio_bytes<0x400 || !cfg->timeout_us || cfg->timeout_us>30000000)
        return XHCI_INVALID;
    copy(&callbacks,ops,sizeof(callbacks));copy(&config,cfg,sizeof(config));
    zero(x,sizeof(*x));copy(&x->ops,&callbacks,sizeof(callbacks));
    x->mmio_bytes=config.mmio_bytes;x->timeout_us=config.timeout_us;x->state=XHCI_STARTING;
    if((result=rd(x,0,&first))!=0 || (result=rd(x,4,&hcs1))!=0 ||
       (result=rd(x,8,&hcs2))!=0 || (result=rd(x,16,&x->hccparams1))!=0 ||
       (result=rd(x,20,&db))!=0 || (result=rd(x,24,&rt))!=0) return fail(x,result);
    x->op_base=first&255u;x->version=first>>16;
    x->max_slots=hcs1&255u;x->max_ports=hcs1>>24;x->max_interrupters=(hcs1>>8)&2047u;
    x->scratchpads=((hcs2>>27)&31u)|((hcs2>>16)&0x3e0u);
    x->doorbell_base=db&~3u;x->runtime_base=rt&~31u;
    if((x->version!=0x100 && x->version!=0x110 && x->version!=0x120) ||
       x->scratchpads || !x->max_slots || !x->max_ports || !x->max_interrupters ||
       x->max_interrupters>1024 || x->hccparams1==UINT32_MAX) return fail(x,XHCI_UNSUPPORTED);
    op_bytes=0x400u+x->max_ports*16u;rt_bytes=32u+x->max_interrupters*32u;
    db_bytes=(x->max_slots+1u)*4u;
    if(x->op_base<0x20 || (x->op_base&3u) || db!=x->doorbell_base || rt!=x->runtime_base ||
       !range(x,x->op_base,op_bytes) || !range(x,rt,rt_bytes) || !range(x,db,db_bytes) ||
       rt<x->op_base || db<x->op_base || overlap(x->op_base,op_bytes,rt,rt_bytes) ||
       overlap(x->op_base,op_bytes,db,db_bytes) || overlap(rt,rt_bytes,db,db_bytes))
        return fail(x,XHCI_INVALID);
    if((result=rd(x,x->op_base+PAGESIZE,&pages))!=0) return fail(x,result);
    if(!(pages&1u)) return fail(x,XHCI_UNSUPPORTED);
    if((result=legacy_handoff(x))!=0 || (result=halt_reset(x))!=0) return fail(x,result);
    limit=(x->hccparams1&1u)?UINT64_MAX:UINT32_MAX;
    if(!x->ops.allocate(x->ops.context,XHCI_DMA_BYTES,4096,limit,&x->dma)) return fail(x,XHCI_NO_MEMORY);
    x->dma_owned=1;
    if(!x->dma.cpu || ((uintptr_t)x->dma.cpu&4095u) || (x->dma.bus&4095u) ||
       x->dma.bytes<XHCI_DMA_BYTES || x->dma.bus>limit-(XHCI_DMA_BYTES-1u) ||
       (uintptr_t)x->dma.cpu>UINTPTR_MAX-(XHCI_DMA_BYTES-1u)) return fail(x,XHCI_INVALID);
    memory=x->dma.cpu;zero(memory,XHCI_DMA_BYTES);
    put64(memory+XHCI_ERST_OFFSET,x->dma.bus+XHCI_EVENT_OFFSET);
    put32(memory+XHCI_ERST_OFFSET+8,XHCI_EVENT_TRBS);
    x->command_cycle=1;x->event_cycle=1;
    if((result=sync_area(x,0,XHCI_DMA_BYTES,1))!=0) return fail(x,result);
    x->dma_published=1;
    if((result=address_reg(x,x->op_base+DCBAAP,x->dma.bus))!=0 ||
       (result=address_reg(x,x->op_base+CRCR,(x->dma.bus+XHCI_COMMAND_OFFSET)|1u))!=0 ||
       (result=wr(x,x->op_base+CONFIG,0))!=0 ||
       (result=wr(x,x->runtime_base+IMAN,1))!=0 || /* clear IP, IE remains zero */
       (result=wr(x,x->runtime_base+ERSTSZ,1))!=0 ||
       (result=address_reg(x,x->runtime_base+ERDP,x->dma.bus+XHCI_EVENT_OFFSET))!=0 ||
       (result=address_reg(x,x->runtime_base+ERSTBA,x->dma.bus+XHCI_ERST_OFFSET))!=0 ||
       (result=wr(x,x->op_base+USBCMD,CMD_RUN))!=0 ||
       (result=wait_bits(x,x->op_base+USBSTS,ST_HALT,0,x->timeout_us))!=0)
        return fail(x,result);
    if((result=rd(x,x->op_base+USBSTS,&x->last_status))!=0) return fail(x,result);
    if(x->last_status&(ST_HSE|ST_HCE|ST_CNR)) return fail(x,XHCI_CONTROLLER_ERROR);
    x->state=XHCI_READY;return XHCI_OK;
}
static int publish(struct xhci_device *x,uint32_t offset,uint32_t type,uint64_t address,uint32_t cycle)
{
    uint8_t *trb=(uint8_t *)x->dma.cpu+offset;int result;
    /* Keep ownership invalid until the payload is visible, including PCS=0. */
    put32(trb+12,(type<<10)|(cycle^1u));put64(trb,address);put32(trb+8,0);
    if((result=sync_area(x,offset,16,1))!=0) return result;
    put32(trb+12,(type<<10)|cycle|(type==6?2u:0u));
    return sync_area(x,offset+12,4,1);
}
int xhci_noop(struct xhci_device *x)
{
    uint32_t offset,control,type,status,lo,hi,seen=0,consumed;
    uint64_t submitted,pointer;uint8_t *event;struct deadline d;int result;
    if(!x || x->state!=XHCI_READY) return XHCI_INVALID;
    if(x->command_index>=XHCI_COMMAND_TRBS-1 || x->event_index>=XHCI_EVENT_TRBS ||
       x->command_cycle>1 || x->event_cycle>1) return fail(x,XHCI_INVALID);
    if((result=rd(x,x->op_base+USBSTS,&x->last_status))!=0) return fail(x,result);
    if(x->last_status&(ST_HALT|ST_HSE|ST_HCE|ST_CNR)) return fail(x,XHCI_CONTROLLER_ERROR);
    offset=XHCI_COMMAND_OFFSET+x->command_index*16u;submitted=x->dma.bus+offset;
    if(x->command_index==XHCI_COMMAND_TRBS-2 &&
       (result=publish(x,XHCI_COMMAND_OFFSET+(XHCI_COMMAND_TRBS-1u)*16u,6,
                       x->dma.bus+XHCI_COMMAND_OFFSET,x->command_cycle))!=0) return fail(x,result);
    if((result=publish(x,offset,23,0,x->command_cycle))!=0 ||
       (result=wr(x,x->doorbell_base,0))!=0) return fail(x,result);
    begin(x,&d);
    for(;;) {
        if((result=rd(x,x->op_base+USBSTS,&x->last_status))!=0) return fail(x,result);
        if(x->last_status&(ST_HALT|ST_HSE|ST_HCE|ST_CNR)) return fail(x,XHCI_CONTROLLER_ERROR);
        offset=XHCI_EVENT_OFFSET+x->event_index*16u;event=(uint8_t *)x->dma.cpu+offset;
        if((result=sync_area(x,offset,16,0))!=0) return fail(x,result);
        control=get32(event+12);
        if((control&1u)!=x->event_cycle) {
            if((result=expired(x,&d,x->timeout_us))!=0) return fail(x,result);
            continue;
        }
        /* Acquire after observing ownership; a producer writes the cycle last. */
        if((result=sync_area(x,offset,16,0))!=0) return fail(x,result);
        if(control!=get32(event+12)) return fail(x,XHCI_BAD_EVENT);
        lo=get32(event);hi=get32(event+4);status=get32(event+8);type=(control>>10)&63u;
        if(control&~UINT32_C(0xfc01)) return fail(x,XHCI_BAD_EVENT);
        if(type==33) {
            pointer=(uint64_t)lo|((uint64_t)hi<<32);
            x->last_completion_pointer=pointer;x->last_completion_code=status>>24;
            if(pointer!=submitted || (status&0xffffffu)) return fail(x,XHCI_BAD_EVENT);
            if(x->last_completion_code!=1) return fail(x,XHCI_COMPLETION_ERROR);
        } else if(type==34) {
            uint32_t port=lo>>24;
            if(!port || port>x->max_ports || (lo&0xffffffu) || hi || status!=0x01000000u)
                return fail(x,XHCI_BAD_EVENT);
            ++x->port_events;
            if(++seen>EVENT_LIMIT) return fail(x,XHCI_EVENT_LIMIT);
        } else return fail(x,XHCI_BAD_EVENT);
        consumed=offset;
        if(++x->event_index==XHCI_EVENT_TRBS) { x->event_index=0;x->event_cycle^=1; }
        /* ERDP names the last evaluated event; DESI=0, EHB is RW1C. */
        if((result=address_reg(x,x->runtime_base+ERDP,(x->dma.bus+consumed)|8u))!=0)
            return fail(x,result);
        if(type==33) break;
        if((result=expired(x,&d,x->timeout_us))!=0) return fail(x,result);
    }
    if((result=rd(x,x->op_base+USBSTS,&x->last_status))!=0) return fail(x,result);
    if(x->last_status&(ST_HALT|ST_HSE|ST_HCE|ST_CNR)) return fail(x,XHCI_CONTROLLER_ERROR);
    if(++x->command_index==XHCI_COMMAND_TRBS-1) { x->command_index=0;x->command_cycle^=1; }
    ++x->commands_completed;return XHCI_OK;
}
