/* SPDX-License-Identifier: GPL-2.0-only
 * Original independent asynchronous USB2/xHC model. No hardware/VM access.
 * Drafted from the public interface and Intel xHCI1.2b/USB2 interface facts,
 * without reading the new EP0 implementation. CPU/device DMA shadows ensure
 * that completion and publication depend on explicit synchronization.
 */
#include "xhci_usb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checks, scenarios, injected;
#define CHECK(v) do { ++checks; if(!(v)) { \
    fprintf(stderr,"scenario %u line %u: %s\n",scenarios,(unsigned)__LINE__,#v); \
    exit(1); } } while(0)
enum { OP=0x40, RT=0x1000, DB=0x2000, LEG=0x3000, PROTO=0x3040,
       PORT=OP+0x400, DEVICE_BYTES=12288 };
enum { CCS=1, PED=2, OCA=8, PR=16, PP=512, CSC=1<<17, PRC=1<<21 };
#define CHANGE UINT32_C(0x00fe0000)
#define PRESERVE UINT32_C(0x0e00c200)
enum bad_transfer { GOOD=0, SHORT_DATA, SHORT_ZERO, WRONG_POINTER, WRONG_SLOT,
    WRONG_ENDPOINT, EVENT_DATA, MISALIGNED, RESIDUE_TOO_LARGE, STATUS_RESIDUE,
    SETUP_ERROR, DATA_ERROR, STATUS_ERROR, SETUP_SUCCESS, DATA_SUCCESS,
    STATUS_SHORT, DUPLICATE_SHORT, RESERVED_CONTROL, OLD_POINTER,
    NO_STATUS, DESCRIPTOR_MISMATCH, DESCRIPTOR_INVALID, DMA_OVERRUN };
struct block {
    uint8_t *cpu,*device;
    size_t bytes;
    uint64_t bus;
    struct xhci_dma handed;
    unsigned owned;
};
struct model {
    uint32_t regs[0x4000/4],observed_port[4];
    struct block blocks[2];
    uint64_t clock,cmd_cursor,ep_cursor,reset_due,reset_done,address_done;
    uint64_t pending_cmd,old_transfer,transfer_setup,transfer_data,transfer_status;
    unsigned calls,fault,fail_after,allocations,releases,command_cycle,ep_cycle;
    unsigned event_index,event_cycle,command_pending,transfer_pending,port_pending;
    unsigned commands,enables,addresses,evaluates,disables,transfers,cmd_wraps,events;
    unsigned speed,packet,stride,slot_type,slot_enabled,addressed,current_packet;
    unsigned mode,mode_transfer,bad_command,context_error,never_complete;
    unsigned freeze,backwards,halt_stuck,reset_stuck,port_stuck,malformed_dma;
    unsigned disconnect_transfer,change_speed,bad_port_event,port_flood,reset_count;
    unsigned output_poison,extra_events,allocation_fault,was_running,psceg,released_dcbaa_zero;
    uint64_t hidden_bounce_due;
    unsigned hidden_bounce_seen;
    uint8_t descriptor[18];
};
static uint32_t u32(const uint8_t *p)
{ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t u64(const uint8_t *p)
{ return (uint64_t)u32(p)|((uint64_t)u32(p+4)<<32); }
static void w32(uint8_t *p,uint32_t n)
{ p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);p[2]=(uint8_t)(n>>16);p[3]=(uint8_t)(n>>24); }
static void w64(uint8_t *p,uint64_t n)
{ w32(p,(uint32_t)n);w32(p+4,(uint32_t)(n>>32)); }
static uint64_t r64(const struct model *m,unsigned a)
{ return (uint64_t)m->regs[a/4]|((uint64_t)m->regs[a/4+1]<<32); }
static int fault(struct model *m) { return ++m->calls==m->fault; }
static uint8_t *dma(struct model *m,uint64_t bus,size_t bytes)
{
    unsigned i;
    for(i=0;i<2;++i) {
        struct block *b=&m->blocks[i];
        if(b->owned && bus>=b->bus && bus-b->bus<=b->bytes &&
           bytes<=b->bytes-(size_t)(bus-b->bus))return b->device+(size_t)(bus-b->bus);
    }
    CHECK(0);return NULL;
}
static void hardware_reset(struct model *m)
{
    unsigned i;
    for(i=0;i<0x40/4;++i)m->regs[OP/4+i]=m->regs[RT/4+i]=0;
    m->regs[(OP+4)/4]=1;m->regs[(OP+8)/4]=1;
    m->command_pending=m->transfer_pending=m->port_pending=0;
    m->psceg=0;
    for(i=0;i<4;++i)m->regs[(PORT+i*16u)/4]&=~CHANGE;
    m->cmd_cursor=m->ep_cursor=0;m->command_cycle=m->ep_cycle=1;
    m->event_index=0;m->event_cycle=1;m->slot_enabled=m->addressed=0;
}
static void emit(struct model *m,uint64_t pointer,uint32_t status,uint32_t ctl)
{
    uint8_t *erst=dma(m,r64(m,RT+48),16);
    uint64_t address=u64(erst)+(uint64_t)m->event_index*16u;
    uint8_t *p=dma(m,address,16);
    CHECK(u32(erst+8)==64 && u32(erst+12)==0);
    w64(p,pointer);w32(p+8,status);w32(p+12,ctl|m->event_cycle);
    if(++m->event_index==64){m->event_index=0;m->event_cycle^=1;}
    ++m->events;
}
static void check_zero(const uint8_t *p,size_t bytes)
{ size_t i;for(i=0;i<bytes;++i)CHECK(p[i]==0); }
static void context_command(struct model *m,const uint8_t *trb,unsigned kind)
{
    uint64_t input=u64(trb),output=u64(dma(m,r64(m,OP+48)+8,8));
    uint8_t *in=dma(m,input,33u*m->stride),*out=dma(m,output,32u*m->stride);
    uint8_t *slot=in+m->stride,*ep=in+2u*m->stride;
    CHECK(input==m->blocks[1].bus+4096 && output==m->blocks[1].bus);
    CHECK(u32(in)==0 && u32(in+4)==(kind==11?3u:2u));
    check_zero(in+8,m->stride-8u);
    if(kind==11) {
        CHECK(m->slot_enabled && !m->addressed && m->reset_done);
        CHECK(m->clock-m->reset_done>=10000);
        CHECK(u32(slot)==((1u<<27)|(m->speed<<20)));
        CHECK(u32(slot+4)==(1u<<16) && u32(slot+8)==0 && u32(slot+12)==0);
        check_zero(slot+16,m->stride-16u);
        CHECK(u32(ep)==0);
        CHECK(u32(ep+4)==(((m->speed==3?64u:8u)<<16)|(4u<<3)|(3u<<1)));
        CHECK(u64(ep+8)==((m->blocks[1].bus+8192)|1u));
        CHECK(u32(ep+16)==8);check_zero(ep+20,m->stride-20u);
        memcpy(out,slot,m->stride);memcpy(out+m->stride,ep,m->stride);
        w32(out+12,(2u<<27)|7u);w32(out+m->stride,1);
        m->ep_cursor=u64(ep+8)&~UINT64_C(15);m->ep_cycle=1;
        m->current_packet=m->speed==3?64u:8u;m->addressed=1;m->address_done=m->clock;
        /* Output dequeue is undefined while Running; do not reward readers
         * which mistake a stale output pointer for transfer progress. */
        if(m->output_poison)w64(out+m->stride+8,UINT64_C(0xfeed12345000));
        if(m->context_error==1)w32(out+12,0);
        if(m->context_error==2)w32(out+m->stride,2);
        ++m->addresses;
    } else {
        CHECK(m->addressed && m->transfers==1 && m->speed==1);
        CHECK((u32(ep+4)>>16)==m->packet);
        m->current_packet=m->packet;
        w32(out+m->stride+4,(u32(out+m->stride+4)&65535u)|(m->packet<<16));
        ++m->evaluates;
    }
}
static void execute_command(struct model *m)
{
    uint8_t *trb=dma(m,m->pending_cmd,16);uint32_t ctl=u32(trb+12);
    unsigned kind=(ctl>>10)&63u,slot=0;uint64_t pointer=m->pending_cmd;
    uint32_t result=1u<<24;
    CHECK((ctl&1u)==m->command_cycle && u32(trb+8)==0);
    if(kind==9) {
        CHECK(ctl==((9u<<10)|(m->slot_type<<16)|m->command_cycle));
        CHECK(u64(trb)==0 && m->regs[(OP+56)/4]==1 && !m->slot_enabled);
        slot=1;m->slot_enabled=1;++m->enables;
    } else if(kind==11 || kind==13) {
        CHECK(ctl==((kind<<10)|(1u<<24)|m->command_cycle));slot=1;
        context_command(m,trb,kind);
    } else if(kind==10) {
        uint8_t *out=dma(m,m->blocks[1].bus,2u*m->stride);
        CHECK(ctl==((10u<<10)|(1u<<24)|m->command_cycle));
        CHECK(u64(trb)==0 && m->slot_enabled && !m->transfer_pending);slot=1;
        /* Disable invalidates the live USB address. The pre-disable snapshot,
         * not this deliberately poisoned address, must establish identity. */
        w32(out+12,0xee);w32(out+m->stride,0);
        m->slot_enabled=m->addressed=0;++m->disables;
    } else {
        CHECK(kind==23 && ctl==((23u<<10)|m->command_cycle) && u64(trb)==0);
    }
    if(m->bad_command==1)pointer+=16;
    if(m->bad_command==2)pointer|=1;
    if(m->bad_command==3)slot=2;
    if(m->bad_command==4)result=5u<<24;
    if(m->bad_command==5)result|=1;
    emit(m,pointer,result,(33u<<10)|(slot<<24));
    m->command_pending=0;++m->commands;m->cmd_cursor+=16;
    if(((u32(dma(m,m->cmd_cursor,16)+12)>>10)&63u)==6) {
        trb=dma(m,m->cmd_cursor,16);
        CHECK((u32(trb+12)&1u)==m->command_cycle && (u32(trb+12)&2u));
        CHECK(u32(trb+8)==0);m->cmd_cursor=u64(trb);m->command_cycle^=1;++m->cmd_wraps;
    }
}
static void transfer_step(struct model *m)
{
    unsigned mode=m->transfers==m->mode_transfer?m->mode:GOOD;
    uint64_t pointer=m->transfer_status;uint32_t cc=1,residue=0,ctl=(32u<<10)|(1u<<16)|(1u<<24);
    if(m->transfer_pending==1) {
        uint8_t *data=dma(m,m->transfer_data,16),*buffer;
        unsigned length=u32(data+8)&0x1ffffu,actual=length;
        if(mode==SHORT_DATA)actual=length-1;
        buffer=dma(m,u64(data),length+(mode==DMA_OVERRUN?1u:0u));
        memcpy(buffer,m->descriptor,actual);
        if(mode==DESCRIPTOR_MISMATCH)buffer[4]^=1;
        if(mode==DESCRIPTOR_INVALID && length==18)buffer[17]=0;
        if(mode==DMA_OVERRUN)buffer[length]^=0x80;
        if(m->disconnect_transfer==m->transfers)m->regs[PORT/4]&=~3u;
        m->transfer_pending=2;
        if(mode==SHORT_DATA || mode==SHORT_ZERO || mode==DUPLICATE_SHORT) {
            emit(m,m->transfer_data,(13u<<24)|(length-actual),ctl);return;
        }
    } else if(m->transfer_pending==2 && mode==DUPLICATE_SHORT) {
        ++m->transfer_pending;emit(m,m->transfer_data,13u<<24,ctl);return;
    }
    if(mode==NO_STATUS)return;
    if(mode==WRONG_POINTER)pointer+=4096;
    if(mode==WRONG_SLOT)ctl=(ctl&~(255u<<24))|(2u<<24);
    if(mode==WRONG_ENDPOINT)ctl=(ctl&~(31u<<16))|(2u<<16);
    if(mode==EVENT_DATA)ctl|=4;
    if(mode==MISALIGNED)pointer|=1;
    if(mode==RESIDUE_TOO_LARGE){pointer=m->transfer_data;cc=13;residue=100;}
    if(mode==STATUS_RESIDUE)residue=1;
    if(mode==SETUP_ERROR){pointer=m->transfer_setup;cc=6;}
    if(mode==DATA_ERROR){pointer=m->transfer_data;cc=6;}
    if(mode==STATUS_ERROR)cc=6;
    if(mode==SETUP_SUCCESS)pointer=m->transfer_setup;
    if(mode==DATA_SUCCESS)pointer=m->transfer_data;
    if(mode==STATUS_SHORT)cc=13;
    if(mode==RESERVED_CONTROL)ctl|=1u<<9;
    if(mode==OLD_POINTER)pointer=m->old_transfer;
    emit(m,pointer,(cc<<24)|residue,ctl);
    m->transfer_pending=0;m->old_transfer=m->transfer_status;
}
static void progress(struct model *m)
{
    if(m->hidden_bounce_due && m->clock>=m->hidden_bounce_due) {
        /* A disconnect/reconnect can occur between software polls. CCS is
         * already one again, but the latched CSC still reports the bounce. */
        m->regs[PORT/4]|=CSC;m->hidden_bounce_due=0;m->hidden_bounce_seen=1;
    }
    if(m->reset_due && m->clock>=m->reset_due && !m->port_stuck) {
        m->reset_due=0;m->reset_done=m->clock;
        m->regs[PORT/4]=(m->regs[PORT/4]&~(16u|0x1e0u|0x3c00u))|
                        PED|PRC|(m->speed<<10);
        if(m->change_speed)m->regs[PORT/4]=(m->regs[PORT/4]&~0x3c00u)|(4u<<10);
    }
    if(!(m->regs[OP/4]&1u) || m->never_complete)return;
    if((m->regs[PORT/4]&CHANGE) && !m->psceg)++m->port_pending;
    m->psceg=(m->regs[PORT/4]&CHANGE)?1u:0u;
    if(m->port_pending || m->port_flood) {
        emit(m,(uint64_t)(m->bad_port_event?5u:1u)<<24,1u<<24,34u<<10);
        if(m->port_pending)--m->port_pending;
        return;
    }
    if(m->extra_events) {
        emit(m,UINT64_C(2)<<24,1u<<24,34u<<10);--m->extra_events;return;
    }
    if(m->command_pending)execute_command(m);
    else if(m->transfer_pending)transfer_step(m);
}
static int read32(void *opaque,uint32_t offset,uint32_t *value)
{
    struct model *m=opaque;CHECK(!(offset&3u) && offset<sizeof(m->regs));
    if(fault(m))return 0;
    if((offset==OP || offset==OP+4) && (m->regs[OP/4]&2u) && !m->reset_stuck)hardware_reset(m);
    *value=m->regs[offset/4];
    if(offset>=PORT && offset<PORT+64 && !((offset-PORT)&15u))m->observed_port[(offset-PORT)/16]=*value;
    return 1;
}
static void transfer_doorbell(struct model *m,uint32_t value)
{
    const uint8_t *setup,*data,*status;uint32_t c;
    CHECK(value==1 && m->addressed && !m->transfer_pending);
    CHECK(m->clock-m->address_done>=2000);
    setup=dma(m,m->ep_cursor,48);data=setup+16;status=data+16;
    CHECK(u32(setup)==0x01000680u);
    CHECK(u32(setup+4)==((m->transfers==0?8u:18u)<<16));
    CHECK(u32(setup+8)==8);
    CHECK(u32(setup+12)==((2u<<10)|(3u<<16)|(1u<<6)|m->ep_cycle));
    CHECK((u32(data+8)&0x1ffffu)==(m->transfers==0?8u:18u));
    CHECK((u32(data+8)&~UINT32_C(0x1ffff))==0);
    c=u32(data+12);
    CHECK(c==((3u<<10)|(1u<<16)|(1u<<2)|m->ep_cycle));
    CHECK(u64(data)==m->blocks[1].bus+(m->transfers==0?8448u:8512u));
    CHECK(u64(status)==0 && u32(status+8)==0);
    CHECK(u32(status+12)==((4u<<10)|(1u<<5)|m->ep_cycle));
    CHECK(m->transfers<2 && m->current_packet==(m->transfers?m->packet:(m->speed==3?64u:8u)));
    m->transfer_setup=m->ep_cursor;m->transfer_data=m->ep_cursor+16;m->transfer_status=m->ep_cursor+32;
    m->ep_cursor+=48;m->transfer_pending=1;++m->transfers;
}
static int write32(void *opaque,uint32_t offset,uint32_t value)
{
    struct model *m=opaque;int bad=fault(m);
    CHECK(!(offset&3u) && offset<sizeof(m->regs));if(bad && !m->fail_after)return 0;
    if(offset==OP) {
        if(value&2u){CHECK(m->regs[(OP+4)/4]&1u);m->regs[OP/4]=value;}
        else if(value&1u) {
            CHECK(r64(m,OP+48)==m->blocks[0].bus && m->blocks[0].owned);
            CHECK(m->regs[(RT+32)/4]==0 && value==1);
            if(m->regs[(OP+56)/4]) {
                CHECK(m->regs[(OP+56)/4]==1 && m->blocks[1].owned);
                CHECK(u64(m->blocks[0].device+8)==m->blocks[1].bus);
                check_zero(m->blocks[1].device,4096);
            }
            m->regs[OP/4]=value;m->regs[(OP+4)/4]&=~1u;m->was_running=1;
            m->cmd_cursor=r64(m,OP+24)&~UINT64_C(63);m->command_cycle=1;
        } else {m->regs[OP/4]=value;if(!m->halt_stuck)m->regs[(OP+4)/4]|=1;}
    } else if(offset==DB) {
        CHECK(value==0 && !m->command_pending && m->cmd_cursor);
        m->pending_cmd=m->cmd_cursor;m->command_pending=1;
    } else if(offset==DB+4)transfer_doorbell(m,value);
    else if(offset>=PORT && offset<PORT+64 && !((offset-PORT)&15u)) {
        unsigned port=(offset-PORT)/16;uint32_t old=m->regs[offset/4];
        CHECK(!(value&(PED|(1u<<16)|(1u<<31))));
        CHECK((value&CHANGE&~m->observed_port[port])==0);
        CHECK((value&PRESERVE)==(old&PRESERVE));
        m->regs[offset/4]&=~(value&CHANGE);
        if(!port && !(m->regs[offset/4]&CHANGE))m->psceg=0;
        if(value&PR) {
            CHECK(port==0 && (old&CCS) && m->clock>=100000);
            CHECK(!m->reset_due);m->reset_due=m->clock+50000;++m->reset_count;
            m->regs[offset/4]=(m->regs[offset/4]&~2u)|PR;
        }
    } else if(offset==RT+32)m->regs[offset/4]&=~(value&1u);
    else m->regs[offset/4]=value;
    return !bad;
}
static int write8(void *opaque,uint32_t offset,uint8_t value)
{
    struct model *m=opaque;int bad=fault(m);CHECK(offset==LEG+3);
    if(bad && !m->fail_after)return 0;
    m->regs[LEG/4]=(m->regs[LEG/4]&0x00ffffffu)|((uint32_t)value<<24);
    if(value&1u)m->regs[LEG/4]&=~0x10000u;
    return !bad;
}
static int allocate(void *opaque,size_t bytes,size_t alignment,uint64_t limit,struct xhci_dma *out)
{
    struct model *m=opaque;unsigned index=bytes==4096?0u:1u;struct block *b=&m->blocks[index];
    CHECK(bytes==(index?12288u:4096u) && alignment==4096 && !b->owned);
    CHECK(limit==((m->regs[4]&1u)?UINT64_MAX:UINT32_MAX));
    if(fault(m) || m->allocation_fault==index+1)return 0;
    b->cpu=aligned_alloc(4096,bytes);b->device=malloc(bytes);CHECK(b->cpu && b->device);
    memset(b->cpu,0xa5,bytes);memset(b->device,0x5a,bytes);b->bytes=bytes;b->owned=1;++m->allocations;
    out->cpu=b->cpu;out->bus=b->bus;out->bytes=bytes;
    if(index && m->malformed_dma==1)out->bytes=12287;
    if(index && m->malformed_dma==2)++out->bus;
    if(index && m->malformed_dma==3)out->cpu=b->cpu+1;
    if(index && m->malformed_dma==4)out->cpu=NULL;
    if(index && m->malformed_dma==5)out->bus=m->blocks[0].bus;
    if(index && m->malformed_dma==6)out->bus=UINT64_MAX-4095;
    if(index && m->malformed_dma==7)out->bus=UINT64_C(0x100000000);
    if(index && m->malformed_dma==8)out->bus=UINT64_C(0xfffff000);
    b->handed=*out;return 1;
}
static void release(void *opaque,struct xhci_dma *given)
{
    struct model *m=opaque;unsigned i;
    for(i=0;i<2;++i)if(m->blocks[i].owned && m->blocks[i].handed.cpu==given->cpu)break;
    CHECK(i<2 && !m->command_pending && !m->transfer_pending);
    CHECK((m->regs[(OP+4)/4]&1u) && r64(m,OP+24)==0 && r64(m,OP+48)==0 && r64(m,RT+48)==0);
    if(i==0)m->released_dcbaa_zero=u64(m->blocks[0].device+8)==0?1u:0u;
    free(m->blocks[i].cpu);free(m->blocks[i].device);
    m->blocks[i].cpu=m->blocks[i].device=NULL;m->blocks[i].owned=0;++m->releases;
}
static int sync_dma(void *opaque,const struct xhci_dma *block,size_t offset,size_t bytes,int to_device)
{
    struct model *m=opaque;unsigned i;int bad=fault(m);
    for(i=0;i<2;++i)if(m->blocks[i].owned && m->blocks[i].cpu==block->cpu)break;
    CHECK(i<2 && offset<=m->blocks[i].bytes && bytes<=m->blocks[i].bytes-offset);
    CHECK(to_device==0 || to_device==1);if(bad && !m->fail_after)return 0;
    if(to_device) {
        if(i && m->addressed && offset<32u*m->stride)CHECK(bytes==0);
        memcpy(m->blocks[i].device+offset,m->blocks[i].cpu+offset,bytes);
    } else memcpy(m->blocks[i].cpu+offset,m->blocks[i].device+offset,bytes);
    return !bad;
}
static uint64_t now(void *opaque)
{ struct model *m=opaque;if(m->backwards && m->clock)return --m->clock;return m->clock; }
static void relax(void *opaque)
{ struct model *m=opaque;if(!m->freeze)m->clock+=1000;progress(m); }
static struct xhci_ops callbacks(struct model *m)
{ struct xhci_ops ops={m,read32,write32,allocate,release,sync_dma,now,relax,write8};return ops; }
static struct xhci_config configuration(void)
{ struct xhci_config c={0x0c0330,6,0x4000,1000000,1};return c; }
static struct xhciu_request request(void)
{ struct xhciu_request r={sizeof(r),XHCIU_ABI_VERSION,0,0};return r; }
static void initialize(struct model *m,unsigned speed,unsigned packet,unsigned wide,unsigned large)
{
    static const uint8_t descriptor[18]={18,1,0,2,0,0,0,64,9,0x12,2,0x98,0,1,1,2,3,1};
    memset(m,0,sizeof(*m));++scenarios;m->speed=speed;m->packet=packet;m->stride=large?64u:32u;
    m->blocks[0].bus=UINT64_C(0x120000)+(wide?UINT64_C(0x100000000):0);
    m->blocks[1].bus=UINT64_C(0x180000)+(wide?UINT64_C(0x100000000):0);
    m->regs[0]=0x01000040;m->regs[1]=0x04000108;
    m->regs[4]=(wide?1u:0u)|(large?4u:0u)|((LEG/4u)<<16);
    m->regs[5]=DB;m->regs[6]=RT;m->regs[LEG/4]=0x00011001u;
    m->regs[PROTO/4]=(2u<<24)|2u;m->regs[PROTO/4+1]=0x20425355;
    m->regs[PROTO/4+2]=0x401;m->regs[PROTO/4+3]=0;
    hardware_reset(m);m->regs[PORT/4]=CCS|PP|CSC|(7u<<5);
    m->regs[(PORT+16)/4]=m->regs[(PORT+32)/4]=m->regs[(PORT+48)/4]=PP|(5u<<5);
    memcpy(m->descriptor,descriptor,18);m->descriptor[7]=(uint8_t)packet;
    m->mode_transfer=2;m->output_poison=1;
}
static void no_leak(struct model *m)
{ CHECK(!m->blocks[0].owned && !m->blocks[1].owned && m->allocations==m->releases); }
static struct xhciu_result probe(struct model *m,struct xhci_device *x,struct xhciu_descriptor *out)
{
    struct xhciu_request r=request();struct xhciu_descriptor before;
    struct xhciu_result result;
    memset(out,0xa5,sizeof(*out));before=*out;result=xhciu_probe_device(x,&r,out);
    if(result.status)CHECK(memcmp(out,&before,sizeof(*out))==0);
    else {
        CHECK(out->struct_size==84 && out->abi_version==1 && out->root_port==1 && out->slot_id==1);
        CHECK(out->context_bytes==m->stride && out->port_speed_id==m->speed);
        CHECK(out->initial_ep0_packet==(m->speed==3?64:8) && out->final_ep0_packet==m->packet);
        CHECK(memcmp(out->raw_device,m->descriptor,18)==0 && memcmp(out->first_eight,m->descriptor,8)==0);
        CHECK(out->parsed.vendor_id==0x1209 && out->parsed.product_id==0x9802);
        CHECK(out->parsed.speed==(m->speed==1?NTWU_FULL_SPEED:m->speed==2?NTWU_LOW_SPEED:NTWU_HIGH_SPEED));
        CHECK(out->parsed.control_packet_bytes==m->packet && out->reserved[0]==0 && out->reserved[1]==0);
        CHECK(x->state==XHCI_CLOSED && m->enables==1 && m->addresses==1 && m->disables==1 && m->transfers==2);
        CHECK(m->released_dcbaa_zero);
        CHECK(m->evaluates==(m->speed==1 && m->packet!=8?1u:0u));no_leak(m);
    }
    return result;
}
static void success_cases(void)
{
    unsigned wide,large,which;
    for(wide=0;wide<2;++wide)for(large=0;large<2;++large)for(which=0;which<6;++which) {
        struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
        struct xhci_ops ops;struct xhci_config cfg=configuration();
        unsigned speed=which<4?1u:which==4?2u:3u;
        unsigned packet=which<4?8u<<which:which==4?8u:64u;
        initialize(&m,speed,packet,wide,large);ops=callbacks(&m);
        if(which==2)m.extra_events=2;
        if(which==3){m.slot_type=7;m.regs[PROTO/4+3]=7;}
        CHECK(xhci_open_one_slot(&x,&ops,&cfg)==0);
        if(which&1u)m.regs[PORT/4]=CCS|PED|PP|CSC|(speed<<10)|(1u<<25)|(2u<<14)|PRC|(1u<<18);
        CHECK(x.enabled_slots==1 && m.allocations==2);
        CHECK(probe(&m,&x,&out).status==0);CHECK(xhci_close(&x)==0);no_leak(&m);
    }
    /* NoOp traffic exercises both command/event wraps before USB uses the
     * same event cursor, rather than rewarding a second consumer. */
    {
        struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
        struct xhci_ops ops;struct xhci_config cfg=configuration();unsigned i;
        initialize(&m,1,64,1,1);ops=callbacks(&m);CHECK(xhci_open_one_slot(&x,&ops,&cfg)==0);
        for(i=0;i<130;++i)CHECK(xhci_noop(&x)==0);
        CHECK(m.cmd_wraps>=8 && m.events==130);CHECK(probe(&m,&x,&out).status==0);no_leak(&m);
    }
}
static void failure_cases(void)
{
    unsigned mode,which;
    for(which=1;which<=2;++which)for(mode=1;mode<=DMA_OVERRUN;++mode) {
        struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
        struct xhci_ops ops;struct xhci_config cfg=configuration();struct xhciu_result result;
        if((mode==DESCRIPTOR_INVALID || mode==DESCRIPTOR_MISMATCH || mode==OLD_POINTER) && which==1)continue;
        initialize(&m,1,64,1,mode&1u);m.mode=mode;m.mode_transfer=which;ops=callbacks(&m);
        CHECK(xhci_open_one_slot(&x,&ops,&cfg)==0);result=probe(&m,&x,&out);
        if(mode==SHORT_ZERO)CHECK(result.status==0);
        else CHECK(result.status!=0);
        CHECK(xhci_close(&x)==0);no_leak(&m);
    }
    for(mode=1;mode<=7;++mode) {
        struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
        struct xhci_ops ops;struct xhci_config cfg=configuration();
        initialize(&m,1,64,0,0);ops=callbacks(&m);CHECK(xhci_open_one_slot(&x,&ops,&cfg)==0);
        if(mode<=5)m.bad_command=mode;else m.context_error=mode-5;
        CHECK(probe(&m,&x,&out).status!=0);CHECK(xhci_close(&x)==0);no_leak(&m);
    }
}
static void topology_cases(void)
{
    unsigned mode;
    for(mode=0;mode<17;++mode) {
        struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
        struct xhci_ops ops;struct xhci_config cfg=configuration();int opened;
        initialize(&m,1,64,0,0);
        if(mode==0)m.regs[PROTO/4]|=1u<<16;
        if(mode==1)m.regs[PROTO/4]=(3u<<24)|2u;
        if(mode==2)m.regs[PROTO/4+1]=0;
        if(mode==3)m.regs[PROTO/4+2]|=1u<<28;
        if(mode==4)m.regs[PROTO/4+2]=0x400;
        if(mode==5)m.regs[PROTO/4+2]=0x405;
        if(mode==6)m.regs[PROTO/4+2]=1;
        if(mode==7)m.regs[PORT/4]&=~1u;
        if(mode==8)m.regs[(PORT+16)/4]|=CCS;
        if(mode==9)m.regs[PORT/4]&=~512u;
        if(mode==10)m.regs[PORT/4]|=OCA;
        if(mode==11)m.port_stuck=1;
        if(mode==12)m.bad_port_event=1;
        if(mode==13)m.change_speed=1;
        if(mode==14)m.disconnect_transfer=1;
        if(mode==15) {
            m.regs[PROTO/4]|=4u<<8;
            m.regs[PROTO/4+4]=(2u<<24)|2u;m.regs[PROTO/4+5]=0x20425355;
            m.regs[PROTO/4+6]=0x201;m.regs[PROTO/4+7]=0;
        }
        if(mode==16)m.port_flood=1;
        ops=callbacks(&m);opened=xhci_open_one_slot(&x,&ops,&cfg);
        if(!opened)CHECK(probe(&m,&x,&out).status!=0);
        CHECK(xhci_close(&x)==0);no_leak(&m);
    }
}
static void invalid_arguments(void)
{
    struct model m;struct xhci_device x={0};struct xhciu_descriptor out,before;
    struct xhciu_request r=request();struct xhci_ops ops;struct xhci_config cfg=configuration();
    unsigned mode;
    initialize(&m,1,64,0,0);ops=callbacks(&m);CHECK(xhci_open(&x,&ops,&cfg)==0);
    memset(&out,0xa5,sizeof(out));before=out;
    CHECK(xhciu_probe_device(&x,&r,&out).status==XHCI_INVALID);
    CHECK(x.state==XHCI_READY && m.allocations==1 && !m.releases);
    CHECK(xhci_open_one_slot(&x,&ops,&cfg)==XHCI_INVALID);CHECK(xhci_close(&x)==0);no_leak(&m);
    memset(&x,0,sizeof(x));initialize(&m,1,64,0,0);ops=callbacks(&m);
    CHECK(xhci_open_one_slot(&x,&ops,&cfg)==0);
    for(mode=0;mode<6;++mode) {
        struct xhciu_result result;unsigned calls=m.calls;r=request();
        if(mode==0)r.struct_size=0;
        if(mode==1)r.abi_version=2;
        if(mode==2)r.flags=1;
        if(mode==3)result=xhciu_probe_device(NULL,&r,&out);
        else if(mode==4)result=xhciu_probe_device(&x,NULL,&out);
        else if(mode==5)result=xhciu_probe_device(&x,&r,NULL);
        else result=xhciu_probe_device(&x,&r,&out);
        CHECK(result.status==XHCI_INVALID && m.calls==calls);
        CHECK(memcmp(&out,&before,sizeof(out))==0 && x.state==XHCI_READY);
    }
    CHECK(xhci_close(&x)==0);no_leak(&m);
}
static unsigned baseline(void)
{
    struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
    struct xhci_ops ops;struct xhci_config cfg=configuration();
    initialize(&m,1,64,1,1);ops=callbacks(&m);CHECK(xhci_open_one_slot(&x,&ops,&cfg)==0);
    CHECK(probe(&m,&x,&out).status==0);no_leak(&m);return m.calls;
}
static void faults_and_quarantine(void)
{
    unsigned count=baseline(),index,after,mode;
    for(after=0;after<2;++after)for(index=1;index<=count;++index) {
        struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
        struct xhci_ops ops;struct xhci_config cfg=configuration();int result;
        initialize(&m,1,64,1,1);m.fault=index;m.fail_after=after;ops=callbacks(&m);
        result=xhci_open_one_slot(&x,&ops,&cfg);if(!result)result=probe(&m,&x,&out).status;
        CHECK(result!=0);m.fault=0;CHECK(xhci_close(&x)==0);no_leak(&m);++injected;
    }
    for(mode=0;mode<4;++mode) {
        struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
        struct xhci_ops ops;struct xhci_config cfg=configuration();
        initialize(&m,1,64,0,0);ops=callbacks(&m);CHECK(xhci_open_one_slot(&x,&ops,&cfg)==0);
        m.mode=STATUS_ERROR;
        if(mode==0)m.halt_stuck=1;
        if(mode==1)m.reset_stuck=1;
        if(mode==2){m.never_complete=1;m.freeze=1;}
        if(mode==3){m.clock=200000;m.backwards=1;}
        if(mode<2) {
            CHECK(probe(&m,&x,&out).status==XHCI_QUARANTINED);
            CHECK(m.blocks[0].owned && m.blocks[1].owned && !m.releases);
        } else CHECK(probe(&m,&x,&out).status!=0);
        m.halt_stuck=m.reset_stuck=m.freeze=m.backwards=m.never_complete=0;
        CHECK(xhci_close(&x)==0);no_leak(&m);
    }
    for(mode=1;mode<=10;++mode) {
        struct model m;struct xhci_device x={0};struct xhci_ops ops;struct xhci_config cfg=configuration();
        initialize(&m,1,64,0,0);if(mode<=8)m.malformed_dma=mode;else m.allocation_fault=mode-8;
        ops=callbacks(&m);CHECK(xhci_open_one_slot(&x,&ops,&cfg)!=0);CHECK(xhci_close(&x)==0);no_leak(&m);
    }
}
static void deadline_and_diagnostics(void)
{
    unsigned mode;
    for(mode=0;mode<3;++mode) {
        struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
        struct xhci_ops ops;struct xhci_config cfg=configuration();
        struct xhciu_result result;uint64_t started;
        initialize(&m,1,64,0,0);ops=callbacks(&m);
        if(mode==0)cfg.timeout_us=30000000;
        CHECK(xhci_open_one_slot(&x,&ops,&cfg)==0);started=m.clock;
        if(mode==0)m.mode=NO_STATUS;
        else {
            m.halt_stuck=1;
            if(mode==1)m.bad_command=4;
        }
        result=probe(&m,&x,&out);
        if(mode==0) {
            CHECK(result.status==XHCI_TIMEOUT && result.transport_error==XHCI_TIMEOUT);
            CHECK(m.clock-started>=10000000 && m.clock-started<=10020000);
        } else {
            CHECK(result.status==XHCI_QUARANTINED && x.last_error==XHCI_TIMEOUT);
            CHECK(m.blocks[0].owned && m.blocks[1].owned && !m.releases);
            if(mode==1) {
                CHECK(result.transport_error==XHCI_COMPLETION_ERROR);
                CHECK(x.operation_error==XHCI_COMPLETION_ERROR);
            } else {
                CHECK(result.transport_error==XHCI_TIMEOUT && x.operation_error==0);
                CHECK(m.transfers==2 && m.disables==1);
            }
        }
        m.halt_stuck=0;CHECK(xhci_close(&x)==0);no_leak(&m);
    }
}
static void hidden_disconnect(void)
{
    struct model m;struct xhci_device x={0};struct xhciu_descriptor out;
    struct xhci_ops ops;struct xhci_config cfg=configuration();struct xhciu_result result;
    initialize(&m,1,64,0,0);ops=callbacks(&m);
    CHECK(xhci_open_one_slot(&x,&ops,&cfg)==0);
    m.hidden_bounce_due=m.clock+90000;
    result=probe(&m,&x,&out);
    CHECK(result.status==XHCIU_DISCONNECTED && m.hidden_bounce_seen);
    CHECK(m.reset_count==0 && m.commands==0 && x.state==XHCI_CLOSED);
    CHECK(xhci_close(&x)==0);no_leak(&m);
}
int main(void)
{
    success_cases();failure_cases();topology_cases();invalid_arguments();faults_and_quarantine();
    deadline_and_diagnostics();
    hidden_disconnect();
    printf("{\"status\":\"PASS\",\"checks\":%u,\"scenarios\":%u,\"injected_callbacks\":%u}\n",
           checks,scenarios,injected);
    return 0;
}
