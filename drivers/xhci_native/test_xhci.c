/* SPDX-License-Identifier: GPL-2.0-only -- original asynchronous xHC model. */
#include "xhci.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static unsigned assertions;
#define CHECK(v) do { ++assertions; if(!(v)) { fprintf(stderr,"line %u: %s\n",(unsigned)__LINE__,#v);exit(1); } } while(0)
enum { OP=0x40, RT=0x1000, DB=0x2000, LEGACY=0x3000 };
struct model {
    uint32_t regs[0x4000/4];uint8_t *memory;uint64_t bus,clock,pending_pointer;
    unsigned calls,fault,reads,writes,allocations,releases,commands,links,events,syncs;
    unsigned command_index,command_cycle,event_index,event_cycle,pending,port_pending;
    unsigned ports_per_command,port_flood,never_complete,bad_event,late_error;
    unsigned halt_stuck,reset_stuck,start_stuck,cnr_stuck,legacy_stuck;
    unsigned bad_allocation,frozen_time,backward_time,initial_sync,last_write,payload_sync;
};
static uint32_t u32(const uint8_t *p)
{ return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t u64(const uint8_t *p)
{ return (uint64_t)u32(p)|((uint64_t)u32(p+4)<<32); }
static void w32(uint8_t *p,uint32_t n)
{ p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);p[2]=(uint8_t)(n>>16);p[3]=(uint8_t)(n>>24); }
static void w64(uint8_t *p,uint64_t n)
{ w32(p,(uint32_t)n);w32(p+4,(uint32_t)(n>>32)); }
static uint64_t reg64(struct model *m,unsigned offset)
{ return (uint64_t)m->regs[offset/4]|((uint64_t)m->regs[offset/4+1]<<32); }
static int fail_call(struct model *m) { return ++m->calls==m->fault; }
static void reset_state(struct model *m)
{
    unsigned i;
    for(i=0;i<0x40/4;++i)m->regs[OP/4+i]=0;
    for(i=0;i<0x40/4;++i)m->regs[RT/4+i]=0;
    m->regs[(OP+4)/4]=1;m->regs[(OP+8)/4]=1;
    m->command_index=m->event_index=0;m->command_cycle=m->event_cycle=1;
    m->pending=0;
}
static int read32(void *opaque,uint32_t offset,uint32_t *value)
{
    struct model *m=opaque;
    CHECK(!(offset&3u) && offset<sizeof(m->regs));++m->reads;
    if((offset==OP || offset==OP+4) && (m->regs[OP/4]&2u) && !m->reset_stuck)reset_state(m);
    if(offset==OP+4 && !m->cnr_stuck && !(m->regs[OP/4]&2u))m->regs[offset/4]&=~2048u;
    if(fail_call(m))return 0;
    *value=m->regs[offset/4];return 1;
}
static void submit(struct model *m,uint32_t value)
{
    const uint8_t *trb=m->memory+XHCI_COMMAND_OFFSET+m->command_index*16u;
    uint32_t ctl=u32(trb+12);
    CHECK(value==0 && !m->pending && m->memory && m->initial_sync);
    CHECK(m->regs[OP/4]==1 && !(m->regs[(OP+4)/4]&1u));
    CHECK(ctl==((23u<<10)|m->command_cycle));
    CHECK(u64(trb)==0 && u32(trb+8)==0);
    m->pending_pointer=m->bus+XHCI_COMMAND_OFFSET+m->command_index*16u;
    m->pending=1;m->port_pending=m->ports_per_command;++m->commands;
    if(++m->command_index==15) {
        trb=m->memory+XHCI_COMMAND_OFFSET+15u*16u;
        CHECK(u64(trb)==m->bus+XHCI_COMMAND_OFFSET && u32(trb+8)==0);
        CHECK(u32(trb+12)==((6u<<10)|2u|m->command_cycle));
        m->command_index=0;m->command_cycle^=1;++m->links;
    }
}
static int write32(void *opaque,uint32_t offset,uint32_t value)
{
    struct model *m=opaque;int failure;
    CHECK(!(offset&3u) && offset<sizeof(m->regs));++m->writes;failure=fail_call(m);
    if(offset==OP) {
        CHECK(!(m->regs[(OP+4)/4]&2048u));
        if(value&2u) {
            CHECK(m->regs[(OP+4)/4]&1u);
            m->regs[OP/4]=value;m->regs[(OP+4)/4]|=2048;
        } else if(value&1u) {
            CHECK(m->memory && reg64(m,OP+48)==m->bus && m->initial_sync);
            CHECK(reg64(m,OP+24)==((m->bus+XHCI_COMMAND_OFFSET)|1u));
            CHECK(reg64(m,RT+48)==m->bus+XHCI_ERST_OFFSET && m->regs[(RT+40)/4]==1);
            CHECK(reg64(m,RT+56)==m->bus+XHCI_EVENT_OFFSET && m->regs[(RT+32)/4]==0);
            CHECK(u64(m->memory+XHCI_ERST_OFFSET)==m->bus+XHCI_EVENT_OFFSET);
            CHECK(u32(m->memory+XHCI_ERST_OFFSET+8)==64 && u32(m->memory+XHCI_ERST_OFFSET+12)==0);
            CHECK(m->regs[(OP+56)/4]==0);
            m->regs[OP/4]=value;if(!m->start_stuck)m->regs[(OP+4)/4]&=~1u;
        } else {
            m->regs[OP/4]=value;if(!m->halt_stuck)m->regs[(OP+4)/4]|=1;
        }
    } else if(offset==DB)submit(m,value);
    else if(offset==RT+32) { CHECK(!(value&2u));m->regs[offset/4]&=~(value&1u); }
    else if(offset==LEGACY+4) {
        CHECK(!(value&0xfff1e011u));m->regs[offset/4]=value;
    } else {
        if(offset==OP+28 || offset==OP+52 || offset==RT+52 || offset==RT+60) {
            CHECK(m->regs[16/4]&1u);CHECK(m->last_write==offset-4);
        }
        m->regs[offset/4]=value;
    }
    m->last_write=offset;return !failure;
}
static int write8(void *opaque,uint32_t offset,uint8_t value)
{
    struct model *m=opaque;int failure=fail_call(m);++m->writes;
    CHECK(offset==LEGACY+3);
    m->regs[LEGACY/4]=(m->regs[LEGACY/4]&0x00ffffffu)|((uint32_t)value<<24);
    if((value&1u) && !m->legacy_stuck)m->regs[LEGACY/4]&=~0x10000u;
    return !failure;
}
static int allocate(void *opaque,size_t bytes,size_t alignment,uint64_t limit,struct xhci_dma *block)
{
    struct model *m=opaque;
    CHECK(!m->memory && bytes==4096 && alignment==4096);
    CHECK(limit==((m->regs[16/4]&1u)?UINT64_MAX:UINT32_MAX));
    if(fail_call(m))return 0;
    m->memory=aligned_alloc(4096,8192);CHECK(m->memory!=NULL);++m->allocations;
    memset(m->memory,0xa5,8192);block->cpu=m->memory;block->bus=m->bus;block->bytes=4096;
    if(m->bad_allocation==1)++block->bus;
    if(m->bad_allocation==2)block->cpu=m->memory+1;
    if(m->bad_allocation==3)block->bytes=4095;
    if(m->bad_allocation==4)block->cpu=NULL;
    return 1;
}
static void release(void *opaque,struct xhci_dma *block)
{
    struct model *m=opaque;(void)block;
    CHECK(m->memory && !m->pending && (m->regs[(OP+4)/4]&1u));
    CHECK(reg64(m,OP+24)==0 && reg64(m,OP+48)==0 && reg64(m,RT+48)==0);
    free(m->memory);m->memory=NULL;++m->releases;
}
static void event(struct model *m)
{
    uint8_t *p=m->memory+XHCI_EVENT_OFFSET+m->event_index*16u;
    uint32_t type=33,status=0x01000000u,control;
    uint64_t pointer=m->pending_pointer;
    if(m->port_pending || m->port_flood) {
        type=34;pointer=UINT64_C(1)<<24;
        if(m->port_pending)--m->port_pending;
    } else m->pending=0;
    if(m->bad_event==1)pointer+=16;
    if(m->bad_event==2)pointer|=1;
    if(m->bad_event==3)status=5u<<24;
    if(m->bad_event==4)type=32;
    if(m->bad_event==5)status|=1;
    if(m->bad_event==6){type=34;pointer=UINT64_C(5)<<24;}
    control=(type<<10)|m->event_cycle;
    if(m->bad_event==7)control|=1u<<24;
    if(m->bad_event==8)control^=1;
    if(m->bad_event==9)control|=1u<<16;
    w64(p,pointer);w32(p+8,status);w32(p+12,control);
    if(++m->event_index==64){m->event_index=0;m->event_cycle^=1;}
    if(m->late_error)m->regs[(OP+4)/4]|=4;
    ++m->events;
}
static int sync_dma(void *opaque,const struct xhci_dma *block,size_t offset,size_t bytes,int to_device)
{
    struct model *m=opaque;
    CHECK(block->cpu==m->memory && offset<4096 && bytes<=4096-offset);
    CHECK(to_device==0 || to_device==1);++m->syncs;
    if(fail_call(m))return 0;
    if(to_device && offset==0 && bytes==4096)m->initial_sync=1;
    if(to_device && offset>=XHCI_COMMAND_OFFSET && offset<XHCI_EVENT_OFFSET) {
        uint32_t control=u32(m->memory+(offset&~(size_t)15u)+12);
        if(bytes==16) {
            CHECK((control&1u)!=(uint32_t)m->command_cycle);
            m->payload_sync=(unsigned)offset+1u;
        } else {
            CHECK(bytes==4 && (offset&15u)==12 && m->payload_sync==offset-11u);
            CHECK((control&1u)==m->command_cycle);
            m->payload_sync=0;
        }
    }
    if(!to_device && m->pending && !m->never_complete &&
       offset==XHCI_EVENT_OFFSET+m->event_index*16u)event(m);
    return 1;
}
static uint64_t now(void *opaque)
{ struct model *m=opaque;if(m->backward_time && m->clock)return --m->clock;return m->clock; }
static void relax(void *opaque)
{ struct model *m=opaque;if(!m->frozen_time)m->clock+=1000; }
static struct xhci_ops callbacks(struct model *m)
{ const struct xhci_ops ops={m,read32,write32,allocate,release,sync_dma,now,relax,write8};return ops; }
static struct xhci_config config(void)
{ const struct xhci_config cfg={0x0c0330,6,0x4000,1000000,1};return cfg; }
static void reset(struct model *m)
{
    memset(m,0,sizeof(*m));m->bus=0x120000;
    m->regs[0]=0x01000040;m->regs[1]=0x04000108;m->regs[4]=1;
    m->regs[5]=DB;m->regs[6]=RT;reset_state(m);
}
static void no_leaks(struct model *m)
{ CHECK(!m->memory && !m->pending && m->allocations==m->releases); }
static void success_and_wrap(void)
{
    struct model m;struct xhci_device x={0};struct xhci_ops ops;struct xhci_config cfg=config();unsigned i;
    reset(&m);ops=callbacks(&m);m.ports_per_command=1;
    CHECK(xhci_open(&x,&ops,&cfg)==0 && x.state==XHCI_READY);
    CHECK(x.version==0x100 && x.max_slots==8 && x.max_ports==4 && x.max_interrupters==1);
    CHECK(xhci_open(&x,&ops,&cfg)==XHCI_INVALID);
    for(i=0;i<150;++i) {
        CHECK(xhci_noop(&x)==0);
        CHECK(x.commands_completed==i+1 && x.port_events==i+1 && x.last_completion_code==1);
        CHECK(x.last_completion_pointer==m.pending_pointer);
    }
    CHECK(m.links==10 && x.command_index==0 && x.command_cycle==1);
    CHECK(x.event_index==44 && x.event_cycle==1 && m.events==300);
    CHECK(xhci_close(&x)==0 && x.state==XHCI_CLOSED);no_leaks(&m);
    CHECK(xhci_close(&x)==0 && xhci_noop(&x)==XHCI_INVALID);
    CHECK(xhci_open(&x,&ops,&cfg)==0);CHECK(xhci_noop(&x)==0);CHECK(xhci_close(&x)==0);no_leaks(&m);
}
static unsigned baseline(void)
{
    struct model m;struct xhci_device x={0};struct xhci_ops ops;struct xhci_config cfg=config();
    reset(&m);ops=callbacks(&m);m.regs[4]|=(LEGACY/4u)<<16;m.regs[LEGACY/4]=0x10001;
    m.regs[(LEGACY+4)/4]=0xe000e011u;
    CHECK(xhci_open(&x,&ops,&cfg)==0);CHECK(xhci_noop(&x)==0);CHECK(xhci_close(&x)==0);no_leaks(&m);
    CHECK(!(m.regs[LEGACY/4]&0x01000000u));return m.calls;
}
static void callback_failures(void)
{
    unsigned max=baseline(),i;struct model m;struct xhci_device x;struct xhci_ops ops;
    struct xhci_config cfg=config();int result;
    for(i=1;i<=max;++i) {
        reset(&m);memset(&x,0,sizeof(x));ops=callbacks(&m);m.fault=i;
        m.regs[4]|=(LEGACY/4u)<<16;m.regs[LEGACY/4]=0x10001;m.regs[(LEGACY+4)/4]=0xe000e011u;
        result=xhci_open(&x,&ops,&cfg);if(!result)result=xhci_noop(&x);if(!result)result=xhci_close(&x);
        CHECK(result!=0);m.fault=0;
        result=xhci_close(&x);
        if(result)fprintf(stderr,"fault=%u retry=%d reason=%d state=%u CMD=%x STS=%x\n",
                          i,result,x.last_error,x.state,m.regs[OP/4],m.regs[(OP+4)/4]);
        CHECK(result==0);no_leaks(&m);
        CHECK(!(m.regs[LEGACY/4]&0x01000000u));
    }
    printf("Injected failure after each of %u MMIO/byte/DMA/sync operations\n",max);
}
static void capability_errors(void)
{
    struct model m;struct xhci_device x;struct xhci_ops ops;struct xhci_config cfg;unsigned mode;
    for(mode=0;mode<23;++mode) {
        reset(&m);memset(&x,0,sizeof(x));ops=callbacks(&m);cfg=config();
        if(mode==0)cfg.pci_class=0x0c0320;
        if(mode==1)cfg.exclusive=0;
        if(mode==2)cfg.pci_command=2;
        if(mode==3)m.regs[0]=0x00960040;
        if(mode==4)m.regs[1]&=~255u;
        if(mode==5)m.regs[1]&=~0x7ff00u;
        if(mode==6)m.regs[1]&=~0xff000000u;
        if(mode==7)m.regs[2]=1u<<27;
        if(mode==8)m.regs[2]=1u<<21;
        if(mode==9)m.regs[5]=OP;
        if(mode==10)m.regs[6]=DB;
        if(mode==11)m.regs[5]=0xfffffffcu;
        if(mode==12)m.regs[6]=0x1001;
        if(mode==13)m.regs[0]|=1;
        if(mode==14)m.regs[(OP+8)/4]=2;
        if(mode==15){m.regs[4]|=(LEGACY/4u)<<16;m.regs[LEGACY/4]=1;ops.write8=NULL;}
        if(mode==16){m.regs[4]|=(LEGACY/4u)<<16;m.regs[LEGACY/4]=0xff01;}
        if(mode==17){m.regs[4]|=(OP/4u)<<16;m.regs[OP/4]=1;}
        if(mode==18){m.regs[4]|=(LEGACY/4u)<<16;m.regs[LEGACY/4]=0x101;}
        if(mode==19)cfg.mmio_bytes=RT+63;
        if(mode==20){m.regs[4]|=(LEGACY/4u)<<16;m.regs[LEGACY/4]=0x201;m.regs[LEGACY/4+2]=1;}
        if(mode==21) {
            unsigned j;
            m.regs[4]|=(LEGACY/4u)<<16;
            for(j=0;j<257;++j)m.regs[LEGACY/4+j]=0x1ff;
        }
        if(mode==22){m.regs[4]|=(0xfffcu/4u)<<16;}
        CHECK(xhci_open(&x,&ops,&cfg)!=0);CHECK(!m.writes && !m.allocations);no_leaks(&m);
    }
    CHECK(xhci_open(NULL,&ops,&cfg)==XHCI_INVALID && xhci_close(NULL)==XHCI_INVALID);
}
static void dma_errors(void)
{
    struct model m;struct xhci_device x;struct xhci_ops ops;struct xhci_config cfg=config();unsigned mode;
    for(mode=1;mode<=7;++mode) {
        reset(&m);memset(&x,0,sizeof(x));ops=callbacks(&m);
        if(mode<=4)m.bad_allocation=mode;
        if(mode==5){m.regs[4]=0;m.bus=UINT64_C(0x100000000);}
        if(mode==6)m.bus=UINT64_MAX-2047u;
        if(mode==7){m.regs[4]=0;m.bus=UINT64_C(0xfffff800);}
        CHECK(xhci_open(&x,&ops,&cfg)!=0);no_leaks(&m);
    }
    reset(&m);memset(&x,0,sizeof(x));ops=callbacks(&m);m.bus=UINT64_C(0x1234500000);
    CHECK(xhci_open(&x,&ops,&cfg)==0);CHECK(xhci_noop(&x)==0);CHECK(xhci_close(&x)==0);no_leaks(&m);
    reset(&m);memset(&x,0,sizeof(x));ops=callbacks(&m);m.regs[4]=0;m.bus=0xfffff000u;
    CHECK(xhci_open(&x,&ops,&cfg)==0);CHECK(xhci_noop(&x)==0);CHECK(xhci_close(&x)==0);no_leaks(&m);
}
static void completion_errors(void)
{
    struct model m;struct xhci_device x;struct xhci_ops ops;struct xhci_config cfg=config();unsigned mode;
    for(mode=1;mode<=15;++mode) {
        reset(&m);memset(&x,0,sizeof(x));ops=callbacks(&m);
        CHECK(xhci_open(&x,&ops,&cfg)==0);
        if(mode<=9)m.bad_event=mode;
        if(mode==10)m.never_complete=1;
        if(mode==11)m.late_error=1;
        if(mode==12){m.never_complete=1;m.frozen_time=1;}
        if(mode==13){m.never_complete=1;m.clock=10000;m.backward_time=1;}
        if(mode==14)m.port_flood=1;
        if(mode==15)m.regs[(OP+4)/4]|=4096;
        CHECK(xhci_noop(&x)!=0 && x.commands_completed==0);
        CHECK(x.state==XHCI_CLOSED);no_leaks(&m);
    }
}
static void timeout_and_quarantine(void)
{
    struct model m;struct xhci_device x;struct xhci_ops ops;struct xhci_config cfg=config();unsigned mode;
    for(mode=0;mode<5;++mode) {
        reset(&m);memset(&x,0,sizeof(x));ops=callbacks(&m);
        if(mode==0){m.cnr_stuck=1;m.regs[(OP+4)/4]|=2048;}
        if(mode==1){m.halt_stuck=1;m.regs[OP/4]=1;m.regs[(OP+4)/4]=0;}
        if(mode==2)m.reset_stuck=1;
        if(mode==3){m.regs[4]|=(LEGACY/4u)<<16;m.regs[LEGACY/4]=0x10001;m.legacy_stuck=1;}
        if(mode==4)m.start_stuck=1;
        CHECK(xhci_open(&x,&ops,&cfg)!=0);no_leaks(&m);
        if(mode==0)CHECK(!m.writes);
    }
    for(mode=0;mode<2;++mode) {
        reset(&m);memset(&x,0,sizeof(x));ops=callbacks(&m);CHECK(xhci_open(&x,&ops,&cfg)==0);
        m.never_complete=1;if(mode==0)m.halt_stuck=1;else m.reset_stuck=1;
        CHECK(xhci_noop(&x)==XHCI_QUARANTINED && x.state==XHCI_RETAINED);
        CHECK(m.memory && !m.releases && x.dma_owned && x.dma_published);
        m.halt_stuck=m.reset_stuck=0;
        CHECK(xhci_close(&x)==0);no_leaks(&m);
    }
}
int main(void)
{
    success_and_wrap();callback_failures();capability_errors();dma_errors();
    completion_errors();timeout_and_quarantine();
    printf("PASS: original xHCI model %u assertions; command/event wraps and DMA lifetime checked\n",assertions);
    return 0;
}
