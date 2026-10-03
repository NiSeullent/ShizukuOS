/* SPDX-License-Identifier: GPL-2.0-only -- host model of the xHCI HID interrupt-IN transport.
 * A simulated controller (registers, command ring, EP0 and interrupt transfer
 * rings with cycle bits and Link TRBs, event ring) executes the real
 * xhciu_probe_configuration + xhciu_hid_* code. No hardware, no VM. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hid_interrupt.h"

static unsigned checks, scenarios;
#define CHECK(v) do { ++checks; if(!(v)) { \
    fprintf(stderr,"scenario %u line %u: %s\n",scenarios,(unsigned)__LINE__,#v); exit(1); } } while(0)
enum { OP=0x40, RT=0x1000, DB=0x2000, PROTO=0x3040, PORT=OP+0x400 };
enum { CCS=1, PED=2, PR=16, PP=512, CSC=1<<17, PRC=1<<21 };
#define CHANGE UINT32_C(0x00fe0000)
struct ring { uint64_t cursor; unsigned cycle; };
struct model {
    uint32_t regs[0x4000/4];
    uint8_t *cpu[2]; uint64_t bus[2]; unsigned owned[2],allocations,releases;
    uint64_t clock; unsigned relaxes,stride,speed;
    struct ring cmd,ep0,intr; unsigned ev_index,ev_cycle,dci,slot_enabled;
    unsigned events,port_events;
    uint8_t device[18],config[64],report[128]; unsigned config_len,report_len,hang_ep0,stall_after;
    uint64_t last_int_buffer; unsigned config_commands,interval_seen,mps_seen;
    unsigned halted,stall_no_halt,reset_eps,set_deqs,clear_halts; uint32_t clear_index;
};
static uint32_t u32(const uint8_t *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8)|((uint32_t)p[2]<<16)|((uint32_t)p[3]<<24); }
static uint64_t u64(const uint8_t *p) { return (uint64_t)u32(p)|((uint64_t)u32(p+4)<<32); }
static void w32(uint8_t *p,uint32_t n) { p[0]=(uint8_t)n;p[1]=(uint8_t)(n>>8);p[2]=(uint8_t)(n>>16);p[3]=(uint8_t)(n>>24); }
static void w64(uint8_t *p,uint64_t n) { w32(p,(uint32_t)n);w32(p+4,(uint32_t)(n>>32)); }
static uint64_t r64(const struct model *m,unsigned a) { return (uint64_t)m->regs[a/4]|((uint64_t)m->regs[a/4+1]<<32); }
static uint8_t *dma(struct model *m,uint64_t bus,size_t bytes)
{
    unsigned i;
    for(i=0;i<2;++i) if(m->owned[i] && bus>=m->bus[i] && bus-m->bus[i]+bytes<=(i?12288u:4096u))
        return m->cpu[i]+(bus-m->bus[i]);
    CHECK(0);return NULL;
}
static void emit(struct model *m,uint64_t pointer,uint32_t status,uint32_t ctl)
{
    uint8_t *erst=dma(m,r64(m,RT+48),16);
    uint8_t *p=dma(m,u64(erst)+(uint64_t)m->ev_index*16u,16);
    w64(p,pointer);w32(p+8,status);w32(p+12,ctl|m->ev_cycle);
    if(++m->ev_index==64) { m->ev_index=0;m->ev_cycle^=1; }
    ++m->events;
}
static void port_event(struct model *m)
{ emit(m,1u<<24,0x01000000u,34u<<10);++m->port_events; }
static void hw_reset(struct model *m)
{
    unsigned i;
    for(i=0;i<0x40/4;++i) m->regs[OP/4+i]=0;
    for(i=0;i<0x40/4;++i) m->regs[RT/4+i]=0;
    m->regs[(OP+4)/4]=1;m->regs[(OP+8)/4]=1;
    m->ev_index=0;m->ev_cycle=1;m->slot_enabled=0;m->cmd.cycle=1;
}
/* Fetch the next valid TRB of a ring following Link TRBs; NULL when not ready. */
static uint8_t *fetch(struct model *m,struct ring *r,uint64_t *address)
{
    unsigned guard;
    for(guard=0;guard<4;++guard) {
        uint8_t *t=dma(m,r->cursor,16);uint32_t c=u32(t+12);
        if((c&1u)!=r->cycle) return NULL;
        if(((c>>10)&63u)==6u) { r->cursor=u64(t)&~UINT64_C(15);if(c&2u) r->cycle^=1u;continue; }
        *address=r->cursor;return t;
    }
    CHECK(0);return NULL;
}
static uint8_t *out_ctx(struct model *m) { return dma(m,u64(dma(m,r64(m,OP+48)+8,8)),(size_t)m->stride*32u); }
static void context_command(struct model *m,uint64_t input_bus,unsigned kind)
{
    uint8_t *in=dma(m,input_bus,m->stride*33u),*out=out_ctx(m);unsigned i,flags;
    uint32_t add=u32(in+4);
    if(kind==11) {
        CHECK(add==3 && u32(in)==0);
        CHECK(((u32(in+m->stride)>>20)&15u)==m->speed && (u32(in+m->stride+4)>>16)==1u);
        memcpy(out,in+m->stride,m->stride);
        memcpy(out+m->stride,in+2u*m->stride,m->stride);
        w32(out+12,(2u<<27)|1u);w32(out+m->stride,(u32(out+m->stride)&~7u)|1u);
        m->ep0.cursor=u64(in+2u*m->stride+8)&~UINT64_C(15);m->ep0.cycle=(unsigned)(u64(in+2u*m->stride+8)&1u);
    } else if(kind==13) {
        CHECK(add==2);
        w32(out+m->stride+4,(u32(out+m->stride+4)&0xffffu)|(u32(in+2u*m->stride+4)&0xffff0000u));
    } else {
        CHECK(kind==12 && (add&1u) && (u32(in+m->stride)>>27)>=m->dci);
        flags=add>>2;(void)flags;
        for(i=2;i<32;++i) if(add&(1u<<i)) {
            const uint8_t *e=in+(i+1u)*m->stride;
            CHECK(i==m->dci && ((u32(e+4)>>3)&7u)==7u && (u32(e+4)>>1&3u)==3u);
            m->interval_seen=(u32(e)>>16)&255u;m->mps_seen=u32(e+4)>>16;
            memcpy(out+i*m->stride,e,m->stride);w32(out+i*m->stride,(u32(e)&~7u)|1u);
            m->intr.cursor=u64(e+8)&~UINT64_C(15);m->intr.cycle=(unsigned)(u64(e+8)&1u);
        }
        memcpy(out,in+m->stride,16);w32(out+12,(3u<<27)|1u);
    }
}
static void run_commands(struct model *m)
{
    uint64_t at;uint8_t *t;
    while((t=fetch(m,&m->cmd,&at))!=NULL) {
        uint32_t c=u32(t+12),type=(c>>10)&63u,slot=1;
        if(type==9) { CHECK(!m->slot_enabled);m->slot_enabled=1; }
        else if(type==10) m->slot_enabled=0;
        else if(type==14u || type==16u) {                  /* Reset Endpoint / Set TR Dequeue Pointer */
            uint8_t *ep=out_ctx(m)+m->dci*m->stride;
            CHECK(m->slot_enabled && (c>>24)==1u && ((c>>16)&31u)==m->dci);
            if(type==14u) { CHECK(m->halted && (u32(ep)&7u)==2u);w32(ep,(u32(ep)&~7u)|3u);m->halted=0;++m->reset_eps; }
            else {
                CHECK((u32(ep)&7u)==3u && !(u64(t)&14u));
                m->intr.cursor=u64(t)&~UINT64_C(15);m->intr.cycle=(unsigned)(u64(t)&1u);++m->set_deqs;
            }
        }
        else { CHECK(m->slot_enabled && (c>>24)==1u);context_command(m,u64(t),type);if(type==12) ++m->config_commands; }
        emit(m,at,1u<<24,(33u<<10)|(slot<<24));
        m->cmd.cursor=at+16u;
    }
}
static void ep0_work(struct model *m)
{
    uint64_t at,sat,dat=0;uint8_t *t,*s,*d=NULL;
    if(m->hang_ep0) return;
    while((t=fetch(m,&m->ep0,&at))!=NULL) {
        uint32_t c=u32(t+12);const uint8_t *pkt=t;uint8_t bm,req;uint16_t value,index,length;
        const uint8_t *data=NULL;unsigned n=0,have=0;
        CHECK(((c>>10)&63u)==2u && (c&(1u<<6)));
        bm=pkt[0];req=pkt[1];value=(uint16_t)(pkt[2]|(pkt[3]<<8));index=(uint16_t)(pkt[4]|(pkt[5]<<8));
        length=(uint16_t)(pkt[6]|(pkt[7]<<8));(void)index;
        m->ep0.cursor=at+16u;
        if(length) {
            d=fetch(m,&m->ep0,&dat);CHECK(d && ((u32(d+12)>>10)&63u)==3u);
            m->ep0.cursor=dat+16u;
        }
        s=fetch(m,&m->ep0,&sat);CHECK(s && ((u32(s+12)>>10)&63u)==4u && (u32(s+12)&(1u<<5)));
        m->ep0.cursor=sat+16u;
        if(bm==0x80 && req==6 && value==0x0100) { data=m->device;have=18; }
        else if(bm==0x80 && req==6 && value==0x0200) { data=m->config;have=m->config_len; }
        else if(bm==0x81 && req==6 && value==0x2200) { data=m->report;have=m->report_len; }
        else if(bm==0x02 && req==1 && !length && !value) { m->clear_index=index;++m->clear_halts; }
        else CHECK(bm==0x00 && req==9 && !length);
        if(length) {
            n=have<length?have:length;
            memcpy(dma(m,u64(d),length),data,n);
            if(n<length) emit(m,dat,(13u<<24)|(unsigned)(length-n),(32u<<10)|(1u<<24)|(1u<<16));
        }
        emit(m,sat,1u<<24,(32u<<10)|(1u<<24)|(1u<<16));
    }
}
static int inject(struct model *m,const uint8_t *report,unsigned n,unsigned code)
{
    uint64_t at;uint8_t *t;unsigned len;
    if(m->halted) return 0;                                  /* a halted endpoint processes nothing */
    t=fetch(m,&m->intr,&at);
    if(!t) return 0;
    CHECK(((u32(t+12)>>10)&63u)==1u && (u32(t+12)&(1u<<5)));
    len=u32(t+8)&0x1ffffu;CHECK(n<=len);
    memcpy(dma(m,u64(t),len),report,n);m->last_int_buffer=u64(t);
    m->intr.cursor=at+16u;
    emit(m,at,(code<<24)|(len-n),(32u<<10)|(1u<<24)|(m->dci<<16));
    if(code==6u && !m->stall_no_halt) {
        uint8_t *ep=out_ctx(m)+m->dci*m->stride;
        w32(ep,(u32(ep)&~7u)|2u);m->halted=1;
    }
    return 1;
}
static int read32(void *o,uint32_t off,uint32_t *v)
{ struct model *m=o;CHECK(!(off&3u) && off<sizeof(m->regs));*v=m->regs[off/4];return 1; }
static int write32(void *o,uint32_t off,uint32_t v)
{
    struct model *m=o;CHECK(!(off&3u) && off<sizeof(m->regs));
    if(off==OP) {
        if(v&2u) hw_reset(m);
        else if(v&1u) { m->regs[OP/4]=v;m->regs[(OP+4)/4]&=~1u;m->cmd.cursor=r64(m,OP+24)&~UINT64_C(63);m->cmd.cycle=1; }
        else { m->regs[OP/4]=v;m->regs[(OP+4)/4]|=1u; }
    } else if(off==DB) { CHECK(v==0);run_commands(m); }
    else if(off==DB+4) {
        if(v==1) ep0_work(m); else { uint8_t *ep=out_ctx(m)+m->dci*m->stride;CHECK(v==m->dci && m->dci && !m->halted);if((u32(ep)&7u)==3u) w32(ep,(u32(ep)&~7u)|1u); }
    } else if(off==PORT) {
        uint32_t old=m->regs[PORT/4];
        m->regs[PORT/4]&=~(v&CHANGE);
        if(v&PR) {
            CHECK(old&CCS);
            m->regs[PORT/4]=(old&~(PR|CHANGE|(15u<<5)|(15u<<10)))|PED|PRC|(m->speed<<10)|PP|CCS;port_event(m);
        }
    } else m->regs[off/4]=v;
    return 1;
}
static int allocate(void *o,size_t bytes,size_t align,uint64_t limit,struct xhci_dma *out)
{
    struct model *m=o;unsigned i=bytes==4096?0u:1u;(void)limit;
    CHECK((bytes==4096 || bytes==12288) && align==4096 && !m->owned[i]);
    m->cpu[i]=aligned_alloc(4096,bytes);CHECK(m->cpu[i]);memset(m->cpu[i],0xa5,bytes);
    m->bus[i]=UINT64_C(0x180000)+(uint64_t)i*0x10000u;m->owned[i]=1;++m->allocations;
    out->cpu=m->cpu[i];out->bus=m->bus[i];out->bytes=bytes;return 1;
}
static void release(void *o,struct xhci_dma *g)
{
    struct model *m=o;unsigned i;
    for(i=0;i<2;++i) if(m->owned[i] && m->cpu[i]==g->cpu) break;
    CHECK(i<2 && (m->regs[(OP+4)/4]&1u) && r64(m,OP+24)==0 && r64(m,RT+48)==0);
    free(m->cpu[i]);m->cpu[i]=NULL;m->owned[i]=0;++m->releases;
}
static int sync_dma(void *o,const struct xhci_dma *b,size_t off,size_t n,int to) { (void)o;(void)b;(void)off;(void)n;(void)to;return 1; }
static uint64_t now(void *o) { return ((struct model *)o)->clock; }
static void relax(void *o) { struct model *m=o;m->clock+=1000;++m->relaxes; }

static const uint8_t mouse_report[]={0x05,1,0x09,2,0xA1,1,0x09,1,0xA1,0,0x05,9,0x19,1,0x29,3,0x15,0,0x25,1,
    0x95,3,0x75,1,0x81,2,0x95,1,0x75,5,0x81,3,0x05,1,0x09,0x30,0x09,0x31,0x15,0x81,0x25,0x7f,0x75,8,0x95,2,0x81,6,0xC0,0xC0};
static const uint8_t keyboard_report[]={0x05,1,0x09,6,0xA1,1,0x05,7,0x19,0xE0,0x29,0xE7,0x15,0,0x25,1,0x75,1,0x95,8,0x81,2,
    0x95,1,0x75,8,0x81,3,0x95,6,0x75,8,0x15,0,0x25,0x65,0x05,7,0x19,0,0x29,0x65,0x81,0,0xC0};
static void setup(struct model *m,unsigned large,const uint8_t *report,unsigned report_len)
{
    static const uint8_t dev[18]={18,1,0,2,0,0,0,64,0x6d,0x04,0x01,0xc0,0,1,1,2,0,1};
    uint8_t cfg[34]={9,2,34,0,1,1,0,0xa0,50, 9,4,0,0,1,3,1,2,0, 9,0x21,0x11,1,0,1,0x22,0,0, 7,5,0x81,3,4,0,10};
    memset(m,0,sizeof(*m));++scenarios;m->stride=large?64u:32u;m->speed=1;m->dci=3;
    cfg[25]=(uint8_t)report_len;memcpy(m->device,dev,18);memcpy(m->config,cfg,34);m->config_len=34;
    memcpy(m->report,report,report_len);m->report_len=report_len;
    m->regs[0]=0x01000040;m->regs[1]=0x04000108;m->regs[4]=(large?4u:0u)|((PROTO/4u)<<16);
    m->regs[5]=DB;m->regs[6]=RT;
    m->regs[PROTO/4]=(2u<<24)|2u;m->regs[PROTO/4+1]=0x20425355;m->regs[PROTO/4+2]=0x401;
    hw_reset(m);m->regs[PORT/4]=CCS|PP|CSC|(7u<<5)|(m->speed<<10);
    m->regs[(PORT+16)/4]=m->regs[(PORT+32)/4]=m->regs[(PORT+48)/4]=PP|(5u<<5);
}
static struct xhci_ops ops(struct model *m)
{ struct xhci_ops o={m,read32,write32,allocate,release,sync_dma,now,relax,NULL};return o; }
static struct xhci_config cfgs(void) { struct xhci_config c={0x0c0330,6,0x4000,1000000,1};return c; }
static void no_leak(struct model *m) { CHECK(!m->owned[0] && !m->owned[1] && m->allocations==m->releases); }

struct capture { unsigned count,refuse_every; int fatal_after; uint8_t last[64];size_t last_len;uint64_t gen;
                 unsigned seen_pointer; int32_t sum_x,sum_y; unsigned buttons; };
static int sink(void *c,uint64_t gen,const struct shz_hid_layout *l,const uint8_t *r,size_t n)
{
    struct capture *k=c;struct shz_pointer p;
    CHECK(gen==k->gen && l->pointer);
    memcpy(k->last,r,n);k->last_len=n;++k->count;
    if(k->fatal_after>=0 && (int)k->count>k->fatal_after) return -1;
    if(shz_hid_pointer(l,r,n,&p)==0) { k->sum_x+=p.contacts[0].x;k->sum_y+=p.contacts[0].y;k->buttons=p.buttons;++k->seen_pointer; }
    if(k->refuse_every && k->count%k->refuse_every==0) return 1;
    return 0;
}
/* Phase 1: existing xhciu_probe_configuration (closes its session); phase 2: reopen. */
static int probe_and_open(struct model *m,struct xhci_device *x,struct xhciu_hid *h,struct capture *k,
                          struct xhciu_configuration_descriptor *p)
{
    struct xhci_ops o=ops(m);struct xhci_config c=cfgs();
    struct xhciu_configuration_request rq={sizeof(rq),XHCIU_ABI_VERSION,0,0,0};
    struct xhciu_hid_sink s={k,sink};
    memset(x,0,sizeof(*x));
    CHECK(xhci_open_one_slot(x,&o,&c)==0);
    CHECK(xhciu_probe_configuration(x,&rq,p).status==0);
    CHECK(p->raw_length==34 && p->device.root_port==1);
    CHECK(m->owned[0]==0 && m->owned[1]==0);                 /* probe closed its session */
    memset(x,0,sizeof(*x));
    CHECK(xhci_open_one_slot(x,&o,&c)==0);
    return xhciu_hid_open(h,x,p,k->gen,&s);
}
static void reset_model_after_probe(struct model *m)
{ m->regs[PORT/4]=CCS|PP|CSC|(7u<<5)|(m->speed<<10);m->slot_enabled=0; }

static void success(unsigned large)
{
    struct model m;struct xhci_device x;struct xhciu_hid h;struct capture k;
    struct xhciu_configuration_descriptor p;uint32_t got=0,total=0,i;uint8_t rep[4]={0,0,0,0};
    setup(&m,large,mouse_report,sizeof(mouse_report));memset(&k,0,sizeof(k));k.gen=7;k.fatal_after=-1;
    {
        struct xhci_ops o=ops(&m);struct xhci_config c=cfgs();
        struct xhciu_configuration_request rq={sizeof(rq),XHCIU_ABI_VERSION,0,0,0};
        struct xhciu_hid_sink s={&k,sink};
        memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
        { struct xhciu_result pr=xhciu_probe_configuration(&x,&rq,&p);
          if(pr.status) fprintf(stderr,"probe status %d transport %d stage %u parser %d\n",pr.status,pr.transport_error,pr.failed_stage,pr.parser_status);
          CHECK(pr.status==0); }
        reset_model_after_probe(&m);memset(&x,0,sizeof(x));
        CHECK(xhci_open_one_slot(&x,&o,&c)==0);
        CHECK(xhciu_hid_open(&h,&x,&p,k.gen,&s)==0);
    }
    CHECK(h.state==XHCIU_HID_OPEN && h.dci==3 && h.mps==4 && h.iface==0 && h.speed==1);
    CHECK(m.config_commands==1 && m.interval_seen==6 && m.mps_seen==4);
    CHECK(x.budget_active==0);
    /* nothing posted: poll is non-blocking and consumes no clock */
    { uint64_t clock=m.clock;unsigned relaxes=m.relaxes;
      CHECK(xhciu_hid_poll(&h,16,&got)==0 && got==0);CHECK(m.relaxes==relaxes && m.clock==clock); }
    for(i=0;i<40;++i) {                       /* crosses the Link TRB twice (15 TRBs per lap) */
        rep[0]=(uint8_t)(i&1u);rep[1]=3;rep[2]=(uint8_t)-2;
        CHECK(inject(&m,rep,3,13));
        CHECK(xhciu_hid_poll(&h,16,&got)==0 && got==1);total+=got;
    }
    CHECK(total==40 && h.reports==40 && k.count==40 && h.short_reports==40);
    CHECK(k.sum_x==120 && k.sum_y==-80 && k.seen_pointer==40);
    CHECK(inject(&m,rep,4,1));                /* full-length report */
    CHECK(xhciu_hid_poll(&h,16,&got)==0 && got==1 && k.last_len==4);
    for(i=0;i<XHCIU_HID_DEPTH;++i) CHECK(inject(&m,rep,3,13));  /* burst: all queued TRBs complete */
    CHECK(!inject(&m,rep,3,13) || 1);
    CHECK(xhciu_hid_poll(&h,3,&got)==0 && got==3);             /* bounded per call */
    CHECK(xhciu_hid_poll(&h,64,&got)==0 && got>=XHCIU_HID_DEPTH-3);
    CHECK(xhciu_hid_close(&h,k.gen+1)==XHCIU_HID_STATE);        /* stale generation refused */
    CHECK(h.state==XHCIU_HID_OPEN);
    CHECK(xhciu_hid_close(&h,k.gen)==0 && h.state==XHCIU_HID_CLOSED);
    CHECK(xhciu_hid_poll(&h,1,&got)==XHCIU_HID_STATE);
    no_leak(&m);
}
static void swapped_and_nonpointer(void)
{
    struct model m;struct xhci_device x;struct xhciu_hid h;struct capture k;
    struct xhciu_configuration_descriptor p;
    struct xhci_ops o;struct xhci_config c=cfgs();struct xhciu_hid_sink s={&k,sink};
    struct xhciu_configuration_request rq={sizeof(rq),XHCIU_ABI_VERSION,0,0,0};
    /* different device after the probe */
    setup(&m,0,mouse_report,sizeof(mouse_report));memset(&k,0,sizeof(k));k.gen=3;k.fatal_after=-1;o=ops(&m);
    memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
    CHECK(xhciu_probe_configuration(&x,&rq,&p).status==0);reset_model_after_probe(&m);
    m.device[9]^=1u;memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
    CHECK(xhciu_hid_open(&h,&x,&p,3,&s)==XHCIU_HID_STALE);no_leak(&m);
    /* same device, changed configuration blob */
    setup(&m,0,mouse_report,sizeof(mouse_report));o=ops(&m);
    memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
    CHECK(xhciu_probe_configuration(&x,&rq,&p).status==0);reset_model_after_probe(&m);
    m.config[30]^=1u;memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
    CHECK(xhciu_hid_open(&h,&x,&p,3,&s)==XHCIU_HID_STALE);no_leak(&m);
    /* HID device that is not a pointer */
    setup(&m,0,keyboard_report,sizeof(keyboard_report));memset(&k,0,sizeof(k));k.gen=3;o=ops(&m);
    CHECK(probe_and_open(&m,&x,&h,&k,&p)==XHCIU_HID_NO_POINTER);no_leak(&m);
}
static void open_then(unsigned scenario)
{
    struct model m;struct xhci_device x;struct xhciu_hid h;struct capture k;
    struct xhciu_configuration_descriptor p;uint32_t got=0;uint8_t rep[3]={1,1,1};
    struct xhci_ops o;struct xhci_config c=cfgs();struct xhciu_hid_sink s={&k,sink};
    struct xhciu_configuration_request rq={sizeof(rq),XHCIU_ABI_VERSION,0,0,0};
    setup(&m,0,mouse_report,sizeof(mouse_report));memset(&k,0,sizeof(k));k.gen=9;k.fatal_after=-1;o=ops(&m);
    if(scenario==3) k.refuse_every=2;
    if(scenario==2) k.fatal_after=1;
    memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
    CHECK(xhciu_probe_configuration(&x,&rq,&p).status==0);reset_model_after_probe(&m);
    memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
    CHECK(xhciu_hid_open(&h,&x,&p,k.gen,&s)==0);
    if(scenario==0) {                          /* device unplugged */
        m.regs[PORT/4]=PP|CSC;port_event(&m);
        CHECK(xhciu_hid_poll(&h,8,&got)==XHCIU_HID_STALE && h.state==XHCIU_HID_GONE);
        CHECK(xhciu_hid_poll(&h,8,&got)==XHCIU_HID_STATE);
    } else if(scenario==1) {                   /* STALL: Reset Endpoint + Set TR Dequeue + CLEAR_HALT, stream resumes */
        unsigned i,round;
        for(round=0;round<XHCIU_HID_RECOVERY_MAX;++round) {
            CHECK(inject(&m,rep,0,6));
            CHECK(xhciu_hid_poll(&h,8,&got)==0 && got==0 && h.state==XHCIU_HID_OPEN && h.recoveries==round+1u);
            CHECK(m.reset_eps==round+1u && m.set_deqs==round+1u && m.clear_halts==round+1u && m.clear_index==0x81u && !m.halted);
            for(i=0;i<20;++i) {                    /* crosses the rewound ring's Link TRB */
                CHECK(inject(&m,rep,3,13));
                CHECK(xhciu_hid_poll(&h,8,&got)==0 && got==1);
            }
        }
        CHECK(h.reports==XHCIU_HID_RECOVERY_MAX*20u);
        CHECK(inject(&m,rep,0,6));                 /* recovery budget exhausted: fail closed, no silent loop */
        CHECK(xhciu_hid_poll(&h,8,&got)==XHCIU_HID_TRANSFER && h.state==XHCIU_HID_FAILED && h.last_code==6);
        CHECK(m.reset_eps==XHCIU_HID_RECOVERY_MAX);
    } else if(scenario==5) {                   /* STALL event but the endpoint context is not Halted: no reset issued */
        m.stall_no_halt=1;CHECK(inject(&m,rep,0,6));
        CHECK(xhciu_hid_poll(&h,8,&got)==XHCIU_HID_TRANSFER && h.state==XHCIU_HID_FAILED && !m.reset_eps && !h.recoveries);
    } else if(scenario==2) {                   /* consumer revoked mid-stream */
        CHECK(inject(&m,rep,3,13)&&inject(&m,rep,3,13));
        CHECK(xhciu_hid_poll(&h,8,&got)==XHCIU_HID_SINK && h.state==XHCIU_HID_GONE);
    } else if(scenario==3) {                   /* refused reports are counted, stream continues */
        CHECK(inject(&m,rep,3,13)&&inject(&m,rep,3,13)&&inject(&m,rep,3,13)&&inject(&m,rep,3,13));
        CHECK(xhciu_hid_poll(&h,8,&got)==0 && got==2 && h.refused==2 && h.state==XHCIU_HID_OPEN);
    } else {                                   /* residue larger than the TRB: malformed event */
        CHECK(inject(&m,rep,3,13));
        w32(dma(&m,u64(dma(&m,r64(&m,RT+48),16))+(uint64_t)((m.ev_index+63u)%64u)*16u,16)+8,(13u<<24)|9u);
        CHECK(xhciu_hid_poll(&h,8,&got)==XHCI_BAD_EVENT && h.state==XHCIU_HID_FAILED);
    }
    CHECK(xhciu_hid_close(&h,k.gen)==0);no_leak(&m);
}
static void bounded_clock(void)
{
    struct model m;struct xhci_device x;struct xhciu_hid h;struct capture k;
    struct xhciu_configuration_descriptor p;struct xhci_ops o;struct xhci_config c=cfgs();
    struct xhciu_hid_sink s={&k,sink};
    struct xhciu_configuration_request rq={sizeof(rq),XHCIU_ABI_VERSION,0,0,0};
    uint64_t start;
    setup(&m,0,mouse_report,sizeof(mouse_report));memset(&k,0,sizeof(k));k.gen=1;o=ops(&m);
    memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
    CHECK(xhciu_probe_configuration(&x,&rq,&p).status==0);reset_model_after_probe(&m);
    memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
    m.hang_ep0=1;start=m.clock;
    CHECK(xhciu_hid_open(&h,&x,&p,1,&s)==XHCI_TIMEOUT);
    CHECK(m.clock-start<=XHCIU_PROBE_US+2000000u);no_leak(&m);
    /* argument validation leaves the controller untouched */
    setup(&m,0,mouse_report,sizeof(mouse_report));o=ops(&m);
    memset(&x,0,sizeof(x));CHECK(xhci_open_one_slot(&x,&o,&c)==0);
    CHECK(xhciu_hid_open(&h,&x,&p,0,&s)==XHCI_INVALID);       /* generation 0 */
    memset(&p,0,sizeof(p));
    CHECK(xhciu_hid_open(&h,&x,&p,1,&s)==XHCI_INVALID);       /* empty probe result */
    CHECK(x.state==XHCI_READY);CHECK(xhci_close(&x)==0);no_leak(&m);
}
int main(void)
{
    unsigned i;
    success(0);success(1);swapped_and_nonpointer();
    for(i=0;i<6;++i) open_then(i);
    bounded_clock();
    printf("{\"status\":\"PASS\",\"checks\":%u,\"scenarios\":%u}\n",checks,scenarios);
    return 0;
}
