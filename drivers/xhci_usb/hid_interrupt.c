/* SPDX-License-Identifier: GPL-2.0-only -- original xHCI USB HID interrupt-IN transport. */
#include "hid_interrupt.h"
#include "../xhci_native/xhci_internal.h"

enum { PORT_CCS=1, PORT_PED=2, PORT_OCA=8, PORT_PR=16, PORT_PP=512, PORT_CSC=1u<<17,
       PORT_PRC=1u<<21, PORT_CHANGES=0x00fe0000u, PORT_KEEP=0x0e00c200u,
       EVENT_LIMIT=256u, RING_TRBS=16u, EP0_RING=XHCIU_RING_OFFSET };

static uint32_t port_reg(const struct xhci_device *x,uint32_t port)
{ return x->op_base+0x400u+(port-1u)*16u; }
static void trb(uint8_t *p,uint64_t parameter,uint32_t status,uint32_t control)
{ xhci_i_put64(p,parameter);xhci_i_put32(p+8,status);xhci_i_put32(p+12,control); }
static uint32_t rd16(const uint8_t *p) { return (uint32_t)p[0]|((uint32_t)p[1]<<8); }

/* Gone/stale detection for our single port. */
static int port_check(struct xhciu_hid *h,int clear)
{
    struct xhci_device *x=h->x;uint32_t s;int r=xhci_i_read(x,port_reg(x,h->port),&s);
    if(r) return r;
    if(!(s&PORT_CCS) || !(s&PORT_PED) || (s&PORT_PR) || (s&PORT_CSC) ||
       (h->speed && ((s>>10)&15u)!=h->speed)) return XHCIU_HID_STALE;
    if(clear && (s&PORT_CHANGES))
        return xhci_i_write(x,port_reg(x,h->port),(s&PORT_KEEP)|(s&PORT_CHANGES));
    return XHCI_OK;
}
static int wait_us(struct xhci_device *x,uint32_t us)
{
    struct xhci_deadline d;uint64_t now;int r;
    xhci_i_begin(x,&d);
    for(;;) {
        if((r=xhci_i_health(x))!=0) return r;
        now=x->ops.now_us(x->ops.context);
        if(now<d.last) return XHCI_CLOCK;
        d.last=now;
        if(now-d.start>=us) return XHCI_OK;
        if((r=xhci_i_expired(x,&d,XHCIU_PROBE_US))!=0) return r;
    }
}
/* Ring producer: reserves the next TRB slot, writing/toggling the Link TRB first. */
static int ring_next(struct xhci_device *x,uint32_t base,uint32_t *index,uint32_t *cycle,
                     uint32_t *offset,uint32_t *slot_cycle)
{
    int r;
    if(*index>=RING_TRBS-1u) {
        uint32_t lo=base+(RING_TRBS-1u)*16u;
        trb((uint8_t *)x->device_dma.cpu+lo,x->device_dma.bus+base,0,(6u<<10)|2u|*cycle);
        if((r=xhci_i_sync(x,&x->device_dma,lo,16u,1))!=0) return r;
        *index=0;*cycle^=1u;
    }
    *offset=base+*index*16u;*slot_cycle=*cycle;++*index;return XHCI_OK;
}
static int control(struct xhciu_hid *h,uint32_t bm,uint32_t req,uint32_t value,uint32_t index,
                   uint32_t len,int in)
{
    struct xhci_device *x=h->x;uint8_t *base=x->device_dma.cpu;
    uint32_t so,sc,dof=0,dc=0,to,tc,seen=0,residue=0,short_seen=0,kind,code,i;
    uint64_t data_ptr=0,status_ptr,pointer;struct xhci_event ev;struct xhci_deadline d;int r;
    if(len>XHCIU_HID_CONTROL_BYTES) return XHCI_INVALID;
    if(len) {
        for(i=0;i<len;++i) base[XHCIU_HID_CONTROL_BUFFER+i]=0xa5u;
        if((r=xhci_i_sync(x,&x->device_dma,XHCIU_HID_CONTROL_BUFFER,len,1))!=0) return r;
    }
    if((r=ring_next(x,EP0_RING,&h->ep0_index,&h->ep0_cycle,&so,&sc))!=0) return r;
    trb(base+so,(uint64_t)bm|((uint64_t)req<<8)|((uint64_t)value<<16)|((uint64_t)index<<32)|
        ((uint64_t)len<<48),8,(2u<<10)|(1u<<6)|((len?(in?3u:2u):0u)<<16)|(sc^1u));
    if(len) {
        if((r=ring_next(x,EP0_RING,&h->ep0_index,&h->ep0_cycle,&dof,&dc))!=0) return r;
        trb(base+dof,x->device_dma.bus+XHCIU_HID_CONTROL_BUFFER,len,
            (3u<<10)|(in?(1u<<16):0u)|(1u<<2)|dc);
        data_ptr=x->device_dma.bus+dof;
    }
    if((r=ring_next(x,EP0_RING,&h->ep0_index,&h->ep0_cycle,&to,&tc))!=0) return r;
    trb(base+to,0,0,(4u<<10)|(1u<<5)|((len&&in)?0u:(1u<<16))|tc);
    status_ptr=x->device_dma.bus+to;
    if((r=xhci_i_sync(x,&x->device_dma,EP0_RING,RING_TRBS*16u,1))!=0) return r;
    xhci_i_put32(base+so+12,xhci_i_get32(base+so+12)^1u);
    if((r=xhci_i_sync(x,&x->device_dma,so+12u,4u,1))!=0 ||
       (r=xhci_i_write(x,x->doorbell_base+h->slot*4u,1))!=0) return r;
    xhci_i_begin(x,&d);
    for(;;) {
        if((r=xhci_i_event(x,&d,&ev))!=0) return r;
        kind=(ev.word[3]>>10)&63u;
        if(kind==34u) {
            if(++seen>EVENT_LIMIT) return XHCI_EVENT_LIMIT;
            if((r=port_check(h,0))!=0) return r;
        } else if(kind==32u) {
            pointer=(uint64_t)ev.word[0]|((uint64_t)ev.word[1]<<32);
            code=ev.word[2]>>24;h->last_code=code;
            if((ev.word[3]&4u) || (ev.word[3]>>24)!=h->slot || ((ev.word[3]>>16)&31u)!=1u)
                return XHCI_BAD_EVENT;
            if(len && pointer==data_ptr && code==13u) {
                if(short_seen) return XHCI_BAD_EVENT;
                short_seen=1;residue=ev.word[2]&0xffffffu;
            } else if(pointer==status_ptr) {
                if(code!=1u) return XHCI_COMPLETION_ERROR;
                if((r=xhci_i_ack(x))!=0) return r;
                break;
            } else return code==1u?XHCI_BAD_EVENT:XHCI_COMPLETION_ERROR;
        } else return XHCI_BAD_EVENT;
        if((r=xhci_i_ack(x))!=0 || (r=xhci_i_expired(x,&d,x->timeout_us))!=0) return r;
    }
    if(residue) return XHCIU_SHORT_READ;
    if(len && (r=xhci_i_sync(x,&x->device_dma,XHCIU_HID_CONTROL_BUFFER,len,0))!=0) return r;
    return XHCI_OK;
}

static int reset_port(struct xhciu_hid *h,uint32_t request_port)
{
    struct xhci_device *x=h->x;struct xhci_deadline d;uint32_t s;int r;
    if(!request_port || request_port>x->max_ports) return XHCI_INVALID;
    h->port=request_port;
    if((r=xhci_i_read(x,port_reg(x,h->port),&s))!=0) return r;
    if(!(s&PORT_CCS)) return XHCIU_DISCONNECTED;
    if(!(s&PORT_PP) || (s&PORT_OCA) || (s&PORT_PR)) return XHCI_UNSUPPORTED;
    if((r=xhci_i_write(x,port_reg(x,h->port),(s&PORT_KEEP)|(s&PORT_CHANGES)))!=0 ||
       (r=wait_us(x,XHCIU_DEBOUNCE_US))!=0 ||
       (r=xhci_i_read(x,port_reg(x,h->port),&s))!=0) return r;
    if(!(s&PORT_CCS)) return XHCIU_DISCONNECTED;
    if((r=xhci_i_write(x,port_reg(x,h->port),(s&PORT_KEEP)|(s&PORT_CHANGES)))!=0 ||
       (r=xhci_i_read(x,port_reg(x,h->port),&s))!=0) return r;
    if(!(s&PORT_CCS) || (s&PORT_PR) || (s&PORT_CHANGES)) return XHCIU_DISCONNECTED;
    if((r=xhci_i_write(x,port_reg(x,h->port),(s&PORT_KEEP)|PORT_PR))!=0) return r;
    xhci_i_begin(x,&d);
    for(;;) {
        if((r=xhci_i_health(x))!=0 || (r=xhci_i_read(x,port_reg(x,h->port),&s))!=0) return r;
        if(!(s&PORT_CCS)) return XHCIU_DISCONNECTED;
        if(s&PORT_PRC) break;
        if((r=xhci_i_expired(x,&d,x->timeout_us))!=0) return r;
    }
    if((s&(PORT_PR|PORT_PED))!=PORT_PED || ((s>>5)&15u)!=0u) return XHCIU_DISCONNECTED;
    h->speed=(s>>10)&15u;
    if(h->speed<1u || h->speed>3u) return XHCI_UNSUPPORTED;
    if((r=xhci_i_write(x,port_reg(x,h->port),(s&PORT_KEEP)|(s&PORT_CHANGES)))!=0) return r;
    return wait_us(x,XHCIU_RESET_RECOVERY_US);
}

static int context_input(struct xhciu_hid *h,int phase)
{
    struct xhci_device *x=h->x;uint8_t *base=x->device_dma.cpu,*in=base+XHCIU_INPUT_OFFSET;
    uint32_t stride=h->stride,i;uint8_t *slot=in+stride,*ep0=in+2u*stride;
    xhci_i_zero(in,33u*stride);
    if(phase==0) { /* Address Device: A0|A1 */
        xhci_i_put32(in+4,3u);
        xhci_i_put32(slot,(h->speed<<20)|(1u<<27));xhci_i_put32(slot+4,h->port<<16);
        xhci_i_put32(ep0+4,(h->ep0_packet<<16)|(4u<<3)|(3u<<1));
        xhci_i_put64(ep0+8,(x->device_dma.bus+EP0_RING)|1u);xhci_i_put32(ep0+16,8u);
    } else if(phase==1) { /* Evaluate Context: A1 only consumes EP0 max packet */
        xhci_i_put32(in+4,2u);xhci_i_put32(ep0+4,h->ep0_packet<<16);
    } else { /* Configure Endpoint: A0|A(dci); slot copied from the output context */
        uint8_t *ep=in+(h->dci+1u)*stride;
        xhci_i_put32(in+4,1u|(1u<<h->dci));
        for(i=0;i<32u;i+=4u) xhci_i_put32(slot+i,xhci_i_get32(base+i));
        xhci_i_put32(slot,(xhci_i_get32(slot)&~(31u<<27))|(h->dci<<27));
        xhci_i_put32(ep,h->interval<<16);
        xhci_i_put32(ep+4,(h->mps<<16)|(7u<<3)|(3u<<1));
        xhci_i_put64(ep+8,(x->device_dma.bus+XHCIU_HID_INT_RING)|1u);
        xhci_i_put32(ep+16,h->mps|(h->mps<<16));
    }
    return xhci_i_sync(x,&x->device_dma,XHCIU_INPUT_OFFSET,33u*stride,1);
}
static int output_check(struct xhciu_hid *h,uint32_t state_code,uint32_t ep_dci)
{
    struct xhci_device *x=h->x;uint8_t *base=x->device_dma.cpu;uint32_t slot,status,ep;int r;
    if((r=xhci_i_sync(x,&x->device_dma,0,(ep_dci+1u)*h->stride,0))!=0) return r;
    slot=xhci_i_get32(base);status=xhci_i_get32(base+12);
    if(((slot>>20)&15u)!=h->speed || ((xhci_i_get32(base+4)>>16)&255u)!=h->port ||
       (status>>27)!=state_code || !(status&255u)) return XHCI_BAD_EVENT;
    ep=xhci_i_get32(base+ep_dci*h->stride);
    if((ep&7u)!=1u) return XHCI_BAD_EVENT; /* endpoint must be Running */
    return XHCI_OK;
}
/* Configure Endpoint (type 12): xhci_i_command only admits 9/10/11/13. This
 * follows its exact command-ring protocol using the same public device state. */
static int slot_command(struct xhciu_hid *h,uint32_t type,uint64_t param,uint32_t ctl)
{
    struct xhci_device *x=h->x;uint8_t *ring=x->dma.cpu;uint32_t offset,seen=0,kind;
    uint64_t submitted,pointer;
    struct xhci_event ev;struct xhci_deadline d;int r;
    if(x->command_index>=XHCI_COMMAND_TRBS-1u || x->command_cycle>1u) return XHCI_INVALID;
    if((r=xhci_i_health(x))!=0) return r;
    if(x->command_index==XHCI_COMMAND_TRBS-2u) {
        uint32_t lo=XHCI_COMMAND_OFFSET+(XHCI_COMMAND_TRBS-1u)*16u;
        trb(ring+lo,x->dma.bus+XHCI_COMMAND_OFFSET,0,(6u<<10)|2u|(x->command_cycle^1u));
        if((r=xhci_i_sync(x,&x->dma,lo,16u,1))!=0) return r;
        xhci_i_put32(ring+lo+12,(6u<<10)|2u|x->command_cycle);
        if((r=xhci_i_sync(x,&x->dma,lo+12u,4u,1))!=0) return r;
    }
    offset=XHCI_COMMAND_OFFSET+x->command_index*16u;submitted=x->dma.bus+offset;
    trb(ring+offset,param,0,(type<<10)|ctl|(x->command_cycle^1u));
    if((r=xhci_i_sync(x,&x->dma,offset,16u,1))!=0) return r;
    xhci_i_put32(ring+offset+12,(type<<10)|ctl|x->command_cycle);
    if((r=xhci_i_sync(x,&x->dma,offset+12u,4u,1))!=0 ||
       (r=xhci_i_write(x,x->doorbell_base,0))!=0) return r;
    xhci_i_begin(x,&d);
    for(;;) {
        if((r=xhci_i_event(x,&d,&ev))!=0) return r;
        kind=(ev.word[3]>>10)&63u;
        if(kind==33u) {
            pointer=(uint64_t)ev.word[0]|((uint64_t)ev.word[1]<<32);
            x->last_completion_pointer=pointer;x->last_completion_code=ev.word[2]>>24;
            if(pointer!=submitted || (ev.word[2]&0xffffffu) || (ev.word[3]>>24)!=h->slot)
                return XHCI_BAD_EVENT;
            if(x->last_completion_code!=1u) return XHCI_COMPLETION_ERROR;
        } else if(kind==34u) {
            if(++seen>EVENT_LIMIT) return XHCI_EVENT_LIMIT;
        } else return XHCI_BAD_EVENT;
        if((r=xhci_i_ack(x))!=0) return r;
        if(kind==33u) break;
        if((r=xhci_i_expired(x,&d,x->timeout_us))!=0) return r;
    }
    if(++x->command_index==XHCI_COMMAND_TRBS-1u) { x->command_index=0;x->command_cycle^=1u; }
    ++x->commands_completed;return xhci_i_health(x);
}

static int queue_one(struct xhciu_hid *h);
static int configure_command(struct xhciu_hid *h)
{ return slot_command(h,12u,h->x->device_dma.bus+XHCIU_INPUT_OFFSET,1u<<24); }

/* Endpoint context state (0 disabled, 1 running, 2 halted, 3 stopped, 4 error) read from the output device context. */
static int ep_state(struct xhciu_hid *h,uint32_t *state)
{
    struct xhci_device *x=h->x;int r;
    if((r=xhci_i_sync(x,&x->device_dma,h->dci*h->stride,4u,0))!=0) return r;
    *state=xhci_i_get32((uint8_t *)x->device_dma.cpu+h->dci*h->stride)&7u;return XHCI_OK;
}
/* Halted interrupt-IN endpoint (STALL completion): the xHC stops processing the ring. Bounded recovery per the xHCI sequence:
 * verify Halted, Reset Endpoint, rewind our ring and Set TR Dequeue Pointer, CLEAR_FEATURE(ENDPOINT_HALT) on EP0, requeue and
 * ring the doorbell. Any deviation (endpoint not halted, wrong state afterwards, command error) fails closed to the caller. */
static int recover_halt(struct xhciu_hid *h)
{
    struct xhci_device *x=h->x;uint32_t st,i;uint64_t ring=x->device_dma.bus+XHCIU_HID_INT_RING;int r;
    if(h->recoveries>=XHCIU_HID_RECOVERY_MAX) return XHCIU_HID_TRANSFER;
    if((r=ep_state(h,&st))!=0) return r;
    if(st!=2u) return XHCIU_HID_TRANSFER;                      /* only a Halted endpoint is reset */
    ++h->recoveries;
    if((r=slot_command(h,14u,0,(h->slot<<24)|(h->dci<<16)))!=0) return r;
    if((r=ep_state(h,&st))!=0) return r;
    if(st!=3u) return XHCI_BAD_EVENT;                          /* must now be Stopped */
    for(i=0;i<RING_TRBS;++i) xhci_i_zero((uint8_t *)x->device_dma.cpu+XHCIU_HID_INT_RING+i*16u,16u);
    if((r=xhci_i_sync(x,&x->device_dma,XHCIU_HID_INT_RING,RING_TRBS*16u,1))!=0) return r;
    h->int_index=0;h->int_cycle=1;
    if((r=slot_command(h,16u,ring|1u,(h->slot<<24)|(h->dci<<16)))!=0) return r;
    if((r=control(h,0x02,1,0,0x80u|(h->dci>>1),0,0))!=0) return r;   /* ENDPOINT_HALT cleared on the device */
    for(i=0;i<XHCIU_HID_DEPTH;++i) if((r=queue_one(h))!=0) return r;
    return xhci_i_write(x,x->doorbell_base+h->slot*4u,h->dci);
}

struct candidate { uint32_t iface,report_bytes,ep_addr,mps,interval; };
/* Walk the validated configuration blob for HID alternate-0 interfaces that own
 * exactly one interrupt-IN endpoint. Returns count (<=out_max). */
static unsigned candidates(const uint8_t *raw,uint32_t total,struct candidate *out,unsigned out_max)
{
    uint32_t pos=raw[0],len;unsigned n=0;int in_hid=0;uint32_t cur_iface=0;
    struct candidate c;uint32_t have_report=0,eps=0,have_ep=0;
    xhci_i_zero(&c,sizeof(c));
    while(pos+2u<=total) {
        len=raw[pos];
        if(len<2u || len>total-pos) return 0;
        if(raw[pos+1]==4u && len>=9u) {
            if(in_hid && have_report && have_ep && eps==1u && n<out_max) out[n++]=c;
            in_hid=raw[pos+5]==3u && raw[pos+3]==0u;cur_iface=raw[pos+2];
            xhci_i_zero(&c,sizeof(c));c.iface=cur_iface;have_report=have_ep=eps=0;
        } else if(in_hid && raw[pos+1]==0x21u && len>=9u) {
            uint32_t k,descs=raw[pos+5];
            for(k=0;k<descs && 6u+3u*(k+1u)<=len;++k)
                if(raw[pos+6u+3u*k]==0x22u) { c.report_bytes=rd16(raw+pos+7u+3u*k);have_report=1; }
        } else if(in_hid && raw[pos+1]==5u && len>=7u) {
            ++eps;
            if((raw[pos+3]&3u)==3u && (raw[pos+2]&0x80u)) {
                c.ep_addr=raw[pos+2];c.mps=rd16(raw+pos+4)&0x7ffu;c.interval=raw[pos+6];have_ep=1;
            }
        }
        pos+=len;
    }
    if(in_hid && have_report && have_ep && eps==1u && n<out_max) out[n++]=c;
    return n;
}
static uint32_t xhci_interval(uint32_t speed,uint32_t b)
{
    uint32_t v,e=0;
    if(!b) b=1;
    if(speed==3u) { if(b>16u) b=16u;return b-1u; }          /* 125 us exponent */
    v=b*8u;while(v>1u) { v>>=1;++e; }                        /* floor(log2(8*ms)) */
    return e<3u?3u:e>10u?10u:e;
}

static int queue_one(struct xhciu_hid *h)
{
    struct xhci_device *x=h->x;uint8_t *base=x->device_dma.cpu;uint32_t off,c,idx;int r;
    if((r=ring_next(x,XHCIU_HID_INT_RING,&h->int_index,&h->int_cycle,&off,&c))!=0) return r;
    idx=(off-XHCIU_HID_INT_RING)/16u;
    trb(base+off,x->device_dma.bus+XHCIU_HID_BUFFERS+idx*XHCIU_HID_REPORT_MAX,h->mps,
        (1u<<10)|(1u<<5)|(1u<<2)|(c^1u));
    if((r=xhci_i_sync(x,&x->device_dma,off,16u,1))!=0) return r;
    xhci_i_put32(base+off+12,xhci_i_get32(base+off+12)^1u);
    return xhci_i_sync(x,&x->device_dma,off+12u,4u,1);
}

int xhciu_hid_open(struct xhciu_hid *out,struct xhci_device *x,
                   const struct xhciu_configuration_descriptor *p,uint64_t generation,
                   const struct xhciu_hid_sink *sink)
{
    struct xhciu_hid *h=out;struct candidate cand[4];unsigned count,i;uint32_t total,k;
    uint32_t slot_out=0;uint8_t *base;int r;uint32_t picked=0;
    if(!h || !x || !p || !sink || !sink->report || !generation || x->state!=XHCI_READY ||
       x->enabled_slots!=1u || !x->device_dma_owned || x->dma.bytes<XHCI_DMA_BYTES ||
       x->device_dma.bytes<XHCI_DEVICE_DMA_BYTES ||
       (((x->device_dma.bus+XHCIU_HID_CONTROL_BUFFER)&0xffffu)+XHCIU_HID_CONTROL_BYTES>65536u) ||
       (((x->device_dma.bus+XHCIU_HID_BUFFERS)&0xffffu)+RING_TRBS*XHCIU_HID_REPORT_MAX>65536u) ||
       p->struct_size!=sizeof(*p) || p->abi_version!=XHCIU_ABI_VERSION ||
       p->device.abi_version!=XHCIU_ABI_VERSION || !p->device.root_port ||
       p->raw_length<9u || p->raw_length>XHCIU_CONFIGURATION_MAX || p->raw[0]!=9u ||
       p->raw[1]!=2u || rd16(p->raw+2)!=p->raw_length || !p->raw[5])
        return XHCI_INVALID;
    xhci_i_zero(h,sizeof(*h));h->x=x;h->sink=*sink;h->generation=generation;
    h->state=XHCIU_HID_FAILED;h->stride=(x->hccparams1&4u)?64u:32u;
    h->config_value=p->raw[5];total=p->raw_length;
    xhci_i_copy(h->vendor_product,&p->device.raw_device[8],4u);
    count=candidates(p->raw,total,cand,4u);
    if(!count) { r=XHCIU_HID_NO_POINTER;goto bad; }
    x->operation_error=0;x->budget_start=x->ops.now_us(x->ops.context);x->budget_last=x->budget_start;
    x->budget_us=XHCIU_PROBE_US;x->budget_active=1;
    base=x->device_dma.cpu;h->ep0_index=0;h->ep0_cycle=1;
    if((r=reset_port(h,p->device.root_port))!=0) goto bad;
    h->ep0_packet=h->speed==3u?64u:8u;
    if((r=xhci_i_command(x,9,0,0,&slot_out))!=0) goto bad;
    h->slot=slot_out;
    if((r=port_check(h,0))!=0) goto bad;
    if((r=context_input(h,0))!=0 ||
       (r=xhci_i_command(x,11,x->device_dma.bus+XHCIU_INPUT_OFFSET,1u<<24,0))!=0) goto bad;
    if((r=output_check(h,2u,1u))!=0 || (r=wait_us(x,XHCIU_ADDRESS_RECOVERY_US))!=0) goto bad;
    if((r=control(h,0x80,6,0x0100,0,8,1))!=0) goto bad;
    k=base[XHCIU_HID_CONTROL_BUFFER+7];
    if(base[XHCIU_HID_CONTROL_BUFFER]!=18u || base[XHCIU_HID_CONTROL_BUFFER+1]!=1u ||
       (h->speed==2u && k!=8u) || (h->speed==3u && k!=64u) ||
       (h->speed==1u && k!=8u && k!=16u && k!=32u && k!=64u)) { r=XHCIU_DESCRIPTOR;goto bad; }
    if(k!=h->ep0_packet) {
        h->ep0_packet=k;
        if((r=context_input(h,1))!=0 ||
           (r=xhci_i_command(x,13,x->device_dma.bus+XHCIU_INPUT_OFFSET,1u<<24,0))!=0) goto bad;
        ++x->usb_evaluates;
    }
    if((r=control(h,0x80,6,0x0100,0,18,1))!=0) goto bad;
    for(i=0;i<18u;++i) if(base[XHCIU_HID_CONTROL_BUFFER+i]!=p->device.raw_device[i]) {
        r=XHCIU_HID_STALE;goto bad;                      /* a different device is attached */
    }
    if((r=control(h,0x80,6,0x0200,0,total,1))!=0) goto bad;
    for(i=0;i<total;++i) if(base[XHCIU_HID_CONTROL_BUFFER+i]!=p->raw[i]) {
        r=XHCIU_HID_STALE;goto bad;
    }
    if((r=control(h,0x00,9,h->config_value,0,0,0))!=0) goto bad;
    for(i=0;i<count && !picked;++i) {
        if(!cand[i].report_bytes || cand[i].report_bytes>SHZ_HID_DESCRIPTOR_MAX ||
           cand[i].mps>XHCIU_HID_REPORT_MAX || !cand[i].mps) continue;
        if((r=control(h,0x81,6,0x2200,cand[i].iface,cand[i].report_bytes,1))!=0) goto bad;
        if(shz_hid_parse_report(base+XHCIU_HID_CONTROL_BUFFER,cand[i].report_bytes,&h->layout)==SHZ_DRIVER_OK &&
           h->layout.pointer) picked=i+1u;
    }
    if(!picked) { r=XHCIU_HID_NO_POINTER;goto bad; }
    --picked;h->iface=cand[picked].iface;h->mps=cand[picked].mps;
    h->dci=(cand[picked].ep_addr&15u)*2u+1u;
    if(!(cand[picked].ep_addr&15u) || h->dci>31u) { r=XHCIU_HID_ENDPOINT;goto bad; }
    h->interval=xhci_interval(h->speed,cand[picked].interval);
    if((r=port_check(h,0))!=0) goto bad;
    h->int_index=0;h->int_cycle=1;
    if((r=context_input(h,2))!=0 || (r=configure_command(h))!=0) goto bad;
    if((r=output_check(h,3u,h->dci))!=0) goto bad;
    for(i=0;i<XHCIU_HID_DEPTH;++i) if((r=queue_one(h))!=0) goto bad;
    if((r=xhci_i_write(x,x->doorbell_base+h->slot*4u,h->dci))!=0) goto bad;
    x->budget_active=0;h->state=XHCIU_HID_OPEN;
    return XHCI_OK;
bad:
    {
        int closed=xhci_i_fail(x,r);
        xhci_i_zero(h,sizeof(*h));
        return closed==XHCI_QUARANTINED?closed:r;
    }
}

static int peek(struct xhci_device *x,struct xhci_event *out)
{
    uint32_t offset,control,i,type;uint8_t *event;int r;
    if(x->event_index>=XHCI_EVENT_TRBS || x->event_cycle>1u) return XHCI_INVALID;
    if((r=xhci_i_health(x))!=0) return r;
    offset=XHCI_EVENT_OFFSET+x->event_index*16u;event=(uint8_t *)x->dma.cpu+offset;
    if((r=xhci_i_sync(x,&x->dma,offset,16u,0))!=0) return r;
    control=xhci_i_get32(event+12);
    if((control&1u)!=x->event_cycle) return 0;
    for(i=0;i<4u;++i) out->word[i]=xhci_i_get32(event+i*4u);
    if(out->word[3]!=control) return XHCI_BAD_EVENT;
    type=(control>>10)&63u;
    if(type==34u) {
        uint32_t port=out->word[0]>>24;
        if((control&~UINT32_C(0xfc01)) || !port || port>x->max_ports) return XHCI_BAD_EVENT;
    } else if(type==32u) {
        if(control&~UINT32_C(0xff1ffc05)) return XHCI_BAD_EVENT;
    } else return XHCI_BAD_EVENT;
    return 1;
}

int xhciu_hid_poll(struct xhciu_hid *h,uint32_t max_events,uint32_t *delivered)
{
    struct xhci_device *x;uint32_t n,kind,code,residue,idx,len;
    uint8_t copy[XHCIU_HID_REPORT_MAX];struct xhci_event ev;uint64_t pointer,ring;int r,sr;
    if(delivered) *delivered=0;
    if(!h || !delivered || !max_events || max_events>256u) return XHCI_INVALID;
    if(h->state!=XHCIU_HID_OPEN || !h->x) return XHCIU_HID_STATE;
    x=h->x;
    if(x->state!=XHCI_READY || !x->dma_owned || !x->device_dma_owned) { h->state=XHCIU_HID_GONE;return XHCIU_HID_STATE; }
    ++h->polls;ring=x->device_dma.bus+XHCIU_HID_INT_RING;
    for(n=0;n<max_events;++n) {
        if((r=peek(x,&ev))<0) goto failed;
        if(!r) return XHCI_OK;
        kind=(ev.word[3]>>10)&63u;
        if(kind==34u) {
            ++h->port_events;
            if((ev.word[0]>>24)==h->port) {
                if((r=port_check(h,1))==XHCIU_HID_STALE) { h->state=XHCIU_HID_GONE;h->last_error=r;return r; }
                if(r) goto failed;
            }
        } else {
            pointer=(uint64_t)ev.word[0]|((uint64_t)ev.word[1]<<32);
            code=ev.word[2]>>24;residue=ev.word[2]&0xffffffu;h->last_code=code;
            if((ev.word[3]>>24)!=h->slot || ((ev.word[3]>>16)&31u)!=h->dci ||
               pointer<ring || pointer-ring>=(RING_TRBS-1u)*16u || ((pointer-ring)&15u) ||
               residue>h->mps) { r=XHCI_BAD_EVENT;goto failed; }
            if(code==6u) {                                        /* STALL: halted endpoint, bounded recovery */
                if((r=xhci_i_ack(x))!=0) goto failed;
                if((r=recover_halt(h))!=0) goto failed;
                continue;
            }
            if(code!=1u && code!=13u) { r=XHCIU_HID_TRANSFER;goto failed; }
            idx=(uint32_t)((pointer-ring)/16u);len=h->mps-residue;
            if(code==13u) ++h->short_reports;
            if((r=xhci_i_sync(x,&x->device_dma,XHCIU_HID_BUFFERS+idx*XHCIU_HID_REPORT_MAX,len,0))!=0)
                goto failed;
            xhci_i_copy(copy,(uint8_t *)x->device_dma.cpu+XHCIU_HID_BUFFERS+idx*XHCIU_HID_REPORT_MAX,len);
            if((r=xhci_i_ack(x))!=0) goto failed;
            if(queue_one(h)!=0 ||
               xhci_i_write(x,x->doorbell_base+h->slot*4u,h->dci)!=0) { r=XHCI_IO;goto failed; }
            if(len) {
                sr=h->sink.report(h->sink.context,h->generation,&h->layout,copy,len);
                if(sr<0) { h->state=XHCIU_HID_GONE;h->last_error=XHCIU_HID_SINK;return XHCIU_HID_SINK; }
                if(sr>0) ++h->refused; else { ++h->reports;++*delivered; }
            }
            continue;
        }
        if((r=xhci_i_ack(x))!=0) goto failed;
    }
    return XHCI_OK;
failed:
    h->state=XHCIU_HID_FAILED;h->last_error=r;return r;
}

int xhciu_hid_close(struct xhciu_hid *h,uint64_t generation)
{
    int r;
    if(!h || !h->x || h->state==XHCIU_HID_CLOSED || h->generation!=generation) return XHCIU_HID_STATE;
    r=xhci_close(h->x);
    if(r==XHCI_QUARANTINED) return r;          /* DMA lifetime continues: keep the handle */
    h->state=XHCIU_HID_CLOSED;return r;
}
