/* SPDX-License-Identifier: GPL-2.0-only -- original bounded USB2 EP0 path. */
#include "xhci_usb.h"
#include "../xhci_native/xhci_internal.h"

enum { PORT_CCS=1, PORT_PED=2, PORT_OCA=8, PORT_PR=16, PORT_PP=512, PORT_CSC=1u<<17,
       PORT_PRC=1u<<21, PORT_CHANGES=0x00fe0000u, PORT_KEEP=0x0e00c200u,
       PORT_EVENTS=256 };

static int disjoint(const void *a,size_t an,const void *b,size_t bn)
{
    uintptr_t x=(uintptr_t)a,y=(uintptr_t)b;
    if(!a || !b || an>UINTPTR_MAX-x || bn>UINTPTR_MAX-y) return 0;
    return x>=y ? x-y>=bn : y-x>=an;
}
static uint32_t port_offset(const struct xhci_device *x,uint32_t port)
{ return x->op_base+0x400u+(port-1u)*16u; }
static int port_state(struct xhci_device *x,uint32_t port,uint32_t speed,int enabled,uint32_t *state)
{
    int result=xhci_i_read(x,port_offset(x,port),state);
    if(result) return result;
    if(!(*state&PORT_CCS)) return XHCIU_DISCONNECTED;
    if(!(*state&PORT_PP) || (*state&PORT_OCA)) return XHCI_UNSUPPORTED;
    if(enabled && ((*state&(PORT_PR|PORT_PED))!=PORT_PED || ((*state>>5)&15u)!=0u))
        return XHCIU_DISCONNECTED;
    if(enabled && (*state&PORT_CSC)) return XHCIU_DISCONNECTED;
    if(speed && ((*state>>10)&15u)!=speed) return XHCIU_DISCONNECTED;
    return XHCI_OK;
}
static int delay(struct xhci_device *x,uint32_t port,uint32_t speed,int enabled,uint32_t duration)
{
    struct xhci_deadline d;uint32_t state;uint64_t now;int result;
    xhci_i_begin(x,&d);
    for(;;) {
        if((result=xhci_i_health(x))!=0 ||
           (result=port_state(x,port,speed,enabled,&state))!=0) return result;
        if(state&PORT_CSC) return XHCIU_DISCONNECTED;
        now=x->ops.now_us(x->ops.context);
        if(now<d.last) return XHCI_CLOCK;
        d.last=now;
        if(now-d.start>=duration) return XHCI_OK;
        /* Duration is a required quiet interval, not an operation timeout. */
        if((result=xhci_i_expired(x,&d,XHCIU_PROBE_US))!=0) return result;
    }
}
static int ranges_overlap(uint32_t a,uint32_t an,uint32_t b,uint32_t bn)
{ return a<=b ? b-a<an : a-b<bn; }
static int select_port(struct xhci_device *x,uint32_t requested,uint32_t *selected,uint32_t *slot_type)
{
    uint8_t covered[256],usb2[256];uint32_t offset,header,next,name,ports,slot,count=0;
    uint32_t first,number,bytes,i,connected=0,state;int result;
    xhci_i_zero(covered,sizeof(covered));xhci_i_zero(usb2,sizeof(usb2));
    offset=(x->hccparams1>>16)*4u;
    while(offset) {
        if(++count>256 || offset<0x20) return XHCI_INVALID;
        if((result=xhci_i_read(x,offset,&header))!=0) return result;
        if(!(header&255u)) return XHCI_INVALID;
        next=((header>>8)&255u)*4u;
        if((header&255u)==2u) {
            if((result=xhci_i_read(x,offset+4u,&name))!=0 ||
               (result=xhci_i_read(x,offset+8u,&ports))!=0 ||
               (result=xhci_i_read(x,offset+12u,&slot))!=0) return result;
            bytes=16u+(ports>>28)*4u;
            if(offset>x->mmio_bytes || bytes>x->mmio_bytes-offset ||
               (next && next<bytes) ||
               ranges_overlap(offset,bytes,x->op_base,0x400u+x->max_ports*16u) ||
               ranges_overlap(offset,bytes,x->runtime_base,32u+x->max_interrupters*32u) ||
               ranges_overlap(offset,bytes,x->doorbell_base,(x->max_slots+1u)*4u))
                return XHCI_INVALID;
            first=ports&255u;number=(ports>>8)&255u;
            if(!first || !number || first>x->max_ports || number>x->max_ports-first+1u)
                return XHCI_INVALID;
            if((header>>24)==2u && (name!=UINT32_C(0x20425355) ||
               ((header>>16)&255u)!=0u || (ports>>28)!=0u)) return XHCI_UNSUPPORTED;
            for(i=first;i<first+number;++i) {
                if(covered[i]) return XHCI_INVALID;
                covered[i]=1;
                if((header>>24)==2u) usb2[i]=(uint8_t)((slot&31u)+1u);
            }
        }
        if(!next) break;
        if(offset>UINT32_MAX-next) return XHCI_INVALID;
        offset+=next;
    }
    *selected=0;*slot_type=0;
    for(i=1;i<=x->max_ports;++i) {
        if((result=xhci_i_read(x,port_offset(x,i),&state))!=0) return result;
        if(state&PORT_CCS) {
            ++connected;
            if(!usb2[i] || (requested && requested!=i)) return XHCIU_TOPOLOGY;
            if(!(state&PORT_PP) || (state&PORT_OCA)) return XHCI_UNSUPPORTED;
            *selected=i;*slot_type=(uint32_t)usb2[i]-1u;
        }
    }
    if(connected==1u) return XHCI_OK;
    return XHCIU_TOPOLOGY;
}
static int acknowledge_port(struct xhci_device *x,uint32_t port,uint32_t state,uint32_t action)
{
    return xhci_i_write(x,port_offset(x,port),(state&PORT_KEEP)|(state&PORT_CHANGES)|action);
}
static int reset_port(struct xhci_device *x,uint32_t port,uint32_t *speed)
{
    struct xhci_deadline d;struct xhci_event event;uint32_t state,seen=0;int result;
    /* Start debounce after clearing the initial connect indication. A newly
     * latched CSC then detects even a disconnect/reconnect between polls. */
    if((result=port_state(x,port,0,0,&state))!=0) return result;
    if(state&PORT_PR) return XHCI_UNSUPPORTED;
    if((result=acknowledge_port(x,port,state,0))!=0 ||
       (result=delay(x,port,0,0,XHCIU_DEBOUNCE_US))!=0 ||
       (result=port_state(x,port,0,0,&state))!=0) return result;
    if(state&PORT_CSC) return XHCIU_DISCONNECTED;
    if(state&PORT_PR) return XHCI_UNSUPPORTED;
    /* Clear observed change causes before requesting a new PSCEG edge. */
    if((result=acknowledge_port(x,port,state,0))!=0 ||
       (result=port_state(x,port,0,0,&state))!=0) return result;
    if(state&(PORT_PR|PORT_CHANGES)) return XHCIU_DISCONNECTED;
    if((result=xhci_i_write(x,port_offset(x,port),(state&PORT_KEEP)|PORT_PR))!=0) return result;
    xhci_i_begin(x,&d);
    for(;;) {
        if((result=xhci_i_event(x,&d,&event))!=0) return result;
        if(((event.word[3]>>10)&63u)!=34u) return XHCI_BAD_EVENT;
        if(++seen>PORT_EVENTS) return XHCI_EVENT_LIMIT;
        if((result=port_state(x,port,0,0,&state))!=0) return result;
        if(state&PORT_CSC) return XHCIU_DISCONNECTED;
        if((result=xhci_i_ack(x))!=0) return result;
        if((event.word[0]>>24)==port && (state&PORT_PRC)) {
            if((state&(PORT_PR|PORT_PED))!=PORT_PED || ((state>>5)&15u)!=0u)
                return XHCIU_DISCONNECTED;
            *speed=(state>>10)&15u;
            if(*speed<1u || *speed>3u) return XHCI_UNSUPPORTED;
            if((result=acknowledge_port(x,port,state,0))!=0) return result;
            return delay(x,port,*speed,1,XHCIU_RESET_RECOVERY_US);
        }
        if((result=xhci_i_expired(x,&d,x->timeout_us))!=0) return result;
    }
}
static int input_context(struct xhci_device *x,uint32_t stride,uint32_t speed,
                         uint32_t packet,int evaluate)
{
    uint8_t *base=x->device_dma.cpu,*input=base+XHCIU_INPUT_OFFSET;
    uint8_t *slot=input+stride,*ep=input+stride*2u;
    xhci_i_zero(input,33u*stride);
    xhci_i_put32(input+4,evaluate?2u:3u);
    if(!evaluate) {
        xhci_i_put32(slot,(speed<<20)|(1u<<27));
        xhci_i_put32(slot+4,x->usb_port<<16);
        xhci_i_put32(ep+4,(packet<<16)|(4u<<3)|(3u<<1));
        xhci_i_put64(ep+8,(x->device_dma.bus+XHCIU_RING_OFFSET)|1u);
        xhci_i_put32(ep+16,8);
        xhci_i_copy(base+XHCIU_INPUT_SNAPSHOT,input,3u*stride);
    } else {
        /* Evaluate Context only consumes EP0 Max Packet Size for A1. */
        xhci_i_put32(ep+4,packet<<16);
    }
    return xhci_i_sync(x,&x->device_dma,XHCIU_INPUT_OFFSET,33u*stride,1);
}
static int output_context(struct xhci_device *x,uint32_t stride,uint32_t speed,uint32_t packet)
{
    uint8_t *base=x->device_dma.cpu;uint32_t slot,ep,status;int result;
    if((result=xhci_i_sync(x,&x->device_dma,0,2u*stride,0))!=0) return result;
    slot=xhci_i_get32(base);status=xhci_i_get32(base+12);
    ep=xhci_i_get32(base+stride);
    if(((slot>>20)&15u)!=speed || ((slot>>27)&31u)!=1u ||
       (slot&0xfffffu) || ((xhci_i_get32(base+4)>>16)&255u)!=x->usb_port ||
       (status>>27)!=2u || !(status&255u) || (status&255u)>127u || (ep&7u)!=1u ||
       ((xhci_i_get32(base+stride+4)>>3)&7u)!=4u ||
       (xhci_i_get32(base+stride+4)>>16)!=packet) return XHCI_BAD_EVENT;
    /* A running output dequeue pointer is undefined; never use it as a cursor. */
    return XHCI_OK;
}
static void trb(uint8_t *p,uint64_t parameter,uint32_t status,uint32_t control)
{ xhci_i_put64(p,parameter);xhci_i_put32(p+8,status);xhci_i_put32(p+12,control); }
static int descriptor_transfer(struct xhci_device *x,uint32_t request_index,uint32_t bytes,
                               uint32_t buffer_offset,uint32_t speed)
{
    uint8_t *base=x->device_dma.cpu,*ring=base+XHCIU_RING_OFFSET;
    uint32_t start=request_index*3u,offset=XHCIU_RING_OFFSET+start*16u;
    uint32_t i,kind,code,residue,seen=0,short_seen=0,missing=0,state;
    uint64_t pointer,data_pointer=x->device_dma.bus+offset+16u;
    uint64_t status_pointer=data_pointer+16u;struct xhci_event event;
    struct xhci_deadline d;int result;
    if(request_index>1u || (bytes!=8u && bytes!=18u)) return XHCI_INVALID;
    for(i=0;i<64u;++i) ((volatile uint8_t *)base)[buffer_offset+i]=0xa5u;
    if((result=xhci_i_sync(x,&x->device_dma,buffer_offset,64u,1))!=0) return result;
    /* Each stage is a separate TD; the one Data TRB is also its final TRB. */
    trb(ring+start*16u,UINT64_C(0x000001000680)|((uint64_t)bytes<<48),8,
        (2u<<10)|(3u<<16)|(1u<<6)); /* ownership invalid until the batch is ready */
    trb(ring+(start+1u)*16u,x->device_dma.bus+buffer_offset,bytes,
        (3u<<10)|(1u<<16)|(1u<<2)|1u);
    trb(ring+(start+2u)*16u,0,0,(4u<<10)|(1u<<5)|1u);
    if((result=xhci_i_sync(x,&x->device_dma,offset,48u,1))!=0) return result;
    xhci_i_put32(ring+start*16u+12,(2u<<10)|(3u<<16)|(1u<<6)|1u);
    if((result=xhci_i_sync(x,&x->device_dma,offset+12u,4u,1))!=0 ||
       (result=xhci_i_write(x,x->doorbell_base+x->usb_slot*4u,1))!=0) return result;
    xhci_i_begin(x,&d);
    for(;;) {
        if((result=xhci_i_event(x,&d,&event))!=0) return result;
        kind=(event.word[3]>>10)&63u;
        if((result=port_state(x,x->usb_port,speed,1,&state))!=0) return result;
        if(kind==34u) {
            if(++seen>PORT_EVENTS) return XHCI_EVENT_LIMIT;
        } else if(kind==32u) {
            pointer=(uint64_t)event.word[0]|((uint64_t)event.word[1]<<32);
            code=event.word[2]>>24;residue=event.word[2]&0xffffffu;
            x->last_transfer_pointer=pointer;x->last_transfer_code=code;
            x->last_transfer_residue=residue;
            if((event.word[3]&4u) || (event.word[3]>>24)!=x->usb_slot ||
               ((event.word[3]>>16)&31u)!=1u || (pointer&15u)) return XHCI_BAD_EVENT;
            if(pointer==data_pointer && code==13u) {
                if(short_seen || residue>bytes) return XHCI_BAD_EVENT;
                short_seen=1;missing=residue;++x->short_events;
            } else if(pointer==status_pointer) {
                if(residue) return XHCI_BAD_EVENT;
                if(code!=1u) return XHCI_COMPLETION_ERROR;
                if((result=xhci_i_ack(x))!=0) return result;
                if(missing) return XHCIU_SHORT_READ;
                ++x->transfers_completed;
                break;
            } else {
                if(pointer!=x->device_dma.bus+offset && pointer!=data_pointer)
                    return XHCI_BAD_EVENT;
                if(residue>(pointer==data_pointer?bytes:8u)) return XHCI_BAD_EVENT;
                return code==1u?XHCI_BAD_EVENT:XHCI_COMPLETION_ERROR;
            }
        } else return XHCI_BAD_EVENT;
        if((result=xhci_i_ack(x))!=0 ||
           (result=xhci_i_expired(x,&d,x->timeout_us))!=0) return result;
    }
    if((result=xhci_i_sync(x,&x->device_dma,buffer_offset,64u,0))!=0) return result;
    for(i=bytes;i<64u;++i) if(base[buffer_offset+i]!=0xa5u) return XHCI_BAD_EVENT;
    return XHCI_OK;
}
struct xhciu_result xhciu_probe_device(struct xhci_device *x,const struct xhciu_request *request,
                                      struct xhciu_descriptor *output)
{
    struct xhciu_result answer;struct xhciu_descriptor parsed;struct ntwu_result decoded;
    uint32_t slot_type=0,speed=0,stride=0,packet=0,stage=XHCIU_VALIDATE,i,state;
    enum ntwu_speed usb_speed=NTWU_FULL_SPEED;uint8_t *memory;int result=XHCI_INVALID,closed;
    xhci_i_zero(&answer,sizeof(answer));answer.status=XHCI_INVALID;answer.transport_error=XHCI_INVALID;
    if(!x || !request || !output || x->state!=XHCI_READY || x->enabled_slots!=1u ||
       !x->device_dma_owned || request->struct_size!=sizeof(*request) ||
       request->abi_version!=XHCIU_ABI_VERSION || request->flags || request->root_port>x->max_ports ||
       !disjoint(request,sizeof(*request),output,sizeof(*output)) ||
       !disjoint(x,sizeof(*x),output,sizeof(*output)) ||
       !disjoint(x,sizeof(*x),request,sizeof(*request)) ||
       !disjoint(x->dma.cpu,XHCI_DMA_BYTES,output,sizeof(*output)) ||
       !disjoint(x->device_dma.cpu,XHCI_DEVICE_DMA_BYTES,output,sizeof(*output)) ||
       !disjoint(x->dma.cpu,XHCI_DMA_BYTES,request,sizeof(*request)) ||
       !disjoint(x->device_dma.cpu,XHCI_DEVICE_DMA_BYTES,request,sizeof(*request))) return answer;
    xhci_i_zero(&parsed,sizeof(parsed));memory=x->device_dma.cpu;x->operation_error=0;
    x->budget_start=x->ops.now_us(x->ops.context);x->budget_last=x->budget_start;
    x->budget_us=XHCIU_PROBE_US;x->budget_active=1;
    stride=(x->hccparams1&4u)?64u:32u;
#define STAGE(value) do { stage=(value);x->usb_stage=stage; } while(0)
#define REQUIRE(expression) do { result=(expression);if(result) goto finish; } while(0)
    STAGE(XHCIU_PROTOCOL);
    REQUIRE(select_port(x,request->root_port,&x->usb_port,&slot_type));
    STAGE(XHCIU_RESET);REQUIRE(reset_port(x,x->usb_port,&speed));
    usb_speed=speed==1u?NTWU_FULL_SPEED:speed==2u?NTWU_LOW_SPEED:NTWU_HIGH_SPEED;
    packet=speed==3u?64u:8u;x->usb_initial_mps=packet;x->usb_final_mps=packet;
    STAGE(XHCIU_ENABLE);REQUIRE(xhci_i_command(x,9,0,slot_type<<16,&x->usb_slot));
    REQUIRE(port_state(x,x->usb_port,speed,1,&state));
    /* Initialize the reserved transfer segment before publishing it in EP0. */
    trb(memory+XHCIU_RING_OFFSET+(XHCIU_RING_TRBS-1u)*16u,
        x->device_dma.bus+XHCIU_RING_OFFSET,0,(6u<<10)|3u);
    REQUIRE(xhci_i_sync(x,&x->device_dma,XHCIU_RING_OFFSET,256u,1));
    STAGE(XHCIU_ADDRESS);REQUIRE(input_context(x,stride,speed,packet,0));
    REQUIRE(xhci_i_command(x,11,x->device_dma.bus+XHCIU_INPUT_OFFSET,1u<<24,0));
    REQUIRE(output_context(x,stride,speed,packet));
    REQUIRE(delay(x,x->usb_port,speed,1,XHCIU_ADDRESS_RECOVERY_US));
    STAGE(XHCIU_FIRST_READ);REQUIRE(descriptor_transfer(x,0,8,XHCIU_FIRST_OFFSET,speed));
    xhci_i_copy(parsed.first_eight,memory+XHCIU_FIRST_OFFSET,8);
    packet=parsed.first_eight[7];
    if(parsed.first_eight[0]!=18u || parsed.first_eight[1]!=1u ||
       (speed==2u && packet!=8u) || (speed==3u && packet!=64u) ||
       (speed==1u && packet!=8u && packet!=16u && packet!=32u && packet!=64u)) {
        result=XHCIU_DESCRIPTOR;goto finish;
    }
    x->usb_final_mps=packet;
    if(packet!=x->usb_initial_mps) {
        STAGE(XHCIU_EVALUATE);REQUIRE(input_context(x,stride,speed,packet,1));
        REQUIRE(xhci_i_command(x,13,x->device_dma.bus+XHCIU_INPUT_OFFSET,1u<<24,0));
        ++x->usb_evaluates;REQUIRE(output_context(x,stride,speed,packet));
    }
    STAGE(XHCIU_DEVICE_READ);REQUIRE(descriptor_transfer(x,1,18,XHCIU_DEVICE_OFFSET,speed));
    xhci_i_copy(parsed.raw_device,memory+XHCIU_DEVICE_OFFSET,18);
    for(i=0;i<8u;++i) if(parsed.raw_device[i]!=parsed.first_eight[i]) {
        result=XHCIU_DESCRIPTOR;goto finish;
    }
    STAGE(XHCIU_PARSE);decoded=ntwu_parse_device(parsed.raw_device,18,usb_speed,&parsed.parsed);
    answer.parser_status=decoded.status;answer.parser_offset=decoded.offset;
    if(decoded.status!=NTWU_OK) { result=XHCIU_DESCRIPTOR;goto finish; }
    REQUIRE(output_context(x,stride,speed,packet));
    xhci_i_copy(memory+XHCIU_OUTPUT_SNAPSHOT,memory,2u*stride);
    REQUIRE(port_state(x,x->usb_port,speed,1,&state));
    parsed.struct_size=sizeof(parsed);parsed.abi_version=XHCIU_ABI_VERSION;
    parsed.root_port=x->usb_port;parsed.slot_id=x->usb_slot;parsed.context_bytes=stride;
    parsed.port_speed_id=speed;parsed.initial_ep0_packet=(uint16_t)x->usb_initial_mps;
    parsed.final_ep0_packet=(uint16_t)packet;
    STAGE(XHCIU_DISABLE);REQUIRE(xhci_i_command(x,10,0,1u<<24,0));
    /* Disable Slot completion returns ownership of its DCBAA entry. */
    xhci_i_put64((uint8_t *)x->dma.cpu+8u,0);
    REQUIRE(xhci_i_sync(x,&x->dma,8u,8u,1));
    STAGE(XHCIU_CLOSE);result=XHCI_OK;
finish:
    answer.failed_stage=stage;answer.transport_error=result;
    if(result==XHCI_QUARANTINED) {
        answer.status=result;
        answer.transport_error=x->operation_error?x->operation_error:x->last_error;
        return answer;
    }
    x->operation_error=result;
    closed=xhci_close(x);
    if(closed) {
        answer.status=closed;
        if(!result) answer.transport_error=x->last_error?x->last_error:closed;
        return answer;
    }
    answer.status=result;
    if(!result) {
        x->usb_stage=XHCIU_COMPLETE;answer.failed_stage=XHCIU_COMPLETE;
        xhci_i_copy(output,&parsed,sizeof(parsed));
    }
    return answer;
#undef REQUIRE
#undef STAGE
}
