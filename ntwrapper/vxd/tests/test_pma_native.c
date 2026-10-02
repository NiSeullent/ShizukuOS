/* SPDX-License-Identifier: GPL-2.0-only. Actual broker/bridge/service/rings;
 * only privileged VMM/page/hypercall boundaries are modeled. */
#define main legacy_w64_fixture_main
#include "test_w64vxd.c"
#undef main
#include "../pma_endpoint.h"
#include "../../../shizukudos/pma_bridge/service.h"
static uint32_t vm=0x100, thread=0x200, process=0x300, device=0x400, clock_ms;
static uint32_t event_ref, timer_ref, event_object, close_count, signal_count;
static uint32_t fail_open, fail_timer, fail_event, fail_signal, fail_close, close_copy_failure,signal_reenter;
static void signal_race(void);
static void release_during_unlock(void){CHECK(ntwv_endpoint_release()==NTWV_ERROR_BUSY);}
static shz_pma_service_t service;
static struct ntwv_pma_owner identity;
static uint32_t sys_vm(void) { return 0x100; }
static uint32_t cur_vm(void) { return vm; }
static uint32_t cur_thread(void) { return thread; }
static uint32_t now_ms(void) { return clock_ms; }
static uint32_t open_event(uint32_t h) { CHECK(!protected_now && h==0x123); if(fail_open)return 0; CHECK(!event_object);return event_object=0xabc; }
static int set_event(uint32_t h) { CHECK(!protected_now && h==event_object && vm==sys_vm()); ++signal_count; CHECK(!ntwv_pma_shutdown()); if(signal_reenter){signal_reenter=0;signal_race();} CHECK(h==event_object); return !fail_signal; }
static int close_event(uint32_t h) { CHECK(!protected_now && h==event_object); if(fail_close)return 0; ++close_count;event_object=0;return 1; }
static uint32_t schedule_event(uint32_t ref) { CHECK(protected_now && ref && !event_ref);if(fail_event)return 0;event_ref=ref;return 0x555; }
static void cancel_event(uint32_t h) { CHECK(protected_now && h==0x555 && event_ref); event_ref=0; }
static uint32_t schedule_timer(uint32_t ms,uint32_t ref) { CHECK(protected_now && ms==NTWV_PMA_POLL_MS && ref && !timer_ref);if(fail_timer)return 0;timer_ref=ref;return 0x666; }
static void cancel_timer(uint32_t h) { CHECK(protected_now && h==0x666 && timer_ref);timer_ref=0; }
static const struct ntwv_pma_services services={sys_vm,cur_vm,cur_thread,now_ms,open_event,set_event,close_event,schedule_event,cancel_event,schedule_timer,cancel_timer,enter,leave};
static uint32_t pcall(uint32_t code,const void *in,uint32_t in_bytes,uint32_t out_bytes,void *out) {
    struct ntwv_dioc r={0}; uint32_t rc;
    step=unlocks=writes=reads=protected_now=0;
    r.code=code;r.vm=vm;r.process=process;r.device=device;
    r.output=0x00500ff0;r.output_bytes=out_bytes;r.returned=0x00600ffe;
    if(in_bytes) {r.input=0x00700ff0;r.input_bytes=in_bytes;memcpy(buffers[2]+0xff0,in,in_bytes);}
    rc=ntwv_dioc_ex(&r,&ops,&hv);
    if(out)memcpy(out,buffers[0]+0xff0,out_bytes);
    CHECK(!protected_now);return rc;
}
static void tick(void) {
    uint32_t ref=timer_ref;CHECK(ref);timer_ref=0;ntwv_pma_timeout(ref);
    if(event_ref) {ref=event_ref;event_ref=0;ntwv_pma_event(vm,thread,ref);}
}
static void begin(void) {
    regression_begin();CHECK(ntwv_pma_initialize(&services,&hv));
    CHECK(shz_pma_service_init(&service,SHZ_DOM_KERNEL64,SHZ_DOM_WIN98,1)==SHZ_OK);
}
static uint32_t register_owner(uint32_t timeout) {
    struct ntwv_pma_registration r={sizeof r,0x123,timeout,0};
    return pcall(NTWV_IOCTL_PMA_REGISTER,&r,sizeof r,sizeof identity,&identity);
}
static void lease(void) {
    CHECK(!register_owner(100));CHECK(identity.magic==NTWV_PMA_ENDPOINT_MAGIC && identity.pid==process && identity.tid==thread);
    CHECK(identity.owner_generation && identity.owner_generation==identity.thread_generation && identity.channel_generation==1);
    CHECK(!ntwv_pma_shutdown() && !ntwv_shutdown() && ntwv_pma_unload_safe());
    CHECK(dioc(NTWV_IOCTL_W64_OPEN,0,0,64,0,0)==NTWV_ERROR_BUSY);
    CHECK(dioc(NTWV_IOCTL_W64_RECV,0,0,256,0,0)==NTWV_ERROR_BUSY);
    CHECK(dioc(0,0,0,0,0,0)==0 && dioc(UINT32_MAX,0,0,0,0,0)==1);
}
static struct ntwv_pma_ticket query(void) {
    struct ntwv_pma_ticket t;CHECK(!pcall(NTWV_IOCTL_PMA_QUERY,0,0,sizeof t,&t));CHECK(t.request_id && t.generation==1 && !t.reserved);return t;
}
static shz_msg_hdr_t receive(uint32_t opcode) {
    shz_msg_hdr_t h;uint8_t payload[SHZ_MSG_MAX_INLINE];int reason;shz_pma_request_t r;
    CHECK(shz_ring_pop(k64_rx(),&h,payload,sizeof payload,&reason)==SHZ_OK);
    CHECK(h.opcode==opcode && h.src_domain==SHZ_DOM_WIN98 && h.dst_domain==SHZ_DOM_KERNEL64 && h.generation==1);
    memcpy(&r,payload,sizeof r);CHECK(r.pid==process && r.tid==thread && r.domain==SHZ_DOM_WIN98);
    if(identity.magic==NTWV_PMA_ENDPOINT_MAGIC) CHECK(r.owner_generation==identity.owner_generation && r.thread_generation==identity.thread_generation);
    else CHECK(r.owner_generation && r.owner_generation==r.thread_generation);
    CHECK(shz_pma_service_dispatch(&service,&h,payload,123456)==SHZ_OK);return h;
}
static shz_pma_frame_t frame(void) { const shz_pma_frame_t *f=shz_pma_service_peek(&service);CHECK(f);return *f; }
static void publish(void) { shz_pma_frame_t f=frame();CHECK(shz_ring_push(k64_tx(),&f.header,f.payload)==SHZ_OK);CHECK(shz_pma_service_ack(&service,f.header.request_id)==SHZ_OK); }
static struct ntwv_pma_result take(void) { struct ntwv_pma_result r;CHECK(!pcall(NTWV_IOCTL_PMA_TAKE,0,0,sizeof r,&r));CHECK(r.magic==NTWV_PMA_ENDPOINT_MAGIC && r.size==sizeof r);return r; }
static void close_owner(void) {
    uint32_t status=99,initial_closes=close_count;
    CHECK(pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status)==NTWV_ERROR_BUSY);
    (void)receive(SHZ_OP_PMA_PROCESS_EXIT);publish();tick();
    if(close_copy_failure) {failure=13;CHECK(pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status)==NTWV_ERROR_NOACCESS && writes==2);failure=0;
        CHECK(!ntwv_pma_shutdown() && dioc(NTWV_IOCTL_W64_OPEN,0,0,64,0,0)==NTWV_ERROR_BUSY);}
    CHECK(!pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status) && !status);
    CHECK(close_count==initial_closes+1 && !timer_ref && !event_ref && !event_object);
    CHECK(ntwv_pma_shutdown());ntwv_w64_reset();CHECK(ntwv_shutdown());
}
static void signal_race(void) {
    uint32_t status;
    CHECK(pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status)==NTWV_ERROR_BUSY);
    (void)receive(SHZ_OP_PMA_PROCESS_EXIT);publish();tick();
    /* Same owner reenters before the original SetWin32Event returns. */
    CHECK(pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status)==NTWV_ERROR_BUSY);
    CHECK(register_owner(100)==NTWV_ERROR_BUSY && !close_count && event_object);
}
int main(int argc,char **argv) {
    const char *name=argc>1?argv[1]:"happy";struct ntwv_pma_ticket t;struct ntwv_pma_result r;
    begin();
    if(!strcmp(name,"unlock-inflight")) {
        lease();t=query();(void)receive(SHZ_OP_PMA_QUERY);publish();tick();
        unlock_interleave=release_during_unlock;r=take();CHECK(r.request_id==t.request_id && !locked);close_owner();
    } else if(!strcmp(name,"unlock-abort")) {
        fail_open=1;unlock_fail_mask=7;CHECK(register_owner(100)==NTWV_ERROR_NOACCESS && locked==3 && !event_object);
        CHECK(!ntwv_shutdown() && locked==3);unlock_fail_mask=0;fail_open=0;
        CHECK(ntwv_pma_shutdown());CHECK(ntwv_shutdown() && !locked);
    } else if(!strcmp(name,"unlock-rundown")) {
        lease();t=query();(void)receive(SHZ_OP_PMA_QUERY);publish();tick();unlock_fail_mask=3;
        CHECK(pcall(NTWV_IOCTL_PMA_TAKE,0,0,sizeof r,&r)==NTWV_ERROR_NOACCESS && locked==2);
        ntwv_pma_owner_departed(0,thread,0,0);tick();(void)receive(SHZ_OP_PMA_PROCESS_EXIT);publish();tick();
        CHECK(!ntwv_pma_shutdown() && locked==2 && close_count==1 && !event_object && timer_ref);
        unlock_fail_mask=0;tick();CHECK(!locked && !timer_ref && !event_ref);
        CHECK(ntwv_pma_shutdown());ntwv_w64_reset();CHECK(ntwv_shutdown());
    } else if(!strncmp(name,"unlock-",7)) {
        struct ntwv_w64_open info;uint32_t old_locks,old_checks,old_pin_calls,old_unlocks;
        if(!strcmp(name,"unlock-all")) {unlock_fail_mask=7;CHECK(register_owner(100)==NTWV_ERROR_NOACCESS && locked==3 && writes==2);}
        else {unlock_fail_mask=5;failure=!strcmp(name,"unlock-partial-returned")?6:4;
            if(!strcmp(name,"unlock-bad-alias")){failure=0;bad_alias=1;}
            CHECK(register_owner(100)==NTWV_ERROR_NOACCESS && locked>0 && !writes);bad_alias=0;}
        old_locks=all_locks;old_checks=all_checks;old_pin_calls=all_pin_calls;failure=0;
        old_unlocks=unlocks;CHECK(!ntwv_shutdown());CHECK(unlocks-old_unlocks<=3);CHECK(ntwv_endpoint_release()==NTWV_ERROR_BUSY);
        if(strcmp(name,"unlock-all"))CHECK(ntwv_endpoint_acquire(&hv,&info)==NTWV_ERROR_BUSY);
        CHECK(register_owner(100)==NTWV_ERROR_NOACCESS && all_locks==old_locks &&
              all_checks==old_checks && all_pin_calls==old_pin_calls && locked && unlocks<=3);
        unlock_fail_mask=0;
        if(strcmp(name,"unlock-all"))CHECK(!register_owner(100));
        if(strcmp(name,"unlock-all"))CHECK(!locked);
        close_owner();
    } else if(!strcmp(name,"legacy")) {
        regression_open();CHECK(register_owner(100)==NTWV_ERROR_BUSY && !event_object && !timer_ref);
        CHECK(ntwv_pma_shutdown());ntwv_w64_reset();CHECK(ntwv_shutdown());
    } else if(!strcmp(name,"registration-failure")) {
        fail_open=1;CHECK(register_owner(100)==NTWV_ERROR_INVALID_PARAMETER && !event_object);fail_open=0;
        fail_timer=1;CHECK(register_owner(100)==NTWV_ERROR_GEN_FAILURE && !event_object);fail_timer=0;
        CHECK(ntwv_pma_shutdown());ntwv_w64_reset();CHECK(ntwv_shutdown());
    } else if(!strcmp(name,"close-copy-failure")) {
        lease();close_copy_failure=1;close_owner();
    } else if(!strcmp(name,"registration-close-failure")) {
        fail_timer=fail_close=1;CHECK(register_owner(100)==NTWV_ERROR_GEN_FAILURE);
        CHECK(event_object && !ntwv_pma_shutdown() && !ntwv_shutdown());
        fail_timer=fail_close=0;close_owner();
    } else {
        lease();
        if(!strcmp(name,"forgery")) {
            ++process;CHECK(pcall(NTWV_IOCTL_PMA_QUERY,0,0,16,0)==NTWV_ERROR_ACCESS_DENIED);--process;
            ++device;CHECK(pcall(NTWV_IOCTL_PMA_QUERY,0,0,16,0)==NTWV_ERROR_ACCESS_DENIED);--device;
            ++thread;CHECK(pcall(NTWV_IOCTL_PMA_QUERY,0,0,16,0)==NTWV_ERROR_ACCESS_DENIED);--thread;
            ++vm;CHECK(pcall(NTWV_IOCTL_PMA_QUERY,0,0,16,0)==NTWV_ERROR_ACCESS_DENIED);--vm;
            CHECK(k64_rx()->head==k64_rx()->tail);close_owner();
        } else if(!strcmp(name,"close-mismatch")) {
            uint32_t status;shz_pma_frame_t f;shz_pma_completion_t c;
            CHECK(pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status)==NTWV_ERROR_BUSY);(void)receive(SHZ_OP_PMA_PROCESS_EXIT);
            f=frame();memcpy(&c,f.payload,sizeof c);++c.owner_generation;memcpy(f.payload,&c,sizeof c);
            CHECK(shz_ring_push(k64_tx(),&f.header,f.payload)==SHZ_OK);tick();
            CHECK(pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status)==NTWV_ERROR_BUSY && !close_count);
            publish();tick();fail_close=1;CHECK(pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status)==NTWV_ERROR_GEN_FAILURE && event_object);
            CHECK(!ntwv_pma_shutdown());fail_close=0;CHECK(!pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status));
            CHECK(close_count==1 && !event_object && !event_ref && !timer_ref);CHECK(ntwv_pma_shutdown());ntwv_w64_reset();CHECK(ntwv_shutdown());
        } else if(!strcmp(name,"lifecycle")) {
            ntwv_pma_owner_departed(vm,thread+1,0,0);tick();CHECK(k64_rx()->head==k64_rx()->tail);
            /* Thread notifications specify EDI, not a current VM. */
            ntwv_pma_owner_departed(0,thread,0,0);tick();CHECK(!ntwv_pma_shutdown());
            (void)receive(SHZ_OP_PMA_PROCESS_EXIT);publish();tick();
            CHECK(close_count==1 && !event_object && !timer_ref && !event_ref);CHECK(ntwv_pma_shutdown());ntwv_w64_reset();CHECK(ntwv_shutdown());
        } else {
            if(!strcmp(name,"timeout"))clock_ms=UINT32_MAX-30u;
            t=query();CHECK(!ntwv_pma_unload_safe());
            if(!strcmp(name,"stale")) {
                shz_msg_hdr_t h;uint8_t payload[192];int reason;service.last_sequence=100;
                CHECK(shz_ring_pop(k64_rx(),&h,payload,sizeof payload,&reason)==SHZ_OK);
                CHECK(shz_pma_service_dispatch(&service,&h,payload,123456)==SHZ_E_STALE);
                k64_reply(h.request_id,h.opcode,SHZ_E_STALE,0,0);tick();r=take();
                CHECK(r.kind==NTWV_PMA_RESULT_ERROR && r.error==NTWV_ERROR_DEV_NOT_EXIST);
                CHECK(pcall(NTWV_IOCTL_PMA_QUERY,0,0,16,0)==NTWV_ERROR_DEV_NOT_EXIST);
                CHECK(pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,0)==NTWV_ERROR_BUSY && !ntwv_pma_shutdown() && !ntwv_shutdown());
                printf("PASS: native PMA %s (%u production C/ring checks; privileged VMM modeled)\n",name,checks);return 0;
            }
            (void)receive(SHZ_OP_PMA_QUERY);
            if(!strcmp(name,"delivery-failure")) {
                fail_event=1;tick();CHECK(!signal_count);fail_event=0;tick();
                r=take();CHECK(r.kind==NTWV_PMA_RESULT_ERROR && r.error==NTWV_ERROR_GEN_FAILURE);
                CHECK(pcall(NTWV_IOCTL_PMA_QUERY,0,0,16,0)==NTWV_ERROR_BUSY);publish();tick();close_owner();
            } else if(!strcmp(name,"wrong-vm")) {
                publish();++vm;tick();CHECK(!signal_count && k64_tx()->head!=k64_tx()->tail);--vm;tick();
                r=take();CHECK(r.kind==NTWV_PMA_RESULT_QUERY && r.request_id==t.request_id);close_owner();
            } else if(!strcmp(name,"timeout")) {
                clock_ms+=99;tick();CHECK(!signal_count);clock_ms+=1;tick();CHECK(signal_count==1);
                r=take();CHECK(r.kind==NTWV_PMA_RESULT_ERROR && r.error==NTWV_ERROR_TIMEOUT && r.request_id==t.request_id);
                tick();CHECK(signal_count==1);CHECK(pcall(NTWV_IOCTL_PMA_QUERY,0,0,16,0)==NTWV_ERROR_BUSY);
                publish();tick();CHECK(signal_count==1);close_owner();
            } else if(!strcmp(name,"epoch")) {
                chdr()->generation=2;tick();r=take();CHECK(r.kind==NTWV_PMA_RESULT_ERROR && r.error==NTWV_ERROR_DEV_NOT_EXIST);
                CHECK(pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,0)==NTWV_ERROR_BUSY);CHECK(!ntwv_pma_shutdown() && !ntwv_shutdown());
            } else if(!strcmp(name,"rejected")) {
                (void)shz_pma_service_ack(&service,t.request_id);
                k64_reply(t.request_id,SHZ_OP_PMA_QUERY,SHZ_E_UNSUPPORTED,0,0);tick();
                r=take();CHECK(r.kind==NTWV_PMA_RESULT_ERROR && r.error==NTWV_ERROR_NOT_SUPPORTED);close_owner();
            } else {
                if(!strcmp(name,"mismatch")) {
                    shz_pma_frame_t f=frame();++f.header.request_id;CHECK(shz_ring_push(k64_tx(),&f.header,f.payload)==SHZ_OK);tick();CHECK(!signal_count);
                    f=frame();f.payload[0]^=1;CHECK(shz_ring_push(k64_tx(),&f.header,f.payload)==SHZ_OK);tick();CHECK(!signal_count);
                    ntwv_pma_event(vm,thread,identity.owner_generation+1);CHECK(timer_ref);
                }
                if(!strcmp(name,"signal-failure"))fail_signal=1;
                if(!strcmp(name,"signal-race"))signal_reenter=1;
                publish();tick();CHECK(signal_count==1);
                if(!strcmp(name,"signal-race")){uint32_t status;CHECK(!pcall(NTWV_IOCTL_PMA_CLOSE,0,0,4,&status));
                    CHECK(close_count==1 && !event_object);uint32_t old_generation=identity.owner_generation;
                    CHECK(!register_owner(100) && identity.owner_generation>old_generation);close_owner();
                    printf("PASS: native PMA %s (%u production C/ring checks; privileged VMM modeled)\n",name,checks);return 0;}
                if(!strcmp(name,"copy-failure")) {
                    /* First unlock fails after both writes; TAKE must remain retained. */
                    failure=13;CHECK(pcall(NTWV_IOCTL_PMA_TAKE,0,0,sizeof r,&r)==NTWV_ERROR_NOACCESS);CHECK(writes==2);failure=0;
                }
                r=take();CHECK(r.kind==NTWV_PMA_RESULT_QUERY && r.request_id==t.request_id && r.info.magic==SHZ_PMA_MAGIC && r.info.now_ns==123456);
                CHECK(r.error==(!strcmp(name,"signal-failure")?NTWV_ERROR_GEN_FAILURE:0));
                CHECK(pcall(NTWV_IOCTL_PMA_TAKE,0,0,sizeof r,&r)==NTWV_ERROR_NO_MORE_ITEMS);
                tick();CHECK(signal_count==1);close_owner();
            }
        }
    }
    printf("PASS: native PMA %s (%u production C/ring checks; privileged VMM modeled)\n",name,checks);return 0;
}
