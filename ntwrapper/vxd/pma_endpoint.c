/* SPDX-License-Identifier: GPL-2.0-only -- original one-owner QUERY broker.
 * VMM schedules Windows. This broker reserves a transport lease and retains
 * results; it does not schedule DOS or Windows threads. */
#include "pma_endpoint.h"
static void copy(void *d, const void *s, size_t n) { uint8_t *a=d; const uint8_t *b=s; while(n--) *a++=*b++; }
static void zero(void *d, size_t n) { uint8_t *a=d; while(n--) *a++=0; }
static struct ntwv_pma_services svc;
static struct ntwv_hv transport;
static uint32_t initialized, admitted, owner_vm, owner_thread, owner_device, owner_process;
static uint32_t lifetime, owner_present, dying, callback_active, notification_active, event_handle, timeout_handle, schedule_failed;
static struct {
    struct ntwv_w64_open channel;
    uint32_t event, timeout_ms, start, closing, cleanup_sent, cleanup_done, ready, completed, notified;
    uint64_t query_id, cleanup_id;
    struct ntwv_pma_result result;
} owner;
static uint64_t next_sequence;
static uint32_t ever_sent, namespace_poisoned;

static int enter(void) {
    uint32_t expected=0;
    return __atomic_compare_exchange_n(&admitted,&expected,1,0,__ATOMIC_ACQUIRE,__ATOMIC_RELAXED);
}
static void leave(void) { __atomic_store_n(&admitted,0,__ATOMIC_RELEASE); }
static uint32_t load(const uint32_t *p) { return __atomic_load_n(p,__ATOMIC_ACQUIRE); }
static void store(uint32_t *p,uint32_t v) { __atomic_store_n(p,v,__ATOMIC_RELEASE); }

/* These Win98 services are asynchronous and PEF_ALWAYS_SCHED prevents an
 * immediate callback. IRQ masking covers only publication/cancellation of the
 * service handles. No ring, event signaling, page service or DOS call is here. */
static void arm(uint32_t ref) {
    uintptr_t flags;
    if (!load(&owner_present) || ref!=load(&lifetime)) return;
    flags=svc.enter(0);
    if (!load(&timeout_handle) && !load(&event_handle)) {
        uint32_t h=svc.schedule_timeout(NTWV_PMA_POLL_MS,ref);
        store(&timeout_handle,h);
        if(!h) store(&schedule_failed,1);
    }
    svc.leave(0,flags);
}
static void cancel_progress(void) {
    uintptr_t flags=svc.enter(0);
    uint32_t h=__atomic_exchange_n(&event_handle,0,__ATOMIC_ACQ_REL);
    if(h) svc.cancel_event(h);
    h=__atomic_exchange_n(&timeout_handle,0,__ATOMIC_ACQ_REL);
    if(h) svc.cancel_timeout(h);
    svc.leave(0,flags);
}

int ntwv_pma_initialize(const struct ntwv_pma_services *s,const struct ntwv_hv *hv) {
    if(load(&initialized) || !s || !hv || !s->system_vm || !s->current_vm || !s->current_thread ||
       !s->now_ms || !s->open_event || !s->set_event || !s->close_event || !s->schedule_event ||
       !s->cancel_event || !s->schedule_timeout || !s->cancel_timeout || !s->enter || !s->leave)
        return 0;
    copy(&svc,s,sizeof svc); copy(&transport,hv,sizeof transport);
    store(&initialized,1); return 1;
}
int ntwv_pma_shutdown(void) {
    if(!enter()) return 0;
    if(load(&owner_present) || load(&callback_active) || load(&notification_active) || load(&event_handle) || load(&timeout_handle)) {
        leave(); return 0;
    }
    store(&initialized,0); leave(); return 1;
}
void ntwv_pma_resume(void) { store(&initialized,1); }
/* The existing ABI has no persistent VxD incarnation allocator. Keep this
 * namespace resident after backend admission; BSS reset is not a new epoch. */
int ntwv_pma_unload_safe(void) { return !load(&ever_sent); }

static int authorized(const struct ntwv_dioc *r) {
    return r->vm==load(&owner_vm) && r->device==load(&owner_device) && r->process==load(&owner_process) &&
           svc.current_vm()==r->vm && svc.current_thread()==load(&owner_thread);
}
static uint64_t sequence(void) {
    if(next_sequence==UINT64_MAX) return 0;
    return ++next_sequence;
}
static uint32_t send(uint32_t opcode,uint64_t id) {
    shz_msg_hdr_t h;
    shz_pma_request_t r;
    zero(&h,sizeof h); zero(&r,sizeof r);
    h.opcode=opcode; h.request_id=id; h.payload_length=sizeof r;
    r.magic=SHZ_PMA_MAGIC; r.abi_major=SHZ_PMA_ABI_MAJOR; r.abi_minor=SHZ_PMA_ABI_MINOR;
    r.size=sizeof r; r.required_features=SHZ_PMA_FEATURE_EVENTS|SHZ_PMA_FEATURE_LIFECYCLE;
    r.domain=owner.channel.self_domain; r.pid=load(&owner_process); r.tid=load(&owner_thread);
    r.owner_generation=load(&lifetime); r.thread_generation=load(&lifetime);
    uint32_t rc=ntwv_endpoint_send(&transport,&h,&r);
    if(!rc) store(&ever_sent,1);
    return rc;
}
static void error_result(uint32_t error) {
    if(owner.completed || owner.closing || !owner.query_id) return;
    zero(&owner.result,sizeof owner.result);
    owner.result.magic=NTWV_PMA_ENDPOINT_MAGIC; owner.result.size=sizeof owner.result;
    owner.result.kind=NTWV_PMA_RESULT_ERROR; owner.result.error=error;
    owner.result.request_id=owner.query_id; owner.result.generation=owner.channel.generation;
    owner.ready=owner.completed=1;
}
static void request_cleanup(void) {
    owner.closing=1; owner.ready=0;
    if(!owner.cleanup_id) owner.cleanup_id=sequence();
    if(owner.cleanup_id && !owner.cleanup_sent && !send(SHZ_OP_PMA_PROCESS_EXIT,owner.cleanup_id))
        owner.cleanup_sent=1;
}
static uint32_t finish_close(void) {
    if(!owner.cleanup_done || owner.query_id || load(&notification_active)) return NTWV_ERROR_BUSY;
    cancel_progress();
    if(owner.event && !svc.close_event(owner.event)) return NTWV_ERROR_GEN_FAILURE;
    owner.event=0;
    return 0;
}
static uint32_t release_owner(void) {
    uint32_t rc;
    if(!owner.cleanup_done || owner.query_id || owner.event || load(&notification_active)) return NTWV_ERROR_BUSY;
    rc=ntwv_endpoint_release();
    if(rc) return rc;
    store(&owner_present,0); store(&dying,0); store(&schedule_failed,0);
    store(&owner_vm,0); store(&owner_thread,0); store(&owner_process,0); store(&owner_device,0);
    zero(&owner,sizeof owner); return 0;
}

uint32_t ntwv_pma_dispatch(const struct ntwv_dioc *r,const void *input,void *output,uint32_t *bytes) {
    uint32_t rc=0, ref;
    if(!r || !input || !output || !bytes) return NTWV_ERROR_INVALID_PARAMETER;
    if(!load(&initialized)) return NTWV_ERROR_NOT_READY;
    if(!enter()) return NTWV_ERROR_BUSY;
    if(!load(&initialized)) { leave(); return NTWV_ERROR_NOT_READY; }
    *bytes=0; ref=load(&lifetime);
    if(r->code==NTWV_IOCTL_PMA_REGISTER) {
        struct ntwv_pma_registration registration;
        struct ntwv_pma_owner result;
        uint32_t vm=svc.current_vm(), tid=svc.current_thread();
        copy(&registration,input,sizeof registration);
        if(load(&owner_present)) rc=NTWV_ERROR_BUSY;
        else if(load(&namespace_poisoned)) rc=NTWV_ERROR_DEV_NOT_EXIST;
        else if(!r->process || !r->device || !tid || r->vm!=vm || vm!=svc.system_vm()) rc=NTWV_ERROR_ACCESS_DENIED;
        else if(registration.size!=sizeof registration || !registration.event_handle || registration.reserved ||
                !registration.timeout_ms || registration.timeout_ms>NTWV_PMA_TIMEOUT_MAX_MS) rc=NTWV_ERROR_INVALID_PARAMETER;
        else if(ref==UINT32_MAX) rc=NTWV_ERROR_NOT_ENOUGH_MEMORY;
        else {
            zero(&owner,sizeof owner);
            rc=ntwv_endpoint_acquire(&transport,&owner.channel);
            if(!rc) {
                owner.event=svc.open_event(registration.event_handle);
                if(!owner.event) { rc=NTWV_ERROR_INVALID_PARAMETER; ntwv_endpoint_abort_registration(); }
                else {
                    ++ref; store(&lifetime,ref);
                    store(&owner_vm,vm); store(&owner_thread,tid); store(&owner_process,r->process); store(&owner_device,r->device);
                    owner.timeout_ms=registration.timeout_ms; store(&owner_present,1);
                    zero(&result,sizeof result); result.magic=NTWV_PMA_ENDPOINT_MAGIC; result.size=sizeof result;
                    result.domain=owner.channel.self_domain; result.pid=r->process; result.tid=tid;
                    result.owner_generation=result.thread_generation=ref; result.channel_generation=owner.channel.generation;
                    copy(output,&result,sizeof result); *bytes=sizeof result;
                    arm(ref);
                    /* Registration itself admits no backend operation. */
                    if(load(&schedule_failed)) {
                        cancel_progress();
                        if(svc.close_event(owner.event)) owner.event=0;
                        /* A failed native handle close is still an owned VMM
                         * reference. Retain the lease for explicit rundown;
                         * never report the image safe to unload. */
                        if(!owner.event) {
                            ntwv_endpoint_abort_registration();
                            store(&owner_present,0); zero(&owner,sizeof owner);
                        } else owner.closing=1;
                        store(&schedule_failed,0);
                        rc=NTWV_ERROR_GEN_FAILURE;
                    }
                }
            }
        }
    } else if(!load(&owner_present)) rc=NTWV_ERROR_NOT_READY;
    else if(!authorized(r)) rc=NTWV_ERROR_ACCESS_DENIED;
    else if(r->code==NTWV_IOCTL_PMA_QUERY) {
        struct ntwv_pma_ticket ticket;
        if(load(&namespace_poisoned)) rc=NTWV_ERROR_DEV_NOT_EXIST;
        else if(owner.closing || load(&dying) || owner.query_id || owner.ready) rc=NTWV_ERROR_BUSY;
        else {
            owner.completed=owner.notified=0;
            owner.query_id=sequence();
            if(!owner.query_id) rc=NTWV_ERROR_NOT_ENOUGH_MEMORY;
            else {
                owner.start=svc.now_ms();
                rc=send(SHZ_OP_PMA_QUERY,owner.query_id);
                if(rc) owner.query_id=0;
                else {
                    zero(&ticket,sizeof ticket); ticket.request_id=owner.query_id; ticket.generation=owner.channel.generation;
                    copy(output,&ticket,sizeof ticket); *bytes=sizeof ticket;
                    arm(ref); if(load(&schedule_failed)) error_result(NTWV_ERROR_GEN_FAILURE);
                }
            }
        }
    } else if(r->code==NTWV_IOCTL_PMA_TAKE) {
        if(!owner.ready) rc=NTWV_ERROR_NO_MORE_ITEMS;
        else {
            copy(output,&owner.result,sizeof owner.result); *bytes=sizeof owner.result;
        }
    } else if(r->code==NTWV_IOCTL_PMA_CLOSE) {
        request_cleanup();
        rc=finish_close();
        if(!rc) { uint32_t status=0; copy(output,&status,sizeof status); *bytes=sizeof status; }
        else arm(ref);
    } else rc=NTWV_ERROR_NOT_SUPPORTED;
    leave(); return rc;
}
uint32_t ntwv_pma_take_ack(const struct ntwv_dioc *r,uint64_t id) {
    uint32_t rc=0;
    if(!enter()) return NTWV_ERROR_BUSY;
    if(!load(&owner_present) || !authorized(r) || !owner.ready || owner.result.request_id!=id)
        rc=NTWV_ERROR_ACCESS_DENIED;
    else owner.ready=0;
    leave(); return rc;
}
uint32_t ntwv_pma_close_ack(const struct ntwv_dioc *r) {
    uint32_t rc;
    if(!enter()) return NTWV_ERROR_BUSY;
    if(!load(&owner_present) || !authorized(r) || !owner.closing) rc=NTWV_ERROR_ACCESS_DENIED;
    else rc=release_owner();
    leave(); return rc;
}

void ntwv_pma_timeout(uint32_t ref) {
    uintptr_t flags;
    if(!load(&initialized) || ref!=load(&lifetime) || !load(&owner_present)) return;
    /* First invalidate the matching handle; never cancel an executed timeout. */
    (void)__atomic_exchange_n(&timeout_handle,0,__ATOMIC_ACQ_REL);
    flags=svc.enter(0);
    if(!load(&event_handle)) {
        uint32_t h=svc.schedule_event(ref);
        store(&event_handle,h);
        if(!h) store(&schedule_failed,1);
    }
    svc.leave(0,flags);
    if(!load(&event_handle)) arm(ref);
}

static int query_info(const shz_msg_hdr_t *h,const uint8_t *payload) {
    shz_pma_info_t info;
    if(h->status!=SHZ_OK || h->payload_length!=sizeof info) return 0;
    copy(&info,payload,sizeof info);
    if(info.magic!=SHZ_PMA_MAGIC || info.size!=sizeof info || info.abi_major!=SHZ_PMA_ABI_MAJOR || info.flags ||
       (info.features&(SHZ_PMA_FEATURE_EVENTS|SHZ_PMA_FEATURE_LIFECYCLE))!=
           (SHZ_PMA_FEATURE_EVENTS|SHZ_PMA_FEATURE_LIFECYCLE) ||
       info.generation!=owner.channel.generation || info.self_domain!=owner.channel.peer_domain ||
       info.peer_domain!=owner.channel.self_domain || !info.max_owners || !info.max_threads ||
       !info.max_objects || !info.max_waits || !info.max_completions) return 0;
    if(!owner.completed && !owner.closing) {
        zero(&owner.result,sizeof owner.result); owner.result.magic=NTWV_PMA_ENDPOINT_MAGIC;
        owner.result.size=sizeof owner.result; owner.result.kind=NTWV_PMA_RESULT_QUERY;
        owner.result.request_id=h->request_id; owner.result.generation=h->generation;
        copy(&owner.result.info,&info,sizeof info); owner.ready=owner.completed=1;
    }
    return 1;
}
static uint32_t rejection(const shz_msg_hdr_t *h) {
    /* Kernel64's actual pma_retry_inbound returns a header-only rejection for
     * an unaccepted request. Unknown statuses or bodies are not terminal. */
    if(h->payload_length) return 0;
    switch(h->status) {
    case SHZ_E_UNSUPPORTED: return NTWV_ERROR_NOT_SUPPORTED;
    case SHZ_E_DENIED: return NTWV_ERROR_ACCESS_DENIED;
    case SHZ_E_NOMEM: return NTWV_ERROR_NOT_ENOUGH_MEMORY;
    case SHZ_E_STALE: return NTWV_ERROR_DEV_NOT_EXIST;
    case SHZ_E_TIMEOUT: return NTWV_ERROR_TIMEOUT;
    case SHZ_E_BUSY: case SHZ_E_QUEUE_FULL: return NTWV_ERROR_BUSY;
    case SHZ_E_INVALID: case SHZ_E_RANGE: return NTWV_ERROR_INVALID_PARAMETER;
    case SHZ_E_CANCELLED: case SHZ_E_PROTO: return NTWV_ERROR_GEN_FAILURE;
    default: return 0;
    }
}
static int cleanup_reply(const shz_msg_hdr_t *h,const uint8_t *payload) {
    shz_pma_completion_t c;
    if(h->status!=SHZ_OK || h->payload_length!=sizeof c) return 0;
    copy(&c,payload,sizeof c);
    return c.magic==SHZ_PMA_MAGIC && c.abi_major==SHZ_PMA_ABI_MAJOR && c.size==sizeof c && !c.flags &&
        c.domain==owner.channel.self_domain && c.pid==load(&owner_process) && c.tid==load(&owner_thread) &&
        c.owner_generation==load(&lifetime) && c.thread_generation==load(&lifetime) &&
        !c.object && c.sequence==owner.cleanup_id && c.status==SHZ_OK && !c.reserved;
}
void ntwv_pma_event(uint32_t vm,uint32_t thread,uint32_t ref) {
    uint32_t notify=0, handle=0;
    uint64_t notified_id=0;
    (void)thread;
    if(!load(&initialized) || ref!=load(&lifetime) || !load(&owner_present)) return;
    (void)__atomic_exchange_n(&event_handle,0,__ATOMIC_ACQ_REL);
    __atomic_add_fetch(&callback_active,1,__ATOMIC_ACQ_REL);
    if(!enter()) { arm(ref); goto finished; }
    if(vm!=svc.system_vm() || vm!=svc.current_vm()) { arm(ref); leave(); goto finished; }
    if(load(&dying)) request_cleanup();
    if(owner.query_id || owner.cleanup_sent) {
        for(uint32_t n=0;n<owner.channel.slot_count;++n) {
            uint8_t slot[SHZ_MSG_SLOT_SIZE]; shz_msg_hdr_t h;
            uint32_t rc=ntwv_endpoint_recv(slot);
            if(rc==NTWV_ERROR_NO_MORE_ITEMS || rc==NTWV_ERROR_BUSY) break;
            if(rc) { error_result(rc); break; }
            copy(&h,slot,sizeof h);
            if(h.flags!=SHZ_MSGF_REPLY || h.generation!=owner.channel.generation ||
               h.src_domain!=owner.channel.peer_domain || h.dst_domain!=owner.channel.self_domain) continue;
            if(owner.query_id && h.request_id==owner.query_id && h.opcode==SHZ_OP_PMA_QUERY) {
                uint32_t rejected=rejection(&h);
                if(rejected) {
                    if(h.status==SHZ_E_STALE) store(&namespace_poisoned,1);
                    error_result(rejected); owner.query_id=0;
                }
                else if(query_info(&h,slot+sizeof h)) owner.query_id=0;
            } else if(owner.cleanup_sent && h.request_id==owner.cleanup_id && h.opcode==SHZ_OP_PMA_PROCESS_EXIT) {
                if(cleanup_reply(&h,slot+sizeof h)) owner.cleanup_done=1;
            }
        }
    }
    if(owner.query_id && (uint32_t)(svc.now_ms()-owner.start)>=owner.timeout_ms) error_result(NTWV_ERROR_TIMEOUT);
    if(load(&schedule_failed)) { error_result(NTWV_ERROR_GEN_FAILURE); store(&schedule_failed,0); }
    if(owner.ready && !owner.closing && !owner.notified) {
        notify=1; handle=owner.event; notified_id=owner.result.request_id; owner.notified=1;
        /* This hold belongs to the native call, not to broker admission. A
         * resumed owner may request CLOSE while signaling is in flight. */
        __atomic_add_fetch(&notification_active,1,__ATOMIC_ACQ_REL);
    }
    if(owner.closing && load(&dying) && !finish_close()) (void)release_owner();
    if(load(&owner_present) && (!owner.cleanup_done || (owner.closing && load(&dying)))) arm(ref);
    leave();
    /* Native Win32 signaling may make the waiting thread runnable. All broker
     * and SPSC admission and IRQ masking have ended before this service. */
    if(notify && !svc.set_event(handle)) {
        if(enter()) {
            if(load(&owner_present) && ref==load(&lifetime) && owner.ready && owner.result.request_id==notified_id)
                owner.result.error=NTWV_ERROR_GEN_FAILURE;
            leave();
        }
    }
    if(notify) __atomic_sub_fetch(&notification_active,1,__ATOMIC_ACQ_REL);
finished:
    __atomic_sub_fetch(&callback_active,1,__ATOMIC_ACQ_REL);
}
void ntwv_pma_owner_departed(uint32_t vm,uint32_t thread,uint32_t device,uint32_t process) {
    /* VMM thread notices specify an authoritative global EDI handle, with no
     * VM register contract. VM/device notices instead bind the specified VM. */
    if(!load(&owner_present) || (vm ? vm!=load(&owner_vm) : !thread)) return;
    if((thread && thread!=load(&owner_thread)) || (device && device!=load(&owner_device)) ||
       (process && process!=load(&owner_process))) return;
    store(&dying,1); arm(load(&lifetime));
}
