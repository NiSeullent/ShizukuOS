/* SPDX-License-Identifier: GPL-2.0-only -- original provider ingress ownership */
#include "ingress.h"
#define NI_OPEN 1u
#define NI_CLOSED 2u
#define NI_STARTING 1u
#define NI_READY 2u
#define NI_TLS_ONLY 3u
#define NI_STOPPING 4u

static int overlap(const void *a, size_t na, const void *b, size_t nb)
{
    uintptr_t x=(uintptr_t)a, y=(uintptr_t)b;
    if(!na || !nb) return 0;
    if(x>UINTPTR_MAX-(na-1) || y>UINTPTR_MAX-(nb-1)) return 1;
    return x<=y ? y-x<na : x-y<nb;
}
static ni_status open_manager(const ni_manager *m)
{
    if(!m || m->self!=m || m->state!=NI_OPEN || !m->plan || !m->plan->ready)
        return NI_NOT_OPEN;
    return m->notification_active ? NI_NOTIFICATION_ACTIVE : NI_OK;
}
static int output_alias(const ni_manager *m, const void *out, size_t bytes)
{
    uint32_t i,j;
    if(overlap(out,bytes,m,sizeof(*m)) || overlap(out,bytes,m->plan,sizeof(*m->plan))) return 1;
    for(i=0;i<m->plan->count;i++) {
        const ntw_tls_module *s=&m->plan->module[i];
        if(overlap(out,bytes,s->index_address,4) ||
           overlap(out,bytes,s->initial,s->bytes)) return 1;
        for(j=0;j<NI_WORKERS;j++) {
            const ntw_tls_thread *t=&m->worker[j].tls;
            uint32_t data_bytes=s->bytes+s->zero;
            if(overlap(out,bytes,t->data[i],t->data[i]?(data_bytes?data_bytes:1):0)) return 1;
        }
    }
    return 0;
}
static ni_status get_worker(ni_manager *m, const ni_handle *h, ni_worker **out)
{
    ni_worker *w;
    if(!h || h->manager!=m || h->slot>=NI_WORKERS || !h->generation) return NI_HANDLE;
    w=&m->worker[h->slot];
    if(!w->state || w->generation!=h->generation) return NI_HANDLE;
    if(m->plan->ops.thread_id(m->plan->ops.context)!=w->owner) return NI_WRONG_THREAD;
    *out=w; return NI_OK;
}
static int tls_identity(ni_manager *m, const ni_worker *w)
{
    uint32_t i;
    if(!w->tls.active || w->tls.plan!=m->plan || w->tls.owner!=w->owner ||
       w->tls.published>m->plan->count) return 0;
    for(i=0;i<w->tls.published;i++) {
        void *actual=NULL;
        if(!m->plan->ops.read(m->plan->ops.context,m->plan->module[i].slot,&actual) ||
           actual!=w->tls.data[i]) return 0;
    }
    return 1;
}
static void notification(ni_manager *m, ni_worker *w, uint32_t reason)
{
    m->notification_active=1;
    m->notify(m->context,reason,&w->tls);
    m->notification_active=0;
}
static void retired(ni_manager *m, ni_worker *w)
{
    w->state=0; w->owner=0; w->depth=0; w->notified=0;
    m->live_workers--;
}
ni_status ni_manager_init(ni_manager *m, ntw_tls_plan *p, ni_notify notify, void *context)
{
    uint32_t i;
    if(!m || !p || !notify || !p->ready || p->count>NTW_TLS_MODULES || !p->ops.thread_id ||
       !p->ops.read || !p->ops.publish || !p->ops.allocate || !p->ops.deallocate)
        return NI_ARGUMENT;
    if(overlap(m,sizeof(*m),p,sizeof(*p))) return NI_OUTPUT_ALIAS;
    for(i=0;i<p->count;i++) {
        if(overlap(m,sizeof(*m),p->module[i].index_address,4) ||
           overlap(m,sizeof(*m),p->module[i].initial,p->module[i].bytes))
            return NI_OUTPUT_ALIAS;
    }
    if(m->self || m->state || m->closing || m->notification_active || m->live_workers || m->live_calls)
        return NI_NOT_OPEN;
    for(i=0;i<NI_WORKERS;i++) {
        const ni_worker *w=&m->worker[i];
        if(w->state || w->generation || w->owner || w->depth || w->serial || w->notified || w->tls.active)
            return NI_ARGUMENT;
    }
    m->self=m; m->plan=p; m->notify=notify; m->context=context; m->last_tls_error=NULL; m->state=NI_OPEN;
    return NI_OK;
}
ni_status ni_worker_start(ni_manager *m, ni_handle *out)
{
    ni_status s=open_manager(m); ni_worker *w=NULL; ni_handle h;
    uint32_t i,owner;
    if(s!=NI_OK) return s;
    if(!out) return NI_ARGUMENT;
    if(output_alias(m,out,sizeof(*out))) return NI_OUTPUT_ALIAS;
    if(m->closing) return NI_CLOSING;
    owner=m->plan->ops.thread_id(m->plan->ops.context);
    if(!owner) return NI_ARGUMENT;
    for(i=0;i<NI_WORKERS;i++) {
        if(m->worker[i].state && m->worker[i].owner==owner) return NI_DUPLICATE_THREAD;
        if(!w && !m->worker[i].state && m->worker[i].generation!=UINT32_MAX) {
            w=&m->worker[i]; h.slot=i;
        }
    }
    if(!w) return NI_LIMIT;
    h.generation=++w->generation; h.manager=m;
    w->owner=owner; w->state=NI_STARTING; w->serial=0; m->live_workers++;
    if(!ntw_tls_attach(m->plan,&w->tls,&m->last_tls_error)) {
        if(w->tls.active) { w->state=NI_TLS_ONLY; *out=h; return NI_TLS_RETAINED; }
        retired(m,w); return NI_TLS_ATTACH;
    }
    notification(m,w,NI_THREAD_ATTACH); w->notified=1;
    if(!tls_identity(m,w)) { w->state=NI_TLS_ONLY; *out=h; return NI_TLS_IDENTITY; }
    w->state=NI_READY; *out=h; return NI_OK;
}
ni_status ni_callback_enter(ni_manager *m, const ni_handle *h, ni_frame *out)
{
    ni_status s=open_manager(m); ni_worker *w; ni_frame frame;
    if(s!=NI_OK) return s;
    if(!out || !h) return NI_ARGUMENT;
    if(output_alias(m,out,sizeof(*out)) || overlap(out,sizeof(*out),h,sizeof(*h))) return NI_OUTPUT_ALIAS;
    if(m->closing) return NI_CLOSING;
    s=get_worker(m,h,&w); if(s!=NI_OK) return s;
    if(w->state!=NI_READY) return NI_BUSY;
    if(!tls_identity(m,w)) return NI_TLS_IDENTITY;
    if(w->depth>=NI_DEPTH || w->serial==UINT32_MAX) return NI_LIMIT;
    frame.worker=*h; frame.depth=w->depth+1; frame.serial=++w->serial;
    w->stack[w->depth++]=frame.serial; m->live_calls++; *out=frame;
    return NI_OK;
}
ni_status ni_callback_leave(ni_manager *m, const ni_frame *frame)
{
    ni_status s=open_manager(m); ni_worker *w;
    if(s!=NI_OK) return s;
    if(!frame) return NI_ARGUMENT;
    s=get_worker(m,&frame->worker,&w); if(s!=NI_OK) return s;
    if(w->state!=NI_READY || !w->depth || frame->depth!=w->depth || frame->serial!=w->stack[w->depth-1])
        return NI_FRAME_ORDER;
    if(!tls_identity(m,w)) return NI_TLS_IDENTITY;
    w->stack[--w->depth]=0; m->live_calls--; return NI_OK;
}
ni_status ni_worker_stop(ni_manager *m, const ni_handle *h)
{
    ni_status s=open_manager(m); ni_worker *w;
    if(s!=NI_OK) return s;
    s=get_worker(m,h,&w); if(s!=NI_OK) return s;
    if(w->state!=NI_READY && w->state!=NI_TLS_ONLY) return NI_BUSY;
    if(w->depth) return NI_BUSY;
    if(!tls_identity(m,w)) return NI_TLS_IDENTITY;
    w->state=NI_STOPPING;
    if(w->notified) { notification(m,w,NI_THREAD_DETACH); w->notified=0; }
    if(!tls_identity(m,w)) { w->state=NI_TLS_ONLY; return NI_TLS_IDENTITY; }
    if(!ntw_tls_detach(&w->tls,&m->last_tls_error)) { w->state=NI_TLS_ONLY; return NI_TLS_DETACH; }
    retired(m,w); return NI_OK;
}
ni_status ni_begin_close(ni_manager *m)
{
    ni_status s=open_manager(m); if(s!=NI_OK) return s;
    m->closing=1; return NI_OK;
}
ni_status ni_finish(ni_manager *m)
{
    ni_status s=open_manager(m); if(s!=NI_OK) return s;
    if(!m->closing || m->live_workers || m->live_calls) return NI_BUSY;
    m->state=NI_CLOSED; return NI_OK;
}
const char *ni_status_name(ni_status status)
{
    static const char *const names[]={"OK","ARGUMENT","NOT_OPEN","NOTIFICATION_ACTIVE","CLOSING",
        "LIMIT","DUPLICATE_THREAD","HANDLE","WRONG_THREAD","BUSY","FRAME_ORDER","TLS_ATTACH",
        "TLS_RETAINED","TLS_IDENTITY","TLS_DETACH","OUTPUT_ALIAS"};
    return (unsigned)status<sizeof(names)/sizeof(names[0]) ? names[status] : "UNKNOWN";
}
