/* SPDX-License-Identifier: GPL-2.0-only
 * ReactOS-reference derivative, distributed under GNU GPL version 2.
 * Original upstream notice (sdk/lib/rtl/vectoreh.c):
 * COPYRIGHT:         See COPYING in the top level directory
 * PROJECT:           ReactOS sysem libraries
 * PURPOSE:           Vectored Exception Handling
 * FILE:              lib/rtl/vectoreh.c
 * PROGRAMERS:        Thomas Weidenmueller
 *
 * Reference pin cae3c053d47024545c773148185319075eae0202.
 * 2026 Shizuku port changes: explicit registry/callback services, numeric
 * handles, immediate unlink, bounded reference-pinned snapshots, no Win32
 * exports. This is deliberately not an unchanged Windows behavior clone.
 * Wine's corresponding implementation was reviewed, not copied. Provenance
 * and the preserved GPLv2 text accompany this file.
 */
#include "veh.h"
typedef struct ntwe_node {
    struct ntwe_node *next,*previous;
    ntwe_handler handler;
    void *user;
    uint32_t handle,refs,active;
} ntwe_node;

static int valid(ntwe_registry *r)
{ return r && r->ops.allocate && r->ops.release && r->ops.lock && r->ops.unlock; }
static int kind_valid(enum ntwe_kind kind)
{ return kind==NTWE_EXCEPTION || kind==NTWE_CONTINUE; }
static void lock(ntwe_registry *r){r->ops.lock(r->ops.user);}
static void unlock(ntwe_registry *r){r->ops.unlock(r->ops.user);}
static void dispose(ntwe_registry *r,ntwe_node *n)
{ r->ops.release(r->ops.user,n,sizeof(*n)); }
static void dispose_chain(ntwe_registry *r,ntwe_node *n)
{ while(n){ntwe_node *next=n->next;dispose(r,n);n=next;} }

int ntwe_init(ntwe_registry *r,const ntwe_ops *ops)
{
    unsigned i;
    if(!r || !ops || !ops->allocate || !ops->release || !ops->lock || !ops->unlock)return NTWE_INVALID;
    r->ops=*ops;
    for(i=0;i<2;++i){r->head[i]=0;r->tail[i]=0;r->count[i]=0;}
    r->dispatches=0;r->next_handle=1;r->closed=0;
    return NTWE_OK;
}

int ntwe_add(ntwe_registry *r,enum ntwe_kind kind,int first,ntwe_handler handler,void *user,ntwe_handle *out)
{
    ntwe_node *n;int error=NTWE_OK;
    if(!valid(r)||!kind_valid(kind)||!handler||!out)return NTWE_INVALID;
    /* Never call a potentially reentrant heap while holding the registry lock. */
    n=r->ops.allocate(r->ops.user,sizeof(*n));
    if(!n)return NTWE_NO_MEMORY;
    n->next=0;n->previous=0;n->handler=handler;n->user=user;n->refs=1;n->active=1;
    lock(r);
    if(r->closed)error=NTWE_CLOSED;
    else if(r->count[0]+r->count[1]>=NTWE_MAX_HANDLERS || !r->next_handle)error=NTWE_LIMIT;
    else {
        n->handle=r->next_handle++;
        if(first){n->next=r->head[kind];if(n->next)n->next->previous=n;else r->tail[kind]=n;r->head[kind]=n;}
        else {n->previous=r->tail[kind];if(n->previous)n->previous->next=n;else r->head[kind]=n;r->tail[kind]=n;}
        ++r->count[kind];*out=n->handle;
    }
    unlock(r);
    if(error!=NTWE_OK)dispose(r,n);
    return error;
}

int ntwe_remove(ntwe_registry *r,enum ntwe_kind kind,ntwe_handle handle)
{
    ntwe_node *n;int pending;
    if(!valid(r)||!kind_valid(kind))return NTWE_INVALID;
    lock(r);
    for(n=r->head[kind];n && n->handle!=handle;n=n->next){}
    if(!n){unlock(r);return NTWE_NOT_FOUND;}
    /* Unlink immediately: repeated remove cannot consume a dispatch reference. */
    if(n->previous)n->previous->next=n->next;else r->head[kind]=n->next;
    if(n->next)n->next->previous=n->previous;else r->tail[kind]=n->previous;
    n->next=0;n->previous=0;n->active=0;--r->count[kind];
    pending=--n->refs!=0;
    unlock(r);
    if(!pending)dispose(r,n);
    return pending?NTWE_PENDING:NTWE_OK;
}

int ntwe_dispatch(ntwe_registry *r,enum ntwe_kind kind,void *record,void *context,int32_t *out)
{
    ntwe_node *snapshot[NTWE_MAX_HANDLERS],*n,*free_list=0;
    uint32_t count=0,i;ntwe_pointers exception;
    int32_t result=NTWE_CONTINUE_SEARCH;
    if(!valid(r)||!kind_valid(kind)||!record||!context||!out)return NTWE_INVALID;
    exception.exception_record=record;exception.context_record=context;
    lock(r);
    if(r->closed){unlock(r);return NTWE_CLOSED;}
    if(r->dispatches>=NTWE_MAX_DISPATCHES){unlock(r);return NTWE_LIMIT;}
    ++r->dispatches;
    for(n=r->head[kind];n;n=n->next){++n->refs;snapshot[count++]=n;}
    unlock(r);
    for(i=0;i<count;++i){
        ntwe_handler handler=0;void *user=0;
        n=snapshot[i];
        lock(r);
        /* This lock acquisition reserves this callback. A later remove may
         * return before it runs, but its pinned node/code lifetime remains. */
        if(n->active){handler=n->handler;user=n->user;}
        unlock(r);
        if(handler && handler(&exception,user)==NTWE_CONTINUE_EXECUTION){result=NTWE_CONTINUE_EXECUTION;break;}
    }
    lock(r);
    for(i=0;i<count;++i){n=snapshot[i];if(--n->refs==0){n->next=free_list;free_list=n;}}
    unlock(r);
    dispose_chain(r,free_list);
    /* Keep dispatches nonzero through release callbacks, including reentry. */
    lock(r);--r->dispatches;unlock(r);
    *out=result;
    return NTWE_OK;
}

int ntwe_get_stats(ntwe_registry *r,ntwe_stats *out)
{
    ntwe_stats value;
    if(!valid(r)||!out)return NTWE_INVALID;
    lock(r);value.exception_count=r->count[0];value.continue_count=r->count[1];
    value.dispatches=r->dispatches;value.closed=r->closed;unlock(r);
    *out=value;return NTWE_OK;
}

int ntwe_close(ntwe_registry *r)
{
    ntwe_node *n,*next,*free_list=0;unsigned kind;int pending;
    if(!valid(r))return NTWE_INVALID;
    lock(r);r->closed=1;
    for(kind=0;kind<2;++kind){
        for(n=r->head[kind];n;n=next){
            next=n->next;n->active=0;n->previous=0;n->next=0;
            if(--n->refs==0){n->next=free_list;free_list=n;}
        }
        r->head[kind]=0;r->tail[kind]=0;r->count[kind]=0;
    }
    pending=r->dispatches!=0;unlock(r);
    dispose_chain(r,free_list);
    return pending?NTWE_PENDING:NTWE_OK;
}
