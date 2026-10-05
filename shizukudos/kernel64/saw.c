/* SPDX-License-Identifier: GPL-2.0-only
 * Native process cleanup on the existing UP NT-compatible process manager.
 * IRQ exclusion protects snapshot/fence/ref publication. No allocation, sleep,
 * destructor or user copy occurs under that exclusion. Every acquired object
 * is referenced until its reply has been copied into private kernel storage.
 */
#include "saw.h"
#include "ipc.h"
#include "auth_policy.h"

void process_saw_protect(process_t *p, uint32_t flags)
{
    const uint64_t f=irq_save();
    if(p&&p->used)p->saw_protection|=flags&(SHZ_SAW_PROTECT_ROOT|SHZ_SAW_PROTECT_CRITICAL);
    irq_restore(f);
}

/* A child either publishes its ancestry before an atomic NUKE fence (and is
 * included) or fails admission afterwards. An unfinished loader cannot escape
 * by resuming its initial thread: proc.c repeats the child's fence check at
 * the actual thread-object publication point. */
int32_t process_attach_parent(process_t *parent, process_t *child)
{
    const uint64_t f=irq_save();
    int32_t st=STATUS_SUCCESS;
    if(parent&&(!parent->used||!parent->object||parent->terminated||parent->teardown||
               parent->exit_owner||parent->saw_fenced))st=STATUS_PROCESS_IS_TERMINATING;
    else if(parent){child->parent_pid=(uint64_t)parent->pid;child->parent_generation=parent->saw_generation;}
    irq_restore(f);
    return st;
}

typedef struct {process_t *p;unsigned count;int kernel_wait;} census_t;
static void census_thread(thread_t *t,void *opaque)
{
    census_t *c=opaque;
    if(t->proc!=c->p||!t->object||t->state==TS_FREE||t->state==TS_ZOMBIE)return;
    ++c->count;
    if(t->state==TS_BLOCKED&&t->wait_sem)c->kernel_wait=1;
}
static unsigned live_threads(process_t *p,int *kernel_wait)
{
    census_t c={p,0,0};
    /* thread_slot may return NULL at a restricted AP slot in the middle of
     * the table. The native iterator skips these holes rather than stopping. */
    sched_for_each_thread(census_thread,&c);
    *kernel_wait=c.kernel_wait;
    return c.count;
}

static void snapshot(process_t *p, shz_saw_row *r)
{
    int kernel_wait;
    memset(r,0,sizeof *r);
    r->pid=(uint64_t)p->pid;r->parent_pid=p->parent_pid;r->generation=p->saw_generation;
    r->protection=p->saw_protection;r->contexts=SHZ_SAW_CONTEXT_KERNEL64;
    r->threads=live_threads(p,&kernel_wait);r->handles=p->handle_count;r->vads=p->vads.count;
    r->references=p->object?p->object->refs:0;
    memcpy(r->name,p->name,sizeof r->name-1);
    if(p->pml4&&p->pml4!=kernel_pml4())r->contexts|=SHZ_SAW_CONTEXT_ADDRESS_SPACE;
    if(p->handle_count)r->contexts|=SHZ_SAW_CONTEXT_HANDLES;
    if(p->ipc)r->contexts|=SHZ_SAW_CONTEXT_IPC;
    r->lifecycle=p->terminated?SHZ_SAW_EXIT_PENDING:SHZ_SAW_RUNNING;
    if(p->saw_protection)r->reasons|=SHZ_SAW_REASON_ROOT_BOUNDARY;
    if(!p->object||!p->object->refs) {
        r->classification=SHZ_SAW_ARMORED;r->reasons|=SHZ_SAW_REASON_THREAD_ACCOUNTING;
    } else if((p->object&&p->object->signaled&&p->threads_alive>0)||
       (p->teardown==2&&p->threads_alive>0)) {
        r->classification=SHZ_SAW_ARMORED;r->reasons|=SHZ_SAW_REASON_LIVE_AFTER_SIGNAL;
    } else if(p->teardown==2&&((r->contexts&~SHZ_SAW_CONTEXT_KERNEL64)||p->token||p->modules)) {
        r->classification=SHZ_SAW_ARMORED;r->reasons|=SHZ_SAW_REASON_RESOURCES_AFTER_TEARDOWN;
    } else if(p->threads_alive<0) {
        r->classification=SHZ_SAW_ARMORED;r->reasons|=SHZ_SAW_REASON_THREAD_ACCOUNTING;
    } else if(p->terminated&&!p->teardown&&!(r->contexts&SHZ_SAW_CONTEXT_ADDRESS_SPACE)) {
        /* A normal used process owns a private PML4 until teardown. Never
         * pass a missing/kernel PML4 to the reclamation path after corruption. */
        r->classification=SHZ_SAW_ARMORED;r->reasons|=SHZ_SAW_REASON_NO_TEARDOWN;
    } else if(p->terminated&&p->teardown==2) {
        /* A last exiting thread can still be in thread_exit's kernel tail.
         * It is not user execution left after exit. NT object/exit status,
         * open-handle references and creator/reaper holds remain legitimate. */
        r->classification=SHZ_SAW_ADMISSED;r->lifecycle=SHZ_SAW_EXITED;
        r->reasons|=SHZ_SAW_REASON_WAIT_REFS;
    } else if(p->terminated&&p->threads_alive==0&&!r->threads&&!p->teardown&&!p->saw_constructing) {
        r->classification=SHZ_SAW_ZOMBIE;r->reasons|=SHZ_SAW_REASON_NO_TEARDOWN;
    } else if(p->terminated||p->exit_owner||p->teardown) {
        r->reasons|=SHZ_SAW_REASON_EXIT_PENDING;
        if(p->teardown==1)r->reasons|=SHZ_SAW_REASON_TEARDOWN_BUSY;
        if(p->saw_constructing)r->reasons|=SHZ_SAW_REASON_TEARDOWN_BUSY;
        if(kernel_wait)r->reasons|=SHZ_SAW_REASON_KERNEL_WAIT;
    }
}

typedef struct {process_t *p;kobject_t *object;unsigned depth;} target_t;
static int target_index(target_t *t,unsigned count,process_t *p)
{
    unsigned i;for(i=0;i<count;i++)if(t[i].p==p)return (int)i;return -1;
}

static int32_t finish_target(target_t *target,uint64_t deadline,const shz_saw_row *before,shz_saw_row *row)
{
    process_t *p=target->p;
    for(;;) {
        int reclaim=0;
        const uint64_t f=irq_save();
        snapshot(p,row);
        if(row->classification==SHZ_SAW_ARMORED){irq_restore(f);return STATUS_UNSUCCESSFUL;}
        if(!row->threads&&p->threads_alive==0&&p->terminated&&!p->teardown&&!p->saw_constructing)reclaim=1;
        if(p->terminated&&p->teardown==2&&!row->threads) {
            if(before->threads)row->steps|=SHZ_SAW_STEP_THREADS_QUIESCENT;
            if(before->contexts&SHZ_SAW_CONTEXT_ADDRESS_SPACE)row->steps|=SHZ_SAW_STEP_MEMORY_RELEASED;
            if(before->contexts&SHZ_SAW_CONTEXT_HANDLES)row->steps|=SHZ_SAW_STEP_HANDLES_CLOSED;
            if(before->contexts&SHZ_SAW_CONTEXT_IPC)row->steps|=SHZ_SAW_STEP_IPC_RELEASED;
            irq_restore(f);
            thread_reap_process(p);
            return STATUS_SUCCESS;
        }
        irq_restore(f);
        if(reclaim) {
            process_teardown(p);
            /* Mirrors the actual last-thread signal, without a fabricated
             * thread exit. Caller reference pins the object through this. */
            {const uint64_t g=irq_save();p->object->signaled=1;ob_release_check(p->object);irq_restore(g);}
            sem_post(&p->exited);
            continue;
        }
        if(ticks_now()>=deadline)return STATUS_PENDING;
        thread_sleep_ms(1);
    }
}

int32_t saw_execute(process_t *actor,const shz_saw_request *q,shz_saw_reply *out)
{
    target_t targets[SHZ_SAW_MAX_ROWS];
    unsigned n=0,i,pass;
    process_t *p,*root;
    uint64_t f,deadline;
    int32_t st=STATUS_SUCCESS;
    const int force=q->operation==SHZ_SAW_CHARBOMBA;
    memset(out,0,sizeof *out);out->version=SHZ_SAW_VERSION;out->size=sizeof *out;
    if(q->version!=SHZ_SAW_VERSION||q->size!=sizeof *q||q->flags||q->reserved||
       q->operation<SHZ_SAW_QUERY||q->operation>SHZ_SAW_CHARBOMBA||q->wait_ms>SHZ_SAW_MAX_WAIT_MS||
       (!force&&q->acknowledgement))return out->status=STATUS_INVALID_PARAMETER;
    if(q->operation==SHZ_SAW_QUERY) {
        if(q->pid||q->generation||q->wait_ms)return out->status=STATUS_INVALID_PARAMETER;
        f=irq_save();
        for(i=1;(p=process_slot(i))!=0&&out->count<SHZ_SAW_MAX_ROWS;i++)if(p->used&&p->object&&p->object->refs&&shz_auth_saw_process_access(actor,p))
            snapshot(p,&out->rows[out->count++]);
        out->targets=out->count;irq_restore(f);return STATUS_SUCCESS;
    }
    if(!q->pid||q->pid>0x7fffffffu||!q->generation)return out->status=STATUS_INVALID_PARAMETER;
    if(force&&(q->acknowledgement!=SHZ_SAW_DESTRUCTIVE_ACK||!shz_auth_saw_force_allowed(actor))) {
        out->rows[0].reasons=SHZ_SAW_REASON_FORCE_ACK;out->count=1;
        out->rows[0].pid=q->pid;out->rows[0].generation=q->generation;out->rows[0].status=STATUS_ACCESS_DENIED;
        return out->status=STATUS_ACCESS_DENIED;
    }
    f=irq_save();root=process_by_pid((int)q->pid);
    if(!root||!root->object||!root->object->refs||root->saw_generation!=q->generation) {
        out->rows[0].reasons=SHZ_SAW_REASON_IDENTITY;out->count=1;
        out->rows[0].pid=q->pid;out->rows[0].generation=q->generation;out->rows[0].status=STATUS_INVALID_CID;
        irq_restore(f);return out->status=STATUS_INVALID_CID;
    }
    if(!shz_auth_saw_process_access(actor,root)) {
        irq_restore(f);return out->status=STATUS_ACCESS_DENIED;
    }
    targets[n++]=(target_t){root,root->object,0};
    if(q->operation==SHZ_SAW_NUKE) {
        /* Fixed-point closure before any mutation. Existing child ancestry
         * is generational; arbitrary reused PID parents do not join the tree. */
        for(pass=0;pass<SHZ_SAW_MAX_ROWS;pass++) {
            unsigned before=n;
            for(i=1;(p=process_slot(i))!=0;i++)if(p->used&&target_index(targets,n,p)<0) {
                unsigned k;for(k=0;k<n;k++)if(p->parent_pid==(uint64_t)targets[k].p->pid&&
                    p->parent_generation==targets[k].p->saw_generation) {
                    if(n==SHZ_SAW_MAX_ROWS){st=STATUS_INSUFFICIENT_RESOURCES;break;}
                    targets[n++]=(target_t){p,p->object,targets[k].depth+1};break;
                }
            }
            if(st||n==before)break;
        }
    }
    out->targets=n;out->count=n;
    /* Preflight all ownership/protection boundaries: rejected NUKE cannot
     * partially kill an accessible branch before finding a protected one. */
    for(i=0;i<n;i++) {
        snapshot(targets[i].p,&out->rows[i]);
        if(!targets[i].object||!targets[i].object->refs)st=STATUS_INVALID_CID;
        else if(!shz_auth_saw_process_access(actor,targets[i].p)) {
            /* Descendant existence is relevant to the rejected tree, but
             * another account's name/resource details are not disclosed. */
            memset(&out->rows[i],0,sizeof out->rows[i]);
            out->rows[i].reasons=SHZ_SAW_REASON_ACCESS;st=STATUS_ACCESS_DENIED;
        } else if(targets[i].p==actor) {
            out->rows[i].reasons|=SHZ_SAW_REASON_SELF;st=STATUS_INVALID_PARAMETER;
        } else if(targets[i].p->saw_protection&&!force) {
            out->rows[i].reasons|=SHZ_SAW_REASON_ROOT_BOUNDARY;
            out->flags|=SHZ_SAW_REPLY_PROTECTED;st=STATUS_ACCESS_DENIED;
        } else if(out->rows[i].classification==SHZ_SAW_ARMORED&&!force)st=STATUS_UNSUCCESSFUL;
    }
    if(st){irq_restore(f);for(i=0;i<n;i++)out->rows[i].status=st;return out->status=st;}
    for(i=0;i<n;i++){ob_ref(targets[i].object);targets[i].p->saw_fenced=1;}
    irq_restore(f);
    deadline=ticks_now()+((uint64_t)q->wait_ms*1000u+TICK_US-1)/TICK_US;
    if(force)out->flags|=SHZ_SAW_REPLY_FORCED;
    /* Dependency order is leaf-to-root. No user children/threads can be
     * published after the whole closure has been fenced. */
    for(pass=SHZ_SAW_MAX_ROWS;pass>0;pass--)for(i=0;i<n;i++)if(targets[i].depth==pass-1) {
        shz_saw_row before;
        f=irq_save();snapshot(targets[i].p,&before);irq_restore(f);
        if(before.classification==SHZ_SAW_ARMORED) {
            /* Explicit force cannot promise recovery from proven corrupt
             * accounting/mappings. Enter the actual fatal kernel path. */
            if(force)kpanic("CHARBOMBA: process teardown invariants lost");
            out->rows[i]=before;out->rows[i].status=STATUS_UNSUCCESSFUL;
            out->status=STATUS_UNSUCCESSFUL;continue;
        }
        if(before.classification==SHZ_SAW_ADMISSED) {
            out->rows[i]=before;out->flags|=SHZ_SAW_REPLY_ADMITTED;
            out->rows[i].status=STATUS_SUCCESS;continue;
        }
        process_terminate(targets[i].p,1,0);
        st=finish_target(&targets[i],deadline,&before,&out->rows[i]);
        out->rows[i].steps|=SHZ_SAW_STEP_TERMINATION_REQUESTED;out->rows[i].status=st;
        if(st==STATUS_SUCCESS)++out->completed;
        else {out->status=st;if(st==STATUS_PENDING)out->flags|=SHZ_SAW_REPLY_PENDING;}
    }
    for(i=0;i<n;i++)ob_deref(targets[i].object);
    return out->status;
}

int32_t saw_syscall(process_t *p,uint64_t request,uint64_t request_bytes,uint64_t reply,uint64_t reply_bytes)
{
    shz_saw_request q;
    shz_saw_reply *out;
    int32_t st;
    if(request_bytes!=sizeof q||reply_bytes!=sizeof *out)return STATUS_INFO_LENGTH_MISMATCH;
    if(copy_from_user(p,&q,request,sizeof q))return STATUS_ACCESS_VIOLATION;
    out=kzalloc(sizeof *out);
    if(!out)return STATUS_NO_MEMORY;
    /* Reject invalid output pages before irreversible native teardown. */
    if(copy_to_user(p,reply,out,sizeof *out)){kfree(out);return STATUS_ACCESS_VIOLATION;}
    st=saw_execute(p,&q,out);
    if(copy_to_user(p,reply,out,sizeof *out))st=STATUS_ACCESS_VIOLATION;
    kfree(out);return st;
}

int32_t sys_ext_saw(process_t *p,struct regs *r,uint32_t num,uint64_t a1,uint64_t a2,uint64_t a3,uint64_t a4)
{
    (void)r;
    return num==SHZ_SAW_SYSCALL?saw_syscall(p,a1,a2,a3,a4):STATUS_NOT_IMPLEMENTED;
}
