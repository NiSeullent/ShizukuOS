/* SPDX-License-Identifier: GPL-2.0-only
 * Actual native W64 consumers and authority, with host hardware/PE boundaries.
 * The runner inserts the named, byte-exact production definitions below.
 * This does not execute a VM, the PE loader body, or a native scheduler.
 */
#include "../kernel64/fs.h"
#include "../kernel64/ipc.h"
#include "../kernel64/sched_cpu.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint64_t host_irq(void);
static void host_restore(uint64_t);
#define irq_save host_irq
#define irq_restore host_restore
#include "../kernel64/sysk32_auth.c"
#include "../kernel64/subsys64.c"

#define MODEL_CHILDREN 16
static thread_t child_threads[MODEL_CHILDREN];
static unsigned child_count;
static thread_t *host_current;
static void kstack_free(uint64_t);
static int bsp_scheduler_owner(void);
static int general_admission_closed(void);
static int restricted_slot(const thread_t *);
static void make_ready(thread_t *);
static int32_t ldr_create_process_body(process_t *,const char *,const char *,const char *,
                                      const ldr_create_ex_t *,process_t *,thread_t **);

/* @PRODUCTION_THREAD_RESUME@ */
/* @PRODUCTION_THREAD_MUST_DIE@ */
/* @PRODUCTION_THREAD_CREATOR_RELEASE@ */
/* @PRODUCTION_THREAD_OBJECT_DETACH@ */
#define threads child_threads
#define thread_hi child_count
#define current host_current
/* @PRODUCTION_REAP_USER_ZOMBIES@ */
/* @PRODUCTION_THREAD_REAP_PROCESS@ */
#undef threads
#undef thread_hi
#undef current
/* @PRODUCTION_IPC_WAKE_TO_DIE@ */
#define process_terminate production_process_terminate
/* @PRODUCTION_PROCESS_TERMINATE@ */
#undef process_terminate
#define proc_wait production_proc_wait
/* @PRODUCTION_PROC_WAIT@ */
#undef proc_wait
/* @PRODUCTION_PROCESS_ATTACH_PARENT@ */
/* @PRODUCTION_LOADER_CREATE@ */

static unsigned checks,cases;
#define CHECK(x) do { __atomic_add_fetch(&checks,1,__ATOMIC_RELAXED); \
    if(!(x)){fprintf(stderr,"check failed at %s:%d: %s\n",__FILE__,__LINE__,#x);abort();} } while(0)
typedef struct {kmutex_t *key;pthread_mutex_t real;} mutex_adapter;
static mutex_adapter mutexes[MODEL_CHILDREN+2];
static unsigned mutex_count;
static pthread_mutex_t irq_mutex=PTHREAD_MUTEX_INITIALIZER;
static _Thread_local unsigned irq_depth,authority_depth;
static _Thread_local int enrollment_worker;
static process_t children[MODEL_CHILDREN],broker;
static thread_t service_thread;
static kobject_t process_objects[MODEL_CHILDREN],thread_objects[MODEL_CHILDREN],broker_token;
static fsnode_t host_fs_root,image_node;
static unsigned loader_calls,fs_calls,wait_calls,teardown_calls,detach_count;
static unsigned user_entries,kill_entries,publication_count,termination_calls;
static int scheduler_closed,scheduler_owner=1,fail_body,fail_allocation,fail_lookup;
static int wait_lookup_failure,pause_teardown;
static uint64_t host_tick;
static _Alignas(64) uint8_t channel_storage[65536];
static uint64_t request_serial;
static int32_t register_status;
static pthread_t register_thread;
static pthread_mutex_t race_mutex=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t race_cond=PTHREAD_COND_INITIALIZER;
static int race_mode,register_prepared,register_enabled,register_attempted;
static int enrolled_publish;                     /* C6: broker-admitted publication of a logged-in owner's child */
static kobject_t child_tokens[MODEL_CHILDREN];
static unsigned ready_order,enrolled_order,order_clock;
enum {RACE_NONE,RACE_ENROLL_IN_LOADER,RACE_READY_FIRST};

static uint64_t host_irq(void)
{
    unsigned previous=irq_depth++;
    if(!previous)CHECK(pthread_mutex_lock(&irq_mutex)==0);
    return previous;
}
static void host_restore(uint64_t previous)
{
    CHECK(irq_depth==(unsigned)previous+1);
    if(!--irq_depth)CHECK(pthread_mutex_unlock(&irq_mutex)==0);
}
static mutex_adapter *adapter(kmutex_t *m)
{
    for(unsigned i=0;i<mutex_count;i++)if(mutexes[i].key==m)return &mutexes[i];
    CHECK(0);return 0;
}
void mutex_init(kmutex_t *m)
{
    CHECK(!authority_depth);CHECK(mutex_count<MODEL_CHILDREN+2);
    for(unsigned i=0;i<mutex_count;i++)CHECK(mutexes[i].key!=m);
    memset(m,0,sizeof *m);mutexes[mutex_count].key=m;
    CHECK(pthread_mutex_init(&mutexes[mutex_count++].real,0)==0);
}
void mutex_lock(kmutex_t *m)
{
    CHECK(!irq_depth);
    if(m==&authority_lock&&enrollment_worker&&race_mode==RACE_READY_FIRST){
        CHECK(pthread_mutex_lock(&race_mutex)==0);register_prepared=1;
        CHECK(pthread_cond_broadcast(&race_cond)==0);
        while(!register_enabled)CHECK(pthread_cond_wait(&race_cond,&race_mutex)==0);
        register_attempted=1;CHECK(pthread_cond_broadcast(&race_cond)==0);
        CHECK(pthread_mutex_unlock(&race_mutex)==0);
    }
    CHECK(pthread_mutex_lock(&adapter(m)->real)==0);m->locked=1;
    if(m==&authority_lock){CHECK(!authority_depth);authority_depth=1;}
}
void mutex_unlock(kmutex_t *m)
{
    if(m==&authority_lock){CHECK(authority_depth==1);authority_depth=0;}
    m->locked=0;CHECK(pthread_mutex_unlock(&adapter(m)->real)==0);
}
static int bsp_scheduler_owner(void){return scheduler_owner;}
static int general_admission_closed(void){return scheduler_closed;}
static int restricted_slot(const thread_t *t){(void)t;return 0;}
static void make_ready(thread_t *t)
{
    CHECK(irq_depth);CHECK(t->state==TS_NEW);
    if(!t->proc->terminated){
        CHECK(authority_depth==1);CHECK(enrolled_publish?authority.count>0:authority.count==0);
        CHECK(t->suspend_count==1);CHECK(find(t->proc,0)->pending);
        ++publication_count;ready_order=++order_clock;
        if(race_mode==RACE_READY_FIRST){
            CHECK(pthread_mutex_lock(&race_mutex)==0);register_enabled=1;
            CHECK(pthread_cond_broadcast(&race_cond)==0);
            while(!register_attempted)CHECK(pthread_cond_wait(&race_cond,&race_mutex)==0);
            CHECK(pthread_mutex_trylock(&adapter(&authority_lock)->real)==EBUSY);
            CHECK(authority.count==0);
            CHECK(pthread_mutex_unlock(&race_mutex)==0);
        }
    }else CHECK(!authority_depth);
    t->state=TS_READY;
}
void thread_wake(thread_t *t){CHECK(irq_depth);t->state=TS_READY;}
thread_t *thread_current(void){return &service_thread;}
void ipc_process_terminating(process_t *p)
{
    uint64_t f=host_irq();
    CHECK(p->terminated);
    for(unsigned i=0;i<child_count;i++)if(child_threads[i].proc==p)ipc_wake_to_die(&child_threads[i]);
    host_restore(f);
}
void process_terminate(process_t *p,int64_t code,int faulted)
{
    CHECK(!authority_depth);CHECK(p&&p->used);++termination_calls;
    production_process_terminate(p,code,faulted);
}
void process_teardown(process_t *p)
{
    CHECK(!authority_depth);CHECK(p->terminated);++teardown_calls;
    if(p->teardown==2)return;
    p->teardown=2;
    if(p->token){ob_deref(p->token);p->token=0;}
}
void ob_ref(kobject_t *o){CHECK(o&&o->refs);++o->refs;}
void ob_deref(kobject_t *o)
{
    CHECK(!authority_depth);CHECK(o&&o->refs);
    if(--o->refs)return;
    if(o->type==OB_PROCESS){process_t *p=o->u.proc.p;CHECK(p&&p->terminated);shz_auth_process_gone(p);p->used=0;}
}
static void kstack_free(uint64_t base)
{
    (void)base;CHECK(!authority_depth);CHECK(irq_depth);++detach_count;
}
int proc_wait(int pid,int64_t *code,int *faulted)
{
    CHECK(!authority_depth);++wait_calls;
    process_t *p=0;
    for(unsigned i=0;i<child_count;i++)if(children[i].used&&children[i].pid==pid)p=&children[i];
    CHECK(p&&p->terminated&&!p->threads_alive&&p->teardown==2);
    return production_proc_wait(pid,code,faulted);
}
void thread_sleep_ms(uint64_t ms)
{
    CHECK(!authority_depth);CHECK(ms==2);host_tick+=ms;
}
uint64_t ticks_now(void){return host_tick;}
void kprintf(const char *format,...){(void)format;}
void kpanic(const char *s,...){fprintf(stderr,"production panic: %s\n",s);abort();}
void sem_init(ksem_t *s,int count){memset(s,0,sizeof *s);s->count=count;}
void sem_post(ksem_t *s){++s->count;}
process_t *process_slot(unsigned index)
{
    if(index&&index<=child_count)return children[index-1].used?&children[index-1]:0;
    return index==64&&broker.used?&broker:0;
}
process_t *process_by_pid(int pid)
{
    if(wait_lookup_failure){wait_lookup_failure=0;return 0;}
    for(unsigned i=0;i<child_count;i++)if(children[i].used&&children[i].pid==pid)return &children[i];
    return broker.used&&broker.pid==pid?&broker:0;
}
process_t *process_create_empty(const char *name)
{
    CHECK(!authority_depth);CHECK(!irq_depth);
    if(fail_allocation)return 0;
    CHECK(child_count<MODEL_CHILDREN);unsigned index=child_count++;
    process_t *p=&children[index];kobject_t *o=&process_objects[index];
    memset(p,0,sizeof *p);memset(o,0,sizeof *o);p->used=1;p->pid=100+(int)index;
    p->create_tick=++host_tick;p->pml4=0x1000u+index*0x1000u;p->object=o;strcpy(p->name,name);
    o->type=OB_PROCESS;o->refs=1;o->u.proc.p=p;
    CHECK(shz_auth_process_pending(p)==0);return p;
}
uint32_t shz_token_integrity(process_t *p,uint32_t fallback){(void)p;return fallback;}
int32_t shz_token_bind_subject(process_t *p,uint64_t auth_id,uint32_t session,uint32_t integrity)
{
    (void)session;(void)integrity;CHECK(!authority_depth);CHECK(auth_id);CHECK(!p->token);
    if(p!=&broker){
        CHECK(enrolled_publish&&p>=children&&p<children+MODEL_CHILDREN);kobject_t *o=&child_tokens[p-children];
        memset(o,0,sizeof *o);o->type=OB_TOKEN;o->refs=1;p->token=o;return 0;
    }
    memset(&broker_token,0,sizeof broker_token);
    broker_token.type=OB_TOKEN;broker_token.refs=1;p->token=&broker_token;return 0;
}
void krandom_get(void *data,size_t bytes)
{
    static uint32_t counter=1;uint8_t *out=data;
    while(bytes--)*out++=(uint8_t)(counter++*37u);
}
int copy_from_user(process_t *p,void *out,uint64_t in,uint64_t bytes)
{
    (void)p;CHECK(!authority_depth);CHECK(!irq_depth);CHECK(in);
    memcpy(out,(void *)(uintptr_t)in,(size_t)bytes);return 0;
}
int copy_to_user(process_t *p,uint64_t out,const void *in,uint64_t bytes)
{
    (void)p;CHECK(!authority_depth);CHECK(!irq_depth);CHECK(out);
    memcpy((void *)(uintptr_t)out,in,(size_t)bytes);return 0;
}
fsnode_t *fs_root_of(char drive){CHECK(!authority_depth);return drive=='C'?&host_fs_root:0;}
fsnode_t *fs_lookup(const char *path)
{
    CHECK(!authority_depth);CHECK(!irq_depth);CHECK(path&&path[0]);++fs_calls;
    return fail_lookup?0:&image_node;
}
fsnode_t *fs_create(const char *path,int directory,int *made)
{
    (void)path;(void)directory;CHECK(!authority_depth);if(made)*made=0;return 0;
}
int utf16_to_utf8(const uint16_t *in,uint64_t chars,char *out,uint64_t capacity)
{
    CHECK(!authority_depth);
    if(chars>=capacity)return -1;
    for(uint64_t i=0;i<chars;i++){if(in[i]>=128)return -1;out[i]=(char)in[i];}
    out[chars]=0;return (int)chars;
}
static int register_account(void)
{
    shz_auth_request req={0};shz_auth_reply output={0};req.version=1;req.roles=SHZ_ROLE_ADMIN;
    strcpy(req.user,"bridge_admin");memcpy(req.password,"test password",13);req.password_bytes=13;
    int32_t rc=shz_auth_syscall(&broker,SHZ_AUTH_REGISTER,(uint64_t)(uintptr_t)&req,sizeof req,
                               (uint64_t)(uintptr_t)&output);
    CHECK(!rc);CHECK(authority.count==1);enrolled_order=++order_clock;return rc;
}
static void *register_main(void *unused)
{
    (void)unused;enrollment_worker=1;register_status=register_account();return 0;
}
static void prepare_broker(void)
{
    broker.used=1;broker.pid=8;broker.create_tick=8;
    CHECK(shz_auth_bootstrap_prepare(&broker,0)==0);CHECK(find(&broker,0)->bootstrap);
}
static int32_t ldr_create_process_body(process_t *parent,const char *image,const char *command,const char *cwd,
                                      const ldr_create_ex_t *ex,process_t *p,thread_t **out)
{
    (void)parent;(void)command;(void)cwd;CHECK(!authority_depth);CHECK(!irq_depth);++loader_calls;
    CHECK(image[0]);CHECK(ex&&ex->suspended==1);CHECK(p->object->refs==1);
    CHECK(find(p,0)->pending);
    if(fail_body)return fail_body;
    if(ex->prepare){int32_t st=ex->prepare(p,ex->prepare_ctx);if(st)return st;}   /* as the production body */
    unsigned index=(unsigned)(p-children);thread_t *t=&child_threads[index];kobject_t *o=&thread_objects[index];
    memset(t,0,sizeof *t);memset(o,0,sizeof *o);t->proc=p;t->state=TS_NEW;
    t->tid=400u+index*4u;t->suspend_count=1;t->creator_hold=out!=0;t->object=o;t->on_cpu=K64_CPU_NONE;
    o->type=OB_THREAD;o->refs=1;o->u.thr.t=t;o->u.thr.pid=(uint64_t)p->pid;o->u.thr.tid=t->tid;
    p->main_thread=t;p->threads_alive=1;ob_ref(p->object);
    if(out)*out=t;
    if(race_mode){
        CHECK(ex->hold_pending==1);CHECK(pthread_create(&register_thread,0,register_main,0)==0);
        if(race_mode==RACE_ENROLL_IN_LOADER)CHECK(pthread_join(register_thread,0)==0);
        else{
            CHECK(pthread_mutex_lock(&race_mutex)==0);
            while(!register_prepared)CHECK(pthread_cond_wait(&race_cond,&race_mutex)==0);
            CHECK(pthread_mutex_unlock(&race_mutex)==0);
        }
    }
    CHECK(t->state==TS_NEW&&t->suspend_count==1);CHECK(find(p,0)->pending);return 0;
}
static void reset_model(void)
{
    for(unsigned i=0;i<child_count;i++){
        CHECK(!children[i].used);CHECK(!process_objects[i].refs);CHECK(!thread_objects[i].refs);
    }
    if(broker.token){ob_deref(broker.token);broker.token=0;}
    for(unsigned i=0;i<mutex_count;i++)CHECK(pthread_mutex_destroy(&mutexes[i].real)==0);
    mutex_count=0;memset(mutexes,0,sizeof mutexes);
    memset(&authority,0,sizeof authority);memset(&authority_lock,0,sizeof authority_lock);
    memset(subjects,0,sizeof subjects);initialized=0;memset(&broker,0,sizeof broker);
    memset(children,0,sizeof children);memset(child_threads,0,sizeof child_threads);
    memset(process_objects,0,sizeof process_objects);memset(thread_objects,0,sizeof thread_objects);
    memset(slots,0,sizeof slots);memset(&bridge_parent,0,sizeof bridge_parent);memset(&pma_service,0,sizeof pma_service);
    child_count=loader_calls=fs_calls=wait_calls=teardown_calls=detach_count=0;
    user_entries=kill_entries=publication_count=termination_calls=0;
    scheduler_closed=fail_body=fail_allocation=fail_lookup=wait_lookup_failure=pause_teardown=0;scheduler_owner=1;
    register_status=-1;race_mode=RACE_NONE;register_prepared=register_enabled=register_attempted=0;
    memset(endpoints,0,sizeof endpoints);channel_epoch_current=0;enrolled_publish=0;memset(child_tokens,0,sizeof child_tokens);
    auth_outstanding=0;memset(&revocations,0,sizeof revocations);
    ready_order=enrolled_order=order_clock=0;host_tick=100;next_gen=1;request_serial=0;host_current=&service_thread;
    memset(&host_fs_root,0,sizeof host_fs_root);memset(&image_node,0,sizeof image_node);image_node.parent=&host_fs_root;
    strcpy(image_node.name,"BRIDGE.EXE");
    CHECK(shz_channel_init(channel_storage,sizeof channel_storage,0,SHZ_DOM_WIN98,SHZ_DOM_KERNEL64,8,37)==SHZ_OK);
    chan_base=channel_storage;chan_size=sizeof channel_storage;chan=(shz_channel_hdr_t *)channel_storage;
    peer=SHZ_DOM_WIN98;rx=shz_channel_ring_rx(chan_base,chan,SHZ_DOM_KERNEL64);
    tx=shz_channel_ring_tx(chan_base,chan,SHZ_DOM_KERNEL64);notify_supported=0;shutdown_requested=0;start_tick=host_tick;
    svc_epoch=chan->generation;revocations.chan_gen=chan->generation;
    ++cases;
}
typedef struct {shz_msg_hdr_t header;_Alignas(8) uint8_t payload[SHZ_MSG_MAX_INLINE];} response;
/* Valid endpoint owner id as NTWRAP9X stamps it (slot 5, generation 1). */
#define TEST_OWNER ((1u<<SHZ_W64_OWNER_GEN_SHIFT)|5u)
static shz_msg_hdr_t request(uint32_t opcode)
{
    shz_msg_hdr_t m={0};m.opcode=opcode;m.request_id=++request_serial;m.src_domain=(uint16_t)peer;
    m.dst_domain=SHZ_DOM_KERNEL64;m.generation=chan->generation;m.capability_id=TEST_OWNER;return m;
}
static response pop_response(const shz_msg_hdr_t *sent)
{
    response r={0};int reason=-1;
    CHECK(shz_ring_pop(tx,&r.header,r.payload,sizeof r.payload,&reason)==SHZ_OK);CHECK(reason==SHZ_PR_NONE);
    CHECK(r.header.flags==SHZ_MSGF_REPLY);CHECK(r.header.request_id==sent->request_id);
    CHECK(r.header.opcode==sent->opcode);CHECK(r.header.generation==sent->generation);
    CHECK(r.header.src_domain==SHZ_DOM_KERNEL64&&r.header.dst_domain==peer);
    CHECK(r.header.capability_id==sent->capability_id);return r;
}
static void no_response(void)
{
    response r={0};CHECK(shz_ring_pop(tx,&r.header,r.payload,sizeof r.payload,0)==SHZ_E_NOENT);
}
static shz_w64_info_t query_info(void)
{
    shz_msg_hdr_t m=request(SHZ_OP_W64_QUERY);handle(&m,0);response r=pop_response(&m);shz_w64_info_t info;
    CHECK(r.header.status==SHZ_OK&&r.header.payload_length==sizeof info);memcpy(&info,r.payload,sizeof info);
    CHECK(info.abi_major==SHZ_ABI_MAJOR&&info.abi_minor==SHZ_ABI_MINOR);
    CHECK(info.max_processes==W64_MAX_PROCS&&info.max_args_bytes==SHZ_W64_MAX_ARGS_BYTES);
    CHECK(info.console_window==SHZ_W64_CONSOLE_WINDOW&&info.console_chunk==SHZ_W64_CONSOLE_CHUNK);
    CHECK((info.capabilities&~SHZ_W64_CAP_CREATE)==(SHZ_W64_CAP_CONSOLE_OUTPUT|SHZ_W64_CAP_CONSOLE_INPUT|
                                                  SHZ_W64_CAP_KILL|SHZ_W64_CAP_POOL_ARGS));
    no_response();return info;
}
static response create_request(void)
{
    _Alignas(8) uint8_t payload[SHZ_MSG_MAX_INLINE]={0};uint16_t path[32],command[32],cwd[8],block[72];
    const char *s="C:\\PUBLIC\\BRIDGE.EXE";unsigned pn=(unsigned)strlen(s);
    for(unsigned i=0;i<pn;i++)path[i]=(uint8_t)s[i];
    s="BRIDGE.EXE";unsigned cn=(unsigned)strlen(s);for(unsigned i=0;i<cn;i++)command[i]=(uint8_t)s[i];
    cwd[0]='C';cwd[1]=':';cwd[2]='\\';shz_w64_create_t packed;int pool=-1;
    unsigned bytes=shz_w64_create_pack(&packed,path,pn,command,cn,cwd,3,block,72,&pool);
    CHECK(bytes&&!pool);memcpy(payload,&packed,sizeof packed);memcpy(payload+sizeof packed,block,bytes);
    shz_msg_hdr_t m=request(SHZ_OP_W64_CREATE_PROCESS);m.payload_length=(uint16_t)(sizeof packed+bytes);
    handle(&m,payload);response r=pop_response(&m);no_response();return r;
}
static process_t *started(response r)
{
    shz_w64_event_t event_body;
    CHECK(r.header.status==SHZ_OK&&r.header.payload_length==sizeof event_body);
    memcpy(&event_body,r.payload,sizeof event_body);CHECK(event_body.state==SHZ_W64_PS_STARTED);
    CHECK(event_body.status==STATUS_SUCCESS&&event_body.pid);process_t *p=process_by_pid((int)event_body.pid);
    CHECK(p&&p->main_thread);CHECK(!p->main_thread->creator_hold);return p;
}
static void run_boundary(thread_t *t)
{
    CHECK(!authority_depth);CHECK(t->state==TS_READY||t->state==TS_RUNNING);
    if(!thread_must_die(t)){CHECK(!t->suspend_count);t->state=TS_RUNNING;++user_entries;return;}
    ++kill_entries;t->state=TS_ZOMBIE;t->exit_code=t->proc->exit_code;t->object->signaled=1;
    CHECK(t->proc->threads_alive==1);t->proc->threads_alive=0;t->proc->teardown=1;
    if(!pause_teardown)process_teardown(t->proc);
}
static void quiet_cleanup(w64_slot_t *s)
{
    CHECK(s->used&&s->rejected&&s->proc);process_t *p=s->proc;thread_t *t=p->main_thread;
    CHECK(p->terminated);int retained_hold=t->creator_hold;unsigned previous_waits=wait_calls;
    CHECK(p->object->refs==2&&t->object->refs==1);
    s->out[0].buf[0]='X';s->out[0].head=1;s->out[1].buf[0]='Y';s->out[1].head=1;
    CHECK(pump_slot(s)==0);CHECK(wait_calls==previous_waits);no_response();
    pause_teardown=1;run_boundary(t);CHECK(p->teardown==1&&!p->threads_alive);
    CHECK(pump_slot(s)==0);CHECK(wait_calls==previous_waits);no_response();process_teardown(p);pause_teardown=0;
    wait_lookup_failure=1;CHECK(pump_slot(s)==0);CHECK(s->used&&s->proc==p);
    CHECK(t->creator_hold==retained_hold);no_response();
    CHECK(pump_slot(s)==1);CHECK(!s->used&&!s->proc);CHECK(!p->used);CHECK(!p->object->refs);
    CHECK(!thread_objects[p-children].refs);CHECK(!find(p,0));CHECK(!t->creator_hold&&t->state==TS_FREE);
    CHECK(wait_calls==previous_waits+2);no_response();CHECK(!user_entries);
}
static void normal_cleanup(process_t *p)
{
    shz_msg_hdr_t owner_hdr={0};owner_hdr.capability_id=TEST_OWNER;
    w64_slot_t *s=slot_lookup(&owner_hdr,(uint32_t)p->pid);CHECK(s&&!s->rejected);uint32_t pid=(uint32_t)p->pid;
    process_terminate(p,77,0);run_boundary(p->main_thread);CHECK(pump_slot(s)==1);
    response out={0};CHECK(shz_ring_pop(tx,&out.header,out.payload,sizeof out.payload,0)==SHZ_OK);
    CHECK(out.header.opcode==SHZ_OP_W64_PROCESS_EXITED&&out.header.flags==SHZ_MSGF_ONEWAY);
    shz_w64_event_t ev;memcpy(&ev,out.payload,sizeof ev);CHECK(ev.pid==pid&&ev.exit_code==77);
    shz_w64_kill_t release={pid,0};shz_msg_hdr_t m=request(SHZ_OP_W64_RELEASE);m.payload_length=sizeof release;
    handle(&m,(const uint8_t *)&release);out=pop_response(&m);CHECK(out.header.status==SHZ_OK);CHECK(!s->used);no_response();
}
static void test_development_and_reuse(void)
{
    reset_model();CHECK(!initialized);CHECK(query_info().capabilities&SHZ_W64_CAP_CREATE);
    CHECK(initialized&&authority.count==0);process_t *p=started(create_request());
    CHECK(publication_count==1&&p->main_thread->state==TS_READY&&!p->main_thread->suspend_count);
    CHECK(!find(p,0)->pending&&!subject(p).uid&&subject(p).auth_id==0x4e7);
    CHECK(p->object->refs==2);CHECK(query_info().active_processes==1);
    process_t stale=*p;unsigned generation=p->console_sink_gen;run_boundary(p->main_thread);CHECK(user_entries==1);
    normal_cleanup(p);CHECK(query_info().active_processes==0);
    p=started(create_request());CHECK(p->console_sink_gen!=generation);CHECK(!sink_of(&stale));
    normal_cleanup(p);CHECK(detach_count==2);
}
static void test_enrolled_and_cached_query(void)
{
    reset_model();prepare_broker();CHECK(query_info().capabilities&SHZ_W64_CAP_CREATE);CHECK(!register_account());
    CHECK(!(query_info().capabilities&SHZ_W64_CAP_CREATE));response r=create_request();
    CHECK(r.header.status==SHZ_E_DENIED&&!r.header.payload_length);
    CHECK(!child_count&&!loader_calls&&!fs_calls&&!active_count()&&!publication_count);CHECK(next_gen==1);
}
static void test_enrollment_inside_loader(void)
{
    reset_model();prepare_broker();CHECK(query_info().capabilities&SHZ_W64_CAP_CREATE);
    race_mode=RACE_ENROLL_IN_LOADER;response r=create_request();
    CHECK(register_status==0&&enrolled_order);CHECK(r.header.status==SHZ_E_DENIED&&!r.header.payload_length);
    CHECK(!publication_count&&!ready_order);CHECK(child_count==1&&loader_calls==1);
    CHECK(find(&children[0],0)->pending);CHECK(!(query_info().capabilities&SHZ_W64_CAP_CREATE));
    CHECK(query_info().active_processes==1);quiet_cleanup(&slots[0]);CHECK(query_info().active_processes==0);
}
static void test_publication_before_enrollment(void)
{
    reset_model();prepare_broker();race_mode=RACE_READY_FIRST;process_t *p=started(create_request());
    CHECK(pthread_join(register_thread,0)==0);CHECK(register_status==0);
    CHECK(register_prepared&&register_attempted&&ready_order&&enrolled_order>ready_order);
    CHECK(publication_count==1&&!find(p,0)->pending&&!p->terminated);
    CHECK(!(query_info().capabilities&SHZ_W64_CAP_CREATE));unsigned loaded=loader_calls;
    response r=create_request();CHECK(r.header.status==SHZ_E_DENIED&&!r.header.payload_length);
    CHECK(loader_calls==loaded);run_boundary(p->main_thread);CHECK(user_entries==1);normal_cleanup(p);
}
static void test_scheduler_quarantine(int closed,int owner)
{
    reset_model();scheduler_closed=closed;scheduler_owner=owner;response r=create_request();
    CHECK(r.header.status==SHZ_E_BUSY&&!r.header.payload_length);CHECK(!publication_count);
    process_t *p=&children[0];thread_t *t=p->main_thread;
    CHECK(p->terminated&&t->state==TS_NEW&&t->suspend_count==1);
    /* Creator release also refuses off-BSP; the existing eventual proc_wait
     * owns dropping that hold when scheduler ownership returns. */
    if(!owner){CHECK(t->creator_hold);scheduler_owner=1;}
    else CHECK(!t->creator_hold);
    CHECK(find(p,0)->pending);CHECK(pump_slot(&slots[0])==0);CHECK(!wait_calls);no_response();
    scheduler_closed=0;uint64_t f=host_irq();ipc_wake_to_die(t);host_restore(f);
    CHECK(t->state==TS_READY&&thread_must_die(t));quiet_cleanup(&slots[0]);
}
static void test_repeated_private_autoreap(void)
{
    reset_model();unsigned last_generation=0;
    for(unsigned i=0;i<W64_MAX_PROCS+2u;i++){
        scheduler_closed=1;response r=create_request();
        CHECK(r.header.status==SHZ_E_BUSY&&!r.header.payload_length);CHECK(active_count()==1);
        CHECK(slots[0].rejected&&slots[0].gen>last_generation);last_generation=slots[0].gen;
        scheduler_closed=0;uint64_t f=host_irq();ipc_wake_to_die(children[i].main_thread);host_restore(f);
        quiet_cleanup(&slots[0]);CHECK(!active_count());CHECK(query_info().capabilities&SHZ_W64_CAP_CREATE);
    }
    CHECK(child_count==W64_MAX_PROCS+2u&&detach_count==child_count);CHECK(!publication_count);
}
static void test_loader_contract_and_failure(void)
{
    reset_model();process_t *p=0;thread_t *t=0;ldr_create_ex_t ex={0};ex.hold_pending=1;
    CHECK(ldr_create_process_ex(0,"C:\\PUBLIC\\BRIDGE.EXE","BRIDGE.EXE","C:\\",&ex,&p,&t)==STATUS_INVALID_PARAMETER);
    ex.suspended=1;ex.hold_pending=2;
    CHECK(ldr_create_process_ex(0,"C:\\PUBLIC\\BRIDGE.EXE","BRIDGE.EXE","C:\\",&ex,&p,&t)==STATUS_INVALID_PARAMETER);
    ex.hold_pending=1;
    CHECK(ldr_create_process_ex(0,"C:\\PUBLIC\\BRIDGE.EXE","BRIDGE.EXE","C:\\",&ex,0,&t)==STATUS_INVALID_PARAMETER);
    CHECK(ldr_create_process_ex(0,"C:\\PUBLIC\\BRIDGE.EXE","BRIDGE.EXE","C:\\",&ex,&p,0)==STATUS_INVALID_PARAMETER);
    CHECK(!fs_calls&&!child_count);
    fail_body=STATUS_INVALID_IMAGE_FORMAT;response r=create_request();shz_w64_event_t ev;
    CHECK(r.header.status==SHZ_OK&&r.header.payload_length==sizeof ev);memcpy(&ev,r.payload,sizeof ev);
    CHECK(ev.state==SHZ_W64_PS_FAILED&&ev.status==STATUS_INVALID_IMAGE_FORMAT&&!ev.pid);
    CHECK(!active_count()&&!children[0].used&&!process_objects[0].refs&&!publication_count);
    CHECK(termination_calls==1&&teardown_calls==1&&!thread_objects[0].refs&&!find(&children[0],0));
    fail_body=0;fail_lookup=1;r=create_request();memcpy(&ev,r.payload,sizeof ev);
    CHECK(ev.state==SHZ_W64_PS_FAILED&&ev.status==STATUS_OBJECT_NAME_NOT_FOUND);CHECK(child_count==1&&!active_count());
    fail_lookup=0;fail_allocation=1;r=create_request();memcpy(&ev,r.payload,sizeof ev);
    CHECK(ev.state==SHZ_W64_PS_FAILED&&ev.status==STATUS_NO_MEMORY);CHECK(child_count==1&&!active_count());
}
static void test_slot_capacity_and_envelopes(void)
{
    reset_model();process_t *live[W64_MAX_PROCS];for(unsigned i=0;i<W64_MAX_PROCS;i++)live[i]=started(create_request());
    CHECK(query_info().active_processes==W64_MAX_PROCS);unsigned loaded=loader_calls;
    response r=create_request();CHECK(r.header.status==SHZ_E_NOMEM&&!r.header.payload_length);CHECK(loader_calls==loaded);
    shz_msg_hdr_t m=request(SHZ_OP_W64_QUERY);m.src_domain=SHZ_DOM_SUPERVISOR;handle(&m,0);no_response();
    m=request(SHZ_OP_W64_QUERY);++m.generation;handle(&m,0);
    response stale={0};CHECK(shz_ring_pop(tx,&stale.header,stale.payload,sizeof stale.payload,0)==SHZ_OK);
    CHECK(stale.header.status==SHZ_E_STALE&&stale.header.request_id==m.request_id);no_response();
    _Alignas(8) uint8_t bad[16]={0};m=request(SHZ_OP_W64_CREATE_PROCESS);m.payload_length=sizeof bad;handle(&m,bad);
    r=pop_response(&m);CHECK(r.header.status==SHZ_E_INVALID&&!r.header.payload_length);CHECK(loader_calls==loaded);no_response();
    for(unsigned i=0;i<W64_MAX_PROCS;i++)normal_cleanup(live[i]);
    CHECK(!active_count());
}
static void test_publication_identity_guards(void)
{
    reset_model();process_t *p=0;thread_t *t=0;ldr_create_ex_t ex={0};ex.suspended=ex.hold_pending=1;
    CHECK(ldr_create_process_ex(0,"C:\\PUBLIC\\BRIDGE.EXE","BRIDGE.EXE","C:\\",&ex,&p,&t)==0);
    binding *b=find(p,0);CHECK(b&&b->pending);process_t saved_p=*p;thread_t saved_t=*t;
    kobject_t saved_po=*p->object,saved_to=*t->object;binding saved_b=*b;
#define BAD_CHANGE(change) do { change;CHECK(shz_auth_bridge_development_publish(p,t)==STATUS_ACCESS_DENIED); \
    CHECK(!publication_count);*p=saved_p;*t=saved_t;process_objects[0]=saved_po;thread_objects[0]=saved_to;*b=saved_b; } while(0)
    BAD_CHANGE(p->used=0);BAD_CHANGE(p->terminated=1);BAD_CHANGE(p->exit_owner=&service_thread);
    BAD_CHANGE(p->teardown=1);BAD_CHANGE(p->parent_pid=123);BAD_CHANGE(p->threads_alive=2);
    BAD_CHANGE(p->main_thread=&service_thread);BAD_CHANGE(p->object=0);BAD_CHANGE(p->object->type=OB_THREAD);
    BAD_CHANGE(p->object->refs=0);BAD_CHANGE(p->object->signaled=1);BAD_CHANGE(p->object->u.proc.p=&broker);
    BAD_CHANGE(p->pid++);BAD_CHANGE(p->pid=0);BAD_CHANGE(p->pml4=0);BAD_CHANGE(p->token=&broker_token);
    BAD_CHANGE(p->create_tick++);BAD_CHANGE(b->pending=0);BAD_CHANGE(b->bootstrap=1);
    BAD_CHANGE(b->subject.uid=1000);BAD_CHANGE(b->subject.session=1);BAD_CHANGE(b->subject.roles=SHZ_ROLE_ADMIN);
    BAD_CHANGE(b->subject.flags=SHZ_SUBJECT_SANDBOX);BAD_CHANGE(b->subject.auth_id=123);
    BAD_CHANGE(b->subject.integrity=0x3000);BAD_CHANGE(b->subject.integrity=0x1000);
    BAD_CHANGE(t->proc=&broker);BAD_CHANGE(t->state=TS_READY);BAD_CHANGE(t->suspend_count=0);
    BAD_CHANGE(t->suspend_count=2);BAD_CHANGE(t->creator_hold=0);BAD_CHANGE(t->kill_pending=1);
    BAD_CHANGE(t->tid=0);BAD_CHANGE(t->object=0);BAD_CHANGE(t->object->type=OB_PROCESS);
    BAD_CHANGE(t->object->refs=0);BAD_CHANGE(t->object->signaled=1);BAD_CHANGE(t->object->u.thr.t=&service_thread);
    BAD_CHANGE(t->object->u.thr.pid++);BAD_CHANGE(t->object->u.thr.tid++);
#undef BAD_CHANGE
    CHECK(shz_auth_bridge_development_publish(0,t)==STATUS_ACCESS_DENIED);
    CHECK(shz_auth_bridge_development_publish(p,0)==STATUS_ACCESS_DENIED);
    CHECK(b->pending&&t->state==TS_NEW&&t->suspend_count==1);
    CHECK(shz_auth_bridge_development_publish(p,t)==0);CHECK(publication_count==1&&!b->pending);
    CHECK(shz_auth_bridge_development_publish(p,t)==STATUS_ACCESS_DENIED);CHECK(publication_count==1);
    thread_creator_release(t);process_terminate(p,66,0);run_boundary(t);
    CHECK(proc_wait(p->pid,0,0)==0);CHECK(!p->used&&!process_objects[0].refs&&!thread_objects[0].refs);
}
static void test_loader_pending_access_boundary(void)
{
    reset_model();process_t observer={0};observer.used=1;observer.pid=44;observer.create_tick=44;
    CHECK(!find(&observer,0));CHECK(!subject(&observer).uid&&!subject(&observer).session);
    for(unsigned hold=0;hold<=1;hold++){
        process_t *p=0;thread_t *t=0;ldr_create_ex_t ex={0};ex.suspended=1;ex.hold_pending=(int)hold;
        CHECK(ldr_create_process_ex(0,"C:\\PUBLIC\\BRIDGE.EXE","BRIDGE.EXE","C:\\",&ex,&p,&t)==0);
        CHECK(p&&t&&p!=&observer&&p->pid!=observer.pid);binding *b=find(p,0);CHECK(b);
        CHECK(b->pending==(int)hold);CHECK(!b->subject.uid&&!b->subject.session&&!b->bootstrap);
        CHECK(t->state==TS_NEW&&t->suspend_count==1&&t->creator_hold);
        CHECK(p->object->refs==2&&t->object->refs==1);CHECK(!p->console_sink&&!active_count());
        CHECK(shz_auth_process_access(&observer,p)==!hold);
        CHECK(shz_auth_handle_allowed(&observer,p->object)==!hold);
        CHECK(shz_auth_thread_access(&observer,(uint64_t)p->pid)==!hold);
        CHECK(shz_auth_handle_allowed(&observer,t->object)==!hold);
        if(hold){
            CHECK(shz_auth_bridge_development_publish(p,t)==STATUS_SUCCESS);
            CHECK(!b->pending&&t->state==TS_READY&&!t->suspend_count&&publication_count==1);
            CHECK(shz_auth_process_access(&observer,p));
            CHECK(shz_auth_handle_allowed(&observer,p->object));
            CHECK(shz_auth_thread_access(&observer,(uint64_t)p->pid));
            CHECK(shz_auth_handle_allowed(&observer,t->object));
        }else CHECK(!publication_count);
        no_response();thread_creator_release(t);CHECK(!t->creator_hold);
        process_terminate(p,55+(int)hold,0);run_boundary(t);int64_t code=0;
        CHECK(proc_wait(p->pid,&code,0)==0&&code==55+(int)hold);
        CHECK(!p->used&&!p->object->refs&&!thread_objects[hold].refs);
        CHECK(t->state==TS_FREE&&!find(p,0));CHECK(!user_entries&&kill_entries==hold+1);
        CHECK(!active_count());no_response();
    }
    CHECK(detach_count==2&&child_count==2);CHECK(!find(&observer,0));
}

/* ---- C6 typed broker requests (routing02) ---- */
#define TEST_OWNER2 ((1u<<SHZ_W64_OWNER_GEN_SHIFT)|6u)
static const char test_user[]="bridge_admin",test_secret[]="test password";
static shz_w64_auth_req_t auth_payload(const char *user,const char *secret,uint32_t roles)
{
    shz_w64_auth_req_t q;memset(&q,0,sizeof q);q.size=sizeof q;q.version=SHZ_W64_AUTH_VERSION;
    q.user_len=(uint32_t)strlen(user);memcpy(q.user,user,q.user_len);
    q.secret_len=(uint32_t)strlen(secret);memcpy(q.secret,secret,q.secret_len);q.roles=roles;return q;
}
static int all_zero(const void *p,size_t n){const uint8_t *b=p;while(n--)if(*b++)return 0;return 1;}
static int contains(const uint8_t *hay,size_t n,const char *needle)
{
    size_t k=strlen(needle);for(size_t i=0;i+k<=n;i++)if(!memcmp(hay+i,needle,k))return 1;return 0;
}
/* Sends one typed request through handle(); checks the reply never carries user/secret and the bounded local
 * copy was scrubbed. Returns the reply (header status mirrors body status when a body is present). */
static response auth_call(uint32_t op,uint32_t owner,const shz_w64_auth_req_t *q,uint16_t len)
{
    shz_msg_hdr_t m=request(op);m.capability_id=owner;m.payload_length=len;
    _Alignas(8) uint8_t pl[SHZ_MSG_MAX_INLINE]={0};memcpy(pl,q,sizeof *q);
    handle(&m,pl);response r=pop_response(&m);no_response();
    CHECK(all_zero(&auth_req,sizeof auth_req));CHECK(!auth_outstanding);
    CHECK(!contains((const uint8_t *)&r,sizeof r,test_secret)&&!contains((const uint8_t *)&r,sizeof r,test_user));
    if(r.header.payload_length){
        shz_w64_auth_reply_t a;CHECK(r.header.payload_length==sizeof a);memcpy(&a,r.payload,sizeof a);
        CHECK(a.size==sizeof a&&a.status==r.header.status&&!a.reserved);
        if(a.status!=SHZ_OK)CHECK(!a.auth_epoch&&!a.subject_flags);
        CHECK(all_zero(r.payload+sizeof a,sizeof r.payload-sizeof a));
    }
    return r;
}
static uint64_t login_ok(uint32_t owner)
{
    shz_w64_auth_req_t q=auth_payload(test_user,test_secret,0);
    response r=auth_call(SHZ_OP_W64_AUTH_LOGIN,owner,&q,sizeof q);shz_w64_auth_reply_t a;
    CHECK(r.header.status==SHZ_OK&&r.header.payload_length==sizeof a);memcpy(&a,r.payload,sizeof a);
    CHECK(a.auth_epoch);uint64_t e=0;
    CHECK(shz_auth_endpoint_query(w64_owner_broker_key(owner,chan->generation),0,&e)==STATUS_SUCCESS&&e==a.auth_epoch);
    return a.auth_epoch;
}
static void enrolled_realm(void){reset_model();prepare_broker();CHECK(!register_account());}
static void test_auth_login_then_create(void)
{
    enrolled_realm();
    response r=create_request();CHECK(r.header.status==SHZ_E_DENIED&&!r.header.payload_length);
    CHECK(!loader_calls&&!child_count);CHECK(!(query_info().capabilities&SHZ_W64_CAP_CREATE));
    uint64_t epoch=login_ok(TEST_OWNER);CHECK(query_info().capabilities&SHZ_W64_CAP_CREATE);
    enrolled_publish=1;process_t *p=started(create_request());
    w64_slot_t *s=&slots[0];CHECK(s->own.broker_owner==w64_owner_broker_key(TEST_OWNER,chan->generation));
    CHECK(s->own.broker_epoch==epoch);CHECK(find(p,0)->ep_published&&!find(p,0)->pending&&p->token);
    CHECK(shz_auth_endpoint_binding_current(s->own.broker_owner,epoch,p)==1);
    /* Another owner never reaches this slot. */
    shz_w64_kill_t k={(uint32_t)p->pid,9};shz_msg_hdr_t m=request(SHZ_OP_W64_KILL_PROCESS);m.capability_id=TEST_OWNER2;
    m.payload_length=sizeof k;handle(&m,(const uint8_t *)&k);r=pop_response(&m);CHECK(r.header.status==SHZ_E_NOENT);
    CHECK(!p->terminated);run_boundary(p->main_thread);CHECK(user_entries==1);normal_cleanup(p);
}
static void test_auth_bad_payloads(void)
{
    enrolled_realm();shz_w64_auth_req_t q=auth_payload(test_user,test_secret,0);response r;
    shz_w64_auth_req_t b=q;b.user_len=0;
    r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_E_INVALID);
    b=q;b.secret_len=SHZ_W64_AUTH_SECRET_MAX+1;
    r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_E_INVALID);
    b=q;b.reserved=1;r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_E_INVALID);
    b=q;b.roles=SHZ_ROLE_ADMIN;r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_E_INVALID);
    b=q;b.user[2]=0;r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_E_INVALID);
    b=q;b.secret[SHZ_W64_AUTH_SECRET_MAX-1]=1;
    r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_E_INVALID);
    r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&q,sizeof q-1);CHECK(r.header.status==SHZ_E_PROTO);
    /* Privileged / no owner: refused by the authority gate before any copy (no body). */
    r=auth_call(SHZ_OP_W64_AUTH_LOGIN,SHZ_W64_OWNER_PRIVILEGED_ID,&q,sizeof q);
    CHECK(r.header.status==SHZ_E_DENIED&&!r.header.payload_length);
    r=auth_call(SHZ_OP_W64_AUTH_LOGIN,SHZ_W64_OWNER_NONE,&q,sizeof q);CHECK(r.header.status==SHZ_E_DENIED&&!r.header.payload_length);
    b=auth_payload(test_user,"wrong password",0);
    r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_E_DENIED&&r.header.payload_length);
    r=auth_call(SHZ_OP_W64_AUTH_CONFIRM_ELEVATION,TEST_OWNER,&q,sizeof q);CHECK(r.header.status==SHZ_E_DENIED);
    CHECK(shz_auth_endpoint_query(w64_owner_broker_key(TEST_OWNER,chan->generation),0,0)!=STATUS_SUCCESS);
    CHECK(create_request().header.status==SHZ_E_DENIED&&!loader_calls);
    /* Elevation then single-use REGISTER for the same owner. */
    login_ok(TEST_OWNER);r=auth_call(SHZ_OP_W64_AUTH_CONFIRM_ELEVATION,TEST_OWNER,&q,sizeof q);CHECK(r.header.status==SHZ_OK);
    b=auth_payload("second_user","second secret",0);
    r=auth_call(SHZ_OP_W64_AUTH_REGISTER,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_OK);CHECK(authority.count==2);
    r=auth_call(SHZ_OP_W64_AUTH_REGISTER,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_E_DENIED);CHECK(authority.count==2);
    /* Unenrolled development realm: the broker fails closed. */
    reset_model();r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&q,sizeof q);CHECK(r.header.status==SHZ_E_DENIED);
}
static void test_auth_epoch_change(void)
{
    enrolled_realm();login_ok(TEST_OWNER2);uint64_t epoch=login_ok(TEST_OWNER);
    const uint64_t key=w64_owner_broker_key(TEST_OWNER,chan->generation),key2=w64_owner_broker_key(TEST_OWNER2,chan->generation);
    enrolled_publish=1;process_t *p=started(create_request());uint32_t pid=(uint32_t)p->pid;
    CHECK(shz_auth_endpoint_binding_current(key,epoch,p)==1);
    ++chan->generation;owner_epoch_cleanup();CHECK(svc_epoch==chan->generation);
    CHECK(shz_auth_endpoint_query(key2,0,0)!=STATUS_SUCCESS);   /* never created a slot: cleared anyway */
    CHECK(shz_auth_endpoint_query(key,0,0)!=STATUS_SUCCESS);CHECK(!shz_auth_endpoint_binding_current(key,epoch,p));
    CHECK(slots[0].rejected&&p->terminated);
    shz_w64_kill_t k={pid,9};shz_msg_hdr_t m=request(SHZ_OP_W64_KILL_PROCESS);m.payload_length=sizeof k;
    handle(&m,(const uint8_t *)&k);response r=pop_response(&m);CHECK(r.header.status==SHZ_E_NOENT);
    m=request(SHZ_OP_W64_RELEASE);m.payload_length=sizeof k;handle(&m,(const uint8_t *)&k);r=pop_response(&m);
    CHECK(r.header.status==SHZ_E_NOENT);CHECK(!(query_info().capabilities&SHZ_W64_CAP_CREATE));
    run_boundary(p->main_thread);CHECK(pump_slot(&slots[0])==1);CHECK(!slots[0].used&&!p->used);no_response();
    /* Logout without epoch change (broker depart): live child is revoked, never published to, ops refused. */
    epoch=login_ok(TEST_OWNER);p=started(create_request());pid=(uint32_t)p->pid;
    shz_auth_endpoint_depart(w64_owner_broker_key(TEST_OWNER,chan->generation));
    m=request(SHZ_OP_W64_KILL_PROCESS);k.pid=pid;m.payload_length=sizeof k;handle(&m,(const uint8_t *)&k);
    r=pop_response(&m);CHECK(r.header.status==SHZ_E_NOENT);CHECK(!p->terminated);
    w64_slot_t *s=&slots[0];CHECK(s->used&&s->proc==p);s->out[0].buf[0]='Z';s->out[0].head=1;
    pump_slot(s);CHECK(s->rejected&&p->terminated);no_response();
    run_boundary(p->main_thread);CHECK(pump_slot(s)==1);CHECK(!s->used&&!p->used);no_response();
}
/* Same owner relogs in as another account: the previous account's child loses ownership at the common lookup
 * (ACK/INPUT/KILL/RELEASE all NOENT, no frame), is terminated and reaped privately; the new login stays valid. */
static void test_auth_relogin_other_account(void)
{
    enrolled_realm();uint64_t epoch=login_ok(TEST_OWNER);
    const uint64_t key=w64_owner_broker_key(TEST_OWNER,chan->generation);
    enrolled_publish=1;process_t *p=started(create_request());uint32_t pid=(uint32_t)p->pid;w64_slot_t *s=&slots[0];
    shz_w64_auth_req_t q=auth_payload(test_user,test_secret,0),b=auth_payload("second_user","second secret",0);
    response r=auth_call(SHZ_OP_W64_AUTH_CONFIRM_ELEVATION,TEST_OWNER,&q,sizeof q);CHECK(r.header.status==SHZ_OK);
    r=auth_call(SHZ_OP_W64_AUTH_REGISTER,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_OK);
    CHECK(shz_auth_endpoint_binding_current(key,epoch,p)==1&&!p->terminated);
    s->out[0].buf[0]='Z';s->out[0].head=1;                 /* undelivered output of the old account's child */
    r=auth_call(SHZ_OP_W64_AUTH_LOGIN,TEST_OWNER,&b,sizeof b);CHECK(r.header.status==SHZ_OK);
    shz_w64_auth_reply_t a;memcpy(&a,r.payload,sizeof a);CHECK(a.auth_epoch&&a.auth_epoch!=epoch);
    CHECK(!shz_auth_endpoint_child_owned(key,a.auth_epoch,p)&&!shz_auth_endpoint_binding_current(key,epoch,p));
    CHECK(s->rejected&&p->terminated&&s->own.owner_id==SHZ_W64_OWNER_NONE);no_response();
    shz_w64_kill_t k={pid,9};shz_msg_hdr_t m=request(SHZ_OP_W64_KILL_PROCESS);m.payload_length=sizeof k;
    handle(&m,(const uint8_t *)&k);r=pop_response(&m);CHECK(r.header.status==SHZ_E_NOENT&&!r.header.payload_length);
    m=request(SHZ_OP_W64_RELEASE);m.payload_length=sizeof k;handle(&m,(const uint8_t *)&k);r=pop_response(&m);
    CHECK(r.header.status==SHZ_E_NOENT&&!r.header.payload_length);
    _Alignas(8) uint8_t pl[SHZ_MSG_MAX_INLINE]={0};shz_w64_console_t c={0};c.pid=pid;c.length=1;
    memcpy(pl,&c,sizeof c);pl[sizeof c]='x';m=request(SHZ_OP_W64_CONSOLE_INPUT);m.payload_length=sizeof c+1;
    handle(&m,pl);r=pop_response(&m);CHECK(r.header.status==SHZ_E_NOENT&&!r.header.payload_length);
    CHECK(s->in_head==s->in_tail);
    c.length=0;c.seq=1;memcpy(pl,&c,sizeof c);m=request(SHZ_OP_W64_CONSOLE_ACK);m.flags=SHZ_MSGF_ONEWAY;
    m.payload_length=sizeof c;handle(&m,pl);no_response();CHECK(!s->seq_acked);
    uint64_t e=0;CHECK(shz_auth_endpoint_query(key,0,&e)==STATUS_SUCCESS&&e==a.auth_epoch);   /* not departed */
    run_boundary(p->main_thread);CHECK(pump_slot(s)==1);CHECK(!s->used&&!p->used);no_response();
    CHECK(shz_auth_endpoint_query(key,0,&e)==STATUS_SUCCESS&&e==a.auth_epoch);
    /* The new account's own child is admitted and current under the new login only. */
    p=started(create_request());CHECK(slots[0].own.broker_epoch==a.auth_epoch);
    CHECK(shz_auth_endpoint_binding_current(key,a.auth_epoch,p)==1&&!shz_auth_endpoint_binding_current(key,epoch,p));
    run_boundary(p->main_thread);normal_cleanup(p);
}
static void test_auth_ring_scrub(void)
{
    enrolled_realm();shz_w64_auth_req_t q=auth_payload(test_user,test_secret,0);
    shz_msg_hdr_t m=request(SHZ_OP_W64_AUTH_LOGIN);m.payload_length=sizeof q;
    uint32_t tail=rx->tail;CHECK(shz_ring_push(rx,&m,&q)==SHZ_OK);
    CHECK(contains(shz_ring_slot(rx,tail),SHZ_MSG_SLOT_SIZE,test_secret));
    CHECK(rx_auth_frame()==1);CHECK(rx->tail==tail+1);
    CHECK(all_zero(shz_ring_slot(rx,tail),SHZ_MSG_SLOT_SIZE));CHECK(all_zero(auth_frame,sizeof auth_frame));
    CHECK(all_zero(&auth_req,sizeof auth_req));response r=pop_response(&m);CHECK(r.header.status==SHZ_OK);
    CHECK(!contains((const uint8_t *)&r,sizeof r,test_secret));no_response();
    /* Corrupted credential frame: consumed, scrubbed, never answered. */
    unsigned errors=proto_errors;m=request(SHZ_OP_W64_AUTH_LOGIN);m.payload_length=sizeof q;tail=rx->tail;
    CHECK(shz_ring_push(rx,&m,&q)==SHZ_OK);shz_ring_slot(rx,tail)[sizeof m+40]^=1;
    CHECK(rx_auth_frame()==1);CHECK(proto_errors==errors+1);CHECK(all_zero(shz_ring_slot(rx,tail),SHZ_MSG_SLOT_SIZE));
    CHECK(all_zero(auth_frame,sizeof auth_frame));no_response();
    /* Other opcodes are left to shz_ring_pop untouched. */
    m=request(SHZ_OP_W64_QUERY);tail=rx->tail;CHECK(shz_ring_push(rx,&m,0)==SHZ_OK);
    CHECK(rx_auth_frame()==0&&rx->tail==tail);shz_msg_hdr_t got;CHECK(shz_ring_pop(rx,&got,0,0,0)==SHZ_OK);
    CHECK(rx_auth_frame()==0);
}
int main(void)
{
    test_development_and_reuse();test_enrolled_and_cached_query();test_enrollment_inside_loader();
    test_publication_before_enrollment();test_scheduler_quarantine(1,1);test_scheduler_quarantine(0,0);
    test_repeated_private_autoreap();test_loader_contract_and_failure();test_slot_capacity_and_envelopes();test_publication_identity_guards();
    test_loader_pending_access_boundary();
    test_auth_login_then_create();test_auth_bad_payloads();test_auth_epoch_change();test_auth_relogin_other_account();test_auth_ring_scrub();
    reset_model();
    printf("native create admission: %u scenarios, %u checks PASS\n",cases-1,checks);
    return 0;
}
