/* SPDX-License-Identifier: GPL-2.0-only
 * The generated regions contain actual production bodies without rewriting.
 * Host adapters supply memory copies, IRQ state and object destructor hooks.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "actual_section_security.h"
#define STATUS_SUCCESS 0
#define STATUS_INVALID_HANDLE ((int32_t)0xc0000008)
#define STATUS_OBJECT_TYPE_MISMATCH ((int32_t)0xc0000024)
#define STATUS_ACCESS_DENIED ((int32_t)0xc0000022)
#define STATUS_NO_MEMORY ((int32_t)0xc0000017)
#define STATUS_ACCESS_VIOLATION ((int32_t)0xc0000005)
#define STATUS_PROCESS_IS_TERMINATING ((int32_t)0xc000010a)
#define MAXIMUM_ALLOWED_ACCESS 0x02000000u
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_ALL 0x10000000u
#define DUPLICATE_CLOSE_SOURCE 1u
#define DUPLICATE_SAME_ACCESS 2u
#define DUPLICATE_SAME_ATTRIBUTES 4u
#define HANDLE_FLAG_INHERIT_BIT 1u
#define OBJ_INHERIT_ATTR 2u
#define PROCESS_DUP_HANDLE 0x0040u
#define PROCESS_ALL_ACCESS 0x1fffffu
#define THREAD_ALL_ACCESS 0x1fffffu
#define SECTION_ALL_ACCESS 0xf001fu
#define CURRENT_PROCESS_HANDLE UINT64_MAX
#define CURRENT_THREAD_HANDLE (UINT64_MAX-1)
#define OB_SECTION 9u
#define OB_PROCESS 5u
#define OB_THREAD 4u
#define OB_EVENT 1u
#define OB_FILE 7u
#define OB_SOCKET 8u
#define BAD_USER_POINTER 1u
typedef struct process process_t;
typedef struct kobject { uint32_t type,refs; void *sd;uint32_t sd_len;
                        union {struct { process_t *p; } proc;} u; } kobject_t;
typedef struct { kobject_t *obj; uint32_t access,inherit; } handle_entry_t;
struct process { handle_entry_t handles[16]; unsigned handle_cap,handle_count;int teardown,pid; kobject_t *object; };
typedef struct { kobject_t *object; } thread_t;
struct regs { uint64_t args[3]; };
static uint64_t irq_depth;
static unsigned checks,failures,trace_events,closed_hooks;
static thread_t current_thread;
static int use_legacy_duplicate;
/* Captured self-relative descriptors: actual empty ACL and explicit NULL DACL.
 * Production security code validates and evaluates these bytes itself. */
static uint8_t empty_sd[28]={[0]=1,[2]=4,[3]=128,[16]=20,[20]=2,[22]=8};
static uint8_t null_sd[20]={[0]=1,[2]=4,[3]=128};
static uint8_t nonempty_sd[48]={[0]=1,[2]=4,[3]=128,[16]=20,[20]=2,[22]=28,[24]=1,
                              [30]=20,[32]=2,[36]=1,[37]=1,[43]=1};
static void protect_section(kobject_t *o) { o->sd=empty_sd;o->sd_len=sizeof empty_sd; }
#define CHECK(x) do {++checks;if(!(x)){++failures;if(failures<=32)fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);}}while(0)
static uint64_t irq_save(void){return irq_depth++;}
static void irq_restore(uint64_t f){CHECK(irq_depth==f+1);irq_depth=f;}
static void ob_ref(kobject_t *o){CHECK(o&&o->refs);++o->refs;}
static void ob_deref(kobject_t *o){CHECK(o&&o->refs);--o->refs;}
static thread_t *thread_current(void){return &current_thread;}
static int copy_to_user(process_t *p,uint64_t dst,const void *src,size_t size){(void)p;if(!dst||dst==BAD_USER_POINTER)return -1;memcpy((void *)(uintptr_t)dst,src,size);return 0;}
static int64_t stack_arg(process_t *p,struct regs *r,unsigned n){(void)p;CHECK(n>=5&&n<=7);return (int64_t)r->args[n-5];}
static void ipc_handle_opened(kobject_t *o){(void)o;}
static void ipc_handle_closed(process_t *p,kobject_t *o){(void)p;(void)o;++closed_hooks;}
void file_object_closed(kobject_t *o){(void)o;}
void net_socket_handle_closing(kobject_t *o){(void)o;}
void ntdrv_device_handle_closing(kobject_t *o){(void)o;}
static void duplicate_failure_trace(process_t *p,process_t *src,process_t *dst,kobject_t *o,
                                    uint64_t h,uint32_t access,uint32_t desired,uint32_t attrs,uint32_t opts,int32_t st)
{(void)p;(void)src;(void)dst;(void)o;(void)h;(void)access;(void)desired;(void)attrs;(void)opts;if(st)++trace_events;}

/* ACTUAL_OBJECT_AND_IPC_FUNCTIONS */

/* ACTUAL_LEGACY_SYSX_HELPERS */
static int32_t legacy_duplicate(process_t *p,struct regs *r,uint64_t a1,uint64_t a2,uint64_t a3,uint64_t a4)
{
    int32_t st;(void)a1;(void)a3;
    switch(1) {
#define SYS_NtDuplicateObject 1
/* ACTUAL_LEGACY_SYSX_DUPLICATE_CASE */
#undef SYS_NtDuplicateObject
    default: return STATUS_INVALID_HANDLE;
    }
}

static void init_process(process_t *p,kobject_t *object,int pid)
{memset(p,0,sizeof *p);p->handle_cap=16;p->pid=pid;p->object=object;memset(object,0,sizeof *object);object->type=OB_PROCESS;object->refs=1;object->u.proc.p=p;}
static uint32_t inserted(process_t *p,kobject_t *o,uint32_t access)
{uint32_t h=0;CHECK(!handle_insert(p,o,access,&h));return h;}
static int32_t duplicate(process_t *p,uint64_t src,uint64_t target,uint32_t desired,uint32_t options,uint64_t output)
{struct regs r={{desired,0,options}};return use_legacy_duplicate?
 legacy_duplicate(p,&r,CURRENT_PROCESS_HANDLE,src,target,output):sys_duplicate(p,&r,CURRENT_PROCESS_HANDLE,src,target,output);}
static uint32_t access_of(process_t *p,uint64_t h)
{kobject_t *o=0;uint32_t access=0;CHECK(!handle_ref(p,h,0,&o,&access));if(o)ob_deref(o);return access;}
static void dispose(process_t *p)
{for(unsigned i=0;i<p->handle_cap;++i)if(p->handles[i].obj)CHECK(!handle_close(p,(i+1)*4));CHECK(p->handle_count==0);CHECK(p->object->refs==1);}

static void actual_readonly_contract(void)
{
    process_t p; kobject_t po,section={.type=OB_SECTION,.refs=1},event={.type=OB_EVENT,.refs=1};
    protect_section(&section);
    init_process(&p,&po,11);kobject_t thread_object={.type=OB_THREAD,.refs=1};current_thread.object=&thread_object;
    uint32_t full=inserted(&p,&section,SECTION_ALL_ACCESS);uint64_t ro=0,x=0,y=0;
    CHECK(!duplicate(&p,full,CURRENT_PROCESS_HANDLE,0x20005u,0,(uintptr_t)&ro));CHECK(access_of(&p,ro)==0x20005u);
    uint32_t denied[]={2,6,GENERIC_ALL,GENERIC_WRITE,0x20,8,0x10,MAXIMUM_ALLOWED_ACCESS|2,MAXIMUM_ALLOWED_ACCESS|GENERIC_ALL};
    for(size_t i=0;i<sizeof denied/sizeof denied[0];++i){x=0;unsigned count=p.handle_count;uint32_t refs=section.refs;
        int32_t st=duplicate(&p,ro,CURRENT_PROCESS_HANDLE,denied[i],0,(uintptr_t)&x);
        CHECK(st==STATUS_ACCESS_DENIED);CHECK(x==0);CHECK(p.handle_count==count);CHECK(section.refs==refs);
        if(!st&&x)CHECK(!handle_close(&p,x));}
    uint32_t allowed[]={4,1,GENERIC_READ};
    for(size_t i=0;i<sizeof allowed/sizeof allowed[0];++i){CHECK(!duplicate(&p,ro,CURRENT_PROCESS_HANDLE,allowed[i],0,(uintptr_t)&x));
        CHECK(!(access_of(&p,x)&0xfffau));CHECK(!handle_close(&p,x));}
    CHECK(!duplicate(&p,ro,CURRENT_PROCESS_HANDLE,GENERIC_WRITE,DUPLICATE_SAME_ACCESS,(uintptr_t)&x));CHECK(access_of(&p,x)==0x20005u);CHECK(!handle_close(&p,x));
    CHECK(!duplicate(&p,ro,CURRENT_PROCESS_HANDLE,MAXIMUM_ALLOWED_ACCESS,0,(uintptr_t)&x));CHECK(access_of(&p,x)==0x20005u);CHECK(!handle_close(&p,x));
    CHECK(!duplicate(&p,full,CURRENT_PROCESS_HANDLE,6,0,(uintptr_t)&x));CHECK(!duplicate(&p,x,CURRENT_PROCESS_HANDLE,4,0,(uintptr_t)&y));
    CHECK(duplicate(&p,y,CURRENT_PROCESS_HANDLE,2,0,(uintptr_t)&x)==STATUS_ACCESS_DENIED);
    CHECK(!duplicate(&p,CURRENT_PROCESS_HANDLE,CURRENT_PROCESS_HANDLE,PROCESS_ALL_ACCESS,0,(uintptr_t)&x));CHECK(access_of(&p,x)==PROCESS_ALL_ACCESS);CHECK(!handle_close(&p,x));
    CHECK(!duplicate(&p,CURRENT_THREAD_HANDLE,CURRENT_PROCESS_HANDLE,THREAD_ALL_ACCESS,0,(uintptr_t)&x));CHECK(access_of(&p,x)==THREAD_ALL_ACCESS);CHECK(!handle_close(&p,x));
    uint32_t eh=inserted(&p,&event,0);CHECK(!duplicate(&p,eh,CURRENT_PROCESS_HANDLE,0x1f0003,0,(uintptr_t)&x));CHECK(access_of(&p,x)==0x1f0003);CHECK(!handle_close(&p,x));
    /* A current explicit NULL DACL permits actual expansion, including open. */
    section.sd=null_sd;section.sd_len=sizeof null_sd;
    uint32_t open=SECTION_ALL_ACCESS;CHECK(!ipc_section_duplicate_access(&section,0,&open));CHECK(open==SECTION_ALL_ACCESS);
    dispose(&p);CHECK(section.refs==1);CHECK(event.refs==1);CHECK(thread_object.refs==1);
}

static void actual_cross_process_and_failure_cleanup(void)
{
    process_t p,q;kobject_t po,qo,section={.type=OB_SECTION,.refs=1};
    protect_section(&section);
    init_process(&p,&po,31);init_process(&q,&qo,32);
    uint32_t src=inserted(&p,&section,5),target=inserted(&p,&qo,PROCESS_DUP_HANDLE);uint64_t out=0;
    CHECK(!duplicate(&p,src,target,4,0,(uintptr_t)&out));CHECK(q.handle_count==1);CHECK(access_of(&q,out)==4);
    CHECK(!handle_close(&q,out));out=0;
    int32_t widened=duplicate(&p,src,target,2,0,(uintptr_t)&out);CHECK(widened==STATUS_ACCESS_DENIED);CHECK(q.handle_count==0);CHECK(out==0);
    if(!widened&&out)CHECK(!handle_close(&q,out));
    CHECK(duplicate(&p,src,target,4,0,BAD_USER_POINTER)==STATUS_ACCESS_VIOLATION);CHECK(q.handle_count==0);
    q.teardown=1;CHECK(duplicate(&p,src,target,4,0,(uintptr_t)&out)==STATUS_PROCESS_IS_TERMINATING);q.teardown=0;
    unsigned count=p.handle_count;
    CHECK(duplicate(&p,src,CURRENT_PROCESS_HANDLE,2,DUPLICATE_CLOSE_SOURCE,(uintptr_t)&out)==STATUS_ACCESS_DENIED);
    CHECK(p.handle_count==count-1);kobject_t *o=0;CHECK(handle_ref(&p,src,0,&o,0)==STATUS_INVALID_HANDLE);
    src=inserted(&p,&section,5);CHECK(!duplicate(&p,src,0,2,DUPLICATE_CLOSE_SOURCE,0));CHECK(!p.handles[src/4-1].obj);
    src=inserted(&p,&section,5);p.handles[src/4-1].inherit=HANDLE_FLAG_INHERIT_BIT;
    CHECK(!duplicate(&p,src,CURRENT_PROCESS_HANDLE,0,DUPLICATE_SAME_ACCESS|DUPLICATE_SAME_ATTRIBUTES,(uintptr_t)&out));
    CHECK(p.handles[out/4-1].inherit==HANDLE_FLAG_INHERIT_BIT);CHECK(!handle_close(&p,out));
    CHECK(handle_ref(&p,0,0,&o,0)==STATUS_INVALID_HANDLE);CHECK(handle_ref(&p,65,0,&o,0)==STATUS_INVALID_HANDLE);
    CHECK(handle_ref(&p,src,OB_EVENT,&o,0)==STATUS_OBJECT_TYPE_MISMATCH);
    dispose(&p);dispose(&q);CHECK(section.refs==1);
}

static void actual_all_specific_access_masks(void)
{
    for(unsigned policy=0;policy<3;++policy)
    for(uint32_t granted=0;granted<64;++granted)for(uint32_t desired=0;desired<64;++desired){
        process_t p;kobject_t po,section={.type=OB_SECTION,.refs=1};init_process(&p,&po,41);
        if(policy==1)protect_section(&section);
        if(policy==2){section.sd=null_sd;section.sd_len=sizeof null_sd;}
        uint32_t src=inserted(&p,&section,granted);uint64_t out=0;unsigned count=p.handle_count;
        int32_t st=duplicate(&p,src,CURRENT_PROCESS_HANDLE,desired,0,(uintptr_t)&out);
        /* An empty ACL denies new object-specific rights. NULL/absent ACLs
         * permit them; source handle data rights are not a universal cap. */
        int denied=policy==1 && (desired&~granted)!=0;
        CHECK(st==(denied?STATUS_ACCESS_DENIED:STATUS_SUCCESS));
        CHECK(p.handle_count==count+(unsigned)!denied);
        if(!denied){CHECK(access_of(&p,out)==desired);CHECK(!handle_close(&p,out));}
        else CHECK(out==0);
        CHECK(access_of(&p,src)==granted);dispose(&p);CHECK(section.refs==1);
    }
}

static void actual_legacy_fallback_scope(void)
{
    process_t p;kobject_t po,section={.type=OB_SECTION,.refs=1};init_process(&p,&po,71);
    protect_section(&section);
    uint32_t src=inserted(&p,&section,5);uint64_t out=0;struct regs r={{2,0,0}};
    /* Only the actual same-process case body is exercised here. A real
     * production syscall still routes through IPC before this fallback. */
    CHECK(legacy_duplicate(&p,&r,CURRENT_PROCESS_HANDLE,src,CURRENT_PROCESS_HANDLE,(uintptr_t)&out)==STATUS_ACCESS_DENIED);
    CHECK(out==0);CHECK(access_of(&p,src)==5);
    printf("scope: both section duplicate policies checked; production route is IPC\n");
    dispose(&p);CHECK(section.refs==1);
}

static void actual_same_process_failure_cleanup(void)
{
    process_t p;kobject_t po,section={.type=OB_SECTION,.refs=1};init_process(&p,&po,81);
    protect_section(&section);
    uint32_t src=inserted(&p,&section,5);unsigned count=p.handle_count;uint64_t out=0;
    CHECK(duplicate(&p,src,CURRENT_PROCESS_HANDLE,4,0,BAD_USER_POINTER)==STATUS_ACCESS_VIOLATION);
    CHECK(p.handle_count==count);CHECK(section.refs==2);CHECK(access_of(&p,src)==5);
    CHECK(duplicate(&p,src,CURRENT_PROCESS_HANDLE,2,DUPLICATE_CLOSE_SOURCE,(uintptr_t)&out)==STATUS_ACCESS_DENIED);
    CHECK(out==0);CHECK(p.handle_count==count-1);CHECK(section.refs==1);
    kobject_t *o=0;CHECK(handle_ref(&p,src,0,&o,0)==STATUS_INVALID_HANDLE);
    src=inserted(&p,&section,5);
    CHECK(duplicate(&p,src,CURRENT_PROCESS_HANDLE,4,DUPLICATE_CLOSE_SOURCE,BAD_USER_POINTER)==STATUS_ACCESS_VIOLATION);
    CHECK(p.handle_count==0);CHECK(section.refs==1);
    CHECK(!duplicate(&p,CURRENT_PROCESS_HANDLE,CURRENT_PROCESS_HANDLE,2,DUPLICATE_SAME_ACCESS,(uintptr_t)&out));
    CHECK(access_of(&p,out)==PROCESS_ALL_ACCESS);CHECK(!handle_close(&p,out));
    dispose(&p);CHECK(section.refs==1);
}

static void actual_descriptor_update_and_null_expansion(void)
{
    process_t p;kobject_t po,section={.type=OB_SECTION,.refs=1};init_process(&p,&po,91);
    uint32_t src=inserted(&p,&section,5);uint64_t out=0;
    /* The default absent descriptor and explicit NULL descriptor both permit
     * a new write handle to the SAME object; actual new grant is checked. */
    CHECK(!duplicate(&p,src,CURRENT_PROCESS_HANDLE,2,0,(uintptr_t)&out));CHECK(access_of(&p,out)==2);CHECK(!handle_close(&p,out));
    section.sd=null_sd;section.sd_len=sizeof null_sd;
    CHECK(!duplicate(&p,src,CURRENT_PROCESS_HANDLE,2,0,(uintptr_t)&out));CHECK(access_of(&p,out)==2);CHECK(!handle_close(&p,out));
    CHECK(!duplicate(&p,src,CURRENT_PROCESS_HANDLE,MAXIMUM_ALLOWED_ACCESS|2,0,(uintptr_t)&out));CHECK(access_of(&p,out)==7);CHECK(!handle_close(&p,out));
    protect_section(&section);out=0;
    CHECK(duplicate(&p,src,CURRENT_PROCESS_HANDLE,2,0,(uintptr_t)&out)==STATUS_ACCESS_DENIED);CHECK(out==0);
    CHECK(duplicate(&p,src,CURRENT_PROCESS_HANDLE,0x20u,0,(uintptr_t)&out)==STATUS_ACCESS_DENIED);CHECK(out==0);
    CHECK(duplicate(&p,src,CURRENT_PROCESS_HANDLE,0x40u,0,(uintptr_t)&out)==SHZ_SEC_UNSUPPORTED);CHECK(out==0);
    /* Generic-read requests READ_CONTROL too; an empty descriptor cannot
     * invent a token/owner evaluator for a grant that did not have it. */
    CHECK(duplicate(&p,src,CURRENT_PROCESS_HANDLE,GENERIC_READ,0,(uintptr_t)&out)==SHZ_SEC_UNSUPPORTED);CHECK(out==0);
    section.sd=nonempty_sd;section.sd_len=sizeof nonempty_sd;
    CHECK(duplicate(&p,src,CURRENT_PROCESS_HANDLE,2,0,(uintptr_t)&out)==SHZ_SEC_UNSUPPORTED);CHECK(out==0);
    CHECK(!duplicate(&p,src,CURRENT_PROCESS_HANDLE,4,0,(uintptr_t)&out));CHECK(access_of(&p,out)==4);CHECK(!handle_close(&p,out));
    section.sd=null_sd;section.sd_len=sizeof null_sd;
    CHECK(!duplicate(&p,src,CURRENT_PROCESS_HANDLE,0x20u,0,(uintptr_t)&out));CHECK(access_of(&p,out)==0x20u);CHECK(!handle_close(&p,out));
    CHECK(!duplicate(&p,src,CURRENT_PROCESS_HANDLE,2,0,(uintptr_t)&out));CHECK(access_of(&p,out)==2);CHECK(!handle_close(&p,out));
    uint32_t closing=inserted(&p,&section,5);out=0;
    CHECK(!duplicate(&p,closing,CURRENT_PROCESS_HANDLE,2,DUPLICATE_CLOSE_SOURCE,(uintptr_t)&out));CHECK(access_of(&p,out)==2);CHECK(!p.handles[closing/4-1].obj);CHECK(!handle_close(&p,out));
    CHECK(access_of(&p,src)==5);dispose(&p);CHECK(section.refs==1);
}

int main(void)
{actual_readonly_contract();actual_cross_process_and_failure_cleanup();actual_all_specific_access_masks();actual_same_process_failure_cleanup();actual_descriptor_update_and_null_expansion();
 use_legacy_duplicate=1;actual_readonly_contract();actual_all_specific_access_masks();actual_same_process_failure_cleanup();actual_legacy_fallback_scope();actual_descriptor_update_and_null_expansion();CHECK(irq_depth==0);
 printf("actual IPC duplicate/handle_ref: %u checks, %u failures, %u close hooks\n",checks,failures,closed_hooks);return failures?1:0;}
