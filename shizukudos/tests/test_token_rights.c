/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel64 regression fixture. Production code is inserted by the Python
 * runner; authorization and handle lifetime behavior are never reimplemented.
 * Process/thread host records only model fields consumed by this dispatch.
 */
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STATUS_SUCCESS 0
#define STATUS_NO_MEMORY ((int32_t)0xc0000017)
#define STATUS_INVALID_HANDLE ((int32_t)0xc0000008)
#define STATUS_OBJECT_TYPE_MISMATCH ((int32_t)0xc0000024)
#define STATUS_ACCESS_DENIED ((int32_t)0xc0000022)
#define STATUS_INFO_LENGTH_MISMATCH ((int32_t)0xc0000004)
#define STATUS_ACCESS_VIOLATION ((int32_t)0xc0000005)
#define STATUS_INVALID_INFO_CLASS ((int32_t)0xc0000003)
#define STATUS_INVALID_PARAMETER ((int32_t)0xc000000d)
#define STATUS_THREAD_IS_TERMINATING ((int32_t)0xc000004b)
#define STATUS_BUFFER_TOO_SMALL ((int32_t)0xc0000023)
#define STATUS_INVALID_SYSTEM_SERVICE ((int32_t)0xc000001c)
#define CURRENT_PROCESS_HANDLE UINT64_MAX
#define CURRENT_THREAD_HANDLE (UINT64_MAX-1)
#define OB_MUTANT 2
#define OB_THREAD 4
#define OB_PROCESS 5
#define OB_FILE 6
#define OB_TIMER 7
#define OB_KEY 0x10
#define OB_TOKEN 0x20
#define OB_SOCKET 0x40
#define KASSERT(x) assert(x)
#define SYS_NtShzToken 0x9d
#define SYS_NtShzSecurityObject 0x9e
#define SHZ_TOK_OPEN_PROCESS 1
#define SHZ_TOK_OPEN_THREAD 2
#define SHZ_TOK_QUERY 3
#define SHZ_TOK_SET 4
#define SHZ_TOK_DUPLICATE 5
#define SHZ_TOK_IMPERSONATE 6
#define SHZ_TOKF_INTEGRITY 1
#define SHZ_TOKF_SESSION 2
#define SHZ_TOKF_PRIVS 3
#define SHZ_SOB_QUERY 1
#define SHZ_SOB_SET 2

typedef struct process process_t;
typedef struct thread thread_t;
typedef struct kobject kobject_t;
/* @PRODUCTION_OBJECT_LAYOUT@ */
struct process {
    int used, pid, teardown;
    kobject_t *object, *token;
    handle_entry_t *handles;
    unsigned handle_cap, handle_count;
};
struct thread { kobject_t *object, *impersonation; process_t *proc; };
struct regs { uint64_t arg5; };
static kobject_t *named_head, *timers_head[16];
static unsigned timer_count;
static unsigned live_allocations, allocation_calls, copy_in_calls, copy_out_calls;
static int fail_allocate, fail_in, fail_out;
static thread_t *current_thread;
static uint64_t irq_save(void) { return 0; }
static void irq_restore(uint64_t f) { (void)f; }
static void *kmalloc(uint64_t n) {
    ++allocation_calls;
    if (fail_allocate) return NULL;
    void *p = malloc((size_t)n);
    if (p) ++live_allocations;
    return p;
}
static void *kzalloc(uint64_t n) { void *p=kmalloc(n); if (p) memset(p,0,(size_t)n); return p; }
static void kfree(void *p) { if (p) { assert(live_allocations); --live_allocations; free(p); } }
static thread_t *thread_current(void) { return current_thread; }
static int copy_to_user(process_t *p,uint64_t dst,const void *src,uint64_t n) {
    (void)p; ++copy_out_calls;
    if (!dst || fail_out) return -1;
    memcpy((void *)(uintptr_t)dst,src,(size_t)n); return 0;
}
static int copy_from_user(process_t *p,void *dst,uint64_t src,uint64_t n) {
    (void)p; ++copy_in_calls;
    if (!src || fail_in) return -1;
    memcpy(dst,(const void *)(uintptr_t)src,(size_t)n); return 0;
}
int64_t stack_arg(process_t *p,struct regs *r,unsigned n) { (void)p; assert(n==5); return (int64_t)r->arg5; }
static void reg_key_object_free(kobject_t *o) { (void)o; }
static void ipc_object_free(kobject_t *o) { (void)o; }
static void ipc_handle_closed(process_t *p,kobject_t *o) { (void)p; (void)o; }
static void file_object_closed(kobject_t *o) { (void)o; }
static void net_socket_handle_closing(kobject_t *o) { (void)o; }
static void ntdrv_device_handle_closing(kobject_t *o) { (void)o; }
void token_object_free(kobject_t *o);
static unsigned auth_calls;
static int deny_other_subject, deny_handle;
int shz_auth_process_access(process_t *cur,process_t *target)
{ return target && (!deny_other_subject || cur==target); }
int shz_auth_handle_allowed(process_t *p,kobject_t *o)
{ (void)p; (void)o; return !deny_handle; }
int32_t shz_auth_syscall(process_t *p,uint64_t op,uint64_t a2,uint64_t a3,uint64_t a4)
{ (void)p; (void)op; (void)a2; (void)a3; (void)a4; ++auth_calls; return (int32_t)0xc00000bb; }
/* @PRODUCTION_OBJECT_FUNCTIONS@ */
/* @PRODUCTION_SECURITY_TRANSLATION_UNIT@ */

/* Only Windows ABI type declarations and transport entry are host adapters;
 * the complete production ntdll wrapper is inserted unchanged below. */
typedef int32_t NTSTATUS;
typedef uint32_t ULONG, ACCESS_MASK;
typedef uintptr_t ULONG_PTR;
typedef uint8_t BOOLEAN;
typedef void *HANDLE;
typedef HANDLE *PHANDLE;
#define NTAPI
#define K32S_SUSPEND_PROCESS 1
#define K32S_RESUME_PROCESS 2
typedef struct { ULONG Length; HANDLE RootDirectory; void *ObjectName; ULONG Attributes;
                 void *SecurityDescriptor, *SecurityQualityOfService; } SHZ_OBJECT_ATTRIBUTES;
static process_t process, target_process;
static int model_old_backend;
static NTSTATUS NtShzToken(ULONG_PTR op,ULONG_PTR a2,ULONG_PTR a3,ULONG_PTR a4)
{
    if (model_old_backend && op==0x100) return STATUS_INVALID_PARAMETER;
    struct regs r={0}; return sys_ext_k32_obj(&process,&r,SYS_NtShzToken,op,a2,a3,a4);
}
static NTSTATUS NtShzSetK32(ULONG cls,HANDLE process,void *buf,ULONG len)
{ (void)cls; (void)process; (void)buf; (void)len; return (int32_t)0xc00000bb; }
/* @PRODUCTION_TOKEN_FRONTEND@ */

static thread_t caller_thread, target_thread;
static handle_entry_t entries[32], target_entries[4];
static kobject_t *roots[16];
static unsigned root_count, assertions, failures;
#define EXPECT(c) do { ++assertions; if (!(c)) { fprintf(stderr,"%s:%d: %s\n",__func__,__LINE__,#c); return 0; } } while (0)
static uint64_t ptr(const void *p) { return (uint64_t)(uintptr_t)p; }
static kobject_t *root_object(unsigned type) {
    kobject_t *o=ob_create(type,0); assert(o && root_count<16); roots[root_count++]=o; return o;
}
static void init_case(void) {
    assert(!live_allocations);
    deny_other_subject=deny_handle=0;
    memset(&process,0,sizeof process); memset(&target_process,0,sizeof target_process);
    memset(&caller_thread,0,sizeof caller_thread); memset(&target_thread,0,sizeof target_thread);
    memset(entries,0,sizeof entries); memset(target_entries,0,sizeof target_entries);
    process.used=target_process.used=1; process.pid=92; target_process.pid=93;
    process.handles=entries; process.handle_cap=32;
    target_process.handles=target_entries; target_process.handle_cap=4;
    process.object=root_object(OB_PROCESS); process.object->u.proc.p=&process;
    target_process.object=root_object(OB_PROCESS); target_process.object->u.proc.p=&target_process;
    caller_thread.object=root_object(OB_THREAD); caller_thread.object->u.thr.t=&caller_thread;
    target_thread.object=root_object(OB_THREAD); target_thread.object->u.thr.t=&target_thread;
    caller_thread.proc=&process; target_thread.proc=&target_process;
    current_thread=&caller_thread;
}
static void finish_case(void) {
    fail_allocate=fail_in=fail_out=0;
    for (unsigned i=0;i<process.handle_cap;++i) if(entries[i].obj) assert(!handle_close(&process,(i+1)*4));
    if(caller_thread.impersonation) ob_deref(caller_thread.impersonation);
    if(target_thread.impersonation) ob_deref(target_thread.impersonation);
    if(process.token) ob_deref(process.token);
    if(target_process.token) ob_deref(target_process.token);
    while(root_count) ob_deref(roots[--root_count]);
    assert(!live_allocations && !named_head);
}
static uint32_t put_handle(kobject_t *o,uint32_t access) {
    uint32_t h=0; assert(!handle_insert(&process,o,access,&h)); return h;
}
static uint32_t token_handle(uint32_t access) { return put_handle(process_token(&process),access); }
static kobject_t *imp_token(void) {
    shz_token_info value={.type=2,.imp_level=2,.integrity_rid=0x2000,.session=1};
    kobject_t *o=token_new(&value,92); assert(o && root_count<16); roots[root_count++]=o; return o;
}
static int32_t token_call(uint64_t op,uint64_t a2,uint64_t a3,uint64_t a4) {
    struct regs r={0}; return sys_ext_k32_obj(&process,&r,SYS_NtShzToken,op,a2,a3,a4);
}
static int32_t security_call(uint64_t op,uint64_t h,void *buf,uint64_t len,uint32_t *need) {
    struct regs r={ptr(need)}; return sys_ext_k32_obj(&process,&r,SYS_NtShzSecurityObject,op,h,ptr(buf),len);
}
typedef struct {
    shz_token_info value;
    uint32_t refs, handles;
    unsigned allocations, in, out;
} token_snapshot;
static token_snapshot snapshot(kobject_t *o) {
    token_snapshot s={*(shz_token_info *)o->u.token.t,o->refs,process.handle_count,allocation_calls,copy_in_calls,copy_out_calls}; return s;
}
static int unchanged(kobject_t *o,token_snapshot s) {
    EXPECT(!memcmp(o->u.token.t,&s.value,sizeof s.value)); EXPECT(o->refs==s.refs);
    EXPECT(process.handle_count==s.handles); EXPECT(allocation_calls==s.allocations);
    EXPECT(copy_in_calls==s.in && copy_out_calls==s.out); return 1;
}

/* Catch loss of the existing TOKEN_QUERY gate or reference/output cleanup. */
static int query_rights(void) {
    uint32_t h=token_handle(8); kobject_t *o=process.token;
    shz_token_info output; memset(&output,0xa5,sizeof output);
    EXPECT(token_call(3,h,ptr(&output),sizeof output)==0);
    EXPECT(!memcmp(&output,o->u.token.t,sizeof output) && o->refs==2);
    const uint32_t denied[]={0,2,4,0x20,0x80,0x10000000};
    for(unsigned i=0;i<sizeof denied/sizeof *denied;++i) {
        entries[h/4-1].access=denied[i]; token_snapshot s=snapshot(o);
        memset(&output,0xa5,sizeof output); shz_token_info before=output;
        EXPECT(token_call(3,h,ptr(&output),sizeof output)==STATUS_ACCESS_DENIED);
        EXPECT(!memcmp(&output,&before,sizeof output)); EXPECT(unchanged(o,s));
        EXPECT(token_call(3,h,0,0)==STATUS_ACCESS_DENIED); EXPECT(unchanged(o,s));
    }
    entries[h/4-1].access=8;
    EXPECT(token_call(3,h,0,sizeof output-1)==STATUS_INFO_LENGTH_MISMATCH);
    EXPECT(token_call(3,h,0,sizeof output)==STATUS_ACCESS_VIOLATION); EXPECT(o->refs==2);
    EXPECT(token_call(3,1,0,sizeof output)==STATUS_INVALID_HANDLE);
    EXPECT(token_call(3,put_handle(process.object,8),0,sizeof output)==STATUS_OBJECT_TYPE_MISMATCH);
    return 1;
}
/* Missing TOKEN_ADJUST_DEFAULT/SESSIONID/PRIVILEGES gates mutate denied tokens. */
static int mutation_denial(void) {
    uint32_t h=token_handle(8); kobject_t *o=process.token;
    const struct {uint64_t field,value;} denied[]={{1,0x1000},{2,1},{3,0x12345678}};
    for(unsigned i=0;i<sizeof denied/sizeof *denied;++i) {
        token_snapshot s=snapshot(o);
        EXPECT(token_call(4,h,denied[i].field,denied[i].value)==STATUS_ACCESS_DENIED);
        EXPECT(unchanged(o,s));
    }
    return 1;
}
static int mutation_allowed(void) {
    uint32_t h=token_handle(0x80); shz_token_info *t=process.token->u.token.t;
    uint64_t modified=t->modified_id;
    EXPECT(token_call(4,h,1,0x1000)==0); EXPECT(t->integrity_rid==0x1000 && t->modified_id!=modified);
    token_snapshot s=snapshot(process.token);
    EXPECT(token_call(4,h,1,0x3000)==STATUS_ACCESS_DENIED); EXPECT(unchanged(process.token,s));
    entries[h/4-1].access=0x20; modified=t->modified_id;
    EXPECT(token_call(4,h,3,0x02)==0); EXPECT(t->flags==0x02 && t->modified_id!=modified);
    entries[h/4-1].access=0x100;
    EXPECT(token_call(4,h,2,1)==0);
    s=snapshot(process.token); EXPECT(token_call(4,h,2,2)==STATUS_ACCESS_DENIED); EXPECT(unchanged(process.token,s));
    return 1;
}
static int duplicate_denial(void) {
    uint32_t h=token_handle(8); kobject_t *o=process.token; uint64_t output=0xa5a5a5a5a5a5a5a5ull;
    token_snapshot s=snapshot(o);
    EXPECT(token_call(5,h,2|(2u<<8),ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(output==0xa5a5a5a5a5a5a5a5ull && unchanged(o,s));
    EXPECT(token_call(0x100,h,8ull|(2ull<<32)|(2ull<<40),ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(output==0xa5a5a5a5a5a5a5a5ull && unchanged(o,s)); return 1;
}
static int duplicate_legacy_no_amplification(void) {
    uint32_t h=token_handle(0xa); uint64_t output=0;
    EXPECT(token_call(5,h,2|(2u<<8),ptr(&output))==0);
    EXPECT(output && entries[output/4-1].access==0xa);
    shz_token_info *t=entries[output/4-1].obj->u.token.t,*original=process.token->u.token.t;
    EXPECT(t->type==2 && t->imp_level==2 && t->id!=original->id && t->owner_pid==92);
    EXPECT(process.token->refs==2); return 1;
}
static int duplicate_explicit_rights(void) {
    uint32_t h=token_handle(0xa); uint64_t output=0;
    EXPECT(token_call(0x100,h,8ull|(2ull<<32)|(2ull<<40),ptr(&output))==0);
    EXPECT(output && entries[output/4-1].access==8);
    shz_token_info *t=entries[output/4-1].obj->u.token.t;
    EXPECT(t->type==2 && t->imp_level==2);
    EXPECT(token_call(0x100,h,(1ull<<32),ptr(&output))==0);
    EXPECT(entries[output/4-1].access==0xa); return 1;
}
/* Desired access cannot exceed the originating handle's actual grant. */
static int duplicate_requested_access_ceiling(void) {
    uint32_t h=token_handle(0xa); uint64_t output=0xa5a5a5a5a5a5a5a5ull;
    token_snapshot s=snapshot(process.token);
    EXPECT(token_call(0x100,h,0xf01ffull|(2ull<<32)|(2ull<<40),ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(output==0xa5a5a5a5a5a5a5a5ull && unchanged(process.token,s));
    EXPECT(token_call(0x100,h,0x02000000ull|(2ull<<32)|(2ull<<40),ptr(&output))==0);
    EXPECT(output && entries[output/4-1].access==0xa); return 1;
}
static int duplicate_invalid_packing(void) {
    uint32_t h=token_handle(2); kobject_t *o=process.token; uint64_t output=0xa5a5a5a5a5a5a5a5ull;
    const uint64_t invalid[]={8ull|(3ull<<32),8ull|(2ull<<32)|(4ull<<40),8ull|(2ull<<32)|(1ull<<48)};
    for(unsigned i=0;i<sizeof invalid/sizeof *invalid;++i) {
        token_snapshot s=snapshot(o);
        EXPECT(token_call(0x100,h,invalid[i],ptr(&output))==STATUS_INVALID_PARAMETER);
        EXPECT(output==0xa5a5a5a5a5a5a5a5ull && unchanged(o,s));
    }
    token_snapshot s=snapshot(o);
    EXPECT(token_call(0x100,h,0x200ull|(2ull<<32),ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(output==0xa5a5a5a5a5a5a5a5ull && unchanged(o,s));
    EXPECT(token_call(5,h,1ull<<16,ptr(&output))==STATUS_INVALID_PARAMETER);
    EXPECT(output==0xa5a5a5a5a5a5a5a5ull && unchanged(o,s));
    return 1;
}
static int token_masks_and_impersonation_level(void) {
    uint64_t output=0;
    EXPECT(token_call(1,CURRENT_PROCESS_HANDLE,0x80000000u,ptr(&output))==0);
    EXPECT(entries[output/4-1].access==0x20008);
    unsigned calls=allocation_calls; uint64_t before=output;
    EXPECT(token_call(1,CURRENT_PROCESS_HANDLE,0x200u,ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(output==before && calls==allocation_calls);
    kobject_t *tok=imp_token(); uint32_t h=put_handle(tok,0xa); token_snapshot s=snapshot(tok);
    EXPECT(token_call(0x100,h,8ull|(2ull<<32)|(3ull<<40),ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(output==before && unchanged(tok,s));
    EXPECT(token_call(0x100,h,8ull|(2ull<<32)|(1ull<<40),ptr(&output))==0);
    EXPECT(entries[output/4-1].access==8 && ((shz_token_info *)entries[output/4-1].obj->u.token.t)->imp_level==1);
    uint32_t primary=token_handle(0x20); s=snapshot(process.token);
    EXPECT(token_call(4,primary,3,0x20)==STATUS_INVALID_PARAMETER);
    EXPECT(unchanged(process.token,s)); return 1;
}
static int duplicate_failure_cleanup(void) {
    uint32_t h=token_handle(0xa); kobject_t *o=process.token; unsigned live=live_allocations;
    uint32_t handles=process.handle_count,refs=o->refs;
    EXPECT(token_call(5,h,2|(2u<<8),0)==STATUS_ACCESS_VIOLATION);
    EXPECT(live_allocations==live && process.handle_count==handles && o->refs==refs);
    EXPECT(token_call(0x100,h,8ull|(2ull<<32)|(2ull<<40),0)==STATUS_ACCESS_VIOLATION);
    EXPECT(live_allocations==live && process.handle_count==handles && o->refs==refs);
    fail_allocate=1;
    EXPECT(token_call(0x100,h,8ull|(2ull<<32)|(2ull<<40),0)==STATUS_NO_MEMORY);
    fail_allocate=0; EXPECT(live_allocations==live && process.handle_count==handles && o->refs==refs); return 1;
}
static int impersonation_token_denial(void) {
    kobject_t *tok=imp_token(); uint32_t h=put_handle(tok,8); token_snapshot s=snapshot(tok);
    EXPECT(token_call(6,CURRENT_THREAD_HANDLE,h,0)==STATUS_ACCESS_DENIED);
    EXPECT(!caller_thread.impersonation && unchanged(tok,s)); return 1;
}
static int impersonation_thread_denial(void) {
    kobject_t *tok=imp_token(); uint32_t th=put_handle(target_thread.object,0),h=put_handle(tok,4);
    token_snapshot s=snapshot(tok); uint32_t threadrefs=target_thread.object->refs;
    EXPECT(token_call(6,th,h,0)==STATUS_ACCESS_DENIED);
    EXPECT(!target_thread.impersonation && target_thread.object->refs==threadrefs && unchanged(tok,s));
    ob_ref(tok); target_thread.impersonation=tok; s=snapshot(tok);
    EXPECT(token_call(6,th,0,0)==STATUS_ACCESS_DENIED);
    EXPECT(target_thread.impersonation==tok && target_thread.object->refs==threadrefs && unchanged(tok,s)); return 1;
}
static int impersonation_allowed_and_revert(void) {
    kobject_t *tok=imp_token(); uint32_t th=put_handle(target_thread.object,0x80),h=put_handle(tok,4),refs=tok->refs;
    EXPECT(token_call(6,th,h,0)==0); EXPECT(target_thread.impersonation==tok && tok->refs==refs+1);
    EXPECT(token_call(6,th,0,0)==0); EXPECT(!target_thread.impersonation && tok->refs==refs);
    EXPECT(token_call(6,CURRENT_THREAD_HANDLE,h,0)==0); EXPECT(caller_thread.impersonation==tok && tok->refs==refs+1);
    EXPECT(token_call(6,0,0,0)==0); EXPECT(!caller_thread.impersonation && tok->refs==refs);
    uint32_t primary=token_handle(4); refs=process.token->refs;
    EXPECT(token_call(6,0,primary,0)==(int32_t)0xc000005c);
    EXPECT(!caller_thread.impersonation && process.token->refs==refs); return 1;
}
static int open_process_denial(void) {
    uint32_t h=put_handle(target_process.object,0); uint64_t output=0xa5a5a5a5a5a5a5a5ull;
    unsigned allocations=allocation_calls,copies=copy_out_calls,refs=target_process.object->refs,handles=process.handle_count;
    EXPECT(token_call(1,h,8,ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(!target_process.token && output==0xa5a5a5a5a5a5a5a5ull);
    EXPECT(allocations==allocation_calls && copies==copy_out_calls && refs==target_process.object->refs && handles==process.handle_count);
    EXPECT(token_call(1,h,8,0)==STATUS_ACCESS_DENIED); return 1;
}
static int open_process_allowed_and_copy_cleanup(void) {
    uint32_t h=put_handle(target_process.object,0x400); uint64_t output=0;
    EXPECT(token_call(1,h,8,ptr(&output))==0);
    EXPECT(output && entries[output/4-1].obj==target_process.token && entries[output/4-1].access==8);
    entries[h/4-1].access=0x1000; EXPECT(token_call(1,h,8,ptr(&output))==0);
    EXPECT(entries[output/4-1].access==8);
    unsigned refs=target_process.token->refs,handles=process.handle_count,live=live_allocations;
    EXPECT(token_call(1,h,8,0)==STATUS_ACCESS_VIOLATION);
    EXPECT(target_process.token->refs==refs && process.handle_count==handles && live_allocations==live);
    EXPECT(token_call(1,CURRENT_PROCESS_HANDLE,8,ptr(&output))==0); return 1;
}
static int open_thread_denial(void) {
    kobject_t *tok=imp_token(); ob_ref(tok); target_thread.impersonation=tok;
    uint32_t h=put_handle(target_thread.object,0); uint64_t output=0xa5a5a5a5a5a5a5a5ull;
    token_snapshot s=snapshot(tok); uint32_t refs=target_thread.object->refs;
    EXPECT(token_call(2,h,8,ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(output==0xa5a5a5a5a5a5a5a5ull && target_thread.impersonation==tok);
    EXPECT(target_thread.object->refs==refs && unchanged(tok,s)); return 1;
}
static int open_thread_allowed_and_copy_cleanup(void) {
    kobject_t *tok=imp_token(); ob_ref(tok); target_thread.impersonation=tok;
    uint32_t h=put_handle(target_thread.object,0x40); uint64_t output=0;
    EXPECT(token_call(2,h,8,ptr(&output))==0);
    EXPECT(output && entries[output/4-1].obj==tok && entries[output/4-1].access==8);
    entries[h/4-1].access=0x800; EXPECT(token_call(2,h,8,ptr(&output))==0);
    unsigned refs=tok->refs,handles=process.handle_count;
    EXPECT(token_call(2,h,8,0)==STATUS_ACCESS_VIOLATION);
    EXPECT(tok->refs==refs && process.handle_count==handles);
    EXPECT(token_call(2,CURRENT_THREAD_HANDLE,8,ptr(&output))==(int32_t)0xc000007c); return 1;
}
static int descriptor_query_denial(void) {
    kobject_t *o=root_object(1); o->sd=kmalloc(20); o->sd_len=20; memset(o->sd,0x42,20);
    uint32_t h=put_handle(o,0),need=0xa5a5a5a5; uint8_t output[20],before[20]; memset(output,0xa5,20); memcpy(before,output,20);
    unsigned alloc=allocation_calls,in=copy_in_calls,out=copy_out_calls,refs=o->refs;
    EXPECT(security_call(1,h,output,20,&need)==STATUS_ACCESS_DENIED);
    EXPECT(!memcmp(output,before,20) && need==0xa5a5a5a5);
    EXPECT(allocation_calls==alloc && copy_in_calls==in && copy_out_calls==out && o->refs==refs); return 1;
}
static int descriptor_set_denial(void) {
    kobject_t *o=root_object(1); o->sd=kmalloc(20); o->sd_len=20; memset(o->sd,0x42,20);
    uint32_t h=put_handle(o,0x20000); uint8_t input[24]; memset(input,0x24,24); void *before=o->sd;
    unsigned alloc=allocation_calls,in=copy_in_calls,out=copy_out_calls,refs=o->refs;
    EXPECT(security_call(2,h,input,24,0)==STATUS_ACCESS_DENIED);
    EXPECT(o->sd==before && o->sd_len==20 && *(uint8_t *)o->sd==0x42);
    EXPECT(allocation_calls==alloc && copy_in_calls==in && copy_out_calls==out && o->refs==refs);
    EXPECT(security_call(2,h,0,0,0)==STATUS_ACCESS_DENIED); return 1;
}
static int descriptor_allowed_and_copy_cleanup(void) {
    kobject_t *o=root_object(1); uint32_t h=put_handle(o,0x40000),need=0; uint8_t input[24],output[24]; memset(input,0x24,24);
    EXPECT(security_call(2,h,input,24,0)==0);
    EXPECT(o->sd_len==24 && !memcmp(o->sd,input,24));
    entries[h/4-1].access=0x20000;
    EXPECT(security_call(1,h,output,24,&need)==0); EXPECT(need==24 && !memcmp(output,input,24));
    unsigned live=live_allocations,refs=o->refs;
    EXPECT(security_call(1,h,0,24,0)==STATUS_ACCESS_VIOLATION); EXPECT(live_allocations==live && o->refs==refs);
    EXPECT(security_call(1,h,output,23,&need)==STATUS_BUFFER_TOO_SMALL); EXPECT(need==24);
    fail_out=1;
    EXPECT(security_call(1,h,output,24,&need)==STATUS_ACCESS_VIOLATION);
    fail_out=0; EXPECT(live_allocations==live && o->refs==refs);
    entries[h/4-1].access=0x40000; void *before=o->sd; fail_in=1;
    EXPECT(security_call(2,h,input,24,0)==STATUS_ACCESS_VIOLATION); fail_in=0;
    EXPECT(o->sd==before && o->sd_len==24 && live_allocations==live && o->refs==refs);
    return 1;
}
static int invalid_dispatch(void) {
    struct regs r={0}; EXPECT(sys_ext_k32_obj(&process,&r,0,0,0,0,0)==STATUS_INVALID_SYSTEM_SERVICE);
    EXPECT(token_call(0,0,0,0)==STATUS_INVALID_PARAMETER);
    EXPECT(token_call(1,0,8,0)==STATUS_INVALID_HANDLE);
    EXPECT(token_call(2,0,8,0)==STATUS_INVALID_HANDLE); return 1;
}
/* Real centralized handle functions must admit before refs or output writes. */
static int centralized_handle_admission(void) {
    uint32_t h=put_handle(target_process.object,0x400),refs=target_process.object->refs;
    uint32_t access=0xa5a5a5a5; kobject_t *out=process.object;
    unsigned alloc=allocation_calls,handles=process.handle_count;
    deny_handle=1;
    EXPECT(!handle_lookup(&process,h,OB_PROCESS));
    EXPECT(handle_ref(&process,h,OB_PROCESS,&out,&access)==STATUS_ACCESS_DENIED);
    EXPECT(out==process.object && access==0xa5a5a5a5);
    EXPECT(target_process.object->refs==refs && process.handle_count==handles && allocation_calls==alloc);
    deny_handle=0;
    EXPECT(handle_lookup(&process,h,OB_PROCESS)==target_process.object);
    EXPECT(handle_ref(&process,h,OB_PROCESS,&out,&access)==0);
    EXPECT(out==target_process.object && access==0x400 && out->refs==refs+1);
    ob_deref(out); EXPECT(out->refs==refs);
    return 1;
}
static int trusted_binding_and_auth_boundary(void) {
    unsigned calls=auth_calls;
    EXPECT(token_call(0x200,0,0,0)==(int32_t)0xc00000bb && auth_calls==calls+1);
    EXPECT(token_call(0x20f,0,0,0)==(int32_t)0xc00000bb && auth_calls==calls+2);
    EXPECT(token_call(0x210,0,0,0)==STATUS_INVALID_PARAMETER && auth_calls==calls+2);
    EXPECT(shz_token_bind_subject(NULL,47,1,0x2000)==STATUS_INVALID_PARAMETER);
    EXPECT(shz_token_bind_subject(&process,0,1,0x2000)==STATUS_INVALID_PARAMETER);
    EXPECT(!process.token && shz_token_integrity(&process,0x2000)==0x2000);
    fail_allocate=1;
    EXPECT(shz_token_bind_subject(&process,47,2,0x3000)==STATUS_NO_MEMORY);
    fail_allocate=0; EXPECT(!process.token);
    EXPECT(shz_token_bind_subject(&process,47,2,0x3000)==0);
    shz_token_info *t=process.token->u.token.t;
    EXPECT(t->auth_id==47 && t->session==2 && t->integrity_rid==0x3000);
    EXPECT(t->type==1 && !t->imp_level && !t->flags && t->owner_pid==92);
    EXPECT(t->elevation_type==2);
    EXPECT(shz_token_bind_subject(&target_process,48,2,0x2000)==0);
    EXPECT(((shz_token_info *)target_process.token->u.token.t)->elevation_type==1);
    EXPECT(shz_token_integrity(&process,0x2000)==0x2000);
    t->integrity_rid=0x1000;
    EXPECT(shz_token_integrity(&process,0x2000)==0x1000);
    token_snapshot s=snapshot(process.token);
    EXPECT(shz_token_bind_subject(&process,99,3,0x4000)==STATUS_ACCESS_DENIED);
    EXPECT(unchanged(process.token,s));
    target_process.teardown=1;
    EXPECT(shz_token_bind_subject(&target_process,99,1,0x2000)==STATUS_INVALID_HANDLE);
    EXPECT(((shz_token_info *)target_process.token->u.token.t)->elevation_type==1); return 1;
}
static int cross_subject_token_denials(void) {
    uint64_t output=0xa5a5a5a5a5a5a5a5ull;
    uint32_t ph=put_handle(target_process.object,0x1000),th=put_handle(target_thread.object,0x880);
    kobject_t *tok=imp_token(); uint32_t h=put_handle(tok,4); ob_ref(tok); target_thread.impersonation=tok;
    token_snapshot s=snapshot(tok); unsigned refs=target_process.object->refs,threadrefs=target_thread.object->refs;
    deny_other_subject=1;
    EXPECT(token_call(1,ph,8,ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(!target_process.token && output==0xa5a5a5a5a5a5a5a5ull && target_process.object->refs==refs);
    EXPECT(token_call(2,th,8,ptr(&output))==STATUS_ACCESS_DENIED);
    EXPECT(token_call(6,th,h,0)==STATUS_ACCESS_DENIED);
    EXPECT(target_thread.object->refs==threadrefs && target_thread.impersonation==tok && unchanged(tok,s));
    deny_other_subject=0; return 1;
}
static int frontend_desired_access_and_old_backend(void) {
    uint32_t h=token_handle(0xa); HANDLE output=(HANDLE)(uintptr_t)0xa5a5a5a5;
    ULONG qos[4]={16,2,0,0}; SHZ_OBJECT_ATTRIBUTES oa={.SecurityQualityOfService=qos};
    EXPECT(NtDuplicateToken((HANDLE)(uintptr_t)h,8,&oa,0,2,&output)==0);
    EXPECT(entries[(uintptr_t)output/4-1].access==8);
    token_snapshot s=snapshot(process.token); output=(HANDLE)(uintptr_t)0xa5a5a5a5;
    EXPECT(NtDuplicateToken((HANDLE)(uintptr_t)h,0xf01ff,&oa,0,2,&output)==STATUS_ACCESS_DENIED);
    EXPECT((uintptr_t)output==0xa5a5a5a5 && unchanged(process.token,s));
    model_old_backend=1;
    EXPECT(NtDuplicateToken((HANDLE)(uintptr_t)h,8,&oa,0,2,&output)==STATUS_INVALID_PARAMETER);
    model_old_backend=0;
    EXPECT((uintptr_t)output==0xa5a5a5a5 && unchanged(process.token,s));
    EXPECT(NtDuplicateToken((HANDLE)(uintptr_t)h,8,&oa,1,2,&output)==(int32_t)0xc00000bb);
    oa.SecurityDescriptor=&s;
    EXPECT(NtDuplicateToken((HANDLE)(uintptr_t)h,8,&oa,0,2,&output)==(int32_t)0xc00000bb);
    oa.SecurityDescriptor=NULL; qos[1]=4;
    EXPECT(NtDuplicateToken((HANDLE)(uintptr_t)h,8,&oa,0,2,&output)==STATUS_INVALID_PARAMETER);
    EXPECT((uintptr_t)output==0xa5a5a5a5 && unchanged(process.token,s)); return 1;
}
int main(void) {
    const struct {const char *name; int (*run)(void);} cases[]={
        {"query-rights",query_rights},{"mutation-denial",mutation_denial},{"mutation-allowed",mutation_allowed},
        {"duplicate-denial",duplicate_denial},{"duplicate-legacy-no-amplification",duplicate_legacy_no_amplification},
        {"duplicate-explicit-rights",duplicate_explicit_rights},{"duplicate-access-ceiling",duplicate_requested_access_ceiling},
        {"duplicate-invalid-packing",duplicate_invalid_packing},{"duplicate-failure-cleanup",duplicate_failure_cleanup},
        {"token-masks-impersonation-level",token_masks_and_impersonation_level},
        {"impersonation-token-denial",impersonation_token_denial},{"impersonation-thread-denial",impersonation_thread_denial},
        {"impersonation-allowed-revert",impersonation_allowed_and_revert},
        {"open-process-denial",open_process_denial},{"open-process-allowed-cleanup",open_process_allowed_and_copy_cleanup},
        {"open-thread-denial",open_thread_denial},{"open-thread-allowed-cleanup",open_thread_allowed_and_copy_cleanup},
        {"descriptor-query-denial",descriptor_query_denial},{"descriptor-set-denial",descriptor_set_denial},
        {"descriptor-allowed-cleanup",descriptor_allowed_and_copy_cleanup},{"invalid-dispatch",invalid_dispatch},
        {"trusted-bind-auth-boundary",trusted_binding_and_auth_boundary},
        {"frontend-desired-old-backend",frontend_desired_access_and_old_backend},
        {"cross-subject-token-denials",cross_subject_token_denials},
        {"centralized-handle-admission",centralized_handle_admission}
    };
    for(unsigned i=0;i<sizeof cases/sizeof *cases;++i) {
        init_case(); int passed=cases[i].run(); finish_case();
        printf("%s %s\n",passed?"PASS":"FAIL",cases[i].name); if(!passed) ++failures;
    }
    printf("production token/security rights: %u assertions, %u cases, %u failures\n",assertions,(unsigned)(sizeof cases/sizeof *cases),failures);
    return failures ? 1 : 0;
}
