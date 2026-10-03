/* SPDX-License-Identifier: GPL-2.0-only
 * Complete production authority dispatcher, with hardware/loader boundary adapters.
 */
#include "../kernel64/fs.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static uint64_t host_irq(void){return 0;}
static void host_restore(uint64_t f){(void)f;}
#define irq_save host_irq
#define irq_restore host_restore
static void host_secret_clear(void *,size_t);
#define shz_secret_clear host_secret_clear
#include "../kernel64/sysk32_auth.c"
#undef shz_secret_clear
extern void shz_secret_clear(void *,size_t);
static process_t children[8];static thread_t threads[8];
static fsnode_t root,users,profile;
static int child_count,resumed,killed,output_fault,bind_fail,input_fault,request_wipes;
static void host_secret_clear(void *p,size_t n){
    shz_secret_clear(p,n);
    for(size_t i=0;i<n;i++)assert(!((unsigned char *)p)[i]);
    if(n==sizeof(shz_auth_request))request_wipes++;
}
process_t *process_slot(unsigned i){(void)i;return 0;}
void reg_lock(void){}
void reg_unlock(void){}
void mutex_init(kmutex_t *m){memset(m,0,sizeof *m);}
void mutex_lock(kmutex_t *m){(void)m;}
void mutex_unlock(kmutex_t *m){(void)m;}
void krandom_get(void *b,size_t n){static unsigned seed=0;uint8_t *p=b;while(n--)*p++=(uint8_t)++seed;}
uint64_t ticks_now(void){return 1000;}
int copy_from_user(process_t *p,void *d,uint64_t s,uint64_t n){(void)p;if(!s)return -1;memcpy(d,(void *)(uintptr_t)s,input_fault?n/2:n);return input_fault?-1:0;}
int copy_to_user(process_t *p,uint64_t d,const void *s,uint64_t n){(void)p;if(!d||output_fault)return -1;memcpy((void *)(uintptr_t)d,s,n);return 0;}
int shz_token_registry_context(process_t *p){(void)p;return 1;}
uint32_t shz_token_integrity(process_t *p,uint32_t fallback){(void)p;return fallback;}
int32_t shz_token_bind_subject(process_t *p,uint64_t a,uint32_t s,uint32_t i){(void)s;(void)i;if(!a)return STATUS_INVALID_PARAMETER;if(bind_fail)return STATUS_NO_MEMORY;assert(!p->token);return 0;}
process_t *process_by_pid(int pid){for(int i=0;i<child_count;i++)if(children[i].pid==pid)return &children[i];return 0;}
fsnode_t *fs_root_of(char c){return c=='C'?&root:0;}
fsnode_t *fs_lookup(const char *p){if(!strcmp(p,"C:\\Users"))return users.parent?&users:0;return 0;}
fsnode_t *fs_create(const char *p,int dir,int *created){(void)dir;if(created)*created=1;if(!strcmp(p,"C:\\Users")){users.parent=&root;return &users;}profile.parent=&users;return &profile;}
int32_t ldr_create_process_ex(process_t *parent,const char *image,const char *cmd,const char *cwd,const ldr_create_ex_t *ex,process_t **p,thread_t **t){
    int st;char env_ascii[512];assert(!parent);assert(image[0]&&cmd[0]&&cwd[0]);assert(ex->suspended);assert(ex->env&&!ex->use_std_handles);
    const shz_subject *expected=ex->prepare_ctx;
    assert(ex->env_chars<512&&ex->env_chars>2&&!ex->env[ex->env_chars-1]&&!ex->env[ex->env_chars-2]);
    for(unsigned i=0;i<ex->env_chars;i++){assert(ex->env[i]<128);env_ascii[i]=(char)ex->env[i];}
    int profile_found=0,temp_found=0;
    for(unsigned i=0;i+1<ex->env_chars;i+=(unsigned)strlen(env_ascii+i)+1){
        if(!strncmp(env_ascii+i,"USERPROFILE=",12)){assert(!strcmp(env_ascii+i+12,cwd));profile_found=1;}
        if(!strncmp(env_ascii+i,"TEMP=",5)){assert(!strncmp(env_ascii+i+5,cwd,strlen(cwd)));temp_found=1;}
    }
    assert(profile_found&&temp_found);
    assert(expected->uid?!strcmp(cwd,"C:\\Users\\1000"):!strcmp(cwd,"C:\\"));
    assert(child_count<8);*p=&children[child_count];*t=&threads[child_count];memset(*p,0,sizeof **p);memset(*t,0,sizeof **t);
    (*p)->used=1;(*p)->pid=100+child_count;(*p)->create_tick=100+child_count;(*t)->proc=*p;(*t)->suspend_count=1;
    child_count++;st=ex->prepare(*p,ex->prepare_ctx);return st;
}
void process_terminate(process_t *p,int64_t c,int f){(void)c;(void)f;p->terminated=1;killed++;}
void thread_resume(thread_t *t){if(!t->proc->terminated)resumed++;}
void thread_creator_release(thread_t *t){(void)t;}
static int call(process_t *p,uint64_t op,shz_auth_request *req,shz_auth_reply *out){return shz_auth_syscall(p,op,(uint64_t)(uintptr_t)req,req?sizeof *req:sizeof *out,(uint64_t)(uintptr_t)out);}
int main(void){
    process_t caller={0},broker={0},inherited={0};shz_auth_request req={0};shz_auth_reply out={0};shz_subject s;
    caller.used=broker.used=inherited.used=1;caller.pid=4;broker.pid=8;inherited.pid=12;
    req.version=1;req.roles=SHZ_ROLE_ADMIN;req.password_bytes=13;strcpy(req.user,"admin");memcpy(req.password,"correct horse",13);
    input_fault=1;assert(call(&caller,SHZ_AUTH_REGISTER,&req,&out)==STATUS_ACCESS_VIOLATION);assert(request_wipes==1);input_fault=0;
    assert(call(&caller,SHZ_AUTH_REGISTER,&req,&out)==STATUS_ACCESS_DENIED);
    assert(!shz_auth_bootstrap_prepare(&broker,0));
    assert(!shz_auth_process_access(&caller,&broker));
    req.roles=0;
    assert(call(&broker,SHZ_AUTH_REGISTER,&req,&out)==STATUS_ACCESS_DENIED);
    assert(!call(&broker,SHZ_AUTH_QUERY,0,&out));assert(!out.accounts);
    req.roles=SHZ_ROLE_ADMIN;
    assert(!call(&broker,SHZ_AUTH_REGISTER,&req,&out));
    assert(call(&broker,SHZ_AUTH_REGISTER,&req,&out)==STATUS_ACCESS_DENIED);
    assert(!call(&caller,SHZ_AUTH_QUERY,0,&out));assert(out.accounts==1&&out.flags==SHZ_AUTH_VOLATILE&&!out.subject.uid);
    req.roles=0;strcpy(req.image,"C:\\SHZ\\SYS64\\SHZDESK.EXE");strcpy(req.command,"SHZDESK.EXE");
    req.reserved=1;assert(call(&caller,SHZ_AUTH_LOGIN_LAUNCH,&req,&out)==STATUS_INVALID_PARAMETER);assert(!child_count);req.reserved=0;
    assert(!call(&caller,SHZ_AUTH_LOGIN_LAUNCH,&req,&out));assert(resumed==1&&out.subject.uid==1000&&out.subject.integrity==0x2000);
    assert(shz_auth_gui_take_entry(&children[0]));assert(!shz_auth_gui_take_entry(&children[0]));
    assert(!shz_auth_process_access(&caller,&children[0]));assert(!subject(&caller).uid);
    assert(!shz_auth_inherit(&children[0],&inherited));s=subject(&inherited);assert(s.auth_id==out.subject.auth_id);
    assert(!find(&inherited,0)->bootstrap);
    assert(!shz_auth_syscall_allowed(&children[0],SYS_NtLoadDriver));
    assert(!call(&caller,SHZ_AUTH_ELEVATE_LAUNCH,&req,&out));assert(out.subject.integrity==0x3000&&resumed==2);
    assert(shz_auth_syscall_allowed(&children[1],SYS_NtLoadDriver));assert(!shz_auth_process_access(&children[0],&children[1]));
    req.password_bytes=0;req.user[0]=0;
    assert(!call(&children[0],SHZ_AUTH_SANDBOX_LAUNCH,&req,&out));assert(out.subject.flags&SHZ_SUBJECT_SANDBOX);
    assert(call(&children[2],SHZ_AUTH_ELEVATE_LAUNCH,&req,&out)==STATUS_ACCESS_DENIED);
    assert(!shz_auth_syscall_allowed(&children[2],SYS_NtShzBlkWrite));
    strcpy(req.user,"admin");req.password_bytes=13;output_fault=1;
    assert(call(&caller,SHZ_AUTH_ELEVATE_LAUNCH,&req,&out)==STATUS_ACCESS_VIOLATION);assert(killed==1&&resumed==3);output_fault=0;
    assert(!shz_auth_gui_take_entry(&children[3]));
    {char mixed[64]="gLoBaL\\private";assert(shz_auth_object_name(&children[0],mixed,sizeof mixed)==STATUS_NOT_SUPPORTED);assert(!strcmp(mixed,"gLoBaL\\private"));}
    inherited.pid=16;s=subject(&inherited);assert(!s.uid);assert(!find(&inherited,0));
    shz_auth_process_gone(&children[0]);assert(!find(&children[0],0));
    bind_fail=1;assert(shz_auth_inherit(&children[1],&inherited)==STATUS_NO_MEMORY);
    puts("auth kernel: trusted enrollment, fresh launch, no parent upgrade, sandbox, stale IDs and failed copyout PASS");
}
