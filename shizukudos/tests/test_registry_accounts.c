/* SPDX-License-Identifier: GPL-2.0-only
 * Complete production registry, syscall, authority and object-manager bodies.
 * Exact token binding/integrity bodies inserted by the runner. Only IRQ, heap,
 * user memory, time, scheduler and loader boundaries are host adapters.
 */
#include "../kernel64/fs.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <pthread.h>
#include <string.h>
static uint64_t host_irq(void){return 0;}
static void host_restore(uint64_t f){(void)f;}
static long host_hcall(hcreg_t op,hcreg_t a,hcreg_t b,hcreg_t *out){(void)op;(void)a;(void)b;if(out)*out=100;return 0;}
static uint64_t host_time(void){return 0;}
#define irq_save host_irq
#define irq_restore host_restore
#define shz_hcall host_hcall
#define shz_time_ns host_time
/* @PRODUCTION_TOKEN_BINDING@ */
#include "../kernel64/sysk32_auth.c"
#include "../kernel64/registry.c"
#include "../kernel64/sysreg.c"
#include "../kernel64/objects.c"
static uint64_t args[12];
static process_t ps[8];static handle_entry_t slots[8][64];
static process_t *lower_during_copy;
static thread_t active_thread;
static thread_t *current_thread;
static int activation_allocation,allocation_fail_after;
static void allocation_barrier(void);
void *kmalloc(size_t n){return malloc(n);}
void *kzalloc(size_t n){if(allocation_fail_after&&!--allocation_fail_after)return 0;if(activation_allocation){activation_allocation=0;allocation_barrier();}return calloc(1,n);}
void kfree(void *p){free(p);}
void kpanic(const char *fmt,...){va_list a;va_start(a,fmt);vfprintf(stderr,fmt,a);va_end(a);abort();}
static pthread_mutex_t host_registry=PTHREAD_MUTEX_INITIALIZER,host_authority=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t barrier=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t attempted=PTHREAD_COND_INITIALIZER;
static int watch_enrollment,first_lock;
static pthread_t enrollment_thread;
void mutex_init(kmutex_t *m){memset(m,0,sizeof *m);}
void mutex_lock(kmutex_t *m){
 if(watch_enrollment&&pthread_equal(pthread_self(),enrollment_thread)){
  assert(!pthread_mutex_lock(&barrier));if(!first_lock){first_lock=m==&reg_mutex?1:2;assert(!pthread_cond_signal(&attempted));}assert(!pthread_mutex_unlock(&barrier));
 }
 assert(!pthread_mutex_lock(m==&reg_mutex?&host_registry:&host_authority));
}
void mutex_unlock(kmutex_t *m){assert(!pthread_mutex_unlock(m==&reg_mutex?&host_registry:&host_authority));}
void krandom_get(void *p,size_t n){static unsigned v;unsigned char *b=p;while(n--)*b++=(unsigned char)++v;}
uint64_t ticks_now(void){return 1000;}
int copy_from_user(process_t *p,void *d,uint64_t s,uint64_t n){(void)p;if(!s)return -1;memcpy(d,(void *)(uintptr_t)s,n);if(lower_during_copy){((shz_token_info *)lower_during_copy->token->u.token.t)->integrity_rid=0x1000;lower_during_copy=0;}return 0;}
int copy_to_user(process_t *p,uint64_t d,const void *s,uint64_t n){(void)p;if(!d)return -1;memcpy((void *)(uintptr_t)d,s,n);return 0;}
int64_t stack_arg(process_t *p,struct regs *r,unsigned n){(void)p;(void)r;assert(n<12);return (int64_t)args[n];}
process_t *process_slot(unsigned i){(void)i;return 0;}
process_t *process_by_pid(int pid){for(unsigned i=0;i<8;i++)if(ps[i].pid==pid)return ps+i;return 0;}
thread_t *thread_current(void){return current_thread;}
void thread_wake(thread_t *t){(void)t;}
void net_socket_handle_closing(kobject_t *o){(void)o;}
void ntdrv_device_handle_closing(kobject_t *o){(void)o;}
fsnode_t *fs_root_of(char c){(void)c;return 0;}
fsnode_t *fs_lookup(const char *p){(void)p;return 0;}
fsnode_t *fs_create(const char *p,int d,int *made){(void)p;(void)d;(void)made;return 0;}
int32_t ldr_create_process_ex(process_t *p,const char *i,const char *c,const char *w,const ldr_create_ex_t *e,process_t **o,thread_t **t){(void)p;(void)i;(void)c;(void)w;(void)e;(void)o;(void)t;return STATUS_NOT_SUPPORTED;}
void process_terminate(process_t *p,int64_t s,int f){(void)p;(void)s;(void)f;}
void thread_resume(thread_t *t){(void)t;}
void thread_creator_release(thread_t *t){(void)t;}
static uint64_t va(const void *p){return (uint64_t)(uintptr_t)p;}
static struct ustr wide(const char *s,uint16_t *buf){unsigned n=0;while(s[n]){buf[n]=(unsigned char)s[n];n++;}return (struct ustr){n*2,n*2,0,va(buf)};}
static int32_t route(process_t *p,uint32_t num,uint64_t a,uint64_t b,uint64_t c,uint64_t d){struct regs r={0};if(!shz_auth_syscall_allowed(p,num))return STATUS_ACCESS_DENIED;return sys_ext_registry(p,&r,num,a,b,c,d);}
static int32_t key(process_t *p,const char *path,uint64_t root,uint32_t rights,int create,uint64_t *h){uint16_t *text=malloc(strlen(path)*2+2);assert(text);struct ustr name=wide(path,text);struct objattr oa={sizeof oa,0,root,va(&name),0,0,0,0};memset(args,0,sizeof args);int32_t st=route(p,create?SYS_NtCreateKey:SYS_NtOpenKey,va(h),rights,va(&oa),0);free(text);return st;}
static int32_t set(process_t *p,uint64_t h,const char *value,uint32_t data){uint16_t text[64];struct ustr n=wide(value,text);args[5]=va(&data);args[6]=4;return route(p,SYS_NtSetValueKey,h,va(&n),0,REG_DWORD);}
static uint32_t last_read;
static int32_t get(process_t *p,uint64_t h,const char *value){uint16_t text[64];struct ustr n=wide(value,text);unsigned char out[128];uint32_t len=0;args[5]=sizeof out;args[6]=va(&len);int32_t st=route(p,SYS_NtQueryValueKey,h,va(&n),2,va(out));if(!st){assert(len==16);memcpy(&last_read,out+12,4);}return st;}
static int32_t auth(process_t *p,uint32_t op,shz_auth_request *req,shz_auth_reply *reply){return shz_auth_syscall(p,op,va(req),req?sizeof *req:sizeof *reply,va(reply));}
static void setup(void){for(unsigned i=0;i<8;i++){ps[i].used=1;ps[i].pid=100+i;ps[i].create_tick=100+i;ps[i].object=ob_create(OB_PROCESS,0);ps[i].object->u.proc.p=ps+i;ps[i].handles=slots[i];ps[i].handle_cap=64;}}
static void enroll(void){shz_auth_request req={0};shz_auth_reply reply;shz_subject s;req.version=SHZ_AUTH_VERSION;strcpy(req.user,"admin");req.password_bytes=13;memcpy(req.password,"correct horse",13);req.roles=SHZ_ROLE_ADMIN;assert(!shz_auth_bootstrap_prepare(ps+1,0));assert(!auth(ps+1,SHZ_AUTH_REGISTER,&req,&reply));assert(!shz_account_elevate(&authority,"admin","correct horse",13,1000,&s));assert(!bind(ps+4,&s));req.roles=0;strcpy(req.user,"user");assert(!auth(ps+4,SHZ_AUTH_REGISTER,&req,&reply));assert(!shz_account_login(&authority,"admin","correct horse",13,1000,&s));assert(!bind(ps+2,&s));assert(!shz_account_login(&authority,"user","correct horse",13,1000,&s));assert(!bind(ps+3,&s));s.uid=0;s.session=88;s.roles=0;s.integrity=0x1000;s.flags=SHZ_SUBJECT_SANDBOX;s.auth_id=88;assert(!bind(ps+5,&s));}
#define HKU "\\REGISTRY\\USER\\S-1-5-21-2210311251-3305482031-1094512843-"
static uint64_t own(process_t *p,const char *sid){char path[256];uint64_t h=0;snprintf(path,sizeof path,HKU "%s\\Software\\Settings",sid);assert(!key(p,path,0,KEY_READ_MASK|KEY_WRITE_MASK|ACC_DELETE,1,&h));assert(h);return h;}
static uint64_t borrowed_own(process_t *p){uint64_t admin=own(ps+4,"1000");uint32_t h;assert(!set(ps+4,admin,"Setting",7));assert(!handle_insert(p,ps[4].handles[admin/4-1].obj,KEY_ALL_ACCESS_MASK,&h));return h;}
static void cleanup(void){for(unsigned i=0;i<8;i++){handles_close_all(ps+i);if(ps[i].token)ob_deref(ps[i].token);ob_deref(ps[i].object);shz_auth_process_gone(ps+i);}}
static uint64_t legacy;
static uint64_t legacy_iosb[2];
static void test_case(const char *test){uint64_t h=0;
 if(!strcmp(test,"own")){h=own(ps+2,"1000");assert(!set(ps+2,h,"Setting",7));assert(!get(ps+2,h,"Setting"));assert(last_read==7);assert(!key(ps+3,HKU "1001\\Environment",0,ACC_MAXIMUM_ALLOWED,0,&h));assert(ps[3].handles[h/4-1].access==KEY_ALL_ACCESS_MASK);puts("own settings and authoritative hive provisioning PASS");}
 else if(!strcmp(test,"cross")){h=own(ps+4,"1000");assert(!set(ps+4,h,"secret",42));uint64_t x=0;assert(key(ps+3,HKU "1000\\Software\\Settings",0,KEY_READ_MASK,0,&x)==STATUS_ACCESS_DENIED);assert(!x);uint32_t borrowed;assert(!handle_insert(ps+3,ps[4].handles[h/4-1].obj,KEY_ALL_ACCESS_MASK,&borrowed));assert(get(ps+3,borrowed,"secret")==STATUS_ACCESS_DENIED);unsigned char out[128];uint32_t len=0;args[5]=va(&len);for(unsigned cls=0;cls<3;cls++)assert(route(ps+3,SYS_NtQueryObject,borrowed,cls,va(out),sizeof out)==STATUS_ACCESS_DENIED);assert(route(ps+3,SYS_NtFlushKey,borrowed,0,0,0)==STATUS_ACCESS_DENIED);assert(key(ps+3,"Child",borrowed,KEY_READ_MASK,1,&x)==STATUS_ACCESS_DENIED);assert(set(ps+3,borrowed,"secret",99)==STATUS_ACCESS_DENIED);assert(route(ps+3,SYS_NtDeleteKey,borrowed,0,0,0)==STATUS_ACCESS_DENIED);args[5]=sizeof out;args[6]=va(&len);assert(route(ps+3,SYS_NtEnumerateKey,borrowed,0,0,va(out))==STATUS_ACCESS_DENIED);assert(route(ps+3,SYS_NtEnumerateValueKey,borrowed,0,2,va(out))==STATUS_ACCESS_DENIED);args[5]=va(&len);assert(route(ps+3,SYS_NtQueryKey,borrowed,3,va(out),sizeof out)==STATUS_ACCESS_DENIED);uint64_t parent=0;assert(!key(ps+4,"\\REGISTRY\\USER",0,KEY_ALL_ACCESS_MASK,0,&parent));assert(!handle_insert(ps+3,ps[4].handles[parent/4-1].obj,KEY_ALL_ACCESS_MASK,&borrowed));assert(key(ps+3,"S-1-5-21-2210311251-3305482031-1094512843-1001",borrowed,KEY_READ_MASK,1,&x)==STATUS_ACCESS_DENIED);puts("cross SID and transferred handles/metadata/relative routes refused PASS");}
 else if(!strcmp(test,"create")){uint32_t before;reg_lock();before=g_bytes;reg_unlock();assert(key(ps+3,HKU "1000\\MustNotExist\\Child",0,KEY_READ_MASK,1,&h)==STATUS_ACCESS_DENIED);assert(g_bytes==before);assert(key(ps+3,"\\REGISTRY\\USER",0,KEY_READ_MASK,0,&h)==STATUS_ACCESS_DENIED);assert(key(ps+3,"\\REGISTRY",0,KEY_READ_MASK,0,&h)==STATUS_ACCESS_DENIED);puts("denied create has no tree/allocation effect; parent roots refused PASS");}
 else if(!strcmp(test,"machine")){assert(key(ps+2,"\\REGISTRY\\MACHINE\\SOFTWARE\\Denied",0,KEY_READ_MASK,1,&h)==STATUS_ACCESS_DENIED);assert(key(ps+2,"\\REGISTRY\\MACHINE\\SOFTWARE",0,KEY_WRITE_MASK,0,&h)==STATUS_ACCESS_DENIED);assert(!key(ps+2,"\\REGISTRY\\MACHINE\\SOFTWARE",0,KEY_READ_MASK,0,&h));assert(!key(ps+2,"\\REGISTRY\\MACHINE\\SOFTWARE",0,KEY_READ_MASK,1,&h));assert(!key(ps+2,"\\REGISTRY\\MACHINE\\SOFTWARE",0,ACC_MAXIMUM_ALLOWED,0,&h));assert(ps[2].handles[h/4-1].access==KEY_READ_MASK);assert(set(ps+2,h,"Denied",9)==STATUS_ACCESS_DENIED);assert(!key(ps+4,"\\REGISTRY\\MACHINE\\SOFTWARE\\Admin",0,KEY_ALL_ACCESS_MASK,1,&h));assert(!set(ps+4,h,"Allowed",1));uint32_t borrowed;assert(!handle_insert(ps+2,ps[4].handles[h/4-1].obj,KEY_ALL_ACCESS_MASK,&borrowed));assert(set(ps+2,borrowed,"Allowed",9)==STATUS_ACCESS_DENIED);assert(!get(ps+2,borrowed,"Allowed"));assert(last_read==1);assert(key(ps+4,HKU "1015\\Invented",0,KEY_READ_MASK,1,&h)==STATUS_ACCESS_DENIED);puts("Machine ordinary read/write separation and explicit elevation PASS");}
 else if(!strcmp(test,"legacy")){uint32_t borrowed;assert(!handle_insert(ps+3,ps[0].handles[legacy/4-1].obj,KEY_ALL_ACCESS_MASK,&borrowed));assert(get(ps+3,borrowed,"secret")==STATUS_ACCESS_DENIED);assert(get(ps,legacy,"secret")==STATUS_ACCESS_DENIED);h=own(ps+3,"1001");assert((int32_t)legacy_iosb[0]==STATUS_ACCESS_DENIED);assert(get(ps+3,h,"secret")==STATUS_OBJECT_NAME_NOT_FOUND);assert(key(ps+3,HKU "1001\\Software\\Old",0,KEY_READ_MASK,0,&h)==STATUS_OBJECT_NAME_NOT_FOUND);assert(get(ps+3,borrowed,"secret")==STATUS_ACCESS_DENIED);assert(route(ps+3,SYS_NtDeleteKey,borrowed,0,0,0)==STATUS_ACCESS_DENIED);assert(route(ps+3,SYS_NtFlushKey,borrowed,0,0,0)==STATUS_ACCESS_DENIED);assert(!((regkey_t *)ps[0].handles[legacy/4-1].obj->u.key.node)->parent);assert(!((regkey_t *)ps[0].handles[legacy/4-1].obj->u.key.node)->values);puts("legacy RID1001 tree and retained handles cannot become enrolled UID1001 PASS");}
 else if(!strcmp(test,"integrity")){h=borrowed_own(ps+2);lower_during_copy=ps+2;assert(set(ps+2,h,"Setting",9)==STATUS_ACCESS_DENIED);assert(get(ps+2,h,"Setting")==STATUS_ACCESS_DENIED);assert(key(ps+2,HKU "1000\\Other",0,KEY_READ_MASK,1,&h)==STATUS_ACCESS_DENIED);puts("lowered primary integrity rechecked after input copy and on retained handles PASS");}
 else if(!strcmp(test,"unbound")){h=borrowed_own(ps+2);uint32_t x;assert(!handle_insert(ps+5,ps[2].handles[h/4-1].obj,KEY_ALL_ACCESS_MASK,&x));assert(get(ps+5,x,"anything")==STATUS_ACCESS_DENIED);assert(key(ps,HKU "1001\\Software",0,KEY_READ_MASK,0,&h)==STATUS_ACCESS_DENIED);assert(key(ps+5,"\\REGISTRY\\MACHINE",0,KEY_READ_MASK,0,&h)==STATUS_ACCESS_DENIED);assert(!shz_auth_process_pending(ps+2));assert(get(ps+2,h,"anything")==STATUS_ACCESS_DENIED);shz_auth_process_ready(ps+2);puts("anonymous, sandbox and pending subjects fail closed PASS");}
 else if(!strcmp(test,"notify")){h=borrowed_own(ps+2);uint64_t iosb[2]={0};args[5]=va(iosb);args[6]=REG_NOTIFY_CHANGE_LAST_SET;args[7]=0;args[8]=0;args[9]=0;args[10]=1;assert(route(ps+2,SYS_NtNotifyChangeKey,h,0,0,0)==STATUS_PENDING);((shz_token_info *)ps[2].token->u.token.t)->integrity_rid=0x1000;uint64_t admin=0;assert(!key(ps+4,HKU "1000\\Software\\Settings",0,KEY_WRITE_MASK,0,&admin));assert(!set(ps+4,admin,"Changed",1));assert((int32_t)iosb[0]==STATUS_ACCESS_DENIED);puts("retained notification rechecks current subject before completion PASS");}
 else if(!strcmp(test,"thread")){h=borrowed_own(ps+2);active_thread.proc=ps+2;current_thread=&active_thread;shz_token_info original=*(shz_token_info *)ps[2].token->u.token.t;original.type=2;original.imp_level=2;kobject_t *imp=token_new(&original,ps[2].pid);active_thread.impersonation=imp;assert(!get(ps+2,h,"Setting"));shz_token_info *info=imp->u.token.t;
 for(unsigned row=0;row<5;row++){*info=original;if(row==0)info->integrity_rid=0x1000;if(row==1)info->auth_id++;if(row==2)info->session++;if(row==3)info->imp_level=1;if(row==4)info->type=1;assert(get(ps+2,h,"Setting")==STATUS_ACCESS_DENIED);assert(set(ps+2,h,"Setting",9)==STATUS_ACCESS_DENIED);assert(key(ps+2,HKU "1000\\ThreadDenied",0,KEY_READ_MASK,1,&h)==STATUS_ACCESS_DENIED);}
 active_thread.impersonation=0;current_thread=0;ob_deref(imp);puts("direct Nt routes reject lowered/different/unsupported thread tokens PASS");}
 else if(!strcmp(test,"stale_notify")){h=borrowed_own(ps+2);uint64_t iosb[2]={0};args[5]=va(iosb);args[6]=REG_NOTIFY_CHANGE_LAST_SET;args[10]=1;assert(route(ps+2,SYS_NtNotifyChangeKey,h,0,0,0)==STATUS_PENDING);ps[2].create_tick++;uint64_t admin=0;assert(!key(ps+4,HKU "1000\\Software\\Settings",0,KEY_WRITE_MASK,0,&admin));assert(!set(ps+4,admin,"Changed",1));assert((int32_t)iosb[0]==STATUS_PENDING);puts("recycled process generation never receives old notification copyout PASS");}
 else if(!strcmp(test,"provision")){regkey_t *old=ps[0].handles[legacy/4-1].obj->u.key.node;uint32_t bytes=g_bytes;uint64_t x=0;
 for(int fail=1;fail<=3;fail++){allocation_fail_after=fail;assert(key(ps+3,HKU "1001\\Environment",0,KEY_READ_MASK,0,&x)==STATUS_NO_MEMORY);assert(!allocation_fail_after);assert(!x);assert(g_bytes==bytes);assert(old->parent&&!(old->flags&RK_DELETED));uint16_t text[16];struct ustr n=wide("secret",text);regval_t *v=reg_find_value(old,text,n.length/2);assert(v&&v->data_len==4);uint32_t data;memcpy(&data,regval_data(v),4);assert(data==42);}
 assert(!key(ps+3,HKU "1001\\Environment",0,KEY_READ_MASK,0,&x));assert((int32_t)legacy_iosb[0]==STATUS_ACCESS_DENIED);puts("all three account-hive allocation failures leave legacy/tree/quota unchanged PASS");}
 else if(!strcmp(test,"path")){char path[2048];strcpy(path,HKU "1001");for(unsigned i=0;i<REG_MAX_DEPTH;i++)strcat(path,"\\a");uint32_t bytes=g_bytes;uint64_t x=0;assert(key(ps+3,path,0,KEY_READ_MASK,1,&x)==STATUS_INVALID_PARAMETER);assert(!x&&g_bytes==bytes);assert(key(ps+3,HKU "1001\\Bad\\\\",0,KEY_READ_MASK,1,&x)==STATUS_OBJECT_NAME_INVALID);assert(!x&&g_bytes==bytes);assert(!((regkey_t *)ps[0].handles[legacy/4-1].obj->u.key.node)->flags);puts("depth and malformed trailing components rejected before provisioning PASS");}
 else {abort();}
 cleanup();}
static void *register_worker(void *unused){
 (void)unused;shz_auth_request req={0};shz_auth_reply reply;req.version=SHZ_AUTH_VERSION;strcpy(req.user,"epochadmin");req.password_bytes=13;memcpy(req.password,"correct horse",13);req.roles=SHZ_ROLE_ADMIN;
 /* Publish the thread identity before entering the real dispatcher. */
 assert(!pthread_mutex_lock(&barrier));enrollment_thread=pthread_self();assert(!pthread_mutex_unlock(&barrier));
 assert(!auth(ps+1,SHZ_AUTH_REGISTER,&req,&reply));return 0;
}
static pthread_t activation_worker;
static void allocation_barrier(void){
 /* This adapter is entered from real key_alloc, after path authorization and
  * while the full native create handler still holds the registry mutex. */
 watch_enrollment=1;assert(!pthread_create(&activation_worker,0,register_worker,0));
 assert(!pthread_mutex_lock(&barrier));while(!first_lock)assert(!pthread_cond_wait(&attempted,&barrier));assert(first_lock==1);assert(!authority.count);assert(!pthread_mutex_unlock(&barrier));
}
static void activation_case(void){
 assert(!shz_auth_bootstrap_prepare(ps+1,0));assert(!authority.count);activation_allocation=1;
 uint64_t h=0;assert(!key(ps,HKU "1001\\Software\\EpochRace",0,KEY_ALL_ACCESS_MASK,1,&h));
 assert(!pthread_join(activation_worker,0));watch_enrollment=0;assert(authority.count==1);
 assert(get(ps,h,"anything")==STATUS_ACCESS_DENIED);assert(get(ps,legacy,"secret")==STATUS_ACCESS_DENIED);
 puts("enrollment activation waits for authorized native legacy create under registry lock PASS");cleanup();
}
int main(int argc,char **argv){
 setup();assert(!key(ps,HKU "1001\\Software\\Old",0,KEY_ALL_ACCESS_MASK,1,&legacy));assert(!set(ps,legacy,"secret",42));
 args[5]=va(legacy_iosb);args[6]=REG_NOTIFY_CHANGE_LAST_SET;args[10]=1;assert(route(ps,SYS_NtNotifyChangeKey,legacy,0,0,0)==STATUS_PENDING);
 int activation_failed=0;
 for(int i=1;i<argc;i++)if(!strcmp(argv[i],"activation")){fflush(0);pid_t child=fork();assert(child>=0);if(!child){activation_case();fflush(0);exit(0);}int status;assert(waitpid(child,&status,0)==child);int code=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);printf("CASE activation EXIT %d\n",code);fflush(0);activation_failed=code!=0;}
 enroll();
 int failed=activation_failed;assert(argc>1);
 for(int i=1;i<argc;i++){if(!strcmp(argv[i],"activation"))continue;fflush(0);pid_t child=fork();assert(child>=0);if(!child){test_case(argv[i]);fflush(0);exit(0);}
  int status;assert(waitpid(child,&status,0)==child);int code=WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status);printf("CASE %s EXIT %d\n",argv[i],code);fflush(0);failed|=code!=0;
 }
 cleanup();return failed;
}

