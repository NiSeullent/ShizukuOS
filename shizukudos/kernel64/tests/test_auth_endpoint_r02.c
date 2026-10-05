/* SPDX-License-Identifier: GPL-2.0-only
 * Host control for the production sysk32_auth.c endpoint broker (routing02):
 * channel epoch reset, binding_current, elevation ticket, store wall path/node
 * denial and credential wipe. Only IRQ/scheduler/loader/fs/user-copy boundary
 * adapters are stubbed; the account authority, PBKDF2 and broker are real.
 * Build: gcc -std=gnu11 -O2 -Wall -Wextra -Werror test_auth_endpoint_r02.c
 *        ../../accounts/{account,kdf,sha256}.c
 */
#include "../fs.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
static uint64_t host_irq(void){return 0;}
static void host_restore(uint64_t f){(void)f;}
#define irq_save host_irq
#define irq_restore host_restore
static void host_secret_clear(void *,size_t);
#define shz_secret_clear host_secret_clear
#include "../sysk32_auth.c"
#undef shz_secret_clear
extern void shz_secret_clear(void *,size_t);
static int request_wipes,input_fault;
static void host_secret_clear(void *p,size_t n){
    shz_secret_clear(p,n);
    for(size_t i=0;i<n;i++)assert(!((unsigned char *)p)[i]);   /* wipe really happened */
    if(n==sizeof(shz_auth_request))request_wipes++;
}
static uint64_t now=1000;
static fsnode_t vroot,nshz,nacc,nrealm,nsys;
process_t *process_slot(unsigned i){(void)i;return 0;}
void mutex_init(kmutex_t *m){memset(m,0,sizeof *m);}
void mutex_lock(kmutex_t *m){assert(!m->locked);m->locked=1;}
void mutex_unlock(kmutex_t *m){assert(m->locked);m->locked=0;}
void krandom_get(void *b,size_t n){static unsigned seed=0;uint8_t *p=b;while(n--)*p++=(uint8_t)++seed;}
uint64_t ticks_now(void){return now;}
int copy_from_user(process_t *p,void *d,uint64_t s,uint64_t n){(void)p;memcpy(d,(void *)(uintptr_t)s,input_fault?n/2:n);return input_fault?-1:0;}
int copy_to_user(process_t *p,uint64_t d,const void *s,uint64_t n){(void)p;memcpy((void *)(uintptr_t)d,s,n);return 0;}
uint32_t shz_token_integrity(process_t *p,uint32_t f){(void)p;return f;}
int32_t shz_token_bind_subject(process_t *p,uint64_t a,uint32_t s,uint32_t i){(void)s;(void)i;assert(a&&!p->token);p->token=(kobject_t *)p;return 0;}
process_t *process_by_pid(int pid){(void)pid;return 0;}
fsnode_t *fs_root_of(char c){return c=='C'?&vroot:0;}
fsnode_t *fs_lookup(const char *p){(void)p;return 0;}
fsnode_t *fs_create(const char *p,int d,int *c){(void)p;(void)d;(void)c;return 0;}
int32_t ldr_create_process_ex(process_t *a,const char *b,const char *c,const char *d,const ldr_create_ex_t *e,process_t **f,thread_t **g){(void)a;(void)b;(void)c;(void)d;(void)e;(void)f;(void)g;return STATUS_NO_MEMORY;}
void process_terminate(process_t *p,int64_t c,int f){(void)c;(void)f;p->terminated=1;}
void thread_resume(thread_t *t){if(--t->suspend_count==0)t->state=TS_READY;}
void thread_creator_release(thread_t *t){(void)t;}
static uint8_t disk[4096];static size_t disk_len;static int written;
static int s_load(void *c,void *b,size_t cap,size_t *n){(void)c;if(!written)return SHZ_AUTH_STORE_ABSENT;if(disk_len>cap)return -1;memcpy(b,disk,disk_len);*n=disk_len;return 0;}
static int s_commit(void *c,const void *b,size_t n){(void)c;if(n>sizeof disk)return -1;memcpy(disk,b,n);disk_len=n;written=1;return 0;}
static const shz_auth_store_ops ops={s_load,s_commit,0};
static process_t procs[8];static thread_t thrs[8];static kobject_t pobj[8],tobj[8];
static void mk(int i){process_t *p=&procs[i];thread_t *t=&thrs[i];memset(p,0,sizeof *p);memset(t,0,sizeof *t);
 p->used=1;p->pid=200+i;p->create_tick=7+i;p->pml4=0x1000;p->threads_alive=1;p->main_thread=t;p->object=&pobj[i];
 pobj[i].type=OB_PROCESS;pobj[i].refs=1;pobj[i].signaled=0;pobj[i].u.proc.p=p;
 t->proc=p;t->state=TS_NEW;t->suspend_count=1;t->creator_hold=1;t->tid=900+i;t->object=&tobj[i];
 tobj[i].type=OB_THREAD;tobj[i].refs=1;tobj[i].u.thr.t=t;tobj[i].u.thr.pid=(uint64_t)p->pid;tobj[i].u.thr.tid=t->tid;
 assert(!shz_auth_process_pending(p));}
/* prepare + bind + (optionally) publish a child of `owner` in slot i */
static shz_auth_endpoint_grant spawn(uint64_t owner,int i,int publish){
 shz_auth_endpoint_grant g;mk(i);assert(!shz_auth_endpoint_prepare(owner,SHZ_AUTH_EP_STANDARD,&g));
 assert(!shz_auth_endpoint_bind_child(&procs[i],&g));
 if(publish)assert(!shz_auth_endpoint_publish(&g,&procs[i],&thrs[i])&&thrs[i].state==TS_READY);
 return g;}
static const char *const store_spellings[]={
 "C:\\SHZ\\ACCOUNTS","c:\\shz\\accounts\\REALM","C:/SHZ/ACCOUNTS/REALM","c:/Shz/Accounts",
 "\\SHZ\\ACCOUNTS","/shz/accounts/realm","\\??\\C:\\SHZ\\ACCOUNTS\\REALM","\\\\?\\C:\\SHZ\\ACCOUNTS",
 "\\\\.\\C:\\SHZ\\ACCOUNTS","\\DosDevices\\C:\\shz\\accounts","\\GLOBAL??\\c:\\SHZ\\ACCOUNTS\\x",
 "D:\\SHZ\\ACCOUNTS\\REALM","C:SHZ\\ACCOUNTS","C:\\SHZ\\.\\ACCOUNTS","C:\\SHZ\\X\\..\\ACCOUNTS\\REALM",
 "C:\\\\SHZ\\\\\\ACCOUNTS","C:\\SHZ\\ACCOUNTS.","C:\\SHZ \\ACCOUNTS. .\\REALM","C:\\SHZ\\ACCOUNTS::$DATA",
 "C:\\X\\..\\..\\SHZ\\ACCOUNTS",0};
static void check_store_denied(process_t *p){
 for(unsigned i=0;store_spellings[i];i++){
  if(shz_auth_path_access(p,store_spellings[i],0)||shz_auth_path_access(p,store_spellings[i],1)){
   printf("store spelling not denied: %s\n",store_spellings[i]);assert(0);}}
 assert(!shz_auth_path_access(p,0,0));
 assert(!shz_auth_node_access(p,&nacc,0)&&!shz_auth_node_access(p,&nrealm,0)&&!shz_auth_node_access(p,&nrealm,1));
}
#define PW "correct horse",13
int main(void){
 process_t boot={0},anon={0},stale;shz_auth_request req;shz_auth_reply out={0};shz_subject s;uint64_t ep,ep2,bepoch;
 shz_auth_endpoint_grant g,g2;int wipes;
 const uint64_t A=(5ull<<32)|0x11,B=(5ull<<32)|0x12,C=(5ull<<32)|0x13;
 boot.used=1;boot.pid=4;anon.used=1;anon.pid=6;
 strcpy(vroot.name,"C:");strcpy(nshz.name,"shz");nshz.parent=&vroot;strcpy(nacc.name,"Accounts");nacc.parent=&nshz;
 strcpy(nrealm.name,"REALM");nrealm.parent=&nacc;strcpy(nsys.name,"SYS64");nsys.parent=&nshz;

 /* store wall: denied in anonymous development mode, node and path forms */
 assert(shz_auth_bridge_development_allowed());
 check_store_denied(&anon);
 assert(shz_auth_path_access(&anon,"C:\\SHZ\\ACCOUNTSX",1)&&shz_auth_path_access(&anon,"C:\\SHZ\\SYS64\\A.EXE",0));
 assert(shz_auth_path_access(&anon,"C:\\ACCOUNTS\\SHZ",0)&&shz_auth_path_access(&anon,"C:\\X\\SHZ\\ACCOUNTS",0));
 assert(shz_auth_node_access(&anon,&nshz,0)&&shz_auth_node_access(&anon,&nsys,0));

 /* realm + bootstrap admin through the syscall; every request copy is wiped */
 assert(!shz_auth_store_attach(&ops));assert(!shz_auth_bootstrap_prepare(&boot,0));
 memset(&req,0,sizeof req);req.version=1;req.roles=SHZ_ROLE_ADMIN;req.password_bytes=13;strcpy(req.user,"admin");memcpy(req.password,"correct horse",13);
 wipes=request_wipes;input_fault=1;
 assert(shz_auth_syscall(&boot,SHZ_AUTH_REGISTER,(uintptr_t)&req,sizeof req,(uintptr_t)&out)==STATUS_ACCESS_VIOLATION);
 input_fault=0;assert(request_wipes==wipes+1);
 req.version=2;assert(shz_auth_syscall(&boot,SHZ_AUTH_REGISTER,(uintptr_t)&req,sizeof req,(uintptr_t)&out)==STATUS_INVALID_PARAMETER);
 assert(request_wipes==wipes+2);req.version=1;
 assert(!shz_auth_syscall(&boot,SHZ_AUTH_REGISTER,(uintptr_t)&req,sizeof req,(uintptr_t)&out));
 assert(request_wipes==wipes+3&&authority.count==1&&written);
 req.roles=0;strcpy(req.image,"C:\\SHZ\\ACCOUNTS\\REALM");strcpy(req.command,"x");
 assert(shz_auth_syscall(&anon,SHZ_AUTH_LOGIN_LAUNCH,(uintptr_t)&req,sizeof req,(uintptr_t)&out)==STATUS_ACCESS_DENIED);
 assert(request_wipes==wipes+4);                                       /* store image refused, request wiped */
 /* broker credential shape: bounded, NUL inside 32 bytes, 1..128 */
 {char longname[40];memset(longname,'a',sizeof longname);
  assert(shz_auth_endpoint_login(A,longname,PW)==STATUS_INVALID_PARAMETER);
  assert(shz_auth_endpoint_login(A,"admin","x",0)==STATUS_INVALID_PARAMETER);
  {static uint8_t big[129];assert(shz_auth_endpoint_login(A,"admin",big,129)==STATUS_INVALID_PARAMETER);}
  assert(shz_auth_endpoint_login(A,"",PW)==STATUS_INVALID_PARAMETER);}

 /* epoch reset drops a login that never created a child, and its elevation ticket */
 shz_auth_endpoint_epoch_reset(4);
 assert(!shz_auth_endpoint_login(C,"admin",PW)&&!shz_auth_endpoint_query(C,&s,&ep));
 assert(!shz_auth_endpoint_confirm_elevation(C,"admin",PW));
 shz_auth_endpoint_epoch_reset(4);                                     /* same epoch: kept */
 assert(!shz_auth_endpoint_query(C,&s,&ep2)&&ep2==ep);
 shz_auth_endpoint_epoch_reset(5);
 assert(shz_auth_endpoint_query(C,&s,0)==STATUS_ACCESS_DENIED);
 assert(!shz_auth_endpoint_login(C,"admin",PW));
 assert(shz_auth_endpoint_prepare(C,SHZ_AUTH_EP_ELEVATED,&g)==STATUS_ACCESS_DENIED);  /* ticket gone */

 /* elevation ticket: single use, expires */
 assert(!shz_auth_endpoint_confirm_elevation(C,"admin",PW));now+=SHZ_AUTH_EP_ELEVATION_MS;
 assert(shz_auth_endpoint_prepare(C,SHZ_AUTH_EP_ELEVATED,&g)==STATUS_ACCESS_DENIED);
 assert(!shz_auth_endpoint_confirm_elevation(C,"admin",PW));
 assert(!shz_auth_endpoint_prepare(C,SHZ_AUTH_EP_ELEVATED,&g)&&g.subject.integrity==0x3000);
 assert(shz_auth_endpoint_prepare(C,SHZ_AUTH_EP_ELEVATED,&g)==STATUS_ACCESS_DENIED);
 assert(shz_auth_endpoint_register(C,"user1","another pass",12,0)==STATUS_ACCESS_DENIED);

 /* binding_current: only the bound, published child of the live login generation */
 assert(!shz_auth_endpoint_login(A,"admin",PW)&&!shz_auth_endpoint_login(B,"admin",PW));
 g=spawn(A,0,0);
 assert(!shz_auth_endpoint_binding_current(A,g.epoch,&procs[0]));      /* bound, unpublished */
 assert(shz_auth_endpoint_child_owned(A,g.epoch,&procs[0]));           /* legacy check still sees binding */
 assert(!shz_auth_endpoint_publish(&g,&procs[0],&thrs[0]));
 assert(shz_auth_endpoint_binding_current(A,g.epoch,&procs[0]));
 assert(!shz_auth_endpoint_binding_current(B,g.epoch,&procs[0]));      /* other owner */
 {uint64_t eb;assert(!shz_auth_endpoint_query(B,0,&eb));assert(!shz_auth_endpoint_binding_current(B,eb,&procs[0]));}
 assert(!shz_auth_endpoint_binding_current(A,g.epoch+1,&procs[0]));    /* other generation */
 assert(!shz_auth_endpoint_binding_current(A,g.epoch,0)&&!shz_auth_endpoint_binding_current(0,g.epoch,&procs[0]));
 stale=procs[0];stale.create_tick++;                                   /* same pid, other process object */
 assert(!shz_auth_endpoint_binding_current(A,g.epoch,&stale));
 g2=spawn(B,1,1);bepoch=g2.epoch;assert(!shz_auth_endpoint_binding_current(A,g.epoch,&procs[1])&&shz_auth_endpoint_binding_current(B,g2.epoch,&procs[1]));
 procs[0].teardown=1;assert(!shz_auth_endpoint_binding_current(A,g.epoch,&procs[0]));procs[0].teardown=0;

 /* departed owner */
 shz_auth_endpoint_depart(A);
 assert(!shz_auth_endpoint_binding_current(A,g.epoch,&procs[0]));
 assert(shz_auth_endpoint_binding_current(B,g2.epoch,&procs[1]));      /* other owner unaffected */
 /* relogin after departure: old child is not current under the new generation either */
 assert(!shz_auth_endpoint_login(A,"admin",PW)&&!shz_auth_endpoint_query(A,0,&ep));
 assert(ep!=g.epoch&&!shz_auth_endpoint_binding_current(A,ep,&procs[0])&&!shz_auth_endpoint_binding_current(A,g.epoch,&procs[0]));

 /* stale channel epoch: published child and pending grant both stop being current */
 g=spawn(A,2,1);assert(shz_auth_endpoint_binding_current(A,g.epoch,&procs[2]));
 g2=spawn(A,3,0);                                                      /* held, unpublished */
 assert(!shz_auth_endpoint_prepare(A,SHZ_AUTH_EP_STANDARD,&g));mk(4);   /* grant prepared, not bound */
 shz_auth_endpoint_epoch_reset(6);
 assert(!shz_auth_endpoint_binding_current(A,g.epoch,&procs[2])&&!shz_auth_endpoint_binding_current(B,bepoch,&procs[1]));
 assert(shz_auth_endpoint_bind_child(&procs[4],&g)==STATUS_ACCESS_DENIED);   /* prepared grant refused */
 assert(!shz_auth_endpoint_login(A,"admin",PW));                       /* new login in epoch 6 */
 assert(shz_auth_endpoint_publish(&g2,&procs[3],&thrs[3])==STATUS_ACCESS_DENIED&&thrs[3].state==TS_NEW);
 assert(find(&procs[3],0)->ep_revoked);
 assert(!shz_auth_endpoint_binding_current(A,g2.epoch,&procs[3]));
 /* a fresh child in the new epoch is current; developer publish never admits endpoint children */
 g=spawn(A,5,0);
 assert(shz_auth_bridge_development_publish(&procs[5],&thrs[5])==STATUS_ACCESS_DENIED);
 assert(!shz_auth_endpoint_publish(&g,&procs[5],&thrs[5])&&shz_auth_endpoint_binding_current(A,g.epoch,&procs[5]));
 assert(shz_auth_endpoint_publish(&g,&procs[5],&thrs[5])==STATUS_ACCESS_DENIED);      /* single publication */
 shz_auth_process_gone(&procs[5]);assert(!shz_auth_endpoint_binding_current(A,g.epoch,&procs[5]));

 /* store wall for enrolled user / admin bootstrap / sandbox subjects */
 check_store_denied(&procs[2]);check_store_denied(&boot);
 mk(6);assert(!shz_auth_endpoint_prepare(A,SHZ_AUTH_EP_SANDBOX,&g));assert(!shz_auth_endpoint_bind_child(&procs[6],&g));
 assert(!shz_auth_endpoint_publish(&g,&procs[6],&thrs[6]));check_store_denied(&procs[6]);
 assert(!shz_auth_bridge_development_allowed());
 printf("account-elevate routing02: epoch reset, binding_current, elevation ticket, store wall (%u spellings + node), credential wipe PASS\n",
        (unsigned)(sizeof store_spellings/sizeof store_spellings[0]-1));
 return 0;}
