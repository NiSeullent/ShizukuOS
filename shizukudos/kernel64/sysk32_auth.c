/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel-owned accounts. No caller can change its own bound subject. Accounts
 * are volatile until the SFS worker attaches a store (shz_auth_store_attach);
 * then every registration is committed and read back before it takes effect.
 * W64 endpoint owners obtain subjects only through the endpoint broker below.
 */
#include "fs.h"
#include "auth_policy.h"
#include "sfs_mount.h"
#include "saw.h"
#include "setup_native_sys.h"
#include "../abi/shz_auth.h"
#include "../accounts/kdf.h"
#include "../accounts/sha256.h"
#ifndef STATUS_DATA_ERROR
#define STATUS_DATA_ERROR ((int32_t)0xC000003E)
#endif
extern int32_t shz_token_bind_subject(process_t *,uint64_t,uint32_t,uint32_t);
extern uint32_t shz_token_integrity(process_t *,uint32_t);
/* ep_published: admitted by shz_auth_endpoint_publish; ep_revoked: the owner's
 * login generation ended (depart, relogin, channel epoch reset) before publication,
 * so the held child can never be published. */
typedef struct {process_t *p;int pid;uint64_t born;shz_subject subject;int bootstrap,pending,gui_entry,logon_broker,logon_busy;
    const fsnode_t *logon_origin;uint64_t logon_origin_id,logon_origin_size,logon_generation;uint8_t logon_digest[32];
    uint64_t ep_owner,ep_epoch;uint32_t ep_mode;int ep_published,ep_revoked;} binding;
/* Endpoint table: written under authority_lock and inside irq_save (the BSP owns
 * the scheduler), so shz_auth_endpoint_binding_current may read it with irq_save
 * alone and never blocks behind a running PBKDF2. */
typedef struct {uint64_t owner,epoch,chan_epoch,elevate_until;shz_subject subject,elevated;int elevate_ready;} endpoint;
static binding subjects[64];
static shz_accounts authority;
static kmutex_t authority_lock;
static int initialized;
/* Store-backed realm: sealed means an attached store could not be trusted.
 * A sealed realm counts as enrolled and has no usable account. */
static const shz_auth_store_ops *store;
static int sealed,store_attached;
static endpoint endpoints[SHZ_AUTH_EP_LIMIT];
static uint64_t endpoint_epoch;
static uint64_t channel_epoch_current;   /* last shz_auth_endpoint_epoch_reset value */
/* Bounded secret length accepted from any broker/syscall caller (= SHZ_W64_AUTH_SECRET_MAX). */
#define AUTH_SECRET_MAX 128u
#define AUTH_USER_MAX 32u
/* Constant-time inequality for digests / store images. */
static unsigned ct_differs(const void *a,const void *b,size_t n) {
    const volatile uint8_t *x=a,*y=b;unsigned d=0;size_t i;
    for(i=0;i<n;i++)d|=(unsigned)(x[i]^y[i]);
    return d!=0;
}
static int enrolled_locked(void){return authority.count||sealed;}
/* Unlocked policy reads: monotonic (count never decreases except a rollback
 * of an uncommitted registration under the mutex; sealed never clears). */
static int realm_active(void){return initialized&&(*(volatile uint32_t *)&authority.count||*(volatile int *)&sealed);}
static int entropy(void *ctx,void *out,size_t n){(void)ctx;krandom_get(out,n);return 0;}
static void init(void) {
    const uint64_t f=irq_save();
    if (!initialized) {
        mutex_init(&authority_lock);
        shz_accounts_init(&authority,entropy,0);
        initialized=1;
    }
    irq_restore(f);
}
static binding *find(process_t *p,int create) {
    unsigned i;binding *free_slot=0;
    if(!p)return 0;
    for(i=0;i<64;i++) {
        binding *b=&subjects[i];
        if(b->p==p&&b->pid==p->pid&&b->born==p->create_tick)return b;
        if(!b->p&&!free_slot)free_slot=b;
    }
    if(create&&free_slot) {
        memset(free_slot,0,sizeof *free_slot);free_slot->p=p;free_slot->pid=p->pid;free_slot->born=p->create_tick;
        free_slot->subject.integrity=0x2000;free_slot->subject.auth_id=0x4e7;
        return free_slot;
    }
    return 0;
}
static shz_subject subject(process_t *p) {
    shz_subject s={0};const uint64_t f=irq_save();binding *b=find(p,0);
    s.integrity=0x2000;s.auth_id=0x4e7;if(b)s=b->subject;irq_restore(f);
    s.integrity=shz_token_integrity(p,s.integrity);return s;
}
static int is_logon_broker(process_t *p) {
    const uint64_t f=irq_save();binding *b=find(p,0);
    int broker=b&&b->logon_broker&&p->saw_generation==b->logon_generation;
    irq_restore(f);return broker;
}
static int bind(process_t *p,const shz_subject *s) {
    binding *b;int32_t st;const uint64_t f=irq_save();b=find(p,1);irq_restore(f);
    if(!b)return STATUS_NO_MEMORY;
    st=shz_token_bind_subject(p,s->auth_id,s->session,s->integrity);
    if(st)return st;
    {const uint64_t f2=irq_save();b->subject=*s;irq_restore(f2);}return 0;
}
int shz_auth_inherit(process_t *parent,process_t *child) {
    shz_subject s;if(!parent)return 0;
    /* A private enrollment grant is never inherited by generic CreateProcess. */
    if(is_logon_broker(parent))return STATUS_ACCESS_DENIED;
    s=subject(parent);
    /* Anonymous legacy development processes keep lazy default tokens. */
    if(!s.uid&&!s.flags)return 0;
    return bind(child,&s);
}
int shz_auth_process_pending(process_t *p) {
    const uint64_t f=irq_save();binding *b=find(p,1);if(b)b->pending=1;irq_restore(f);
    return b?0:STATUS_NO_MEMORY;
}
void shz_auth_process_ready(process_t *p) {
    const uint64_t f=irq_save();binding *b=find(p,0);if(b)b->pending=0;irq_restore(f);
}
int shz_auth_bridge_development_allowed(void) {
    int allowed;init();mutex_lock(&authority_lock);
    allowed=!enrolled_locked();
    mutex_unlock(&authority_lock);return allowed;
}
/* Hold-pending child built by the loader and not yet runnable. Caller holds
 * authority_lock, then interrupts off (0832322 ordering). */
static int held_child(process_t *p,thread_t *t,binding *b) {
    return p&&t&&p->used&&p->pid>0&&p->pml4&&
       !p->terminated&&!p->exit_owner&&!p->teardown&&
       !p->parent_pid&&p->threads_alive==1&&p->main_thread==t&&
       p->object&&p->object->type==OB_PROCESS&&p->object->refs&&!p->object->signaled&&
       p->object->u.proc.p==p&&b&&b->pending&&!b->bootstrap&&
       t->proc==p&&t->state==TS_NEW&&
       t->suspend_count==1&&t->creator_hold&&!t->kill_pending&&t->tid&&
       t->object&&t->object->type==OB_THREAD&&t->object->refs&&!t->object->signaled&&
       t->object->u.thr.t==t&&t->object->u.thr.pid==(uint64_t)p->pid&&
       t->object->u.thr.tid==t->tid;
}
/* Admits READY only once the scheduler accepted it; refusal remains wakeable
 * for kill-only cleanup. */
static int32_t admit_held(thread_t *t,binding *b) {
    thread_resume(t);
    if(t->state!=TS_READY)return STATUS_UNSUCCESSFUL;
    t->suspend_count=0;b->pending=0;return STATUS_SUCCESS;
}
int32_t shz_auth_bridge_development_publish(process_t *p,thread_t *t) {
    int32_t st=STATUS_ACCESS_DENIED;binding *b;uint64_t f;
    init();mutex_lock(&authority_lock);f=irq_save();b=find(p,0);
    /* The loader retains both references and pending admission. Nothing that
     * allocates, copies user memory, loads files or tears down objects occurs
     * in this enrollment/publication critical section. */
    if(!enrolled_locked()&&held_child(p,t,b)&&!p->token&&!b->ep_owner&&
       !b->subject.uid&&!b->subject.session&&!b->subject.roles&&!b->subject.flags&&
       b->subject.auth_id==0x4e7&&b->subject.integrity==0x2000)
        st=admit_held(t,b);
    irq_restore(f);mutex_unlock(&authority_lock);return st;
}
int shz_auth_gui_take_entry(process_t *p) {
    const uint64_t f=irq_save();binding *b=find(p,0);int allowed=b&&b->gui_entry;
    if(allowed)b->gui_entry=0;
    irq_restore(f);return allowed;
}
int shz_auth_handle_allowed(process_t *p,kobject_t *o) {
    if(o->type==OB_PROCESS)return shz_auth_process_access(p,o->u.proc.p);
    if(o->type==OB_THREAD)return shz_auth_thread_access(p,o->u.thr.pid);
    if(o->type==OB_NPIPE||o->type==0x50u)return shz_auth_special_allowed(p,o->type);
    return 1;
}
void shz_auth_process_gone(process_t *p) {
    const uint64_t f=irq_save();binding *b=find(p,0);if(b)shz_secret_clear(b,sizeof *b);irq_restore(f);
}
int32_t shz_auth_bootstrap_prepare(process_t *p,void *unused) {
    binding *b;uint64_t f;shz_subject s={0};int32_t st;(void)unused;init();
    mutex_lock(&authority_lock);st=enrolled_locked()?STATUS_ACCESS_DENIED:0;mutex_unlock(&authority_lock);
    if(st)return st;
    {unsigned i;for(i=1;i<=64;i++){process_t *other=process_slot(i);if(other&&other!=p&&other->used&&(!other->terminated||other->threads_alive))return STATUS_ACCESS_DENIED;}}
    s.uid=0xffffffffu;s.session=0xffffffffu;s.integrity=0x4000;s.auth_id=UINT64_MAX;
    st=bind(p,&s);if(st)return st;
    f=irq_save();b=find(p,1);if(b)b->bootstrap=1;irq_restore(f);
    return b?0:STATUS_NO_MEMORY;
}
int shz_auth_process_access(process_t *a,process_t *b) {
    shz_subject x,y;binding *pending;uint64_t f;
    if(a==b)return 1;
    if(!a||!b)return 0;
    f=irq_save();pending=find(b,0);if(pending&&pending->pending){irq_restore(f);return 0;}irq_restore(f);
    x=subject(a);y=subject(b);return shz_subject_access(&x,&y);
}
/* SAW may fence a child while the loader still owns its construction.
 * Such an unpublished child remains owned by its generational parent. This
 * permits fencing, never early reclamation of the loader's address space.
 * Endpoint admissions have parent zero and cannot acquire this authority. */
int shz_auth_saw_process_access(process_t *a,process_t *b) {
    const uint64_t f=irq_save();int allowed=0;
    if(!a||!b)goto done;
    for(unsigned depth=0;depth<64;depth++) {
        binding *pending=find(b,0);
        if(!pending||!pending->pending) {allowed=shz_auth_process_access(a,b);break;}
        if(!b->saw_constructing||!b->parent_pid||b->parent_pid>0x7fffffffu||!b->parent_generation)break;
        process_t *parent=process_by_pid(b->parent_pid);
        if(!parent||!parent->used||parent==b||parent->saw_generation!=b->parent_generation)break;
        b=parent;
    }
 done:irq_restore(f);return allowed;
}
int shz_auth_thread_access(process_t *a,uint64_t pid) {
    if(pid>0x7fffffffu)return 0;
    return shz_auth_process_access(a,process_by_pid((int)pid));
}
int32_t shz_auth_object_name(process_t *p,char *name,size_t capacity) {
    static const char hex[]="0123456789abcdef";
    char prefix[28];unsigned i,k=0;shz_subject s;size_t n;
    if(name[0]=='@')return STATUS_OBJECT_NAME_INVALID;
    s=subject(p);
    if((!realm_active()&&!s.flags)||!name[0])return STATUS_SUCCESS;
    {static const char global[]="global\\";unsigned j;
     for(j=0;j<7&&name[j];j++){unsigned c=(unsigned char)name[j];if(c>='A'&&c<='Z')c+=32;if(c!=(unsigned char)global[j])break;}
     if(j==7)return STATUS_NOT_SUPPORTED;}
    n=strlen(name);prefix[k++]='@';
    for(i=0;i<8;i++){prefix[k++]=hex[(s.uid>>((7-i)*4))&15];}prefix[k++]=':';
    for(i=0;i<8;i++){prefix[k++]=hex[(s.session>>((7-i)*4))&15];}prefix[k++]=':';
    for(i=0;i<8;i++){prefix[k++]=hex[(s.integrity>>((7-i)*4))&15];}prefix[k++]=':';
    if(n>=capacity||k>=capacity-n)return STATUS_OBJECT_NAME_INVALID;
    memmove(name+k,name,n+1);memcpy(name,prefix,k);return STATUS_SUCCESS;
}
/* Protected account store = SHZ_AUTH_STORE_DIR on any volume, after the same
 * normalisation the fs layer may or may not apply: NT/Win32 device prefixes,
 * optional drive letter, '/' or '\', empty and "." components, "..", case,
 * trailing dots/spaces and ":stream" suffixes. Unparseable input is reserved. */
static unsigned up(unsigned c){return c>='a'&&c<='z'?c-32:c;}
typedef struct {const char *c;size_t n;} path_comp;
/* Component c[0..n) equals w[0..wn) case-insensitively after Win32 trimming
 * (":stream" suffix, trailing dots and spaces). */
static int comp_eq(const char *c,size_t n,const char *w,size_t wn) {
    size_t i,k;
    for(k=0;k<n&&c[k]!=':';k++){}
    while(k&&(c[k-1]=='.'||c[k-1]==' '))k--;
    if(k!=wn)return 0;
    for(i=0;i<k;i++)if(up((unsigned char)c[i])!=up((unsigned char)w[i]))return 0;
    return 1;
}
static int prefix_ci(const char *p,const char *w) {
    size_t i;for(i=0;w[i];i++){unsigned c=(unsigned char)p[i];if(c=='/')c='\\';if(up(c)!=(unsigned char)w[i])return 0;}
    return (int)i;
}
/* Canonical component list; -1 when it does not fit (caller fails closed). */
static int path_split(const char *path,path_comp *out,unsigned cap,unsigned *depth) {
    static const char *const prefixes[]={"\\??\\","\\\\?\\","\\\\.\\","\\DOSDEVICES\\","\\GLOBAL??\\",0};
    unsigned i,d=0;
    for(i=0;prefixes[i];i++){int k=prefix_ci(path,prefixes[i]);if(k){path+=k;break;}}
    if(path[0]&&path[1]==':')path+=2;
    for(;;) {
        const char *c;size_t n;
        while(*path=='\\'||*path=='/')path++;
        if(!*path)break;
        c=path;while(*path&&*path!='\\'&&*path!='/')path++;
        n=(size_t)(path-c);
        if(n==1&&c[0]=='.')continue;
        if(n==2&&c[0]=='.'&&c[1]=='.'){if(d)d--;continue;}
        if(d==cap)return -1;
        out[d].c=c;out[d].n=n;d++;
    }
    *depth=d;return 0;
}
#define STORE_DEPTH_MAX 4u
static unsigned store_components(path_comp want[STORE_DEPTH_MAX]) {
    unsigned d=0;
    if(path_split(SHZ_AUTH_STORE_DIR,want,STORE_DEPTH_MAX,&d)||!d)return 0;
    return d;
}
/* Protected account store = SHZ_AUTH_STORE_DIR on any volume, after the
 * normalisation the fs layer may or may not apply: NT/Win32 device prefixes,
 * optional drive letter, '/' or '\', empty and "." components, "..", case,
 * trailing dots/spaces and ":stream" suffixes. Unparseable input is reserved. */
static int store_reserved(const char *path) {
    path_comp want[STORE_DEPTH_MAX],got[160];unsigned wd=store_components(want),d=0,i;
    if(!path||!wd)return 1;
    if(path_split(path,got,sizeof got/sizeof got[0],&d))return 1;
    if(d<wd)return 0;
    for(i=0;i<wd;i++)if(!comp_eq(got[i].c,got[i].n,want[i].c,want[i].n))return 0;
    return 1;
}
/* Node form: the node's topmost ancestors below a volume root. */
static int store_node_reserved(const fsnode_t *n) {
    path_comp want[STORE_DEPTH_MAX];const fsnode_t *w;unsigned wd=store_components(want),depth=0,i;
    if(!n||!wd)return 1;
    for(w=n;w->parent;w=w->parent)if(++depth>4096)return 1;
    if(depth<wd)return 0;
    for(i=wd;i;i--) {            /* component i-1 is at height depth-(i-1) from n */
        unsigned k;w=n;for(k=0;k<depth-i;k++)w=w->parent;
        if(!comp_eq(w->name,strlen(w->name),want[i-1].c,want[i-1].n))return 0;
    }
    return 1;
}
int shz_auth_path_access(process_t *p,const char *path,int write) {
    shz_subject s;
    /* Credential records are kernel/SFS-worker only, in every realm state. */
    if(store_reserved(path))return 0;
    s=subject(p);if(!realm_active()&&!s.flags&&!is_logon_broker(p))return 1;
    return shz_subject_path(&s,path,write);
}
int shz_auth_node_access(process_t *p,const fsnode_t *n,int write) {
    char path[300];const fsnode_t *parts[32],*root=n;unsigned count=0,i,used=3;char drive;
    /* Store wall first: handle/section/image access never bypasses it, even in
     * anonymous development mode. */
    if(store_node_reserved(n))return 0;
    if(!realm_active()&&!subject(p).flags&&!is_logon_broker(p))return 1;
    while(root->parent) {if(count==32)return 0;parts[count++]=root;root=root->parent;}
    for(drive='A';drive<='Z';drive++)if(fs_root_of(drive)==root)break;
    if(drive>'Z')return 0;
    path[0]=drive;path[1]=':';path[2]='\\';
    if(!count)return !write;
    for(i=count;i;i--) {size_t len=strlen(parts[i-1]->name);if(!len||len>=sizeof path-used-1)return 0;
        memcpy(path+used,parts[i-1]->name,len);used+=(unsigned)len;if(i>1)path[used++]='\\';}
    path[used]=0;return shz_auth_path_access(p,path,write);
}
int shz_auth_special_allowed(process_t *p,uint32_t type) {
    shz_subject s=subject(p);
    if(s.flags)return 0;
    if(!realm_active()&&!is_logon_broker(p))return 1;
    if(type==OB_NPIPE)return 0;
    return s.uid&&s.roles==SHZ_ROLE_ADMIN&&s.integrity>=0x3000;
}
int shz_auth_saw_force_allowed(process_t *p) {
    shz_subject s=subject(p);
    /* CHARBOMBA never inherits the anonymous development-mode bypass. */
    return realm_active() && s.uid && s.roles==SHZ_ROLE_ADMIN &&
           s.integrity>=0x3000 && !s.flags;
}
int shz_auth_sound_control_allowed(process_t *p) {
    shz_subject s;binding *b;int denied;uint64_t f;
    if(!p||!p->used||p->terminated)return 0;
    s=subject(p);f=irq_save();b=find(p,0);denied=b&&(b->bootstrap||b->logon_broker);irq_restore(f);
    if(denied||s.flags)return 0;
    if(!realm_active())return !s.uid&&!s.session&&!s.roles&&s.auth_id==0x4e7&&s.integrity==0x2000;
    if(s.uid<1000||s.uid>=1000+authority.count||!s.session||s.auth_id!=(((uint64_t)s.uid<<32)|s.session))return 0;
    return (s.integrity==0x2000&&!s.roles)||(s.integrity>=0x3000&&s.roles==SHZ_ROLE_ADMIN);
}
int shz_auth_syscall_allowed(process_t *p,uint32_t n) {
    shz_subject s=subject(p);
    /* A fresh sandbox has no inherited sockets. Deny all network operations,
     * including resolution and ping, before their handlers can do work. */
    if(s.flags&&n>=0x80u&&n<=0x8fu)return 0;
    if(!realm_active()&&!s.flags&&!is_logon_broker(p))return 1;
    switch(n) {
    case SYS_NtShzSetupPower:
        return setup_target_prepared(p)||(s.uid&&s.roles==SHZ_ROLE_ADMIN&&s.integrity>=0x3000&&!s.flags);
    case SYS_NtLoadDriver:case SYS_NtUnloadDriver:case SYS_NtShzSetupBlkWrite:
    case SYS_NtShzBlkRead:case SYS_NtShzSetupBlkRead:case SYS_NtDeviceIoControlFile:
    case SYS_NtShzBlkWrite:case SYS_NtShzBlkBatch:case SYS_NtShzBlkControl:case SYS_NtShzBlkDiscard:
    case SYS_NtCreateKey:case SYS_NtSetValueKey:case SYS_NtDeleteKey:case SYS_NtDeleteValueKey:
        s=subject(p);return s.uid&&s.roles==SHZ_ROLE_ADMIN&&s.integrity>=0x3000&&!s.flags;
    case SYS_NtCreateNamedPipeFile:case SYS_NtUserClipboard:return 0;
    default:return 1;
    }
}
static int32_t prepare_subject(process_t *p,void *ctx) {
    /* ldr.c inherited only an anonymous context because this launch has no parent. */
    return bind(p,(const shz_subject *)ctx);
}
static int32_t auth_status(int v) {
    if(!v)return STATUS_SUCCESS;
    if(v==SHZ_AUTH_FULL)return STATUS_NO_MEMORY;
    if(v==SHZ_AUTH_INVALID)return STATUS_INVALID_PARAMETER;
    return STATUS_ACCESS_DENIED;
}
/* ---------------------------------------------------------------- persistent store */
#define STORE_MAGIC 0x43415a53u   /* "SZAC" */
#define STORE_VERSION 1u
typedef struct {uint32_t magic,version,count,bytes;uint8_t digest[32];} store_header;
typedef struct {char name[32];uint32_t uid,roles;uint8_t salt[32],digest[32];} store_record;
#define STORE_MAX (sizeof(store_header)+SHZ_ACCOUNT_LIMIT*sizeof(store_record))
/* Serialized under authority_lock only; cleared after each use. */
static uint8_t store_image[STORE_MAX],store_check[STORE_MAX];
static size_t store_serialize(uint8_t *out) {
    store_header h;store_record r;sha256_ctx c;unsigned i;
    memset(&h,0,sizeof h);h.magic=STORE_MAGIC;h.version=STORE_VERSION;h.count=authority.count;
    h.bytes=(uint32_t)(authority.count*sizeof r);sha256_init(&c);
    for(i=0;i<authority.count;i++) {
        const shz_account *a=&authority.accounts[i];
        memset(&r,0,sizeof r);memcpy(r.name,a->name,32);r.uid=a->uid;r.roles=a->roles;
        memcpy(r.salt,a->salt,32);memcpy(r.digest,a->digest,32);
        memcpy(out+sizeof h+i*sizeof r,&r,sizeof r);sha256_update(&c,&r,sizeof r);
    }
    sha256_final(&c,h.digest);memcpy(out,&h,sizeof h);shz_secret_clear(&r,sizeof r);
    return sizeof h+h.bytes;
}
static int store_name_valid(const char n[32]) {
    unsigned i;
    for(i=0;i<32;i++) {unsigned c=(unsigned char)n[i];if(!c)return i!=0;
        if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-'))return 0;}
    return 0;
}
/* Validates a committed record and imports it into the empty authority. */
static int32_t store_import(const uint8_t *in,size_t len) {
    store_header h;store_record r;sha256_ctx c;uint8_t digest[32];unsigned i,j,diff=0;
    if(len<sizeof h)return STATUS_DATA_ERROR;
    memcpy(&h,in,sizeof h);
    if(h.magic!=STORE_MAGIC||h.version!=STORE_VERSION||h.count>SHZ_ACCOUNT_LIMIT||
       h.bytes!=h.count*sizeof r||len!=sizeof h+h.bytes)return STATUS_DATA_ERROR;
    sha256_init(&c);sha256_update(&c,in+sizeof h,h.bytes);sha256_final(&c,digest);
    for(i=0;i<32;i++)diff|=digest[i]^h.digest[i];
    if(diff)return STATUS_DATA_ERROR;
    for(i=0;i<h.count;i++) {
        memcpy(&r,in+sizeof h+i*sizeof r,sizeof r);
        /* account.c assigns uid=1000+index and has no removal path. */
        if(!store_name_valid(r.name)||r.uid!=1000+i||(r.roles&~SHZ_ROLE_ADMIN))goto bad;
        for(j=0;j<i;j++)if(!strcmp(authority.accounts[j].name,r.name))goto bad;
        memset(&authority.accounts[i],0,sizeof authority.accounts[i]);
        memcpy(authority.accounts[i].name,r.name,32);authority.accounts[i].uid=r.uid;
        authority.accounts[i].roles=r.roles;memcpy(authority.accounts[i].salt,r.salt,32);
        memcpy(authority.accounts[i].digest,r.digest,32);
    }
    authority.count=h.count;shz_secret_clear(&r,sizeof r);return STATUS_SUCCESS;
bad:
    shz_secret_clear(&r,sizeof r);shz_secret_clear(authority.accounts,sizeof authority.accounts);
    return STATUS_DATA_ERROR;
}
/* Commit plus independent readback. Caller holds authority_lock. */
static int32_t store_persist_locked(void) {
    size_t n,back=0;int rc;int32_t st=STATUS_SUCCESS;
    if(!store_attached)return STATUS_SUCCESS;
    if(sealed||!store)return STATUS_ACCESS_DENIED;
    n=store_serialize(store_image);
    rc=store->commit(store->ctx,store_image,n);
    if(rc)st=STATUS_UNSUCCESSFUL;            /* atomic: prior record intact */
    else if(store->load(store->ctx,store_check,sizeof store_check,&back)||back!=n||
            ct_differs(store_check,store_image,n)) {
        /* Durable state unknown: never continue on an unverified store. */
        sealed=1;st=STATUS_DATA_ERROR;
    }
    shz_secret_clear(store_image,sizeof store_image);shz_secret_clear(store_check,sizeof store_check);
    return st;
}
int32_t shz_auth_store_attach(const shz_auth_store_ops *ops) {
    size_t len=0;int rc;int32_t st;
    init();
    if(!ops||!ops->load||!ops->commit)return STATUS_INVALID_PARAMETER;
    mutex_lock(&authority_lock);
    if(store_attached||sealed||authority.count){mutex_unlock(&authority_lock);return STATUS_ACCESS_DENIED;}
    store=ops;store_attached=1;
    rc=ops->load(ops->ctx,store_check,sizeof store_check,&len);
    if(rc==SHZ_AUTH_STORE_ABSENT)st=STATUS_SUCCESS;
    else if(rc||len>sizeof store_check)st=STATUS_DATA_ERROR;
    else st=store_import(store_check,len);
    if(st)sealed=1;
    shz_secret_clear(store_check,sizeof store_check);
    mutex_unlock(&authority_lock);return st;
}
int shz_auth_store_state(uint32_t *accounts) {
    int state;init();mutex_lock(&authority_lock);
    state=sealed?SHZ_AUTH_STORE_SEALED:store_attached?SHZ_AUTH_STORE_PERSISTENT:SHZ_AUTH_STORE_VOLATILE;
    if(accounts)*accounts=authority.count;
    mutex_unlock(&authority_lock);return state;
}
/* Registration takes effect only once committed (or the realm is volatile). */
static int32_t register_locked(const shz_subject *who,int grant,const char *user,const void *pw,size_t n,uint32_t roles) {
    int32_t st;
    if(sealed)return STATUS_ACCESS_DENIED;
    st=auth_status(shz_account_register(&authority,who,grant,user,pw,n,roles));
    if(st)return st;
    st=store_persist_locked();
    if(st&&!sealed) {authority.count--;shz_secret_clear(&authority.accounts[authority.count],sizeof authority.accounts[0]);}
    return st;
}

/* ---------------------------------------------------------------- endpoint broker */
static endpoint *ep_find(uint64_t owner) {
    unsigned i;if(!owner)return 0;
    for(i=0;i<SHZ_AUTH_EP_LIMIT;i++)if(endpoints[i].owner==owner)return &endpoints[i];
    return 0;
}
static void ep_clear(endpoint *e){shz_secret_clear(e,sizeof *e);}
/* Held endpoint children whose owner login generation is gone can never be
 * published. Caller holds authority_lock and irq_save. */
static void ep_revoke_unpublished(void) {
    unsigned i;
    for(i=0;i<64;i++) {
        binding *b=&subjects[i];endpoint *e;
        if(!b->p||!b->ep_owner||b->ep_published)continue;
        e=ep_find(b->ep_owner);
        if(!e||e->epoch!=b->ep_epoch)b->ep_revoked=1;
    }
}
/* Caller-supplied credentials: user NUL-terminated within AUTH_USER_MAX bytes,
 * secret 1..AUTH_SECRET_MAX bytes. The broker never copies, stores or logs
 * either; the caller (service/syscall) owns and wipes its single copy. */
static int cred_shape_ok(const char *user,const void *pw,size_t n) {
    unsigned i;
    if(!user||!pw||!n||n>AUTH_SECRET_MAX)return 0;
    for(i=0;i<AUTH_USER_MAX;i++)if(!user[i])return i!=0;
    return 0;
}
int32_t shz_auth_endpoint_login(uint64_t owner,const char *user,const void *pw,size_t n) {
    shz_subject s;endpoint *e=0;int32_t st;unsigned i;uint64_t f;
    memset(&s,0,sizeof s);
    if(!owner||!cred_shape_ok(user,pw,n))return STATUS_INVALID_PARAMETER;
    init();mutex_lock(&authority_lock);
    if(!authority.count||sealed){st=STATUS_ACCESS_DENIED;goto out;}
    st=auth_status(shz_account_login(&authority,user,pw,n,ticks_now(),&s));
    if(st)goto out;
    f=irq_save();
    e=ep_find(owner);
    if(!e)for(i=0;i<SHZ_AUTH_EP_LIMIT&&!e;i++)if(!endpoints[i].owner)e=&endpoints[i];
    if(!e||endpoint_epoch==UINT64_MAX)st=STATUS_NO_MEMORY;
    else {
        ep_clear(e);
        /* Least privilege: the bound subject carries no role; administration needs
         * a fresh confirmed elevation per use. A relogin starts a new generation:
         * children of the previous one are no longer current. */
        s.roles=0;s.integrity=0x2000;s.flags=0;
        e->owner=owner;e->epoch=++endpoint_epoch;e->chan_epoch=channel_epoch_current;e->subject=s;
        ep_revoke_unpublished();
    }
    irq_restore(f);
out:
    shz_secret_clear(&s,sizeof s);mutex_unlock(&authority_lock);return st;
}
int32_t shz_auth_endpoint_confirm_elevation(uint64_t owner,const char *user,const void *pw,size_t n) {
    shz_subject s;endpoint *e;int32_t st;
    memset(&s,0,sizeof s);
    if(!owner||!cred_shape_ok(user,pw,n))return STATUS_INVALID_PARAMETER;
    init();mutex_lock(&authority_lock);
    e=ep_find(owner);
    if(!e||!authority.count||sealed){st=STATUS_ACCESS_DENIED;goto out;}
    e->elevate_ready=0;
    st=auth_status(shz_account_elevate(&authority,user,pw,n,ticks_now(),&s));
    if(st)goto out;
    e->elevated=s;e->elevate_ready=1;e->elevate_until=ticks_now()+SHZ_AUTH_EP_ELEVATION_MS;
out:
    shz_secret_clear(&s,sizeof s);mutex_unlock(&authority_lock);return st;
}
/* Single use; caller holds authority_lock. */
static int ep_take_elevation(endpoint *e,shz_subject *out) {
    const int ok=e->elevate_ready&&ticks_now()<e->elevate_until&&e->elevated.uid&&
        e->elevated.roles==SHZ_ROLE_ADMIN&&e->elevated.integrity>=0x3000&&!e->elevated.flags;
    if(ok)*out=e->elevated;
    e->elevate_ready=0;shz_secret_clear(&e->elevated,sizeof e->elevated);e->elevate_until=0;
    return ok;
}
int32_t shz_auth_endpoint_register(uint64_t owner,const char *user,const void *pw,size_t n,uint32_t roles) {
    shz_subject who;endpoint *e;int32_t st=STATUS_ACCESS_DENIED;
    memset(&who,0,sizeof who);
    if(!owner||!cred_shape_ok(user,pw,n)||(roles&~SHZ_ROLE_ADMIN))return STATUS_INVALID_PARAMETER;
    init();mutex_lock(&authority_lock);
    e=ep_find(owner);
    if(e&&authority.count&&!sealed&&ep_take_elevation(e,&who))st=register_locked(&who,0,user,pw,n,roles);
    shz_secret_clear(&who,sizeof who);mutex_unlock(&authority_lock);return st;
}
int32_t shz_auth_endpoint_query(uint64_t owner,shz_subject *out,uint64_t *epoch) {
    endpoint *e;int32_t st=STATUS_ACCESS_DENIED;
    if(out)memset(out,0,sizeof *out);
    if(epoch)*epoch=0;
    if(!owner||!initialized)return STATUS_ACCESS_DENIED;
    mutex_lock(&authority_lock);e=ep_find(owner);
    if(e&&authority.count&&!sealed) {if(out)*out=e->subject;if(epoch)*epoch=e->epoch;st=STATUS_SUCCESS;}
    mutex_unlock(&authority_lock);return st;
}
void shz_auth_endpoint_depart(uint64_t owner) {
    endpoint *e;uint64_t f;if(!owner||!initialized)return;
    mutex_lock(&authority_lock);f=irq_save();
    e=ep_find(owner);if(e)ep_clear(e);
    ep_revoke_unpublished();
    irq_restore(f);mutex_unlock(&authority_lock);
}
/* Channel epoch change: every login (with its elevation ticket) stamped with
 * another epoch is dropped whether or not it ever created a child; held
 * children of dropped logins become unpublishable; outstanding grants fail
 * bind/publish because their (owner, login epoch) no longer exists. */
void shz_auth_endpoint_epoch_reset(uint64_t channel_epoch) {
    unsigned i;uint64_t f;
    init();mutex_lock(&authority_lock);f=irq_save();
    channel_epoch_current=channel_epoch;
    for(i=0;i<SHZ_AUTH_EP_LIMIT;i++)
        if(endpoints[i].owner&&endpoints[i].chan_epoch!=channel_epoch)ep_clear(&endpoints[i]);
    ep_revoke_unpublished();
    irq_restore(f);mutex_unlock(&authority_lock);
}
int32_t shz_auth_endpoint_prepare(uint64_t owner,uint32_t mode,shz_auth_endpoint_grant *g) {
    endpoint *e;int32_t st=STATUS_ACCESS_DENIED;shz_subject s;
    if(!g)return STATUS_INVALID_PARAMETER;
    memset(g,0,sizeof *g);memset(&s,0,sizeof s);
    if(!owner||mode>SHZ_AUTH_EP_SANDBOX)return STATUS_INVALID_PARAMETER;
    init();mutex_lock(&authority_lock);e=ep_find(owner);
    if(!e||!authority.count||sealed||e->chan_epoch!=channel_epoch_current)goto out;
    if(mode==SHZ_AUTH_EP_ELEVATED){if(!ep_take_elevation(e,&s))goto out;}
    else {s=e->subject;s.roles=0;
        if(mode==SHZ_AUTH_EP_SANDBOX){s.integrity=0x1000;s.flags|=SHZ_SUBJECT_SANDBOX;}}
    g->owner=owner;g->epoch=e->epoch;g->mode=mode;g->subject=s;st=STATUS_SUCCESS;
out:
    shz_secret_clear(&s,sizeof s);mutex_unlock(&authority_lock);return st;
}
int32_t shz_auth_endpoint_bind_child(process_t *child,void *ctx) {
    const shz_auth_endpoint_grant *g=ctx;binding *b;int32_t st;uint64_t f;int live;
    if(!g||!g->owner||!g->epoch||!g->subject.uid||!child)return STATUS_ACCESS_DENIED;
    /* Refuse early once the grant's login generation is gone (publish rechecks). */
    f=irq_save();{endpoint *e=ep_find(g->owner);live=e&&e->epoch==g->epoch;}irq_restore(f);
    if(!live)return STATUS_ACCESS_DENIED;
    st=bind(child,&g->subject);if(st)return st;
    f=irq_save();b=find(child,0);
    if(b){b->ep_owner=g->owner;b->ep_epoch=g->epoch;b->ep_mode=g->mode;b->ep_published=0;b->ep_revoked=0;}
    irq_restore(f);return b?STATUS_SUCCESS:STATUS_NO_MEMORY;
}
int32_t shz_auth_endpoint_publish(const shz_auth_endpoint_grant *g,process_t *p,thread_t *t) {
    int32_t st=STATUS_ACCESS_DENIED;binding *b;endpoint *e;uint64_t f;
    if(!g)return STATUS_INVALID_PARAMETER;
    init();mutex_lock(&authority_lock);e=ep_find(g->owner);f=irq_save();b=find(p,0);
    /* Same authority_lock -> irq critical section as the development path.
     * The owner must still hold the binding generation the grant came from. */
    if(authority.count&&!sealed&&e&&e->epoch==g->epoch&&e->chan_epoch==channel_epoch_current&&
       held_child(p,t,b)&&p->token&&!b->ep_published&&!b->ep_revoked&&
       b->ep_owner==g->owner&&b->ep_epoch==g->epoch&&b->ep_mode==g->mode&&
       !memcmp(&b->subject,&g->subject,sizeof b->subject)) {
        st=admit_held(t,b);
        if(!st){b->ep_published=1;if(g->mode!=SHZ_AUTH_EP_SANDBOX)b->gui_entry=1;}
    }
    irq_restore(f);mutex_unlock(&authority_lock);return st;
}
int shz_auth_endpoint_child_owned(uint64_t owner,uint64_t epoch,process_t *p) {
    int owned;uint64_t f;binding *b;
    if(!owner||!epoch||!p)return 0;
    f=irq_save();b=find(p,0);owned=b&&b->ep_owner==owner&&b->ep_epoch==epoch&&p->used&&!p->teardown;
    irq_restore(f);return owned;
}
/* Non-blocking (irq_save only): live login of `owner` in the current channel
 * epoch with login generation `epoch`, and `child` is exactly the process
 * object (pointer + pid + creation tick) bound to that generation and admitted
 * by shz_auth_endpoint_publish. Never PID-only. */
int shz_auth_endpoint_binding_current(uint64_t owner,uint64_t epoch,process_t *child) {
    int ok;uint64_t f;binding *b;endpoint *e;
    if(!owner||!epoch||!child||!initialized)return 0;
    f=irq_save();
    e=ep_find(owner);b=find(child,0);
    ok=authority.count&&!sealed&&e&&e->epoch==epoch&&e->chan_epoch==channel_epoch_current&&
       b&&b->ep_owner==owner&&b->ep_epoch==epoch&&b->ep_published&&!b->ep_revoked&&!b->pending&&
       child->used&&!child->teardown;
    irq_restore(f);return ok;
}

static int32_t profile_path(uint32_t uid,char path[48]) {
    char digits[11];unsigned i=0,k=9;int writable=0;char drive;
    memset(path,0,48);drive=sfsk_system_volume(&writable);
    if(store_attached||sealed) {if(!store_attached||sealed||!drive||!writable)return STATUS_ACCESS_DENIED;}
    else drive='C'; /* explicitly volatile development realm, never firstboot DONE */
    memcpy(path,"C:\\Users\\",9);path[0]=drive;
    do {digits[i++]=(char)('0'+uid%10);uid/=10;}while(uid);
    while(i)path[k++]=digits[--i];
    return 0;
}
static int32_t profile_dir(const char *path,int persistent,fsvol_t *volume) {
    int made=0;fsnode_t *node=fs_lookup(path);
    if(!node)node=fs_create(path,1,&made);
    if(!node||!node->is_dir||node->readonly)return STATUS_ACCESS_DENIED;
    if(persistent&&(node->backing!=FSB_DISK||node->vol!=volume||!volume||
       !volume->write||!volume->create||!volume->flush))return STATUS_ACCESS_DENIED;
    if(persistent&&fs_flush(node))return STATUS_UNSUCCESSFUL;
    return 0;
}
static int32_t make_profile(uint32_t uid,char path[48]) {
    char leaf[64],parent[]="C:\\Users";int32_t st;int persistent;fsnode_t *root;fsvol_t *volume=0;
    if(!uid){memset(path,0,48);memcpy(path,"C:\\",4);return 0;}
    st=profile_path(uid,path);if(st)return st;
    persistent=store_attached;parent[0]=path[0];root=fs_root_of(path[0]);
    if(persistent) {
        if(!root||root->backing!=FSB_DISK||root->readonly||!root->vol)return STATUS_ACCESS_DENIED;
        volume=root->vol;
    }
    st=profile_dir(parent,persistent,volume);if(st)return st;
    st=profile_dir(path,persistent,volume);if(st)return st;
    {size_t n=strlen(path);memcpy(leaf,path,n);memcpy(leaf+n,"\\Temp",6);}
    st=profile_dir(leaf,persistent,volume);if(st)return st;
    {size_t n=strlen(path);memcpy(leaf,path,n);memcpy(leaf+n,"\\Documents",11);}
    return profile_dir(leaf,persistent,volume);
}
static uint32_t profile_env(const char *path,uint16_t env[512]) {
    static const char *const entries[]={"SystemRoot=C:\\SHZ","SystemDrive=C:","PATH=C:\\SHZ\\SYS64",
        "COMPUTERNAME=SHZ-K64","OS=Windows_NT","PROCESSOR_ARCHITECTURE=AMD64","NUMBER_OF_PROCESSORS=1",0};
    static const char *const keys[]={"USERPROFILE=","TEMP=","TMP="};
    unsigned i,k=0;const char *s;
    for(i=0;entries[i];i++){for(s=entries[i];*s;s++)env[k++]=(uint8_t)*s;env[k++]=0;}
    for(i=0;i<3;i++){
        for(s=keys[i];*s;s++){env[k++]=(uint8_t)*s;}
        for(s=path;*s;s++){env[k++]=(uint8_t)*s;}
        if(i&&strcmp(path,"C:\\")){for(s="\\Temp";*s;s++){env[k++]=(uint8_t)*s;}}
        env[k++]=0;
    }
    env[k++]=0;return k;
}
#include "auth_firstboot.h"
static int terminated(const void *ptr,size_t n) {const char *s=ptr;while(n--)if(!*s++)return 1;return 0;}
int32_t shz_auth_syscall(process_t *p,uint64_t op,uint64_t input,uint64_t bytes,uint64_t output) {
    shz_auth_request req;shz_auth_reply reply;shz_subject who,s;int32_t st=0;int grant=0,broker=0,broker_lease=0;binding *broker_binding=0;const fsnode_t *origin=0;
    process_t *child=0;thread_t *t=0;ldr_create_ex_t ex;char cwd[48];uint16_t env[512];
    init();memset(&reply,0,sizeof reply);reply.version=1;reply.flags=store_attached?0:SHZ_AUTH_VOLATILE;
    reply.subject=subject(p);
    if(op==SHZ_FIRSTBOOT_QUERY||op==SHZ_FIRSTBOOT_COMPLETE)
        return shz_auth_firstboot_syscall(p,op,input,bytes,output);
    if(op==SHZ_AUTH_QUERY) {
        if(input||bytes!=sizeof reply)return STATUS_INVALID_PARAMETER;
        mutex_lock(&authority_lock);reply.accounts=authority.count;mutex_unlock(&authority_lock);
        return copy_to_user(p,output,&reply,sizeof reply)?STATUS_ACCESS_VIOLATION:0;
    }
    if(op<SHZ_AUTH_REGISTER||op>SHZ_AUTH_SANDBOX_LAUNCH||bytes!=sizeof req)return STATUS_INVALID_PARAMETER;
    memset(&req,0,sizeof req);
    if(copy_from_user(p,&req,input,sizeof req)){st=STATUS_ACCESS_VIOLATION;goto done;}
    if(req.version!=1||req.reserved||req.roles&~SHZ_ROLE_ADMIN||req.password_bytes>128||
       !terminated(req.user,sizeof req.user)||!terminated(req.image,sizeof req.image)||!terminated(req.command,sizeof req.command)) {
        st=STATUS_INVALID_PARAMETER;goto done;
    }
    who=subject(p);
    if(op==SHZ_AUTH_REGISTER) {
        binding *b;uint64_t f=irq_save();b=find(p,0);if(b)grant=b->bootstrap;irq_restore(f);
        mutex_lock(&authority_lock);
        st=b&&b->logon_broker&&!firstboot_origin_valid(b)?STATUS_ACCESS_DENIED:
            register_locked(&who,grant,req.user,req.password,req.password_bytes,req.roles);
        if(!st&&grant) {f=irq_save();b=find(p,0);if(b)b->bootstrap=0;irq_restore(f);}
        if(!st&&b&&b->logon_broker)st=firstboot_stage_registered_locked();
        reply.accounts=authority.count;
        mutex_unlock(&authority_lock);
        /* Registration can be committed even when progress/copyout fails. The
         * helper must requery accounts before retry, never register blindly. */
        if(!st&&copy_to_user(p,output,&reply,sizeof reply))st=STATUS_ACCESS_VIOLATION;
        goto done;
    }
    {const uint64_t f=irq_save();broker_binding=find(p,0);broker=broker_binding&&broker_binding->logon_broker;
     if(broker) {
        if(op!=SHZ_AUTH_LOGIN_LAUNCH||broker_binding->logon_busy||logon_child_pid)st=STATUS_ACCESS_DENIED;
        else {broker_binding->logon_busy=1;broker_lease=1;origin=broker_binding->logon_origin;}
     }
     irq_restore(f);if(st)goto done;}
    if(broker&&(!firstboot_origin_valid(broker_binding)||strcmp(req.image,FIRSTBOOT_IMAGE)||strcmp(req.command,FIRSTBOOT_CHILD_COMMAND))) {
        st=STATUS_ACCESS_DENIED;goto done;
    }
    if(who.flags&&(op==SHZ_AUTH_ELEVATE_LAUNCH||op==SHZ_AUTH_LOGIN_LAUNCH)){st=STATUS_ACCESS_DENIED;goto done;}
    if(!req.image[0]||!req.command[0]||req.roles){st=STATUS_INVALID_PARAMETER;goto done;}
    if(!shz_auth_path_access(p,req.image,0)){st=STATUS_ACCESS_DENIED;goto done;}
    if(op==SHZ_AUTH_SANDBOX_LAUNCH) {
        if(req.password_bytes||req.user[0]) {st=STATUS_INVALID_PARAMETER;goto done;}
        s=who;s.integrity=0x1000;s.roles=0;s.flags|=SHZ_SUBJECT_SANDBOX;
    } else {
        mutex_lock(&authority_lock);
        st=auth_status(op==SHZ_AUTH_ELEVATE_LAUNCH?
            shz_account_elevate(&authority,req.user,req.password,req.password_bytes,ticks_now(),&s):
            shz_account_login(&authority,req.user,req.password,req.password_bytes,ticks_now(),&s));
        mutex_unlock(&authority_lock);if(st)goto done;
        /* Least privilege: a standard logon token carries no role. */
        if(op==SHZ_AUTH_LOGIN_LAUNCH)s.roles=0;
    }
    st=make_profile(s.uid,cwd);if(st)goto done;
    memset(&ex,0,sizeof ex);ex.suspended=1;ex.prepare=prepare_subject;ex.prepare_ctx=&s;
    ex.env=env;ex.env_chars=profile_env(cwd,env);
    if(broker) {ex.trusted_image=origin;ex.prepare=prepare_logon_subject;}
    /* No inherited handles, impersonation token, environment or untrusted parent loader callback. */
    st=ldr_create_process_ex(0,req.image,req.command,cwd,&ex,&child,&t);if(st)goto done;
    reply.subject=s;reply.child_pid=(uint64_t)child->pid;
    /* Keep the actual creation reference discoverable even if the parent's
     * output address faults. The boot supervisor reaps it before returning. */
    if(broker) {const uint64_t f=irq_save();logon_child_pid=child->pid;logon_child_generation=child->saw_generation;irq_restore(f);}
    if(copy_to_user(p,output,&reply,sizeof reply)) {st=STATUS_ACCESS_VIOLATION;process_terminate(child,st,0);}
    if(!st&&(op==SHZ_AUTH_LOGIN_LAUNCH||op==SHZ_AUTH_ELEVATE_LAUNCH)) {
        const uint64_t f=irq_save();binding *b=find(child,0);if(b)b->gui_entry=1;irq_restore(f);
    }
    t->suspend_count=0;thread_resume(t);thread_creator_release(t);
done:
    if(broker_lease) {const uint64_t f=irq_save();binding *b=find(p,0);if(b)b->logon_busy=0;irq_restore(f);}
    shz_secret_clear(&req,sizeof req);return st;
}
