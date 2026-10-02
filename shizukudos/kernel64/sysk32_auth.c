/* SPDX-License-Identifier: GPL-2.0-only
 * Volatile, kernel-owned accounts. No caller can change its own bound subject.
 * Native Windows98 login/persistent secret storage remain separate integration gates.
 */
#include "fs.h"
#include "auth_policy.h"
#include "../abi/shz_auth.h"
#include "../accounts/kdf.h"
extern int32_t shz_token_bind_subject(process_t *,uint64_t,uint32_t,uint32_t);
extern uint32_t shz_token_integrity(process_t *,uint32_t);
typedef struct {process_t *p;int pid;uint64_t born;shz_subject subject;int bootstrap,pending,gui_entry;} binding;
static binding subjects[64];
static shz_accounts authority;
static kmutex_t authority_lock;
static int initialized;
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
static int bind(process_t *p,const shz_subject *s) {
    binding *b;int32_t st;const uint64_t f=irq_save();b=find(p,1);irq_restore(f);
    if(!b)return STATUS_NO_MEMORY;
    st=shz_token_bind_subject(p,s->auth_id,s->session,s->integrity);
    if(st)return st;
    {const uint64_t f2=irq_save();b->subject=*s;irq_restore(f2);}return 0;
}
int shz_auth_inherit(process_t *parent,process_t *child) {
    shz_subject s;if(!parent)return 0;s=subject(parent);
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
    if(authority.count)return STATUS_ACCESS_DENIED;
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
int shz_auth_thread_access(process_t *a,uint64_t pid) {
    if(pid>0x7fffffffu)return 0;
    return shz_auth_process_access(a,process_by_pid((int)pid));
}
int32_t shz_auth_object_name(process_t *p,char *name,size_t capacity) {
    static const char hex[]="0123456789abcdef";
    char prefix[28];unsigned i,k=0;shz_subject s;size_t n;
    if(name[0]=='@')return STATUS_OBJECT_NAME_INVALID;
    s=subject(p);
    if(((!initialized||!authority.count)&&!s.flags)||!name[0])return STATUS_SUCCESS;
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
int shz_auth_path_access(process_t *p,const char *path,int write) {
    shz_subject s=subject(p);if((!initialized||!authority.count)&&!s.flags)return 1;
    return shz_subject_path(&s,path,write);
}
int shz_auth_node_access(process_t *p,const fsnode_t *n,int write) {
    char path[300];const fsnode_t *parts[32],*root=n;unsigned count=0,i,used=3;char drive;
    if((!initialized||!authority.count)&&!subject(p).flags)return 1;
    if(!n)return 0;
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
    if(!initialized||!authority.count)return 1;
    if(type==OB_NPIPE)return 0;
    return s.uid&&s.roles==SHZ_ROLE_ADMIN&&s.integrity>=0x3000;
}
int shz_auth_syscall_allowed(process_t *p,uint32_t n) {
    shz_subject s=subject(p);
    /* A fresh sandbox has no inherited sockets. Deny all network operations,
     * including resolution and ping, before their handlers can do work. */
    if(s.flags&&n>=0x80u&&n<=0x8fu)return 0;
    if((!initialized||!authority.count)&&!s.flags)return 1;
    switch(n) {
    case SYS_NtLoadDriver:case SYS_NtUnloadDriver:case SYS_NtShzSetupBlkWrite:case SYS_NtShzSetupPower:
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
static void profile_path(uint32_t uid,char path[48]) {
    char digits[11];unsigned i=0,k=9;memcpy(path,"C:\\Users\\",9);
    do {digits[i++]=(char)('0'+uid%10);uid/=10;}while(uid);
    while(i){path[k++]=digits[--i];}
    path[k]=0;
}
static int32_t make_profile(uint32_t uid,char path[48]) {
    char temp[64];int made;
    /* Anonymous sandbox launches have no writable profile. */
    if(!uid){memcpy(path,"C:\\",4);return 0;}
    profile_path(uid,path);
    if(!fs_lookup("C:\\Users")&&!fs_create("C:\\Users",1,&made))return STATUS_NO_MEMORY;
    if(!fs_lookup(path)&&!fs_create(path,1,&made))return STATUS_NO_MEMORY;
    {size_t n=strlen(path);memcpy(temp,path,n);memcpy(temp+n,"\\Temp",6);}
    if(!fs_lookup(temp)&&!fs_create(temp,1,&made))return STATUS_NO_MEMORY;
    return 0;
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
static int terminated(const void *ptr,size_t n) {const char *s=ptr;while(n--)if(!*s++)return 1;return 0;}
int32_t shz_auth_syscall(process_t *p,uint64_t op,uint64_t input,uint64_t bytes,uint64_t output) {
    shz_auth_request req;shz_auth_reply reply;shz_subject who,s;int32_t st=0;int grant=0;
    process_t *child=0;thread_t *t=0;ldr_create_ex_t ex;char cwd[48];uint16_t env[512];
    init();memset(&reply,0,sizeof reply);reply.version=1;reply.flags=SHZ_AUTH_VOLATILE;
    reply.subject=subject(p);
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
        st=auth_status(shz_account_register(&authority,&who,grant,req.user,req.password,req.password_bytes,req.roles));
        if(!st&&grant) {f=irq_save();b=find(p,0);if(b)b->bootstrap=0;irq_restore(f);}
        mutex_unlock(&authority_lock);goto done;
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
    }
    st=make_profile(s.uid,cwd);if(st)goto done;
    memset(&ex,0,sizeof ex);ex.suspended=1;ex.prepare=prepare_subject;ex.prepare_ctx=&s;
    ex.env=env;ex.env_chars=profile_env(cwd,env);
    /* No inherited handles, impersonation token, environment or untrusted parent loader callback. */
    st=ldr_create_process_ex(0,req.image,req.command,cwd,&ex,&child,&t);if(st)goto done;
    reply.subject=s;reply.child_pid=(uint64_t)child->pid;
    if(copy_to_user(p,output,&reply,sizeof reply)) {st=STATUS_ACCESS_VIOLATION;process_terminate(child,st,0);}
    if(!st&&(op==SHZ_AUTH_LOGIN_LAUNCH||op==SHZ_AUTH_ELEVATE_LAUNCH)) {
        const uint64_t f=irq_save();binding *b=find(child,0);if(b)b->gui_entry=1;irq_restore(f);
    }
    t->suspend_count=0;thread_resume(t);thread_creator_release(t);
done:
    shz_secret_clear(&req,sizeof req);return st;
}
