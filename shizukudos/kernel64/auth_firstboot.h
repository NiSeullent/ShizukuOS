/* SPDX-License-Identifier: GPL-2.0-only
 * Included by the EXISTING account authority after make_profile. This stores
 * setup progress referencing real accounts; it is not another user database.
 * Lock order remains authority mutex -> ordinary SFS record worker; no IRQ-off
 * section performs filesystem I/O or PBKDF2. */
#ifndef SHZ_AUTH_FIRSTBOOT_KERNEL_H
#define SHZ_AUTH_FIRSTBOOT_KERNEL_H
#include "sfs_mount.h"
#include "archive_source.h"
#include "../abi/shz_firstboot.h"
#include "../../shizukufs/v1/libsfs/sfs.h"
#define FIRSTBOOT_IMAGE "C:\\SHZ\\SYS64\\SHZDESK.EXE"
#define FIRSTBOOT_CHILD_COMMAND "SHZDESK.EXE --firstboot-complete"
#define FIRSTBOOT_IMAGE_BOUND (8u*1024u*1024u)
static int firstboot_origin_digest(const fsnode_t *n,uint8_t digest[32]) {
    sha256_ctx c;
    if(!n||n!=fs_lookup(FIRSTBOOT_IMAGE)||n!=archive_source_bound_node(FIRSTBOOT_IMAGE)||n->is_dir||!n->readonly||n->backing!=FSB_RAM||!n->data||!n->size||n->size>FIRSTBOOT_IMAGE_BOUND)return 0;
    sha256_init(&c);sha256_update(&c,n->data,(size_t)n->size);sha256_final(&c,digest);return 1;
}
static int firstboot_origin_valid(binding *b) {
    uint8_t digest[32];int okay;
    if(!b||!b->p||!b->p->used||b->p->saw_generation!=b->logon_generation||
       !b->logon_origin||b->logon_origin->id!=b->logon_origin_id||b->logon_origin->size!=b->logon_origin_size)return 0;
    okay=firstboot_origin_digest(b->logon_origin,digest)&&!ct_differs(digest,b->logon_digest,sizeof digest);
    shz_secret_clear(digest,sizeof digest);return okay;
}
static int32_t prepare_logon_subject(process_t *p,void *subject_context) {
    int32_t st=bind(p,(const shz_subject *)subject_context);
    if(!st)process_saw_protect(p,SHZ_SAW_PROTECT_CRITICAL);
    return st;
}
#define FIRSTBOOT_RECORD_MAGIC 0x42465a53u /* SZFB */
typedef struct {
    uint32_t magic,version,phase,uid,language,keyboard,reserved[2];
    char user[32],home[48];
} firstboot_record;
_Static_assert(sizeof(firstboot_record)==112,"firstboot protected record");
static int logon_child_pid;
static uint64_t logon_child_generation;
static int firstboot_language(uint32_t language,uint32_t keyboard) {
    return (language==SHZ_FIRSTBOOT_LANG_KO||language==SHZ_FIRSTBOOT_LANG_EN)&&keyboard==SHZ_FIRSTBOOT_KEYBOARD_US;
}
static void firstboot_defaults_locked(uint32_t *language,uint32_t *keyboard) {
    shz_firstboot_preferences preferences;
    char path[]="E:\\SHZ\\SETUP\\FIRSTBOOT.CFG";
    fsnode_t *node;uint64_t got=0;int writable=0;char drive=sfsk_system_volume(&writable);
    *language=SHZ_FIRSTBOOT_LANG_KO;*keyboard=SHZ_FIRSTBOOT_KEYBOARD_US;
    if(!drive||!writable)return;
    path[0]=drive;node=fs_lookup(path);
    if(!node||node->is_dir||node->backing!=FSB_DISK||node->size!=sizeof preferences)return;
    memset(&preferences,0,sizeof preferences);
    if(!fs_read(node,0,&preferences,sizeof preferences,&got)&&got==sizeof preferences&&
       preferences.magic==SHZ_FIRSTBOOT_PREFS_MAGIC&&preferences.version==SHZ_FIRSTBOOT_VERSION&&
       firstboot_language(preferences.language,preferences.keyboard)) {
        *language=preferences.language;*keyboard=preferences.keyboard;
    }
}
/* 1 absent, 0 valid, negative hard failure. Never interpret corrupt DONE as a
 * new installation or grant fresh enrollment. Caller holds authority_lock. */
static int32_t firstboot_read_locked(firstboot_record *record) {
    uint32_t got=0;uint64_t seq=0;int rc;unsigned i;char home[48];
    memset(record,0,sizeof *record);
    rc=sfsk_record_get(NULL,"FIRSTBOOT",record,sizeof *record,&got,&seq);
    if(rc==SFS_ENOENT)return 1;
    if(rc||got!=sizeof *record||record->magic!=FIRSTBOOT_RECORD_MAGIC||record->version!=SHZ_FIRSTBOOT_VERSION||
       (record->phase!=SHZ_FIRSTBOOT_RESUME&&record->phase!=SHZ_FIRSTBOOT_DONE)||record->reserved[0]||record->reserved[1]||
       !firstboot_language(record->language,record->keyboard)||!store_name_valid(record->user))return STATUS_DATA_ERROR;
    for(i=0;i<authority.count;i++)if(authority.accounts[i].uid==record->uid&&!strcmp(authority.accounts[i].name,record->user))break;
    if(i==authority.count||profile_path(record->uid,home)||memcmp(home,record->home,sizeof home))return STATUS_DATA_ERROR;
    return 0;
}
static int32_t firstboot_write_locked(firstboot_record *record) {
    firstboot_record check;uint32_t got=0;uint64_t seq=0;int rc;
    rc=sfsk_record_put(NULL,"FIRSTBOOT",record,sizeof *record,&seq);
    if(rc)return STATUS_UNSUCCESSFUL;
    rc=sfsk_record_get(NULL,"FIRSTBOOT",&check,sizeof check,&got,&seq);
    if(rc||got!=sizeof check||ct_differs(record,&check,sizeof check))return STATUS_DATA_ERROR;
    return 0;
}
static int32_t firstboot_stage_registered_locked(void) {
    firstboot_record record;int32_t st;
    if(!authority.count||!store_attached||sealed)return STATUS_ACCESS_DENIED;
    st=firstboot_read_locked(&record);if(st!=1)return st; /* Existing progress is never overwritten. */
    memset(&record,0,sizeof record);record.magic=FIRSTBOOT_RECORD_MAGIC;record.version=SHZ_FIRSTBOOT_VERSION;
    record.phase=SHZ_FIRSTBOOT_RESUME;record.uid=authority.accounts[0].uid;
    memcpy(record.user,authority.accounts[0].name,sizeof record.user);
    st=profile_path(record.uid,record.home);if(st)return st;
    firstboot_defaults_locked(&record.language,&record.keyboard);
    return firstboot_write_locked(&record);
}
/* Kernel-only loader prepare, used AFTER verifying readonly RAM origin at the
 * boot supervisor. No syscall, command string or caller-owned HWND grants it.
 * Existing bootstrap preparation checks there is no other live process. */
int32_t shz_auth_logon_prepare(process_t *p,void *origin_context) {
    shz_subject s={0};binding *b;int32_t st=0;unsigned i;uint64_t f;uint8_t digest[32];
    const fsnode_t *origin=origin_context;init();
    if(!p||!p->used||!p->saw_generation||!firstboot_origin_digest(origin,digest))return STATUS_ACCESS_DENIED;
    for(i=1;i<=64;i++){process_t *other=process_slot(i);if(other&&other!=p&&other->used&&(!other->terminated||other->threads_alive))return STATUS_ACCESS_DENIED;}
    mutex_lock(&authority_lock);
    if(!store_attached||sealed)st=STATUS_ACCESS_DENIED;
    else if(!authority.count) {
        s.uid=0xffffffffu;s.session=0xffffffffu;s.integrity=0x2000;s.auth_id=UINT64_MAX;
        /* Only the private one-use enrollment bit is privileged; the GUI
         * itself receives no high-integrity or administrative subject. */
    } else {s.integrity=0x2000;s.auth_id=0x4e7;}
    if(!st)st=bind(p,&s);
    if(!st) {
        f=irq_save();b=find(p,0);
        if(!b)st=STATUS_NO_MEMORY;
        else {b->bootstrap=!authority.count;b->logon_broker=1;b->gui_entry=1;
              b->logon_origin=origin;b->logon_origin_id=origin->id;b->logon_origin_size=origin->size;
              b->logon_generation=p->saw_generation;memcpy(b->logon_digest,digest,sizeof digest);
              logon_child_pid=0;logon_child_generation=0;}
        irq_restore(f);
    }
    mutex_unlock(&authority_lock);
    if(!st)process_saw_protect(p,SHZ_SAW_PROTECT_CRITICAL); /* before first thread can run */
    shz_secret_clear(digest,sizeof digest);return st;
}
/* The loader's process creation reference pins this exact child until the
 * kernel boot supervisor proc_wait()s it. Never return a reused PID. */
int shz_auth_logon_child_pid(void) {
    int pid=0;process_t *p;init();mutex_lock(&authority_lock);
    p=logon_child_pid?process_by_pid(logon_child_pid):NULL;
    if(p&&p->used&&p->saw_generation==logon_child_generation)pid=p->pid;
    mutex_unlock(&authority_lock);return pid;
}
static int32_t firstboot_reply_locked(process_t *p,shz_firstboot_reply *out) {
    firstboot_record record;shz_subject who=subject(p);binding *b;uint64_t f;int broker;int32_t st;
    memset(out,0,sizeof *out);out->version=SHZ_FIRSTBOOT_VERSION;out->size=sizeof *out;
    f=irq_save();b=find(p,0);broker=b&&b->logon_broker;irq_restore(f);
    if(broker&&!firstboot_origin_valid(b))return STATUS_ACCESS_DENIED;
    if(!broker&&(!who.uid||who.uid==0xffffffffu||!who.session||who.auth_id!=(((uint64_t)who.uid<<32)|who.session)||who.flags))return STATUS_ACCESS_DENIED;
    out->store_flags=(store_attached?SHZ_FIRSTBOOT_STORE_PERSISTENT:0)|(sealed?SHZ_FIRSTBOOT_STORE_SEALED:0);
    out->accounts=authority.count;
    if(!store_attached||sealed)return STATUS_ACCESS_DENIED;
    st=firstboot_read_locked(&record);
    if(st<0)return st;
    if(!st) {
        out->phase=record.phase;out->uid=record.uid;out->language=record.language;out->keyboard=record.keyboard;
        memcpy(out->user,record.user,sizeof out->user);memcpy(out->home,record.home,sizeof out->home);
    } else {
        out->phase=authority.count?SHZ_FIRSTBOOT_EXISTING:SHZ_FIRSTBOOT_NEW;
        firstboot_defaults_locked(&out->language,&out->keyboard);
        if(authority.count) {
            out->uid=authority.accounts[0].uid;memcpy(out->user,authority.accounts[0].name,sizeof out->user);
            st=profile_path(out->uid,out->home);if(st)return st;
        }
    }
    /* The logon broker may suggest the original account. An authenticated
     * normal session receives ONLY its own recognized profile/name. */
    if(!broker&&out->uid!=who.uid) {
        unsigned i;for(i=0;i<authority.count;i++)if(authority.accounts[i].uid==who.uid)break;
        if(i==authority.count)return STATUS_ACCESS_DENIED;
        out->uid=who.uid;memcpy(out->user,authority.accounts[i].name,sizeof out->user);
        st=profile_path(who.uid,out->home);if(st)return st;
    }
    return 0;
}
static int32_t shz_auth_firstboot_syscall(process_t *p,uint64_t op,uint64_t input,uint64_t bytes,uint64_t output) {
    shz_firstboot_request request;shz_firstboot_reply reply;firstboot_record record;shz_subject who;
    int32_t st=STATUS_INVALID_PARAMETER;unsigned i;char home[48];
    memset(&request,0,sizeof request);memset(&reply,0,sizeof reply);
    if(op==SHZ_FIRSTBOOT_QUERY) {
        if(input||bytes!=sizeof reply)return STATUS_INVALID_PARAMETER;
        mutex_lock(&authority_lock);st=firstboot_reply_locked(p,&reply);mutex_unlock(&authority_lock);
        if(!st&&copy_to_user(p,output,&reply,sizeof reply))st=STATUS_ACCESS_VIOLATION;
        return st;
    }
    if(op!=SHZ_FIRSTBOOT_COMPLETE||bytes!=sizeof request)return STATUS_INVALID_PARAMETER;
    if(copy_from_user(p,&request,input,sizeof request)){st=STATUS_ACCESS_VIOLATION;goto done;}
    if(request.version!=SHZ_FIRSTBOOT_VERSION||request.size!=sizeof request||request.flags||request.reserved[0]||request.reserved[1]||
       !firstboot_language(request.language,request.keyboard))goto done;
    who=subject(p);
    if(!who.uid||who.uid==0xffffffffu||who.uid!=request.uid||!who.session||who.auth_id!=(((uint64_t)who.uid<<32)|who.session)||who.integrity!=0x2000||who.roles||who.flags) {
        st=STATUS_ACCESS_DENIED;goto done;
    }
    /* Validate the writable reply range before any durable state transition.
     * A later concurrent unmap may still fault: DONE is idempotent on retry. */
    if(copy_to_user(p,output,&reply,sizeof reply)){st=STATUS_ACCESS_VIOLATION;goto done;}
    mutex_lock(&authority_lock);
    if(!store_attached||sealed){st=STATUS_ACCESS_DENIED;goto unlock;}
    for(i=0;i<authority.count;i++)if(authority.accounts[i].uid==who.uid)break;
    if(i==authority.count){st=STATUS_ACCESS_DENIED;goto unlock;}
    st=firstboot_read_locked(&record);if(st<0)goto unlock;
    if((!st&&record.phase==SHZ_FIRSTBOOT_RESUME&&record.uid!=who.uid)||
       (st==1&&who.uid!=authority.accounts[0].uid)){st=STATUS_ACCESS_DENIED;goto unlock;}
    st=make_profile(who.uid,home);if(st)goto unlock;
    if(record.phase==SHZ_FIRSTBOOT_DONE&&record.magic==FIRSTBOOT_RECORD_MAGIC){st=firstboot_reply_locked(p,&reply);goto unlock;}
    /* Only the real bound UID/name/profile is persisted. Never caller strings. */
    memset(&record,0,sizeof record);record.magic=FIRSTBOOT_RECORD_MAGIC;record.version=SHZ_FIRSTBOOT_VERSION;
    record.phase=SHZ_FIRSTBOOT_DONE;record.uid=who.uid;record.language=request.language;record.keyboard=request.keyboard;
    memcpy(record.user,authority.accounts[i].name,sizeof record.user);memcpy(record.home,home,sizeof record.home);
    st=firstboot_write_locked(&record);if(!st)st=firstboot_reply_locked(p,&reply);
unlock:
    mutex_unlock(&authority_lock);
    if(!st&&copy_to_user(p,output,&reply,sizeof reply))st=STATUS_ACCESS_VIOLATION;
done:
    shz_secret_clear(&request,sizeof request);return st;
}
#endif
