/* SPDX-License-Identifier: GPL-2.0-only
 * Real Kernel64 filesystem/authority/sysfile and handle duplication bodies.
 * IRQ, user copies, heap, clock, token storage and unavailable device/loader
 * boundaries are host adapters. No native Windows98 isolation is asserted.
 */
#include "../kernel64/ipc.h"
#include "../kcommon/nt_file_rights.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t host_irq(void) { return 0; }
static void schedule_close(void);
static void host_restore(uint64_t f) { (void)f;schedule_close(); }
#define irq_save host_irq
#define irq_restore host_restore
#include "../kernel64/fs.c"
#include "../kernel64/sysk32_auth.c"
#include "../kernel64/sysfile.c"
static kobject_t *named_head, *timers_head[16];
static unsigned timer_count;
/* @PRODUCTION_OBJECT_FUNCTIONS@ */
/* @PRODUCTION_DUPLICATE_FUNCTIONS@ */
/* @PRODUCTION_IO_FUNCTIONS@ */
static unsigned checks, failures, alloc_live, copy_calls, prepare_calls, console_calls;
static uint64_t reuse_handle;
static kobject_t *reuse_object;
static int reuse_on_prepare;
static process_t *close_subject;
static uint64_t close_handle;
static int fail_prepare;
static void schedule_close(void) {
    if(close_handle){uint64_t h=close_handle;close_handle=0;assert(!handle_close(close_subject,h));}
}
static void replace_handle(process_t *p) {
    uint32_t h=0;assert(reuse_handle&&reuse_object);assert(!handle_close(p,reuse_handle));
    assert(!handle_insert(p,reuse_object,GENERIC_READ|GENERIC_WRITE,&h));assert(h==reuse_handle);reuse_handle=0;
}
static uint64_t arguments[12];
static thread_t host_thread;
static process_t owner, outsider, low;
uint32_t ipc_stat_irps;
void *kmalloc(uint64_t n) { void *p=malloc((size_t)n); if(p)alloc_live++; return p; }
void *kzalloc(uint64_t n) { void *p=kmalloc(n); if(p)memset(p,0,(size_t)n); return p; }
void kfree(void *p) { if(p){assert(alloc_live);alloc_live--;free(p);} }
void kprintf(const char *fmt,...) { (void)fmt; }
void kpanic(const char *fmt,...) { (void)fmt; abort(); }
uint64_t ticks_now(void) { return 1000; }
int64_t filetime_now(void) { return 100000000; }
int64_t stack_arg(process_t *p,struct regs *r,unsigned n) { (void)p;(void)r;assert(n<12);return (int64_t)arguments[n]; }
int copy_from_user(process_t *p,void *d,uint64_t s,uint64_t n) { (void)p;copy_calls++;if(!s&&n)return -1;memcpy(d,(void *)(uintptr_t)s,(size_t)n);return 0; }
int copy_to_user(process_t *p,uint64_t d,const void *s,uint64_t n) { (void)p;copy_calls++;if(!d&&n)return -1;memcpy((void *)(uintptr_t)d,s,(size_t)n);return 0; }
void mutex_init(kmutex_t *m) { memset(m,0,sizeof *m); }
void mutex_lock(kmutex_t *m) { (void)m; }
void mutex_unlock(kmutex_t *m) { (void)m; }
void krandom_get(void *b,size_t n) { memset(b,0x59,n); }
uint32_t shz_token_integrity(process_t *p,uint32_t fallback) { (void)p;return fallback; }
int32_t shz_token_bind_subject(process_t *p,uint64_t a,uint32_t s,uint32_t i) { (void)p;(void)a;(void)s;(void)i;return 0; }
process_t *process_slot(unsigned i) { (void)i;return 0; }
process_t *process_by_pid(int pid) { return pid==owner.pid?&owner:pid==outsider.pid?&outsider:pid==low.pid?&low:0; }
thread_t *thread_current(void) { return &host_thread; }
void reg_key_object_free(kobject_t *o) { (void)o;abort(); }
void token_object_free(kobject_t *o) { (void)o;abort(); }
void ipc_object_free(kobject_t *o) { (void)o; }
void ipc_handle_closed(process_t *p,kobject_t *o) { (void)p;(void)o; }
void net_socket_handle_closing(kobject_t *o) { (void)o;abort(); }
void ntdrv_device_handle_closing(kobject_t *o) { (void)o;abort(); }
int k32_lock_conflict(const file_t *f,uint64_t off,uint64_t len,int write) { (void)f;(void)off;(void)len;(void)write;return 0; }
void k32_locks_release(const file_t *f) { (void)f; }
int fs_notify_suppress;
void fs_notify_rename(fsnode_t *from,fsnode_t *to) { (void)from;(void)to; }
int subsys64_console_write(process_t *p,int stream,const void *b,uint64_t n) { (void)p;assert(stream==1||stream==2);assert(b&&n);console_calls++;return 1; }
int subsys64_console_read(process_t *p,void *b,uint64_t n,uint64_t *done) { (void)p;assert(b&&n);*(char *)b='x';*done=1;console_calls++;return 1; }
int32_t ntdrv_open_device_file(process_t *p,const char *path,uint32_t access,uint64_t h,uint64_t io) { (void)p;(void)path;(void)access;(void)h;(void)io;return 0x7fff0002; }
int ntdrv_file_dispatch(process_t *p,struct regs *r,uint32_t n,uint64_t h,int32_t *st) { (void)p;(void)r;(void)n;(void)h;(void)st;return 0; }
int k64_cmdline_has(const char *s) { (void)s;return 0; }
int32_t ipc_section_duplicate_access(kobject_t *o,uint32_t a,uint32_t *d) { (void)o;(void)a;(void)d;abort(); }
int32_t irp_prepare(process_t *p,kobject_t *o,uint64_t ev,uint64_t apc,uint64_t ctx,uint64_t iosb,uint32_t major,irp_t **out) {
    (void)ev;(void)apc;(void)ctx;(void)iosb;prepare_calls++;
    if(fail_prepare)return STATUS_NO_MEMORY;
    *out=kzalloc(sizeof **out);(*out)->proc=p;(*out)->fobj=o;(*out)->major=major;
    ob_ref(p->object);ob_ref(o);ipc_stat_irps++;
    if(reuse_on_prepare){reuse_on_prepare=0;replace_handle(p);}return 0;
}
void irp_complete(irp_t *irp,int32_t status,uint64_t done) { irp->status=status;irp->done=done; }
int32_t irp_finish(irp_t *irp) { int32_t status=irp->status;irp_free(irp);return status; }
static void check(const char *s,int ok) { checks++;failures+=!ok;printf("%s: %s\n",ok?"PASS":"FAIL",s); }
static void setup(process_t *p,int pid,const shz_subject *s) {
    memset(p,0,sizeof *p);p->used=1;p->pid=pid;p->create_tick=(uint64_t)pid;
    p->handle_cap=32;p->handles=kzalloc(32*sizeof *p->handles);
    p->object=ob_create(OB_PROCESS,0);p->object->u.proc.p=p;assert(!bind(p,s));
}
static int32_t open_file(process_t *p,const char *path,uint32_t access,uint32_t disp,uint32_t opts,uint64_t *handle) {
    uint16_t w[260];int n=utf8_to_utf16(path,w,260);assert(n>=0);
    struct ustr u={(uint16_t)(n*2),(uint16_t)(n*2+2),0,(uint64_t)(uintptr_t)w};
    struct objattr oa={.length=sizeof oa,.name=(uint64_t)(uintptr_t)&u};struct iosb io={0};struct regs r={0};int handled=0;
    memset(arguments,0,sizeof arguments);arguments[8]=disp;arguments[9]=opts;
    return sysfile_dispatch(p,&r,SYS_NtCreateFile,(uint64_t)(uintptr_t)handle,access,(uint64_t)(uintptr_t)&oa,(uint64_t)(uintptr_t)&io,&handled);
}
static uint64_t duplicate(process_t *p,uint64_t from,uint32_t access) {
    struct regs r={0};uint64_t h=0;memset(arguments,0,sizeof arguments);arguments[5]=access;
    if(sys_duplicate(p,&r,CURRENT_PROCESS_HANDLE,from,CURRENT_PROCESS_HANDLE,(uint64_t)(uintptr_t)&h))return 0;
    return h;
}
static int32_t rw(process_t *p,uint64_t h,int write,void *data,unsigned len) {
    struct regs r={0};struct iosb io={0};int handled=0;uint64_t off=0;
    memset(arguments,0,sizeof arguments);arguments[5]=(uint64_t)(uintptr_t)&io;arguments[6]=(uint64_t)(uintptr_t)data;arguments[7]=len;arguments[8]=(uint64_t)(uintptr_t)&off;
    return sysfile_dispatch(p,&r,write?SYS_NtWriteFile:SYS_NtReadFile,h,0,0,0,&handled);
}
static int32_t async_rw(process_t *p,uint64_t h,int write,void *data,unsigned len) {
    struct regs r={0};struct ipc_iosb io={0};uint64_t off=0;
    memset(arguments,0,sizeof arguments);arguments[5]=(uint64_t)(uintptr_t)&io;arguments[6]=(uint64_t)(uintptr_t)data;arguments[7]=len;arguments[8]=(uint64_t)(uintptr_t)&off;
    return file_rw(p,&r,write?SYS_NtWriteFile:SYS_NtReadFile,h,0,0,0);
}
static int32_t setinfo(process_t *p,uint64_t h,unsigned cls,void *data,unsigned len) {
    struct regs r={0};struct iosb io={0};int handled=0;memset(arguments,0,sizeof arguments);arguments[5]=cls;
    return sysfile_dispatch(p,&r,SYS_NtSetInformationFile,h,(uint64_t)(uintptr_t)&io,(uint64_t)(uintptr_t)data,len,&handled);
}
static int32_t queryinfo(process_t *p,uint64_t h,unsigned cls,void *data,unsigned len) {
    struct regs r={0};struct iosb io={0};int handled=0;memset(arguments,0,sizeof arguments);arguments[5]=cls;
    return sysfile_dispatch(p,&r,SYS_NtQueryInformationFile,h,(uint64_t)(uintptr_t)&io,(uint64_t)(uintptr_t)data,len,&handled);
}
static void remove_tree(fsnode_t *n) { while(n->child)remove_tree(n->child);fs_remove(n); }
int main(int argc,char **argv) {
    const int reuse_control=argc==2&&!strcmp(argv[1],"reuse");
    shz_subject s={.uid=1000,.session=1,.integrity=0x2000,.auth_id=0x3e800000001};
    fs_init();init();authority.count=1;setup(&owner,4,&s);host_thread.proc=&owner;
    s.uid=1001;s.session=2;s.auth_id++;setup(&outsider,8,&s);
    s.uid=1000;s.session=1;s.flags=SHZ_SUBJECT_SANDBOX;s.integrity=0x1000;setup(&low,12,&s);
    assert(fs_create("C:\\Users",1,0));assert(fs_create("C:\\Users\\1000",1,0));assert(fs_create("C:\\Users\\1001",1,0));
    uint64_t full=0;assert(!open_file(&owner,"C:\\Users\\1000\\file.txt",GENERIC_READ|GENERIC_WRITE|DELETE_ACCESS|FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_WRITE_ATTRIBUTES,FILE_CREATE,0,&full));
    char original[]="payload",changed[]="tampered",readback[16]={0};assert(!rw(&owner,full,1,original,7));
    uint64_t ro=duplicate(&owner,full,FILE_READ_DATA),wo=duplicate(&owner,full,FILE_WRITE_DATA),meta=duplicate(&owner,full,FILE_WRITE_ATTRIBUTES);
    check("duplicate keeps only requested read rights",owner.handles[ro/4-1].access==FILE_READ_DATA);
    check("read-only duplicate can read original data",!rw(&owner,ro,0,readback,7)&&!memcmp(readback,original,7));
    uint32_t queried=0;uint8_t all[400]={0};
    check("FileAccessInformation reports reduced handle rights",!queryinfo(&owner,ro,8,&queried,4)&&queried==FILE_READ_DATA);
    check("FileAllInformation reports reduced handle rights",!queryinfo(&owner,ro,18,all,sizeof all)&&!memcmp(all+76,&(uint32_t){FILE_READ_DATA},4));
    check("read-only duplicate cannot write original object",rw(&owner,ro,1,changed,7)==STATUS_ACCESS_DENIED);
    check("write-only duplicate cannot read original object",rw(&owner,wo,0,readback,7)==STATUS_ACCESS_DENIED);
    unsigned before_prepare=prepare_calls;
    check("async read-only duplicate refuses before IRP side effects",async_rw(&owner,ro,1,changed,7)==STATUS_ACCESS_DENIED&&prepare_calls==before_prepare);
    check("async write-only duplicate refuses before IRP side effects",async_rw(&owner,wo,0,readback,7)==STATUS_ACCESS_DENIED&&prepare_calls==before_prepare);
    check("async read-only duplicate can read",!async_rw(&owner,ro,0,readback,7));
    int64_t eof=1;uint8_t del=1;struct basicinfo basic={.attrs=FILE_ATTRIBUTE_HIDDEN};
    check("read-only duplicate cannot truncate",setinfo(&owner,ro,20,&eof,8)==STATUS_ACCESS_DENIED);
    check("append-only duplicate cannot truncate",setinfo(&owner,duplicate(&owner,full,FILE_APPEND_DATA),20,&eof,8)==STATUS_ACCESS_DENIED);
    check("read-only duplicate cannot delete",setinfo(&owner,ro,13,&del,1)==STATUS_ACCESS_DENIED);
    check("read-only duplicate cannot set attributes",setinfo(&owner,ro,4,&basic,sizeof basic)==STATUS_ACCESS_DENIED);
    struct {uint8_t replace,pad[7];uint64_t root;uint32_t bytes;uint16_t name[260];} rename={0};
    rename.bytes=(uint32_t)utf8_to_utf16("C:\\Users\\1000\\renamed.txt",rename.name,260)*2;
    check("read-only duplicate cannot rename",setinfo(&owner,ro,10,&rename,20+rename.bytes)==STATUS_ACCESS_DENIED);
    fsnode_t *file=((file_t *)handle_lookup(&owner,full,OB_FILE)->u.file.file)->node;
    check("all refused mutations preserve name, content, size and attributes",file==fs_lookup("C:\\Users\\1000\\file.txt")&&!file->delete_pending&&file->size==7&&file->attrs==FILE_ATTRIBUTE_NORMAL&&!memcmp(file->data,original,7));
    file->delete_pending=0;
    check("attribute-only duplicate can change attributes",!setinfo(&owner,meta,4,&basic,sizeof basic)&&file->attrs==FILE_ATTRIBUTE_HIDDEN);
    check("write-data duplicate can truncate",!setinfo(&owner,wo,20,&eof,8)&&file->size==1);
    check("write-data duplicate can write",!rw(&owner,wo,1,changed,7)&&file->size==7&&!memcmp(file->data,changed,7));
    uint64_t append_h=duplicate(&owner,full,FILE_APPEND_DATA);
    check("append-only duplicate appends despite explicit offset zero",!rw(&owner,append_h,1,original,7)&&file->size==14&&!memcmp(file->data,changed,7)&&!memcmp(file->data+7,original,7));
    eof=7;assert(!setinfo(&owner,wo,20,&eof,8));
    uint64_t generic=0;assert(!open_file(&owner,"C:\\Users\\1000\\generic.txt",GENERIC_READ|GENERIC_WRITE,FILE_CREATE,0,&generic));
    check("generic grants are mapped to concrete rights",owner.handles[generic/4-1].access==0x0012019fu);
    check("generic write does not grant DELETE",!(owner.handles[generic/4-1].access&DELETE_ACCESS));
    check("WRITE_DAC grants no data write right",!shz_file_can_write(0x40000u));
    uint64_t gr=duplicate(&owner,generic,FILE_READ_DATA);
    check("concrete read can be duplicated from generic read",gr&&owner.handles[gr/4-1].access==FILE_READ_DATA);
    uint64_t deny=0;check("other account cannot open file",open_file(&outsider,"C:\\Users\\1000\\file.txt",GENERIC_READ,FILE_OPEN,0,&deny)==STATUS_ACCESS_DENIED);
    check("sandbox cannot open file for writing",open_file(&low,"C:\\Users\\1000\\file.txt",GENERIC_WRITE,FILE_OPEN,0,&deny)==STATUS_ACCESS_DENIED);
    check("read-only open cannot overwrite",open_file(&owner,"C:\\Users\\1000\\file.txt",GENERIC_READ,FILE_OVERWRITE,0,&deny)==STATUS_ACCESS_DENIED);
    check("read-only open cannot supersede",open_file(&owner,"C:\\Users\\1000\\file.txt",GENERIC_READ,FILE_SUPERSEDE,0,&deny)==STATUS_ACCESS_DENIED);
    check("read-only open cannot request deletion on close",open_file(&owner,"C:\\Users\\1000\\file.txt",GENERIC_READ,FILE_OPEN,FILE_DELETE_ON_CLOSE,&deny)==STATUS_ACCESS_DENIED);
    uint64_t delete_h=duplicate(&owner,full,DELETE_ACCESS);
    check("delete-only handle can rename",!setinfo(&owner,delete_h,10,&rename,20+rename.bytes));
    check("renamed file data and identity remain",fs_lookup("C:\\Users\\1000\\renamed.txt")&&fs_lookup("C:\\Users\\1000\\renamed.txt")->size==7);
    check("delete-only handle can set disposition",!setinfo(&owner,delete_h,13,&del,1));
    uint64_t conin=0,conout=0,nul=0;
    assert(!open_file(&owner,"\\??\\CONIN$",GENERIC_READ,FILE_OPEN,0,&conin));
    assert(!open_file(&owner,"\\??\\CONOUT$",GENERIC_WRITE,FILE_OPEN,0,&conout));
    owner.console_sink=&host_thread;unsigned before_console=console_calls;
    check("explicit console input refuses writing before relay",rw(&owner,conin,1,original,1)==STATUS_ACCESS_DENIED&&console_calls==before_console);
    check("explicit console output refuses reading before relay",rw(&owner,conout,0,readback,1)==STATUS_ACCESS_DENIED&&console_calls==before_console);
    check("explicit console input remains readable",!rw(&owner,conin,0,readback,1)&&readback[0]=='x');
    check("explicit console output remains writable",!rw(&owner,conout,1,original,1));
    kobject_t *stdio=console_object(1);uint32_t std_h=0;assert(stdio);assert(!handle_insert(&owner,stdio,0xc0000000u,&std_h));ob_deref(stdio);
    check("default standard console RW handle remains writable",!rw(&owner,std_h,1,original,1));
    check("default standard console RW handle remains readable",!rw(&owner,std_h,0,readback,1)&&readback[0]=='x');
    owner.console_sink=0;
    assert(!open_file(&owner,"\\??\\NUL",GENERIC_READ|GENERIC_WRITE,FILE_OPEN,0,&nul));
    check("NUL remains writable",!rw(&owner,nul,1,original,1));
    uint64_t nul_ro=duplicate(&owner,nul,FILE_READ_DATA);
    check("read-only NUL duplicate refuses writing",rw(&owner,nul_ro,1,original,1)==STATUS_ACCESS_DENIED);
    if(reuse_control){
        uint64_t first=0,second=0;
        assert(!open_file(&owner,"C:\\Users\\1000\\first.txt",GENERIC_READ|GENERIC_WRITE,FILE_CREATE,0,&first));
        assert(!open_file(&owner,"C:\\Users\\1000\\second.txt",GENERIC_READ|GENERIC_WRITE,FILE_CREATE,0,&second));
        fsnode_t *first_node=fs_lookup("C:\\Users\\1000\\first.txt"),*second_node=fs_lookup("C:\\Users\\1000\\second.txt");
        assert(!rw(&owner,second,1,original,7));
        reuse_handle=first;reuse_object=handle_lookup(&owner,second,OB_FILE);reuse_on_prepare=1;
        check("async handle reuse keeps captured file target",!async_rw(&owner,first,1,changed,7)&&first_node->size==7&&!memcmp(first_node->data,changed,7)&&second_node->size==7&&!memcmp(second_node->data,original,7));
        check("async last-handle close releases original payload",first_node->open_count==0&&!ipc_stat_irps);
        uint64_t early=0;
        assert(!open_file(&owner,"C:\\Users\\1000\\denied.txt",GENERIC_READ,FILE_CREATE,0,&early));
        fsnode_t *early_node=fs_lookup("C:\\Users\\1000\\denied.txt");close_subject=&owner;close_handle=early;
        check("last-handle close before rights refusal releases payload",async_rw(&owner,early,1,original,1)==STATUS_ACCESS_DENIED&&!early_node->open_count);
        assert(!open_file(&owner,"C:\\Users\\1000\\failed.txt",GENERIC_WRITE,FILE_CREATE,0,&early));
        early_node=fs_lookup("C:\\Users\\1000\\failed.txt");close_subject=&owner;close_handle=early;fail_prepare=1;
        check("last-handle close before IRP failure releases payload",async_rw(&owner,early,1,original,1)==STATUS_NO_MEMORY&&!early_node->open_count);fail_prepare=0;
        assert(!open_file(&owner,"C:\\Users\\1000\\policy.txt",GENERIC_WRITE,FILE_CREATE,0,&early));
        early_node=fs_lookup("C:\\Users\\1000\\policy.txt");kobject_t *policy_object=handle_lookup(&owner,early,OB_FILE);uint32_t low_handle=0;
        assert(!handle_insert(&low,policy_object,FILE_WRITE_DATA,&low_handle));assert(!handle_close(&owner,early));close_subject=&low;close_handle=low_handle;
        check("last-handle close before sandbox refusal releases payload",async_rw(&low,low_handle,1,original,1)==STATUS_ACCESS_DENIED&&!early_node->open_count);
    }
    for(unsigned j=0;j<3;j++){process_t *p=j==0?&owner:j==1?&outsider:&low;for(unsigned i=0;i<p->handle_cap;i++)if(p->handles[i].obj)handle_close(p,(i+1)*4);shz_auth_process_gone(p);ob_deref(p->object);kfree(p->handles);}
    while(fs_root()->child)remove_tree(fs_root()->child);
    check("all filesystem and handle allocations released",!alloc_live);
    printf("file rights: %u checks, %u failures; actual kernel code with host boundaries, no guest claim\n",checks,failures);
    return failures?1:0;
}
