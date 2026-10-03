/* SPDX-License-Identifier: GPL-2.0-only
 * File I/O failure paths through the real Kernel64 fs.c, sysfile.c, sysk32_auth.c and object/handle bodies.
 * Based on test_file_rights_host.c. IRQ, user copies, heap, clock, token storage and the disk volume
 * (fsvol_t callbacks with injected failures) are host adapters. Each scenario runs in its own process so a
 * non-terminating baseline is bounded by the runner's timeout. No guest or native Windows98 claim.
 */
#include "../kernel64/ipc.h"
#include "../kcommon/nt_file_rights.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static uint64_t host_irq(void) { return 0; }
static void host_restore(uint64_t f) { (void)f; }
#define irq_save host_irq
#define irq_restore host_restore
#include "../kernel64/fs.c"
#include "../kernel64/sysk32_auth.c"
#include "../kernel64/sysfile.c"
static kobject_t *named_head, *timers_head[16];
static unsigned timer_count;
/* @PRODUCTION_OBJECT_FUNCTIONS@ */
unsigned host_notify_count;                     /* strong fs_notify: test_file_io_failures_notify.c */
static unsigned checks, failures, alloc_live;
static uint64_t host_alloc_limit = 1u << 20, host_alloc_refused, host_ticks = 1000;
static uint64_t arguments[12];
static thread_t host_thread;
static process_t owner;
void *kmalloc(uint64_t n) {
    void *p;
    if (n > host_alloc_limit) { if (n > host_alloc_refused) host_alloc_refused = n; return 0; }   /* never allocate 64MiB */
    p = malloc((size_t)n); if (p) alloc_live++; return p;
}
void *kzalloc(uint64_t n) { void *p=kmalloc(n); if(p)memset(p,0,(size_t)n); return p; }
void kfree(void *p) { if(p){assert(alloc_live);alloc_live--;free(p);} }
void kprintf(const char *fmt,...) { (void)fmt; }
void kpanic(const char *fmt,...) { (void)fmt; abort(); }
uint64_t ticks_now(void) { return ++host_ticks; }                   /* advances: a stray metadata update is visible */
int64_t filetime_now(void) { return 100000000; }
int64_t stack_arg(process_t *p,struct regs *r,unsigned n) { (void)p;(void)r;assert(n<12);return (int64_t)arguments[n]; }
int copy_from_user(process_t *p,void *d,uint64_t s,uint64_t n) { (void)p;if(!s&&n)return -1;memcpy(d,(void *)(uintptr_t)s,(size_t)n);return 0; }
int copy_to_user(process_t *p,uint64_t d,const void *s,uint64_t n) { (void)p;if(!d&&n)return -1;memcpy((void *)(uintptr_t)d,s,(size_t)n);return 0; }
void mutex_init(kmutex_t *m) { memset(m,0,sizeof *m); }
void mutex_lock(kmutex_t *m) { (void)m; }
void mutex_unlock(kmutex_t *m) { (void)m; }
void krandom_get(void *b,size_t n) { memset(b,0x59,n); }
uint32_t shz_token_integrity(process_t *p,uint32_t fallback) { (void)p;return fallback; }
int32_t shz_token_bind_subject(process_t *p,uint64_t a,uint32_t s,uint32_t i) { (void)p;(void)a;(void)s;(void)i;return 0; }
process_t *process_slot(unsigned i) { (void)i;return 0; }
process_t *process_by_pid(int pid) { return pid==owner.pid?&owner:0; }
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
int subsys64_console_write(process_t *p,int stream,const void *b,uint64_t n) { (void)p;(void)stream;(void)b;(void)n;abort(); }
int subsys64_console_read(process_t *p,void *b,uint64_t n,uint64_t *done) { (void)p;(void)b;(void)n;(void)done;abort(); }
int32_t ntdrv_open_device_file(process_t *p,const char *path,uint32_t access,uint64_t h,uint64_t io) { (void)p;(void)path;(void)access;(void)h;(void)io;return 0x7fff0002; }
int ntdrv_file_dispatch(process_t *p,struct regs *r,uint32_t n,uint64_t h,int32_t *st) { (void)p;(void)r;(void)n;(void)h;(void)st;return 0; }
int k64_cmdline_has(const char *s) { (void)s;return 0; }

/* ---- disk volume adapter (D:): one file payload, injectable read/truncate failures ---- */
#define DISK_CAP 200000u
static uint8_t disk_data[DISK_CAP];
static unsigned read_calls, read_fail_at, trunc_calls, write_calls;
static uint64_t read_fail_got;                  /* bytes a failing callback claims (and poisons) */
static int read_fail_rc = -1, trunc_rc;
static int has_remove = 1;
static int vol_read_adapter(fsvol_t *v,fsnode_t *n,uint64_t off,void *buf,uint64_t len,uint64_t *done) {
    (void)v;++read_calls;*done=0;
    if (read_calls==read_fail_at) {
        /* read_fail_got > len (with rc 0): a contract-violating overlong report; only len bytes are poisoned */
        memset(buf,0xEE,(size_t)(read_fail_got<len?read_fail_got:len));*done=read_fail_got;return read_fail_rc;
    }
    if (off>=n->size) return 0;
    if (len>n->size-off) len=n->size-off;
    memcpy(buf,disk_data+off,(size_t)len);*done=len;return 0;
}
static int vol_write_adapter(fsvol_t *v,fsnode_t *n,uint64_t off,const void *buf,uint64_t len) {
    (void)v;++write_calls;if(off+len>DISK_CAP)return -2;
    memcpy(disk_data+off,buf,(size_t)len);if(off+len>n->size)n->size=off+len;return 0;
}
static int vol_truncate_adapter(fsvol_t *v,fsnode_t *n,uint64_t size) {
    (void)v;++trunc_calls;if(trunc_rc)return trunc_rc;
    if(size>DISK_CAP)return -2;
    if(size>n->size)memset(disk_data+n->size,0,(size_t)(size-n->size));
    n->size=size;return 0;
}
static fsnode_t *vol_create_adapter(fsvol_t *v,fsnode_t *dir,const char *name,int is_dir) { (void)v;return fs_new_child(dir,name,is_dir); }
static int vol_remove_adapter(fsvol_t *v,fsnode_t *n) { (void)v;(void)n;return 0; }
static fsvol_t disk_vol;
static fsnode_t disk_root;
static void mount_disk(void) {
    disk_vol.letter='D';disk_vol.read=vol_read_adapter;disk_vol.write=vol_write_adapter;disk_vol.truncate=vol_truncate_adapter;
    disk_vol.create=vol_create_adapter;disk_vol.remove=has_remove?vol_remove_adapter:0;
    disk_root.is_dir=1;disk_root.attrs=FILE_ATTRIBUTE_DIRECTORY;disk_root.backing=FSB_DISK;disk_root.populated=1;disk_root.vol=&disk_vol;
    assert(!fs_mount('D',&disk_root));
}
static fsnode_t *disk_file(const char *path,uint64_t size) {
    fsnode_t *n=fs_create(path,0,0);uint64_t i;assert(n&&n->backing==FSB_DISK&&!n->readonly);
    for(i=0;i<size;i++)disk_data[i]=(uint8_t)(i*7+3);
    n->size=size;return n;
}

static void check(const char *s,int ok) { checks++;failures+=!ok;printf("%s: %s\n",ok?"PASS":"FAIL",s);fflush(stdout); }
static int32_t open_file(process_t *p,const char *path,uint32_t access,uint32_t disp,uint32_t opts,uint64_t *handle,struct iosb *io) {
    uint16_t w[260];int n=utf8_to_utf16(path,w,260);assert(n>=0);
    struct ustr u={(uint16_t)(n*2),(uint16_t)(n*2+2),0,(uint64_t)(uintptr_t)w};
    struct objattr oa={.length=sizeof oa,.name=(uint64_t)(uintptr_t)&u};struct regs r={0};int handled=0;
    memset(arguments,0,sizeof arguments);arguments[8]=disp;arguments[9]=opts;
    return sysfile_dispatch(p,&r,SYS_NtCreateFile,(uint64_t)(uintptr_t)handle,access,(uint64_t)(uintptr_t)&oa,(uint64_t)(uintptr_t)io,&handled);
}
/* off_ptr 0: the file pointer (FilePositionInformation). */
static int32_t rw(process_t *p,uint64_t h,int write,void *data,uint64_t len,uint64_t *off_ptr,struct iosb *io) {
    struct regs r={0};int handled=0;
    memset(arguments,0,sizeof arguments);arguments[5]=(uint64_t)(uintptr_t)io;arguments[6]=(uint64_t)(uintptr_t)data;
    arguments[7]=len;arguments[8]=(uint64_t)(uintptr_t)off_ptr;
    return sysfile_dispatch(p,&r,write?SYS_NtWriteFile:SYS_NtReadFile,h,0,0,0,&handled);
}
static int32_t setinfo(process_t *p,uint64_t h,unsigned cls,void *data,unsigned len) {
    struct regs r={0};struct iosb io={0};int handled=0;memset(arguments,0,sizeof arguments);arguments[5]=cls;
    return sysfile_dispatch(p,&r,SYS_NtSetInformationFile,h,(uint64_t)(uintptr_t)&io,(uint64_t)(uintptr_t)data,len,&handled);
}
static file_t *file_of(uint64_t h) { kobject_t *o=handle_lookup(&owner,h,OB_FILE);return o?o->u.file.file:0; }
static unsigned handle_count(process_t *p) { unsigned i,c=0;for(i=0;i<p->handle_cap;i++)c+=p->handles[i].obj!=0;return c; }
static void sentinel(struct iosb *io) { io->status=0x5a5a5a5a5a5a5a5aull;io->information=0xa5a5a5a5a5a5a5a5ull; }
static int iosb_is(const struct iosb *io,int32_t st,uint64_t info) { return io->status==(uint64_t)(int64_t)st&&io->information==info; }
static void remove_tree(fsnode_t *n) { while(n->child)remove_tree(n->child);fs_remove(n); }
static const uint32_t RW=GENERIC_READ|GENERIC_WRITE|DELETE_ACCESS;

/* ---- 1. RAM volume growth bound (fs.c reserve) ---- */
struct ram_state { uint64_t size, cap, mtime, total, pos; int64_t ft_write; const uint8_t *data; unsigned notify, allocs; uint8_t head[16]; };
static struct ram_state ram_snap(fsnode_t *n,file_t *f) {
    struct ram_state s;memset(&s,0,sizeof s);s.size=n->size;s.cap=n->cap;s.mtime=n->mtime;s.total=fs_total_bytes();s.pos=f->pos;
    s.ft_write=n->ft_write;s.data=n->data;s.notify=host_notify_count;s.allocs=alloc_live;memcpy(s.head,n->data,n->size<16?n->size:16);return s;
}
static int ram_same(const struct ram_state *a,const struct ram_state *b) { return !memcmp(a,b,sizeof *a); }
static void scenario_ram_position_max(void) {
    uint64_t h=0,off;struct iosb io;fsnode_t *n;file_t *f;struct ram_state before,after;int64_t pos=INT64_MAX;
    char data[]="abc",two[2]={'x','y'};
    assert(!open_file(&owner,"C:\\TEMP\\big.bin",RW,FILE_CREATE,0,&h,&io));
    assert(!rw(&owner,h,1,data,3,0,&io));n=fs_lookup("C:\\TEMP\\big.bin");f=file_of(h);n->ft_write=777;
    check("FilePositionInformation accepts INT64_MAX",!setinfo(&owner,h,14,&pos,8)&&f->pos==(uint64_t)INT64_MAX);
    before=ram_snap(n,f);sentinel(&io);host_alloc_refused=0;
    check("write of 2 bytes at file pointer INT64_MAX returns STATUS_DISK_FULL",rw(&owner,h,1,two,2,0,&io)==STATUS_DISK_FULL);
    after=ram_snap(n,f);
    check("rejected write sets IOSB to DISK_FULL with zero bytes",iosb_is(&io,STATUS_DISK_FULL,0));
    check("rejected write leaves size/cap/data/mtime/ft_write/pos/total unchanged with no notification",ram_same(&before,&after));
    check("rejected write requested no growth allocation",host_alloc_refused==0);
    off=0xFFFFFFFFFFFFFFFEull;sentinel(&io);                      /* FILE_USE_FILE_POINTER_POSITION */
    check("FILE_USE_FILE_POINTER_POSITION at INT64_MAX is rejected the same way",rw(&owner,h,1,two,2,&off,&io)==STATUS_DISK_FULL&&iosb_is(&io,STATUS_DISK_FULL,0));
    after=ram_snap(n,f);check("second rejection is also side-effect free",ram_same(&before,&after));
    off=(uint64_t)INT64_MAX-1;sentinel(&io);
    check("explicit offset INT64_MAX-1 (+2 = 2^63) is rejected",rw(&owner,h,1,two,2,&off,&io)==STATUS_DISK_FULL&&iosb_is(&io,STATUS_DISK_FULL,0));
    after=ram_snap(n,f);check("explicit-offset rejection is side-effect free",ram_same(&before,&after));
    check("original payload still reads back",!memcmp(n->data,"abc",3)&&n->size==3);
    assert(!handle_close(&owner,h));
}
static void scenario_ram_limit_edge(void) {
    uint64_t h=0,off;struct iosb io;fsnode_t *n;file_t *f;struct ram_state before,after;int64_t eof;char one='z';
    assert(!open_file(&owner,"C:\\TEMP\\edge.bin",RW,FILE_CREATE,0,&h,&io));
    assert(!rw(&owner,h,1,"q",1,0,&io));n=fs_lookup("C:\\TEMP\\edge.bin");f=file_of(h);
    before=ram_snap(n,f);host_alloc_refused=0;
    off=64ull<<20;sentinel(&io);                                   /* need = 64MiB + 1 */
    check("write ending at 64MiB+1 returns STATUS_DISK_FULL",rw(&owner,h,1,&one,1,&off,&io)==STATUS_DISK_FULL&&iosb_is(&io,STATUS_DISK_FULL,0));
    check("64MiB+1 request is refused before any growth allocation",host_alloc_refused==0);
    after=ram_snap(n,f);check("64MiB+1 rejection leaves state unchanged",ram_same(&before,&after));
    off=(64ull<<20)-1;sentinel(&io);                               /* need = exactly 64MiB: admitted by the limit */
    check("write ending at exactly 64MiB reaches the allocator (host refuses 64MiB) and maps to DISK_FULL",
          rw(&owner,h,1,&one,1,&off,&io)==STATUS_DISK_FULL&&host_alloc_refused==(64ull<<20)&&iosb_is(&io,STATUS_DISK_FULL,0));
    after=ram_snap(n,f);check("allocator refusal leaves state unchanged",ram_same(&before,&after));
    host_alloc_refused=0;eof=(int64_t)(64ull<<20)+1;
    check("EndOfFile 64MiB+1 is refused (existing status) without allocation",setinfo(&owner,h,20,&eof,8)==STATUS_ACCESS_DENIED&&host_alloc_refused==0);
    eof=INT64_MAX;
    check("EndOfFile INT64_MAX is refused without allocation",setinfo(&owner,h,20,&eof,8)==STATUS_ACCESS_DENIED&&host_alloc_refused==0);
    after=ram_snap(n,f);check("EndOfFile refusals leave state unchanged",ram_same(&before,&after));
    assert(!handle_close(&owner,h));
}
static void scenario_ram_valid(void) {
    uint64_t h=0,off,i;struct iosb io;fsnode_t *n;file_t *f;int64_t eof;uint8_t back[1100];unsigned notify;int ok=1;
    assert(!open_file(&owner,"C:\\TEMP\\valid.bin",RW,FILE_CREATE,0,&h,&io));n=fs_lookup("C:\\TEMP\\valid.bin");f=file_of(h);
    notify=host_notify_count;sentinel(&io);
    check("valid write succeeds with byte count",!rw(&owner,h,1,"hello",5,0,&io)&&iosb_is(&io,STATUS_SUCCESS,5)&&n->size==5&&f->pos==5);
    check("valid write notifies once",host_notify_count==notify+1);
    off=1000;sentinel(&io);
    check("sparse write beyond EOF succeeds",!rw(&owner,h,1,"END",3,&off,&io)&&iosb_is(&io,STATUS_SUCCESS,3)&&n->size==1003&&f->pos==1003);
    off=0;memset(back,0xCC,sizeof back);sentinel(&io);
    check("read back whole sparse file",!rw(&owner,h,0,back,sizeof back,&off,&io)&&iosb_is(&io,STATUS_SUCCESS,1003));
    for(i=5;i<1000;i++)ok&=back[i]==0;
    check("sparse gap is zero-filled",ok&&!memcmp(back,"hello",5)&&!memcmp(back+1000,"END",3)&&back[1003]==0xCC);
    eof=2;check("truncate to 2 bytes",!setinfo(&owner,h,20,&eof,8)&&n->size==2);
    eof=10;check("extend to 10 bytes",!setinfo(&owner,h,20,&eof,8)&&n->size==10);
    off=0;memset(back,0xCC,sizeof back);sentinel(&io);ok=1;
    check("read after truncate/extend",!rw(&owner,h,0,back,sizeof back,&off,&io)&&iosb_is(&io,STATUS_SUCCESS,10));
    for(i=2;i<10;i++)ok&=back[i]==0;
    check("truncated bytes do not reappear after extension",ok&&!memcmp(back,"he",2));
    off=10;sentinel(&io);
    check("read at EOF still reports STATUS_END_OF_FILE",rw(&owner,h,0,back,4,&off,&io)==STATUS_END_OF_FILE&&iosb_is(&io,STATUS_END_OF_FILE,0));
    assert(!handle_close(&owner,h));
}

/* ---- 2. NtCreateFile overwrite/supersede truncation failure ---- */
static void create_fail_case(const char *label,uint32_t disp,int rc,int32_t want) {
    uint64_t h=0xDEADBEEFull;struct iosb io;fsnode_t *n=fs_lookup("D:\\keep.dat");unsigned before_handles=handle_count(&owner),calls=trunc_calls;
    uint32_t opens=n->open_count;char msg[200];
    trunc_rc=rc;sentinel(&io);
    snprintf(msg,sizeof msg,"%s: backend truncate failure (%d) returns the mapped NT error",label,rc);
    check(msg,open_file(&owner,"D:\\keep.dat",RW,disp,0,&h,&io)==want);
    snprintf(msg,sizeof msg,"%s: no handle is returned or inserted",label);
    check(msg,h==0xDEADBEEFull&&handle_count(&owner)==before_handles&&n->open_count==opens&&!n->delete_pending);
    snprintf(msg,sizeof msg,"%s: IOSB carries the failure, not overwrite information",label);
    check(msg,iosb_is(&io,want,0));
    snprintf(msg,sizeof msg,"%s: truncation attempted exactly once (no retry), data intact",label);
    check(msg,trunc_calls==calls+1&&n->size==4096&&disk_data[4095]==(uint8_t)(4095*7+3));
    trunc_rc=0;
}
static void scenario_create_truncate(void) {
    uint64_t h=0;struct iosb io;fsnode_t *n;unsigned calls;
    mount_disk();n=disk_file("D:\\keep.dat",4096);
    create_fail_case("FILE_OVERWRITE",FILE_OVERWRITE,-1,STATUS_ACCESS_DENIED);
    create_fail_case("FILE_OVERWRITE_IF",FILE_OVERWRITE_IF,-1,STATUS_ACCESS_DENIED);
    create_fail_case("FILE_SUPERSEDE",FILE_SUPERSEDE,-1,STATUS_ACCESS_DENIED);
    create_fail_case("FILE_OVERWRITE full volume",FILE_OVERWRITE,-2,STATUS_DISK_FULL);
    create_fail_case("FILE_SUPERSEDE full volume",FILE_SUPERSEDE,-2,STATUS_DISK_FULL);
    calls=trunc_calls;h=0xDEADBEEFull;
    check("read-only overwrite is still refused before truncation",
          open_file(&owner,"D:\\keep.dat",GENERIC_READ,FILE_OVERWRITE,0,&h,&io)==STATUS_ACCESS_DENIED&&trunc_calls==calls&&n->size==4096&&h==0xDEADBEEFull);
    check("supersede without DELETE is still refused before truncation",
          open_file(&owner,"D:\\keep.dat",GENERIC_READ|GENERIC_WRITE,FILE_SUPERSEDE,0,&h,&io)==STATUS_ACCESS_DENIED&&trunc_calls==calls&&n->size==4096);
    disk_vol.remove=0;
    check("overwrite with unsupported delete-on-close is refused before truncation",
          open_file(&owner,"D:\\keep.dat",RW,FILE_OVERWRITE,FILE_DELETE_ON_CLOSE,&h,&io)==STATUS_NOT_SUPPORTED&&trunc_calls==calls&&n->size==4096);
    disk_vol.remove=vol_remove_adapter;
    sentinel(&io);h=0;
    check("successful overwrite truncates and reports FILE_OVERWRITTEN",
          !open_file(&owner,"D:\\keep.dat",RW,FILE_OVERWRITE,0,&h,&io)&&h&&n->size==0&&iosb_is(&io,STATUS_SUCCESS,3)&&trunc_calls==calls+1);
    assert(!handle_close(&owner,h));
    n->size=16;sentinel(&io);h=0;
    check("successful supersede reports FILE_SUPERSEDED",
          !open_file(&owner,"D:\\keep.dat",RW,FILE_SUPERSEDE,0,&h,&io)&&h&&n->size==0&&iosb_is(&io,STATUS_SUCCESS,0));
    assert(!handle_close(&owner,h));
}

/* ---- 3. NtReadFile backend failure ---- */
#define UBUF 200000u
static uint8_t ubuf[UBUF];
static int data_ok(uint64_t from,uint64_t n) { uint64_t i;for(i=from;i<from+n;i++)if(ubuf[i]!=(uint8_t)(i*7+3))return 0;return 1; }
static int all_is(uint64_t from,uint64_t n,uint8_t v) { uint64_t i;for(i=from;i<from+n;i++)if(ubuf[i]!=v)return 0;return 1; }
static void read_fail_case(const char *label,uint64_t h,unsigned fail_at,uint64_t claimed,uint64_t delivered) {
    struct iosb io;file_t *f=file_of(h);uint64_t pos;int64_t zero=0;char msg[200];
    assert(!setinfo(&owner,h,14,&zero,8));pos=f->pos;              /* independent of earlier cases */
    memset(ubuf,0xCC,sizeof ubuf);read_calls=0;read_fail_at=fail_at;read_fail_got=claimed;sentinel(&io);
    snprintf(msg,sizeof msg,"%s: returns STATUS_UNSUCCESSFUL, not EOF/success",label);
    check(msg,rw(&owner,h,0,ubuf,150000,0,&io)==STATUS_UNSUCCESSFUL);
    snprintf(msg,sizeof msg,"%s: IOSB reports the error and %llu delivered bytes",label,(unsigned long long)delivered);
    check(msg,iosb_is(&io,STATUS_UNSUCCESSFUL,delivered));
    snprintf(msg,sizeof msg,"%s: delivered bytes are real data, failed bytes are not copied",label);
    check(msg,data_ok(0,delivered)&&all_is(delivered,UBUF-delivered,0xCC));
    snprintf(msg,sizeof msg,"%s: file pointer is unchanged and no callback retry",label);
    check(msg,f->pos==pos&&read_calls==fail_at);
    read_fail_at=0;
}
static void scenario_read_failure(void) {
    uint64_t h=0,off;struct iosb io;fsnode_t *n;
    mount_disk();n=disk_file("D:\\data.bin",180000);(void)n;
    assert(!open_file(&owner,"D:\\data.bin",GENERIC_READ,FILE_OPEN,0,&h,&io));
    read_fail_case("first chunk fails with no bytes",h,1,0,0);
    read_fail_case("first chunk fails but claims 10 poisoned bytes",h,1,10,0);
    read_fail_case("first chunk fails claiming the whole chunk",h,1,65536,0);
    read_fail_case("second chunk fails after one delivered chunk",h,2,100,65536);
    read_fail_case("third chunk fails after two delivered chunks",h,3,0,131072);
    read_fail_rc=-2;read_fail_case("non -1 backend error",h,1,0,0);
    read_fail_rc=0;read_fail_case("success claiming more than the chunk",h,2,65537,65536);read_fail_rc=-1;
    memset(ubuf,0xCC,sizeof ubuf);read_calls=0;sentinel(&io);
    check("healthy multi-chunk read returns all data short at EOF",
          !rw(&owner,h,0,ubuf,UBUF,0,&io)&&iosb_is(&io,STATUS_SUCCESS,180000)&&data_ok(0,180000)&&all_is(180000,UBUF-180000,0xCC)&&file_of(h)->pos==180000);
    sentinel(&io);
    check("read at EOF reports STATUS_END_OF_FILE",rw(&owner,h,0,ubuf,10,0,&io)==STATUS_END_OF_FILE&&iosb_is(&io,STATUS_END_OF_FILE,0));
    off=100;memset(ubuf,0xCC,sizeof ubuf);read_fail_at=1;read_fail_got=5;read_calls=0;sentinel(&io);
    check("explicit-offset read failure is reported and copies nothing",
          rw(&owner,h,0,ubuf,10,&off,&io)==STATUS_UNSUCCESSFUL&&iosb_is(&io,STATUS_UNSUCCESSFUL,0)&&all_is(0,UBUF,0xCC)&&file_of(h)->pos==180000);
    read_fail_at=0;
    assert(!handle_close(&owner,h));
}

int main(int argc,char **argv) {
    shz_subject s={.uid=1000,.session=1,.integrity=0x2000,.auth_id=0x3e800000001};
    const char *which=argc==2?argv[1]:"";
    fs_init();init();
    memset(&owner,0,sizeof owner);owner.used=1;owner.pid=4;owner.create_tick=4;owner.handle_cap=32;
    owner.handles=kzalloc(32*sizeof *owner.handles);owner.object=ob_create(OB_PROCESS,0);owner.object->u.proc.p=&owner;
    assert(!bind(&owner,&s));host_thread.proc=&owner;
    if(!strcmp(which,"ram_position_max"))scenario_ram_position_max();
    else if(!strcmp(which,"ram_limit_edge"))scenario_ram_limit_edge();
    else if(!strcmp(which,"ram_valid"))scenario_ram_valid();
    else if(!strcmp(which,"create_truncate"))scenario_create_truncate();
    else if(!strcmp(which,"read_failure"))scenario_read_failure();
    else { fprintf(stderr,"unknown scenario '%s'\n",which);return 2; }
    {unsigned i;for(i=0;i<owner.handle_cap;i++)if(owner.handles[i].obj)handle_close(&owner,(i+1)*4);}
    shz_auth_process_gone(&owner);ob_deref(owner.object);kfree(owner.handles);
    while(fs_root()->child)remove_tree(fs_root()->child);
    while(disk_root.child)remove_tree(disk_root.child);
    check("all filesystem and handle allocations released",!alloc_live);
    printf("file io failures [%s]: %u checks, %u failures; actual kernel code with host boundaries, no guest claim\n",which,checks,failures);
    return failures?1:0;
}
