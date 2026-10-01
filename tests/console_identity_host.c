/* GPL-2.0-only. Host adapters for unchanged production function bodies. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define STATUS_SUCCESS 0
#define STATUS_OBJECT_NAME_INVALID ((int32_t)0xc0000033)
#define STATUS_INVALID_HANDLE ((int32_t)0xc0000008)
#define STATUS_INVALID_PARAMETER ((int32_t)0xc000000d)
#define STATUS_BUFFER_TOO_SMALL ((int32_t)0xc0000023)
#define STATUS_BUFFER_OVERFLOW ((int32_t)0x80000005)
#define STATUS_INFO_LENGTH_MISMATCH ((int32_t)0xc0000004)
#define STATUS_INVALID_INFO_CLASS ((int32_t)0xc0000003)
#define STATUS_ACCESS_VIOLATION ((int32_t)0xc0000005)
#define STATUS_INVALID_DEVICE_REQUEST ((int32_t)0xc0000010)
#define STATUS_NO_MEMORY ((int32_t)0xc0000017)
#define STATUS_ACCESS_DENIED ((int32_t)0xc0000022)
#define OB_FILE 1
#define IO_OPENED 1
#define GENERIC_READ 0x80000000u
#define GENERIC_WRITE 0x40000000u
#define GENERIC_ALL 0x10000000u
#define FILE_READ_DATA 1u
#define FILE_WRITE_DATA 2u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define K64_VOLUME_SERIAL 0x53485a31u
#define FS_NAME_MAX 128
#define ERROR_INVALID_HANDLE 6
#define ERROR_ACCESS_DENIED 5
#define TRUE 1
#define FALSE 0
typedef uint64_t HANDLE;
typedef uint32_t ULONG, DWORD;
typedef uint16_t WCHAR;
typedef uint8_t BYTE;
typedef int BOOL;
typedef int32_t NTSTATUS;
typedef void *PVOID;
typedef ULONG *PULONG;
#define NTAPI
typedef struct { uint64_t status, Information; } SHZ_IO_STATUS_BLOCK;
typedef struct { int unused; } process_t;
struct regs { uint64_t cls; };
typedef struct fsnode { struct fsnode *parent; char name[128]; uint64_t size; uint32_t attrs;
    int is_dir, delete_pending; } fsnode_t;
typedef struct { fsnode_t *node; int console; uint32_t access, options; uint64_t pos; } file_t;
static file_t input_file={0,1,GENERIC_READ,0x20,0}, output_file={0,2,GENERIC_WRITE,0x20,0}, null_file={0,3,0,0,0};
static fsnode_t root_node={0,"",0,FILE_ATTRIBUTE_NORMAL,1,0}, named_node={&root_node,"CONOUT$",0,FILE_ATTRIBUTE_NORMAL,0,0};
static file_t normal_file={&named_node,0,GENERIC_READ,0,0};
static struct { file_t *file; uint32_t rights; } handles[16];
static int attached=1, error_code, malformed, query_object_error, volume_error, name_error;
static int checks, failures;
static uint64_t standard_output;
#define CHECK(x) do { ++checks; if (!(x)) { ++failures; fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); } } while(0)
static int64_t stack_arg(process_t *p, struct regs *r, unsigned n) { (void)p; CHECK(n==5); return (int64_t)r->cls; }
static file_t *file_of(process_t *p,uint64_t h,void *unused) { (void)p;(void)unused;return h<16?handles[h].file:0; }
static file_t *k32_file_of(process_t *p,uint64_t h) { return file_of(p,h,0); }
static int copy_to_user(process_t *p,uint64_t dst,const void *src,size_t n) { (void)p;if(!dst)return -1;memcpy((void *)(uintptr_t)dst,src,n);return 0; }
struct iosb { uint64_t status,information; };
static int set_iosb(process_t *p,uint64_t dst,int32_t status,uint64_t n) { struct iosb io={(uint64_t)(int64_t)status,n};return dst?copy_to_user(p,dst,&io,sizeof io):0; }
static int utf8_to_utf16(const char *s,uint16_t *out,size_t cap) { size_t n=strlen(s); if(n>cap)return -1;for(size_t i=0;i<n;++i)out[i]=(uint8_t)s[i];return (int)n; }
static uint64_t node_time(const fsnode_t *n,int which) { (void)n;return (uint64_t)which; }
static uint64_t node_file_id(const fsnode_t *n) { (void)n;return 123; }
static char fs_letter_of(const fsnode_t *n) { (void)n;return 'C'; }
static uint32_t fs_volume_number(char l) { (void)l;return 1; }
static int64_t filetime_now(void) { return 100000; }
static uint64_t ticks_now(void) { return 1; }
static uint64_t kheap_total(void) { return 1<<20; }
static uint64_t kheap_used(void) { return 1<<12; }
static int disk_volume_info(const fsnode_t *n,uint32_t *s,char *l,uint64_t *t,uint64_t *f,uint32_t *c,int *w) { (void)n;(void)s;(void)l;(void)t;(void)f;(void)c;(void)w;return -1; }
static int k32_console_attached(void) { return attached; }
static void shz_set_last_error(int code) { error_code=code; }
static void k32_nt_error(NTSTATUS st) { error_code=(int)st; }
NTSTATUS NtQueryInformationFile(HANDLE,SHZ_IO_STATUS_BLOCK *,void *,ULONG,ULONG);
NTSTATUS NtQueryVolumeInformationFile(HANDLE,SHZ_IO_STATUS_BLOCK *,void *,ULONG,ULONG);
NTSTATUS NtQueryObject(HANDLE,ULONG,PVOID,ULONG,PULONG);

typedef struct { unsigned refs; struct { struct { file_t *file; } file; } u; } kobject_t;
static kobject_t *opened_objects[16];
static unsigned live_objects;
static int allocation_failure, insertion_failure;
static void *kzalloc(size_t n) { return allocation_failure==2 ? NULL : calloc(1,n); }
static void kfree(void *p) { free(p); }
static kobject_t *ob_create(int type,const char *name) {
    CHECK(type==OB_FILE && !name);
    if(allocation_failure==1) return NULL;
    kobject_t *o=calloc(1,sizeof *o);
    if(o) {o->refs=1;++live_objects;}
    return o;
}
static void ob_deref(kobject_t *o) {
    CHECK(o && o->refs);
    if(!--o->refs) {free(o->u.file.file);free(o);--live_objects;}
}
static int32_t handle_insert(process_t *p,kobject_t *o,uint32_t rights,uint32_t *out) {
    (void)p;
    if(insertion_failure) return STATUS_ACCESS_DENIED;
    for(unsigned h=7;h<16;++h) if(!handles[h].file) {
        ++o->refs;opened_objects[h]=o;handles[h].file=o->u.file.file;
        handles[h].rights=rights;*out=h;return 0;
    }
    return STATUS_NO_MEMORY;
}
static void file_object_closed(kobject_t *o) {CHECK(o && o->refs);}
static int32_t handle_close(process_t *p,uint64_t h) {
    (void)p;CHECK(h<16 && opened_objects[h]);
    kobject_t *o=opened_objects[h];opened_objects[h]=NULL;handles[h].file=NULL;
    ob_deref(o);return 0;
}

/* PRODUCTION_CONSOLE_CONSTRUCTOR */

/* Only the exact console branch from sys_create_file is inserted. Other
 * paths fall through; no host filesystem or general NtCreateFile is modeled. */
static int32_t create_console_route(const char *path,uint32_t requested,uint64_t *out,struct iosb *io) {
    process_t *p=NULL;kobject_t *o;int32_t st;uint32_t h;
    uint64_t a1=(uintptr_t)out,a2=requested,a4=(uintptr_t)io;
    /* PRODUCTION_CONSOLE_OPEN_ROUTE */
    return STATUS_OBJECT_NAME_INVALID;
}

/* PRODUCTION_KERNEL_QUERY_BODIES */

NTSTATUS NtQueryInformationFile(HANDLE h,SHZ_IO_STATUS_BLOCK *io,void *buf,ULONG len,ULONG cls)
{
    struct regs r={cls}; NTSTATUS st=sys_query_info_file(0,&r,h,(uintptr_t)io,(uintptr_t)buf,len);
    if(name_error) return STATUS_INVALID_PARAMETER;
    if(!st && malformed) {
        uint32_t n;
        switch(malformed) {
        case 1: io->Information=0;break;
        case 2: io->Information=3;break;
        case 3: io->Information=4;break;
        case 4: io->Information=17;break;
        case 5: io->Information=21;break;
        case 6: io->Information=UINT64_MAX;break;
        case 7: n=15;memcpy(buf,&n,4);break;
        case 8: n=18;memcpy(buf,&n,4);break;
        case 9: n=UINT32_MAX;memcpy(buf,&n,4);break;
        case 10: ((WCHAR *)((BYTE *)buf+4))[1]='X';break;
        case 11: ((WCHAR *)((BYTE *)buf+4))[1]='c';break;
        case 12: ((WCHAR *)((BYTE *)buf+4))[1]=0;break;
        case 15: { static const WCHAR out[]={'\\','C','O','N','O','U','T','$'};
                   n=sizeof out;memcpy(buf,&n,4);memcpy((BYTE *)buf+4,out,sizeof out);io->Information=18;break; }
        }
    }
    return st;
}
NTSTATUS NtQueryVolumeInformationFile(HANDLE h,SHZ_IO_STATUS_BLOCK *io,void *buf,ULONG len,ULONG cls)
{
    struct regs r={cls};NTSTATUS st=sys_query_volume(0,&r,h,(uintptr_t)io,(uintptr_t)buf,len);
    if(volume_error)return STATUS_INVALID_HANDLE;
    if(!st&&malformed==13)io->Information=0;
    if(!st&&malformed==14)io->Information=9;
    return st;
}
NTSTATUS NtQueryObject(HANDLE h,ULONG cls,PVOID out,ULONG size,PULONG returned)
{
    CHECK(cls==0 && size==14*sizeof(ULONG));if(query_object_error)return STATUS_INVALID_HANDLE;
    if(h>=16||!handles[h].file)return STATUS_INVALID_HANDLE;
    memset(out,0,size);((ULONG *)out)[1]=handles[h].rights;if(returned)*returned=size;return 0;
}

/* PRODUCTION_KERNEL32_CONSOLE_BODIES */

static void endpoint_queries(uint64_t h,const WCHAR *name,uint32_t chars)
{
    const uint32_t bytes=chars*2;struct regs r={9};
    for(uint32_t len=0;len<=32;++len) {
        unsigned char buf[160];struct iosb io={UINT64_MAX,UINT64_MAX};uint32_t actual;
        memset(buf,0xa5,sizeof buf);
        NTSTATUS st=sys_query_info_file(0,&r,h,(uintptr_t)&io,(uintptr_t)buf,len);
        if(len<4) { CHECK(st==STATUS_BUFFER_TOO_SMALL);CHECK(io.information==UINT64_MAX);CHECK(buf[0]==0xa5);continue; }
        uint32_t n=bytes<(len-4)?bytes:(len-4)&~1u;
        memcpy(&actual,buf,4);CHECK(actual==bytes);CHECK(st==(n<bytes?STATUS_BUFFER_OVERFLOW:STATUS_SUCCESS));
        CHECK(io.information==4+n);CHECK(!memcmp(buf+4,name,n));CHECK(buf[4+n]==0xa5);
    }
    r.cls=18;
    for(uint32_t len=0;len<=125;++len) {
        unsigned char buf[160];struct iosb io={UINT64_MAX,UINT64_MAX};uint32_t actual;
        memset(buf,0xa5,sizeof buf);NTSTATUS st=sys_query_info_file(0,&r,h,(uintptr_t)&io,(uintptr_t)buf,len);
        if(len<104) { CHECK(st==STATUS_INFO_LENGTH_MISMATCH);CHECK(io.information==UINT64_MAX);CHECK(buf[0]==0xa5);continue; }
        uint32_t n=bytes<(len-100)?bytes:(len-100)&~1u;
        memcpy(&actual,buf+96,4);CHECK(actual==bytes);CHECK(st==(n<bytes?STATUS_BUFFER_OVERFLOW:STATUS_SUCCESS));
        CHECK(io.information==100+n);CHECK(!memcmp(buf+100,name,n));CHECK(buf[100+n]==0xa5);
        memcpy(&actual,buf+76,4);CHECK(actual==handles[h].file->access);
    }
}

int main(void)
{
    static const WCHAR input[]={'\\','C','O','N','I','N','$'},output[]={'\\','C','O','N','O','U','T','$'};
    handles[1].file=&input_file;handles[1].rights=GENERIC_READ|GENERIC_WRITE;
    handles[2].file=&output_file;handles[2].rights=GENERIC_READ;
    handles[3].file=&output_file;handles[3].rights=GENERIC_WRITE;
    handles[4].file=&input_file;handles[4].rights=FILE_READ_DATA;
    handles[5].file=&null_file;handles[5].rights=GENERIC_READ|GENERIC_WRITE;
    handles[6].file=&normal_file;handles[6].rights=GENERIC_READ|GENERIC_WRITE;
    /* Open through the real route and constructor before querying identity.
     * Output identity is independent of each handle's requested rights. */
    static const uint32_t open_rights[]={0,GENERIC_READ,GENERIC_WRITE,GENERIC_ALL,FILE_READ_DATA,FILE_WRITE_DATA};
    for(unsigned endpoint=0;endpoint<2;++endpoint) for(unsigned i=0;i<sizeof open_rights/sizeof open_rights[0];++i) {
        uint64_t h=0;struct iosb io={UINT64_MAX,UINT64_MAX};int opened_kind=-8;
        CHECK(create_console_route(endpoint ? "\\??\\CONOUT$" : "\\??\\CONIN$",open_rights[i],&h,&io)==0);
        CHECK(h>=7 && h<16 && handles[h].file->console==(int)endpoint+1);
        CHECK(io.status==0 && io.information==IO_OPENED);
        CHECK(handles[h].rights==open_rights[i]);
        CHECK(k32_console_handle(h,&opened_kind) && opened_kind==(int)endpoint);
        endpoint_queries(h,endpoint?output:input,endpoint?8:7);
        handle_close(NULL,h);CHECK(live_objects==0);
    }
    for(allocation_failure=1;allocation_failure<=2;++allocation_failure) {
        uint64_t h=0;struct iosb io={UINT64_MAX,UINT64_MAX};
        CHECK(create_console_route("\\??\\CONOUT$",GENERIC_WRITE,&h,&io)==STATUS_NO_MEMORY);
        CHECK(!h && live_objects==0 && io.information==UINT64_MAX);
    }
    allocation_failure=0;insertion_failure=1;
    {uint64_t h=0;struct iosb io={UINT64_MAX,UINT64_MAX};
     CHECK(create_console_route("\\??\\CONOUT$",GENERIC_WRITE,&h,&io)==STATUS_ACCESS_DENIED);
     CHECK(!h && live_objects==0 && io.information==UINT64_MAX);}
    insertion_failure=0;
    {struct iosb io={UINT64_MAX,UINT64_MAX};
     CHECK(create_console_route("\\??\\CONOUT$",GENERIC_WRITE,NULL,&io)==STATUS_ACCESS_VIOLATION);
     CHECK(live_objects==0 && io.information==UINT64_MAX);}
    endpoint_queries(1,input,7);endpoint_queries(2,output,8);
    int kind=-8;
    CHECK(k32_console_handle(1,&kind)&&kind==0);CHECK(k32_console_handle(2,&kind)&&kind==1);
    CHECK(k32_console_handle(3,&kind)&&kind==1);CHECK(k32_console_handle(4,&kind)&&kind==0);
    standard_output=1;CHECK(k32_console_handle(standard_output,&kind)&&kind==0);
    standard_output=6;CHECK(!k32_console_handle(standard_output,&kind));
    CHECK(!k32_console_handle(5,&kind));CHECK(!k32_console_handle(6,&kind));CHECK(!k32_console_handle(15,&kind));
    CHECK(!k32_console_handle(1,0));
    CHECK(k32_console_check(1,0,GENERIC_READ));CHECK(k32_console_check(1,0,GENERIC_WRITE));
    CHECK(!k32_console_check(1,1,GENERIC_WRITE));CHECK(error_code==ERROR_INVALID_HANDLE);
    CHECK(k32_console_check(2,1,GENERIC_READ));CHECK(!k32_console_check(2,1,GENERIC_WRITE));CHECK(error_code==ERROR_ACCESS_DENIED);
    CHECK(k32_console_check(4,0,GENERIC_READ));CHECK(!k32_console_check(4,0,GENERIC_WRITE));
    attached=0;CHECK(!k32_console_check(1,0,GENERIC_READ));attached=1;
    query_object_error=1;CHECK(!k32_console_check(1,0,GENERIC_READ));query_object_error=0;
    volume_error=1;CHECK(!k32_console_handle(1,&kind));volume_error=0;
    name_error=1;CHECK(!k32_console_handle(1,&kind));name_error=0;
    for(malformed=1;malformed<=15;++malformed) {
        kind=-8;
        if(malformed==4) { CHECK(!k32_console_handle(2,&kind)); }
        else CHECK(!k32_console_handle(1,&kind));
        CHECK(kind==-8);
    }
    malformed=0;
    static const uint32_t rights[]={0,GENERIC_READ,GENERIC_WRITE,GENERIC_READ|GENERIC_WRITE,GENERIC_ALL,
                                   FILE_READ_DATA,FILE_WRITE_DATA,FILE_READ_DATA|FILE_WRITE_DATA,0x100000};
    for(size_t i=0;i<sizeof rights/sizeof rights[0];++i) {
        handles[1].rights=rights[i];handles[2].rights=rights[i];
        CHECK(k32_console_handle(1,&kind)&&kind==0);CHECK(k32_console_handle(2,&kind)&&kind==1);
        for(int want=0;want<2;++want) {
            uint32_t access=want?GENERIC_WRITE:GENERIC_READ;
            int allowed=!!(rights[i]&(access|GENERIC_ALL|(want?FILE_WRITE_DATA:FILE_READ_DATA)));
            CHECK(k32_console_check(1,0,access)==allowed);CHECK(k32_console_check(2,1,access)==allowed);
        }
    }
    uint16_t w[10];uint32_t n=999;memset(w,0xa5,sizeof w);
    CHECK(file_name_utf16(&input_file,w,7,&n)==0&&n==7);CHECK(w[7]==0xa5a5);
    CHECK(file_name_utf16(&output_file,w,7,&n)==STATUS_OBJECT_NAME_INVALID);CHECK(w[7]==0xa5a5);
    CHECK(file_name_utf16(&input_file,w,0,&n)==STATUS_OBJECT_NAME_INVALID);
    printf("actual production console bodies: %d checks, %d failures\n",checks,failures);
    return failures?1:0;
}
