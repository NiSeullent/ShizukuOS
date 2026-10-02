/* SPDX-License-Identifier: GPL-2.0-only
 * Exercise extracted, hash-bound production converter/MoveFileExW bytes.
 * Only OS dependencies are mocked; no native Windows execution is claimed.
 * CAPACITY_CONSISTENCY checks source/destination array capacities at compile
 * time. The historical unmodified function is never executed by this test.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint16_t WCHAR;
typedef const WCHAR *LPCWSTR;
typedef uint8_t BYTE;
typedef uint32_t ULONG, DWORD;
typedef int32_t NTSTATUS;
typedef int BOOL;
typedef void *HANDLE;
typedef struct { uintptr_t Status, Information; } SHZ_IO_STATUS_BLOCK;
#define K32API
#define WINAPI
#define TRUE 1
#define FALSE 0
#define DELETE 0x00010000u
#define FILE_OPEN_D 1u
#define MOVEFILE_REPLACE_EXISTING 1u
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_OBJECT_NAME_INVALID ((NTSTATUS)0xc0000033u)
#define ERROR_FILENAME_EXCED_RANGE 206u

struct rename_layout { BYTE replace, pad[7]; HANDLE root; ULONG len; WCHAR name[320]; };
_Static_assert(sizeof(WCHAR)==2 && sizeof(HANDLE)==8, "host must model Win64 widths");
_Static_assert(offsetof(struct rename_layout,name)==20, "Win64 counted name offset");
_Static_assert(sizeof(((struct rename_layout *)0)->name)==640, "name subobject size");

static unsigned checks, open_calls, convert_calls, close_calls, set_calls, live;
static unsigned stub_length, fullpath_calls;
static int controlled;
static NTSTATUS open_status, convert_status, set_status;
static DWORD last_error;
static ULONG observed_size, observed_name_bytes;
static BYTE observed_replace;
static unsigned expected_length;
static int expected_real;
static size_t forced_length;
static char order[32];
static unsigned order_used;
static HANDLE acquired;
static void step(char c) { if(order_used<sizeof(order)-1) order[order_used++]=c; order[order_used]=0; }
static void expect(int condition,const char *label) {
    ++checks;
    if(!condition) { fprintf(stderr,"FAIL %s: open=%u convert=%u set=%u close=%u live=%u error=%u order=%s\n",
        label,open_calls,convert_calls,set_calls,close_calls,live,last_error,order); exit(1); }
}
static void cwd_init(void) { }
static DWORD GetFullPathNameW(LPCWSTR path,DWORD cap,WCHAR *out,WCHAR **part) {
    (void)path;(void)cap;(void)out;(void)part;++fullpath_calls;return 0;
}
static size_t k32_wlen(const WCHAR *s) {
    size_t n=0;if(forced_length)return forced_length;while(s[n])++n;return n;
}
static NTSTATUS open_path(LPCWSTR path,ULONG access,ULONG disposition,ULONG options,HANDLE *out,uintptr_t *info) {
    (void)path;(void)info;++open_calls;step('O');
    expect(access==DELETE && disposition==FILE_OPEN_D && options==0,"source open parameters");
    if(open_status) return open_status;
    acquired=(HANDLE)(uintptr_t)0x1234;*out=acquired;live=1;return 0;
}
static NTSTATUS NtClose(HANDLE h) {
    ++close_calls;step('X');expect(h==acquired && live==1,"close acquired source once");live=0;return 0;
}
static DWORD k32_nt_error(NTSTATUS status) { step('E');last_error=(DWORD)status;return last_error; }
static void shz_set_last_error(DWORD error) { step('L');last_error=error; }
static NTSTATUS NtSetInformationFile(HANDLE h,SHZ_IO_STATUS_BLOCK *iosb,const void *buf,ULONG size,ULONG cls) {
    const unsigned char *bytes=buf;ULONG counted;unsigned i;BYTE replace;
    (void)iosb;++set_calls;step('S');
    expect(h==acquired && live==1 && cls==10,"rename syscall handle/class");
    expect(size>=20,"counted header size");
    memcpy(&counted,bytes+16,4);memcpy(&replace,bytes,1);
    observed_size=size;observed_name_bytes=counted;observed_replace=replace;
    expect(size==20+counted && !(counted&1),"counted bytes exact/no NUL requirement");
    expect(counted==expected_length*2,"requested name length passed unchanged");
    for(i=1;i<16;i++) expect(bytes[i]==0,"header pad/root zero");
    for(i=0;i<expected_length;i++) {
        static const WCHAR prefix[4]={'\\','?','?','\\'};
        WCHAR actual,want=expected_real ? (i<4 ? prefix[i] : (WCHAR)'A') : (WCHAR)'Q';
        memcpy(&actual,bytes+20+i*2,2);
        expect(actual==want,"literal converted name payload copied intact");
    }
    return set_status;
}

/* Includes contain exact production function bytes, emitted by the runner. */
#include "production_converter.inc"
static NTSTATUS dispatched_converter(LPCWSTR path,WCHAR *out,size_t cap) {
    unsigned i;++convert_calls;step('C');
    if(convert_status)return convert_status;
    if(!controlled)return k32_dos_to_nt(path,out,cap);
    expect(stub_length<cap,"controlled output fits converter buffer");
    for(i=0;i<stub_length;i++) {out[i]=(WCHAR)'Q';}
    out[stub_length]=0;return 0;
}

#ifdef CAPACITY_CONSISTENCY
#define memcpy(dst,src,bytes) do { \
    _Static_assert(sizeof(dst)>=sizeof(src),"rename name buffer covers converter buffer"); \
    __builtin_memcpy((dst),(src),(bytes)); \
} while(0)
#endif
#define k32_dos_to_nt dispatched_converter
#include "production_movefileex.inc"
#undef k32_dos_to_nt
#ifdef CAPACITY_CONSISTENCY
#undef memcpy
#endif

static void reset(void) {
    open_calls=convert_calls=close_calls=set_calls=live=fullpath_calls=0;
    controlled=0;stub_length=0;open_status=convert_status=set_status=0;
    last_error=999;order_used=0;order[0]=0;acquired=0;
    observed_size=observed_name_bytes=0;observed_replace=0;forced_length=0;
}
static void make_verbatim(WCHAR *path,unsigned payload) {
    unsigned i;path[0]='\\';path[1]='\\';path[2]='?';path[3]='\\';
    for(i=0;i<payload;i++) {path[4+i]=(WCHAR)'A';}
    path[4+payload]=0;
}
static void accepted(unsigned nt_length,int real,DWORD flags) {
    WCHAR path[324];BOOL result;reset();
    if(real)make_verbatim(path,nt_length-4);else {controlled=1;stub_length=nt_length;path[0]=0;}
    expected_length=nt_length;expected_real=real;result=MoveFileExW(path,path,flags);
    expect(result==TRUE,"bounded counted name accepted");
    expect(open_calls==1 && convert_calls==1 && set_calls==1 && close_calls==1 && !live,"success handle lifecycle");
    expect(observed_size==20+nt_length*2 && observed_name_bytes==nt_length*2,"exact NT counted bytes");
    expect(observed_replace==(BYTE)((flags&1)!=0),"replace flag unchanged");
    expect(!strcmp(order,"OCSX"),"successful call ordering");
    expect(fullpath_calls==0,"verbatim uses genuine converter fast path");
}
static void rejected_reported_length(void) {
    WCHAR path[324];BOOL result;reset();make_verbatim(path,1);
    /* Report an oversized count without making, copying, or reading an
       oversized buffer. Only the defensive guard branch is under test. */
    forced_length=321;result=MoveFileExW(path,path,MOVEFILE_REPLACE_EXISTING);
    expect(result==FALSE,"oversized member rejected");
    expect(last_error==206,"ERROR_FILENAME_EXCED_RANGE on oversized path");
    expect(open_calls==1 && convert_calls==1 && !set_calls && close_calls==1 && !live,"rejection closes handle without syscall");
    expect(!strcmp(order,"OCXL"),"reject before copy/syscall, error after close");
}
static void errors(void) {
    WCHAR path[324];BOOL result;make_verbatim(path,1);
    reset();open_status=(NTSTATUS)0xc0000022u;result=MoveFileExW(path,path,1);
    expect(!result && open_calls==1 && !convert_calls && !close_calls && !set_calls && !live,"open failure has no acquired handle");
    expect(last_error==(DWORD)open_status && !strcmp(order,"OE"),"open error preserved");
    reset();convert_status=STATUS_OBJECT_NAME_INVALID;result=MoveFileExW(path,path,1);
    expect(!result && close_calls==1 && !live && !set_calls,"converter error cleanup");
    expect(last_error==(DWORD)convert_status && !strcmp(order,"OCXE"),"converter error preserved");
    reset();make_verbatim(path,298);result=MoveFileExW(path,path,1);
    expect(!result && close_calls==1 && !live && !set_calls,"real converter rejects payload298");
    expect(last_error==(DWORD)STATUS_OBJECT_NAME_INVALID,"real converter error preserved");
    reset();make_verbatim(path,1);expected_length=5;expected_real=1;set_status=(NTSTATUS)0xc0000035u;result=MoveFileExW(path,path,1);
    expect(!result && close_calls==1 && !live && set_calls==1,"syscall failure cleanup");
    expect(last_error==(DWORD)set_status && !strcmp(order,"OCSXE"),"syscall error preserved");
}
int main(int argc,char **argv) {
    unsigned n;
    if(argc!=2)return 2;
    if(!strcmp(argv[1],"--all")) {
        accepted(5,1,0);accepted(299,1,1);accepted(300,1,1);accepted(301,1,1);
        accepted(299,0,0);accepted(300,0,1);
        for(n=301;n<=319;n++)accepted(n,0,1);
        rejected_reported_length();
        errors();
    } else return 2;
    printf("PASS %u production function host checks (native execution false)\n",checks);return 0;
}
