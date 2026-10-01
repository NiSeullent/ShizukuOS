/* SPDX-License-Identifier: GPL-2.0-only
 * Independent libc/math expectations, exact existing CRT helpers, and explicit
 * deterministic OS-contract adapters with failure injection. No guest claims. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>
#include <stddef.h>
#include <setjmp.h>
#include <pthread.h>
#include "ucrt_legacy_host_contract.h"
#include "legacy_calls.inc"
#include "legacy_vectors.inc"

extern double legacy_fabs(double);
extern unsigned char *_mbschr(const unsigned char *,unsigned);
extern unsigned char *_mbsinc(const unsigned char *);
extern unsigned char *_mbsdec(const unsigned char *,const unsigned char *);
extern int _mbsnbcmp(const unsigned char *,const unsigned char *,size_t);
extern int _mbsnbcpy_s(unsigned char *,size_t,const unsigned char *,size_t);
extern int _chmod(const char *,int);
extern char *_mktemp(char *);
extern int _resetstkoflw(void);
extern void _searchenv(const char *,const char *,char *);
extern wchar16 *_wgetdcwd(int,wchar16 *,int);
extern void _wassert(const wchar16 *,const wchar16 *,unsigned);
extern int system(const char *);
extern char *legacy_setlocale(int,const char *);
extern unsigned legacy____lc_codepage_func(void);
extern int legacy____mb_cur_max_func(void);

static unsigned checks,allocations,live,fail_allocation;
static _Thread_local crt_ptd ptd;
static _Thread_local unsigned invalid_calls;
static os_dword last_error;
static int conversion_fail,attribute_error,set_error,full_second_fail,full_grows,cwd_second_fail;
static unsigned full_calls,cwd_calls,set_calls;
static char console[2048]; static size_t console_length;
static jmp_buf fatal_context; static int fatal_expected;
static int binary_available=1,binary_kind=6,create_error,wait_error,exit_error,close_error;
static unsigned create_calls,close_calls,closed_mask;
static char command_line[1024];
static const char *environment_name,*environment_value,*comspec;
struct file_record {char path[512];os_dword attributes;};
static struct file_record files[64];static unsigned file_count;
#define CHECK(x) do { ++checks; if(!(x)) {fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x);exit(2);} } while(0)

int *crt_errno_ptr(void) {return &ptd.err;}
unsigned long *crt_doserrno_ptr(void) {return &ptd.doserr;}
crt_ptd *crt_getptd(void) {return &ptd;}
void crt_invalid_parameter(void) {++invalid_calls;}
void crt_lock(int which) {(void)which;}
void crt_unlock(int which) {(void)which;}
void crt_dosmaperr(unsigned long error)
{
    ptd.doserr=error;
    ptd.err=(error==2 || error==3)?CRT_ENOENT:error==5?CRT_EACCES:error==8?CRT_ENOMEM:error==193?CRT_ENOEXEC:CRT_EINVAL;
}
void *crt_malloc(size_t size)
{
    void *p;
    ++allocations;
    if(fail_allocation && allocations==fail_allocation) {ptd.err=CRT_ENOMEM;return NULL;}
    p=malloc(size?size:1); if(p)++live;else ptd.err=CRT_ENOMEM;return p;
}
void crt_free(void *p) {if(p){CHECK(live>0);--live;free(p);}}
void legacy_abort(void) {if(fatal_expected)longjmp(fatal_context,1);fprintf(stderr,"unexpected abort\n");exit(4);}
int _dupenv_s(char **out,size_t *length,const char *name)
{
    const char *value=NULL;
    *out=NULL;if(length)*length=0;
    if(!strcmp(name,"COMSPEC"))value=comspec;
    else if(environment_name && !strcmp(name,environment_name))value=environment_value;
    if(value){size_t n=strlen(value)+1;*out=crt_malloc(n);if(!*out)return CRT_ENOMEM;memcpy(*out,value,n);if(length)*length=n;}
    return 0;
}
static void ascii(const wchar16 *wide,char *out,size_t capacity)
{
    size_t n=0;while(wide[n] && n+1<capacity){CHECK(wide[n]<128);out[n]=(char)wide[n];++n;}out[n]=0;
}
static size_t wide_length(const wchar16 *s) {size_t n=0;while(s[n])++n;return n;}
static void wide_copy(wchar16 *out,const char *s) {do{*out++=(unsigned char)*s;}while(*s++);}
static void absolute_name(const char *input,char *output,size_t capacity)
{
    if(input[0] && input[1]==':' && input[2]=='.' && !input[3])snprintf(output,capacity,"%c:\\%s",input[0],input[0]=='D'?"work":"lab");
    else if(input[0] && input[1]==':')snprintf(output,capacity,"%s",input);
    else snprintf(output,capacity,"C:\\lab\\%s",input);
}
static void add_file(const char *path,os_dword attrs)
{
    CHECK(file_count<64);snprintf(files[file_count].path,sizeof files[0].path,"%s",path);files[file_count++].attributes=attrs;
}
static struct file_record *find_file(const wchar16 *path)
{
    char narrow[512],absolute[512];unsigned i;
    ascii(path,narrow,sizeof narrow);absolute_name(narrow,absolute,sizeof absolute);
    for(i=0;i<file_count;i++)if(!strcmp(files[i].path,absolute))return &files[i];
    return NULL;
}
os_dword GetLastError(void) {return last_error;}
os_dword GetCurrentProcessId(void) {return 31415;}
int MultiByteToWideChar(unsigned cp,os_dword flags,const char *s,int count,wchar16 *out,int capacity)
{
    size_t n=count<0?strlen(s)+1:(size_t)count;
    CHECK(cp==OS_CP_ACP && !flags);
    if(conversion_fail){last_error=(os_dword)conversion_fail;return 0;}
    if(!out)return (int)n;
    if(capacity<(int)n){last_error=122;return 0;}
    for(size_t i=0;i<n;i++) out[i]=(unsigned char)s[i];
    return (int)n;
}
int WideCharToMultiByte(unsigned cp,os_dword flags,const wchar16 *s,int count,char *out,int capacity,const char *def,int *used)
{
    size_t n=count<0?wide_length(s)+1:(size_t)count;
    CHECK((cp==OS_CP_ACP || cp==OS_CP_UTF8) && !flags && !def && !used);
    if(conversion_fail){last_error=(os_dword)conversion_fail;return 0;}
    if(!out)return (int)n;
    if(capacity<(int)n){last_error=122;return 0;}
    for(size_t i=0;i<n;i++){CHECK(s[i]<128);out[i]=(char)s[i];}return (int)n;
}
os_dword GetFileAttributesW(const wchar16 *path)
{
    struct file_record *file=find_file(path);
    if(attribute_error){last_error=(os_dword)attribute_error;return OS_INVALID_FILE_ATTRIBUTES;}
    if(!file){last_error=2;return OS_INVALID_FILE_ATTRIBUTES;}
    return file->attributes;
}
os_bool SetFileAttributesW(const wchar16 *path,os_dword attrs)
{
    struct file_record *file=find_file(path);++set_calls;
    if(set_error){last_error=(os_dword)set_error;return 0;}
    if(!file){last_error=2;return 0;}file->attributes=attrs;return 1;
}
unsigned GetDriveTypeW(const wchar16 *root) {return root[0]=='C' || root[0]=='D'?3:1;}
os_dword GetFullPathNameW(const wchar16 *path,os_dword capacity,wchar16 *out,wchar16 **part)
{
    char narrow[512],absolute[512];size_t n;
    CHECK(!part);++full_calls;ascii(path,narrow,sizeof narrow);absolute_name(narrow,absolute,sizeof absolute);n=strlen(absolute);
    if(out && full_second_fail){last_error=5;return 0;}
    if(out && full_grows)return capacity+20;
    if(!out || capacity<=n)return (os_dword)(n+1);
    wide_copy(out,absolute);return (os_dword)n;
}
os_dword GetCurrentDirectoryW(os_dword capacity,wchar16 *out)
{
    ++cwd_calls;
    if(out && cwd_second_fail){last_error=5;return 0;}
    if(!out || capacity<7)return 7;
    wide_copy(out,"C:\\lab");return 6;
}
static os_bool binary_type(const wchar16 *path,os_dword *type)
{
    if(!find_file(path)){last_error=2;return 0;}*type=(os_dword)binary_kind;return 1;
}
os_handle GetModuleHandleW(const wchar16 *name) {char text[40];ascii(name,text,sizeof text);CHECK(!strcmp(text,"kernel32.dll"));return (void *)1;}
void *GetProcAddress(os_handle module,const char *name) {CHECK(module==(void *)1 && !strcmp(name,"GetBinaryTypeW"));return binary_available?(void *)binary_type:NULL;}
os_handle GetStdHandle(os_dword which) {return (void *)(uintptr_t)which;}
os_bool WriteFile(os_handle handle,const void *data,os_dword n,os_dword *written,void *overlapped)
{
    CHECK(handle==(void *)(uintptr_t)OS_STD_ERROR && !overlapped && console_length+n<sizeof console);
    memcpy(console+console_length,data,n);console_length+=n;console[console_length]=0;*written=n;return 1;
}
os_bool CreateProcessW(const wchar16 *app,wchar16 *line,void *pa,void *ta,os_bool inherit,os_dword flags,void *env,const wchar16 *cwd,os_startupinfow *si,void *pi)
{
    struct {os_handle process,thread;os_dword pid,tid;} *p=pi;
    CHECK(find_file(app) && !pa && !ta && inherit && !flags && !env && !cwd);
    CHECK(si->cb==104 && si->dwFlags==0x100 && si->hStdInput==GetStdHandle(OS_STD_INPUT));
    ascii(line,command_line,sizeof command_line);++create_calls;
    if(create_error){last_error=(os_dword)create_error;return 0;}
    p->process=(void *)0x11;p->thread=(void *)0x12;p->pid=101;p->tid=102;closed_mask=0;return 1;
}
os_dword WaitForSingleObject(os_handle handle,os_dword timeout) {CHECK(handle==(void *)0x11 && timeout==OS_INFINITE);if(wait_error){last_error=(os_dword)wait_error;return UINT32_MAX;}return 0;}
os_bool GetExitCodeProcess(os_handle handle,os_dword *code) {CHECK(handle==(void *)0x11);if(exit_error){last_error=(os_dword)exit_error;return 0;}*code=37;return 1;}
os_bool CloseHandle(os_handle handle)
{
    unsigned bit=handle==(void *)0x11?1:handle==(void *)0x12?2:0;CHECK(bit && !(closed_mask&bit));closed_mask|=bit;++close_calls;
    if(close_error){last_error=(os_dword)close_error;return 0;}return 1;
}

static void math_and_mbcs(void)
{
    unsigned char left[40],right[40],copied[40],reference[40];unsigned i,j;uint64_t seed=7;
    CHECK(sizeof(os_dword)==4 && sizeof(os_startupinfow)==104 && offsetof(os_startupinfow,hStdInput)==80);
    CHECK(legacy____lc_codepage_func()==0 && legacy____mb_cur_max_func()==1 && !strcmp(legacy_setlocale(0,NULL),"C"));
    CHECK(legacy_setlocale(0,"Korean")==NULL);
    for(i=0;i<sizeof absolute_vectors/sizeof absolute_vectors[0];i++) {
        union {double value;uint64_t bits;} source,out,expected;source.bits=absolute_vectors[i];out.value=legacy_fabs(source.value);expected.value=fabs(source.value);
        CHECK(out.bits==expected.bits);
    }
    for(i=0;i<2000;i++) {
        size_t length=i%31,count=i%37;
        for(j=0;j<length;j++){seed^=seed<<13;seed^=seed>>7;seed^=seed<<17;left[j]=(unsigned char)(seed%255+1);right[j]=left[j];}
        left[length]=right[length]=0;if(length && i%2)right[length/2]^=0x80;
        CHECK((_mbsnbcmp(left,right,count)<0)==(strncmp((char *)left,(char *)right,count)<0));
        CHECK((_mbsnbcmp(left,right,count)>0)==(strncmp((char *)left,(char *)right,count)>0));
        for(j=0;j<256;j++)CHECK(_mbschr(left,j)==(unsigned char *)strchr((char *)left,(int)j));
        for(j=0;j<=length;j++){CHECK(_mbsinc(left+j)==left+j+1);CHECK(_mbsdec(left,left+j)==(j?left+j-1:NULL));}
        memset(copied,0xcc,sizeof copied);memset(reference,0xcc,sizeof reference);
        size_t n=length<count?length:count;memcpy(reference,left,n);reference[n]=0;
        CHECK(_mbsnbcpy_s(copied,sizeof copied,left,count)==0 && !memcmp(copied,reference,sizeof copied));
    }
    unsigned before=invalid_calls;
    CHECK(_mbschr(NULL,0)==NULL && ptd.err==CRT_EINVAL && invalid_calls==before+1);
    CHECK(_mbsnbcmp(NULL,NULL,0)==0);
    CHECK(_mbsnbcmp(NULL,left,1)==CRT_INT_MAX && ptd.err==CRT_EINVAL);
    CHECK(_mbsinc(NULL)==NULL && _mbsdec(NULL,left)==NULL);
    memset(copied,0xcc,sizeof copied);CHECK(_mbsnbcpy_s(copied,3,(const unsigned char *)"abcd",4)==CRT_ERANGE && !copied[0]);
    CHECK(_mbsnbcpy_s(copied,3,(const unsigned char *)"abcd",SIZE_MAX)==CRT_STRUNCATE && !strcmp((char *)copied,"ab"));
    CHECK(_mbsnbcpy_s(copied,3,NULL,0)==0 && !copied[0]);
    CHECK(_mbsnbcpy_s(copied,3,NULL,1)==CRT_EINVAL && !copied[0]);
    CHECK(_mbschr((const unsigned char *)"abc",0x100)==(const unsigned char *)"abc"+3);
}
static void filesystem_contract(void)
{
    char pattern[80],out[260],huge[600];wchar16 wide[30],*allocated;unsigned before;
    add_file("C:\\lab\\file.bin",0x22);
    before=set_calls;CHECK(_chmod("file.bin",0x100)==0 && files[0].attributes==0x23 && set_calls==before+1);
    CHECK(_chmod("file.bin",0x180)==0 && files[0].attributes==0x22);
    set_error=5;CHECK(_chmod("file.bin",0x80)==-1 && ptd.err==CRT_EACCES && ptd.doserr==5 && files[0].attributes==0x22);set_error=0;
    CHECK(_chmod("absent.bin",0x80)==-1 && ptd.err==CRT_ENOENT);
    CHECK(_chmod(NULL,0x80)==-1 && ptd.err==CRT_EINVAL);
    strcpy(pattern,"newXXXXXX");ptd.err=73;CHECK(_mktemp(pattern)==pattern && !strcmp(pattern,"newa31415") && ptd.err==73);
    for(unsigned i=0;i<26;i++){snprintf(out,sizeof out,"C:\\lab\\new%c31415",'a'+i);add_file(out,128);}
    strcpy(pattern,"newXXXXXX");CHECK(!_mktemp(pattern) && !pattern[0] && ptd.err==CRT_EEXIST);
    strcpy(pattern,"badXXXXX");CHECK(!_mktemp(pattern) && !pattern[0] && ptd.err==CRT_EINVAL);
    attribute_error=5;strcpy(pattern,"deniedXXXXXX");CHECK(!_mktemp(pattern) && ptd.err==CRT_EACCES && !pattern[0]);attribute_error=0;
    attribute_error=3;strcpy(pattern,"dirXXXXXX");CHECK(!_mktemp(pattern) && ptd.doserr==3 && !pattern[0]);attribute_error=0;
    conversion_fail=2;strcpy(pattern,"convertXXXXXX");CHECK(!_mktemp(pattern) && !pattern[0]);conversion_fail=0;
    environment_name="LIB";environment_value="Z:\\missing;\"D:\\has space\";C:\\other";
    add_file("D:\\has space\\needle.dll",0x20);
    ptd.err=71;ptd.doserr=72;_searchenv("needle.dll","LIB",out);CHECK(!strcmp(out,"D:\\has space\\needle.dll") && ptd.err==71 && ptd.doserr==72);
    add_file("C:\\lab\\needle.dll",0x20);_searchenv("needle.dll","LIB",out);CHECK(!strcmp(out,"C:\\lab\\needle.dll"));
    _searchenv("absent.dll","NONE",out);CHECK(!out[0] && ptd.err==CRT_ENOENT);
    memset(huge,'x',sizeof huge);huge[500]=';';strcpy(huge+501,"D:\\has space");environment_value=huge;
    add_file("D:\\has space\\outside.dll",0x20);
    _searchenv("outside.dll","LIB",out);CHECK(!strcmp(out,"D:\\has space\\outside.dll"));
    _searchenv("","LIB",out);CHECK(!out[0] && ptd.err==CRT_ENOENT);
    full_second_fail=1;_searchenv("file.bin","LIB",out);CHECK(!out[0] && ptd.err==CRT_EACCES);full_second_fail=0;
    full_grows=1;_searchenv("file.bin","LIB",out);CHECK(!out[0] && ptd.err==CRT_ERANGE);full_grows=0;
    CHECK(_wgetdcwd(0,wide,30)==wide && wide[0]=='C' && wide[5]=='b' && !wide[6]);
    CHECK(_wgetdcwd(3,wide,30)==wide && wide[0]=='C' && !wide[6]);
    wide[0]=0x1234;unsigned full_before=full_calls;
    CHECK(!_wgetdcwd(4,wide,30) && ptd.err==CRT_ENOSYS && ptd.doserr==120 && wide[0]==0x1234 && full_calls==full_before && !live);
    CHECK(!_wgetdcwd(4,NULL,30) && ptd.err==CRT_ENOSYS && ptd.doserr==120 && !live);
    cwd_second_fail=1;CHECK(!_wgetdcwd(3,wide,30) && ptd.err==CRT_EACCES && !live);cwd_second_fail=0;
    fail_allocation=allocations+1;CHECK(!_wgetdcwd(3,wide,30) && ptd.err==CRT_ENOMEM && !live);fail_allocation=0;
    CHECK(!_wgetdcwd(0,wide,2) && ptd.err==CRT_ERANGE);
    allocated=_wgetdcwd(0,NULL,1);CHECK(allocated && allocated[0]=='C');crt_free(allocated);
    CHECK(!_wgetdcwd(27,wide,30) && ptd.err==CRT_EINVAL);
    CHECK(!_wgetdcwd(26,wide,30) && ptd.err==CRT_EACCES);
    CHECK(!_wgetdcwd(0,wide,0) && ptd.err==CRT_EINVAL);
    cwd_second_fail=1;CHECK(!_wgetdcwd(0,NULL,30) && ptd.err==CRT_EACCES && !live);cwd_second_fail=0;
    fail_allocation=allocations+1;CHECK(!_wgetdcwd(0,NULL,30) && ptd.err==CRT_ENOMEM);fail_allocation=0;
    CHECK(_resetstkoflw()==0 && ptd.err==CRT_ENOSYS && ptd.doserr==120 && !live);
}
static void process_contract(void)
{
    static const wchar16 expr[]={'x','>','0',0},file[]={'t','.','c',0};unsigned before;
    comspec="C:\\missing\\cmd.exe";CHECK(system(NULL)==0 && ptd.err==CRT_ENOENT && !create_calls);
    CHECK(system("exit 37")==-1 && ptd.err==CRT_ENOENT && !create_calls);
    add_file("C:\\bin\\cmd.exe",128);comspec="C:\\bin\\cmd.exe";
    binary_available=0;CHECK(system(NULL)==0 && ptd.err==CRT_ENOSYS);binary_available=1;
    binary_kind=0;CHECK(system("exit 37")==-1 && ptd.err==CRT_ENOEXEC && !create_calls);binary_kind=6;
    CHECK(system(NULL)==1 && !create_calls);
    CHECK(system("exit 37")==37 && !strcmp(command_line,"\"C:\\bin\\cmd.exe\" /c \"exit 37\"") && closed_mask==3 && close_calls==2);
    before=close_calls;create_error=5;CHECK(system("x")==-1 && ptd.err==CRT_EACCES && close_calls==before);create_error=0;
    before=close_calls;wait_error=6;CHECK(system("x")==-1 && close_calls==before+2 && closed_mask==3);wait_error=0;
    exit_error=5;CHECK(system("x")==-1 && ptd.err==CRT_EACCES && closed_mask==3);exit_error=0;
    close_error=6;CHECK(system("x")==-1 && closed_mask==3);close_error=0;
    fail_allocation=allocations+2;CHECK(system("x")==-1 && ptd.err==CRT_ENOMEM && !live);fail_allocation=0;
    fatal_expected=1;if(!setjmp(fatal_context)){_wassert(expr,file,4294967295u);CHECK(0);}fatal_expected=0;
    CHECK(!strcmp(console,"Assertion failed: x>0, file t.c, line 4294967295\n") && !live);
}
static void *worker(void *arg)
{
    unsigned marker=(unsigned)(uintptr_t)arg;
    ptd.err=(int)marker;
    for(unsigned i=0;i<1000;i++){unsigned char text[]={0x80,'x',0};if(_mbschr(text,0x80)!=text || _mbsinc(text)!=text+1 || _mbsdec(text,text+2)!=text+1 || _mbsnbcmp(text,text,3)!=0 || ptd.err!=(int)marker)return (void *)1;}
    return NULL;
}
int main(void)
{
    pthread_t a,b;void *ra,*rb;
    math_and_mbcs();filesystem_contract();process_contract();
    CHECK(!pthread_create(&a,NULL,worker,(void *)(uintptr_t)17) && !pthread_create(&b,NULL,worker,(void *)(uintptr_t)83));
    CHECK(!pthread_join(a,&ra) && !pthread_join(b,&rb) && !ra && !rb);
    CHECK(!live);
    printf("PASS %u checks; libc byte/string/math oracles, real CRT C locale/secure copy, explicit OS-error/ownership adapters, two pthreads\n",checks);
    return 0;
}
