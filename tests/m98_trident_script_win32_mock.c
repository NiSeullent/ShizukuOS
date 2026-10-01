/* SPDX-License-Identifier: GPL-2.0-only
 * Compile the actual production Win32 path with original API fault doubles.
 * This establishes gate/conversion behavior, not native API execution. */
#include "m98_trident_script_win32_mock.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <math.h>
static unsigned checks,bound;static int fail_directory,fail_module,fail_path,fail_zone,missing;
static uint64_t ticks;
#define C(x) do{++checks;if(!(x)){fprintf(stderr,"platform FAIL %d: %s\n",__LINE__,#x);exit(1);}}while(0)
DWORD GetCurrentThreadId(void){return 77;}
UINT GetSystemDirectoryA(char *p,UINT n){if(fail_directory)return fail_directory==1?0:MAX_PATH;const char path[]="C:\\WINDOWS\\SYSTEM";C(n>sizeof(path));memcpy(p,path,sizeof(path));return sizeof(path)-1;}
HMODULE GetModuleHandleA(const char *n){C(!strcmp(n,"MSVCRT.DLL"));return fail_module?NULL:(HMODULE)(uintptr_t)1;}
DWORD GetModuleFileNameA(HMODULE m,char *p,DWORD n){C(m==(HMODULE)(uintptr_t)1);if(fail_path==1)return 0;if(fail_path==2)return n;
    const char *path=fail_path==3?"C:\\GOPLAB\\MSVCRT.DLL":"c:\\windows\\system\\msvcrt.dll";size_t k=strlen(path);C(k<n);memcpy(p,path,k+1);return k;}
int lstrcmpiA(const char *a,const char *b){while(*a&&*b){unsigned x=(unsigned char)*a++,y=(unsigned char)*b++;if(x>='A'&&x<='Z')x+=32;if(y>='A'&&y<='Z')y+=32;if(x!=y)return 1;}return *a!=*b;}
DWORD GetTimeZoneInformation(TIME_ZONE_INFORMATION *p){p->dummy=0;return fail_zone?TIME_ZONE_ID_INVALID:0;}
void GetSystemTimeAsFileTime(FILETIME *p){p->dwLowDateTime=(uint32_t)ticks;p->dwHighDateTime=(uint32_t)(ticks>>32);}
static int legacy(char *p,size_t n,const char *f,va_list a){return vsnprintf(p,n,f,a);}
static struct tm t;
static struct tm *utc(const int32_t *p){t.tm_sec=*p;return &t;}
static struct tm *local(const int32_t *p){t.tm_sec=*p+1;return &t;}
static int32_t make(struct tm *p){return p->tm_sec+2;}
FARPROC GetProcAddress(HMODULE m,const char *name){C(m==(HMODULE)(uintptr_t)1);++bound;if(missing==(int)bound)return NULL;
#define RET(fn) do{__typeof__(&(fn)) p=&(fn);FARPROC result;_Static_assert(sizeof(result)==sizeof(p),"host function pointer");memcpy(&result,&p,sizeof(result));return result;}while(0)
    if(!strcmp(name,"_vsnprintf"))RET(legacy);
    if(!strcmp(name,"gmtime"))RET(utc);if(!strcmp(name,"localtime"))RET(local);if(!strcmp(name,"mktime"))RET(make);
#define MATCH(fn) if(!strcmp(name,#fn))RET(fn)
    MATCH(sin);MATCH(cos);MATCH(tan);MATCH(acos);MATCH(asin);MATCH(atan);MATCH(exp);MATCH(log);MATCH(log10);MATCH(sqrt);
    MATCH(floor);MATCH(ceil);MATCH(fabs);MATCH(sinh);MATCH(cosh);MATCH(tanh);MATCH(atan2);MATCH(fmod);MATCH(frexp);MATCH(ldexp);
#undef MATCH
#undef RET
    C(0);return NULL;
}
#define M98_SCRIPT_PLATFORM_MOCK
#include "../src/m98_trident_script_win32.c"
int main(void){int32_t second=5;unsigned total,i;
    bound=0;C(m98_script_platform_ready()==0);total=bound;C(total==24&&m98_script_thread_id()==77);
    C(m98_qjs_gmtime(&second)->tm_sec==5);C(m98_qjs_localtime(&second)->tm_sec==6);C(m98_qjs_mktime(&t)==8);
    C(m98_math_sqrt(4)==2&&m98_math_ldexp(1,3)==8&&m98_math_sqrtl(9)==3);
    ticks=UINT64_C(116444736000000000);C(m98_qjs_clock_us()==0);
    ticks+=UINT64_C(1234567890);C(m98_qjs_clock_us()==123456789);
    ticks=UINT64_C(116444736000000000)-123450;C(m98_qjs_clock_us()==-12345);
    ticks=0;C(m98_qjs_clock_us()==INT64_C(-11644473600000000));
    fail_directory=1;C(m98_script_platform_ready()!=0);fail_directory=2;C(m98_script_platform_ready()!=0);fail_directory=0;
    fail_module=1;C(m98_script_platform_ready()!=0);fail_module=0;
    for(i=1;i<=3;++i){fail_path=i;C(m98_script_platform_ready()!=0);}fail_path=0;
    fail_zone=1;C(m98_script_platform_ready()!=0);fail_zone=0;
    for(i=1;i<=total;++i){bound=0;missing=i;C(m98_script_platform_ready()!=0&&bound==i);}missing=0;
    bound=0;C(m98_script_platform_ready()==0&&bound==total);
    printf("PASS: actual Win32 platform %u assertions; path/export/UTC fault doubles, native pending\n",checks);return 0;
}
