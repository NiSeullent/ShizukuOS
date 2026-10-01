/* SPDX-License-Identifier: GPL-2.0-only
 * Original Win98 thread/UTC/timezone path; no registration or fabricated time. */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#ifdef M98_SCRIPT_PLATFORM_MOCK
#include "m98_trident_script_win32_mock.h"
#else
#include <windows.h>
#endif
#include <stdint.h>
#include <time.h>
#ifdef M98_SCRIPT_PLATFORM_MOCK
typedef int32_t m98_native_time_t;
#else
typedef time_t m98_native_time_t;
#endif
#include <stdarg.h>
#include <float.h>
#include "m98_trident_script_port.h"
_Static_assert(sizeof(double)==8&&DBL_MANT_DIG==53,"binary64 JS numbers");
_Static_assert(LDBL_MANT_DIG==64&&LDBL_MAX_EXP==16384,"native x87 extended type");
static int (__cdecl *original_vsnprintf)(char *,size_t,const char *,va_list);
_Static_assert(sizeof(m98_native_time_t)==4,"original Win98 MSVCRT time ABI");
static struct tm *(__cdecl *original_gmtime)(const m98_native_time_t *);
static struct tm *(__cdecl *original_localtime)(const m98_native_time_t *);
static m98_native_time_t (__cdecl *original_mktime)(struct tm *);
static double (__cdecl *original_sin)(double);
static double (__cdecl *original_cos)(double);
static double (__cdecl *original_tan)(double);
static double (__cdecl *original_acos)(double);
static double (__cdecl *original_asin)(double);
static double (__cdecl *original_atan)(double);
static double (__cdecl *original_exp)(double);
static double (__cdecl *original_log)(double);
static double (__cdecl *original_log10)(double);
static double (__cdecl *original_sqrt)(double);
static double (__cdecl *original_floor)(double);
static double (__cdecl *original_ceil)(double);
static double (__cdecl *original_fabs)(double);
static double (__cdecl *original_sinh)(double);
static double (__cdecl *original_cosh)(double);
static double (__cdecl *original_tanh)(double);
static double (__cdecl *original_atan2)(double,double),(__cdecl *original_fmod)(double,double);
static double (__cdecl *original_frexp)(double,int *);
static double (__cdecl *original_ldexp)(double,int);
uint32_t m98_script_thread_id(void){return GetCurrentThreadId();}
int m98_script_platform_ready(void){HMODULE crt;char expected[MAX_PATH],actual[MAX_PATH];UINT n;DWORD got;size_t i;
    n=GetSystemDirectoryA(expected,sizeof(expected));if(!n||n>=MAX_PATH-12)return -1;
    expected[n++]='\\';for(i=0;i<sizeof("MSVCRT.DLL");++i)expected[n+i]="MSVCRT.DLL"[i];
    crt=GetModuleHandleA("MSVCRT.DLL");if(!crt)return -1;
    got=GetModuleFileNameA(crt,actual,sizeof(actual));if(!got||got>=sizeof(actual)||lstrcmpiA(actual,expected))return -1;
    TIME_ZONE_INFORMATION zone;if(GetTimeZoneInformation(&zone)==TIME_ZONE_ID_INVALID)return -1;
#define BIND(field,name) do{FARPROC p=GetProcAddress(crt,name);size_t k;if(!p||sizeof(p)!=sizeof(field))return -1; \
    for(k=0;k<sizeof(field);++k)((unsigned char *)&field)[k]=((unsigned char *)&p)[k];}while(0)
    BIND(original_vsnprintf,"_vsnprintf");
    BIND(original_sin,"sin");
    BIND(original_cos,"cos");
    BIND(original_tan,"tan");
    BIND(original_acos,"acos");
    BIND(original_asin,"asin");
    BIND(original_atan,"atan");
    BIND(original_exp,"exp");
    BIND(original_log,"log");
    BIND(original_log10,"log10");
    BIND(original_sqrt,"sqrt");
    BIND(original_floor,"floor");
    BIND(original_ceil,"ceil");
    BIND(original_fabs,"fabs");
    BIND(original_sinh,"sinh");
    BIND(original_cosh,"cosh");
    BIND(original_tanh,"tanh");
    BIND(original_atan2,"atan2");
    BIND(original_fmod,"fmod");
    BIND(original_frexp,"frexp");
    BIND(original_ldexp,"ldexp");
    BIND(original_gmtime,"gmtime");BIND(original_localtime,"localtime");BIND(original_mktime,"mktime");
#undef BIND
    return 0;
}
/* The actual old CRT applies the installed local timezone. QuickJS's upstream
 * 32-bit time_t clamp remains explicit; this is not historical Intl support. */
struct tm *m98_qjs_gmtime(const m98_native_time_t *p){return original_gmtime(p);}
struct tm *m98_qjs_localtime(const m98_native_time_t *p){return original_localtime(p);}
m98_native_time_t m98_qjs_mktime(struct tm *p){return original_mktime(p);}
int64_t m98_qjs_clock_us(void){FILETIME file;uint64_t ticks;GetSystemTimeAsFileTime(&file);
    ticks=((uint64_t)file.dwHighDateTime<<32)|file.dwLowDateTime;
    return ticks>=UINT64_C(116444736000000000)?(int64_t)((ticks-UINT64_C(116444736000000000))/10):
           -(int64_t)((UINT64_C(116444736000000000)-ticks)/10);
}
BOOL WINAPI DllMain(HINSTANCE instance,DWORD reason,LPVOID reserved){(void)instance;(void)reason;(void)reserved;return TRUE;}

int m98_script_legacy_vsnprintf(char *p,size_t n,const char *f,va_list a){return original_vsnprintf(p,n,f,a);}
double m98_math_sin(double x){volatile double y=original_sin(x);return y;}
double m98_math_cos(double x){volatile double y=original_cos(x);return y;}
double m98_math_tan(double x){volatile double y=original_tan(x);return y;}
double m98_math_acos(double x){volatile double y=original_acos(x);return y;}
double m98_math_asin(double x){volatile double y=original_asin(x);return y;}
double m98_math_atan(double x){volatile double y=original_atan(x);return y;}
double m98_math_exp(double x){volatile double y=original_exp(x);return y;}
double m98_math_log(double x){volatile double y=original_log(x);return y;}
double m98_math_log10(double x){volatile double y=original_log10(x);return y;}
double m98_math_sqrt(double x){volatile double y=original_sqrt(x);return y;}
double m98_math_floor(double x){volatile double y=original_floor(x);return y;}
double m98_math_ceil(double x){volatile double y=original_ceil(x);return y;}
double m98_math_fabs(double x){volatile double y=original_fabs(x);return y;}
double m98_math_sinh(double x){volatile double y=original_sinh(x);return y;}
double m98_math_cosh(double x){volatile double y=original_cosh(x);return y;}
double m98_math_tanh(double x){volatile double y=original_tanh(x);return y;}
double m98_math_atan2(double x,double y){volatile double z=original_atan2(x,y);return z;}
double m98_math_fmod(double x,double y){volatile double z=original_fmod(x,y);return z;}
double m98_math_frexp(double x,int *n){return original_frexp(x,n);}
double m98_math_ldexp(double x,int n){volatile double z=original_ldexp(x,n);return z;}
long double m98_math_sqrtl(long double x){long double y;__asm__("fsqrt":"=t"(y):"0"(x));return y;}
