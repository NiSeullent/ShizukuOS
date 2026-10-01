/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _WIN32
#define _GNU_SOURCE
#include <sys/syscall.h>
#include <unistd.h>
#endif
#include "m98_wasm_platform_internal.h"
#include "platform_api_vmcore.h"
#ifdef M98_WASM_TESTING
static unsigned test_ready_mode;
void m98_wasm_test_platform_ready_mode(unsigned mode){test_ready_mode=mode;}
static int test_ready_clobber(void){unsigned short changed=0x077f;if(test_ready_mode)__asm__ volatile("fninit\n\tfldcw %0\n\tfld1"::"m"(changed):"memory");return test_ready_mode==2;}
#endif
#ifdef _WIN32
static int (__cdecl *original_vsnprintf)(char *,size_t,const char *,va_list);
uint32_t m98_wasm_thread_id(void){return GetCurrentThreadId();}
int m98_wasm_platform_ready(void){HMODULE crt;char expected[MAX_PATH],actual[MAX_PATH];UINT n;DWORD got;FARPROC p;
#ifdef M98_WASM_TESTING
 if(test_ready_clobber())return -1;
#endif
 n=GetSystemDirectoryA(expected,MAX_PATH);if(!n||n>=MAX_PATH-12)return -1;
 memcpy(expected+n,"\\MSVCRT.DLL",12);crt=GetModuleHandleA("MSVCRT.DLL");if(!crt)return -1;
 got=GetModuleFileNameA(crt,actual,MAX_PATH);if(!got||got>=MAX_PATH||lstrcmpiA(actual,expected))return -1;
 p=GetProcAddress(crt,"_vsnprintf");if(!p||sizeof(p)!=sizeof(original_vsnprintf))return -1;
 memcpy(&original_vsnprintf,&p,sizeof(p));return 0;
}
int m98_wasm_vsnprintf(char *p,size_t n,const char *f,va_list a){int r;if(!n)return -1;r=original_vsnprintf(p,n,f,a);p[n-1]=0;return r;}
#else
uint32_t m98_wasm_thread_id(void){return (uint32_t)syscall(SYS_gettid);}
int m98_wasm_platform_ready(void){
#ifdef M98_WASM_TESTING
 if(test_ready_clobber())return -1;
#endif
 return 0;}
#undef vsnprintf
int m98_wasm_vsnprintf(char *p,size_t n,const char *f,va_list a){return vsnprintf(p,n,f,a);}
#endif
int m98_wasm_snprintf(char *p,size_t n,const char *f,...){int r;va_list a;va_start(a,f);r=m98_wasm_vsnprintf(p,n,f,a);va_end(a);return r;}
int bh_platform_init(void){return 0;}
void bh_platform_destroy(void){}
void *os_malloc(unsigned n){return malloc(n);}
void *os_realloc(void *p,unsigned n){return realloc(p,n);}
void os_free(void *p){free(p);}
int os_printf(const char *f,...){int r;va_list a;va_start(a,f);r=os_vprintf(f,a);va_end(a);return r;}
int os_vprintf(const char *f,va_list a){char b[512];return m98_wasm_vsnprintf(b,sizeof(b),f,a);}
uint64 os_time_get_boot_us(void){
#ifdef _WIN32
 return (uint64)GetTickCount()*1000;
#else
 struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64)t.tv_sec*1000000+(uint64)t.tv_nsec/1000;
#endif
}
uint64 os_time_thread_cputime_us(void){
#ifdef _WIN32
 /* Win98 supplies no original GetThreadTimes; CPU profiling is disabled. */
 return 0;
#else
 struct timespec t;if(clock_gettime(CLOCK_THREAD_CPUTIME_ID,&t))return 0;return (uint64)t.tv_sec*1000000+(uint64)t.tv_nsec/1000;
#endif
}
korp_tid os_self_thread(void){return (korp_tid)m98_wasm_thread_id();}
unsigned os_getpagesize(void){
#ifdef _WIN32
 SYSTEM_INFO info;GetSystemInfo(&info);return info.dwPageSize;
#else
 long n=sysconf(_SC_PAGESIZE);return n>0?(unsigned)n:0;
#endif
}
uint8 *os_thread_get_stack_boundary(void){
#ifdef _WIN32
 uint8 *p;__asm__ volatile("movl %%fs:8,%0":"=r"(p));return p;
#else
 pthread_attr_t a;void *base;size_t size;
 if(pthread_getattr_np(pthread_self(),&a))return NULL;
 if(pthread_attr_getstack(&a,&base,&size)){pthread_attr_destroy(&a);return NULL;}
 pthread_attr_destroy(&a);return base;
#endif
}
int os_mutex_init(korp_mutex *p){
#ifdef _WIN32
 InitializeCriticalSection(p);return 0;
#else
 return pthread_mutex_init(p,NULL);
#endif
}
int os_recursive_mutex_init(korp_mutex *p){
#ifdef _WIN32
 return os_mutex_init(p);
#else
 pthread_mutexattr_t a;int r;if(pthread_mutexattr_init(&a))return -1;
 r=pthread_mutexattr_settype(&a,PTHREAD_MUTEX_RECURSIVE);if(!r)r=pthread_mutex_init(p,&a);pthread_mutexattr_destroy(&a);return r;
#endif
}
int os_mutex_destroy(korp_mutex *p){
#ifdef _WIN32
 DeleteCriticalSection(p);return 0;
#else
 return pthread_mutex_destroy(p);
#endif
}
int os_mutex_lock(korp_mutex *p){
#ifdef _WIN32
 EnterCriticalSection(p);return 0;
#else
 return pthread_mutex_lock(p);
#endif
}
int os_mutex_unlock(korp_mutex *p){
#ifdef _WIN32
 LeaveCriticalSection(p);return 0;
#else
 return pthread_mutex_unlock(p);
#endif
}
int os_thread_env_init(void){return 0;}
void os_thread_env_destroy(void){}
bool os_thread_env_inited(void){return true;}

/* Optional process-wide profiling is unavailable in this bounded profile.
 * Return the documented failure; never invent successful memory statistics. */
int os_dumps_proc_mem_info(char *out,unsigned size){if(out&&size)out[0]=0;return -1;}

/* Logging clock uses the same actual monotonic platform counter as the VM. */
uint64 bh_get_tick_ms(void){return os_time_get_boot_us()/1000;}

/* Original reentrant in-place tokenizer for the upstream Windows helper. */
char *m98_wasm_strtok_r(char *text,const char *delimiters,char **next){char *start,*end;
 if(!delimiters||!next)return NULL;start=text?text:*next;if(!start)return NULL;
 while(*start&&strchr(delimiters,*start))start++;
 if(!*start){*next=start;return NULL;}end=start;
 while(*end&&!strchr(delimiters,*end))end++;
 if(*end){*end=0;*next=end+1;}else *next=end;return start;
}
