/* SPDX-License-Identifier: GPL-2.0-only
 * Full unmodified production function bodies, platform headers adapted only.
 * Fixed independent Win32/RTL contract tables and real overlapping pthreads.
 */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sched.h>

typedef uint32_t DWORD, ULONG;
typedef int32_t NTSTATUS;
typedef int BOOL;
typedef DWORD *LPDWORD;
typedef ULONG *PULONG;
#define NTAPI
#define WINAPI
#define SHZ_EXPORT
#define K32API
#define TRUE 1
#define FALSE 0
#define SEM_FAILCRITICALERRORS 1u
#define SEM_NOGPFAULTERRORBOX 2u
#define SEM_NOOPENFILEERRORBOX 0x8000u
#define ERROR_INVALID_PARAMETER 87u
#define STATUS_INVALID_PARAMETER_1 ((NTSTATUS)0xc00000efu)
#define STATUS_SUCCESS ((NTSTATUS)0)

static _Thread_local _Alignas(16) unsigned char host_teb[0x2000];
static atomic_uint checks;
static uint64_t shz_teb(void) { return (uintptr_t)host_teb; }
static DWORD host_error(void) { DWORD value;memcpy(&value,host_teb+0x68,sizeof value);return value; }
static void shz_set_last_error(DWORD value) { memcpy(host_teb+0x68,&value,sizeof value); }
static DWORD k32_nt_error(NTSTATUS status) {
    if(status!=STATUS_INVALID_PARAMETER_1)abort();
    shz_set_last_error(ERROR_INVALID_PARAMETER);return ERROR_INVALID_PARAMETER;
}

#include "ntdll_thread_error_mode_production.inc"
#include "kernel32_thread_error_mode_production.inc"

#define CHECK(x) do { atomic_fetch_add(&checks,1);if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);exit(2);} } while(0)
static const DWORD win_modes[8]={0,1,2,3,0x8000,0x8001,0x8002,0x8003};
static const ULONG rtl_modes[8]={0,0x10,0x20,0x30,0x40,0x50,0x60,0x70};
static pthread_barrier_t gate;

static void reset_teb(void) {
    ULONG zero=0;memset(host_teb,0xa5,sizeof host_teb);
    memcpy(host_teb+0x16b0,&zero,sizeof zero);shz_set_last_error(0);
}
static void check_neighbors(void) {
    unsigned i;
    for(i=0;i<sizeof host_teb;++i)
        if(!((i>=0x16b0&&i<0x16b4)||(i>=0x68&&i<0x6c)))CHECK(host_teb[i]==0xa5);
}
static void *worker(void *arg) {
    unsigned index=(unsigned)(uintptr_t)arg,i,prior=index;ULONG old;
    reset_teb();CHECK(GetThreadErrorMode()==0&&RtlGetThreadErrorMode()==0);
    CHECK(SetThreadErrorMode(win_modes[index],NULL));
    pthread_barrier_wait(&gate);
    CHECK(GetThreadErrorMode()==win_modes[index]&&RtlGetThreadErrorMode()==rtl_modes[index]);
    pthread_barrier_wait(&gate);
    for(i=0;i<64;++i) {
        unsigned next=(index+i+1)%8;DWORD sentinel=0x77000000u+index;
        old=0xdeadbeef;shz_set_last_error(sentinel);
        CHECK(RtlSetThreadErrorMode(rtl_modes[next],&old)==0&&old==rtl_modes[prior]);
        sched_yield();
        CHECK(GetThreadErrorMode()==win_modes[next]&&host_error()==sentinel);
        prior=next;
    }
    check_neighbors();return NULL;
}

int main(void) {
    unsigned i,j,bit;DWORD old;ULONG native_old;
    pthread_t workers[8];reset_teb();
    _Static_assert(sizeof(ULONG)==4&&sizeof(DWORD)==4&&sizeof(NTSTATUS)==4,"Windows scalar ABI");
    CHECK(GetThreadErrorMode()==0&&RtlGetThreadErrorMode()==0);
    for(i=0;i<8;++i)for(j=0;j<8;++j) {
        CHECK(RtlSetThreadErrorMode(rtl_modes[i],NULL)==0);old=0xdeadbeef;
        shz_set_last_error(0x55110000u+i);
        CHECK(SetThreadErrorMode(win_modes[j],&old)&&old==win_modes[i]);
        CHECK(RtlGetThreadErrorMode()==rtl_modes[j]&&GetThreadErrorMode()==win_modes[j]);
        CHECK(host_error()==0x55110000u+i);
        native_old=0xdeadbeef;
        CHECK(RtlSetThreadErrorMode(rtl_modes[i],&native_old)==0&&native_old==rtl_modes[j]);
        CHECK(GetThreadErrorMode()==win_modes[i]&&host_error()==0x55110000u+i);
        CHECK(SetThreadErrorMode(win_modes[j],NULL)&&GetThreadErrorMode()==win_modes[j]);
    }
    for(i=0;i<8;++i)for(bit=0;bit<32;++bit) {
        DWORD unknown=(DWORD)1u<<bit;
        CHECK(RtlSetThreadErrorMode(rtl_modes[i],NULL)==0);
        if(!(unknown&0x8003u)) {
            old=0xdeadbeef;shz_set_last_error(0x66110000);
            CHECK(!SetThreadErrorMode(unknown|win_modes[i],&old));
            CHECK(old==0xdeadbeef&&host_error()==ERROR_INVALID_PARAMETER);
            CHECK(GetThreadErrorMode()==win_modes[i]&&RtlGetThreadErrorMode()==rtl_modes[i]);
        }
        if(!(unknown&0x70u)) {
            native_old=0xdeadbeef;shz_set_last_error(0x66120000);
            CHECK(RtlSetThreadErrorMode(unknown|rtl_modes[i],&native_old)==STATUS_INVALID_PARAMETER_1);
            CHECK(native_old==0xdeadbeef&&host_error()==0x66120000);
            CHECK(GetThreadErrorMode()==win_modes[i]&&RtlGetThreadErrorMode()==rtl_modes[i]);
        }
    }
    CHECK(!SetThreadErrorMode(4,(LPDWORD)(uintptr_t)1)&&host_error()==ERROR_INVALID_PARAMETER);
    CHECK(RtlSetThreadErrorMode(1,(PULONG)(uintptr_t)1)==STATUS_INVALID_PARAMETER_1);
    CHECK(RtlSetThreadErrorMode(0x70,NULL)==0);native_old=0;
    CHECK(RtlSetThreadErrorMode(0x10,&native_old)==0&&native_old==0x70);
    CHECK(*(ULONG *)(void *)(host_teb+0x16b0)==0x10);
    CHECK(RtlSetThreadErrorMode(0x70,NULL)==0);
    check_neighbors();
    CHECK(pthread_barrier_init(&gate,NULL,9)==0);
    for(i=0;i<8;++i)CHECK(pthread_create(&workers[i],NULL,worker,(void *)(uintptr_t)i)==0);
    pthread_barrier_wait(&gate);
    CHECK(RtlGetThreadErrorMode()==0x70&&GetThreadErrorMode()==0x8003);
    pthread_barrier_wait(&gate);
    for(i=0;i<8;++i)CHECK(pthread_join(workers[i],NULL)==0);
    CHECK(RtlGetThreadErrorMode()==0x70&&GetThreadErrorMode()==0x8003);
    CHECK(pthread_barrier_destroy(&gate)==0);
    printf("THREAD_ERROR_MODE_HOST: %u checks PASS\n",atomic_load(&checks));return 0;
}
