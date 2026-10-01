/* SPDX-License-Identifier: GPL-2.0-only -- own mapped code, zero native imports */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "fixture.h"
extern unsigned ntw_tls_compiler_word;
extern unsigned ntw_tls_compiler_read(void);
extern void ntw_tls_compiler_write(unsigned);
DWORD _tls_index=0xdeadbeefu;
static ci_observation *observation;
static DWORD process_attached;
void WINAPI CiBind(ci_observation *out) { observation=out; out->process_attach=process_attached; }
DWORD WINAPI CiWord(DWORD word) { DWORD prior=ntw_tls_compiler_read(); ntw_tls_compiler_write(word); return prior; }
static void WINAPI callback(void *base,DWORD reason,void *reserved)
{
    (void)base; (void)reserved;
    if(reason==DLL_PROCESS_ATTACH) { process_attached=ntw_tls_compiler_read()==0x1234abcdu; return; }
    if(!observation) return;
    if(reason==DLL_THREAD_ATTACH) {
        observation->tls_attach++;
        if(ntw_tls_compiler_read()!=0x1234abcdu) observation->failures++;
    }
    if(reason==DLL_THREAD_DETACH) {
        DWORD i=observation->tls_detach++;
        if(i<2) observation->retired_word[i]=ntw_tls_compiler_read(); else observation->failures++;
    }
    if(reason==DLL_PROCESS_DETACH) observation->process_detach++;
}
static PIMAGE_TLS_CALLBACK callbacks[]={callback,NULL};
const IMAGE_TLS_DIRECTORY32 _tls_used={
    (DWORD)(UINT_PTR)&ntw_tls_compiler_word,(DWORD)(UINT_PTR)&ntw_tls_compiler_word+4,
    (DWORD)(UINT_PTR)&_tls_index,(DWORD)(UINT_PTR)callbacks,28,0x00700000u
};
BOOL WINAPI DllMain(HINSTANCE base,DWORD reason,void *reserved)
{
    (void)base; (void)reserved;
    if(reason==DLL_PROCESS_ATTACH) return process_attached==1;
    if(!observation) return FALSE;
    if(reason==DLL_THREAD_ATTACH) {
        if(observation->tls_attach!=observation->dll_attach+1) observation->failures++;
        observation->dll_attach++;
    }
    if(reason==DLL_THREAD_DETACH) {
        if(observation->tls_detach!=observation->dll_detach+1) observation->failures++;
        observation->dll_detach++;
    }
    return TRUE;
}
