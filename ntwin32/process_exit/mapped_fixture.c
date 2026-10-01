/* SPDX-License-Identifier: GPL-2.0-only
 * Zero-import own MS-ABI TLS DLL. No native dependency calls during callbacks.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "mapped_fixture.h"
extern unsigned ntw_tls_compiler_word;
extern unsigned ntw_tls_compiler_read(void);
extern void ntw_tls_compiler_write(unsigned);
DWORD _tls_index=0xdeadbeefu;
static mx_fixture_observation *observation;
static DWORD tls_attached,dll_attached;
void WINAPI MxBind(mx_fixture_observation *borrowed){observation=borrowed;observation->tls_process_attach=tls_attached;observation->dll_process_attach=dll_attached;}
DWORD WINAPI MxWord(DWORD value){DWORD prior=ntw_tls_compiler_read();ntw_tls_compiler_write(value);return prior;}
static void WINAPI callback(void *base,DWORD reason,void *reserved)
{
 (void)base;
 if(reason==DLL_PROCESS_ATTACH){tls_attached=ntw_tls_compiler_read()==0x1234abcdu;return;}
 if(!observation)return;
 if(reason==DLL_THREAD_ATTACH){observation->tls_thread_attach++;if(ntw_tls_compiler_read()!=0x1234abcdu)observation->failures++;}
 if(reason==DLL_PROCESS_DETACH){observation->tls_process_detach++;observation->tls_word=ntw_tls_compiler_read();observation->tls_reserved_nonnull=reserved!=NULL;if(reserved)observation->failures++;}
}
static PIMAGE_TLS_CALLBACK callbacks[]={callback,NULL};
const IMAGE_TLS_DIRECTORY32 _tls_used={
 (DWORD)(UINT_PTR)&ntw_tls_compiler_word,(DWORD)(UINT_PTR)&ntw_tls_compiler_word+4,
 (DWORD)(UINT_PTR)&_tls_index,(DWORD)(UINT_PTR)callbacks,28,0x00700000u
};
BOOL WINAPI DllMain(HINSTANCE base,DWORD reason,void *reserved)
{
 (void)base;
 if(reason==DLL_PROCESS_ATTACH){dll_attached=tls_attached&&ntw_tls_compiler_read()==0x1234abcdu;return dll_attached;}
 if(!observation)return FALSE;
 if(reason==DLL_THREAD_ATTACH){observation->dll_thread_attach++;if(ntw_tls_compiler_read()!=0x1234abcdu)observation->failures++;}
 if(reason==DLL_PROCESS_DETACH){observation->dll_process_detach++;observation->dll_word=ntw_tls_compiler_read();observation->dll_reserved_nonnull=reserved!=NULL;if(!reserved||observation->tls_process_detach!=1||observation->tls_word!=observation->dll_word)observation->failures++;}
 return TRUE;
}
