/* SPDX-License-Identifier: GPL-2.0-only
 * Owned proof DLL. This does not impersonate or replace Microsoft RPCRT4.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
volatile DWORD rpcfix_state,rpcfix_flag,rpcfix_counts[4];
static DWORD object=0x71c0ffee;
void __attribute__((naked)) WINAPI rpcfix_store(void){
 __asm__("push %edi\n\txor %edi,%edi\n\t.globl _rpcfix_store_site\n_rpcfix_store_site:\n\tmov %edi,_rpcfix_state\n\tpop %edi\n\tret");
}
DWORD WINAPI rpcfix_snapshot(void){
 return (rpcfix_state==(DWORD)(UINT_PTR)&object?1u:0u)|(rpcfix_flag?2u:0u)|
        ((rpcfix_counts[2]&255u)<<8)|((rpcfix_counts[3]&255u)<<16);
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){
 (void)module;(void)reserved;if(reason>3)return FALSE;rpcfix_counts[reason]++;
 if(reason==DLL_PROCESS_ATTACH){rpcfix_flag=0;rpcfix_state=(DWORD)(UINT_PTR)&object;}
 if(reason==DLL_PROCESS_DETACH){rpcfix_flag=1;rpcfix_store();}
 return TRUE;
}
