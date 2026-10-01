/* SPDX-License-Identifier: GPL-2.0-only -- own hash-closed resource diagnostic. */
#include "patched/probe_loader.c"
void WINAPI entry(void)
{
 DWORD result=31,observed;void *borrowed;
 report=CreateFileA("C:\\VXDLAB\\RBPROBE.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
 if(report==INVALID_HANDLE_VALUE)ExitProcess(21);
 line("DIAGNOSTIC=","OWN_HASH_CLOSED_NATIVE_RESOURCE_GRAPH");value("CHROMIUM_ENTRY_CALLS=",0);value("APPLICATION_SUCCESS=",0);
 if(!px_original_win98())goto done;
 result=perform("C:\\VXDLAB\\RBAPP.EXE",2);value("DEFAULT_RUNTIME_RESOURCE_RESULT=",result);
 if(result!=20){result=31;goto done;}
 result=perform("C:\\VXDLAB\\RBAPP.EXE",3);if(result)goto done;
 borrowed=resource_last_data;SetLastError(0);if(resource_lock(borrowed)){result=31;goto done;}observed=GetLastError();
 value("AFTER_APPLICATION_CLEANUP_HANDLE_ERROR=",observed);if(!borrowed||observed!=ERROR_INVALID_HANDLE){result=31;goto done;}
 result=perform("C:\\VXDLAB\\RBROOT.DLL",3);if(result)goto done;
 borrowed=resource_last_data;SetLastError(0);if(resource_lock(borrowed)){result=31;goto done;}observed=GetLastError();
 value("AFTER_DLL_ROOT_CLEANUP_HANDLE_ERROR=",observed);if(!borrowed||observed!=ERROR_INVALID_HANDLE)result=31;
done:
 value("RESOURCE_DIAGNOSTIC_SELECTED_RESULT=",result);value("OWN_OS_EXIT_REQUIRES_INDEPENDENT_OBSERVER=",1);
 if(report_failed||!FlushFileBuffers(report))result=21;if(!CloseHandle(report))result=21;ExitProcess(result);
}
