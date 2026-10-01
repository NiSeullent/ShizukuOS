/* SPDX-License-Identifier: GPL-2.0-only
 * Failure injection for the new bootstrap; not native execution evidence.
 */
#define NTTHBOOT_HOST_TEST
#include "launcher.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define LOG ((HANDLE)(uintptr_t)1)
#define PIN ((HANDLE)(uintptr_t)2)
#define PROCESS ((HANDLE)(uintptr_t)3)
#define THREAD ((HANDLE)(uintptr_t)4)
static unsigned assertions;
static char output[8192], pin_value[34];
static size_t output_bytes;
static int fail_log, fail_pin, fail_read, tail_present, pin_closes;
static int fail_pin_close, fail_module, fail_os, fail_create, created_count;
static int fail_query, fail_thread_close, fail_process_close, fail_log_close;
static int fail_flush, fail_write, short_write, zero_write, oversized_write;
static int log_closes, process_closes, thread_closes, query_count, wait_count;
static DWORD wait_value, exit_value;
#define CHECK(c) do { ++assertions; if (!(c)) { fprintf(stderr,"line %d: %s\n",__LINE__,#c); exit(1); } } while (0)

static void reset(void)
{
    memset(output,0,sizeof(output)); output_bytes=0;
    strcpy(pin_value,"0123456789abcdef0123456789abcdef");
    fail_log=fail_pin=fail_read=tail_present=pin_closes=fail_pin_close=0;
    fail_module=fail_os=fail_create=created_count=fail_query=0;
    fail_thread_close=fail_process_close=fail_log_close=fail_flush=0;
    fail_write=short_write=zero_write=oversized_write=0;
    log_closes=process_closes=thread_closes=query_count=wait_count=0;
    wait_value=WAIT_OBJECT_0; exit_value=0;
}
HANDLE CreateFileA(const char *p,DWORD a,DWORD s,void *sec,DWORD mode,DWORD attr,HANDLE tmpl)
{
    CHECK(!sec && !tmpl && s==FILE_SHARE_READ && attr==FILE_ATTRIBUTE_NORMAL);
    if (!strcmp(p,"C:\\VXDLAB\\THBOOT.LOG")) { CHECK(a==GENERIC_WRITE && mode==CREATE_NEW); return fail_log?INVALID_HANDLE_VALUE:LOG; }
    CHECK(!strcmp(p,"C:\\VXDLAB\\THNONCE.TXT") && a==GENERIC_READ && mode==OPEN_EXISTING);
    return fail_pin?INVALID_HANDLE_VALUE:PIN;
}
BOOL ReadFile(HANDLE h,void *buffer,DWORD bytes,DWORD *read,void *overlap)
{
    CHECK(h==PIN && !overlap);
    if(fail_read) { *read=0; return FALSE; }
    if(bytes==32u) { memcpy(buffer,pin_value,32); *read=32; }
    else { CHECK(bytes==1u); *read=(DWORD)tail_present; if(tail_present) *(char *)buffer='x'; }
    return TRUE;
}
BOOL WriteFile(HANDLE h,const void *buffer,DWORD bytes,DWORD *written,void *overlap)
{
    CHECK(h==LOG && !overlap);
    if(fail_write) { *written=0; return FALSE; }
    if(zero_write) { *written=0; return TRUE; }
    if(oversized_write) { *written=bytes+1u; return TRUE; }
    if(short_write && bytes>1) bytes=1;
    CHECK(output_bytes+bytes<sizeof(output)); memcpy(output+output_bytes,buffer,bytes);
    output_bytes+=bytes; *written=bytes; return TRUE;
}
BOOL FlushFileBuffers(HANDLE h) { CHECK(h==LOG); return !fail_flush; }
BOOL CloseHandle(HANDLE h)
{
    if(h==PIN) { ++pin_closes; return !fail_pin_close; }
    if(h==LOG) { ++log_closes; return !fail_log_close; }
    if(h==THREAD) { ++thread_closes; return !fail_thread_close; }
    CHECK(h==PROCESS); ++process_closes; return !fail_process_close;
}
DWORD GetModuleFileNameA(HANDLE h,char *p,DWORD count)
{
    CHECK(!h && count==MAX_PATH); if(fail_module) return 0;
    strcpy(p,"C:\\VXDLAB\\NTTHBOOT.EXE"); return (DWORD)strlen(p);
}
BOOL GetVersionExA(OSVERSIONINFOA *v)
{
    CHECK(v->dwOSVersionInfoSize==sizeof(*v)); v->dwPlatformId=1; v->dwMajorVersion=4;
    v->dwMinorVersion=10; v->dwBuildNumber=2222; if(fail_os) v->dwPlatformId=2; return TRUE;
}
BOOL CreateProcessA(const char *app,char *cmd,void *psec,void *tsec,BOOL inherit,DWORD flags,
                    void *env,const char *cwd,STARTUPINFOA *si,PROCESS_INFORMATION *pi)
{
    ++created_count;
    CHECK(!strcmp(app,"C:\\VXDLAB\\NTTHRUN.EXE"));
    CHECK(!strcmp(cmd,"\"C:\\VXDLAB\\NTTHRUN.EXE\" --nonce=0123456789abcdef0123456789abcdef"));
    CHECK(!psec && !tsec && !inherit && !flags && !env && !strcmp(cwd,"C:\\VXDLAB"));
    CHECK(si->cb==sizeof(*si) && !si->dwFlags);
    if(fail_create) return FALSE;
    pi->hProcess=PROCESS; pi->hThread=THREAD; pi->dwProcessId=123; return TRUE;
}
DWORD WaitForSingleObject(HANDLE h,DWORD ms) { CHECK(h==PROCESS && ms==OBSERVER_WAIT_MS); ++wait_count; return wait_value; }
BOOL GetExitCodeProcess(HANDLE h,DWORD *code) { CHECK(h==PROCESS); ++query_count; if(fail_query) return FALSE; *code=exit_value; return TRUE; }

int main(void)
{
    int *before_launch[] = {&fail_log,&fail_pin,&fail_read,&tail_present,&fail_pin_close,&fail_module,&fail_os};
    int *failures[] = {&fail_create,&fail_query,&fail_thread_close,&fail_process_close,&fail_log_close,&fail_flush,&fail_write,&zero_write,&oversized_write};
    size_t i;
    reset(); CHECK(boot_main()==0); CHECK(created_count==1 && pin_closes==1 && thread_closes==1 && process_closes==1 && log_closes==1);
    CHECK(strstr(output,"OBSERVER_ACTUAL_EXIT_CODE=0\r\n") && strstr(output,"OBSERVER_LIFECYCLE_BEFORE_FINAL_LOG_IO=PASS\r\n"));
    CHECK(strstr(output,"THEME_VERDICT=NOT-EVALUATED") && strstr(output,"EXTERNAL_BOOTSTRAP_EXIT=NOT-OBSERVED"));
    for(i=0;i<sizeof(before_launch)/sizeof(before_launch[0]);++i) { reset(); *before_launch[i]=1; CHECK(boot_main()!=0); CHECK(!created_count && !query_count && !process_closes && !thread_closes); }
    reset(); pin_value[4]='G'; CHECK(boot_main()!=0 && !created_count && pin_closes==1);
    for(i=0;i<sizeof(failures)/sizeof(failures[0]);++i) { reset(); *failures[i]=1; CHECK(boot_main()!=0); CHECK(log_closes==1); if(!fail_create) CHECK(process_closes==1 && thread_closes==1); }
    reset(); short_write=1; CHECK(boot_main()==0); CHECK(strstr(output,"OBSERVER_LIFECYCLE_BEFORE_FINAL_LOG_IO=PASS\r\n"));
    reset(); wait_value=WAIT_TIMEOUT; CHECK(boot_main()!=0 && query_count==0 && process_closes==1 && thread_closes==1); CHECK(!strstr(output,"OBSERVER_ACTUAL_EXIT_CODE="));
    reset(); wait_value=WAIT_FAILED; CHECK(boot_main()!=0 && query_count==0);
    reset(); exit_value=UINT32_C(0x100); CHECK(boot_main()!=0); CHECK(strstr(output,"OBSERVER_ACTUAL_EXIT_CODE=256"));
    reset(); exit_value=UINT32_C(0xffffffff); CHECK(boot_main()!=0); CHECK(strstr(output,"OBSERVER_ACTUAL_EXIT_CODE=4294967295"));
    CHECK(boot_log==INVALID_HANDLE_VALUE);
    printf("PASS: %u startup bootstrap ownership, exact-command, exit and IO assertions\n",assertions);
    return 0;
}
