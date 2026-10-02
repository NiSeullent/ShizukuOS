/* SPDX-License-Identifier: GPL-2.0-only */
#ifdef SHZ_GLOBAL_BOOT_HOST_TEST
#include "launcher_mock.h"
#else
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0400
#define _WIN32_WINNT 0x0400
#include <windows.h>
#endif

/* OEM Win98 control: observe only the owned child, never our own final exit. */
#define BOOT_LOG_LIMIT 4096u
#define BOOT_WAIT_MS 450000u
#define BOOT_FAILURE 5u
static const char boot_path[]="C:\\VXDLAB\\SHZGBOOT.EXE";
static const char case_path[]="C:\\VXDLAB\\SHZCASE.TXT";
static const char observer_path[]="C:\\VXDLAB\\SHZOBS.EXE";
static const char observer_command[]="\"C:\\VXDLAB\\SHZOBS.EXE\"";
static HANDLE log_handle;
static DWORD log_attempted;
static const char *failure_stage;
static DWORD failure_error;

static void zero_bytes(void *memory,DWORD bytes)
{
    volatile BYTE *out=(volatile BYTE *)memory;
    while (bytes) { *out++=0; --bytes; }
}
static BOOL same_bytes(const void *left,const void *right,DWORD bytes)
{
    const BYTE *a=(const BYTE *)left,*b=(const BYTE *)right;
    while (bytes) { if (*a++!=*b++) return FALSE; --bytes; }
    return TRUE;
}
static DWORD bounded_length(const char *text,DWORD maximum)
{
    DWORD bytes=0;
    if (!text) return maximum;
    while (bytes<maximum && text[bytes]) ++bytes;
    return bytes;
}
static void fail_at(const char *stage,DWORD error)
{
    if (!failure_stage) { failure_stage=stage; failure_error=error; }
}
static void api_failed(const char *stage)
{
    DWORD error=GetLastError();
    fail_at(stage,error?error:ERROR_INVALID_DATA);
}
/* Failed/short writes also consume this conservative 4096-byte allowance. */
static BOOL log_bytes(const void *data,DWORD bytes)
{
    DWORD written=0;
    if (!bytes) return TRUE;
    if (bytes>BOOT_LOG_LIMIT-log_attempted) {
        fail_at("LOG_BOUND",ERROR_BUFFER_OVERFLOW); return FALSE;
    }
    log_attempted+=bytes;
    if (!WriteFile(log_handle,data,bytes,&written,NULL)) { api_failed("LOG_WRITE"); return FALSE; }
    if (written!=bytes) { fail_at("LOG_SHORT_WRITE",ERROR_WRITE_FAULT); return FALSE; }
    return TRUE;
}
static BOOL log_text(const char *text)
{
    DWORD bytes=bounded_length(text,512u);
    if (bytes==512u) { fail_at("LOG_TEXT_BOUND",ERROR_BUFFER_OVERFLOW); return FALSE; }
    return log_bytes(text,bytes);
}
static BOOL log_value(const char *key,const char *value)
{
    return log_text(key) && log_text("=") && log_text(value) && log_text("\r\n");
}
static BOOL log_number(const char *key,DWORD number)
{
    char digits[11]; DWORD at=10u;
    digits[at]=0;
    do { digits[--at]=(char)('0'+number%10u); number/=10u; } while (number);
    return log_value(key,digits+at);
}
static BOOL valid_case(const BYTE data[60],char nonce[33],unsigned *phase)
{
    static const char prefix[]="SHZGCASE1\r\nnonce=";
    static const char middle[]="\r\nphase=";
    DWORD i;
    if (!same_bytes(data,prefix,sizeof(prefix)-1u) ||
        !same_bytes(data+49u,middle,sizeof(middle)-1u) ||
        data[58]!='\r' || data[59]!='\n' || (data[57]!='1' && data[57]!='2')) return FALSE;
    for (i=0;i<32u;++i) {
        BYTE c=data[17u+i];
        if (!((c>='0' && c<='9') || (c>='a' && c<='f'))) return FALSE;
        nonce[i]=(char)c;
    }
    nonce[32]=0; *phase=(unsigned)(data[57]-'0'); return TRUE;
}
static BOOL exact_own_command(void)
{
    const char *command=GetCommandLineA();
    DWORD length=bounded_length(command,1024u),at=0,path_bytes=(DWORD)sizeof(boot_path)-1u;
    BOOL quoted;
    if (!command || length==1024u) return FALSE;
    while (at<length && (command[at]==' ' || command[at]=='\t')) ++at;
    quoted=(at<length && command[at]=='"');
    if (quoted) ++at;
    if (length-at<path_bytes || !same_bytes(command+at,boot_path,path_bytes)) return FALSE;
    at+=path_bytes;
    if (quoted) { if (at>=length || command[at]!='"') return FALSE; ++at; }
    while (at<length && (command[at]==' ' || command[at]=='\t')) ++at;
    return at==length;
}
/* Best-effort cleanup retries a failed close, never terminates a child. */
static void release_child(PROCESS_INFORMATION *child)
{
    if (child->hThread && child->hThread!=INVALID_HANDLE_VALUE) {
        if (!CloseHandle(child->hThread)) api_failed("THREAD_CLEANUP_CLOSE");
        child->hThread=NULL;
    }
    if (child->hProcess && child->hProcess!=INVALID_HANDLE_VALUE) {
        if (!CloseHandle(child->hProcess)) api_failed("PROCESS_CLEANUP_CLOSE");
        child->hProcess=NULL;
    }
}
static void failure_record(void)
{
    /* A strict parser rejects incomplete records and any failure suffix after
     * an earlier self-requested success footer. No own final exit is observed.
     */
    (void)log_value("FAIL_STAGE",failure_stage?failure_stage:"UNSPECIFIED");
    (void)log_number("FAIL_ERROR",failure_error);
    (void)log_value("BOOTSTRAP_EXTERNAL_EXIT","NOT_OBSERVED");
    (void)log_number("BOOTSTRAP_REQUESTED_EXIT",BOOT_FAILURE);
    (void)log_value("RESULT","NOT_A_FINAL_BOOTSTRAP_EXIT_VERDICT");
}
static DWORD boot_main(void)
{
    BYTE data[60],tail;
    char nonce[33],module[MAX_PATH],command[sizeof(observer_command)];
    HANDLE case_handle;
    OSVERSIONINFOA version;
    STARTUPINFOA startup;
    PROCESS_INFORMATION child;
    DWORD actual=0,length,wait_result,exit_code=0,i;
    unsigned phase=0;
    BOOL read_ok;
    log_handle=INVALID_HANDLE_VALUE; log_attempted=0; failure_stage=NULL; failure_error=0;
    zero_bytes(&child,sizeof(child));
    case_handle=CreateFileA(case_path,GENERIC_READ,FILE_SHARE_READ,NULL,
                            OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if (case_handle==INVALID_HANDLE_VALUE) return BOOT_FAILURE;
    read_ok=ReadFile(case_handle,data,sizeof(data),&actual,NULL);
    if (!read_ok) api_failed("CASE_READ");
    else if (actual!=sizeof(data)) fail_at("CASE_LENGTH",ERROR_INVALID_DATA);
    else {
        actual=0;
        if (!ReadFile(case_handle,&tail,1u,&actual,NULL)) api_failed("CASE_EOF_READ");
        else if (actual) fail_at("CASE_TRAILING_BYTES",ERROR_INVALID_DATA);
        else if (!valid_case(data,nonce,&phase)) fail_at("CASE_FORMAT",ERROR_INVALID_DATA);
    }
    if (!CloseHandle(case_handle)) { api_failed("CASE_CLOSE"); (void)CloseHandle(case_handle); }
    if (failure_stage) return BOOT_FAILURE;
    log_handle=CreateFileA(phase==1u?"C:\\VXDLAB\\SHZGB1.LOG":"C:\\VXDLAB\\SHZGB2.LOG",
                           GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if (log_handle==INVALID_HANDLE_VALUE) return BOOT_FAILURE;
    if (!log_value("HEADER",phase==1u?"SHZGB1_V1":"SHZGB2_V1") ||
        !log_value("NONCE",nonce) || !log_number("PHASE",phase) ||
        !log_number("BOOTSTRAP_PID",GetCurrentProcessId())) goto failed;
    zero_bytes(module,sizeof(module));
    length=GetModuleFileNameA(NULL,module,MAX_PATH);
    if (!length) { api_failed("MODULE_PATH_QUERY"); goto failed; }
    if (length!=sizeof(boot_path)-1u || length>=MAX_PATH ||
        !same_bytes(module,boot_path,sizeof(boot_path))) { fail_at("MODULE_PATH",ERROR_INVALID_NAME); goto failed; }
    if (!exact_own_command()) { fail_at("OWN_COMMAND",ERROR_INVALID_PARAMETER); goto failed; }
    if (!log_value("BOOTSTRAP_PATH",boot_path) ||
        !log_value("BOOTSTRAP_COMMAND_MODE","FIXED_PATH_NO_ARGUMENTS")) goto failed;
    zero_bytes(&version,sizeof(version)); version.dwOSVersionInfoSize=sizeof(version);
    if (!GetVersionExA(&version)) { api_failed("OS_QUERY"); goto failed; }
    if (!log_number("OS_PLATFORM",version.dwPlatformId) || !log_number("OS_MAJOR",version.dwMajorVersion) ||
        !log_number("OS_MINOR",version.dwMinorVersion) || !log_number("OS_BUILD_RAW",version.dwBuildNumber) ||
        !log_number("OS_BUILD_LOW_WORD",version.dwBuildNumber&0xffffu)) goto failed;
    if (version.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS || version.dwMajorVersion!=4u ||
        version.dwMinorVersion!=10u || (version.dwBuildNumber&0xffffu)!=2222u) {
        fail_at("OS_NOT_OEM_WIN98SE",ERROR_OLD_WIN_VERSION); goto failed;
    }
    if (!log_value("OBSERVER_COMMAND",observer_command) ||
        !log_value("OBSERVER_WORKING_DIRECTORY","C:\\VXDLAB") ||
        !log_number("OBSERVER_INHERIT_HANDLES",0u)) goto failed;
    zero_bytes(&startup,sizeof(startup)); startup.cb=sizeof(startup);
    for (i=0;i<sizeof(observer_command);++i) command[i]=observer_command[i];
    if (!CreateProcessA(observer_path,command,NULL,NULL,FALSE,0,NULL,"C:\\VXDLAB",&startup,&child)) {
        api_failed("OBSERVER_CREATE"); goto failed;
    }
    if (!child.hProcess || child.hProcess==INVALID_HANDLE_VALUE || !child.hThread ||
        child.hThread==INVALID_HANDLE_VALUE || !child.dwProcessId) {
        fail_at("OBSERVER_INVALID_PROCESS_INFORMATION",ERROR_INVALID_HANDLE); goto failed;
    }
    if (!log_number("OBSERVER_PID",child.dwProcessId)) goto failed;
    if (!CloseHandle(child.hThread)) { api_failed("OBSERVER_THREAD_CLOSE"); goto failed; }
    child.hThread=NULL;
    if (!log_number("OBSERVER_THREAD_HANDLE_CLOSED",1u)) goto failed;
    wait_result=WaitForSingleObject(child.hProcess,BOOT_WAIT_MS);
    if (wait_result==WAIT_FAILED) api_failed("OBSERVER_WAIT");
    else if (wait_result==WAIT_TIMEOUT) fail_at("OBSERVER_WAIT_TIMEOUT",ERROR_TIMEOUT);
    else if (wait_result!=WAIT_OBJECT_0) fail_at("OBSERVER_WAIT_RESULT",ERROR_INVALID_DATA);
    if (!log_number("OBSERVER_WAIT_RESULT",wait_result) || failure_stage) goto failed;
    if (!GetExitCodeProcess(child.hProcess,&exit_code)) {
        api_failed("OBSERVER_EXIT_QUERY"); (void)log_number("OBSERVER_EXIT_QUERY_SUCCEEDED",0u); goto failed;
    }
    if (!log_number("OBSERVER_EXIT_QUERY_SUCCEEDED",1u) || !log_number("OBSERVER_EXIT_CODE",exit_code)) goto failed;
    if (exit_code!=0u) { fail_at("OBSERVER_NONZERO_EXIT",exit_code); goto failed; }
    if (!CloseHandle(child.hProcess)) { api_failed("OBSERVER_PROCESS_CLOSE"); goto failed; }
    child.hProcess=NULL;
    if (!log_number("OBSERVER_PROCESS_HANDLE_CLOSED",1u)) goto failed;
    if (!FlushFileBuffers(log_handle)) { api_failed("LOG_INITIAL_FLUSH"); goto failed; }
    if (!log_number("LOG_FLUSH_OBSERVED",1u) ||
        !log_value("LOG_FINAL_FLUSH","REQUESTED_NOT_EXTERNALLY_OBSERVED") ||
        !log_value("LOG_FINAL_CLOSE","REQUESTED_NOT_EXTERNALLY_OBSERVED") ||
        !log_value("BOOTSTRAP_EXTERNAL_EXIT","NOT_OBSERVED") || !log_number("BOOTSTRAP_REQUESTED_EXIT",0u) ||
        !log_value("RESULT","NOT_A_FINAL_BOOTSTRAP_EXIT_VERDICT")) goto failed;
    if (!FlushFileBuffers(log_handle)) { api_failed("LOG_FINAL_FLUSH"); goto failed; }
    if (!CloseHandle(log_handle)) { api_failed("LOG_FINAL_CLOSE"); goto failed; }
    log_handle=INVALID_HANDLE_VALUE; return 0u;
failed:
    release_child(&child);
    failure_record();
    if (!FlushFileBuffers(log_handle)) api_failed("LOG_FAILURE_FLUSH");
    if (!CloseHandle(log_handle)) {
        api_failed("LOG_FAILURE_CLOSE");
        failure_record(); (void)FlushFileBuffers(log_handle); (void)CloseHandle(log_handle);
    }
    log_handle=INVALID_HANDLE_VALUE; return BOOT_FAILURE;
}
#ifndef SHZ_GLOBAL_BOOT_HOST_TEST
void mainCRTStartup(void) { ExitProcess(boot_main()); }
#endif
