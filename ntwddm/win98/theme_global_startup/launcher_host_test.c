/* SPDX-License-Identifier: GPL-2.0-only
 * Deterministic host models only. No guest execution or native API verdict.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "launcher_mock.h"

#define SHZ_GLOBAL_BOOT_HOST_TEST
#define HCASE ((HANDLE)(uintptr_t)1)
#define HLOG ((HANDLE)(uintptr_t)2)
#define HPROCESS ((HANDLE)(uintptr_t)3)
#define HTHREAD ((HANDLE)(uintptr_t)4)
static unsigned checks;
#define CHECK(c) do { ++checks; if (!(c)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#c); exit(1); } } while (0)

enum defect { OK, CASE_OPEN, CASE_READ, CASE_TAIL_READ, CASE_CLOSE, LOG_OPEN,
    MODULE_QUERY, VERSION_QUERY, CREATE_CHILD, WAIT_TIMED_OUT, WAIT_BAD,
    EXIT_QUERY, THREAD_CLOSE, PROCESS_CLOSE, LOG_CLOSE, FIRST_FLUSH, FINAL_FLUSH,
    FIRST_WRITE, FOOTER_WRITE, SHORT_WRITE };
static struct {
    enum defect defect;
    BYTE input[80]; DWORD input_bytes, read_at;
    char output[8192]; DWORD output_bytes;
    const char *module, *command;
    DWORD major, minor, platform, build, exit_code, wait_result, last_error;
    DWORD case_opens, log_opens, read_calls, write_calls, flush_calls;
    DWORD creates, waits, queries, case_closes, thread_closes, process_closes, log_closes;
    int case_open, log_open, process_open, thread_open;
    int defect_triggered;
} m;

static BOOL broken(enum defect wanted)
{
    if (m.defect != wanted || m.defect_triggered) return FALSE;
    m.defect_triggered = 1; m.last_error = 5u; return TRUE;
}

HANDLE CreateFileA(const char *path,DWORD access,DWORD sharing,void *security,
                   DWORD creation,DWORD attributes,HANDLE template_file)
{
    CHECK(sharing == FILE_SHARE_READ && !security && attributes == FILE_ATTRIBUTE_NORMAL && !template_file);
    if (access == GENERIC_READ) {
        CHECK(!strcmp(path,"C:\\VXDLAB\\SHZCASE.TXT") && creation == OPEN_EXISTING);
        ++m.case_opens;
        if (broken(CASE_OPEN)) return INVALID_HANDLE_VALUE;
        m.case_open=1; return HCASE;
    }
    CHECK(access == GENERIC_WRITE && creation == CREATE_NEW);
    CHECK(!strcmp(path,m.input[57]=='2'?"C:\\VXDLAB\\SHZGB2.LOG":"C:\\VXDLAB\\SHZGB1.LOG"));
    CHECK(m.input_bytes == 60 && m.read_at == 60 && m.case_closes == 1 && !m.case_open);
    ++m.log_opens;
    if (broken(LOG_OPEN)) return INVALID_HANDLE_VALUE;
    m.log_open=1; return HLOG;
}

BOOL ReadFile(HANDLE handle,void *buffer,DWORD requested,DWORD *actual,void *overlapped)
{
    DWORD available, bytes;
    CHECK(handle==HCASE && m.case_open && !overlapped && actual && buffer);
    ++m.read_calls;
    CHECK(requested == (m.read_calls == 1 ? 60u : 1u));
    if ((m.read_calls == 1 && broken(CASE_READ)) || (m.read_calls == 2 && broken(CASE_TAIL_READ))) {
        *actual=0; return FALSE;
    }
    available=m.input_bytes-m.read_at; bytes=requested<available?requested:available;
    memcpy(buffer,m.input+m.read_at,bytes); m.read_at+=bytes; *actual=bytes; return TRUE;
}

BOOL WriteFile(HANDLE handle,const void *data,DWORD bytes,DWORD *written,void *overlapped)
{
    DWORD count=bytes;
    CHECK(handle==HLOG && m.log_open && !overlapped && written && data && bytes>0);
    CHECK(m.output_bytes+bytes <= 4096);
    ++m.write_calls;
    if ((m.write_calls==1 && broken(FIRST_WRITE)) ||
        (bytes==strlen("NOT_A_FINAL_BOOTSTRAP_EXIT_VERDICT") &&
         !memcmp(data,"NOT_A_FINAL_BOOTSTRAP_EXIT_VERDICT",bytes) && broken(FOOTER_WRITE))) {
        *written=0; return FALSE;
    }
    if (m.write_calls==1 && broken(SHORT_WRITE)) count=bytes-1u;
    memcpy(m.output+m.output_bytes,data,count); m.output_bytes+=count;
    m.output[m.output_bytes]=0; *written=count; return TRUE;
}

BOOL FlushFileBuffers(HANDLE handle)
{
    CHECK(handle==HLOG && m.log_open);
    ++m.flush_calls;
    if ((m.flush_calls==1 && broken(FIRST_FLUSH)) || (m.flush_calls==2 && broken(FINAL_FLUSH))) return FALSE;
    return TRUE;
}

BOOL CloseHandle(HANDLE handle)
{
    if (handle==HCASE) {
        CHECK(m.case_open); ++m.case_closes;
        if (broken(CASE_CLOSE)) return FALSE;
        m.case_open=0; return TRUE;
    }
    if (handle==HTHREAD) {
        CHECK(m.thread_open); ++m.thread_closes;
        if (broken(THREAD_CLOSE)) return FALSE;
        m.thread_open=0; return TRUE;
    }
    if (handle==HPROCESS) {
        CHECK(m.process_open); ++m.process_closes;
        if (broken(PROCESS_CLOSE)) return FALSE;
        m.process_open=0; return TRUE;
    }
    CHECK(handle==HLOG && m.log_open); ++m.log_closes;
    if (broken(LOG_CLOSE)) return FALSE;
    m.log_open=0; return TRUE;
}

DWORD GetLastError(void) { return m.last_error; }
char *GetCommandLineA(void) { return (char *)m.command; }
DWORD GetCurrentProcessId(void) { return 101u; }
DWORD GetModuleFileNameA(HMODULE module,char *buffer,DWORD capacity)
{
    DWORD bytes=(DWORD)strlen(m.module);
    CHECK(!module && buffer && capacity==MAX_PATH);
    if (broken(MODULE_QUERY)) return 0;
    CHECK(bytes+1u <= capacity); memcpy(buffer,m.module,bytes+1u); return bytes;
}
BOOL GetVersionExA(OSVERSIONINFOA *version)
{
    CHECK(version->dwOSVersionInfoSize==sizeof(*version));
    if (broken(VERSION_QUERY)) return FALSE;
    version->dwMajorVersion=m.major; version->dwMinorVersion=m.minor;
    version->dwPlatformId=m.platform; version->dwBuildNumber=m.build; return TRUE;
}
BOOL CreateProcessA(const char *application,char *command,void *process_security,void *thread_security,
                    BOOL inherit,DWORD flags,void *environment,const char *directory,
                    STARTUPINFOA *startup,PROCESS_INFORMATION *process)
{
    CHECK(!strcmp(application,"C:\\VXDLAB\\SHZOBS.EXE"));
    CHECK(!strcmp(command,"\"C:\\VXDLAB\\SHZOBS.EXE\""));
    CHECK(!process_security && !thread_security && inherit==FALSE && flags==0 && !environment);
    CHECK(!strcmp(directory,"C:\\VXDLAB"));
    CHECK(startup->cb==sizeof(*startup) && !startup->dwFlags && !startup->lpReserved &&
          !startup->lpDesktop && !startup->lpTitle && !startup->hStdInput && !startup->hStdOutput && !startup->hStdError);
    CHECK(!process->hProcess && !process->hThread && !process->dwProcessId && !process->dwThreadId);
    CHECK(m.case_closes==1 && m.log_open && m.output_bytes>0);
    ++m.creates;
    if (broken(CREATE_CHILD)) return FALSE;
    process->hProcess=HPROCESS; process->hThread=HTHREAD;
    process->dwProcessId=202u; process->dwThreadId=203u;
    m.process_open=m.thread_open=1; return TRUE;
}
DWORD WaitForSingleObject(HANDLE handle,DWORD milliseconds)
{
    CHECK(handle==HPROCESS && m.process_open && milliseconds==450000u);
    CHECK(!m.thread_open && m.thread_closes==1);
    ++m.waits;
    if (broken(WAIT_TIMED_OUT)) m.wait_result=WAIT_TIMEOUT;
    else if (broken(WAIT_BAD)) m.wait_result=WAIT_FAILED;
    else m.wait_result=WAIT_OBJECT_0;
    return m.wait_result;
}
BOOL GetExitCodeProcess(HANDLE handle,DWORD *code)
{
    CHECK(handle==HPROCESS && m.process_open && code && m.waits==1 && m.wait_result==WAIT_OBJECT_0);
    ++m.queries;
    if (broken(EXIT_QUERY)) return FALSE;
    *code=m.exit_code; return TRUE;
}

#include "launcher.c"

static void reset(unsigned phase)
{
    static const char input[]="SHZGCASE1\r\nnonce=0123456789abcdef0123456789abcdef\r\nphase=1\r\n";
    memset(&m,0,sizeof(m)); memcpy(m.input,input,sizeof(input)-1u); m.input_bytes=60;
    m.input[57]=(BYTE)('0'+phase); m.module="C:\\VXDLAB\\SHZGBOOT.EXE"; m.command=m.module;
    m.major=4; m.minor=10; m.platform=VER_PLATFORM_WIN32_WINDOWS; m.build=0x040a08aeu;
}
static void succeeded(unsigned phase)
{
    char expected[2048];
    CHECK(boot_main()==0);
    CHECK(m.creates==1 && m.waits==1 && m.queries==1);
    CHECK(m.thread_closes==1 && m.process_closes==1 && m.log_closes==1);
    CHECK(!m.case_open && !m.log_open && !m.process_open && !m.thread_open);
    CHECK(strstr(m.output,phase==1?"HEADER=SHZGB1_V1\r\n":"HEADER=SHZGB2_V1\r\n")!=NULL);
    CHECK(strstr(m.output,"NONCE=0123456789abcdef0123456789abcdef\r\n")!=NULL);
    CHECK(strstr(m.output,"OBSERVER_PID=202\r\n")!=NULL);
    CHECK(strstr(m.output,"OBSERVER_WAIT_RESULT=0\r\nOBSERVER_EXIT_QUERY_SUCCEEDED=1\r\nOBSERVER_EXIT_CODE=0\r\n")!=NULL);
    CHECK(strstr(m.output,"BOOTSTRAP_EXTERNAL_EXIT=NOT_OBSERVED\r\n")!=NULL);
    CHECK(strstr(m.output,"RESULT=NOT_A_FINAL_BOOTSTRAP_EXIT_VERDICT\r\n")!=NULL);
    CHECK(!strstr(m.output,"PASS") && !strstr(m.output,"FAIL_STAGE") && m.output_bytes<=4096);
    CHECK(m.flush_calls==2);
    CHECK(snprintf(expected,sizeof(expected),
        "HEADER=SHZGB%u_V1\r\nNONCE=0123456789abcdef0123456789abcdef\r\nPHASE=%u\r\n"
        "BOOTSTRAP_PID=101\r\nBOOTSTRAP_PATH=C:\\VXDLAB\\SHZGBOOT.EXE\r\n"
        "BOOTSTRAP_COMMAND_MODE=FIXED_PATH_NO_ARGUMENTS\r\nOS_PLATFORM=1\r\nOS_MAJOR=4\r\nOS_MINOR=10\r\n"
        "OS_BUILD_RAW=%u\r\nOS_BUILD_LOW_WORD=2222\r\nOBSERVER_COMMAND=\"C:\\VXDLAB\\SHZOBS.EXE\"\r\n"
        "OBSERVER_WORKING_DIRECTORY=C:\\VXDLAB\r\nOBSERVER_INHERIT_HANDLES=0\r\nOBSERVER_PID=202\r\n"
        "OBSERVER_THREAD_HANDLE_CLOSED=1\r\nOBSERVER_WAIT_RESULT=0\r\nOBSERVER_EXIT_QUERY_SUCCEEDED=1\r\n"
        "OBSERVER_EXIT_CODE=0\r\nOBSERVER_PROCESS_HANDLE_CLOSED=1\r\nLOG_FLUSH_OBSERVED=1\r\n"
        "LOG_FINAL_FLUSH=REQUESTED_NOT_EXTERNALLY_OBSERVED\r\nLOG_FINAL_CLOSE=REQUESTED_NOT_EXTERNALLY_OBSERVED\r\n"
        "BOOTSTRAP_EXTERNAL_EXIT=NOT_OBSERVED\r\nBOOTSTRAP_REQUESTED_EXIT=0\r\n"
        "RESULT=NOT_A_FINAL_BOOTSTRAP_EXIT_VERDICT\r\n",phase,phase,m.build)>0);
    CHECK(!strcmp(m.output,expected));
}

int main(void)
{
    enum defect defects[]={CASE_OPEN,CASE_READ,CASE_TAIL_READ,CASE_CLOSE,LOG_OPEN,MODULE_QUERY,
        VERSION_QUERY,CREATE_CHILD,WAIT_TIMED_OUT,WAIT_BAD,EXIT_QUERY,THREAD_CLOSE,PROCESS_CLOSE,
        LOG_CLOSE,FIRST_FLUSH,FINAL_FLUSH,FIRST_WRITE,FOOTER_WRITE,SHORT_WRITE};
    unsigned i;
    DWORD exits[]={1u,0x10000u,0x80000000u,0xffffffffu,259u};
    reset(1); succeeded(1);
    reset(2); m.command=" \t\"C:\\VXDLAB\\SHZGBOOT.EXE\" \t"; succeeded(2);
    for(i=0;i<sizeof(defects)/sizeof(defects[0]);++i) {
        reset(1); m.defect=defects[i]; CHECK(boot_main()!=0); CHECK(m.defect_triggered);
        CHECK(!m.process_open && !m.thread_open && !m.case_open && !m.log_open);
        if (m.log_opens && defects[i]!=LOG_OPEN) CHECK(strstr(m.output,"FAIL_STAGE=")!=NULL);
        if (defects[i]==WAIT_TIMED_OUT || defects[i]==WAIT_BAD || defects[i]==THREAD_CLOSE) CHECK(m.queries==0);
        CHECK(m.output_bytes<=4096 && !strstr(m.output,"PASS"));
    }
    for(i=0;i<sizeof(exits)/sizeof(exits[0]);++i) {
        reset(1); m.exit_code=exits[i]; CHECK(boot_main()!=0);
        CHECK(m.queries==1 && m.process_closes==1 && strstr(m.output,"FAIL_STAGE=")!=NULL);
    }
    reset(1); m.input_bytes=59; CHECK(boot_main()!=0 && !m.log_opens && !m.creates);
    reset(1); m.input[60]='x'; m.input_bytes=61; CHECK(boot_main()!=0 && !m.log_opens && !m.creates);
    reset(1); m.input[0]='x'; CHECK(boot_main()!=0 && !m.log_opens);
    reset(1); m.input[17]='G'; CHECK(boot_main()!=0 && !m.log_opens);
    reset(1); m.input[57]='3'; CHECK(boot_main()!=0 && !m.log_opens);
    reset(1); m.input[58]='\n'; CHECK(boot_main()!=0 && !m.log_opens);
    reset(1); m.input[30]=0; CHECK(boot_main()!=0 && !m.log_opens);
    reset(1); m.module="D:\\VXDLAB\\SHZGBOOT.EXE"; CHECK(boot_main()!=0 && !m.creates);
    reset(1); m.command="C:\\VXDLAB\\SHZGBOOT.EXE /restore"; CHECK(boot_main()!=0 && !m.creates);
    reset(1); m.command="\"C:\\VXDLAB\\SHZGBOOT.EXE\" extra"; CHECK(boot_main()!=0 && !m.creates);
    reset(1); m.command="C:\\VXDLAB\\OTHER.EXE"; CHECK(boot_main()!=0 && !m.creates);
    reset(1); m.command="\"C:\\VXDLAB\\SHZGBOOT.EXE\"x"; CHECK(boot_main()!=0 && !m.creates);
    reset(1); m.major=5; CHECK(boot_main()!=0 && !m.creates);
    reset(1); m.minor=0; CHECK(boot_main()!=0 && !m.creates);
    reset(1); m.platform=2; CHECK(boot_main()!=0 && !m.creates);
    reset(1); m.build=1998; CHECK(boot_main()!=0 && !m.creates);
    CHECK(checks>=30);
    printf("PASS: %u global bootstrap checks\n",checks);
    return 0;
}
