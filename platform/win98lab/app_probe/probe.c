/* SPDX-License-Identifier: GPL-2.0-only
 * Original bounded Windows 98 application observation tool; no CRT.
 * API declarations/import thunks are supplied by MinGW, implementations by
 * the guest's stock KERNEL32/USER32. See README.md for evidence limits.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#ifdef NTWAPP_TEST
#include "mock.h"
#else
#include <windows.h>
#endif

#define OBSERVE_MS 20000u
#define SLICE_MS 500u
#define GRACE_MS 5000u
#define STOP_CODE 0x4e544101u
#define ENUM_LIMIT 256u
#define OWNED_LIMIT 8u
static const char self_path[] = "C:\\NTWLAB\\NTWAPP.EXE";
static const char log_path[] = "C:\\NTWLAB\\NTWAPP.LOG";
#ifdef NTWAPP_CD_SOURCE
#define APP_DIRECTORY "D:\\CHROME"
#else
#define APP_DIRECTORY "C:\\CHROMIUM"
#endif
#define APP_PATH APP_DIRECTORY "\\CHROME.EXE"
static const char app_path[] = APP_PATH;
static const char app_directory[] = APP_DIRECTORY;

typedef struct run {
    HANDLE log, process;
    DWORD pid, sample, scanned, owned, stopped_enum, windows_seen, visible_seen;
    int io_failed, closing;
} run;

static DWORD length(const char *s)
{ DWORD n = 0; while (s[n]) ++n; return n; }

static void write_bytes(run *r, const char *s, DWORD size)
{
    DWORD written = 0;
    if (!r->io_failed && (!WriteFile(r->log,s,size,&written,NULL) || written != size))
        r->io_failed = 1;
}

static void field(run *r, const char *key, const char *value)
{
    write_bytes(r,key,length(key)); write_bytes(r,"=",1);
    write_bytes(r,value,length(value)); write_bytes(r,"\r\n",2);
    if (!r->io_failed && !FlushFileBuffers(r->log)) r->io_failed = 1;
}

static void number(run *r, const char *key, DWORD value)
{
    char reverse[10], text[11]; DWORD n = 0, i;
    do { reverse[n++] = (char)('0' + value % 10u); value /= 10u; } while (value);
    for (i=0;i<n;++i) text[i]=reverse[n-i-1u];
    text[n]=0; field(r,key,text);
}

static void hex_bytes(run *r, const char *key, const char *data, DWORD n)
{
    static const char hex[]="0123456789ABCDEF";
    char encoded[193]; DWORD i;
    if (n>96) { r->io_failed=1; return; }
    for(i=0;i<n;++i) { unsigned ch=(unsigned char)data[i]; encoded[i*2u]=hex[ch>>4]; encoded[i*2u+1u]=hex[ch&15u]; }
    encoded[n*2u]=0; field(r,key,encoded);
}

static void api_error(run *r, const char *stage, DWORD code)
{ field(r,"API_ERROR_STAGE",stage); number(r,"WIN32_ERROR",code); }

static int location_ok(void)
{
    char path[MAX_PATH]={0}; DWORD i,n=GetModuleFileNameA(NULL,path,MAX_PATH);
    if (!n || n>=MAX_PATH || n!=sizeof(self_path)-1u || path[n]!=0) return 0;
    for(i=0;i<n;++i) { char c=path[i]; if(c>='a'&&c<='z')c=(char)(c-'a'+'A'); if(c!=self_path[i])return 0; }
    return 1;
}

static BOOL CALLBACK window(HWND window, LPARAM parameter)
{
    run *r=(run *)parameter;
    DWORD pid=0,thread,code,again=0; BOOL visible,posted; int n;
    char title[96]={0},class_name[64]={0};
    if (r->io_failed || r->scanned>=ENUM_LIMIT || r->owned>=OWNED_LIMIT) {
        r->stopped_enum=1; SetLastError(0); return FALSE;
    }
    ++r->scanned;
    SetLastError(0); thread=GetWindowThreadProcessId(window,&pid);
    code=thread?0:GetLastError();
    if (!thread) { api_error(r,"WindowOwner",code); return TRUE; }
    if (pid!=r->pid) return TRUE;
    ++r->owned; ++r->windows_seen;
    visible=IsWindowVisible(window); if(visible)++r->visible_seen;
    number(r,"WINDOW_HANDLE",(DWORD)(ULONG_PTR)window);
    number(r,"WINDOW_PID",pid); number(r,"WINDOW_TID",thread);
    number(r,"WINDOW_VISIBLE",visible?1u:0u);
    SetLastError(0); n=GetClassNameA(window,class_name,sizeof(class_name));
    code=n?0:GetLastError();
    number(r,"CLASS_RETURN",(DWORD)n); number(r,"CLASS_ERROR",code);
    if(n>=0 && n<(int)sizeof(class_name)) {
        hex_bytes(r,"CLASS_HEX",class_name,(DWORD)n);
        number(r,"CLASS_AT_CAP",n==(int)sizeof(class_name)-1?1u:0u);
    } else field(r,"CLASS_INVALID_RETURN","1");
    SetLastError(0); n=GetWindowTextA(window,title,sizeof(title));
    code=n?0:GetLastError();
    number(r,"TITLE_RETURN",(DWORD)n); number(r,"TITLE_ERROR",code);
    if(n>=0 && n<(int)sizeof(title)) {
        hex_bytes(r,"TITLE_HEX",title,(DWORD)n);
        number(r,"TITLE_AT_CAP",n==(int)sizeof(title)-1?1u:0u);
    } else field(r,"TITLE_INVALID_RETURN","1");
    if (r->closing) {
        /* Recheck immediately before posting; window metadata is a snapshot,
         * not an atomic ownership lock. Never target foreign/changed owners. */
        SetLastError(0); thread=GetWindowThreadProcessId(window,&again);
        code=thread?0:GetLastError();
        number(r,"CLOSE_OWNER_PID",again); number(r,"CLOSE_OWNER_TID",thread);
        if (!thread) api_error(r,"CloseOwner",code);
        if (thread && again==r->pid) {
            posted=PostMessageA(window,WM_CLOSE,0,0);
            code=posted?0:GetLastError();
            number(r,"WM_CLOSE_RETURN",posted?1u:0u); number(r,"WM_CLOSE_ERROR",code);
        } else field(r,"WM_CLOSE_SKIPPED","OWNER_CHANGED");
    }
    return TRUE;
}

static void enumerate(run *r, int closing)
{
    BOOL result; DWORD code;
    r->scanned=0; r->owned=0; r->stopped_enum=0; r->closing=closing;
    number(r,"SAMPLE",r->sample++); number(r,"CLOSING_SAMPLE",closing?1u:0u);
    /* Closing enumeration continues despite a failed logger to permit owned
     * child cleanup; if callback stops due to I/O, termination still follows. */
    SetLastError(0); result=EnumWindows(window,(LPARAM)r); code=result?0:GetLastError();
    number(r,"ENUM_RETURN",result?1u:0u); number(r,"ENUM_ERROR",code);
    number(r,"ENUM_SCANNED",r->scanned); number(r,"ENUM_OWNED",r->owned);
    number(r,"ENUM_STOPPED_BY_LIMIT_OR_IO",r->stopped_enum);
}

static DWORD wait_child(run *r,DWORD timeout,const char *key)
{
    DWORD state=WaitForSingleObject(r->process,timeout);
    DWORD code=state==WAIT_FAILED?GetLastError():0;
    number(r,key,state); if(state==WAIT_FAILED)api_error(r,key,code);
    return state;
}

static int observe(run *r)
{
    DWORD start=GetTickCount(),elapsed,i,state,code; BOOL terminated;
    int stopped=0;
    for(i=0;i<40u && !r->io_failed;++i) {
        elapsed=GetTickCount()-start; /* unsigned arithmetic handles one wrap */
        number(r,"ELAPSED_MS",elapsed);
        if(elapsed>=OBSERVE_MS)break;
        state=wait_child(r,0,"POLL_RESULT");
        if(state==WAIT_OBJECT_0){stopped=1;break;}
        if(state!=WAIT_TIMEOUT)break;
        enumerate(r,0);
        if(r->io_failed)break;
        elapsed=GetTickCount()-start;
        if(elapsed>=OBSERVE_MS)break;
        state=wait_child(r,OBSERVE_MS-elapsed<SLICE_MS?OBSERVE_MS-elapsed:SLICE_MS,"OBSERVE_WAIT_RESULT");
        if(state==WAIT_OBJECT_0){stopped=1;break;}
        if(state!=WAIT_TIMEOUT)break;
    }
    number(r,"OBSERVATION_END_ELAPSED_MS",GetTickCount()-start);
    if(!stopped) {
        state=wait_child(r,0,"PRECLOSE_WAIT_RESULT");
        if(state==WAIT_OBJECT_0)stopped=1;
        else {
            enumerate(r,1);
            state=wait_child(r,GRACE_MS,"GRACE_WAIT_RESULT");
            if(state==WAIT_OBJECT_0)stopped=1;
        }
    }
    if(!stopped) {
        terminated=TerminateProcess(r->process,STOP_CODE);
        code=terminated?0:GetLastError();
        number(r,"TERMINATE_RETURN",terminated?1u:0u); number(r,"TERMINATE_ERROR",code);
        state=wait_child(r,GRACE_MS,"STOP_WAIT_RESULT");
        if(state==WAIT_OBJECT_0)stopped=1;
    }
    number(r,"OWNED_PROCESS_STOPPED",stopped?1u:0u);
    if(!stopped)return 0;
    if(!GetExitCodeProcess(r->process,&code)) {
        code=GetLastError(); api_error(r,"GetExitCodeProcess",code); return 0;
    }
    number(r,"CHILD_EXIT_DWORD",code);
    return 1;
}

static int close_owned(run *r,HANDLE h,const char *key)
{
    BOOL result=CloseHandle(h); DWORD code=result?0:GetLastError();
    number(r,key,result?1u:0u); if(!result)api_error(r,key,code);
    return result?1:0;
}

void mainCRTStartup(void)
{
    run r={0}; OSVERSIONINFOA os={0}; STARTUPINFOA startup={0}; PROCESS_INFORMATION child={0};
    char command[]="\"" APP_PATH "\"";
    DWORD code,previous_mode=0; int complete=0,mode_changed=0; BOOL launched;
    if(!location_ok())ExitProcess(2);
    r.log=CreateFileA(log_path,GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(r.log==INVALID_HANDLE_VALUE)ExitProcess(2);
    field(&r,"NTWAPP_VERSION","1"); field(&r,"EVIDENCE","GUEST_REPORTED_OBSERVATION");
    field(&r,"APP",app_path); field(&r,"CWD",app_directory); field(&r,"COMMAND",command);
    field(&r,"DESCENDANTS","UNTRACKED"); field(&r,"PAGE_FUNCTIONALITY","UNTESTED");
    if(r.io_failed)goto done;
    os.dwOSVersionInfoSize=sizeof(os);
    if(!GetVersionExA(&os)){code=GetLastError();api_error(&r,"GetVersionExA",code);goto done;}
    number(&r,"OS_PLATFORM",os.dwPlatformId); number(&r,"OS_MAJOR",os.dwMajorVersion);
    number(&r,"OS_MINOR",os.dwMinorVersion); number(&r,"OS_BUILD_RAW",os.dwBuildNumber);
    number(&r,"OS_BUILD_LOW",os.dwBuildNumber&0xffffu);
    if(os.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS || os.dwMajorVersion!=4 || os.dwMinorVersion!=10) {
        field(&r,"WIN98_IDENTIFIED","0");goto done;
    }
    field(&r,"WIN98_IDENTIFIED","1"); if(r.io_failed)goto done;
    previous_mode=SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOOPENFILEERRORBOX); mode_changed=1;
    number(&r,"ERROR_MODE_PREVIOUS",previous_mode); number(&r,"ERROR_MODE_REQUESTED",0x8001u);
    if(r.io_failed)goto done;
    startup.cb=sizeof(startup);
    field(&r,"LAUNCH_BEGIN","1"); if(r.io_failed)goto done;
    launched=CreateProcessA(app_path,command,NULL,NULL,FALSE,0,NULL,app_directory,&startup,&child);
    code=launched?0:GetLastError(); /* Capture before any log/API can overwrite. */
    number(&r,"CREATEPROCESS_RETURN",launched?1u:0u); number(&r,"CREATEPROCESS_ERROR",code);
    if(!launched){field(&r,"OBSERVATION","LAUNCH_FAILED");complete=1;goto done;}
    r.process=child.hProcess;r.pid=child.dwProcessId;
    number(&r,"PROCESS_ID",child.dwProcessId); number(&r,"THREAD_ID",child.dwThreadId);
    number(&r,"PROCESS_HANDLE",(DWORD)(ULONG_PTR)child.hProcess);
    number(&r,"THREAD_HANDLE",(DWORD)(ULONG_PTR)child.hThread);
    field(&r,"OBSERVATION","PROCESS_CREATED");
    complete=observe(&r);
    if(!close_owned(&r,child.hThread,"CLOSE_THREAD_RETURN"))complete=0;
    if(!close_owned(&r,child.hProcess,"CLOSE_PROCESS_RETURN"))complete=0;
    number(&r,"OWNED_WINDOW_OBSERVATIONS",r.windows_seen);
    number(&r,"VISIBLE_WINDOW_OBSERVATIONS",r.visible_seen);
done:
    if(mode_changed){code=SetErrorMode(previous_mode);number(&r,"ERROR_MODE_RESTORE_RETURN",code);}
    field(&r,"BROWSER_COMPATIBILITY","UNVERIFIED");
    number(&r,"DIAGNOSTIC_COMPLETE",complete&&!r.io_failed?1u:0u);
    field(&r,"END","BEFORE_LOG_CLOSE");
    if(!CloseHandle(r.log))r.io_failed=1;
    ExitProcess(r.io_failed?3u:complete?0u:1u);
}
