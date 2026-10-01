/* SPDX-License-Identifier: GPL-2.0-only
 * Actual runtime/file/process fixture. Native command-shell positive execution
 * is not claimed by a child that merely emulates a command interpreter. */
#include "k32test.h"
#undef free
__declspec(dllimport) void __cdecl free(void *);
__declspec(dllimport) double __cdecl fabs(double);
__declspec(dllimport) unsigned char *__cdecl _mbschr(const unsigned char *,unsigned);
__declspec(dllimport) unsigned char *__cdecl _mbsinc(const unsigned char *);
__declspec(dllimport) unsigned char *__cdecl _mbsdec(const unsigned char *,const unsigned char *);
__declspec(dllimport) int __cdecl _mbsnbcmp(const unsigned char *,const unsigned char *,size_t);
__declspec(dllimport) int __cdecl _mbsnbcpy_s(unsigned char *,size_t,const unsigned char *,size_t);
__declspec(dllimport) int __cdecl _chmod(const char *,int);
__declspec(dllimport) char *__cdecl _mktemp(char *);
__declspec(dllimport) int __cdecl _resetstkoflw(void);
__declspec(dllimport) void __cdecl _searchenv(const char *,const char *,char *);
__declspec(dllimport) WCHAR *__cdecl _wgetdcwd(int,WCHAR *,int);
__declspec(dllimport) void __cdecl _wassert(const WCHAR *,const WCHAR *,unsigned);
__declspec(dllimport) int __cdecl system(const char *);
__declspec(dllimport) int *__cdecl _errno(void);
__declspec(dllimport) unsigned long *__cdecl __doserrno(void);
__declspec(dllimport) int __cdecl _dupenv_s(char **,size_t *,const char *);
__declspec(dllimport) int __cdecl _putenv_s(const char *,const char *);
typedef void (__cdecl *invalid_handler)(const WCHAR *,const WCHAR *,const WCHAR *,unsigned,uintptr_t);
__declspec(dllimport) invalid_handler __cdecl _set_thread_local_invalid_parameter_handler(invalid_handler);

static void __cdecl continuing_handler(const WCHAR *a,const WCHAR *b,const WCHAR *c,unsigned d,uintptr_t e)
{(void)a;(void)b;(void)c;(void)d;(void)e;}
static int narrow_equal(const char *a,const char *b)
{while(*a && *a==*b){++a;++b;}return *a==*b;}
static int wide_contains(const WCHAR *text,const WCHAR *word)
{for(;*text;++text){unsigned n=0;while(word[n] && text[n]==word[n])++n;if(!word[n])return 1;}return 0;}
struct mb_worker_context {int marker;HANDLE start;};
static struct mb_worker_context worker_contexts[2];
static DWORD WINAPI mb_worker(void *argument)
{
    struct mb_worker_context *context=argument;
    unsigned char text[]={0x80,'x',0};unsigned i;
    if(WaitForSingleObject(context->start,30000)!=WAIT_OBJECT_0)return 1;
    *_errno()=context->marker;
    for(i=0;i<1000;i++) {
        if(_mbschr(text,0x80)!=text || _mbsinc(text)!=text+1 || _mbsdec(text,text+2)!=text+1
           || _mbsnbcmp(text,text,3)!=0 || *_errno()!=context->marker)return 2;
    }
    return 0;
}
int main(void)
{
    static const char *exports[]={"fabs","_mbschr","_mbsinc","_mbsdec","_mbsnbcmp","_mbsnbcpy_s","_chmod","_mktemp","_resetstkoflw","_searchenv","_wgetdcwd","_wassert","system"};
    HMODULE runtime=GetModuleHandleW(L"ucrtbase.dll");BOOL bindings=runtime!=NULL;
    WCHAR current[260],actual[260],executable[260],command[560];
    char cwd[260],path[260],pattern[260],found[260],variable[80],*saved=NULL;
    unsigned char text[]={0x80,'x',0},copy[8];unsigned i;HANDLE file=INVALID_HANDLE_VALUE;
    HANDLE start=NULL,threads[2]={NULL,NULL};WCHAR *allocated;DWORD attributes,code;
    STARTUPINFOW startup;PROCESS_INFORMATION process;invalid_handler old_handler;
    union {ULONGLONG bits;double value;} input,absolute;
    const WCHAR *args=GetCommandLineW();
    if(args && wide_contains(args,L"--assert-child")) {
        _wassert(L"actual assert child",L"T_UCRT_LEGACY",7);
        return 9;
    }
    old_handler=_set_thread_local_invalid_parameter_handler(continuing_handler);
    for(i=0;i<sizeof(exports)/sizeof(exports[0]);i++)bindings &= GetProcAddress(runtime,exports[i])!=NULL;
    CHECK(bindings,"all 13 additive CRT functions are genuine named DLL exports");
    input.bits=0x8000000000000000ULL;absolute.value=fabs(input.value);
    CHECK(absolute.bits==0,"absolute value turns negative zero into positive zero");
    input.bits=0xfff8000000000042ULL;absolute.value=fabs(input.value);
    CHECK(absolute.bits==0x7ff8000000000042ULL,"absolute value preserves NaN payload while clearing sign");
    CHECK(_mbschr(text,0x80)==text && _mbschr(text,0)==text+2,"actual C locale searches unsigned bytes and terminator");
    CHECK(_mbsinc(text)==text+1 && _mbsdec(text,text+2)==text+1 && !_mbsdec(text,text),"actual single-byte cursor operations honor start boundary");
    CHECK(_mbsnbcmp(text,(const unsigned char *)"x",1)>0 && _mbsnbcmp(NULL,NULL,0)==0,"byte comparison uses unsigned ordering and zero count");
    CHECK(_mbsnbcpy_s(copy,sizeof copy,text,2)==0 && copy[0]==0x80 && copy[1]=='x' && !copy[2],"secure copy writes a terminator without null padding");
    CHECK(_mbsnbcpy_s(copy,2,text,(size_t)-1)==80 && copy[0]==0x80 && !copy[1],"actual secure-copy helper reports intentional truncation");
    CHECK(_mbsnbcpy_s(copy,2,text,2)==34 && !copy[0] && *_errno()==34,"secure-copy range failure empties destination and sets errno");
    CHECK(!_mbschr(NULL,1) && *_errno()==22,"NULL search invokes continuing invalid-parameter route");
    CHECK(!_resetstkoflw() && *_errno()==40 && *__doserrno()==120,"absent stack-growth recovery returns honest unsupported error");
    DWORD current_length=GetCurrentDirectoryW(260,current);
    CHECK(current_length>0 && current_length<260,"actual current directory fits the fixture path buffer");
    if(!current_length || current_length>=260)goto end;
    CHECK(_wgetdcwd(0,actual,260)==actual && k32t_weq(actual,current),"current-drive directory agrees with actual independent kernel32 provider");
    allocated=_wgetdcwd(0,NULL,260);
    CHECK(allocated && k32t_weq(allocated,current),"automatic directory allocation contains actual current directory");
    free(allocated);
    if(current[0]>='A' && current[0]<='Z' && current[1]==':')
        CHECK(_wgetdcwd(current[0]-'A'+1,actual,260)==actual && k32t_weq(actual,current),"explicit current drive uses actual volume and path providers");
    for(int drive=1;drive<=26;++drive) {
        WCHAR root[4]={(WCHAR)('A'+drive-1),':','\\',0};
        WCHAR letter=current[0];if(letter>='a' && letter<='z')letter=(WCHAR)(letter-'a'+'A');
        if(GetDriveTypeW(root)>=DRIVE_REMOVABLE && root[0]!=letter) {
            actual[0]=0x1234;
            CHECK(!_wgetdcwd(drive,actual,260) && *_errno()==40 && *__doserrno()==120 && actual[0]==0x1234,"another actual mounted drive reports absent retained-directory backend without publishing its root");
        }
    }
    CHECK(!_wgetdcwd(27,actual,260) && *_errno()==22,"invalid drive is rejected rather than replaced with a host path");
    CHECK(!_wgetdcwd(0,actual,1) && *_errno()==34,"caller directory capacity is respected");
    if(!WideCharToMultiByte(CP_ACP,0,current,-1,cwd,sizeof cwd,NULL,NULL)) {CHECK(FALSE,"real current path converts to actual narrow encoding");goto end;}
    snprintf(path,sizeof path,"%s\\ucrt-%u-%u.tmp",cwd,(unsigned)GetCurrentProcessId(),(unsigned)GetCurrentThreadId());
    file=CreateFileA(path,GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_HIDDEN,NULL);
    CHECK(file!=INVALID_HANDLE_VALUE,"fixture creates a uniquely owned real file without overwriting an existing file");
    if(file!=INVALID_HANDLE_VALUE) {
        CHECK(CloseHandle(file),"fixture file is closed before attribute operations");file=INVALID_HANDLE_VALUE;
        attributes=GetFileAttributesA(path);
        CHECK(_chmod(path,0x100)==0 && (GetFileAttributesA(path)&FILE_ATTRIBUTE_READONLY) && (GetFileAttributesA(path)&FILE_ATTRIBUTE_HIDDEN)==(attributes&FILE_ATTRIBUTE_HIDDEN),"chmod changes actual readonly bit and preserves hidden metadata");
        CHECK(_chmod(path,0x180)==0 && !(GetFileAttributesA(path)&FILE_ATTRIBUTE_READONLY),"chmod restores actual write permission");
        _searchenv(path,"PATH",found);
        CHECK(narrow_equal(found,path),"searchenv finds an actual absolute file through real path providers");
        snprintf(variable,sizeof variable,"SHZ_UCRT_PATH_%u",(unsigned)GetCurrentProcessId());
        char *prior_variable=NULL;
        int snapshot=_dupenv_s(&prior_variable,NULL,variable);
        CHECK(snapshot==0 && !prior_variable,"fixture environment name was absent before ownership");
        if(snapshot==0 && !prior_variable) {
            CHECK(_putenv_s(variable,cwd)==0,"owned CRT environment entry stores the real directory");
            const char *basename=path;for(const char *p=path;*p;p++)if(*p=='\\' || *p=='/')basename=p+1;
            _searchenv(basename,variable,found);CHECK(narrow_equal(found,path),"environment search returns the same actual file");
            CHECK(_putenv_s(variable,"")==0,"fixture removes only its owned environment entry");
        }
        free(prior_variable);
        CHECK(DeleteFileA(path),"fixture deletes its actual owned file");
        CHECK(_chmod(path,0x80)==-1 && *_errno()==2,"chmod reports real missing-file failure after deletion");
    }
    snprintf(pattern,sizeof pattern,"%s\\unique-%u-XXXXXX",cwd,(unsigned)GetCurrentThreadId());
    BOOL unique_ready=_mktemp(pattern)==pattern && GetFileAttributesA(pattern)==INVALID_FILE_ATTRIBUTES && GetLastError()==ERROR_FILE_NOT_FOUND;
    CHECK(unique_ready,"mktemp produces a name actually absent on disk without creating a file");
    if(unique_ready) {
        int snapshot=_dupenv_s(&saved,NULL,"COMSPEC");
        CHECK(snapshot==0,"fixture snapshots caller CRT command-shell environment");
        if(snapshot==0) {
            int changed=_putenv_s("COMSPEC",pattern);
            CHECK(changed==0,"fixture uses its verified absent filename to test shell absence");
            if(changed==0) {
                CHECK(system(NULL)==0 && *_errno()==2,"missing real command interpreter is reported unavailable");
                CHECK(system("exit 37")==-1 && *_errno()==2,"missing real shell cannot produce successful command execution");
            }
            CHECK(_putenv_s("COMSPEC",saved?saved:"")==0,"caller CRT command-shell environment is restored");
        }
        free(saved);saved=NULL;
    }
    start=CreateEventW(NULL,TRUE,FALSE,NULL);CHECK(start!=NULL,"real event gates two CRT thread workers");
    if(start) {
        worker_contexts[0].marker=17;worker_contexts[1].marker=83;worker_contexts[0].start=worker_contexts[1].start=start;
        for(i=0;i<2;i++)threads[i]=CreateThread(NULL,0,mb_worker,&worker_contexts[i],0,NULL);
        BOOL signalled=SetEvent(start);
        CHECK(threads[0] && threads[1] && signalled,"both kernel threads receive actual byte-iteration work");
        if(!signalled)ExitProcess(2);
        for(i=0;i<2;i++)if(threads[i]) {
            if(WaitForSingleObject(threads[i],30000)!=WAIT_OBJECT_0){CHECK(FALSE,"worker exit unproved; terminate process before event release");ExitProcess(2);}
            CHECK(GetExitCodeThread(threads[i],&code) && code==0,"actual per-thread errno remains isolated during byte operations");
            CHECK(CloseHandle(threads[i]),"joined CRT worker handle is released");
        }
        CHECK(CloseHandle(start),"joined workers' actual event is released");
    }
    if(GetModuleFileNameW(NULL,executable,260)>0) {
        unsigned n=0;command[n++]='"';for(i=0;executable[i] && n+1<560;i++)command[n++]=executable[i];command[n++]='"';
        static const WCHAR suffix[]=L" --assert-child";for(i=0;i<sizeof suffix/sizeof suffix[0];i++)command[n++]=suffix[i];
        ZeroMemory(&startup,sizeof startup);ZeroMemory(&process,sizeof process);startup.cb=sizeof startup;
        BOOL created=CreateProcessW(executable,command,NULL,NULL,FALSE,0,NULL,NULL,&startup,&process);
        CHECK(created,"actual subprocess enters the assertion failure path");
        if(created) {
            if(WaitForSingleObject(process.hProcess,30000)!=WAIT_OBJECT_0){CHECK(FALSE,"assertion child exit unproved");TerminateProcess(process.hProcess,2);if(WaitForSingleObject(process.hProcess,30000)!=WAIT_OBJECT_0)ExitProcess(2);}
            CHECK(GetExitCodeProcess(process.hProcess,&code) && code==3,"wassert routes to actual SIGABRT/default process exit 3");
            CHECK(CloseHandle(process.hThread) && CloseHandle(process.hProcess),"assertion child handles are released after proved exit");
        }
    } else CHECK(FALSE,"actual fixture executable path is available for assertion child");
end:
    _set_thread_local_invalid_parameter_handler(old_handler);
    return k32t_finish("T_UCRT_LEGACY");
}
