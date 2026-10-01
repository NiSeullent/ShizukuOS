/* SPDX-License-Identifier: GPL-2.0-only
 * A bounded native guest smoke; it does not launch a modern application.
 */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
typedef void *(WINAPI *open_fn)(const char *);
typedef FARPROC (WINAPI *find_fn)(void *,const char *,const char *);
typedef void (WINAPI *close_fn)(void *);
typedef BOOL (WINAPI *critical_fn)(CRITICAL_SECTION *,DWORD,DWORD);
typedef ULONGLONG (WINAPI *tick_fn)(void);
static HANDLE log_file;
static unsigned checks,failures;
static void line(const char *text)
{DWORD wrote=0,n=(DWORD)lstrlenA(text);if(!WriteFile(log_file,text,n,&wrote,NULL)||wrote!=n)ExitProcess(12);}
static void number(const char *label,DWORD value)
{char out[11];unsigned n;for(n=0;n<8;n++)out[n]="0123456789ABCDEF"[(value>>(28-4*n))&15];out[8]='\r';out[9]='\n';out[10]=0;line(label);line(out);}
static void check(int passed,const char *label)
{checks++;if(!passed){failures++;line("FAIL ");}else line("PASS ");line(label);line("\r\n");}
void mainCRTStartup(void)
{
    HMODULE dll;open_fn open;find_fn find;close_fn close;void *ctx=NULL;
    critical_fn critical=NULL;tick_fn tick=NULL;CRITICAL_SECTION section;
    log_file=CreateFileA("C:\\VXDLAB\\NPVPRB.LOG",GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_file==INVALID_HANDLE_VALUE)ExitProcess(11);
    line("NATIVE_WIN98_PROVIDER_BRIDGE_PROBE=1\r\nAPPLICATION_LAUNCHED=0\r\n");
    number("OS_VERSION=",GetVersion());
    dll=LoadLibraryA("C:\\VXDLAB\\NTWPROV.DLL");check(dll!=NULL,"actual NTWPROV LoadLibrary");
    if(!dll)goto done;
    open=(open_fn)(void *)GetProcAddress(dll,"NtwOpenProviderDirectoryA");
    find=(find_fn)(void *)GetProcAddress(dll,"NtwFindProviderExportA");
    close=(close_fn)(void *)GetProcAddress(dll,"NtwCloseProviderDirectory");
    check(open&&find&&close,"exact stdcall bridge exports");if(!open||!find||!close)goto unload;
    ctx=open("C:\\VXDLAB");check(ctx!=NULL,"native provider context");if(!ctx)goto unload;
    critical=(critical_fn)(void *)find(ctx,"KERNEL32.DLL","InitializeCriticalSectionEx");
    check(critical!=NULL,"real source-built CriticalSectionEx pointer");
    if(critical){BOOL initialized=critical(&section,0,0);check(initialized,"native CriticalSectionEx initialize");
        if(initialized){EnterCriticalSection(&section);LeaveCriticalSection(&section);DeleteCriticalSection(&section);}
        SetLastError(0);check(!critical(&section,0,2)&&GetLastError()==ERROR_INVALID_PARAMETER,"invalid flags preserve failure");}
    tick=(tick_fn)(void *)find(ctx,"kernel32.dll","GetTickCount64");
    check(tick!=NULL,"module case-insensitive real TickCount64 pointer");
    if(tick){ULONGLONG before=tick();Sleep(50);check(tick()>=before,"actual observed tick samples monotonic");}
    check(find(ctx,"KERNEL32.DLL","__UNKNOWN_EXPORT__")==NULL&&GetLastError()==ERROR_PROC_NOT_FOUND,"missing export remains absent");
    check(find(ctx,"GDI32.DLL","GdiAlphaBlend")==NULL&&GetLastError()==ERROR_MOD_NOT_FOUND,"unavailable GDI prerequisite not inferred");
    check(find(ctx,"SHELL32.DLL","SHCreateItemFromParsingName")!=NULL,"real shell provider table closure");
    check(find(ctx,"ADVAPI32.DLL","RegGetValueA")!=NULL,"real registry provider table closure");
    check(find(ctx,"USER32.DLL","AddClipboardFormatListener")!=NULL,"real user provider table closure");
    check(find(ctx,"COMCTL32.DLL",(const char *)(UINT_PTR)381)!=NULL,"real COMCTL ordinal table closure");
    close(ctx);
unload:
    FreeLibrary(dll);
done:
    number("CHECKS=",checks);number("FAILURES=",failures);number("LAST_ERROR=",GetLastError());
    if(!FlushFileBuffers(log_file))ExitProcess(13);
    CloseHandle(log_file);
    ExitProcess(failures?1:0);
}
