/* SPDX-License-Identifier: GPL-2.0-only
 * Real file/registry/process tests of shared Win32 search policy. Each guest
 * is disposable; registry value, PATH, current directory and files restored.
 */
#include "k32test.h"
#include <winreg.h>

static const WCHAR value[] = L"SafeProcessSearchMode";
static const WCHAR keypath[] = L"SYSTEM\\CurrentControlSet\\Control\\Session Manager";
static const WCHAR directory[] = L"C:\\SHZ\\SPMODE";
static const WCHAR file[] = L"C:\\SHZ\\SPMODE\\kernel32.dll";
static const WCHAR unicode[] = L"C:\\SHZ\\SPMODE\\\ub3c4\uad6c.exe";
static BOOL make_file(LPCWSTR name)
{
    HANDLE h = CreateFileW(name, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD written = 0;
    BOOL ok;
    if (h == INVALID_HANDLE_VALUE) return FALSE;
    ok = WriteFile(h, "actual-file", 11, &written, NULL) && written == 11;
    return CloseHandle(h) && ok;
}
static void expected(LPCWSTR name)
{
    WCHAR out[MAX_PATH], *part = NULL;
    DWORD n = SearchPathW(NULL, L"kernel32.dll", NULL, MAX_PATH, out, &part);
    CHECK(n == (DWORD)k32t_wlen(name) && k32t_weq(out, name), "search resolves the independently chosen actual file");
    CHECK(part && k32t_weq(part, L"kernel32.dll"), "filepart points inside actual returned filename");
}
static DWORD WINAPI worker(void *unused)
{
    WCHAR out[MAX_PATH], sys[MAX_PATH];
    DWORD n;
    (void)unused;
    n = GetSystemDirectoryW(sys, MAX_PATH);
    memcpy(sys+n, L"\\kernel32.dll", sizeof L"\\kernel32.dll");
    for (DWORD i=0; i<200; ++i) {
        if (!SetSearchPathMode(i & 1 ? 1 : 0x10000)) return 1;
        if (!SearchPathW(NULL,L"kernel32.dll",NULL,MAX_PATH,out,NULL)) return 2;
        if (!k32t_weq(out, sys) && !k32t_weq(out, file)) return 3;
    }
    return 0;
}
int main(int argc, char **argv)
{
    WCHAR oldcwd[MAX_PATH], sys[MAX_PATH], out[MAX_PATH], *part;
    char ansi[MAX_PATH], *apart;
    DWORD n, oldlen=4, oldtype=0, oldvalue=0, setting=0, disposition;
    HKEY key = NULL;
    LONG previous;
    BOOL prior_supported;
    HANDLE threads[4];
    (void)argv;
    if (argc > 1) {
        CHECK(SetCurrentDirectoryW(directory), "child sets its own actual CWD");
        expected(file); /* Parent permanence must not be inherited. */
        return k32t_finish("T_SEARCH_PATH_CHILD");
    }
    CHECK(GetCurrentDirectoryW(MAX_PATH,oldcwd)>0, "retain actual original current directory");
    n=GetSystemDirectoryW(sys,MAX_PATH);
    CHECK(n>0 && n+13<MAX_PATH, "obtain actual system directory");
    memcpy(sys+n,L"\\kernel32.dll",sizeof L"\\kernel32.dll");
    CHECK(GetFileAttributesW(sys)!=INVALID_FILE_ATTRIBUTES, "system contender is the actual runtime DLL");
    CHECK(CreateDirectoryW(directory,NULL), "create fresh own search directory");
    CHECK(make_file(file)&&make_file(unicode), "create two real distinct test files");
    CHECK(SetCurrentDirectoryW(directory), "select actual test current directory");
    CHECK(RegCreateKeyExW(HKEY_LOCAL_MACHINE,keypath,0,NULL,0,KEY_QUERY_VALUE|KEY_SET_VALUE,NULL,&key,&disposition)==0, "open genuine session-manager registry backend");
    if (!key) return 1;
    previous=RegQueryValueExW(key,value,NULL,&oldtype,(BYTE*)&oldvalue,&oldlen);
    prior_supported=previous==ERROR_FILE_NOT_FOUND || (previous==0&&oldtype==REG_DWORD&&oldlen==sizeof oldvalue);
    CHECK(prior_supported, "prior registry policy is absent or genuine DWORD");
    if (!prior_supported) goto cleanup;
    CHECK(RegSetValueExW(key,value,0,REG_DWORD,(BYTE*)&setting,4)==0, "write actual temporary default unsafe policy");
    expected(file);
    setting=1;CHECK(RegSetValueExW(key,value,0,REG_DWORD,(BYTE*)&setting,4)==0, "change actual registry default safe policy");
    expected(sys);
    for (unsigned i=0;i<5;++i) {
        const DWORD invalid[]={0,0x8000,0x10001,0x18000,0xffffffff};
        CHECK(!SetSearchPathMode(invalid[i])&&GetLastError()==ERROR_INVALID_PARAMETER, "invalid flags fail without committing process mode");
    }
    expected(sys);
    SetLastError(0x4411);CHECK(SetSearchPathMode(1)&&GetLastError()==0x4411, "enable real safe mode and preserve LastError on success");
    setting=0;CHECK(RegSetValueExW(key,value,0,REG_DWORD,(BYTE*)&setting,4)==0, "change registry independently after process override");
    expected(sys);
    CHECK(SetSearchPathMode(0x10000), "disable process safe mode");expected(file);
    CHECK(SearchPathW(directory,L"\ub3c4\uad6c",L".exe",MAX_PATH,out,&part)>0&&k32t_weq(out,unicode), "actual Unicode search and extension resolve real file");
    CHECK(SearchPathA("C:\\SHZ\\SPMODE","\xeb\x8f\x84\xea\xb5\xac.exe",NULL,MAX_PATH,ansi,&apart)>0&&apart&&!strcmp(apart,"\xeb\x8f\x84\xea\xb5\xac.exe"), "actual platform ANSI codec preserves Korean bytes");
    part=(WCHAR*)(ULONG_PTR)0x1234;out[0]=0x5555;
    CHECK(SearchPathW(directory,L"kernel32.dll",NULL,1,out,&part)==(DWORD)k32t_wlen(file)+1&&out[0]==0x5555&&part==(WCHAR*)(ULONG_PTR)0x1234, "short output reports full size and leaves buffer/filepart untouched");
    CHECK(SearchPathW(directory,L"kernel32.dll",NULL,0,NULL,NULL)==(DWORD)k32t_wlen(file)+1, "zero-size query reports actual required WCHAR count");
    for (unsigned i=0;i<4;++i) threads[i]=CreateThread(NULL,0,worker,NULL,0,NULL);
    for (unsigned i=0;i<4;++i) {
        DWORD exit=~0u;
        CHECK(threads[i]&&WaitForSingleObject(threads[i],30000)==WAIT_OBJECT_0&&GetExitCodeThread(threads[i],&exit)&&exit==0, "real concurrent mode/search worker sees valid whole policies");
        if (threads[i]) CloseHandle(threads[i]);
    }
    CHECK(SetSearchPathMode(0x8001), "permanently enable safe search for actual process");expected(sys);
    CHECK(!SetSearchPathMode(0x10000)&&GetLastError()==ERROR_ACCESS_DENIED, "permanent process mode cannot become unsafe");
    CHECK(!SetSearchPathMode(1)&&GetLastError()==ERROR_ACCESS_DENIED, "permanent process mode cannot become mutable");
    CHECK(SetSearchPathMode(0x8001), "same permanent mode can be requested again");
    {
        WCHAR exe[MAX_PATH], command[MAX_PATH+32];
        STARTUPINFOW si; PROCESS_INFORMATION pi;
        memset(&si,0,sizeof si);si.cb=sizeof si;memset(&pi,0,sizeof pi);
        n=GetModuleFileNameW(NULL,exe,MAX_PATH);command[0]='"';memcpy(command+1,exe,n*2);memcpy(command+n+1,L"\" child",sizeof L"\" child");
        CHECK(CreateProcessW(exe,command,NULL,NULL,FALSE,0,NULL,NULL,&si,&pi), "create genuine child to test process policy isolation");
        if (pi.hProcess) {
            DWORD exit=~0u;
            CHECK(WaitForSingleObject(pi.hProcess,30000)==WAIT_OBJECT_0&&GetExitCodeProcess(pi.hProcess,&exit)&&exit==0, "child reads actual registry instead of inheriting permanent parent mode");
            CloseHandle(pi.hThread);CloseHandle(pi.hProcess);
        }
    }
    CHECK(previous==ERROR_FILE_NOT_FOUND ? RegDeleteValueW(key,value)==0 : RegSetValueExW(key,value,0,oldtype,(BYTE*)&oldvalue,oldlen)==0, "restore exact actual prior registry policy");
cleanup:
    CHECK(RegCloseKey(key)==0&&SetCurrentDirectoryW(oldcwd), "close registry and restore original CWD");
    CHECK(DeleteFileW(unicode)&&DeleteFileW(file)&&RemoveDirectoryW(directory), "remove own actual files and directory");
    return k32t_finish("T_SEARCH_PATH_MODE");
}
