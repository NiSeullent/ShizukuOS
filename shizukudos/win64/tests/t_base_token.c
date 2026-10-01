/* SPDX-License-Identifier: GPL-2.0-only
 * Kernel32 API-set callers and Advapi32 observe the same actual Nt tokens.
 */
#include "k32test.h"

typedef BOOL (WINAPI *process_open)(HANDLE,DWORD,PHANDLE);
typedef BOOL (WINAPI *thread_open)(HANDLE,DWORD,BOOL,PHANDLE);
int main(void)
{
    HMODULE base=GetModuleHandleW(L"kernel32.dll");
    process_open open_process=(process_open)(void *)GetProcAddress(base,"OpenProcessToken");
    thread_open open_thread=(thread_open)(void *)GetProcAddress(base,"OpenThreadToken");
    HANDLE a=NULL,b=NULL,impersonation=NULL,thread=NULL;
    BYTE first[256],second[256];
    DWORD count=0;
    BOOL first_ok,second_ok;
    CHECK(open_process&&open_thread, "actual Kernel32 exports both genuine token entry points");
    if (!open_process||!open_thread) return 1;
    SetLastError(0x6622);
    CHECK(open_process(GetCurrentProcess(),TOKEN_QUERY|TOKEN_DUPLICATE,&a)&&GetLastError()==0x6622, "base token open obtains actual handle and preserves success error");
    CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&b), "Advapi32 opens actual same process token");
    if (!a||!b) return 1;
    first_ok=GetTokenInformation(a,TokenUser,first,sizeof first,&count)&&count<=sizeof first;
    CHECK(first_ok, "query actual base token user via Advapi32");
    second_ok=GetTokenInformation(b,TokenUser,second,sizeof second,&count)&&count<=sizeof second;
    CHECK(second_ok, "query actual Advapi token user");
    if (!first_ok||!second_ok) {
        CloseHandle(a);CloseHandle(b);
        return k32t_finish("T_BASE_TOKEN");
    }
    CHECK(EqualSid(((TOKEN_USER*)first)->User.Sid,((TOKEN_USER*)second)->User.Sid), "both providers expose identical actual SID bytes");
    CHECK(!open_process((HANDLE)(ULONG_PTR)0x1234,TOKEN_QUERY,&thread)&&GetLastError()==ERROR_INVALID_HANDLE, "bad process handle reports actual Nt invalid-handle error");
    CHECK(!open_thread(GetCurrentThread(),TOKEN_QUERY,TRUE,&thread)&&GetLastError()==ERROR_NO_TOKEN, "thread without actual impersonation token reports no token");
    CHECK(DuplicateTokenEx(a,TOKEN_QUERY|TOKEN_IMPERSONATE,NULL,SecurityImpersonation,TokenImpersonation,&impersonation), "create genuine impersonation token with actual backend");
    if (impersonation) {
        CHECK(SetThreadToken(NULL,impersonation), "install actual thread impersonation token");
        CHECK(open_thread(GetCurrentThread(),TOKEN_QUERY,TRUE,&thread), "base entry opens actual existing thread token");
        if (thread) {
            second_ok=GetTokenInformation(thread,TokenUser,second,sizeof second,&count)&&count<=sizeof second;
            CHECK(second_ok, "Advapi queries base-opened real thread token");
            if (second_ok) CHECK(EqualSid(((TOKEN_USER*)first)->User.Sid,((TOKEN_USER*)second)->User.Sid), "real thread token user agrees across providers");
            CHECK(CloseHandle(thread), "close genuine thread token handle");thread=NULL;
        }
        CHECK(RevertToSelf(), "revert actual thread impersonation");
        CHECK(!open_thread(GetCurrentThread(),TOKEN_QUERY,TRUE,&thread)&&GetLastError()==ERROR_NO_TOKEN, "base entry observes actual token removal");
        CHECK(CloseHandle(impersonation), "close actual impersonation token");
    }
    CHECK(CloseHandle(a)&&CloseHandle(b), "close both real process-token handles");
    CHECK(!CloseHandle(a)&&GetLastError()==ERROR_INVALID_HANDLE, "closed actual token handle is invalid");
    return k32t_finish("T_BASE_TOKEN");
}
