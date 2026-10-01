/* SPDX-License-Identifier: GPL-2.0-only
 * Real native token access, event/key lifetime and absent managed hive provider.
 * No profile, registry root or success is manufactured by this fixture. */
#include "k32test.h"
#include <userenv.h>
_Static_assert(sizeof(PROFILEINFOW)==56 && offsetof(PROFILEINFOW,hProfile)==48,"Win64 PROFILEINFOW ABI");
_Static_assert(sizeof(PROFILEINFOA)==56 && offsetof(PROFILEINFOA,hProfile)==48,"Win64 PROFILEINFOA ABI");
int main(void)
{
    HANDLE token=NULL,query=NULL,unload=NULL,event=NULL;HKEY key=NULL;
    PROFILEINFOW w={0};PROFILEINFOA a={0};WCHAR user[]=L"shizuku";DWORD flags=0,subkeys=0;
    CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY|TOKEN_IMPERSONATE|TOKEN_DUPLICATE,&token),"genuine process token with all required profile rights");
    CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&query),"genuine token with query rights only");
    CHECK(OpenProcessToken(GetCurrentProcess(),TOKEN_IMPERSONATE|TOKEN_DUPLICATE,&unload),"genuine unload token without query right");
    event=CreateEventW(NULL,TRUE,FALSE,NULL);CHECK(event,"genuine unrelated event exists");
    if(!token||!query||!unload||!event)goto done;
    CHECK(!LoadUserProfileW(token,NULL)&&GetLastError()==ERROR_INVALID_PARAMETER,"NULL PROFILEINFO fails invalid parameter");
    w.dwSize=1;w.lpUserName=user;w.hProfile=event;
    CHECK(!LoadUserProfileW(token,&w)&&GetLastError()==ERROR_INVALID_PARAMETER&&w.hProfile==event,"bad size rejects without writing beyond a valid structure contract");
    w.dwSize=sizeof w;w.lpUserName=NULL;
    CHECK(!LoadUserProfileW(token,&w)&&GetLastError()==ERROR_INVALID_PARAMETER&&!w.hProfile,"missing user name fails with no fabricated profile handle");
    w.lpUserName=user;w.hProfile=event;
    CHECK(!LoadUserProfileW((HANDLE)(ULONG_PTR)0x7fff0001,&w)&&GetLastError()==ERROR_INVALID_HANDLE&&!w.hProfile,"actual invalid token handle rejected");
    CHECK(!LoadUserProfileW(event,&w)&&GetLastError()==ERROR_INVALID_HANDLE&&!w.hProfile,"actual event is not a token despite a real handle");
    CHECK(!LoadUserProfileW(query,&w)&&GetLastError()==ERROR_ACCESS_DENIED&&!w.hProfile,"actual token rights are enforced");
    CHECK(!LoadUserProfileW(token,&w)&&GetLastError()==ERROR_CALL_NOT_IMPLEMENTED&&!w.hProfile,"valid token reports genuine absent managed hive backend");
    a.dwSize=sizeof a;a.lpUserName="shizuku";a.hProfile=event;
    CHECK(!LoadUserProfileA(token,&a)&&GetLastError()==ERROR_CALL_NOT_IMPLEMENTED&&!a.hProfile,"ANSI valid token reports same absent backend and NULL output");
    a.lpUserName=NULL;a.hProfile=event;
    CHECK(!LoadUserProfileA(token,&a)&&GetLastError()==ERROR_INVALID_PARAMETER&&!a.hProfile,"ANSI parameter validation precedes token or backend access");
    CHECK(!UnloadUserProfile(token,NULL)&&GetLastError()==ERROR_INVALID_HANDLE,"NULL is not a profile issued by this provider");
    CHECK(!UnloadUserProfile(query,event)&&GetLastError()==ERROR_ACCESS_DENIED,"unload checks actual duplicate and impersonate rights");
    CHECK(!UnloadUserProfile(unload,event)&&GetLastError()==ERROR_INVALID_HANDLE,"unload does not impose an undocumented query-right requirement");
    CHECK(!UnloadUserProfile(token,event)&&GetLastError()==ERROR_INVALID_HANDLE,"unrelated caller event cannot be unloaded as a hive");
    CHECK(WaitForSingleObject(event,0)==WAIT_TIMEOUT&&SetEvent(event)&&WaitForSingleObject(event,0)==WAIT_OBJECT_0,"failure paths never close or signal caller event");
    CHECK(GetHandleInformation(token,&flags)&&GetHandleInformation(query,&flags)&&GetHandleInformation(unload,&flags),"all caller token handles remain valid");
    CHECK(!UnloadUserProfile(token,(HANDLE)HKEY_CURRENT_USER)&&GetLastError()==ERROR_INVALID_HANDLE,"predefined HKCU is not a fabricated loaded profile");
    CHECK(RegOpenCurrentUser(KEY_READ,&key)==ERROR_SUCCESS&&key,"actual existing registry key opens read-only");
    if(key){
        CHECK(!UnloadUserProfile(token,(HANDLE)key)&&GetLastError()==ERROR_INVALID_HANDLE,"unrelated actual registry key cannot match a loaded profile");
        CHECK(RegQueryInfoKeyW(key,NULL,NULL,NULL,&subkeys,NULL,NULL,NULL,NULL,NULL,NULL,NULL)==ERROR_SUCCESS,"unload failure leaves caller registry key valid");
    }
done:
    if(key)RegCloseKey(key);
    if(event)CloseHandle(event);
    if(unload)CloseHandle(unload);
    if(query)CloseHandle(query);
    if(token)CloseHandle(token);
    return k32t_finish("T_USERENV_PROFILE");
}
