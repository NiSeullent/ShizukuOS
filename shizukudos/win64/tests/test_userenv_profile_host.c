/* SPDX-License-Identifier: GPL-2.0-only
 * Exact production profile bodies with declared Windows API host adapters.
 * Native t_userenv_profile uses actual token/event/registry handles instead. */
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef int BOOL; typedef uint16_t WCHAR; typedef uint8_t BYTE;
typedef uint32_t DWORD,ULONG; typedef uintptr_t ULONG_PTR; typedef int32_t NTSTATUS;
typedef void *HANDLE; typedef struct { uint16_t Length,MaximumLength; WCHAR *Buffer; } SHZ_UNICODE_STRING;
typedef struct { DWORD dwSize,dwFlags; WCHAR *lpUserName,*lpProfilePath,*lpDefaultPath,*lpServerName,*lpPolicyPath; HANDLE hProfile; } PROFILEINFOW,*LPPROFILEINFOW;
typedef struct { DWORD dwSize,dwFlags; char *lpUserName,*lpProfilePath,*lpDefaultPath,*lpServerName,*lpPolicyPath; HANDLE hProfile; } PROFILEINFOA,*LPPROFILEINFOA;
#define WINAPI
#define DLLAPI
#define TRUE 1
#define FALSE 0
#define ERROR_SUCCESS 0
#define ERROR_INVALID_HANDLE 6
#define ERROR_ACCESS_DENIED 5
#define ERROR_INVALID_DATA 13
#define ERROR_INVALID_PARAMETER 87
#define ERROR_CALL_NOT_IMPLEMENTED 120
#define TOKEN_DUPLICATE 2
#define TOKEN_IMPERSONATE 4
#define TOKEN_QUERY 8
#define DUPLICATE_SAME_ACCESS 2
#define SHZ_ObjectBasicInformation 0
#define SHZ_ObjectTypeInformation 2
#define STATUS_INVALID_HANDLE ((NTSTATUS)0xc0000008)
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xc0000022)
#define STATUS_NOT_IMPLEMENTED ((NTSTATUS)0xc0000002)
typedef struct { unsigned alive,kind; DWORD access; } record;
static record caller[4],owned;
static DWORD error;
static unsigned duplicates,closes,caller_closes,checks,inject,query_count;
static void SetLastError(DWORD e) { error=e; }
static DWORD GetLastError(void) { return error; }
static HANDLE GetCurrentProcess(void) { return (HANDLE)(uintptr_t)-1; }
static BOOL DuplicateHandle(HANDLE sp,HANDLE h,HANDLE tp,HANDLE *out,DWORD access,BOOL inherit,DWORD options) {
    record *r=NULL;unsigned i;(void)sp;(void)tp;(void)access;(void)inherit;
    for(i=0;i<4;++i)if(h==&caller[i])r=&caller[i];
    if(!r||!r->alive||inject==1){SetLastError(ERROR_INVALID_HANDLE);return FALSE;}
    if(options!=DUPLICATE_SAME_ACCESS||owned.alive)abort();
    owned=*r;*out=&owned;++duplicates;
    if(inject==8)r->kind=2; /* Caller closes/reuses after actual snapshot boundary. */
    return TRUE;
}
static BOOL CloseHandle(HANDLE h) {
    if(h!=&owned){++caller_closes;return FALSE;}
    if(!owned.alive)abort();
    owned.alive=0;++closes;
    if(inject==7){SetLastError(ERROR_ACCESS_DENIED);return FALSE;}return TRUE;
}
static ULONG RtlNtStatusToDosError(NTSTATUS status) {
    return status==STATUS_ACCESS_DENIED?ERROR_ACCESS_DENIED:status==STATUS_NOT_IMPLEMENTED?ERROR_CALL_NOT_IMPLEMENTED:ERROR_INVALID_HANDLE;
}
static NTSTATUS NtQueryObject(HANDLE h,ULONG cls,void *out,ULONG cap,ULONG *returned) {
    record *r=h;++query_count;if(h!=&owned||!r->alive)return STATUS_INVALID_HANDLE;
    if(cls==0){ULONG *basic=out;if(cap!=56)abort();if(inject==2)return STATUS_ACCESS_DENIED;
        memset(out,0,cap);basic[1]=r->access;*returned=inject==3?4:56;return 0;}
    if(cls==2){SHZ_UNICODE_STRING *name=out;static const WCHAR token[]=L"Token",event[]=L"Event";
        if(inject==4)return STATUS_NOT_IMPLEMENTED;
        memset(out,0,cap);name->Length=10;name->MaximumLength=12;name->Buffer=(WCHAR *)((BYTE *)out+104);
        memcpy(name->Buffer,r->kind==1?token:event,12);*returned=116;
        if(inject==5)*returned=cap+1;
        if(inject==6)name->Buffer=(WCHAR *)(uintptr_t)1;
        if(inject==9)name->Buffer=(WCHAR *)((BYTE *)out+200);
        return 0;}
    abort();
}
#include "userenv_profile_production.inc"
#define CHECK(x) do { ++checks;if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);exit(2);} } while(0)
static void setup(void) { unsigned i;memset(caller,0,sizeof caller);for(i=0;i<4;++i){caller[i].alive=1;caller[i].kind=1;caller[i].access=14;}caller[1].kind=2;inject=0;error=0;query_count=0;CHECK(!owned.alive); }
int main(void) {
    PROFILEINFOW w={0};PROFILEINFOA a={0};static WCHAR user[]=L"shizuku";unsigned i,before;
    _Static_assert(sizeof(PROFILEINFOW)==56&&offsetof(PROFILEINFOW,hProfile)==48,"Win64 PROFILEINFOW ABI");
    _Static_assert(sizeof(PROFILEINFOA)==56&&sizeof(SHZ_UNICODE_STRING)==16,"Win64 public record ABI");
    setup();w.dwSize=sizeof w;w.lpUserName=user;w.hProfile=&caller[1];
    CHECK(!LoadUserProfileW(&caller[0],NULL)&&error==ERROR_INVALID_PARAMETER&&duplicates==0);
    w.dwSize=1;CHECK(!LoadUserProfileW(&caller[0],&w)&&error==ERROR_INVALID_PARAMETER&&w.hProfile==&caller[1]);
    w.dwSize=sizeof w;w.lpUserName=NULL;CHECK(!LoadUserProfileW(&caller[0],&w)&&error==ERROR_INVALID_PARAMETER&&!w.hProfile&&duplicates==0);
    w.lpUserName=user;CHECK(!LoadUserProfileW(NULL,&w)&&error==ERROR_INVALID_HANDLE&&!w.hProfile);
    CHECK(!LoadUserProfileW(&caller[1],&w)&&error==ERROR_INVALID_HANDLE&&!w.hProfile);
    for(i=2;i<=8;i*=2){caller[0].access=14^i;CHECK(!LoadUserProfileW(&caller[0],&w)&&error==ERROR_ACCESS_DENIED&&!w.hProfile);}
    caller[0].access=14;CHECK(!LoadUserProfileW(&caller[0],&w)&&error==ERROR_CALL_NOT_IMPLEMENTED&&!w.hProfile);
    a.dwSize=sizeof a;a.lpUserName="shizuku";a.hProfile=&caller[1];
    CHECK(!LoadUserProfileA(&caller[0],&a)&&error==ERROR_CALL_NOT_IMPLEMENTED&&!a.hProfile);
    a.lpUserName=NULL;CHECK(!LoadUserProfileA(&caller[0],&a)&&error==ERROR_INVALID_PARAMETER&&!a.hProfile);
    CHECK(!UnloadUserProfile(&caller[0],NULL)&&error==ERROR_INVALID_HANDLE);
    CHECK(!UnloadUserProfile(NULL,&caller[1])&&error==ERROR_INVALID_HANDLE);
    CHECK(!UnloadUserProfile(&caller[1],&caller[0])&&error==ERROR_INVALID_HANDLE);
    caller[0].access=TOKEN_IMPERSONATE|TOKEN_DUPLICATE;
    CHECK(!UnloadUserProfile(&caller[0],&caller[1])&&error==ERROR_INVALID_HANDLE&&caller[1].alive);
    caller[0].access=TOKEN_QUERY;CHECK(!UnloadUserProfile(&caller[0],&caller[1])&&error==ERROR_ACCESS_DENIED);
    caller[0].access=14;
    for(i=1;i<=7;++i){DWORD expected=i==2||i==7?ERROR_ACCESS_DENIED:i==3||i==5||i==6?ERROR_INVALID_DATA:i==4?ERROR_CALL_NOT_IMPLEMENTED:ERROR_INVALID_HANDLE;
        inject=i;before=closes;w.hProfile=&caller[1];CHECK(!LoadUserProfileW(&caller[0],&w)&&error==expected&&!w.hProfile&&!owned.alive);CHECK(closes==before+(i!=1));}
    inject=8;CHECK(!LoadUserProfileW(&caller[0],&w)&&error==ERROR_CALL_NOT_IMPLEMENTED&&caller[0].kind==2);
    caller[0].kind=1;inject=9;CHECK(!LoadUserProfileW(&caller[0],&w)&&error==ERROR_INVALID_DATA&&!w.hProfile);
    CHECK(caller_closes==0&&duplicates==closes&&!owned.alive);
    for(i=0;i<4;++i)CHECK(caller[i].alive);
    printf("USERENV-PROFILE-HOST:%u checks PASS; exact bodies, explicit API adapters, no hive success\n",checks);return 0;
}
