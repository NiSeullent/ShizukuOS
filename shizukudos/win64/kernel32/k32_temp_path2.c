/* SPDX-License-Identifier: GPL-2.0-only
 * GetTempPath2 process-SYSTEM routing from Microsoft's documented contract.
 * Query the genuine current-process token through the existing Advapi SID
 * provider; no elevation/group/environment identity guess or static DLL cycle.
 * The actual kernel currently has one interactive identity and no ACL access
 * enforcement. A returned path does not prove directory existence or access. */
#ifdef SHZ_TEMP_PATH2_HOST
#include "../tests/temp_path2_host_contract.h"
#else
#include "k32.h"
#endif

typedef BOOL (WINAPI *temp_token_query)(HANDLE,TOKEN_INFORMATION_CLASS,LPVOID,DWORD,PDWORD);
static volatile LONG temp_token_lock;
static void temp_lock(void){while(__atomic_exchange_n(&temp_token_lock,1,__ATOMIC_ACQUIRE))NtYieldExecution();}
static void temp_unlock(void){__atomic_store_n(&temp_token_lock,0,__ATOMIC_RELEASE);}
static DWORD temp_error(DWORD fallback){DWORD error=GetLastError();return error?error:fallback;}
static DWORD temp_nt_error(NTSTATUS status){return RtlNtStatusToDosError(status);}

/* Only the owned process-token and module references are released. Loader
 * callbacks may reenter this API: Load/FreeLibrary run outside the query lock. */
static int temp_process_is_system(void)
{
    HMODULE module;
    HANDLE token=0;
    temp_token_query query;
    struct {TOKEN_USER user;BYTE sid[SECURITY_MAX_SID_SIZE+16];} record;
    DWORD needed=0,error=0;
    NTSTATUS status;
    int system=-1;
    module=LoadLibraryW(L"advapi32.dll");
    if(!module){SetLastError(temp_error(ERROR_MOD_NOT_FOUND));return -1;}
    query=(temp_token_query)GetProcAddress(module,"GetTokenInformation");
    if(!query){error=temp_error(ERROR_PROC_NOT_FOUND);goto done;}
    status=NtOpenProcessToken((HANDLE)(LONG_PTR)-1,TOKEN_QUERY,&token);
    if(!NT_SUCCESS(status)){error=temp_nt_error(status);goto done;}
    if(!token){error=ERROR_INVALID_HANDLE;goto done;}
    temp_lock();
    SetLastError(ERROR_SUCCESS);
    if(query(token,TokenUser,0,0,&needed))error=ERROR_INVALID_DATA;
    else if(GetLastError()!=ERROR_INSUFFICIENT_BUFFER)error=temp_error(ERROR_GEN_FAILURE);
    else if(needed<sizeof(TOKEN_USER)+8 || needed>sizeof record)error=ERROR_INVALID_DATA;
    if(!error) {
        if(!query(token,TokenUser,&record,sizeof record,&needed))error=temp_error(ERROR_GEN_FAILURE);
        else if(needed<sizeof(TOKEN_USER)+8 || needed>sizeof record)error=ERROR_INVALID_DATA;
        else {
            uintptr_t start=(uintptr_t)&record,end=start+needed,address=(uintptr_t)record.user.User.Sid;
            if(address<start+sizeof(TOKEN_USER) || address>end || end-address<8)error=ERROR_INVALID_SID;
            else {
                const BYTE *sid=(const BYTE *)address;
                unsigned count=sid[1];
                if(sid[0]!=SID_REVISION || count>SID_MAX_SUB_AUTHORITIES || (SIZE_T)(end-address)<8u+4u*count)error=ERROR_INVALID_SID;
                else {
                    system=count==1 && sid[2]==0 && sid[3]==0 && sid[4]==0 && sid[5]==0 && sid[6]==0 && sid[7]==5
                        && sid[8]==18 && sid[9]==0 && sid[10]==0 && sid[11]==0;
                }
            }
        }
    }
    temp_unlock();
done:
    if(token) {
        status=NtClose(token);
        if(!NT_SUCCESS(status) && !error)error=temp_nt_error(status);
    }
    if(!FreeLibrary(module) && !error)error=temp_error(ERROR_GEN_FAILURE);
    if(error){SetLastError(error);return -1;}
    return system;
}

/* Bounded path formatting only; the documented API does not test existence,
 * create a directory, inspect ACLs, or assert that a caller can access it. */
static DWORD temp_system_path(WCHAR *out)
{
    static const WCHAR component[]={'S','y','s','t','e','m','T','e','m','p',0};
    WCHAR raw[MAX_PATH+1];
    DWORD saved=GetLastError(),n,error;
    SetLastError(ERROR_SUCCESS);
    n=GetEnvironmentVariableW(L"SystemTemp",raw,MAX_PATH+1);
    if(!n) {
        error=GetLastError();
        if(error && error!=ERROR_ENVVAR_NOT_FOUND)return 0;
        n=GetWindowsDirectoryW(raw,MAX_PATH+1);
        if(!n){SetLastError(temp_error(ERROR_GEN_FAILURE));return 0;}
        if(n>MAX_PATH){SetLastError(ERROR_FILENAME_EXCED_RANGE);return 0;}
        if(raw[n-1]!='\\') {
            if(n==MAX_PATH){SetLastError(ERROR_FILENAME_EXCED_RANGE);return 0;}
            raw[n++]='\\';
        }
        if(n+10>MAX_PATH){SetLastError(ERROR_FILENAME_EXCED_RANGE);return 0;}
        for(unsigned i=0;i<=10;++i)raw[n+i]=component[i];
    } else if(n>MAX_PATH) {SetLastError(ERROR_FILENAME_EXCED_RANGE);return 0;}
    n=GetFullPathNameW(raw,MAX_PATH+1,out,0);
    if(!n){SetLastError(temp_error(ERROR_GEN_FAILURE));return 0;}
    if(n>MAX_PATH){SetLastError(ERROR_FILENAME_EXCED_RANGE);return 0;}
    if(out[n-1]!='\\') {
        if(n==MAX_PATH){SetLastError(ERROR_FILENAME_EXCED_RANGE);return 0;}
        out[n++]='\\';out[n]=0;
    }
    SetLastError(saved);
    return n;
}

K32API DWORD WINAPI GetTempPath2W(DWORD capacity,LPWSTR out)
{
    WCHAR path[MAX_PATH+1];
    DWORD saved=GetLastError(),n;
    int system=temp_process_is_system();
    if(system<0)return 0;
    SetLastError(saved);
    if(!system)return GetTempPathW(capacity,out);
    n=temp_system_path(path);
    if(!n)return 0;
    if(capacity<=n || !out)return n+1;
    for(DWORD i=0;i<=n;++i)out[i]=path[i];
    return n;
}

K32API DWORD WINAPI GetTempPath2A(DWORD capacity,LPSTR out)
{
    WCHAR wide[MAX_PATH+1];
    char path[3*(MAX_PATH+1)];
    DWORD saved=GetLastError(),n;
    int bytes,system=temp_process_is_system();
    if(system<0)return 0;
    SetLastError(saved);
    if(!system)return GetTempPathA(capacity,out);
    n=temp_system_path(wide);
    if(!n)return 0;
    bytes=WideCharToMultiByte(CP_ACP,0,wide,-1,path,sizeof path,0,0);
    if(!bytes){SetLastError(temp_error(ERROR_NO_UNICODE_TRANSLATION));return 0;}
    if(bytes>MAX_PATH+1){SetLastError(ERROR_FILENAME_EXCED_RANGE);return 0;}
    if((DWORD)bytes>capacity || !out){SetLastError(saved);return (DWORD)bytes;}
    for(int i=0;i<bytes;++i)out[i]=path[i];
    SetLastError(saved);
    return (DWORD)bytes-1;
}
