/* SPDX-License-Identifier: GPL-2.0-only
 * Exact provider-absence production bodies; inaccessible handles/buffers and
 * typed output guards. Host-only, no KSP or publisher fallback proof. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/uio.h>
#include <unistd.h>
#define SHZ_NCRYPT_HOST_TEST
#include "ncrypt_boundary_host_contract.h"
static DWORD last_error;
static int trace_enabled, debug_calls;
static char debug_line[257];
static DWORD shz_last_error(void) { return last_error; }
static void shz_set_last_error(DWORD value) { last_error = value; }
static DWORD GetEnvironmentVariableW(LPCWSTR name, WCHAR *value, DWORD size)
{
    (void)name;
    if (size != 2) abort();
    last_error = 777;
    if (!trace_enabled) return 0;
    value[0] = '1'; value[1] = 0; return 1;
}
static LONG InterlockedCompareExchange(volatile LONG *p, LONG value, LONG expected)
{
    __atomic_compare_exchange_n(p, &expected, value, 0, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST);
    return expected;
}
static LONG NtShzDebugPrint(const char *bytes, DWORD size)
{
    if (size > 256) abort();
    memcpy(debug_line, bytes, size); debug_line[size] = 0;
    ++debug_calls; last_error = 999; return 0;
}
static HANDLE GetCurrentProcess(void) { return (HANDLE)(uintptr_t)-1; }
static BOOL ReadProcessMemory(HANDLE process, const void *from, void *to, SIZE_T size, SIZE_T *read)
{
    struct iovec local = {to, size}, remote = {(void *)from, size};
    ssize_t result;
    if (process != (HANDLE)(uintptr_t)-1) abort();
    result = process_vm_readv(getpid(), &local, 1, &remote, 1, 0);
    *read = result > 0 ? (SIZE_T)result : 0;
    last_error = 888;
    return result == (ssize_t)size;
}
#include "../dlls/ncrypt/ncrypt_unavailable.c"
static unsigned checks;
#define VERIFY(v) do { ++checks; if (!(v)) { fprintf(stderr,"FAIL line%d: %s\n",__LINE__,#v); abort(); } } while (0)
int main(void)
{
    static const WCHAR software[] = {'M','i','c','r','o','s','o','f','t',' ','S','o','f','t','w','a','r','e',' ','K','e','y',' ','S','t','o','r','a','g','e',' ','P','r','o','v','i','d','e','r',0};
    static const WCHAR platform[] = {'M','i','c','r','o','s','o','f','t',' ','P','l','a','t','f','o','r','m',' ','C','r','y','p','t','o',' ','P','r','o','v','i','d','e','r',0};
    struct { uint64_t before; NCRYPT_HANDLE handle; uint64_t after; } guarded = {0x1122334455667788ull,~(uintptr_t)0,0x8877665544332211ull};
    struct { DWORD before, count, after; } size = {0x12345678,~0u,0x87654321};
    BYTE bytes[32], original[32];
    long page = sysconf(_SC_PAGESIZE);
    void *bad = mmap(NULL,(size_t)page,PROT_NONE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    BYTE *edge = mmap(NULL,(size_t)page * 2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    NCRYPT_HANDLE handle = (uintptr_t)bad;
    unsigned i;
    VERIFY(bad != MAP_FAILED);
    VERIFY(edge != MAP_FAILED && !mprotect(edge+page,(size_t)page,PROT_NONE));
    *(WCHAR *)(edge+page-sizeof(WCHAR)) = 0;
    memset(bytes,0x5a,sizeof bytes); memcpy(original,bytes,sizeof bytes);
    last_error = 123;
    VERIFY(NCryptOpenStorageProvider(&guarded.handle,NULL,0)==NTE_PROV_DLL_NOT_FOUND && !guarded.handle);
    guarded.handle = ~(uintptr_t)0;
    VERIFY(NCryptOpenStorageProvider(&guarded.handle,software,0)==NTE_PROV_DLL_NOT_FOUND && !guarded.handle);
    guarded.handle = ~(uintptr_t)0;
    VERIFY(NCryptOpenStorageProvider(&guarded.handle,platform,0)==NTE_PROV_DLL_NOT_FOUND && !guarded.handle);
    VERIFY(NCryptOpenStorageProvider(&guarded.handle,software,1)==NTE_BAD_FLAGS && !guarded.handle);
    VERIFY(NCryptOpenStorageProvider(NULL,software,0)==NTE_INVALID_PARAMETER);
    VERIFY(last_error==123 && !debug_calls);
    guarded.handle = ~(uintptr_t)0;
    VERIFY(NCryptCreatePersistedKey(handle,&guarded.handle,NULL,NULL,0,0)==NTE_INVALID_HANDLE && !guarded.handle);
    guarded.handle = ~(uintptr_t)0;
    VERIFY(NCryptOpenKey(handle,&guarded.handle,NULL,0,0)==NTE_INVALID_HANDLE && !guarded.handle);
    guarded.handle = ~(uintptr_t)0;
    VERIFY(NCryptImportKey(handle,handle,NULL,bad,&guarded.handle,bad,0xffffffffu,0)==NTE_INVALID_HANDLE && !guarded.handle);
    VERIFY(NCryptCreatePersistedKey(handle,NULL,NULL,NULL,0,0)==NTE_INVALID_PARAMETER);
    VERIFY(NCryptOpenKey(handle,NULL,NULL,0,0)==NTE_INVALID_PARAMETER);
    VERIFY(NCryptImportKey(handle,0,NULL,NULL,NULL,NULL,0,0)==NTE_INVALID_PARAMETER);
    VERIFY(NCryptGetProperty(handle,NULL,bytes,sizeof bytes,&size.count,0)==NTE_INVALID_HANDLE && !size.count);
    size.count=~0u;
    VERIFY(NCryptExportKey(handle,handle,NULL,bad,bytes,sizeof bytes,&size.count,0)==NTE_INVALID_HANDLE && !size.count);
    size.count=~0u;
    VERIFY(NCryptSignHash(handle,bad,bad,0xffffffffu,bytes,sizeof bytes,&size.count,0)==NTE_INVALID_HANDLE && !size.count);
    size.count=~0u;
    VERIFY(NCryptCreateClaim(handle,handle,0,bad,bytes,sizeof bytes,&size.count,0)==NTE_INVALID_HANDLE && !size.count);
    VERIFY(NCryptGetProperty(handle,NULL,bad,0xffffffffu,NULL,0)==NTE_INVALID_PARAMETER);
    VERIFY(NCryptExportKey(handle,0,NULL,NULL,bad,0xffffffffu,NULL,0)==NTE_INVALID_PARAMETER);
    VERIFY(NCryptSignHash(handle,bad,bad,0xffffffffu,bad,0xffffffffu,NULL,0)==NTE_INVALID_PARAMETER);
    VERIFY(NCryptCreateClaim(handle,0,0,NULL,bad,0xffffffffu,NULL,0)==NTE_INVALID_PARAMETER);
    VERIFY(NCryptSetProperty(handle,NULL,bad,0xffffffffu,0)==NTE_INVALID_HANDLE);
    VERIFY(NCryptIsAlgSupported(handle,NULL,0)==NTE_INVALID_HANDLE);
    VERIFY(NCryptFinalizeKey(handle,0)==NTE_INVALID_HANDLE);
    VERIFY(NCryptDeleteKey(handle,0)==NTE_INVALID_HANDLE);
    VERIFY(NCryptFreeObject(handle)==NTE_INVALID_HANDLE);
    VERIFY(NCryptFreeObject(0)==NTE_INVALID_HANDLE);
    VERIFY(!memcmp(bytes,original,sizeof bytes));
    VERIFY(guarded.before==0x1122334455667788ull && guarded.after==0x8877665544332211ull);
    VERIFY(size.before==0x12345678 && size.after==0x87654321);
    trace_enabled=1;
    VERIFY(NCryptOpenStorageProvider(&guarded.handle,(WCHAR *)(edge+page-sizeof(WCHAR)),0)==NTE_PROV_DLL_NOT_FOUND);
    VERIFY(debug_calls==1 && !strstr(debug_line,"<unreadable>") && last_error==123);
    VERIFY(NCryptOpenStorageProvider(&guarded.handle,bad,0)==NTE_PROV_DLL_NOT_FOUND && !guarded.handle);
    VERIFY(debug_calls==2 && strstr(debug_line,"<unreadable>") && last_error==123);
    VERIFY(NCryptOpenStorageProvider(NULL,bad,0)==NTE_INVALID_PARAMETER);
    VERIFY(debug_calls==3 && strstr(debug_line,"<unreadable>") && last_error==123);
    for (i=0;i<1000;++i) VERIFY(NCryptOpenStorageProvider(&guarded.handle,platform,0)==NTE_PROV_DLL_NOT_FOUND);
    VERIFY(debug_calls==16 && trace_calls==16 && last_error==123);
    VERIFY(strstr(debug_line,"Microsoft Platform Crypto Provider") && strstr(debug_line,"flags=00000000 status=8009001e"));
    VERIFY(!munmap(bad,(size_t)page));
    VERIFY(!munmap(edge,(size_t)page * 2));
    printf("NCRYPT-BOUNDARY-HOST: %u checks; genuine provider absence, invalid handles/typed outputs/buffer guards, opt-in16-line metadata cap; no crypto provider success\n",checks);
    return 0;
}
