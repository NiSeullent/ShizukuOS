/* SPDX-License-Identifier: GPL-2.0-only
 * Original opt-in Win98 adapter. Microsoft IP Helper supplies configuration;
 * this module performs no DNS transaction or global configuration change.
 */
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "m98_dns_config.h"
typedef DWORD (WINAPI *network_params_fn)(void *,ULONG *);
static uint32_t decode_acp(void *unused,const char *a,uint32_t n,uint16_t *w,uint32_t cap) {
    char back[132];int wc,ac;BOOL substituted=FALSE;uint32_t i;
    (void)unused;
    if(!n){w[0]=0;return 0;}
    wc=MultiByteToWideChar(CP_ACP,0,a,(int)n,(WCHAR *)w,(int)cap-1);
    if(wc<=0)return M98_DNS_INVALID_DATA;
    w[wc]=0;
    /* Win98 flags=0 plus exact byte roundtrip also rejects silent best fits. */
    ac=WideCharToMultiByte(CP_ACP,0,(WCHAR *)w,wc,back,sizeof(back),NULL,&substituted);
    if(ac!=(int)n||substituted)return M98_DNS_INVALID_DATA;
    for(i=0;i<n;++i)if(back[i]!=a[i])return M98_DNS_INVALID_DATA;
    return 0;
}
static void *allocate(void *unused,uint32_t n){(void)unused;return LocalAlloc(LMEM_FIXED,n);}
static char lower(char c){return c>='A'&&c<='Z'?(char)(c+32):c;}
static int same_path(const char *a,const char *b){uint32_t i=0;while(a[i]&&b[i]&&lower(a[i])==lower(b[i]))++i;return !a[i]&&!b[i];}
static uint32_t capture(m98_dns_snapshot *snapshot) {
    char path[MAX_PATH],loaded[MAX_PATH];const char suffix[]="\\IPHLPAPI.DLL";
    UINT n=GetSystemDirectoryA(path,sizeof(path));HMODULE dll;network_params_fn fn;
    ULONG size=0;DWORD status;void *buffer=NULL;uint32_t attempt,i;
    if(!n||n>=MAX_PATH-sizeof(suffix))return M98_DNS_INVALID_DATA;
    for(i=0;i<sizeof(suffix);++i)path[n+i]=suffix[i];
    dll=LoadLibraryA(path);if(!dll){status=GetLastError();return status?status:ERROR_MOD_NOT_FOUND;}
    n=GetModuleFileNameA(dll,loaded,sizeof(loaded));
    if(!n||n>=sizeof(loaded)||!same_path(path,loaded)){FreeLibrary(dll);return M98_DNS_INVALID_DATA;}
    fn=(network_params_fn)(void *)GetProcAddress(dll,"GetNetworkParams");
    if(!fn){FreeLibrary(dll);return M98_DNS_NOT_SUPPORTED;}
    status=fn(NULL,&size);
    if(status!=ERROR_BUFFER_OVERFLOW||size<584||size>65536){FreeLibrary(dll);return status?status:M98_DNS_INVALID_DATA;}
    for(attempt=0;attempt<3;++attempt){ULONG reported=size;
        buffer=LocalAlloc(LMEM_FIXED,size);if(!buffer){status=M98_DNS_NOMEM;break;}
        status=fn(buffer,&reported);
        if(status==ERROR_SUCCESS){
            if(reported>size||reported<584)status=M98_DNS_INVALID_DATA;
            else status=m98_dns_parse_fixed4(buffer,reported,(uint32_t)(uintptr_t)buffer,decode_acp,NULL,snapshot);
            LocalFree(buffer);buffer=NULL;break;
        }
        LocalFree(buffer);buffer=NULL;
        if(status!=ERROR_BUFFER_OVERFLOW||reported<=size||reported>65536)break;
        size=reported;
    }
    FreeLibrary(dll);return status;
}
DWORD WINAPI m98dns_DnsQueryConfig(uint32_t config,DWORD flags,const WCHAR *adapter,
                                  void *reserved,void *buffer,DWORD *length) {
    m98_dns_snapshot snapshot={0};uint32_t status,bytes=0;
    /* Validate before loading the optional installed provider. */
    status=m98_dns_validate_request(config,flags,(const uint16_t *)adapter,reserved,
                                    buffer,length?&bytes:NULL,allocate);
    if(status)return status;
    status=capture(&snapshot);if(status)return status;
    bytes=flags?0:*length;
    status=m98_dns_query(&snapshot,config,flags,(const uint16_t *)adapter,reserved,
                         buffer,&bytes,allocate,NULL);
    if(status==M98_DNS_OK||status==M98_DNS_INSUFFICIENT_BUFFER||status==M98_DNS_MORE_DATA)*length=bytes;
    return status;
}
BOOL WINAPI DllMain(HINSTANCE module,DWORD reason,LPVOID reserved){(void)module;(void)reason;(void)reserved;return TRUE;}
