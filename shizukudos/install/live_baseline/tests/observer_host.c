/* SPDX-License-Identifier: GPL-2.0-only. Execute actual observer C with modeled APIs. */
#define SHZ_BASELINE_OBSERVER_HOSTTEST
#include "../observer.c"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <setjmp.h>
static int mode,opened,closed,erased,bad_query,bad_access,driver_queries,code,version_calls,nonce_reads,nonce_closed,report_created;
static char output_bytes[4096];static unsigned extent;static jmp_buf finish;
static int root_key,display_key,keyboard_key;
int WriteFile(HANDLE h,const void *raw,DWORD n,DWORD *done,void *ignored){(void)h;(void)ignored;if(extent+n>=sizeof output_bytes||mode==8||mode==10)return 0;memcpy(output_bytes+extent,raw,n);extent+=n;output_bytes[extent]=0;*done=n;return 1;}
LONG RegQueryValueExA(HKEY k,const char *name,void *reserved,DWORD *type,LPBYTE raw,DWORD *size){
    (void)reserved;const char *s=NULL;
    if(strcmp(name,"Class")==0){if(k==&root_key)return ERROR_FILE_NOT_FOUND;s=k==&display_key?(mode==7?"Keyboard":"Display"):"Keyboard";}
    else if(strcmp(name,"Driver")==0){++driver_queries;if(k!=&display_key){++bad_query;return 1;}if(mode==3)return ERROR_FILE_NOT_FOUND;s="Display\\0000";}
    else {++bad_query;return 1;}
    unsigned n=(unsigned)strlen(s)+1;if(*size<n)return ERROR_MORE_DATA;memcpy(raw,s,n);*size=n;*type=(mode==4&&strcmp(name,"Class")==0)?2:REG_SZ;
    if(mode==5&&strcmp(name,"Driver")==0)raw[n-1]='!';
    return ERROR_SUCCESS;
}
LONG RegEnumKeyExA(HKEY k,DWORD index,char *name,DWORD *size,void *a,void *b,void *c,void *d){
    (void)a;(void)b;(void)c;(void)d;if(k!=&root_key||index>=2)return ERROR_NO_MORE_ITEMS;
    const char *s=index==0?"PCI\\VEN_1234&DEV_1111\\00":"USB\\PRIVATE_KEY_NOT_READ";unsigned n=(unsigned)strlen(s);
    if(mode==6){*size=256;return ERROR_MORE_DATA;}if(*size<=n)return ERROR_MORE_DATA;memcpy(name,s,n+1);*size=n;return ERROR_SUCCESS;
}
LONG RegOpenKeyExA(HKEY k,const char *name,DWORD options,DWORD access,HKEY *out){
    if(options||access!=(KEY_QUERY_VALUE|KEY_ENUMERATE_SUB_KEYS))++bad_access;
    if(k==HKEY_LOCAL_MACHINE){if(strcmp(name,"Enum")){++bad_access;return 1;}*out=&root_key;}
    else *out=strncmp(name,"PCI",3)==0?(HKEY)&display_key:(HKEY)&keyboard_key;
    ++opened;return ERROR_SUCCESS;
}
LONG RegCloseKey(HKEY key){(void)key;++closed;return ERROR_SUCCESS;}
int lstrcmpiA(const char *a,const char *b){return strcasecmp(a,b);}
DWORD GetTickCount(void){return mode==9?started+60001:100;}
int GetVersionExA(OSVERSIONINFOA *v){version_calls++;v->dwPlatformId=mode==1?2:1;v->dwMajorVersion=4;v->dwMinorVersion=mode==21?0:10;v->dwBuildNumber=(mode==20&&version_calls==2)?1998:2222;return mode!=22;}
HANDLE CreateFileA(const char *p,DWORD access,DWORD share,void *security,DWORD disposition,DWORD flags,void *other){
    (void)security;(void)other;
    if(!strcmp(p,"C:\\BASENONC.BIN")){
        if(access!=GENERIC_READ||share!=FILE_SHARE_READ||disposition!=OPEN_EXISTING||flags!=FILE_ATTRIBUTE_NORMAL)++bad_access;
        return mode==11?INVALID_HANDLE_VALUE:(HANDLE)(intptr_t)3;
    }
    report_created=1;
    if(strcmp(p,"C:\\BASEOBS.JSON")||access!=GENERIC_WRITE||share!=FILE_SHARE_READ||disposition!=CREATE_NEW||flags!=FILE_ATTRIBUTE_NORMAL)++bad_access;
    return mode==2?INVALID_HANDLE_VALUE:(HANDLE)(intptr_t)2;
}
int FlushFileBuffers(HANDLE h){(void)h;return 1;}
int CloseHandle(HANDLE h){if(h==(HANDLE)(intptr_t)3){nonce_closed++;return mode!=18;}return mode!=19;}
int DeleteFileA(const char *p){if(strcmp(p,"C:\\BASEOBS.JSON"))++bad_access;++erased;return mode!=10;}
DWORD GetFileSize(HANDLE h,DWORD *high){if(h!=(HANDLE)(intptr_t)3)++bad_access;*high=mode==12?1:0;return mode==13?31:32;}
DWORD SetFilePointer(HANDLE h,LONG at,LONG *high,DWORD how){if(h!=(HANDLE)(intptr_t)3||at||high||how!=FILE_BEGIN)++bad_access;return mode==14?0xffffffffu:0;}
int ReadFile(HANDLE h,void *raw,DWORD n,DWORD *done,void *overlapped){
    if(h!=(HANDLE)(intptr_t)3||n!=32||overlapped)++bad_access;
    nonce_reads++;unsigned char *b=raw;for(unsigned i=0;i<n;i++)b[i]=mode==16?0:(unsigned char)(i+1);
    if(mode==17&&nonce_reads==2)b[0]^=1;
    *done=mode==15?31:32;return mode!=23;
}
_Noreturn void ExitProcess(DWORD n){code=(int)n;longjmp(finish,1);}
int main(int argc,char **argv){mode=argc>1?atoi(argv[1]):0;if(!setjmp(finish))mainCRTStartup();
    printf("%d %d %d %d %d %d %d\n",code,opened,closed,erased,bad_query,bad_access,driver_queries);
    printf("nonce_reads=%d nonce_closed=%d report_created=%d\n",nonce_reads,nonce_closed,report_created);
    puts(output_bytes);return 0;
}
