/* SPDX-License-Identifier: GPL-2.0-only
 * Actual Win98 dynamic VxD load request after readonly native admission.
 * Source-bound embedded bytes deny changed binaries; fresh host nonce is
 * separately staged by the guardian owner. No default/mode/registry writes. */
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include "contract.h"
#include "expected.h"
static HANDLE log_handle;
static int equal(const void *a,const void *b,unsigned n){const unsigned char *x=a,*y=b;while(n--)if(*x++!=*y++)return 0;return 1;}
static int log_line(const char *s){DWORD n=0,w=0;while(s[n])n++;return WriteFile(log_handle,s,n,&w,NULL) && w==n && FlushFileBuffers(log_handle);}
static int log_snapshot(const char *label,const unsigned char raw[352])
{
    static const char hex[]="0123456789abcdef";char line[800];unsigned at=0;
    while(label[at]){if(at>=80)return 0;line[at]=label[at];at++;}
    for(unsigned i=0;i<352;i++){line[at++]=hex[raw[i]>>4];line[at++]=hex[raw[i]&15];}
    line[at++]='\r';line[at++]='\n';line[at]=0;return log_line(line);
}
static HANDLE held(const char *name,const unsigned char *bytes,DWORD n)
{
    HANDLE f=CreateFileA(name,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    unsigned char chunk[512];DWORD high=0,got=0,at=0;
    if(f==INVALID_HANDLE_VALUE)return f;
    if(GetFileSize(f,&high)!=n || high)goto fail;
    while(at<n){DWORD want=n-at;if(want>sizeof chunk)want=sizeof chunk;
        if(!ReadFile(f,chunk,want,&got,NULL) || got!=want || !equal(chunk,bytes+at,want))goto fail;
        at+=want;}
    return f;
fail:CloseHandle(f);return INVALID_HANDLE_VALUE;
}
static int query(HANDLE guard,unsigned char out[352],const unsigned char nonce[32])
{
    DWORD got=0;
    if(!DeviceIoControl(guard,SHZGUARD_QUERY,NULL,0,out,352,&got,NULL) || got!=352 ||
       !equal(out,shzguard_expected_provider,32) ||
       !shzguard_epoch_valid((const uint32_t *)(const void *)(out+32)) ||
       !equal(out+96,nonce,32))return 0;
    return 1;
}
static unsigned run(void)
{
    HANDLE guard_file=INVALID_HANDLE_VALUE,gop_file=INVALID_HANDLE_VALUE,nonce_file=INVALID_HANDLE_VALUE;
    HANDLE guard=INVALID_HANDLE_VALUE,gop=INVALID_HANDLE_VALUE;unsigned rc=1;
    unsigned char nonce[32],first[352],second[352];DWORD got=0,high=0;
    OSVERSIONINFOA version;unsigned char *raw=(unsigned char *)&version;
    for(unsigned i=0;i<sizeof version;i++)raw[i]=0;
    version.dwOSVersionInfoSize=sizeof version;
    log_handle=CreateFileA("C:\\SHZGOP\\FIRSTLOAD.LOG",GENERIC_WRITE,FILE_SHARE_READ,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(log_handle==INVALID_HANDLE_VALUE)return 2;
    if(!log_line("START=SHZGOP-FIRSTLOAD/1\r\nDEFAULT_CHANGED=0\r\nMODE_CHANGED=0\r\n"))goto done;
    if(!GetVersionExA(&version) || version.dwPlatformId!=VER_PLATFORM_WIN32_WINDOWS || version.dwMajorVersion!=4 || version.dwMinorVersion!=10)goto done;
    guard_file=held("C:\\SHZGOP\\SHZGUARD.VXD",shzguard_expected,sizeof shzguard_expected);
    gop_file=held("C:\\SHZGOP\\SHZGOP.VXD",shzgop_expected,sizeof shzgop_expected);
    if(guard_file==INVALID_HANDLE_VALUE || gop_file==INVALID_HANDLE_VALUE)goto done;
    nonce_file=CreateFileA("C:\\SHZGOP\\GPEPOCH.NON",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(nonce_file==INVALID_HANDLE_VALUE || GetFileSize(nonce_file,&high)!=32 || high ||
       !ReadFile(nonce_file,nonce,32,&got,NULL) || got!=32)goto done;
    /* Only the nongraphics bootstrap is loaded on an unproven baseline. Its
     * init callback performs no mappings, hypercall or graphics operation. */
    guard=CreateFileA("\\\\.\\C:\\SHZGOP\\SHZGUARD.VXD",0,0,NULL,OPEN_EXISTING,0,NULL);
    if(guard==INVALID_HANDLE_VALUE || !query(guard,first,nonce) ||
       !query(guard,second,nonce) || !equal(first,second,352))goto done;
    if(!log_snapshot("BEFORE_GOP_LOAD_SNAPSHOT_HEX=",first) ||
       !log_line("CURRENT_NATIVE_GOP_AND_GUARDIAN_ADMISSION=1\r\n"))goto done;
    /* Existing actual Win9x dynamic VxD contract. No delete-on-close flag on
     * the target: successful admission leaves it loaded for Win16's fresh
     * PM16 current-boot query. Still no class installation/default mutation. */
    gop=CreateFileA("\\\\.\\C:\\SHZGOP\\SHZGOP.VXD",0,0,NULL,OPEN_EXISTING,0,NULL);
    if(gop==INVALID_HANDLE_VALUE || !query(guard,second,nonce) || !equal(first,second,352))goto done;
    if(!log_snapshot("AFTER_GOP_LOAD_SNAPSHOT_HEX=",second))goto done;
    if(!log_line("GOP_DYNAMIC_LOAD_HANDLE_OBSERVED=1\r\nGPU_ACTIVE_UNVERIFIED=1\r\nDEFAULT_CHANGED=0\r\nMODE_CHANGED=0\r\n"))goto done;
    rc=0;
done:
    if(rc)log_line("FAIL=FIRSTLOAD_REFUSED_OR_FAILED\r\nDEFAULT_CHANGED=0\r\n");
    if(gop!=INVALID_HANDLE_VALUE && !CloseHandle(gop))rc=1;
    if(guard!=INVALID_HANDLE_VALUE && !CloseHandle(guard))rc=1;
    if(nonce_file!=INVALID_HANDLE_VALUE && !CloseHandle(nonce_file))rc=1;
    if(gop_file!=INVALID_HANDLE_VALUE && !CloseHandle(gop_file))rc=1;
    if(guard_file!=INVALID_HANDLE_VALUE && !CloseHandle(guard_file))rc=1;
    if(!CloseHandle(log_handle))rc=1;
    return rc;
}
void mainCRTStartup(void){ExitProcess(run());}
