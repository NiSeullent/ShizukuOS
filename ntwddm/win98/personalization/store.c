/* SPDX-License-Identifier: GPL-2.0-only */
#define WIN32_LEAN_AND_MEAN
#define WINVER 0x0410
#define _WIN32_WINNT 0x0400
#include <windows.h>
#include <string.h>
#include "store.h"
typedef struct paths {const char *file;char temporary[MAX_PATH],backup[MAX_PATH],lock[MAX_PATH];} paths;
static DWORD last_error(void){DWORD e=GetLastError();return e?e:ERROR_WRITE_FAULT;}
static int paths_init(paths *p,const char *file)
{
    unsigned n=0;
    if(!file){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
    while(n<MAX_PATH && file[n])++n;
    if(!n || n+5>MAX_PATH){SetLastError(ERROR_BUFFER_OVERFLOW);return 0;}
    p->file=file;
    memcpy(p->temporary,file,n);memcpy(p->temporary+n,".tmp",5);
    memcpy(p->backup,file,n);memcpy(p->backup+n,".bak",5);
    memcpy(p->lock,file,n);memcpy(p->lock+n,".lck",5);return 1;
}
/* Absent is distinct from access errors and directories. */
static int exists(const char *name,int *present)
{
    DWORD a=GetFileAttributesA(name);
    if(a==INVALID_FILE_ATTRIBUTES) {
        DWORD e=GetLastError();
        if(e!=ERROR_FILE_NOT_FOUND && e!=ERROR_PATH_NOT_FOUND)return 0;
        *present=0;return 1;
    }
    if(a&FILE_ATTRIBUTE_DIRECTORY){SetLastError(ERROR_ACCESS_DENIED);return 0;}
    *present=1;return 1;
}
/* Caller holds .lck with sharing denied. OPEN_ALWAYS leaves an empty lock file
 * but the live handle, not its existence, owns the lock; crashes release it. */
static int recover(const paths *p)
{
    int backup,file,temporary;
    if(!exists(p->backup,&backup) || !exists(p->file,&file))return 0;
    if(backup && !(file?DeleteFileA(p->backup):MoveFileA(p->backup,p->file)))return 0;
    if(!exists(p->temporary,&temporary))return 0;
    return !temporary || DeleteFileA(p->temporary);
}
static int write_exact(HANDLE h,const void *data,DWORD bytes)
{
    DWORD n;
    if(!WriteFile(h,data,bytes,&n,NULL))return 0;
    if(n!=bytes){SetLastError(ERROR_WRITE_FAULT);return 0;}
    return 1;
}
int pz98_store_write(const char *path,const void *first,uint32_t n,const void *second,uint32_t m)
{
    paths p;HANDLE lock=INVALID_HANDLE_VALUE,file=INVALID_HANDLE_VALUE;
    unsigned char readback[4096];DWORD size,i,error=ERROR_WRITE_FAULT;int temporary=0,old,ok=0;
    if(!n || !first || (m && !second) || n>PZ98_MAX_BYTES+54u || m>PZ98_MAX_BYTES+54u-n) {
        SetLastError(ERROR_INVALID_PARAMETER);return 0;
    }
    if(!paths_init(&p,path))return 0;
    lock=CreateFileA(p.lock,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(lock==INVALID_HANDLE_VALUE)return 0;
    if(!recover(&p))goto done;
    file=CreateFileA(p.temporary,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)goto done;
    temporary=1;
    if(!write_exact(file,first,n) || (m && !write_exact(file,second,m)) || !FlushFileBuffers(file))goto done;
    if(!CloseHandle(file))goto done;
    file=INVALID_HANDLE_VALUE;
    file=CreateFileA(p.temporary,GENERIC_READ,0,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)goto done;
    size=GetFileSize(file,NULL);
    if(size==INVALID_FILE_SIZE)goto done;
    if(size!=n+m){SetLastError(ERROR_CRC);goto done;}
    for(i=0;i<size;) {
        DWORD remaining,batch,got;const unsigned char *expected;
        if(i<n){remaining=n-i;expected=(const unsigned char *)first+i;}
        else {remaining=size-i;expected=(const unsigned char *)second+i-n;}
        batch=remaining>sizeof readback?sizeof readback:remaining;
        if(!ReadFile(file,readback,batch,&got,NULL))goto done;
        if(got!=batch || memcmp(readback,expected,batch)){SetLastError(ERROR_CRC);goto done;}
        i+=batch;
    }
    if(!CloseHandle(file))goto done;
    file=INVALID_HANDLE_VALUE;
    if(!exists(p.file,&old))goto done;
    if(old && !MoveFileA(p.file,p.backup))goto done;
    if(!MoveFileA(p.temporary,p.file)) {
        error=last_error();
        if(old)MoveFileA(p.backup,p.file); /* Failed rollback leaves the prior .bak. */
        SetLastError(error);goto done;
    }
    temporary=0;
    if(old && !DeleteFileA(p.backup))goto done; /* New file exists, report cleanup failure. */
    ok=1;
done:
    if(!ok)error=last_error();
    if(file!=INVALID_HANDLE_VALUE && !CloseHandle(file)) {if(ok){error=last_error();ok=0;}CloseHandle(file);}
    if(temporary)DeleteFileA(p.temporary);
    if(!CloseHandle(lock)){if(ok){error=last_error();ok=0;}CloseHandle(lock);}
    if(!ok)SetLastError(error);
    return ok;
}
int pz98_store_preferences(const char *path,pz98_preferences *out)
{
    paths p;HANDLE lock,file=INVALID_HANDLE_VALUE;DWORD got,size,error=ERROR_READ_FAULT;
    unsigned char record[PZ98_RECORD_BYTES];pz98_preferences candidate;int ok=0;
    if(!out){SetLastError(ERROR_INVALID_PARAMETER);return 0;}
    if(!paths_init(&p,path))return 0;
    lock=CreateFileA(p.lock,GENERIC_READ|GENERIC_WRITE,0,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
    if(lock==INVALID_HANDLE_VALUE)return 0;
    if(!recover(&p))goto done;
    file=CreateFileA(p.file,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(file==INVALID_HANDLE_VALUE)goto done;
    size=GetFileSize(file,NULL);
    if(size==INVALID_FILE_SIZE)goto done;
    if(size!=sizeof record){SetLastError(ERROR_INVALID_DATA);goto done;}
    if(!ReadFile(file,record,sizeof record,&got,NULL))goto done;
    if(got!=sizeof record || !pz98_decode(record,sizeof record,&candidate)){SetLastError(ERROR_INVALID_DATA);goto done;}
    if(!CloseHandle(file))goto done;
    file=INVALID_HANDLE_VALUE;
    if(!CloseHandle(lock)){error=last_error();CloseHandle(lock);SetLastError(error);return 0;}
    *out=candidate;return 1;
done:
    error=last_error();
    if(file!=INVALID_HANDLE_VALUE && !CloseHandle(file))CloseHandle(file);
    if(!CloseHandle(lock))CloseHandle(lock);
    if(!ok)SetLastError(error);
    return ok;
}
