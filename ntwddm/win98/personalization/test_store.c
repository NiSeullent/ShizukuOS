/* SPDX-License-Identifier: GPL-2.0-only
 * Actual production store.c with in-memory Win32 file boundary failure injection.
 * No claim that these mocks execute FAT, the Win98 kernel, or real sharing. */
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "store.h"
typedef struct {char name[MAX_PATH];unsigned char data[8192];DWORD length;int used,opened; } item;
typedef struct {item *file;DWORD offset;int live;} handle;
static item files[8];static handle handles[8];static DWORD error;
static unsigned checks,failed,calls,fail_at,live;
static int short_write,corrupt_read,rollback_failure,publish_failure;
static void check(int ok,unsigned line){++checks;if(!ok){++failed;fprintf(stderr,"store assertion %u\n",line);}}
#define CHECK(x) check(!!(x),__LINE__)
static int fault(void){++calls;if(calls==fail_at){error=ERROR_ACCESS_DENIED;return 1;}return 0;}
static item *find(const char *name){unsigned i;for(i=0;i<8;i++)if(files[i].used && !strcmp(files[i].name,name))return files+i;return NULL;}
static item *add(const char *name,const void *data,DWORD bytes){unsigned i;item *p=find(name);if(!p)for(i=0;i<8;i++)if(!files[i].used){p=files+i;break;}if(!p || bytes>8192)abort();memset(p,0,sizeof *p);p->used=1;strcpy(p->name,name);p->length=bytes;if(bytes)memcpy(p->data,data,bytes);return p;}
static void reset(void){memset(files,0,sizeof files);memset(handles,0,sizeof handles);calls=fail_at=live=0;error=0;short_write=corrupt_read=rollback_failure=publish_failure=0;}
DWORD GetLastError(void){return error;}void SetLastError(DWORD e){error=e;}
HANDLE CreateFileA(const char *name,DWORD access,DWORD share,void *security,DWORD disposition,DWORD attrs,HANDLE template)
{
    item *p;unsigned i;(void)access;(void)share;(void)security;(void)attrs;(void)template;
    if(fault())return INVALID_HANDLE_VALUE;
    p=find(name);
    if(p && p->opened){error=ERROR_SHARING_VIOLATION;return INVALID_HANDLE_VALUE;}
    if(disposition==CREATE_NEW && p){error=ERROR_ALREADY_EXISTS;return INVALID_HANDLE_VALUE;}
    if(!p && disposition==OPEN_EXISTING){error=ERROR_FILE_NOT_FOUND;return INVALID_HANDLE_VALUE;}
    if(!p)p=add(name,NULL,0);
    for(i=0;i<8;i++)if(!handles[i].live){handles[i].file=p;handles[i].offset=0;handles[i].live=1;p->opened++;live++;return handles+i;}
    abort();
}
BOOL WriteFile(HANDLE file,const void *data,DWORD bytes,DWORD *written,void *overlapped)
{
    handle *h=file;(void)overlapped;if(fault())return 0;if(!h->live || bytes>8192-h->offset)abort();
    *written=short_write && bytes?bytes-1:bytes;memcpy(h->file->data+h->offset,data,*written);h->offset+=*written;h->file->length=h->offset;return 1;
}
BOOL ReadFile(HANDLE file,void *data,DWORD bytes,DWORD *read,void *overlapped)
{
    handle *h=file;(void)overlapped;if(fault())return 0;if(!h->live)abort();
    *read=bytes<h->file->length-h->offset?bytes:h->file->length-h->offset;
    memcpy(data,h->file->data+h->offset,*read);h->offset+=*read;if(corrupt_read && *read)((unsigned char *)data)[0]^=1;return 1;
}
BOOL FlushFileBuffers(HANDLE h){(void)h;return !fault();}
BOOL CloseHandle(HANDLE file){handle *h=file;if(fault())return 0;if(!h->live)abort();h->live=0;h->file->opened--;live--;return 1;}
DWORD GetFileSize(HANDLE file,DWORD *high){handle *h=file;if(fault())return INVALID_FILE_SIZE;if(high)*high=0;return h->file->length;}
DWORD GetFileAttributesA(const char *name){if(fault())return INVALID_FILE_ATTRIBUTES;if(!find(name)){error=ERROR_FILE_NOT_FOUND;return INVALID_FILE_ATTRIBUTES;}return FILE_ATTRIBUTE_NORMAL;}
BOOL DeleteFileA(const char *name){item *p;if(fault())return 0;p=find(name);if(!p){error=ERROR_FILE_NOT_FOUND;return 0;}if(p->opened){error=ERROR_SHARING_VIOLATION;return 0;}p->used=0;return 1;}
BOOL MoveFileA(const char *from,const char *to){item *p;if(fault() || (rollback_failure && strstr(from,".bak")) || (publish_failure && strstr(from,".tmp"))){error=ERROR_ACCESS_DENIED;return 0;}p=find(from);if(!p){error=ERROR_FILE_NOT_FOUND;return 0;}if(p->opened || find(to)){error=ERROR_ACCESS_DENIED;return 0;}strcpy(p->name,to);return 1;}
static int bytes_equal(const char *name,const void *data,DWORD bytes){item *p=find(name);return p && p->length==bytes && !memcmp(p->data,data,bytes);}
int main(void)
{
    static const unsigned char old[]={1,2,3,4},a[]={9,8,7},b[]={6,5};unsigned count,i;
    pz98_preferences p,q;unsigned char record[PZ98_RECORD_BYTES];
    reset();CHECK(pz98_store_write("prefs",a,sizeof a,b,sizeof b));CHECK(bytes_equal("prefs","\11\10\7\6\5",5));CHECK(live==0 && !find("prefs.tmp") && !find("prefs.bak"));
    reset();add("prefs",old,sizeof old);CHECK(pz98_store_write("prefs",a,sizeof a,b,sizeof b));count=calls;CHECK(live==0 && !find("prefs.bak"));
    for(i=1;i<=count;i++) {
        reset();add("prefs",old,sizeof old);fail_at=i;
        if(pz98_store_write("prefs",a,sizeof a,b,sizeof b))CHECK(bytes_equal("prefs","\11\10\7\6\5",5));
        else {CHECK(GetLastError()!=0);CHECK(bytes_equal("prefs",old,sizeof old) || bytes_equal("prefs.bak",old,sizeof old) || bytes_equal("prefs","\11\10\7\6\5",5));}
        CHECK(live==0);
    }
    reset();add("prefs",old,sizeof old);short_write=1;CHECK(!pz98_store_write("prefs",a,sizeof a,NULL,0));CHECK(GetLastError()==ERROR_WRITE_FAULT && bytes_equal("prefs",old,sizeof old) && live==0);
    reset();add("prefs",old,sizeof old);corrupt_read=1;CHECK(!pz98_store_write("prefs",a,sizeof a,NULL,0));CHECK(GetLastError()==ERROR_CRC && bytes_equal("prefs",old,sizeof old) && live==0);
    reset();add("prefs",old,sizeof old);publish_failure=1;CHECK(!pz98_store_write("prefs",a,sizeof a,NULL,0));CHECK(bytes_equal("prefs",old,sizeof old) && !find("prefs.bak") && live==0);
    reset();add("prefs",old,sizeof old);publish_failure=rollback_failure=1;CHECK(!pz98_store_write("prefs",a,sizeof a,NULL,0));CHECK(!find("prefs") && bytes_equal("prefs.bak",old,sizeof old) && live==0);
    publish_failure=rollback_failure=0;CHECK(pz98_store_write("prefs",a,sizeof a,NULL,0));CHECK(bytes_equal("prefs",a,sizeof a) && !find("prefs.bak") && live==0);
    reset();add("prefs.bak",old,sizeof old);add("prefs.tmp",b,sizeof b);CHECK(pz98_store_write("prefs",a,sizeof a,NULL,0));CHECK(bytes_equal("prefs",a,sizeof a) && !find("prefs.bak") && live==0);
    reset();add("prefs",old,sizeof old);add("prefs.bak",b,sizeof b);CHECK(pz98_store_write("prefs",a,sizeof a,NULL,0));CHECK(bytes_equal("prefs",a,sizeof a) && !find("prefs.bak"));
    reset();add("prefs.lck",NULL,0)->opened=1;CHECK(!pz98_store_write("prefs",a,sizeof a,NULL,0));CHECK(!find("prefs") && !find("prefs.tmp"));
    reset();CHECK(!pz98_store_write("prefs",NULL,1,NULL,0));CHECK(calls==0 && GetLastError()==ERROR_INVALID_PARAMETER);
    pz98_defaults(&p);p.scene=1;p.paused=1;CHECK(pz98_encode(&p,record,sizeof record));
    reset();add("prefs.bak",record,sizeof record);add("prefs.tmp",b,sizeof b);pz98_defaults(&q);CHECK(pz98_store_preferences("prefs",&q));CHECK(!memcmp(&p,&q,sizeof p) && bytes_equal("prefs",record,sizeof record) && !find("prefs.bak") && !find("prefs.tmp") && live==0);
    reset();add("prefs",record,sizeof record);CHECK(pz98_store_preferences("prefs",&q));count=calls;
    for(i=1;i<=count;i++) {
        reset();add("prefs",record,sizeof record);fail_at=i;pz98_defaults(&q);
        CHECK(!pz98_store_preferences("prefs",&q));CHECK(q.scene==0 && q.paused==0 && GetLastError()==ERROR_ACCESS_DENIED && live==0);
    }
    record[7]^=1;reset();add("prefs",record,sizeof record);q=p;CHECK(!pz98_store_preferences("prefs",&q));CHECK(!memcmp(&p,&q,sizeof p) && live==0);
    printf("%s: %u production store checks, %u failures; Win32 file boundaries mocked\n",failed?"FAIL":"PASS",checks,failed);return failed?1:0;
}
