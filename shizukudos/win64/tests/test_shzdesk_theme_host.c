/* SPDX-License-Identifier: GPL-2.0-only */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>
#include <stdlib.h>
#if !__has_include("../apps/shzdesk/theme.h")
int main(void) { puts("FAIL: production theme selection and persistence are missing"); return 1; }
#else
#define SHZ_THEME_HOST_TEST 1
typedef uint32_t DWORD;
typedef int BOOL;
typedef intptr_t HANDLE;
typedef wchar_t WCHAR;
typedef uint32_t COLORREF;
typedef union { long long QuadPart; } LARGE_INTEGER;
#define INVALID_HANDLE_VALUE ((HANDLE)-1)
#define GENERIC_READ 1u
#define GENERIC_WRITE 2u
#define FILE_SHARE_READ 1u
#define OPEN_EXISTING 3u
#define CREATE_NEW 1u
#define FILE_ATTRIBUTE_NORMAL 0u
#define MOVEFILE_REPLACE_EXISTING 1u
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_PATH_NOT_FOUND 3u
#define ERROR_INVALID_DATA 13u
#define ERROR_READ_FAULT 30u
#define ERROR_WRITE_FAULT 29u
#define ERROR_HANDLE_EOF 38u
#define ERROR_INVALID_PARAMETER 87u
struct fixture { char data[40]; unsigned bytes, position; int exists, opened; } files[2];
static unsigned checks, call_write, call_read, call_flush, call_close, call_move, call_delete;
static DWORD last_error;
static int fault_write, fault_zero, fault_over, fault_flush, fault_close, fault_read, fault_corrupt, fault_move, fault_size;
static unsigned short_write, short_read;
#define CHECK(x) do { ++checks; if (!(x)) { fprintf(stderr,"FAIL line=%d: %s\n",__LINE__,#x); exit(1); } } while (0)
static DWORD GetLastError(void) { return last_error; }
static HANDLE CreateFileW(const WCHAR *name,DWORD access,DWORD share,void *security,DWORD mode,DWORD attrs,HANDLE template_handle)
{
    unsigned at = wcsstr(name,L"SHZTHNEW") ? 1u : 0u;
    struct fixture *f=&files[at]; (void)access;(void)share;(void)security;(void)attrs;(void)template_handle;
    if (mode==CREATE_NEW && f->exists) { last_error=80; return INVALID_HANDLE_VALUE; }
    if (mode==OPEN_EXISTING && !f->exists) { last_error=ERROR_FILE_NOT_FOUND; return INVALID_HANDLE_VALUE; }
    if (mode==CREATE_NEW) { f->exists=1; f->bytes=0; }
    f->opened=1; f->position=0; return (HANDLE)(at+1u);
}
static BOOL GetFileSizeEx(HANDLE h,LARGE_INTEGER *size) { if(fault_size){last_error=0;return 0;}size->QuadPart=files[h-1].bytes;return 1; }
static BOOL ReadFile(HANDLE h,void *buffer,DWORD size,DWORD *got,void *overlap)
{
    struct fixture *f=&files[h-1]; unsigned n=f->bytes-f->position; (void)overlap;++call_read;
    if(fault_read) { last_error=fault_read==2 ? 0 : ERROR_READ_FAULT;return 0; }
    if(n>size)n=size;
    if(short_read && n>short_read)n=short_read;
    memcpy(buffer,f->data+f->position,n); f->position+=n; *got=n;
    if(fault_corrupt && h==2 && n) ((char*)buffer)[0]^=1;
    return 1;
}
static BOOL WriteFile(HANDLE h,const void *buffer,DWORD size,DWORD *written,void *overlap)
{
    struct fixture *f=&files[h-1]; DWORD n=size; (void)overlap;++call_write;
    if(fault_write) { last_error=fault_write==2 ? 0 : ERROR_WRITE_FAULT;return 0; }
    if(fault_zero) { *written=0;return 1; }
    if(fault_over) { *written=size+1;return 1; }
    if(short_write && n>short_write)n=short_write;
    if(f->position+n>sizeof f->data) { last_error=ERROR_WRITE_FAULT;return 0; }
    memcpy(f->data+f->position,buffer,n);f->position+=n;f->bytes=f->position;*written=n;return 1;
}
static BOOL FlushFileBuffers(HANDLE h) { (void)h;++call_flush;if(fault_flush){last_error=ERROR_WRITE_FAULT;return 0;}return 1; }
static BOOL CloseHandle(HANDLE h) { files[h-1].opened=0;++call_close;if(fault_close){last_error=6;return 0;}return 1; }
static BOOL MoveFileExW(const WCHAR *from,const WCHAR *to,DWORD flags)
{
    (void)from;(void)to;CHECK(flags==MOVEFILE_REPLACE_EXISTING);++call_move;
    if(fault_move){last_error=5;return 0;}files[0]=files[1];files[0].opened=0;memset(&files[1],0,sizeof files[1]);return 1;
}
static BOOL DeleteFileW(const WCHAR *path) { (void)path;++call_delete;memset(&files[1],0,sizeof files[1]);return 1; }
#include "../apps/shzdesk/theme.h"
static void reset(void)
{
    memset(files,0,sizeof files);last_error=0;
    call_write=call_read=call_flush=call_close=call_move=call_delete=0;
    fault_write=fault_zero=fault_over=fault_flush=fault_close=fault_read=fault_corrupt=fault_move=fault_size=0;
    short_write=short_read=0;
}
int main(void)
{
    char record[SHZ_THEME_RECORD_BYTES]={0}, mutated[40];unsigned style,i,j;DWORD error;
    CHECK(shz_theme_palette(SHZ_THEME_CLASSIC)->desktop==0x00808000u);
    CHECK(shz_theme_palette(SHZ_THEME_SHIZUKU)->desktop!=shz_theme_palette(SHZ_THEME_CLASSIC)->desktop);
    CHECK(shz_theme_palette(99)==NULL);
    CHECK(!shz_theme_encode(SHZ_THEME_CLASSIC,NULL));CHECK(!shz_theme_decode(NULL,SHZ_THEME_RECORD_BYTES,&style));CHECK(!shz_theme_decode(record,SHZ_THEME_RECORD_BYTES,NULL));
    for(style=SHZ_THEME_CLASSIC;style<=SHZ_THEME_SHIZUKU;++style){
        unsigned decoded=99;
        CHECK(shz_theme_encode(style,record));CHECK(shz_theme_decode(record,sizeof record,&decoded));CHECK(decoded==style);
        for(i=0;i<40;++i)if(i!=sizeof record){decoded=99;memset(mutated,0,sizeof mutated);memcpy(mutated,record,sizeof record);CHECK(!shz_theme_decode(mutated,i,&decoded));CHECK(decoded==99);}
        for(i=0;i<sizeof record;++i){memcpy(mutated,record,sizeof record);mutated[i]^=0x40;decoded=99;CHECK(!shz_theme_decode(mutated,sizeof record,&decoded));CHECK(decoded==99);}
        reset();short_write=3;short_read=2;CHECK(shz_theme_save(style,&error));CHECK(error==0);CHECK(call_write==6);CHECK(call_flush==1);CHECK(call_move==1);CHECK(!files[1].exists);
        decoded=99;CHECK(shz_theme_load(&decoded,&error)==1);CHECK(decoded==style);CHECK(error==0);CHECK(!files[0].opened);
    }
    reset();style=99;CHECK(shz_theme_load(&style,&error)==0);CHECK(style==99);CHECK(error==0);
    memset(record,'Q',sizeof record);CHECK(!shz_theme_encode(0,record));for(i=0;i<sizeof record;++i)CHECK(record[i]=='Q');
    reset();CHECK(!shz_theme_save(99,&error));CHECK(error==ERROR_INVALID_PARAMETER);CHECK(call_write==0);
    for(j=0;j<11;++j){
        reset();CHECK(shz_theme_save(SHZ_THEME_CLASSIC,&error));memcpy(record,files[0].data,sizeof record);
        call_write=call_read=call_flush=call_close=call_move=call_delete=0;
        switch(j){case 0:fault_write=1;break;case 1:fault_zero=1;break;case 2:fault_over=1;break;case 3:fault_flush=1;break;case 4:fault_close=1;break;case 5:fault_read=1;break;case 6:fault_corrupt=1;break;case 7:fault_move=1;break;case 8:fault_write=2;break;case 9:fault_read=2;break;case 10:fault_size=1;break;}
        CHECK(!shz_theme_save(SHZ_THEME_SHIZUKU,&error));CHECK(error!=0);CHECK(files[0].exists);CHECK(!memcmp(record,files[0].data,sizeof record));CHECK(!files[1].exists);CHECK(!files[1].opened);
    }
    reset();files[1].exists=1;memcpy(files[1].data,"other",5);files[1].bytes=5;CHECK(!shz_theme_save(SHZ_THEME_CLASSIC,&error));CHECK(call_delete==0);CHECK(files[1].bytes==5);CHECK(!memcmp(files[1].data,"other",5));
    for(i=0;i<40;++i)if(i!=SHZ_THEME_RECORD_BYTES){reset();files[0].exists=1;files[0].bytes=i;style=99;CHECK(shz_theme_load(&style,&error)==-1);CHECK(style==99);CHECK(error==ERROR_INVALID_DATA);CHECK(call_read==0);CHECK(!files[0].opened);}
    reset();files[0].exists=1;files[0].bytes=SHZ_THEME_RECORD_BYTES;memset(files[0].data,'?',SHZ_THEME_RECORD_BYTES);style=99;CHECK(shz_theme_load(&style,&error)==-1);CHECK(style==99);CHECK(error==ERROR_INVALID_DATA);
    reset();CHECK(shz_theme_save(SHZ_THEME_CLASSIC,&error));fault_close=1;style=99;CHECK(shz_theme_load(&style,&error)==-1);CHECK(style==99);CHECK(error==6);
    printf("PASS %u production theme palette/record/persistence checks; Windows98 native acceptance unverified\n",checks);return 0;
}
#endif
