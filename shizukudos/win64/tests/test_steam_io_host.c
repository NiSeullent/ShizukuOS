/* SPDX-License-Identifier: GPL-2.0-only
 * Production CopyFileExW on real POSIX files with injected partial/failed writes.
 * Win32 metadata adapters are checked for correct arguments, not guest behavior.
 */
#define _GNU_SOURCE
#define SHZ_STEAM_IO_HOST_TEST
#include "steam_io_host.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <assert.h>

struct file { int fd; DWORD access; };
static DWORD last_error, source_attributes=0x20, target_attributes;
static size_t partial_limit;
static int fail_write, zero_write, time_failure, live_handles, live_buffers, metadata_calls;
static FILETIME time_values[3];
static unsigned checks;
#define VERIFY(c) do { ++checks; if (!(c)) { fprintf(stderr,"FAIL:%d: %s\n",__LINE__,#c);abort(); } } while(0)
static char *narrow(LPCWSTR path,char out[256]) { unsigned i;for(i=0;path[i]&&i<255;++i)out[i]=(char)path[i];out[i]=0;return out; }
static void widen(const char *input,WCHAR out[256]) { unsigned i;for(i=0;input[i]&&i<255;++i)out[i]=(unsigned char)input[i];out[i]=0; }
DWORD shz_last_error(void) { return last_error; }
void shz_set_last_error(DWORD e) { last_error=e; }
BOOL k32_unsupported(const char *a,const char *b,DWORD e) { (void)a;(void)b;last_error=e;return FALSE; }
void *ShzProcessHeap(void) { return (void *)1; }
void *RtlAllocateHeap(void *h,DWORD f,size_t n) { void *p;(void)h;(void)f;p=malloc(n);if(p)++live_buffers;return p; }
BOOL RtlFreeHeap(void *h,DWORD f,void *p) { (void)h;(void)f;if(p){--live_buffers;free(p);}return TRUE; }
HANDLE WINAPI CreateFileW(LPCWSTR path,DWORD access,DWORD share,void *sec,DWORD disp,DWORD attrs,HANDLE tmpl)
{
 char name[256];int fd,flags=access&GENERIC_WRITE?O_RDWR:O_RDONLY;struct file *file;
 (void)share;(void)sec;(void)attrs;(void)tmpl;
 if(disp==CREATE_NEW)flags|=O_CREAT|O_EXCL;
 if(disp==CREATE_ALWAYS)flags|=O_CREAT|O_TRUNC;
 fd=open(narrow(path,name),flags,0600);
 if(fd<0){last_error=disp==CREATE_NEW?ERROR_FILE_EXISTS:ERROR_FILE_NOT_FOUND;return INVALID_HANDLE_VALUE;}
 file=malloc(sizeof *file);VERIFY(file!=NULL);file->fd=fd;file->access=access;++live_handles;return file;
}
BOOL WINAPI GetFileInformationByHandle(HANDLE h,BY_HANDLE_FILE_INFORMATION *out)
{
 struct stat statbuf;struct file *file=h;if(fstat(file->fd,&statbuf))return FALSE;
 memset(out,0,sizeof *out);out->dwFileAttributes=source_attributes;out->nFileSizeLow=(DWORD)statbuf.st_size;
 out->ftCreationTime.dwLowDateTime=111;out->ftLastAccessTime.dwLowDateTime=222;out->ftLastWriteTime.dwLowDateTime=333;return TRUE;
}
BOOL WINAPI GetFileSizeEx(HANDLE h,LARGE_INTEGER *out) { struct stat b;if(fstat(((struct file *)h)->fd,&b))return FALSE;out->QuadPart=b.st_size;return TRUE; }
DWORD WINAPI GetFileAttributesW(LPCWSTR path) { char name[256];if(access(narrow(path,name),F_OK))return INVALID_FILE_ATTRIBUTES;return target_attributes; }
BOOL WINAPI ReadFile(HANDLE h,void *b,DWORD n,DWORD *got,void *ov) { ssize_t r;(void)ov;r=read(((struct file *)h)->fd,b,n);if(r<0)return FALSE;*got=(DWORD)r;return TRUE; }
BOOL WINAPI WriteFile(HANDLE h,const void *b,DWORD n,DWORD *put,void *ov)
{
 ssize_t r;(void)ov;
 if(fail_write){last_error=ERROR_WRITE_FAULT;return FALSE;}
 if(zero_write){*put=0;return TRUE;}
 if(partial_limit&&n>partial_limit)n=(DWORD)partial_limit;
 r=write(((struct file *)h)->fd,b,n);if(r<0){last_error=ERROR_WRITE_FAULT;return FALSE;}*put=(DWORD)r;return TRUE;
}
BOOL WINAPI SetFileTime(HANDLE h,const FILETIME *c,const FILETIME *a,const FILETIME *w)
{
 VERIFY(((struct file *)h)->access&FILE_WRITE_ATTRIBUTES);
 if(time_failure){last_error=ERROR_ACCESS_DENIED;return FALSE;}
 time_values[0]=*c;time_values[1]=*a;time_values[2]=*w;++metadata_calls;return TRUE;
}
BOOL WINAPI SetFileAttributesW(LPCWSTR path,DWORD attrs) { char n[256];VERIFY(!access(narrow(path,n),F_OK));target_attributes=attrs;++metadata_calls;return TRUE; }
BOOL WINAPI CloseHandle(HANDLE h) { struct file *f=h;VERIFY(close(f->fd)==0);free(f);--live_handles;return TRUE; }
BOOL WINAPI DeleteFileW(LPCWSTR path) { char n[256];return unlink(narrow(path,n))==0; }
#include "../kernel32/k32_steam_io.c"

struct progress { DWORD action; unsigned calls,chunks; int64_t last,total; BOOL *cancel; };
static DWORD WINAPI progress(LARGE_INTEGER total,LARGE_INTEGER copied,LARGE_INTEGER stream,LARGE_INTEGER streamcopied,DWORD number,DWORD reason,HANDLE source,HANDLE target,LPVOID data)
{
 struct progress *p=data;
 VERIFY(source!=INVALID_HANDLE_VALUE&&target!=INVALID_HANDLE_VALUE&&source!=target);
 VERIFY(total.QuadPart==p->total&&stream.QuadPart==total.QuadPart&&streamcopied.QuadPart==copied.QuadPart);
 VERIFY(number==1&&copied.QuadPart>=p->last&&copied.QuadPart<=total.QuadPart);
 if(!p->calls)VERIFY(reason==CALLBACK_STREAM_SWITCH&&copied.QuadPart==0);
 else VERIFY(reason==CALLBACK_CHUNK_FINISHED&&copied.QuadPart>p->last);
 ++p->calls;p->last=copied.QuadPart;
 if(reason==CALLBACK_CHUNK_FINISHED){++p->chunks;if(p->cancel)*p->cancel=TRUE;return p->action;}
 return PROGRESS_CONTINUE;
}
static int64_t length(const char *path) { struct stat b;return stat(path,&b)?-1:b.st_size; }
static void match_file(const char *path,const BYTE *expected,size_t length_expected)
{
 BYTE buf[4096];size_t offset=0;int fd=open(path,O_RDONLY);VERIFY(fd>=0);
 while(offset<length_expected){ssize_t n=read(fd,buf,sizeof buf);VERIFY(n>0&&offset+(size_t)n<=length_expected);VERIFY(!memcmp(buf,expected+offset,(size_t)n));offset+=(size_t)n;}
 VERIFY(read(fd,buf,1)==0);close(fd);
}
int main(void)
{
 char directory[]="/tmp/shz-steam-copy-XXXXXX",source_name[256],target_name[256];WCHAR source[256],target[256];
 BYTE input[150003];size_t i;int fd;BOOL cancel=FALSE;struct progress p;
 VERIFY(mkdtemp(directory)!=NULL);snprintf(source_name,sizeof source_name,"%s/source",directory);snprintf(target_name,sizeof target_name,"%s/target",directory);
 widen(source_name,source);widen(target_name,target);
 for(i=0;i<sizeof input;++i)input[i]=(BYTE)(i*17+i/257);
 fd=open(source_name,O_WRONLY|O_CREAT|O_EXCL,0600);VERIFY(fd>=0);VERIFY(write(fd,input,sizeof input)==sizeof input);close(fd);
 partial_limit=997;memset(&p,0,sizeof p);p.total=sizeof input;
 VERIFY(CopyFileExW(source,target,progress,&p,NULL,0));VERIFY(p.chunks>3&&p.last==sizeof input);match_file(target_name,input,sizeof input);
 VERIFY(metadata_calls==2&&target_attributes==source_attributes&&time_values[0].dwLowDateTime==111&&time_values[1].dwLowDateTime==222&&time_values[2].dwLowDateTime==333);
 VERIFY(!CopyFileExW(source,target,NULL,NULL,NULL,COPY_FILE_FAIL_IF_EXISTS)&&last_error==ERROR_FILE_EXISTS);match_file(target_name,input,sizeof input);
 VERIFY(!CopyFileExW(source,target,NULL,NULL,NULL,2)&&last_error==ERROR_NOT_SUPPORTED);match_file(target_name,input,sizeof input);
 cancel=TRUE;VERIFY(!CopyFileExW(source,target,NULL,NULL,&cancel,0)&&last_error==ERROR_REQUEST_ABORTED);match_file(target_name,input,sizeof input);cancel=FALSE;
 target_attributes=FILE_ATTRIBUTE_READONLY;VERIFY(!CopyFileExW(source,target,NULL,NULL,NULL,COPY_FILE_FAIL_IF_EXISTS)&&last_error==ERROR_FILE_EXISTS);match_file(target_name,input,sizeof input);VERIFY(!CopyFileExW(source,target,NULL,NULL,NULL,0)&&last_error==ERROR_ACCESS_DENIED);match_file(target_name,input,sizeof input);target_attributes=0;
 source_attributes=FILE_ATTRIBUTE_REPARSE_POINT;VERIFY(!CopyFileExW(source,target,NULL,NULL,NULL,0)&&last_error==ERROR_NOT_SUPPORTED);match_file(target_name,input,sizeof input);source_attributes=0x20;
 memset(&p,0,sizeof p);p.total=sizeof input;p.action=PROGRESS_CANCEL;VERIFY(!CopyFileExW(source,target,progress,&p,NULL,0)&&last_error==ERROR_REQUEST_ABORTED);VERIFY(length(target_name)==-1);
 memset(&p,0,sizeof p);p.total=sizeof input;p.action=PROGRESS_STOP;VERIFY(!CopyFileExW(source,target,progress,&p,NULL,0)&&last_error==ERROR_REQUEST_ABORTED);VERIFY(length(target_name)==997);match_file(target_name,input,997);
 memset(&p,0,sizeof p);p.total=sizeof input;p.action=PROGRESS_QUIET;VERIFY(CopyFileExW(source,target,progress,&p,NULL,0));VERIFY(p.calls==2);match_file(target_name,input,sizeof input);
 memset(&p,0,sizeof p);p.total=sizeof input;p.cancel=&cancel;VERIFY(!CopyFileExW(source,target,progress,&p,&cancel,0)&&last_error==ERROR_REQUEST_ABORTED);VERIFY(length(target_name)==-1);cancel=FALSE;
 fail_write=1;VERIFY(!CopyFileExW(source,target,NULL,NULL,NULL,0)&&last_error==ERROR_WRITE_FAULT);VERIFY(length(target_name)==-1);fail_write=0;
 zero_write=1;VERIFY(!CopyFileExW(source,target,NULL,NULL,NULL,0)&&last_error==ERROR_WRITE_FAULT);VERIFY(length(target_name)==-1);zero_write=0;
 time_failure=1;VERIFY(!CopyFileExW(source,target,NULL,NULL,NULL,0)&&last_error==ERROR_ACCESS_DENIED);VERIFY(length(target_name)==-1);time_failure=0;
 VERIFY(live_handles==0&&live_buffers==0);unlink(source_name);unlink(target_name);rmdir(directory);
 printf("STEAM-COPY-HOST: %u checks passed, real-file partial writes/progress/cancellation/metadata adapters\n",checks);return 0;
}
