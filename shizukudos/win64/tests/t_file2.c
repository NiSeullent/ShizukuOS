/* SPDX-License-Identifier: GPL-2.0-only */
#include "k32test.h"
#include <fileapi.h>
static const WCHAR source[]=L"C:\\SHZ\\F2SOURCE.BIN";
static const WCHAR target[]=L"C:\\SHZ\\F2TARGET.BIN";
static BYTE block[65536];
static unsigned started,finished,streams,ended,callback_errors;
static COPYFILE2_MESSAGE_ACTION requested;
static ULONGLONG completed;
static BYTE expected_byte(ULONGLONG index){return (BYTE)((index*37u+(index>>8)*13u)^0x5a);}
static COPYFILE2_MESSAGE_ACTION CALLBACK observe(const COPYFILE2_MESSAGE *m,void *ctx)
{
    if(ctx!=(void*)(ULONG_PTR)0x6611||m->dwPadding) ++callback_errors;
    if(m->Type==COPYFILE2_CALLBACK_STREAM_STARTED){
        ++streams;
        if(m->Info.StreamStarted.dwStreamNumber!=1||m->Info.StreamStarted.uliTotalFileSize.QuadPart!=131089||
            m->Info.StreamStarted.hSourceFile==INVALID_HANDLE_VALUE||m->Info.StreamStarted.hDestinationFile==INVALID_HANDLE_VALUE)++callback_errors;
    }else if(m->Type==COPYFILE2_CALLBACK_CHUNK_STARTED){
        if(m->Info.ChunkStarted.uliChunkNumber.QuadPart!=started||m->Info.ChunkStarted.uliChunkSize.QuadPart!=(started<2?65536:17))++callback_errors;
        ++started;
    }else if(m->Type==COPYFILE2_CALLBACK_CHUNK_FINISHED){
        ++finished;completed+=finished<3?65536:17;
        if(m->Info.ChunkFinished.uliTotalBytesTransferred.QuadPart!=completed||m->Info.ChunkFinished.uliChunkNumber.QuadPart!=finished-1)++callback_errors;
        if(requested!=COPYFILE2_PROGRESS_CONTINUE)return requested;
    }else if(m->Type==COPYFILE2_CALLBACK_STREAM_FINISHED){
        ++ended;if(m->Info.StreamFinished.uliTotalBytesTransferred.QuadPart!=(requested==COPYFILE2_PROGRESS_STOP?65536:131089))++callback_errors;
    }else ++callback_errors;
    return COPYFILE2_PROGRESS_CONTINUE;
}
static void reset(COPYFILE2_MESSAGE_ACTION action){started=finished=streams=ended=callback_errors=0;completed=0;requested=action;}
static BOOL verify_bytes(LPCWSTR name)
{
    HANDLE h=CreateFileW(name,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    BYTE bytes[1024];DWORD got;ULONGLONG total=0;
    if(h==INVALID_HANDLE_VALUE)return FALSE;
    for(;;){if(!ReadFile(h,bytes,sizeof bytes,&got,NULL)){CloseHandle(h);return FALSE;}if(!got)break;
        for(DWORD i=0;i<got;++i) {
            if(bytes[i]!=expected_byte(total+i)){CloseHandle(h);return FALSE;}
        }
        total+=got;
    }
    return CloseHandle(h)&&total==131089;
}
int main(void)
{
    HANDLE h;DWORD put;COPYFILE2_EXTENDED_PARAMETERS p;CREATEFILE2_EXTENDED_PARAMETERS create;
    HRESULT result;BOOL cancel=FALSE;
    memset(&create,0,sizeof create);create.dwSize=sizeof create;create.dwFileAttributes=FILE_ATTRIBUTE_NORMAL;
    h=CreateFile2(source,GENERIC_WRITE,0,CREATE_NEW,&create);
    CHECK(h!=INVALID_HANDLE_VALUE,"CreateFile2 genuinely creates source");if(h==INVALID_HANDLE_VALUE)return 1;
    for(DWORD part=0;part<3;++part){DWORD n=part<2?65536:17;for(DWORD i=0;i<n;++i)block[i]=expected_byte((ULONGLONG)part*65536+i);
        CHECK(WriteFile(h,block,n,&put,NULL)&&put==n,"write independently patterned real source chunk");}
    CHECK(CloseHandle(h),"close actual source handle");
    CHECK(CopyFile2(source,source,NULL)==HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION),"actual same-file copy is refused before source truncation");
    CHECK(verify_bytes(source),"same-path refusal preserves every original source byte and EOF");
    CHECK(CopyFile2(source,L"c:\\shz\\.\\f2source.bin",NULL)==HRESULT_FROM_WIN32(ERROR_SHARING_VIOLATION),"actual normalized case/path alias identifies the same native file");
    CHECK(verify_bytes(source),"alias refusal preserves original source node and every byte");
    memset(&p,0,sizeof p);p.dwSize=sizeof p;p.dwCopyFlags=COPY_FILE_FAIL_IF_EXISTS;p.pProgressRoutine=observe;p.pvCallbackContext=(void*)(ULONG_PTR)0x6611;
    reset(COPYFILE2_PROGRESS_CONTINUE);result=CopyFile2(source,target,&p);
    CHECK(result==S_OK,"CopyFile2 completes actual three-chunk copy");
    CHECK(!callback_errors&&streams==1&&started==3&&finished==3&&ended==1&&completed==131089,"actual progress stream/chunk/byte/handle fields agree with independent oracle");
    CHECK(verify_bytes(target),"all actual131089 destination bytes and EOF match independent pattern");
    CHECK(CopyFile2(source,target,&p)==HRESULT_FROM_WIN32(ERROR_FILE_EXISTS),"fail-if-exists refuses actual existing destination");
    CHECK(verify_bytes(target),"refused overwrite preserves all existing destination bytes");
    CHECK(DeleteFileW(target),"remove actual destination for cancellation");
    reset(COPYFILE2_PROGRESS_CANCEL);CHECK(CopyFile2(source,target,&p)==HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED),"actual callback cancels after first completed chunk");
    CHECK(finished==1&&GetFileAttributesW(target)==INVALID_FILE_ATTRIBUTES,"cancel removes actual partial file");
    reset(COPYFILE2_PROGRESS_STOP);CHECK(CopyFile2(source,target,&p)==HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED),"actual callback stops copy after first chunk");
    CHECK(ended==1&&!callback_errors,"stopped actual stream reports its genuine partial completion");
    h=CreateFile2(target,GENERIC_READ,FILE_SHARE_READ,OPEN_EXISTING,NULL);
    if(h!=INVALID_HANDLE_VALUE){LARGE_INTEGER n;CHECK(GetFileSizeEx(h,&n)&&n.QuadPart==65536,"stop retains genuine65536-byte partial file");CloseHandle(h);}else CHECK(FALSE,"stop retains actual file");
    CHECK(DeleteFileW(target),"remove stopped partial file");
    reset(COPYFILE2_PROGRESS_QUIET);CHECK(CopyFile2(source,target,&p)==S_OK&&finished==1&&started==1&&ended==0,"quiet completes real copy while suppressing further callbacks");
    CHECK(verify_bytes(target)&&DeleteFileW(target),"quiet destination bytes are actual complete copy");
    cancel=TRUE;p.pfCancel=&cancel;reset(COPYFILE2_PROGRESS_CONTINUE);
    CHECK(CopyFile2(source,target,&p)==HRESULT_FROM_WIN32(ERROR_REQUEST_ABORTED)&&GetFileAttributesW(target)==INVALID_FILE_ATTRIBUTES,"initial actual cancel creates no destination");
    p.pfCancel=NULL;p.dwSize=1;CHECK(CopyFile2(source,target,&p)==HRESULT_FROM_WIN32(ERROR_INVALID_PARAMETER),"bad extended structure fails before any copy");
    p.dwSize=sizeof p;p.dwCopyFlags=COPY_FILE_RESTARTABLE;CHECK(CopyFile2(source,target,&p)==HRESULT_FROM_WIN32(ERROR_NOT_SUPPORTED)&&GetFileAttributesW(target)==INVALID_FILE_ATTRIBUTES,"unavailable restart checkpoints report unsupported before creation");
    create.dwSize=1;CHECK(CreateFile2(target,GENERIC_WRITE,0,CREATE_NEW,&create)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_INVALID_PARAMETER,"CreateFile2 rejects bad ABI size");
    create.dwSize=sizeof create;create.hTemplateFile=(HANDLE)(ULONG_PTR)123;
    CHECK(CreateFile2(target,GENERIC_WRITE,0,CREATE_NEW,&create)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_SUPPORTED&&GetFileAttributesW(target)==INVALID_FILE_ATTRIBUTES,"unavailable template metadata never creates a file");
    create.hTemplateFile=NULL;
    for (unsigned i=0;i<3;++i) {
        const DWORD unavailable[]={FILE_ATTRIBUTE_READONLY,FILE_ATTRIBUTE_HIDDEN,FILE_ATTRIBUTE_TEMPORARY};
        create.dwFileAttributes=unavailable[i];
        CHECK(CreateFile2(target,GENERIC_WRITE,0,CREATE_NEW,&create)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_SUPPORTED,"unavailable initial attributes are refused honestly");
        CHECK(GetFileAttributesW(target)==INVALID_FILE_ATTRIBUTES,"refused attributes do not create a success-shaped normal file");
    }
    create.dwFileAttributes=FILE_ATTRIBUTE_NORMAL;create.dwFileFlags=FILE_FLAG_WRITE_THROUGH;
    CHECK(CreateFile2(target,GENERIC_WRITE,0,CREATE_NEW,&create)==INVALID_HANDLE_VALUE&&GetLastError()==ERROR_NOT_SUPPORTED,"unavailable per-write device flush is refused before creation");
    CHECK(GetFileAttributesW(target)==INVALID_FILE_ATTRIBUTES,"write-through refusal creates no cached substitute file");
    CHECK(DeleteFileW(source),"remove original actual source");
    return k32t_finish("T_FILE2");
}
