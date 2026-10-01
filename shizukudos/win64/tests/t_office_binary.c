/* SPDX-License-Identifier: GPL-2.0-only */
#include "k32test.h"
typedef BOOL (WINAPI *binary_w_fn)(LPCWSTR,LPDWORD);
typedef BOOL (WINAPI *binary_a_fn)(LPCSTR,LPDWORD);
static void put16(BYTE *p,unsigned v){p[0]=(BYTE)v;p[1]=(BYTE)(v>>8);}
static void put32(BYTE *p,DWORD v){unsigned i;for(i=0;i<4;++i)p[i]=(BYTE)(v>>(i*8));}
static BOOL write_fixture(LPCWSTR path,const BYTE *bytes,DWORD size)
{
    HANDLE file=CreateFileW(path,GENERIC_WRITE,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);DWORD written;BOOL result;
    if(file==INVALID_HANDLE_VALUE)return FALSE;
    result=WriteFile(file,bytes,size,&written,NULL)&&written==size;CloseHandle(file);return result;
}
int main(void)
{
    HMODULE module=GetModuleHandleW(L"kernel32.dll");
    binary_w_fn wide=module?(binary_w_fn)GetProcAddress(module,"GetBinaryTypeW"):NULL;
    binary_a_fn ansi=module?(binary_a_fn)GetProcAddress(module,"GetBinaryTypeA"):NULL;
    WCHAR self[512];BYTE bytes[1024];DWORD type,error;BOOL result;
    static const WCHAR path[]=L"C:\\SHZ\\OFFICE_BINARY.COM",txt[]=L"C:\\SHZ\\OFFICE_BINARY.TXT";
    CHECK(wide&&ansi,"both actual binary-classification exports resolve");if(!wide||!ansi)return 1;
    CHECK(GetModuleFileNameW(NULL,self,512)>0,"obtain actual guest test executable path");
    type=99;CHECK(wide(self,&type)&&type==SCS_64BIT_BINARY,"actual AMD64 guest executable classifies from its real headers");
    type=99;result=wide(L"C:\\SHZ\\SYS64\\KERNEL32.DLL",&type);error=GetLastError();
    CHECK(!result&&type==99&&error==ERROR_BAD_EXE_FORMAT,"real DLL fails application classification without changing output");
    type=99;result=wide(L"C:\\SHZ\\NO_SUCH_BINARY.EXE",&type);error=GetLastError();
    CHECK(!result&&type==99&&error==ERROR_FILE_NOT_FOUND,"missing file propagates real open failure");
    result=wide(NULL,&type);error=GetLastError();CHECK(!result&&error==ERROR_INVALID_PARAMETER,"null path fails before file access");
    memset(bytes,0,sizeof bytes);bytes[0]='M';bytes[1]='Z';put16(bytes+8,4);
    CHECK(write_fixture(path,bytes,sizeof bytes),"create actual DOS-header fixture file");
    CHECK(wide(path,&type)&&type==SCS_DOS_BINARY,"real MZ DOS file classification");
    put32(bytes+60,128);memcpy(bytes+128,"PE\0\0",4);put16(bytes+132,0x8664);put16(bytes+134,1);put16(bytes+148,240);put16(bytes+150,2);
    put16(bytes+152,0x20b);put32(bytes+208,8192);put32(bytes+212,512);put32(bytes+400,16);put32(bytes+404,4096);put32(bytes+408,512);put32(bytes+412,512);
    CHECK(write_fixture(path,bytes,sizeof bytes),"write actual PE32+ fixture over DOS file");
    CHECK(wide(path,&type)&&type==SCS_64BIT_BINARY,"PE headers take precedence over COM extension");
    CHECK(ansi("C:\\SHZ\\OFFICE_BINARY.COM",&type)&&type==SCS_64BIT_BINARY,"ANSI classifier reads the same actual PE32+ file");
    memset(bytes+128,0,64);bytes[128]='N';bytes[129]='E';bytes[182]=2;
    CHECK(write_fixture(path,bytes,sizeof bytes),"write explicit Windows NE fixture");
    CHECK(wide(path,&type)&&type==SCS_WOW_BINARY,"actual NE Windows16 target classification");
    bytes[182]=1;CHECK(write_fixture(path,bytes,sizeof bytes)&&wide(path,&type)&&type==SCS_OS216_BINARY,"actual NE OS216 target classification");
    bytes[182]=0;CHECK(write_fixture(path,bytes,sizeof bytes),"write ambiguous NE fixture");
    type=99;result=wide(path,&type);error=GetLastError();CHECK(!result&&type==99&&error==ERROR_NOT_SUPPORTED,"ambiguous NE target fails explicitly");
    memset(bytes,0,sizeof bytes);CHECK(write_fixture(path,bytes,3),"write actual non-MZ COM input");
    CHECK(wide(path,&type)&&type==SCS_DOS_BINARY,"native non-MZ COM extension fallback");
    CHECK(write_fixture(txt,bytes,3),"write actual unsupported file input");
    type=99;result=wide(txt,&type);error=GetLastError();CHECK(!result&&type==99&&error==ERROR_BAD_EXE_FORMAT,"unsupported file has no fabricated binary type");
    CHECK(DeleteFileW(path)&&DeleteFileW(txt),"remove probe-owned fixture files");
    return k32t_finish("T_OFFICE_BINARY");
}
