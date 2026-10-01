#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Test actual probe C on Linux; Windows acceptance remains explicitly false.

Default: mock Win32/SSPI calls and protocol results, with actual SHA-256 file
hashing, gcc and clang ASan/UBSan fault cases. --real-protocol: execute the actual
protocol body with a real isolated Linux SSPI/TLS DSO and independent server.
Neither mode loads a Windows DLL, runs a guest, opens a socket or installs an OS
provider. Sources, binaries, logs and receipts stay in a NEW build directory.
All tools are local; this script does not install tools or download inputs.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SOURCES = ("sspi_guest_probe.c", "sspi_guest_probe_host_test.py", "sspi_native.h",
           "sspi_stream.h", "transport.h", "native_runtime.h", "sspi_native_host_test.py")


def digest(path):
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            value.update(block)
    return value.hexdigest()


def read_shim():
    # Read the reviewed ABI literal without executing any existing test script.
    module = ast.parse((HERE / "sspi_native_host_test.py").read_text())
    matches = [ast.literal_eval(node.value) for node in module.body
               if isinstance(node, ast.Assign)
               and any(isinstance(target, ast.Name) and target.id == "SHIM"
                       for target in node.targets)]
    if len(matches) != 1 or not isinstance(matches[0], str):
        raise RuntimeError("Expected exactly one literal ABI shim")
    return matches[0]


HEADER = r'''#ifndef M98SSPI_PROBE_TEST_WINDOWS_H
#define M98SSPI_PROBE_TEST_WINDOWS_H
#include "sspi_native_test_win32.h"
typedef void *HANDLE, *HMODULE;
typedef void (*FARPROC)(void);
typedef PSecurityFunctionTableA (*INIT_SECURITY_INTERFACE_A)(void);
#define FALSE 0
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)(uintptr_t)-1)
#define INVALID_FILE_ATTRIBUTES UINT32_C(0xffffffff)
#define INVALID_FILE_SIZE UINT32_C(0xffffffff)
#define ERROR_FILE_NOT_FOUND 2u
#define ERROR_HANDLE_EOF 38u
#define ERROR_SUCCESS 0u
#define GENERIC_READ UINT32_C(0x80000000)
#define GENERIC_WRITE UINT32_C(0x40000000)
#define FILE_SHARE_READ 1u
#define CREATE_NEW 1u
#define OPEN_EXISTING 3u
#define FILE_ATTRIBUTE_NORMAL 128u
#define FILE_FLAG_SEQUENTIAL_SCAN UINT32_C(0x08000000)
#define VER_PLATFORM_WIN32_WINDOWS 1u
#define FILE_BEGIN 0u
typedef struct { DWORD dwOSVersionInfoSize,dwMajorVersion,dwMinorVersion,
 dwBuildNumber,dwPlatformId; char szCSDVersion[128]; } OSVERSIONINFOA;
char *GetCommandLineA(void);
DWORD GetModuleFileNameA(HMODULE,char *,DWORD);
void SetLastError(DWORD);
DWORD GetLastError(void);
DWORD GetFileAttributesA(const char *);
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
DWORD GetFileSize(HANDLE,DWORD *);
BOOL ReadFile(HANDLE,void *,DWORD,DWORD *,void *);
BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
BOOL GetVersionExA(OSVERSIONINFOA *);
DWORD GetCurrentProcessId(void);
DWORD GetCurrentThreadId(void);
DWORD GetTickCount(void);
HMODULE LoadLibraryA(const char *);
FARPROC GetProcAddress(HMODULE,const char *);
BOOL FreeLibrary(HMODULE);
void ExitProcess(DWORD);
void Sleep(DWORD);
#endif
'''

DRIVER = r'''#define M98SSPI_HOST_TEST 1
#define M98SSPI_GUEST_HOST_TEST 1
#define M98_PROBE_DLL_SHA256 "MODEL_DLL_HASH"
#define M98_PROBE_DLL_BYTES MODEL_DLL_SIZEu
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "windows.h"
#include "PROBE_SOURCE"

enum fault { F_NONE, F_WRONG_SELF, F_LOG_EXISTS, F_ATTR_ERROR, F_OPEN_RACE,
 F_OS_QUERY, F_OS_NT, F_OS_MAJOR, F_OS_MINOR, F_OS_BUILD,
 F_DLL_OPEN, F_DLL_READ, F_DLL_ZERO, F_DLL_OVERCOUNT, F_DLL_TRUNCATED,
 F_DLL_CORRUPT, F_DLL_CLOSE, F_LOAD, F_SYMBOL, F_NULL_TABLE,
 F_TABLE_VERSION, F_TABLE_MEMBER, F_PACKAGE, F_FREE_PACKAGE, F_FREE_DLL,
 F_WRITE, F_ZERO_WRITE, F_OVER_WRITE, F_SHORT_WRITE, F_FLUSH,
 F_LATE_WRITE, F_LATE_FLUSH, F_CLOSE_LOG, F_SHORT_READ,
 F_MODULE_PATH, F_MODULE_LENGTH, F_SIZE, F_SIZE_HIGH, F_TRAILING,
 F_EXPORT_BINDING, F_ROOT_UNAVAILABLE, F_ROOT_FREE, F_DLL_DEADLINE };
static enum fault selected;
static char commandline[512], log_bytes[131072];
static size_t log_used, dll_offset;
static DWORD last_error, observed_exit, protocol_result;
static DWORD mock_ticks=223344;
static unsigned check_count, write_calls, flush_calls, log_closes, dll_closes;
static unsigned loads, unloads, protocol_calls;
static unsigned root_acquires, root_frees;
static const char *missing_symbol;
static FILE *fixture_file;
static jmp_buf escaped;
#define REPORT ((HANDLE)(uintptr_t)16)
#define INPUT ((HANDLE)(uintptr_t)32)
#define MODULE ((HMODULE)(uintptr_t)48)
#define REQUIRE(test) do { if (!(test)) { fprintf(stderr,"MODEL ASSERT line=%u: %s\n",(unsigned)__LINE__,#test); exit(100); } } while (0)
static void pass(const char *name) { ++check_count; printf("PASS %s\n",name); }

char *GetCommandLineA(void) { return commandline; }
DWORD GetModuleFileNameA(HMODULE module,char *out,DWORD capacity) {
 const char *path=module==MODULE?(selected==F_MODULE_PATH?"C:\\OTHER\\M98SSPI.DLL":"C:\\GOPLAB\\M98SSPI.DLL"):
  selected==F_WRONG_SELF?"C:\\OTHER\\TLS13PRB.EXE":"C:\\GOPLAB\\TLS13PRB.EXE";
 REQUIRE((!module||module==MODULE)&&capacity>strlen(path));
 strcpy(out,path);return module==MODULE&&selected==F_MODULE_LENGTH?capacity:(DWORD)strlen(path);
}
void SetLastError(DWORD value) { last_error=value; }
DWORD GetLastError(void) { return last_error; }
DWORD GetFileAttributesA(const char *path) {
 REQUIRE(!strcmp(path,"C:\\GOPLAB\\SSPI13.LOG"));
 if(selected==F_LOG_EXISTS)return FILE_ATTRIBUTE_NORMAL;
 last_error=selected==F_ATTR_ERROR?5u:ERROR_FILE_NOT_FOUND;
 return INVALID_FILE_ATTRIBUTES;
}
HANDLE CreateFileA(const char *path,DWORD access,DWORD share,void *security,
 DWORD mode,DWORD attributes,HANDLE template_) {
 REQUIRE(!security&&!template_);
 if(!strcmp(path,"C:\\GOPLAB\\SSPI13.LOG")){
  REQUIRE(access==GENERIC_WRITE&&!share&&mode==CREATE_NEW&&attributes==FILE_ATTRIBUTE_NORMAL);
  if(selected==F_OPEN_RACE||selected==F_LOG_EXISTS){last_error=80;return INVALID_HANDLE_VALUE;}return REPORT;
 }
 REQUIRE(!strcmp(path,"C:\\GOPLAB\\M98SSPI.DLL")&&access==GENERIC_READ&&
         share==FILE_SHARE_READ&&mode==OPEN_EXISTING);
 if(selected==F_DLL_OPEN){last_error=5;return INVALID_HANDLE_VALUE;}
 fixture_file=fopen(MODEL_DLL_PATH,"rb");REQUIRE(fixture_file);dll_offset=0;return INPUT;
}
DWORD GetFileSize(HANDLE handle,DWORD *high) {
 long size;REQUIRE(handle==INPUT&&fixture_file);REQUIRE(fseek(fixture_file,0,SEEK_END)==0);
 size=ftell(fixture_file);REQUIRE(size>0&&size<16777216);REQUIRE(fseek(fixture_file,0,SEEK_SET)==0);
 if(high)*high=selected==F_SIZE_HIGH?1u:0u;
 return selected==F_SIZE?(DWORD)size-1u:(DWORD)size;
}
BOOL ReadFile(HANDLE handle,void *data,DWORD size,DWORD *received,void *overlapped) {
 size_t count;REQUIRE(handle==INPUT&&fixture_file&&!overlapped&&size&&received);
 if(selected==F_DLL_READ){last_error=5;*received=0;return FALSE;}
 if(selected==F_DLL_ZERO||(selected==F_DLL_TRUNCATED&&dll_offset>=16)){*received=0;return TRUE;}
 if(selected==F_DLL_OVERCOUNT){*received=size+1;return TRUE;}
 if(selected==F_SHORT_READ&&size>17)size=17;
 if(selected==F_DLL_TRUNCATED&&size>16)size=16;
 count=fread(data,1,size,fixture_file);REQUIRE(!ferror(fixture_file));
 if(selected==F_TRAILING&&!count){((unsigned char *)data)[0]=0;count=1;}
 if(selected==F_DLL_CORRUPT&&!dll_offset&&count)((unsigned char *)data)[0]^=1;
 dll_offset+=count;*received=(DWORD)count;
 if(selected==F_DLL_DEADLINE)mock_ticks=probe_started+PROBE_MS;
 return TRUE;
}
BOOL WriteFile(HANDLE handle,const void *data,DWORD size,DWORD *written,void *overlapped) {
 REQUIRE(handle==REPORT&&!overlapped&&size&&written);++write_calls;
 if(selected==F_WRITE||(selected==F_LATE_WRITE&&protocol_calls)){last_error=112;return FALSE;}
 if(selected==F_ZERO_WRITE){*written=0;return TRUE;}
 if(selected==F_OVER_WRITE){*written=size+1;return TRUE;}
 if(selected==F_SHORT_WRITE)size=1;
 REQUIRE(log_used+size<sizeof log_bytes);memcpy(log_bytes+log_used,data,size);
 log_used+=size;log_bytes[log_used]=0;*written=size;return TRUE;
}
BOOL FlushFileBuffers(HANDLE handle) {
 REQUIRE(handle==REPORT);++flush_calls;
 if(selected==F_FLUSH||(selected==F_LATE_FLUSH&&protocol_calls)){last_error=112;return FALSE;}return TRUE;
}
BOOL CloseHandle(HANDLE handle) {
 REQUIRE(handle==REPORT||handle==INPUT);
 if(handle==INPUT){++dll_closes;REQUIRE(fixture_file);REQUIRE(fclose(fixture_file)==0);
  fixture_file=NULL;if(selected==F_DLL_CLOSE){last_error=6;return FALSE;}}
 if(handle==REPORT){++log_closes;if(selected==F_CLOSE_LOG){last_error=6;return FALSE;}}
 return TRUE;
}
BOOL GetVersionExA(OSVERSIONINFOA *version) {
 REQUIRE(version->dwOSVersionInfoSize==sizeof *version);
 if(selected==F_OS_QUERY){last_error=120;return FALSE;}
 version->dwPlatformId=selected==F_OS_NT?2u:1u;
 version->dwMajorVersion=selected==F_OS_MAJOR?5u:4u;
 version->dwMinorVersion=selected==F_OS_MINOR?90u:10u;
 version->dwBuildNumber=selected==F_OS_BUILD?1998u:UINT32_C(0xc00008ae);return TRUE;
}
DWORD GetCurrentProcessId(void) { return 1101; }
DWORD GetCurrentThreadId(void) { return 1102; }
DWORD GetTickCount(void) { return mock_ticks; }
void Sleep(DWORD milliseconds) { REQUIRE(!milliseconds); }
HMODULE LoadLibraryA(const char *path) {
 REQUIRE(!strcmp(path,"C:\\GOPLAB\\M98SSPI.DLL"));++loads;
 if(selected==F_LOAD){last_error=193;return NULL;}return MODULE;
}
BOOL FreeLibrary(HMODULE module) {
 REQUIRE(module==MODULE);++unloads;
 if(selected==F_FREE_DLL){last_error=6;return FALSE;}return TRUE;
}
void ExitProcess(DWORD code) { observed_exit=code;longjmp(escaped,1); }

DWORD run_protocol_cases(void) { ++protocol_calls;return protocol_result; }
int ntwst_native_runtime_fini(void) { REQUIRE(0);return NTWST_INVALID; }

static SECURITY_STATUS fake_handshake_status=SEC_I_CONTINUE_NEEDED;
static SECURITY_STATUS fake_decrypt_status=SEC_E_OK;
static ULONG fake_attrs=ISC_RET_STREAM, fake_output_size=3;
static int fake_handshake_retry, fake_decrypt_kind;
static unsigned fake_handshake_calls;
static SECURITY_STATUS mock_acquire(SEC_CHAR *principal,SEC_CHAR *package,ULONG use,
 void *luid,void *policy,SEC_GET_KEY_FN key_fn,void *key_argument,PCredHandle output,PTimeStamp expiry) {
 REQUIRE(!principal&&!strcmp(package,M98SSPI_PACKAGE_A)&&use==SECPKG_CRED_OUTBOUND&&
         !luid&&!policy&&!key_fn&&!key_argument&&output&&!expiry);++root_acquires;
 if(selected==F_ROOT_UNAVAILABLE)return SEC_E_NO_CREDENTIALS;
 output->dwLower=55;output->dwUpper=66;return SEC_E_OK;
}
static SECURITY_STATUS mock_free(PCredHandle value) {
 REQUIRE(value&&value->dwLower==55&&value->dwUpper==66);++root_frees;
 return selected==F_ROOT_FREE?SEC_E_INTERNAL_ERROR:SEC_E_OK;
}
static SECURITY_STATUS mock_initialize(PCredHandle cred,PCtxtHandle old,SEC_CHAR *name,
 ULONG flags,ULONG reserved,ULONG representation,PSecBufferDesc input,ULONG reserved2,
 PCtxtHandle output,PSecBufferDesc out,ULONG *attributes,PTimeStamp expiry) {
 (void)cred;(void)old;(void)name;(void)input;
 REQUIRE(flags==REQ&&!reserved&&!representation&&!reserved2&&output&&out&&attributes&&!expiry);
 ++fake_handshake_calls;*attributes=fake_attrs;output->dwLower=3;output->dwUpper=4;
 out->pBuffers[0].cbBuffer=fake_output_size;
 if(fake_handshake_retry&&fake_handshake_calls==1)return SEC_E_BUFFER_TOO_SMALL;
 return fake_handshake_status;
}
static SECURITY_STATUS mock_delete(PCtxtHandle value) { (void)value;return SEC_E_UNSUPPORTED_FUNCTION; }
static SECURITY_STATUS mock_query(PCtxtHandle value,ULONG attribute,void *output) {
 (void)value;(void)attribute;(void)output;return SEC_E_UNSUPPORTED_FUNCTION;
}
static SECURITY_STATUS mock_package(SEC_CHAR *name,PSecPkgInfoA *out) {
 (void)name;(void)out;return SEC_E_UNSUPPORTED_FUNCTION;
}
static SECURITY_STATUS mock_enumerate(ULONG *count,PSecPkgInfoA *out) {
 (void)count;(void)out;return SEC_E_UNSUPPORTED_FUNCTION;
}
static SECURITY_STATUS mock_free_buffer(void *value) { (void)value;return SEC_E_UNSUPPORTED_FUNCTION; }
static SECURITY_STATUS mock_encrypt(PCtxtHandle value,ULONG qop,PSecBufferDesc desc,ULONG sequence) {
 (void)value;(void)qop;(void)desc;(void)sequence;return SEC_E_UNSUPPORTED_FUNCTION;
}
static SECURITY_STATUS mock_decrypt(PCtxtHandle value,PSecBufferDesc desc,ULONG sequence,ULONG *qop) {
 SecBuffer *b=desc->pBuffers;unsigned char *start=b[0].pvBuffer;ULONG count=b[0].cbBuffer;
 (void)value;REQUIRE(!sequence&&desc->cBuffers==4&&count>=8);
 *qop=fake_decrypt_kind==1?1u:0u;
 if(fake_decrypt_status==SEC_E_INCOMPLETE_MESSAGE){b[1].BufferType=SECBUFFER_MISSING;b[1].cbBuffer=fake_decrypt_kind==2?0u:1u;return fake_decrypt_status;}
 b[0].BufferType=SECBUFFER_DATA;b[0].cbBuffer=fake_decrypt_kind==3?count+1u:3u;
 b[0].pvBuffer=fake_decrypt_kind==4?(void *)(uintptr_t)((uintptr_t)start-1u):
                  fake_decrypt_kind==5?(void *)(uintptr_t)((uintptr_t)start+count+1u):start;
 b[1].BufferType=SECBUFFER_EXTRA;b[1].cbBuffer=count-3;
 b[1].pvBuffer=fake_decrypt_kind==6?start+4:start+3;
 return fake_decrypt_status;
}
static SECURITY_STATUS mock_apply(PCtxtHandle value,PSecBufferDesc desc) {
 (void)value;(void)desc;return SEC_E_UNSUPPORTED_FUNCTION;
}
static SECURITY_STATUS mock_export(PCtxtHandle value,ULONG flags,PSecBuffer out,void **token) {
 (void)value;(void)flags;(void)out;(void)token;return SEC_E_UNSUPPORTED_FUNCTION;
}
static SECURITY_STATUS mock_import(SEC_CHAR *name,PSecBuffer input,void *token,PCtxtHandle out) {
 (void)name;(void)input;(void)token;(void)out;return SEC_E_UNSUPPORTED_FUNCTION;
}
static SECURITY_STATUS mock_end(PCtxtHandle value) { (void)value;return SEC_E_ILLEGAL_MESSAGE; }
static SecurityFunctionTableA table;
static PSecurityFunctionTableA mock_init(void) {
 if(selected==F_NULL_TABLE)return NULL;
 table.dwVersion=selected==F_TABLE_VERSION?2u:1u;
 table.AcquireCredentialsHandleA=mock_acquire;table.FreeCredentialHandle=mock_free;
 table.InitializeSecurityContextA=mock_initialize;table.DeleteSecurityContext=mock_delete;
 table.QueryContextAttributesA=mock_query;table.QuerySecurityPackageInfoA=mock_package;
 table.EnumerateSecurityPackagesA=mock_enumerate;table.FreeContextBuffer=mock_free_buffer;
 table.EncryptMessage=mock_encrypt;table.DecryptMessage=mock_decrypt;
 table.ApplyControlToken=mock_apply;table.ExportSecurityContext=mock_export;
 table.ImportSecurityContextA=mock_import;
 if(selected==F_TABLE_MEMBER)table.AcquireCredentialsHandleA=NULL;
 return &table;
}
FARPROC GetProcAddress(HMODULE module_,const char *name) {
 REQUIRE(module_==MODULE);
 if(selected==F_SYMBOL&&missing_symbol&&!strcmp(name,missing_symbol))return NULL;
 if(selected==F_EXPORT_BINDING&&!strcmp(name,"EncryptMessage"))return (FARPROC)(uintptr_t)mock_decrypt;
#define SYMBOL(text, function) if(!strcmp(name,text))return (FARPROC)(uintptr_t)function
 SYMBOL("InitSecurityInterfaceA",mock_init);
 SYMBOL("AcquireCredentialsHandleA",mock_acquire);
 SYMBOL("FreeCredentialsHandle",mock_free);
 SYMBOL("InitializeSecurityContextA",mock_initialize);
 SYMBOL("DeleteSecurityContext",mock_delete);
 SYMBOL("QueryContextAttributesA",mock_query);
 SYMBOL("QuerySecurityPackageInfoA",mock_package);
 SYMBOL("EnumerateSecurityPackagesA",mock_enumerate);
 SYMBOL("FreeContextBuffer",mock_free_buffer);
 SYMBOL("EncryptMessage",mock_encrypt);
 SYMBOL("DecryptMessage",mock_decrypt);
 SYMBOL("ApplyControlToken",mock_apply);
 SYMBOL("ExportSecurityContext",mock_export);
 SYMBOL("ImportSecurityContextA",mock_import);
 SYMBOL("M98SspiEndInput",mock_end);
#undef SYMBOL
 REQUIRE(0);return NULL;
}

static void reset(enum fault fault_) {
 REQUIRE(!fixture_file);selected=fault_;strcpy(commandline,"C:\\GOPLAB\\TLS13PRB.EXE --nonce tls7707-20261001-c72e541a");
 log_used=dll_offset=0;log_bytes[0]=0;last_error=0;observed_exit=UINT32_C(0xdeadbeef);
 protocol_result=0;
 write_calls=flush_calls=log_closes=dll_closes=loads=unloads=protocol_calls=0;
 root_acquires=root_frees=0;missing_symbol=NULL;
 report.file=INVALID_HANDLE_VALUE;report.failed=0;report.records=0;
 module=NULL;api=NULL;end_input=NULL;dll_file=INVALID_HANDLE_VALUE;
 cases=failures=server_runtime=0;mock_ticks=223344;probe_started=mock_ticks;memset(nonce,0,sizeof nonce);
}
static void nonce_case(const char *name,const char *input,int wanted) {
 struct { unsigned char prefix[8];char value[65];unsigned char suffix[8]; } out;
 unsigned i;memset(&out,0xa5,sizeof out);
 REQUIRE(probe_nonce(input,out.value)==wanted);
 for(i=0;i<8;++i)REQUIRE(out.prefix[i]==0xa5&&out.suffix[i]==0xa5);
 if(wanted)REQUIRE(strlen(out.value)>=16&&strlen(out.value)<=64);
 pass(name);
}
static void entry_case(const char *name,enum fault fault_,DWORD result_,DWORD wanted,int expect_protocol) {
 reset(fault_);protocol_result=result_;
 if(!setjmp(escaped)){M98SspiProbeEntry();REQUIRE(0);}
 REQUIRE(observed_exit==wanted&&protocol_calls==(unsigned)expect_protocol&&!fixture_file);
 if(loads&&fault_!=F_LOAD)REQUIRE(unloads==1);
 if(log_closes)REQUIRE(log_closes==1);
 if(wanted==0)REQUIRE(strstr(log_bytes,"\"event\":\"terminal_candidate_only\",\"passed\":true")&&
  strstr(log_bytes,"\"process_exit_observed\":false")&&root_acquires==1&&root_frees==(fault_==F_ROOT_UNAVAILABLE?0u:1u));
 pass(name);
}
static void write_case(const char *name,enum fault fault_,int okay) {
 probe_log local={REPORT,0,0};reset(fault_);
 REQUIRE(probe_write(&local,"bounded log record\n")==okay);
 REQUIRE(local.records==(unsigned)okay&&local.failed==!okay);
 if(okay)REQUIRE(!strcmp(log_bytes,"bounded log record\n")&&flush_calls==1);
 else {unsigned before=write_calls;REQUIRE(!probe_write(&local,"retry\n")&&write_calls==before);}
 pass(name);
}
static void finish_case(const char *name,enum fault fault_,DWORD candidate,DWORD wanted,int failed) {
 /* Static storage remains defined across the intercepted ExitProcess longjmp. */
 static probe_log local;reset(fault_);local=(probe_log){REPORT,failed,0};
 if(!setjmp(escaped)){probe_finish(&local,candidate);REQUIRE(0);}
 REQUIRE(observed_exit==wanted&&log_closes==1&&flush_calls==1&&local.file==INVALID_HANDLE_VALUE);
 pass(name);
}
static void helper_cases(void) {
 char nonce64[65];unsigned i;probe_log local;pair p;SecBuffer hint;
 const char *prefix="C:\\GOPLAB\\TLS13PRB.EXE --nonce ";char command[160];
 nonce_case("nonce_minimum16", "C:\\GOPLAB\\TLS13PRB.EXE --nonce abcdefghijklmnop",1);
 nonce_case("nonce_quoted_executable", "\"C:\\GOPLAB\\TLS13PRB.EXE\" --nonce abcdefghijklmnop",1);
 nonce_case("nonce_case_insensitive_path", "c:\\goplab\\tls13prb.exe --nonce tls7707-20261001",1);
 for(i=0;i<64;++i)nonce64[i]='a';
 nonce64[64]=0;
 strcpy(command,prefix);strcat(command,nonce64);nonce_case("nonce_maximum64",command,1);
 nonce_case("nonce_missing_option","C:\\GOPLAB\\TLS13PRB.EXE",0);
 nonce_case("nonce_empty_command","",0);
 nonce_case("nonce_null_command",NULL,0);
 nonce_case("nonce_truncated_option","C:\\GOPLAB\\TLS13PRB.EXE --n",0);
 nonce_case("nonce_empty_value","C:\\GOPLAB\\TLS13PRB.EXE --nonce ",0);
 nonce_case("nonce_wrong_executable","C:\\OTHER\\TLS13PRB.EXE --nonce abcdefghijklmnop",0);
 nonce_case("nonce_unknown_option","C:\\GOPLAB\\TLS13PRB.EXE --other abcdefghijklmnop",0);
 nonce_case("nonce_extra_argument","C:\\GOPLAB\\TLS13PRB.EXE --nonce abcdefghijklmnop more",0);
 nonce_case("nonce_quote_fragment","C:\\GOPLAB\\TLS13PRB.EXE --nonce \"abcdefghijklmnop\"fragment",0);
 nonce_case("nonce_quoted_nonce_rejected","C:\\GOPLAB\\TLS13PRB.EXE --nonce \"abcdefghijklmnop\"",0);
 nonce_case("nonce_unclosed_executable_quote","\"C:\\GOPLAB\\TLS13PRB.EXE --nonce abcdefghijklmnop",0);
 nonce_case("nonce_short15","C:\\GOPLAB\\TLS13PRB.EXE --nonce abcdefghijklmno",0);
 strcat(command,"a");nonce_case("nonce_long65",command,0);
 nonce_case("nonce_underscore_rejected","C:\\GOPLAB\\TLS13PRB.EXE --nonce abcdefghijklmno_",0);
 nonce_case("nonce_nonascii_rejected","C:\\GOPLAB\\TLS13PRB.EXE --nonce abcdefghijklmn\xc3\xa9",0);
 write_case("write_complete_flushed",F_NONE,1);write_case("write_partial_completed",F_SHORT_WRITE,1);
 write_case("write_error_persistent",F_WRITE,0);write_case("write_zero_persistent",F_ZERO_WRITE,0);
 write_case("write_overcount_persistent",F_OVER_WRITE,0);write_case("write_flush_error_persistent",F_FLUSH,0);
 reset(F_NONE);local=(probe_log){INVALID_HANDLE_VALUE,0,0};REQUIRE(!probe_write(&local,"x")&&!write_calls);pass("write_invalid_handle_rejected");
 local=(probe_log){REPORT,0,0};REQUIRE(!probe_write(&local,"")&&local.failed&&!write_calls);pass("write_empty_record_rejected");
 {char big[2050];memset(big,'x',sizeof big);big[2049]=0;local=(probe_log){REPORT,0,0};
  REQUIRE(!probe_write(&local,big)&&local.failed&&!write_calls);pass("write_oversize_record_rejected");}
 finish_case("finish_zero_exit",F_NONE,0,0,0);
 finish_case("finish_full_dword_exit",F_NONE,UINT32_C(0xc0000005),UINT32_C(0xc0000005),0);
 finish_case("finish_flush_failure_overrides_zero",F_FLUSH,0,UINT32_C(0x50000003),0);
 finish_case("finish_close_failure_overrides_zero",F_CLOSE_LOG,0,UINT32_C(0x50000003),0);
 finish_case("finish_prior_error_overrides_zero",F_NONE,0,UINT32_C(0x50000003),1);
 memset(&p,0,sizeof p);append(&p.assembled,"0123456789",10);
 hint=(SecBuffer){4,SECBUFFER_EXTRA,p.assembled.bytes+6};REQUIRE(retain_input(&p,&hint)&&p.assembled.count==4&&!memcmp(p.assembled.bytes,"6789",4));pass("retain_exact_extra_suffix");
 hint=(SecBuffer){5,SECBUFFER_EXTRA,p.assembled.bytes};REQUIRE(!retain_input(&p,&hint)&&p.assembled.count==4);pass("retain_extra_overcount_rejected");
 hint=(SecBuffer){3,SECBUFFER_EXTRA,p.assembled.bytes};REQUIRE(!retain_input(&p,&hint)&&p.assembled.count==4);pass("retain_extra_wrong_pointer_rejected");
 hint=(SecBuffer){1,SECBUFFER_MISSING,NULL};REQUIRE(retain_input(&p,&hint)&&p.assembled.count==4&&p.missing==1);pass("retain_missing_keeps_input");
 hint.cbBuffer=0;REQUIRE(!retain_input(&p,&hint));pass("retain_missing_zero_rejected");
 hint.cbBuffer=1;hint.pvBuffer=p.assembled.bytes;REQUIRE(!retain_input(&p,&hint));pass("retain_missing_pointer_rejected");
 hint=(SecBuffer){0,SECBUFFER_EMPTY,NULL};REQUIRE(retain_input(&p,&hint)&&!p.assembled.count);pass("retain_empty_consumes_input");
 hint.BufferType=SECBUFFER_TOKEN;REQUIRE(!retain_input(&p,&hint));pass("retain_unknown_type_rejected");
 probe_started=1000;mock_ticks=70999;REQUIRE(probe_live());pass("probe_deadline_before_limit");
 mock_ticks=71000;REQUIRE(!probe_live());pass("probe_deadline_exact_limit_rejected");
 probe_started=UINT32_C(0xfffffff0);mock_ticks=16;REQUIRE(probe_live());pass("probe_deadline_tick_wrap_safe");
 probe_started=1000;mock_ticks=8999;p.started=1000;p.steps=0;REQUIRE(live(&p));pass("pair_deadline_before_limit");
 mock_ticks=9000;REQUIRE(!live(&p));pass("pair_deadline_exact_limit_rejected");
 mock_ticks=1000;p.steps=MAX_STEPS-1;REQUIRE(!live(&p));pass("pair_step_budget_exhaustion_rejected");
 mock_ticks=71000;p.started=71000;p.steps=0;REQUIRE(!live(&p));pass("whole_probe_deadline_bounds_new_pair");
}

static void driver_fault_cases(void) {
 pair *p=calloc(1,sizeof *p);unsigned char plain[32];size_t got;SECURITY_STATUS status;int kind;
 REQUIRE(p);reset(F_NONE);api=mock_init();fake_handshake_calls=0;fake_handshake_retry=1;
 fake_handshake_status=SEC_I_CONTINUE_NEEDED;fake_attrs=ISC_RET_STREAM;fake_output_size=3;
 status=client_handshake(p,"tls13.win98.test");REQUIRE(status==SEC_I_CONTINUE_NEEDED&&fake_handshake_calls==2&&p->client_live&&p->retries==1&&p->to_server.count==3);pass("handshake_retained_token_retry");
 memset(p,0,sizeof *p);fake_handshake_calls=0;fake_handshake_retry=0;fake_output_size=CAPACITY+1;
 REQUIRE(client_handshake(p,"tls13.win98.test")==SEC_E_INTERNAL_ERROR&&!p->to_server.count);pass("handshake_oversize_output_rejected");
 memset(p,0,sizeof *p);fake_handshake_status=SEC_E_OK;fake_output_size=3;fake_attrs=0;
 REQUIRE(client_handshake(p,"tls13.win98.test")==SEC_E_INTERNAL_ERROR);pass("handshake_missing_stream_attribute_rejected");
 fake_handshake_status=SEC_I_CONTINUE_NEEDED;fake_attrs=ISC_RET_STREAM;
 for(kind=0;kind<=6;++kind){
  const char *names[]={"decrypt_valid_extra_retained","decrypt_nonzero_qop_rejected","decrypt_missing_zero_rejected",
    "decrypt_plain_overcount_rejected","decrypt_pointer_before_input_rejected","decrypt_pointer_after_input_rejected","decrypt_extra_bad_pointer_rejected"};
  memset(p,0,sizeof *p);append(&p->assembled,"0123456789",10);
  fake_decrypt_kind=kind;fake_decrypt_status=kind==2?SEC_E_INCOMPLETE_MESSAGE:SEC_E_OK;
  memset(plain,0xa5,sizeof plain);status=client_decrypt(p,plain,sizeof plain,&got);
  if(kind==0)REQUIRE(status==SEC_E_OK&&got==3&&!memcmp(plain,"012",3)&&p->assembled.count==7&&!memcmp(p->assembled.bytes,"3456789",7));
  else REQUIRE(status==SEC_E_INTERNAL_ERROR);
  pass(names[kind]);
 }
 free(p);api=NULL;
}

int main(void) {
 static const struct {const char *name;enum fault fault_;DWORD exit_;int protocol;} tests[]={
  {"entry_true_dll_digest_and_table",F_NONE,0,1},
  {"entry_wrong_self_rejected",F_WRONG_SELF,UINT32_C(0x50000001),0},
  {"entry_create_new_collision",F_LOG_EXISTS,UINT32_C(0x50000002),0},
  {"entry_create_new_race",F_OPEN_RACE,UINT32_C(0x50000002),0},
  {"entry_os_query_rejected",F_OS_QUERY,UINT32_C(0x50000004),0},
  {"entry_os_nt_rejected",F_OS_NT,UINT32_C(0x50000004),0},
  {"entry_os_major_rejected",F_OS_MAJOR,UINT32_C(0x50000004),0},
  {"entry_os_me_rejected",F_OS_MINOR,UINT32_C(0x50000004),0},
  {"entry_os_build_rejected",F_OS_BUILD,UINT32_C(0x50000004),0},
  {"entry_dll_open_rejected",F_DLL_OPEN,UINT32_C(0x50000004),0},
  {"entry_dll_read_error_rejected",F_DLL_READ,UINT32_C(0x50000004),0},
  {"entry_dll_zero_read_rejected",F_DLL_ZERO,UINT32_C(0x50000004),0},
  {"entry_dll_overread_rejected",F_DLL_OVERCOUNT,UINT32_C(0x50000004),0},
  {"entry_dll_truncation_rejected",F_DLL_TRUNCATED,UINT32_C(0x50000004),0},
  {"entry_dll_digest_mismatch_rejected",F_DLL_CORRUPT,UINT32_C(0x50000004),0},
  {"entry_dll_size_mismatch_rejected",F_SIZE,UINT32_C(0x50000004),0},
  {"entry_dll_size_high_rejected",F_SIZE_HIGH,UINT32_C(0x50000004),0},
  {"entry_dll_trailing_byte_rejected",F_TRAILING,UINT32_C(0x50000004),0},
  {"entry_dll_hash_deadline_rejected",F_DLL_DEADLINE,UINT32_C(0x50000004),0},
  {"entry_dll_partial_reads_completed",F_SHORT_READ,0,1},
  {"entry_loader_failure",F_LOAD,UINT32_C(0x50000004),0},
  {"entry_loaded_path_rejected",F_MODULE_PATH,UINT32_C(0x50000004),0},
  {"entry_loaded_path_truncated",F_MODULE_LENGTH,UINT32_C(0x50000004),0},
  {"entry_null_table_rejected",F_NULL_TABLE,UINT32_C(0x50000004),0},
  {"entry_table_version_rejected",F_TABLE_VERSION,UINT32_C(0x50000004),0},
  {"entry_table_null_member_rejected",F_TABLE_MEMBER,UINT32_C(0x50000004),0},
  {"entry_table_export_mismatch_rejected",F_EXPORT_BINDING,UINT32_C(0x50000004),0},
  {"entry_root_unavailable_not_counted",F_ROOT_UNAVAILABLE,0,1},
  {"entry_root_free_failure",F_ROOT_FREE,UINT32_C(0x50000004),0},
  {"entry_initial_write_failure",F_WRITE,UINT32_C(0x50000003),0},
  {"entry_initial_zero_write",F_ZERO_WRITE,UINT32_C(0x50000003),0},
  {"entry_initial_overwrite",F_OVER_WRITE,UINT32_C(0x50000003),0},
  {"entry_initial_flush_failure",F_FLUSH,UINT32_C(0x50000003),0},
  {"entry_all_partial_writes_completed",F_SHORT_WRITE,0,1},
  {"entry_terminal_write_failure",F_LATE_WRITE,UINT32_C(0x50000003),1},
  {"entry_terminal_flush_failure",F_LATE_FLUSH,UINT32_C(0x50000003),1},
  {"entry_terminal_close_failure",F_CLOSE_LOG,UINT32_C(0x50000003),1},
  {"entry_library_close_failure",F_FREE_DLL,UINT32_C(0x50000006),1},
  {"entry_dll_handle_close_failure",F_DLL_CLOSE,UINT32_C(0x50000007),1}
 };
 static const char *symbols[]={"InitSecurityInterfaceA","AcquireCredentialsHandleA","FreeCredentialsHandle",
 "InitializeSecurityContextA","DeleteSecurityContext","QueryContextAttributesA","QuerySecurityPackageInfoA",
 "EnumerateSecurityPackagesA","FreeContextBuffer","EncryptMessage","DecryptMessage","ApplyControlToken",
 "ExportSecurityContext","ImportSecurityContextA","M98SspiEndInput"};unsigned i;
 helper_cases();driver_fault_cases();
 for(i=0;i<sizeof tests/sizeof tests[0];++i)entry_case(tests[i].name,tests[i].fault_,0,tests[i].exit_,tests[i].protocol);
 entry_case("entry_full_dword_protocol_failure",F_NONE,UINT32_C(0xc0000005),UINT32_C(0xc0000005),1);
 for(i=0;i<sizeof symbols/sizeof symbols[0];++i){char name[128];
  reset(F_SYMBOL);missing_symbol=symbols[i];
  if(!setjmp(escaped)){M98SspiProbeEntry();REQUIRE(0);}
  REQUIRE(observed_exit==UINT32_C(0x50000004)&&!protocol_calls&&!fixture_file&&log_closes==1);
  snprintf(name,sizeof name,"entry_missing_export_%s",symbols[i]);pass(name);
 }
 printf("PROBE_HOST_MODEL_CHECKS=%u FAILURES=0 REAL_TLS_EXECUTED=0 NATIVE_WINDOWS_EXECUTED=0\n",check_count);
 return 0;
}
'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "build/secure-transport/sspi-guest-probe-host-v1")
    parser.add_argument("--dll-fixture", type=Path, default=ROOT /
                        "build/secure-transport/sspi-native-v1/native-root-readonly/M98SSPI.dll")
    parser.add_argument("--real-protocol", action="store_true",
                        help="Build an isolated Linux SSPI DSO and execute the actual TLS protocol driver")
    parser.add_argument("--reuse-pic", type=Path,
                        help="Read-only successful real-mode receipt whose PIC libraries may be reused")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to((ROOT / "build").resolve()):
        parser.error("Output must stay below this worktree's build directory")
    if output.exists():
        parser.error("Output already exists; preserve this attempt and use a new suffix")
    if args.real_protocol:
        return real_protocol(output, args.reuse_pic)
    if args.reuse_pic:
        parser.error("--reuse-pic requires --real-protocol")
    compilers = {name: shutil.which(name) for name in ("gcc", "clang")}
    if not all(compilers.values()):
        parser.error("Both local gcc and clang are required")
    hashes = {name: digest(HERE / name) for name in SOURCES}
    config = ROOT / "build/secure-transport/host-v4-gui/project"
    headers = ROOT / "build/secure-transport/native-v3/upstream/mbedtls-3.6.7/include"
    crypto = ROOT / "build/secure-transport/host-v4-gui/cmake/upstream/library/libmbedcrypto.a"
    fixture = args.dll_fixture.resolve(strict=True)
    required = [config / "user_config.h", headers / "mbedtls/ssl.h",
                headers / "mbedtls/sha256.h", headers / "mbedtls/build_info.h", crypto, fixture]
    dependency_hashes = {str(path): digest(path) for path in required}
    output.mkdir(parents=True, mode=0o700)
    snapshot = output / "source-snapshot"
    snapshot.mkdir(mode=0o700)
    for name in SOURCES:
        shutil.copyfile(HERE / name, snapshot / name)
    (output / "sspi_native_test_win32.h").write_text(read_shim())
    (output / "windows.h").write_text(HEADER)
    (output / "sspi_guest_probe_test_win32.h").write_text(HEADER)
    driver = output / "driver.c"
    driver.write_text(DRIVER.replace("PROBE_SOURCE", str(HERE / "sspi_guest_probe.c"))
                      .replace("MODEL_DLL_PATH", json.dumps(str(fixture)))
                      .replace("MODEL_DLL_HASH", digest(fixture))
                      .replace("MODEL_DLL_SIZE", str(fixture.stat().st_size)))
    runs = []
    models = {}
    passed = True
    for name in ("gcc", "clang"):
        executable = output / ("probe-model-" + name)
        command = [compilers[name], "-std=c11", "-O1", "-g", "-Wall", "-Wextra",
                   "-Werror", "-Wpedantic", "-ffunction-sections", "-fdata-sections",
                   "-Wno-unused-function",
                   "-pthread", '-DMBEDTLS_USER_CONFIG_FILE="user_config.h"',
                   "-I" + str(output), "-I" + str(config), "-I" + str(headers),
                   "-I" + str(HERE), str(driver), str(crypto),
                   "-Wl,--gc-sections", "-o", str(executable)]
        if name == "clang":
            command[1:1] = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
        compiler = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=120)
        (output / (name + "-compile.stdout")).write_text(compiler.stdout)
        (output / (name + "-compile.stderr")).write_text(compiler.stderr)
        run = {"compiler": name, "sanitize": name == "clang", "compile_argv": command,
               "compile_exit": compiler.returncode}
        runs.append(run)
        if compiler.returncode:
            passed = False
            print(compiler.stderr, end="")
            continue
        tested = subprocess.run([str(executable)], cwd=ROOT, text=True,
                                capture_output=True, timeout=90)
        (output / (name + "-test.stdout")).write_text(tested.stdout)
        (output / (name + "-test.stderr")).write_text(tested.stderr)
        run["test_argv"] = [str(executable)]
        run["test_exit"] = tested.returncode
        rows = [row[5:] for row in tested.stdout.splitlines() if row.startswith("PASS ")]
        models[name] = {"cases": rows, "case_count": len(rows),
                        "unique": len(rows) == len(set(rows))}
        # Exact expected names are pinned by the checked-in production-C model.
        okay = tested.returncode == 0 and rows == EXPECTED_CASES
        passed = passed and okay
        print(json.dumps({"compiler": name, "cases": len(rows), "passed": okay}))
        if not okay:
            print(tested.stdout, end="")
            print(tested.stderr, end="")
    after_hashes = {name: digest(HERE / name) for name in SOURCES}
    after_dependencies = {str(path): digest(path) for path in required}
    source_stable = hashes == after_hashes
    dependencies_stable = dependency_hashes == after_dependencies
    passed = passed and source_stable and dependencies_stable
    generated = {path.name: digest(path) for path in sorted(output.iterdir()) if path.is_file()}
    receipt = {"schema": "win98modern.sspi-guest-probe-host-fault-model.v1",
               "passed": passed, "source_sha256": hashes,
               "source_after_sha256": after_hashes, "source_stable": source_stable,
               "dependency_sha256": dependency_hashes, "generated_sha256": generated,
               "dependency_after_sha256": after_dependencies, "dependencies_stable": dependencies_stable,
               "runs": runs, "models": models,
               "scope": "Actual probe C with mocked Win32 and protocol driver on Linux",
               "mocks": ["Win32 file, module and process APIs",
                         "SSPI function table and exports, including ROOT acquisition",
                         "run_protocol_cases crypto-case result"],
               "actual_dll_fixture_hashing": passed,
               "expected_dll_fixture": {"path": str(fixture), "sha256": dependency_hashes[str(fixture)],
                                        "bytes": fixture.stat().st_size,
                                        "expected_hash_and_size_macros_overridden_for_model": True},
               "real_tls_proven": False, "native_guest_proven": False,
               "native_dll_loaded": False, "socket_transport_proven": False,
               "os_provider_registered": False}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": passed, "receipt": str(output / "receipt.json")}))
    return 0 if passed else 1


REAL_RUNTIME = r'''#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <errno.h>
#include <sys/random.h>
#include <pthread.h>
#include "sspi_native_test_win32.h"
#include "transport.h"
static unsigned init_calls, fini_calls, random_calls;
static DWORD error_value;
unsigned M98HostInitCalls(void) { return init_calls; }
unsigned M98HostFiniCalls(void) { return fini_calls; }
unsigned M98HostRandomCalls(void) { return random_calls; }
uintptr_t M98HostRuntimeMarker(void) { return (uintptr_t)&init_calls; }
static int random_bytes(void *context,unsigned char *bytes,size_t size) {
 size_t used=0;(void)context;++random_calls;
 while(used<size){ssize_t n=getrandom(bytes+used,size-used,0);
  if(n<0&&errno==EINTR)continue;
  if(n<=0)return -1;
  used+=(size_t)n;
 }return 0;
}
int ntwst_native_runtime_init(void) { ++init_calls;return ntwst_runtime_init(random_bytes,NULL); }
int ntwst_native_runtime_fini(void) { ++fini_calls;return ntwst_runtime_fini(); }
void InitializeCriticalSection(CRITICAL_SECTION *p) { if(pthread_mutex_init(p,NULL))__builtin_trap(); }
void DeleteCriticalSection(CRITICAL_SECTION *p) { if(pthread_mutex_destroy(p))__builtin_trap(); }
void EnterCriticalSection(CRITICAL_SECTION *p) { if(pthread_mutex_lock(p))__builtin_trap(); }
void LeaveCriticalSection(CRITICAL_SECTION *p) { if(pthread_mutex_unlock(p))__builtin_trap(); }
HCERTSTORE CertOpenStore(const char *provider,DWORD encoding,ULONG_PTR h,DWORD flags,const void *name) {
 if(provider!=CERT_STORE_PROV_SYSTEM_A||encoding||h||!name||
    flags!=(CERT_SYSTEM_STORE_CURRENT_USER|CERT_STORE_OPEN_EXISTING_FLAG|CERT_STORE_READONLY_FLAG))__builtin_trap();
 /* Model an absent ROOT store, never create or insert a certificate. */
 error_value=2;return NULL;
}
PCCERT_CONTEXT CertEnumCertificatesInStore(HCERTSTORE store,PCCERT_CONTEXT previous) {
 (void)store;(void)previous;error_value=CRYPT_E_NOT_FOUND;return NULL;
}
BOOL CertFreeCertificateContext(PCCERT_CONTEXT certificate_) { (void)certificate_;return TRUE; }
BOOL CertCloseStore(HCERTSTORE store,DWORD flags) { (void)store;(void)flags;return TRUE; }
DWORD GetLastError(void) { return error_value; }
'''

REAL_DRIVER = r'''#define _POSIX_C_SOURCE 200809L
#define M98SSPI_HOST_TEST 1
#define M98SSPI_GUEST_HOST_TEST 1
#define M98SSPI_GUEST_REAL_PROTOCOL 1
#define M98_PROBE_DLL_SHA256 "REAL_DSO_HASH"
#define M98_PROBE_DLL_BYTES REAL_DSO_SIZEu
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <sched.h>
#include <setjmp.h>
#include <dlfcn.h>
#include "psa/crypto.h"
#include "windows.h"
#include "PROBE_SOURCE"
#define REPORT ((HANDLE)(uintptr_t)16)
#define REQUIRE(test) do {if(!(test)){fprintf(stderr,"REAL HOST ASSERT line=%u: %s\n",(unsigned)__LINE__,#test);exit(100);}}while(0)
typedef struct file_handle { FILE *stream; } file_handle;
typedef BOOL (*dll_entry_fn)(HINSTANCE,DWORD,LPVOID);
typedef unsigned (*counter_fn)(void);
typedef uintptr_t (*marker_fn)(void);
static FILE *log_stream;
static unsigned open_files, dll_init, dll_fini, dll_random;
static int namespaces_independent;
static unsigned server_version_calls, server_version_bad;
static char server_version[32];
static DWORD host_error, observed_exit;
static void *actual_dso;
static jmp_buf escaped;
unsigned M98HostInitCalls(void);
unsigned M98HostFiniCalls(void);
unsigned M98HostRandomCalls(void);
uintptr_t M98HostRuntimeMarker(void);
const char *__real_ntwst_version(ntwst_connection *);
const char *__wrap_ntwst_version(ntwst_connection *connection) {
 const char *version=__real_ntwst_version(connection);++server_version_calls;
 if(!version||strcmp(version,"TLSv1.3"))++server_version_bad;
 if(version){size_t n=strlen(version);REQUIRE(n<sizeof server_version);memcpy(server_version,version,n+1);}
 return version;
}
static const char *mapped_input(const char *path) {
 static const struct {const char *guest,*host;} names[]={
  {"C:\\GOPLAB\\M98SSPI.DLL",REAL_DSO_PATH},
  {"C:\\GOPLAB\\CA.PEM",REAL_CA_PATH},{"C:\\GOPLAB\\BADCA.PEM",REAL_BADCA_PATH},
  {"C:\\GOPLAB\\SRV.PEM",REAL_SRV_PATH},{"C:\\GOPLAB\\SRV.KEY",REAL_KEY_PATH},
  {"C:\\GOPLAB\\EXP.PEM",REAL_EXP_PATH},{"C:\\GOPLAB\\EXP.KEY",REAL_EXPKEY_PATH},
  {"C:\\GOPLAB\\FUT.PEM",REAL_FUT_PATH}};unsigned i;
 for(i=0;i<sizeof names/sizeof names[0];++i)if(!strcmp(path,names[i].guest))return names[i].host;
 REQUIRE(0);return NULL;
}
char *GetCommandLineA(void) {return "C:\\GOPLAB\\TLS13PRB.EXE --nonce tls7707-real-linux-c72e541a";}
DWORD GetModuleFileNameA(HMODULE module_,char *out,DWORD capacity) {
 const char *path=module_?"C:\\GOPLAB\\M98SSPI.DLL":"C:\\GOPLAB\\TLS13PRB.EXE";
 REQUIRE((!module_||module_==actual_dso)&&capacity>strlen(path));strcpy(out,path);return (DWORD)strlen(path);
}
void SetLastError(DWORD value) {host_error=value;}
HANDLE CreateFileA(const char *path,DWORD access,DWORD share,void *security,DWORD mode,DWORD attributes,HANDLE template_) {
 file_handle *handle;REQUIRE(!security&&!template_&&attributes==FILE_ATTRIBUTE_NORMAL);
 if(!strcmp(path,"C:\\GOPLAB\\SSPI13.LOG")){
  REQUIRE(access==GENERIC_WRITE&&!share&&mode==CREATE_NEW&&!log_stream);
  log_stream=fopen(REAL_LOG_PATH,"wx");REQUIRE(log_stream);return REPORT;
 }
 REQUIRE(access==GENERIC_READ&&share==FILE_SHARE_READ&&mode==OPEN_EXISTING);
 handle=calloc(1,sizeof *handle);REQUIRE(handle);handle->stream=fopen(mapped_input(path),"rb");
 REQUIRE(handle->stream);++open_files;return handle;
}
DWORD GetFileSize(HANDLE value,DWORD *high) {
 file_handle *handle=value;long size;REQUIRE(value!=REPORT&&handle&&handle->stream);
 REQUIRE(!fseek(handle->stream,0,SEEK_END));size=ftell(handle->stream);REQUIRE(size>0&&size<(16u<<20));
 REQUIRE(!fseek(handle->stream,0,SEEK_SET));if(high)*high=0;return (DWORD)size;
}
BOOL ReadFile(HANDLE value,void *bytes,DWORD size,DWORD *got,void *overlapped) {
 file_handle *handle=value;REQUIRE(value!=REPORT&&handle&&handle->stream&&!overlapped&&size&&got);
 *got=(DWORD)fread(bytes,1,size,handle->stream);return !ferror(handle->stream);
}
BOOL WriteFile(HANDLE value,const void *bytes,DWORD size,DWORD *written,void *overlapped) {
 REQUIRE(value==REPORT&&log_stream&&!overlapped&&written&&size);
 *written=(DWORD)fwrite(bytes,1,size,log_stream);return !ferror(log_stream);
}
BOOL FlushFileBuffers(HANDLE value) {REQUIRE(value==REPORT&&log_stream);return !fflush(log_stream);}
BOOL CloseHandle(HANDLE value) {
 file_handle *handle=value;int result;
 if(value==REPORT){REQUIRE(log_stream);result=fclose(log_stream);log_stream=NULL;return !result;}
 REQUIRE(handle&&handle->stream&&open_files);result=fclose(handle->stream);free(handle);--open_files;return !result;
}
BOOL GetVersionExA(OSVERSIONINFOA *version) {
 REQUIRE(version->dwOSVersionInfoSize==sizeof *version);
 /* This identity is mocked; this harness never proves Windows guest behavior. */
 version->dwPlatformId=1;version->dwMajorVersion=4;version->dwMinorVersion=10;version->dwBuildNumber=UINT32_C(0xc00008ae);return TRUE;
}
DWORD GetCurrentProcessId(void) {return 2201;}
DWORD GetCurrentThreadId(void) {return 2202;}
DWORD GetTickCount(void) {struct timespec t;REQUIRE(!clock_gettime(CLOCK_MONOTONIC,&t));return (DWORD)((uint64_t)t.tv_sec*1000u+(uint64_t)t.tv_nsec/1000000u);}
void Sleep(DWORD value) {REQUIRE(!value);sched_yield();}
HMODULE LoadLibraryA(const char *path) {
 dll_entry_fn attach;marker_fn marker;void *symbol;
 REQUIRE(!strcmp(path,"C:\\GOPLAB\\M98SSPI.DLL")&&!actual_dso);
 actual_dso=dlopen(REAL_DSO_PATH,RTLD_NOW|RTLD_LOCAL);
 if(!actual_dso){fprintf(stderr,"dlopen failed: %s\n",dlerror());return NULL;}
 symbol=dlsym(actual_dso,"M98SspiDllMain");REQUIRE(symbol);attach=(dll_entry_fn)(uintptr_t)symbol;
 symbol=dlsym(actual_dso,"M98HostRuntimeMarker");REQUIRE(symbol);marker=(marker_fn)(uintptr_t)symbol;
 namespaces_independent=marker()!=M98HostRuntimeMarker()&&
  (uintptr_t)dlsym(actual_dso,"ntwst_runtime_init")!=(uintptr_t)ntwst_runtime_init&&
  (uintptr_t)dlsym(actual_dso,"ntwst_runtime_fini")!=(uintptr_t)ntwst_runtime_fini&&
  (uintptr_t)dlsym(actual_dso,"psa_crypto_init")!=(uintptr_t)psa_crypto_init;
 REQUIRE(namespaces_independent&&attach(actual_dso,DLL_PROCESS_ATTACH,NULL));return actual_dso;
}
FARPROC GetProcAddress(HMODULE module_,const char *name) {REQUIRE(module_==actual_dso);return (FARPROC)(uintptr_t)dlsym(actual_dso,name);}
BOOL FreeLibrary(HMODULE module_) {
 dll_entry_fn detach;counter_fn count;
 REQUIRE(module_==actual_dso);detach=(dll_entry_fn)(uintptr_t)dlsym(actual_dso,"M98SspiDllMain");
 REQUIRE(detach&&detach(actual_dso,DLL_PROCESS_DETACH,NULL));
 count=(counter_fn)(uintptr_t)dlsym(actual_dso,"M98HostInitCalls");REQUIRE(count);dll_init=count();
 count=(counter_fn)(uintptr_t)dlsym(actual_dso,"M98HostFiniCalls");REQUIRE(count);dll_fini=count();
 count=(counter_fn)(uintptr_t)dlsym(actual_dso,"M98HostRandomCalls");REQUIRE(count);dll_random=count();
 REQUIRE(!dlclose(actual_dso));actual_dso=NULL;return TRUE;
}
void ExitProcess(DWORD code) {observed_exit=code;longjmp(escaped,1);}
int main(void) {
 observed_exit=UINT32_C(0xdeadbeef);
 if(!setjmp(escaped)){M98SspiProbeEntry();REQUIRE(0);}
 REQUIRE(!open_files&&!log_stream&&!actual_dso);
 printf("{\"exit_candidate\":%u,\"protocol_cases\":%u,\"failures\":%u,\"records\":%u,"
        "\"namespaces_independent\":%s,\"client_runtime_init\":%u,\"client_runtime_fini\":%u,"
        "\"client_random_calls\":%u,\"server_runtime_init\":%u,\"server_runtime_fini\":%u,\"server_random_calls\":%u,"
        "\"server_version_calls\":%u,\"server_version_bad\":%u,\"server_version\":\"%s\"}\n",
  observed_exit,cases,failures,report.records,namespaces_independent?"true":"false",
  dll_init,dll_fini,dll_random,M98HostInitCalls(),M98HostFiniCalls(),M98HostRandomCalls(),
  server_version_calls,server_version_bad,server_version);
 return observed_exit==0?0:1;
}
'''


def real_protocol(output, reuse_pic=None):
    """Run real production crypto in two isolated Linux namespaces, no Windows."""
    cc = shutil.which("gcc")
    cmake = shutil.which("cmake")
    if not cc or not cmake:
        raise RuntimeError("Local gcc and cmake required; no tools are installed")
    upstream = ROOT / "build/secure-transport/native-v3/upstream/mbedtls-3.6.7"
    guest = ROOT / "build/secure-transport/sspi-guest-probe-native-v3/guest-files"
    native_receipt = guest.parent / "receipt.json"
    fixture_names = ("CA.PEM", "BADCA.PEM", "SRV.PEM", "SRV.KEY", "EXP.PEM", "EXP.KEY", "FUT.PEM")
    native = json.loads(native_receipt.read_text())
    if not native.get("passed"):
        raise RuntimeError("Native staging receipt is not passing")
    source_names = tuple(dict.fromkeys(SOURCES + ("sspi_native.c", "sspi_stream.c", "transport.c", "user_config.h")))
    source_hashes = {name: digest(HERE / name) for name in source_names}
    inputs = [native_receipt] + [guest / name for name in fixture_names]
    for name in fixture_names:
        if digest(guest / name) != native["guest_file_sha256"][str(guest / name)]:
            raise RuntimeError("Native staged fixture changed: " + name)
    server = ROOT / "build/secure-transport/host-v5-crt/cmake/upstream"
    server_libraries = [server / "library" / ("lib" + name + ".a")
                        for name in ("mbedtls", "mbedx509", "mbedcrypto")]
    server_libraries += [server / "3rdparty/everest/libeverest.a", server / "3rdparty/p256-m/libp256m.a"]
    inputs.extend(server_libraries)
    cache = None
    cache_libraries = []
    if reuse_pic:
        reuse_pic = reuse_pic.resolve(strict=True)
        if not reuse_pic.is_relative_to((ROOT / "build").resolve()):
            raise RuntimeError("PIC cache receipt must stay inside this worktree's build directory")
        cache = json.loads(reuse_pic.read_text())
        if (cache.get("schema") != "win98modern.sspi-guest-probe-real-linux-protocol.v1"
                or not cache.get("passed") or cache["source_sha256"]["user_config.h"] != source_hashes["user_config.h"]):
            raise RuntimeError("PIC cache does not bind a passing compatible source configuration")
        paths = ["cmake-pic/library/lib" + name + ".a" for name in ("mbedtls", "mbedx509", "mbedcrypto")]
        paths += ["cmake-pic/3rdparty/everest/libeverest.a", "cmake-pic/3rdparty/p256-m/libp256m.a"]
        cache_libraries = [reuse_pic.parent / name for name in paths]
        for path in cache_libraries:
            if digest(path) != cache["generated_sha256"][str(path.relative_to(reuse_pic.parent))]:
                raise RuntimeError("PIC cache library changed: " + str(path))
        inputs += [reuse_pic] + cache_libraries
    input_hashes = {str(path): digest(path) for path in inputs}
    output.mkdir(parents=True, mode=0o700)
    snapshot = output / "source-snapshot"
    snapshot.mkdir(mode=0o700)
    for name in source_names:
        shutil.copyfile(HERE / name, snapshot / name)
    fixtures = output / "fixtures"
    fixtures.mkdir(mode=0o700)
    for name in fixture_names:
        shutil.copyfile(guest / name, fixtures / name)
        (fixtures / name).chmod(0o600)
    (output / "sspi_native_test_win32.h").write_text(read_shim())
    (output / "windows.h").write_text(HEADER)
    (output / "sspi_guest_probe_test_win32.h").write_text(HEADER)
    runtime = output / "real-runtime.c"
    runtime.write_text(REAL_RUNTIME)
    upstream_copy = output / "upstream"
    shutil.copytree(upstream, upstream_copy)
    upstream_hashes = {str(path.relative_to(upstream_copy)): digest(path)
                       for path in sorted(upstream_copy.rglob("*")) if path.is_file()}
    runs = []
    model = None
    events = []
    error = None

    def run(command, label, timeout=120):
        proc = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, timeout=timeout)
        (output / (label + ".stdout")).write_text(proc.stdout)
        (output / (label + ".stderr")).write_text(proc.stderr)
        runs.append({"label": label, "argv": command, "exit": proc.returncode})
        print(json.dumps({"step": label, "exit": proc.returncode}), flush=True)
        if proc.returncode:
            raise RuntimeError(label + " failed; see captured logs")
        return proc.stdout

    try:
        pic = output / "cmake-pic"
        if cache:
            if cache["upstream_sha256"] != upstream_hashes:
                raise RuntimeError("PIC cache upstream source bytes differ")
        else:
            flags = r'-DMBEDTLS_USER_CONFIG_FILE=\"user_config.h\" -I' + str(snapshot)
            run([cmake, "-S", str(upstream_copy), "-B", str(pic), "-DENABLE_PROGRAMS=OFF",
                 "-DENABLE_TESTING=OFF", "-DCMAKE_BUILD_TYPE=Release",
                 "-DCMAKE_POSITION_INDEPENDENT_CODE=ON", "-DCMAKE_C_FLAGS=" + flags], "configure-pic")
            run([cmake, "--build", str(pic), "--parallel", "2"], "build-pic", 300)
        headers = upstream_copy / "include"
        libraries = [pic / "library" / ("lib" + name + ".a")
                     for name in ("mbedtls", "mbedx509", "mbedcrypto")]
        libraries += [pic / "3rdparty/everest/libeverest.a", pic / "3rdparty/p256-m/libp256m.a"]
        if cache:
            for source, destination in zip(cache_libraries, libraries, strict=True):
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
        common = [cc, "-std=c11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wpedantic",
                  "-pthread", '-DMBEDTLS_USER_CONFIG_FILE="user_config.h"',
                  "-I" + str(output), "-I" + str(snapshot), "-I" + str(headers)]
        dso = output / "libm98sspi-real-host.so"
        run(common + ["-DM98SSPI_HOST_TEST=1", "-fPIC", "-shared",
                      str(snapshot / "sspi_native.c"), str(snapshot / "sspi_stream.c"),
                      str(snapshot / "transport.c"), str(runtime),
                      "-Wl,-Bsymbolic,--no-undefined", "-Wl,--start-group"] +
            [str(path) for path in libraries] + ["-Wl,--end-group", "-o", str(dso)], "link-client-dso")
        dynamic = run(["readelf", "-d", str(dso)], "audit-client-dso")
        if "SYMBOLIC" not in dynamic:
            raise RuntimeError("DSO dynamic section does not confirm SYMBOLIC binding")
        driver = output / "real-driver.c"
        replacements = {"PROBE_SOURCE": str(snapshot / "sspi_guest_probe.c"),
                        "REAL_DSO_HASH": digest(dso), "REAL_DSO_SIZE": str(dso.stat().st_size),
                        "REAL_DSO_PATH": json.dumps(str(dso)),
                        "REAL_LOG_PATH": json.dumps(str(output / "real-probe.log"))}
        for macro, name in (("CA", "CA.PEM"), ("BADCA", "BADCA.PEM"), ("SRV", "SRV.PEM"),
                            ("KEY", "SRV.KEY"), ("EXP", "EXP.PEM"), ("EXPKEY", "EXP.KEY"), ("FUT", "FUT.PEM")):
            replacements["REAL_" + macro + "_PATH"] = json.dumps(str(fixtures / name))
        body = REAL_DRIVER
        for key, value in replacements.items():
            body = body.replace(key, value)
        driver.write_text(body)
        exe = output / "real-protocol-probe"
        run(common + [str(driver), str(snapshot / "transport.c"), str(runtime),
                      "-Wl,--export-dynamic,--wrap=ntwst_version", "-Wl,--start-group"] +
            [str(path) for path in server_libraries] +
            ["-Wl,--end-group", "-ldl", "-o", str(exe)], "link-server-probe")
        stdout = run([str(exe)], "real-protocol", 100)
        model = json.loads(stdout.strip().splitlines()[-1])
        events = [json.loads(line) for line in (output / "real-probe.log").read_text().splitlines()]
    except Exception as exc:
        error = str(exc)
        telemetry = output / "real-protocol.stdout"
        log_path = output / "real-probe.log"
        if telemetry.exists():
            try:
                model = json.loads(telemetry.read_text().strip().splitlines()[-1])
            except (ValueError, IndexError):
                pass
        if log_path.exists():
            try:
                events = [json.loads(line) for line in log_path.read_text().splitlines()]
            except ValueError:
                pass
    source_after = {name: digest(HERE / name) for name in source_names}
    inputs_after = {str(path): digest(path) for path in inputs}
    expected_protocol = ["fragmented_handshake", "retained_token_retry", "real_stream_sizes",
                         "actual_encrypted_echo", "multiple_record_EXTRA", "authenticated_bidirectional_close", "typed_stale_context",
                         "wrong_dns_rejected", "untrusted_root_rejected", "expired_certificate_rejected",
                         "future_certificate_rejected", "tampered_record_rejected", "unauthenticated_memory_EOF_rejected"]
    protocol = [event for event in events if event["event"] in expected_protocol]
    passed = bool(not error and model and model["exit_candidate"] == 0 and
                  model["protocol_cases"] == 13 and model["failures"] == 0 and
                  model["namespaces_independent"] and model["client_runtime_init"] > 0 and
                  model["client_runtime_init"] == model["client_runtime_fini"] and
                  model["client_random_calls"] > 0 and model["server_random_calls"] > 0 and
                  model["server_version_calls"] > 0 and model["server_version_bad"] == 0 and
                  model["server_version"] == "TLSv1.3" and
                  model["server_runtime_init"] == model["server_runtime_fini"] == 1 and
                  [event["event"] for event in protocol] == expected_protocol and
                  all(event["passed"] for event in protocol) and
                  source_hashes == source_after and input_hashes == inputs_after)
    generated = {str(path.relative_to(output)): digest(path) for path in sorted(output.rglob("*"))
                 if path.is_file() and not path.is_relative_to(upstream_copy)}
    receipt = {"schema": "win98modern.sspi-guest-probe-real-linux-protocol.v1", "passed": passed,
               "error": error, "source_sha256": source_hashes, "source_after_sha256": source_after,
               "input_sha256": input_hashes, "input_after_sha256": inputs_after,
               "upstream_sha256": upstream_hashes, "generated_sha256": generated,
               "runs": runs, "model": model, "events": events,
               "scope": "Actual probe protocol C + isolated real SSPI TLS DSO and server on Linux",
               "mocked": ["Win32 file, module, clock, OS identity and ExitProcess APIs",
                          "Absent Windows ROOT store; no ROOT certificate insertion"],
               "rng": "Linux getrandom, independently initialized client and server runtimes",
               "pic_cache_receipt": str(reuse_pic) if reuse_pic else None,
               "dll_hash_and_size_macros_overridden_for_model": True,
               "file_hash_and_executed_module": "Same generated Linux ELF DSO; native PE DLL is not executed",
               "real_tls_proven": passed, "native_guest_proven": False,
               "actual_windows_dll_execution": False, "socket_transport_proven": False,
               "native_default_ROOT_certificate_validation": False, "os_provider_registered": False}
    (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"passed": passed, "receipt": str(output / "receipt.json"), "error": error}), flush=True)
    return 0 if passed else 1


EXPECTED_CASES = [
    "nonce_minimum16", "nonce_quoted_executable", "nonce_case_insensitive_path", "nonce_maximum64",
    "nonce_missing_option", "nonce_empty_command", "nonce_null_command", "nonce_truncated_option",
    "nonce_empty_value", "nonce_wrong_executable", "nonce_unknown_option", "nonce_extra_argument",
    "nonce_quote_fragment", "nonce_quoted_nonce_rejected", "nonce_unclosed_executable_quote", "nonce_short15",
    "nonce_long65", "nonce_underscore_rejected", "nonce_nonascii_rejected",
    "write_complete_flushed", "write_partial_completed", "write_error_persistent", "write_zero_persistent",
    "write_overcount_persistent", "write_flush_error_persistent", "write_invalid_handle_rejected",
    "write_empty_record_rejected", "write_oversize_record_rejected",
    "finish_zero_exit", "finish_full_dword_exit", "finish_flush_failure_overrides_zero",
    "finish_close_failure_overrides_zero", "finish_prior_error_overrides_zero",
    "retain_exact_extra_suffix", "retain_extra_overcount_rejected", "retain_extra_wrong_pointer_rejected",
    "retain_missing_keeps_input", "retain_missing_zero_rejected", "retain_missing_pointer_rejected",
    "retain_empty_consumes_input", "retain_unknown_type_rejected",
    "probe_deadline_before_limit", "probe_deadline_exact_limit_rejected", "probe_deadline_tick_wrap_safe",
    "pair_deadline_before_limit", "pair_deadline_exact_limit_rejected", "pair_step_budget_exhaustion_rejected",
    "whole_probe_deadline_bounds_new_pair",
    "handshake_retained_token_retry", "handshake_oversize_output_rejected",
    "handshake_missing_stream_attribute_rejected", "decrypt_valid_extra_retained",
    "decrypt_nonzero_qop_rejected", "decrypt_missing_zero_rejected", "decrypt_plain_overcount_rejected",
    "decrypt_pointer_before_input_rejected", "decrypt_pointer_after_input_rejected",
    "decrypt_extra_bad_pointer_rejected",
    "entry_true_dll_digest_and_table", "entry_wrong_self_rejected", "entry_create_new_collision",
    "entry_create_new_race", "entry_os_query_rejected", "entry_os_nt_rejected", "entry_os_major_rejected",
    "entry_os_me_rejected", "entry_os_build_rejected", "entry_dll_open_rejected",
    "entry_dll_read_error_rejected", "entry_dll_zero_read_rejected", "entry_dll_overread_rejected",
    "entry_dll_truncation_rejected", "entry_dll_digest_mismatch_rejected", "entry_dll_size_mismatch_rejected",
    "entry_dll_size_high_rejected", "entry_dll_trailing_byte_rejected", "entry_dll_hash_deadline_rejected",
    "entry_dll_partial_reads_completed",
    "entry_loader_failure", "entry_loaded_path_rejected", "entry_loaded_path_truncated",
    "entry_null_table_rejected", "entry_table_version_rejected", "entry_table_null_member_rejected",
    "entry_table_export_mismatch_rejected", "entry_root_unavailable_not_counted", "entry_root_free_failure",
    "entry_initial_write_failure", "entry_initial_zero_write", "entry_initial_overwrite",
    "entry_initial_flush_failure", "entry_all_partial_writes_completed", "entry_terminal_write_failure",
    "entry_terminal_flush_failure", "entry_terminal_close_failure", "entry_library_close_failure",
    "entry_dll_handle_close_failure", "entry_full_dword_protocol_failure",
] + ["entry_missing_export_" + symbol for symbol in (
    "InitSecurityInterfaceA", "AcquireCredentialsHandleA", "FreeCredentialsHandle",
    "InitializeSecurityContextA", "DeleteSecurityContext", "QueryContextAttributesA", "QuerySecurityPackageInfoA",
    "EnumerateSecurityPackagesA", "FreeContextBuffer", "EncryptMessage", "DecryptMessage", "ApplyControlToken",
    "ExportSecurityContext", "ImportSecurityContextA", "M98SspiEndInput")]


if __name__ == "__main__":
    raise SystemExit(main())
