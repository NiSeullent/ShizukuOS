#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Fault-model the actual native observer C; this never executes Windows or TLS.

Generated sources, executable and hash-bound receipt live in ignored build/.
The model checks ownership, full exit values, freshness, bounded termination,
and error handling. Native API availability and behavior require guest evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


HEADER = r'''
#ifndef OBSERVER_MODEL_WINDOWS_H
#define OBSERVER_MODEL_WINDOWS_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD; typedef int BOOL; typedef void *HANDLE;
#define FALSE 0
#define TRUE 1
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)(uintptr_t)-1)
#define INVALID_FILE_ATTRIBUTES 0xffffffffu
#define ERROR_FILE_NOT_FOUND 2u
#define GENERIC_WRITE 0x40000000u
#define CREATE_NEW 1u
#define FILE_ATTRIBUTE_NORMAL 128u
#define VER_PLATFORM_WIN32_WINDOWS 1u
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xffffffffu
typedef struct { DWORD dwOSVersionInfoSize,dwMajorVersion,dwMinorVersion,
 dwBuildNumber,dwPlatformId; char szCSDVersion[128]; } OSVERSIONINFOA;
typedef struct { DWORD cb; void *reserved[8]; } STARTUPINFOA;
typedef struct { HANDLE hProcess,hThread; DWORD dwProcessId,dwThreadId; } PROCESS_INFORMATION;
char *GetCommandLineA(void);
DWORD GetModuleFileNameA(HANDLE,char *,DWORD);
void SetLastError(DWORD); DWORD GetLastError(void);
DWORD GetFileAttributesA(const char *);
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
BOOL WriteFile(HANDLE,const void *,DWORD,DWORD *,void *);
BOOL FlushFileBuffers(HANDLE); BOOL CloseHandle(HANDLE);
DWORD GetCurrentProcessId(void); DWORD GetCurrentThreadId(void);
BOOL GetVersionExA(OSVERSIONINFOA *);
BOOL CreateProcessA(const char *,char *,void *,void *,BOOL,DWORD,void *,const char *,STARTUPINFOA *,PROCESS_INFORMATION *);
DWORD WaitForSingleObject(HANDLE,DWORD);
BOOL GetExitCodeProcess(HANDLE,DWORD *); BOOL TerminateProcess(HANDLE,DWORD);
void ExitProcess(DWORD);
#endif
'''

MODEL = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "windows.h"
#include "OBSERVER_SOURCE"

enum fault { NONE, WRONG_SELF, CHILD_EXISTS, OBS_EXISTS, ATTR_ERROR, ATTR_PATH,
 OPEN_RACE, OS_QUERY, OS_PLATFORM, OS_MAJOR, OS_MINOR, OS_BUILD,
 WRITE_FIRST, FLUSH_FIRST, WRITE_ZERO, WRITE_OVERCOUNT, SHORT_WRITES,
 WRITE_AFTER_CREATE, FLUSH_AFTER_CREATE, CHILD_RACE, CREATE_FAIL,
 CLOSE_THREAD, CLOSE_PROCESS, WAIT_TIMED_OUT, WAIT_BROKEN, TERMINATE_FAIL,
 REAP_TIMEOUT, EXIT_QUERY, CRASH_EXIT, ACTIVE_EXIT, CLOSE_REPORT };
static enum fault fault;
static char cli[512], log_data[32768], wanted_command[384];
static size_t log_size;
static DWORD error_value, actual_exit;
static unsigned created, opened, waits, terminated_calls, queried_calls,
 thread_closes, process_closes, report_closes, attr_child, checks;
static jmp_buf escaped;
#define REPORT ((HANDLE)(uintptr_t)10)
#define PROCESS ((HANDLE)(uintptr_t)20)
#define THREAD ((HANDLE)(uintptr_t)30)
#define REQUIRE(test) do { if (!(test)) { fprintf(stderr,"MODEL ASSERT line=%u: %s\n",(unsigned)__LINE__,#test); exit(100); } } while (0)
char *GetCommandLineA(void) { return cli; }
DWORD GetModuleFileNameA(HANDLE module,char *out,DWORD cap) {
 const char *path=fault==WRONG_SELF?"C:\\OTHER\\TLSWATCH.EXE":"C:\\GOPLAB\\TLSWATCH.EXE";
 REQUIRE(!module&&cap>strlen(path));strcpy(out,path);return (DWORD)strlen(path);
}
void SetLastError(DWORD value) { error_value=value; }
DWORD GetLastError(void) { return error_value; }
DWORD GetFileAttributesA(const char *path) {
 int child=!strcmp(path,"C:\\GOPLAB\\TLS13.LOG");
 REQUIRE(child||!strcmp(path,"C:\\GOPLAB\\TLSOBS.LOG"));
 if(child)++attr_child;
 if((child&&fault==CHILD_EXISTS)||(!child&&fault==OBS_EXISTS)||
    (child&&fault==CHILD_RACE&&attr_child==2))return 128;
 error_value=fault==ATTR_ERROR?5:fault==ATTR_PATH?3:ERROR_FILE_NOT_FOUND;
 return INVALID_FILE_ATTRIBUTES;
}
HANDLE CreateFileA(const char *path,DWORD access,DWORD share,void *sa,DWORD mode,DWORD attrs,HANDLE template_) {
 REQUIRE(!strcmp(path,"C:\\GOPLAB\\TLSOBS.LOG")&&access==GENERIC_WRITE&&!share&&!sa&&mode==CREATE_NEW&&attrs==FILE_ATTRIBUTE_NORMAL&&!template_);
 ++opened;if(fault==OPEN_RACE){error_value=80;return INVALID_HANDLE_VALUE;}return REPORT;
}
BOOL WriteFile(HANDLE handle,const void *data,DWORD size,DWORD *written,void *overlapped) {
 REQUIRE(handle==REPORT&&!overlapped&&size);
 if(fault==WRITE_FIRST||(fault==WRITE_AFTER_CREATE&&created)){error_value=112;return FALSE;}
 if(fault==WRITE_ZERO){*written=0;return TRUE;}
 if(fault==WRITE_OVERCOUNT){*written=size+1;return TRUE;}
 if(fault==SHORT_WRITES)size=1;
 REQUIRE(log_size+size<sizeof log_data);memcpy(log_data+log_size,data,size);log_size+=size;log_data[log_size]=0;*written=size;return TRUE;
}
BOOL FlushFileBuffers(HANDLE handle) {
 REQUIRE(handle==REPORT);
 if(fault==FLUSH_FIRST||(fault==FLUSH_AFTER_CREATE&&created)){error_value=112;return FALSE;}return TRUE;
}
BOOL CloseHandle(HANDLE handle) {
 REQUIRE(handle==REPORT||handle==PROCESS||handle==THREAD);
 if(handle==REPORT){++report_closes;if(fault==CLOSE_REPORT){error_value=6;return FALSE;}}
 if(handle==PROCESS){++process_closes;if(fault==CLOSE_PROCESS){error_value=6;return FALSE;}}
 if(handle==THREAD){++thread_closes;if(fault==CLOSE_THREAD){error_value=6;return FALSE;}}
 return TRUE;
}
DWORD GetCurrentProcessId(void){return 1001;}
DWORD GetCurrentThreadId(void){return 1002;}
BOOL GetVersionExA(OSVERSIONINFOA *version) {
 REQUIRE(version->dwOSVersionInfoSize==sizeof *version);
 if(fault==OS_QUERY){error_value=120;return FALSE;}
 version->dwPlatformId=fault==OS_PLATFORM?2:1;
 version->dwMajorVersion=fault==OS_MAJOR?5:4;
 version->dwMinorVersion=fault==OS_MINOR?90:10;
 version->dwBuildNumber=fault==OS_BUILD?1998:0xc00008aeu;return TRUE;
}
BOOL CreateProcessA(const char *app,char *cmd,void *psa,void *tsa,BOOL inherited,DWORD flags,void *env,const char *cwd,STARTUPINFOA *start,PROCESS_INFORMATION *child) {
 REQUIRE(!strcmp(app,"C:\\GOPLAB\\TLS13PRB.EXE")&&!strcmp(cmd,wanted_command)&&!psa&&!tsa&&!inherited&&!flags&&!env&&!strcmp(cwd,"C:\\GOPLAB")&&start->cb==sizeof *start);
 if(fault==CREATE_FAIL){error_value=193;return FALSE;}
 ++created;child->hProcess=PROCESS;child->hThread=THREAD;child->dwProcessId=2001;child->dwThreadId=2002;return TRUE;
}
DWORD WaitForSingleObject(HANDLE handle,DWORD timeout) {
 REQUIRE(handle==PROCESS&&created);++waits;
 if(waits==1){REQUIRE(timeout==90000u);if(fault==WAIT_TIMED_OUT||fault==TERMINATE_FAIL||fault==REAP_TIMEOUT)return WAIT_TIMEOUT;if(fault==WAIT_BROKEN){error_value=6;return WAIT_FAILED;}return WAIT_OBJECT_0;}
 REQUIRE(waits==2&&timeout==5000u&&terminated_calls==1);
 return fault==REAP_TIMEOUT?WAIT_TIMEOUT:WAIT_OBJECT_0;
}
BOOL GetExitCodeProcess(HANDLE handle,DWORD *code) {
 REQUIRE(handle==PROCESS&&waits&&fault!=REAP_TIMEOUT);++queried_calls;
 if(fault==EXIT_QUERY){error_value=6;return FALSE;}
 *code=fault==CRASH_EXIT?0xc0000005u:fault==ACTIVE_EXIT?259u:0u;return TRUE;
}
BOOL TerminateProcess(HANDLE handle,DWORD code) {
 REQUIRE(handle==PROCESS&&created&&waits==1&&code==0x77070001u);++terminated_calls;
 if(fault==TERMINATE_FAIL){error_value=5;return FALSE;}return TRUE;
}
void ExitProcess(DWORD code) { actual_exit=code;longjmp(escaped,1); }

static void run_case(const char *name,enum fault selected,const char *commandline,DWORD expected,int expected_child) {
 char nonce[65];const char *last=strrchr(commandline,' ');
 fault=selected;strcpy(cli,commandline);log_data[0]=0;log_size=0;error_value=0;actual_exit=999;
 created=opened=waits=terminated_calls=queried_calls=thread_closes=process_closes=report_closes=attr_child=0;
 report=NULL;io_failed=0;
 if(last&&strlen(last+1)<sizeof nonce){strcpy(nonce,last+1);if(nonce[0]=='"'){size_t n=strlen(nonce);memmove(nonce,nonce+1,n);if(n>1)nonce[n-2]=0;}}
 else nonce[0]=0;
 snprintf(wanted_command,sizeof wanted_command,"%s%s",child_arguments,nonce);
 if(!setjmp(escaped)){mainCRTStartup();REQUIRE(0);}
 REQUIRE(actual_exit==expected&&created==(unsigned)expected_child);
 if(expected_child)REQUIRE(thread_closes==1&&process_closes==1&&waits>=1);
 if(opened&&selected!=OPEN_RACE)REQUIRE(report_closes==1);
 if(actual_exit==0)REQUIRE(strstr(log_data,"child.wait=0\r\n")&&strstr(log_data,"child.exit-query=1\r\n")&&strstr(log_data,"child.exit-code=0\r\n")&&strstr(log_data,"os.exact-win98se=1\r\n")&&strstr(log_data,"observer.exit-candidate=0\r\n")&&!terminated_calls);
 if(selected==CRASH_EXIT)REQUIRE(strstr(log_data,"child.exit-code=3221225477\r\n"));
 if(selected==ACTIVE_EXIT)REQUIRE(strstr(log_data,"child.exit-code=259\r\n"));
 if(selected==WAIT_TIMED_OUT||selected==WAIT_BROKEN||selected==TERMINATE_FAIL||selected==REAP_TIMEOUT)REQUIRE(terminated_calls==1&&waits==2&&actual_exit!=0);
 if(selected==CLOSE_REPORT)REQUIRE(strstr(log_data,"observer.exit-candidate=0\r\n")&&actual_exit!=0);
 ++checks;printf("PASS %s\n",name);
}
int main(void) {
 const char *valid="C:\\GOPLAB\\TLSWATCH.EXE --nonce tls7707-d4fe7e8ac2a04086";
 static const struct { const char *name;enum fault value;DWORD exit_code;int child; } faults[]={
  {"wrong_self",WRONG_SELF,20,0},{"child_log_exists",CHILD_EXISTS,22,0},{"observer_log_exists",OBS_EXISTS,22,0},
  {"attribute_access_failure",ATTR_ERROR,22,0},{"attribute_missing_directory",ATTR_PATH,22,0},{"create_new_race",OPEN_RACE,21,0},
  {"os_query_failure",OS_QUERY,23,0},{"os_nt_rejected",OS_PLATFORM,23,0},{"os_major_rejected",OS_MAJOR,23,0},
  {"os_me_rejected",OS_MINOR,23,0},{"os_wrong_build_rejected",OS_BUILD,23,0},
  {"write_failure_before_child",WRITE_FIRST,29,0},{"flush_failure_before_child",FLUSH_FIRST,29,0},
  {"zero_write_fails_closed",WRITE_ZERO,29,0},{"oversized_write_fails_closed",WRITE_OVERCOUNT,29,0},
  {"partial_writes_completed",SHORT_WRITES,0,1},{"write_failure_after_child_cleanup",WRITE_AFTER_CREATE,29,1},
  {"flush_failure_after_child_cleanup",FLUSH_AFTER_CREATE,29,1},{"child_output_freshness_race",CHILD_RACE,22,0},
  {"process_create_failure",CREATE_FAIL,24,0},{"thread_close_failure",CLOSE_THREAD,28,1},{"process_close_failure",CLOSE_PROCESS,28,1},
  {"timeout_zero_guard_exit_still_fails",WAIT_TIMED_OUT,25,1},{"wait_failure_owned_cleanup",WAIT_BROKEN,25,1},
  {"terminate_failure_reap_still_fails",TERMINATE_FAIL,25,1},{"unreaped_owned_child_fails",REAP_TIMEOUT,25,1},
  {"exit_query_failure",EXIT_QUERY,26,1},{"full_dword_crash_exit",CRASH_EXIT,27,1},{"terminated_exit_259_not_running",ACTIVE_EXIT,27,1},
  {"report_close_failure_changes_real_exit",CLOSE_REPORT,29,1}
 };
 static const char *bad[]={
  "C:\\GOPLAB\\TLSWATCH.EXE", "C:\\GOPLAB\\TLSWATCH.EXE --nonce short",
  "C:\\GOPLAB\\TLSWATCH.EXE --nonce abcdefghijklmnop!", "C:\\GOPLAB\\TLSWATCH.EXE --other abcdefghijklmnop",
  "C:\\GOPLAB\\TLSWATCH.EXE --nonce abcdefghijklmnop extra", "C:\\OTHER\\TLSWATCH.EXE --nonce abcdefghijklmnop",
  "\"C:\\GOPLAB\\TLSWATCH.EXE --nonce abcdefghijklmnop", "C:\\GOPLAB\\TLSWATCH.EXE --nonce \"abcdefghijklmnop\"fragment",
  "C:\\GOPLAB\\TLSWATCH.EXE --nonce abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abc",
  "C:\\GOPLAB\\TLSWATCH.EXE --nonce abcdefghijklmn\xc3\xa9",
  "C:\\GOPLAB\\TLSWATCH.EXE --nonce abcdefghijklmno"
 };
 static const char *bad_names[]={"missing_nonce_option","nonce_too_short","nonce_punctuation_rejected",
  "unknown_option_rejected","extra_argument_rejected","wrong_argv0_rejected","unterminated_quote_rejected",
  "quoted_fragment_rejected","nonce_65bytes_rejected","non_ascii_nonce_rejected","nonce_15bytes_rejected"};
 unsigned i;
 run_case("native_low_build2222_fixed_child",NONE,valid,0,1);
 run_case("quoted_executable_and_nonce",NONE,"\"C:\\GOPLAB\\TLSWATCH.EXE\" --nonce \"abcdefghijklmnop\"",0,1);
 run_case("minimum_16char_nonce",NONE,"C:\\GOPLAB\\TLSWATCH.EXE --nonce abcdefghijklmnop",0,1);
 run_case("maximum_64char_nonce",NONE,"C:\\GOPLAB\\TLSWATCH.EXE --nonce abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ab",0,1);
 for(i=0;i<sizeof faults/sizeof faults[0];++i)run_case(faults[i].name,faults[i].value,valid,faults[i].exit_code,faults[i].child);
 for(i=0;i<sizeof bad/sizeof bad[0];++i)run_case(bad_names[i],NONE,bad[i],20,0);
 printf("OBSERVER_HOST_MODEL_CHECKS=%u FAILURES=0 NATIVE_WINDOWS_EXECUTED=0\n",checks);return 0;
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=root / "build/secure-transport/guest-observer-host-model")
    parser.add_argument("--cc", default="gcc")
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(root / "build"):
        parser.error("Generated files must stay below this worktree's ignored build directory")
    output.mkdir(parents=True, exist_ok=True)
    # A failed rebuild must never leave an earlier successful model receipt.
    (output / "result.json").unlink(missing_ok=True)
    source = Path(__file__).with_name("guest_observer.c")
    before = sha(source)
    header, model, executable = output / "windows.h", output / "model.c", output / "observer-model"
    header.write_text(HEADER)
    model.write_text(MODEL.replace("OBSERVER_SOURCE", str(source)))
    compile_command = [args.cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(output), str(model), "-o", str(executable)]
    compiled = subprocess.run(compile_command, text=True, capture_output=True, timeout=30)
    (output / "compile.log").write_text(compiled.stdout + compiled.stderr)
    if compiled.returncode:
        raise RuntimeError(compiled.stderr)
    tested = subprocess.run([str(executable)], text=True, capture_output=True, timeout=10)
    (output / "test.log").write_text(tested.stdout + tested.stderr)
    rows = [row[5:] for row in tested.stdout.splitlines() if row.startswith("PASS ")]
    passed = tested.returncode == 0 and len(rows) == 45 and len(set(rows)) == 45 and sha(source) == before
    receipt = {"schema": "win98modern.tls-observer-host-fault-model.v1", "status": "PASS" if passed else "FAIL",
               "scope": "Linux mocks executing the actual observer C, no Windows/TLS execution",
               "native_windows_executed": False, "native_tls_verified": False,
               "cases": rows, "checks": len(rows), "compile_command": compile_command,
               "source": {"path": str(source), "sha256": before},
               "test_driver": {"path": str(Path(__file__).resolve()), "sha256": sha(Path(__file__))},
               "files": [{"path": str(p), "sha256": sha(p)} for p in (header, model, executable, output / "compile.log", output / "test.log")],
               "test_exit": tested.returncode}
    (output / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(tested.stdout, end="")
    if not passed:
        raise RuntimeError(f"Observer host fault model failed: {tested.stderr}; checks={len(rows)}")


if __name__ == "__main__":
    main()
