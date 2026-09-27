#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original deterministic WinAPI fault model; no native Windows execution.

Runs generated host fixtures with strict GCC/Clang and Clang ASan/UBSan,
then builds/audits the PE32 runner. Writes build/native_runner/ only.
The mock verifies supervisor policy, not actual Win98 API implementation.
"""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / 'build' / 'native_runner'
SOURCES = ('platform/win98lab/native_runner.c', 'platform/win98lab/build_native.py',
           'platform/win98lab/test_native_runner.py', 'ntwin32/prepare.py')

HEADER = r'''
#ifndef NTWRUN_MOCK_H
#define NTWRUN_MOCK_H
#include <stdint.h>
#include <stddef.h>
typedef uint32_t DWORD;
typedef int BOOL;
typedef uintptr_t HANDLE;
typedef struct { DWORD cb; unsigned char remaining[64]; } STARTUPINFOA;
typedef struct { HANDLE hProcess, hThread; DWORD dwProcessId, dwThreadId; } PROCESS_INFORMATION;
typedef struct { DWORD dwOSVersionInfoSize, dwMajorVersion, dwMinorVersion,
    dwBuildNumber, dwPlatformId; char szCSDVersion[128]; } OSVERSIONINFOA;
#define FALSE 0
#define TRUE 1
#define MAX_PATH 260
#define INVALID_HANDLE_VALUE ((HANDLE)~(uintptr_t)0)
#define INVALID_FILE_ATTRIBUTES 0xffffffffu
#define GENERIC_WRITE 0x40000000u
#define FILE_SHARE_READ 1u
#define CREATE_NEW 1u
#define FILE_ATTRIBUTE_NORMAL 0x80u
#define ERROR_FILE_NOT_FOUND 2u
#define VER_PLATFORM_WIN32_WINDOWS 1u
#define WAIT_OBJECT_0 0u
#define WAIT_TIMEOUT 258u
#define WAIT_FAILED 0xffffffffu
DWORD GetModuleFileNameA(void *, char *, DWORD);
HANDLE CreateFileA(const char *, DWORD, DWORD, void *, DWORD, DWORD, void *);
BOOL WriteFile(HANDLE, const void *, DWORD, DWORD *, void *);
BOOL FlushFileBuffers(HANDLE);
BOOL CloseHandle(HANDLE);
DWORD GetLastError(void);
BOOL GetVersionExA(OSVERSIONINFOA *);
DWORD GetFileAttributesA(const char *);
BOOL CreateProcessA(const char *, char *, void *, void *, BOOL, DWORD, void *,
                    const char *, STARTUPINFOA *, PROCESS_INFORMATION *);
DWORD WaitForSingleObject(HANDLE, DWORD);
BOOL GetExitCodeProcess(HANDLE, DWORD *);
BOOL TerminateProcess(HANDLE, DWORD);
_Noreturn void ExitProcess(DWORD);
#endif
'''

MODEL = r'''
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include "native_runner_mock.h"
void mainCRTStartup(void);
static unsigned long assertions, scenarios, fault_scenarios;
#define CHECK(x) do { ++assertions; if (!(x)) { fprintf(stderr,"check %u: %s (scenario %lu, call %u, fault %u)\n",__LINE__,#x,scenarios,m.calls,m.fault); exit(1); } } while (0)
enum { LOCATION_OK, LOCATION_LOWER, LOCATION_WRONG, LOCATION_TRUNCATED, LOCATION_NONUL };
typedef struct {
    unsigned calls, fault, fired, short_at, short_calls, writes, flushes;
    unsigned created, preflights, waits, stops, getexits, log_closes;
    unsigned launch_failure, exit_index, existing_log, attributes_error, location;
    unsigned own_log_exists, wait_mode, stop_mode, terminate_failure, exit_failure;
    DWORD os_platform, os_major, os_minor, os_build, last_error, exit_value, final_exit;
    unsigned live[32], close_calls[32], child_stopped[3], child_waits[3];
    char log[32768]; size_t log_size;
    jmp_buf exit_jump;
} model;
static model m;
static int call(void) {
    ++m.calls;
    if (m.calls == m.fault) { m.fired = 1; m.last_error = 0xd0000000u + m.calls; return 1; }
    return 0;
}
static void reset(void) {
    memset(&m,0,sizeof(m)); m.os_platform=1; m.os_major=4; m.os_minor=10;
    m.os_build=0x040a08aeu;
}
static int has(const char *text) { return strstr(m.log,text)!=NULL; }
DWORD GetLastError(void) { return m.last_error; }
DWORD GetModuleFileNameA(void *module,char *path,DWORD size) {
    const char *value=m.location==LOCATION_LOWER ? "c:\\ntwlab\\ntwrun.exe" :
        m.location==LOCATION_WRONG ? "C:\\OTHER\\NTWRUN.EXE" : "C:\\NTWLAB\\NTWRUN.EXE";
    size_t n=strlen(value); CHECK(module==NULL && size==260);
    if(call())return 0;
    if(m.location==LOCATION_TRUNCATED){memset(path,'X',size);return size;}
    memcpy(path,value,n+1); if(m.location==LOCATION_NONUL)path[n]='X'; return (DWORD)n;
}
HANDLE CreateFileA(const char *path,DWORD access,DWORD share,void *sa,DWORD mode,DWORD flags,void *temp) {
    CHECK(!strcmp(path,"C:\\NTWLAB\\NTWRUN.LOG"));
    CHECK(access==GENERIC_WRITE && share==FILE_SHARE_READ && !sa && mode==CREATE_NEW && flags==FILE_ATTRIBUTE_NORMAL && !temp);
    if(call())return INVALID_HANDLE_VALUE;
    if(m.own_log_exists){m.last_error=80;return INVALID_HANDLE_VALUE;}
    CHECK(!m.live[1]);m.live[1]=1;return 1;
}
BOOL WriteFile(HANDLE h,const void *data,DWORD n,DWORD *written,void *overlap) {
    CHECK(h==1 && m.live[1] && written && !overlap); ++m.writes;
    if(call())return FALSE;
    CHECK(m.log_size+n<sizeof(m.log));
    if(m.short_at==m.writes){*written=n-1; ++m.short_calls; return TRUE;}
    memcpy(m.log+m.log_size,data,n);m.log_size+=n;m.log[m.log_size]=0;*written=n;
    m.last_error=0xaabbccddu;return TRUE;
}
BOOL FlushFileBuffers(HANDLE h) { CHECK(h==1 && m.live[1]);++m.flushes;return !call(); }
BOOL CloseHandle(HANDLE h) {
    CHECK(h<32 && m.live[h]);++m.close_calls[h];if(h==1)++m.log_closes;
    if(call())return FALSE;
    m.live[h]=0;return TRUE;
}
BOOL GetVersionExA(OSVERSIONINFOA *v) {
    CHECK(v->dwOSVersionInfoSize==sizeof(*v));
    if(call())return FALSE;
    v->dwPlatformId=m.os_platform;v->dwMajorVersion=m.os_major;v->dwMinorVersion=m.os_minor;v->dwBuildNumber=m.os_build;return TRUE;
}
DWORD GetFileAttributesA(const char *path) {
    static const char *const expected[]={"C:\\NTWLAB\\NTWPROBE.LOG","C:\\NTWLAB\\NTWQUERY.LOG","C:\\NTWLAB\\NTWGPROB.LOG"};
    CHECK(!m.created && m.preflights<3 && !strcmp(path,expected[m.preflights]));++m.preflights;
    if(call())return INVALID_FILE_ATTRIBUTES;
    if(m.existing_log==m.preflights)return FILE_ATTRIBUTE_NORMAL;
    m.last_error=m.attributes_error?m.attributes_error:ERROR_FILE_NOT_FOUND;return INVALID_FILE_ATTRIBUTES;
}
BOOL CreateProcessA(const char *app,char *command,void *pa,void *ta,BOOL inherit,DWORD flags,void *env,
                    const char *cwd,STARTUPINFOA *startup,PROCESS_INFORMATION *p) {
    static const char *const expected[]={"C:\\NTWLAB\\NTWPROBE.EXE","C:\\NTWLAB\\NTWQUERY.EXE","C:\\NTWLAB\\NTWGPROB.EXE"};
    char quoted[80];unsigned i;
    CHECK(m.created<3 && m.preflights==3 && !strcmp(app,expected[m.created]));
    CHECK(!strcmp(cwd,"C:\\NTWLAB") && !pa && !ta && !inherit && !flags && !env);
    CHECK(startup->cb==sizeof(*startup));for(i=0;i<sizeof(startup->remaining);++i)CHECK(startup->remaining[i]==0);
    CHECK(p->hProcess==0 && p->hThread==0 && p->dwProcessId==0 && p->dwThreadId==0);
    snprintf(quoted,sizeof(quoted),"\"%s\"",app);CHECK(!strcmp(command,quoted));
    if(call())return FALSE;
    if(m.launch_failure==m.created+1){m.last_error=193;return FALSE;}
    p->hProcess=(HANDLE)(10+2*m.created);p->hThread=p->hProcess+1;
    p->dwProcessId=100+m.created;p->dwThreadId=200+m.created;
    m.live[p->hProcess]=1;m.live[p->hThread]=1;++m.created;
    command[0]='!';return TRUE;
}
DWORD WaitForSingleObject(HANDLE h,DWORD timeout) {
    unsigned index=(unsigned)(h-10)/2;CHECK(h>=10 && h%2==0 && h<16 && m.live[h]);
    CHECK(timeout==120000u || timeout==5000u);++m.waits;++m.child_waits[index];
    if(call())return WAIT_FAILED;
    if(timeout==120000u){CHECK(m.child_waits[index]==1);if(m.wait_mode){m.last_error=4660;return m.wait_mode;}}
    else {CHECK(m.stops>=1);if(m.stop_mode){m.last_error=4661;return m.stop_mode;}}
    m.child_stopped[index]=1;return WAIT_OBJECT_0;
}
BOOL GetExitCodeProcess(HANDLE h,DWORD *code) {
    unsigned index=(unsigned)(h-10)/2;
    CHECK(h>=10 && h%2==0 && h<16 && m.live[h] && m.child_stopped[index]);++m.getexits;
    if(call())return FALSE;
    if(m.exit_failure){m.last_error=6;return FALSE;}
    *code=m.exit_index==index+1?m.exit_value:0;return TRUE;
}
BOOL TerminateProcess(HANDLE h,DWORD code) {
    CHECK(h>=10 && h%2==0 && h<16 && m.live[h] && code==0x4e545701u);++m.stops;
    if(call())return FALSE;
    if(m.terminate_failure){m.last_error=5;return FALSE;}return TRUE;
}
_Noreturn void ExitProcess(DWORD code) { m.final_exit=code;longjmp(m.exit_jump,1); }
static void run(void) {
    unsigned i;++scenarios;
    if(!setjmp(m.exit_jump)){mainCRTStartup();CHECK(0);}
    for(i=0;i<m.created;++i){CHECK(m.close_calls[10+2*i]==1);CHECK(m.close_calls[11+2*i]==1);}
    CHECK(m.close_calls[1]<=1);
    if(m.final_exit==0){CHECK(m.created==3 && !m.stops && m.getexits==3);CHECK(has("RESULT=PASS\r\n"));
        CHECK(has("WIN98_IDENTIFIED=1\r\n") && has("OS_BUILD_LOW=2222\r\n"));
        CHECK(has("END=NTWGPROB.EXE\r\n"));for(i=0;i<32;++i)CHECK(m.live[i]==0);}
}
int main(void) {
    unsigned i, baseline_calls, baseline_writes, timeout_calls, timeout_writes;
    reset();run();CHECK(m.final_exit==0);baseline_calls=m.calls;baseline_writes=m.writes;
    CHECK(has("OS_PLATFORM=1\r\nOS_MAJOR=4\r\nOS_MINOR=10\r\n"));
    CHECK(!has("FAIL_STAGE") && !has("CHILD_STOPPED=UNKNOWN"));
    reset();m.location=LOCATION_LOWER;run();CHECK(m.final_exit==0);
    for(i=LOCATION_WRONG;i<=LOCATION_NONUL;++i){reset();m.location=i;run();CHECK(m.final_exit==2 && !m.created && !m.log_size);}
    reset();m.own_log_exists=1;run();CHECK(m.final_exit==2 && !m.created && !m.log_size);
    for(i=0;i<4;++i){reset();if(i==0)m.os_platform=2;if(i==1)m.os_major=5;if(i==2)m.os_minor=90;if(i==3)m.os_minor=0;
        run();CHECK(m.final_exit==1 && !m.created && has("WIN98_IDENTIFIED=0\r\n"));}
    for(i=1;i<=3;++i){reset();m.existing_log=i;run();CHECK(m.final_exit==1 && !m.created && has("EXISTING_LOG="));}
    for(i=3;i<=5;i+=2){reset();m.attributes_error=i;run();CHECK(m.final_exit==1 && !m.created && has("FAIL_STAGE=LogPreflight\r\n"));}
    for(i=1;i<=3;++i){reset();m.launch_failure=i;run();CHECK(m.final_exit==1 && m.created==i-1);
        CHECK(has("FAIL_STAGE=CreateProcessA\r\nWIN32_ERROR=193\r\n"));}
    for(i=1;i<=3;++i){reset();m.exit_index=i;m.exit_value=0x80000005u;run();
        CHECK(m.final_exit==1 && m.created==i && !m.stops && has("EXIT_CODE=2147483653\r\n"));}
    reset();m.exit_index=1;m.exit_value=259;run();CHECK(m.final_exit==1 && m.created==1 && has("EXIT_CODE=259\r\n"));
    reset();m.exit_failure=1;run();CHECK(m.final_exit==1 && m.created==1 && !m.stops);
    CHECK(has("FAIL_STAGE=GetExitCodeProcess\r\nWIN32_ERROR=6\r\n"));
    for(i=0;i<3;++i){reset();m.wait_mode=i==0?WAIT_TIMEOUT:i==1?WAIT_FAILED:128u;run();
        CHECK(m.final_exit==1 && m.created==1 && m.stops==1 && m.waits==2);
        CHECK(has("CHILD_STOPPED=1\r\n") && !has("END=NTWPROBE.EXE\r\n"));}
    reset();m.wait_mode=WAIT_TIMEOUT;m.stop_mode=WAIT_TIMEOUT;run();
    CHECK(m.final_exit==1 && m.created==1 && !m.getexits && has("CHILD_STOPPED=UNKNOWN\r\n"));
    reset();m.wait_mode=WAIT_TIMEOUT;m.stop_mode=WAIT_FAILED;run();
    CHECK(m.final_exit==1 && m.created==1 && !m.getexits && has("CHILD_STOPPED=UNKNOWN\r\n"));
    CHECK(has("FAIL_STAGE=StopWait\r\nWIN32_ERROR=4661\r\n"));
    reset();m.wait_mode=WAIT_TIMEOUT;m.terminate_failure=1;run();
    CHECK(m.final_exit==1 && m.created==1 && has("FAIL_STAGE=TerminateProcess\r\nWIN32_ERROR=5\r\n"));
    CHECK(has("CHILD_STOPPED=1\r\n"));
    reset();m.wait_mode=WAIT_TIMEOUT;m.exit_failure=1;run();
    CHECK(m.final_exit==1 && m.created==1 && has("FAIL_STAGE=StopGetExitCodeProcess\r\nWIN32_ERROR=6\r\n"));
    reset();m.wait_mode=WAIT_FAILED;run();CHECK(has("FAIL_STAGE=ProbeWait\r\nWIN32_ERROR=4660\r\n"));
    for(i=1;i<=baseline_calls;++i){reset();m.fault=i;run();++fault_scenarios;CHECK(m.fired && m.final_exit!=0);}
    for(i=1;i<=baseline_writes;++i){reset();m.short_at=i;run();++fault_scenarios;CHECK(m.short_calls==1 && m.final_exit==3);}
    reset();m.wait_mode=WAIT_TIMEOUT;run();timeout_calls=m.calls;timeout_writes=m.writes;
    for(i=1;i<=timeout_calls;++i){reset();m.wait_mode=WAIT_TIMEOUT;m.fault=i;run();++fault_scenarios;
        CHECK(m.fired && m.final_exit!=0 && m.created<=1);}
    for(i=1;i<=timeout_writes;++i){reset();m.wait_mode=WAIT_TIMEOUT;m.short_at=i;run();++fault_scenarios;
        CHECK(m.short_calls==1 && m.final_exit==3 && m.created<=1);}
    /* Error values must survive the logger's deliberate GetLastError clobber. */
    reset();m.launch_failure=1;run();CHECK(!has("WIN32_ERROR=2864434397"));
    printf("{\"assertions\":%lu,\"scenarios\":%lu,\"injected_callbacks\":%lu,\"baseline_calls\":%u,\"baseline_writes\":%u}\n",
        assertions,scenarios,fault_scenarios,baseline_calls,baseline_writes);
    return 0;
}
'''


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    receipt = BUILD / 'host-tests.json'
    receipt.unlink(missing_ok=True)
    before = {name: sha(ROOT / name) for name in SOURCES}
    (BUILD / 'native_runner_mock.h').write_text(HEADER)
    model = BUILD / 'native_runner_model.c'
    model.write_text(MODEL)
    variants = {}
    for name, compiler, flags in (
            ('gcc', 'gcc', []), ('clang', 'clang', []),
            ('asan_ubsan', 'clang', ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                                    '-fno-omit-frame-pointer'])):
        executable = BUILD / ('host-' + name)
        command = [compiler, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-Wpedantic', '-Wconversion', '-Wshadow', *flags, '-DNTWRUN_TEST',
                   '-I', str(BUILD), str(HERE / 'native_runner.c'), str(model), '-o', str(executable)]
        compiled = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        tested = subprocess.run([str(executable)], check=True, capture_output=True, text=True, timeout=30)
        if tested.stderr:
            raise RuntimeError('Unexpected host-model/sanitizer diagnostic: ' + tested.stderr)
        counts = json.loads(tested.stdout)
        if (set(counts) != {'assertions', 'scenarios', 'injected_callbacks', 'baseline_calls', 'baseline_writes'}
                or counts['scenarios'] < 100 or counts['injected_callbacks'] < 100):
            raise RuntimeError('Missing meaningful fault-model results')
        log = BUILD / (name + '.log')
        log.write_text(' '.join(command) + '\n' + compiled.stdout + compiled.stderr + tested.stdout + tested.stderr)
        variants[name] = {'passed': True, **counts, 'log_sha256': sha(log),
                          'compiler': subprocess.check_output([compiler, '--version'], text=True,
                                                              timeout=10).splitlines()[0]}
        print(name, json.dumps(counts, sort_keys=True))
    spec = importlib.util.spec_from_file_location('ntw_build_native', HERE / 'build_native.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    built = module.build(BUILD)
    if any(sha(ROOT / name) != digest for name, digest in before.items()):
        raise RuntimeError('Test/build sources changed during run')
    record = {'schema': 'ntw.native_runner.host.v1', 'passed': True, 'sources_sha256': before,
              'artifact_sha256': built['sha256'], 'build_receipt_sha256': sha(BUILD / 'build-result.json'),
              'variants': variants, 'native_win98': 'not_tested', 'guest_executed': False,
              'mock_scope': 'original WinAPI supervisor policy, not native OS behavior'}
    receipt.write_text(json.dumps(record, indent=2) + '\n')
    print('PE/import audit PASS', built['sha256'])


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as failure:
        print(failure.stdout or '', end='')
        print(failure.stderr or '', end='')
        raise
