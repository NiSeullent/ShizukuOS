#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile actual native_crt.c and fault-test its output-based startup ABI.

This is a Linux host model, not a Win98 execution receipt. The controlled
__getmainargs return models arbitrary EAX from old void-return MSVCRT versions.
Compile-time symbol renaming intercepts the application's main and CRT exit;
setjmp observes both exit paths without executing a Windows target or VM.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import time


HEADER = r'''#ifndef NTWST_HOST_WINDOWS_H
#define NTWST_HOST_WINDOWS_H
#include <stdint.h>
#define __cdecl
#define WINAPI
typedef int BOOL;
typedef uint32_t DWORD;
typedef void *HINSTANCE;
typedef void *LPVOID;
#define TRUE 1
_Noreturn void ExitProcess(unsigned int code);
#endif
'''

HARNESS = r'''#include <windows.h>
#include <limits.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct ntwst_startup_info { int newmode; };
void mainCRTStartup(void);

enum fault { VALID, UNWRITTEN, NULL_ARGV, NULL_ENV, NULL_ARGV0, NO_TERMINATOR };
struct test_case {
    const char *name;
    enum fault fault;
    int argc, eax, main_return, expect_main;
};
static const struct test_case cases[] = {
    {"valid_zero_eax_zero_exit", VALID, 2, 0, 0, 1},
    {"valid_positive_eax_full_nonzero_exit", VALID, 2, 41, 0x12345, 1},
    {"valid_negative_eax_negative_exit", VALID, 1, -9001, -17, 1},
    {"valid_argc_upper_bound_arbitrary_eax", VALID, 32767, -559038737, INT_MAX, 1},
    {"unwritten_outputs_zero_eax_refused", UNWRITTEN, -1, 0, 19, 0},
    {"zero_argc_refused", VALID, 0, 0, 19, 0},
    {"negative_argc_refused", VALID, -2, 0, 19, 0},
    {"argc_above_upper_bound_refused", VALID, 32768, 0, 19, 0},
    {"null_argv_refused", NULL_ARGV, 1, 0, 19, 0},
    {"null_environment_refused", NULL_ENV, 1, 0, 19, 0},
    {"null_argv0_refused", NULL_ARGV0, 1, 0, 19, 0},
    {"missing_argv_argc_terminator_refused", NO_TERMINATOR, 2, 0, 19, 0}
};
static jmp_buf stopped;
static const struct test_case *active;
static char *wire_argv[32768];
static char *wire_env[] = {"NTWST_HOST_ABI=1", NULL};
static int getmainargs_calls, initial_sentinels, getter_configuration;
static int unwritten_outputs_unchanged, main_calls, arguments_forwarded;
static int crt_exit_calls, process_exit_calls, observed_crt_exit, returned;
static unsigned int observed_process_exit;

int __getmainargs(int *argc, char ***argv, char ***env, int wildcard,
                  struct ntwst_startup_info *startup)
{
    ++getmainargs_calls;
    initial_sentinels = argc && argv && env && *argc == -1 &&
                        *argv == NULL && *env == NULL;
    getter_configuration = startup && startup->newmode == 0 && wildcard == 0;
    if (active->fault != UNWRITTEN) {
        *argc = active->argc;
        *argv = active->fault == NULL_ARGV ? NULL : wire_argv;
        *env = active->fault == NULL_ENV ? NULL : wire_env;
    } else {
        unwritten_outputs_unchanged = *argc == -1 && *argv == NULL && *env == NULL;
    }
    return active->eax;
}

int test_application_main(int argc, char **argv)
{
    int i;
    ++main_calls;
    arguments_forwarded = argc == active->argc && argv == wire_argv &&
                          !strcmp(argv[0], "TLS13PRB.EXE") && argv[argc] == NULL;
    if (arguments_forwarded) {
        for (i = 1; i < argc; ++i)
            if (argv[i] != wire_argv[i] || strcmp(argv[i], "opaque-argument"))
                arguments_forwarded = 0;
    }
    return active->main_return;
}

_Noreturn void controlled_crt_exit(int code)
{
    ++crt_exit_calls;
    observed_crt_exit = code;
    longjmp(stopped, 1);
}

_Noreturn void ExitProcess(unsigned int code)
{
    ++process_exit_calls;
    observed_process_exit = code;
    longjmp(stopped, 2);
}

int main(void)
{
    /* Static counters retain defined values after an intercepted longjmp. */
    static size_t number;
    static int failures;
    for (number = 0; number < sizeof(cases) / sizeof(cases[0]); ++number) {
        int passed, i;
        active = &cases[number];
        getmainargs_calls = initial_sentinels = getter_configuration = 0;
        unwritten_outputs_unchanged = main_calls = arguments_forwarded = 0;
        crt_exit_calls = process_exit_calls = observed_crt_exit = returned = 0;
        observed_process_exit = 0;
        for (i = 0; i < 32768; ++i) wire_argv[i] = "opaque-argument";
        wire_argv[0] = "TLS13PRB.EXE";
        if (active->argc >= 0 && active->argc <= 32767)
            wire_argv[active->argc] = NULL;
        if (active->fault == NULL_ARGV0) wire_argv[0] = NULL;
        if (active->fault == NO_TERMINATOR) wire_argv[active->argc] = "extra";
        if (setjmp(stopped) == 0) {
            mainCRTStartup();
            returned = 1;
        }
        passed = !returned && getmainargs_calls == 1 && initial_sentinels &&
                 getter_configuration;
        if (active->expect_main)
            passed = passed && main_calls == 1 && arguments_forwarded &&
                     crt_exit_calls == 1 && !process_exit_calls &&
                     observed_crt_exit == active->main_return;
        else
            passed = passed && !main_calls && !crt_exit_calls &&
                     process_exit_calls == 1 && observed_process_exit == 2;
        if (active->fault == UNWRITTEN)
            passed = passed && unwritten_outputs_unchanged;
        printf("{\"case\":\"%s\",\"status\":\"%s\",\"mock_eax\":%d,"
               "\"initial_output_sentinels\":%d,\"main_calls\":%d,"
               "\"arguments_forwarded\":%d,\"crt_exit_calls\":%d,"
               "\"crt_exit_code\":%d,\"process_exit_calls\":%d,"
               "\"process_exit_code\":%u,\"unwritten_outputs_unchanged\":%d}\n",
               active->name, passed ? "PASS" : "FAIL", active->eax,
               initial_sentinels, main_calls, arguments_forwarded, crt_exit_calls,
               observed_crt_exit, process_exit_calls, observed_process_exit,
               unwritten_outputs_unchanged);
        if (!passed) ++failures;
    }
    return failures ? 1 : 0;
}
'''


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    module = Path(__file__).resolve().parent
    root = module.parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path,
                        default=root / 'build/secure-transport/native-crt-host-v1')
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    compiler = shutil.which(args.cc)
    if not compiler:
        raise RuntimeError('A host C compiler is required')
    source = module / 'native_crt.c'
    source_bytes = source.read_bytes()
    source_sha = sha(source_bytes)
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    header = out / 'windows.h'
    fixture = out / 'startup_model.c'
    frozen = out / 'native_crt.c'
    header.write_text(HEADER)
    fixture.write_text(HARNESS)
    frozen.write_bytes(source_bytes)
    flags = ['-std=c11', '-O2', '-g', '-Wall', '-Wextra', '-Werror',
             '-fsanitize=undefined', '-fsanitize-undefined-trap-on-error',
             '-fno-omit-frame-pointer',
             '-I', str(out)]
    commands = [
        [compiler, *flags, '-Dmain=test_application_main', '-Dexit=controlled_crt_exit',
         '-c', str(frozen), '-o', str(out / 'native_crt.o')],
        [compiler, *flags, str(fixture), str(out / 'native_crt.o'),
         '-o', str(out / 'startup_model')],
    ]
    for index, command in enumerate(commands):
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (out / f'compile-{index}.stdout').write_text(result.stdout)
        (out / f'compile-{index}.stderr').write_text(result.stderr)
        if result.returncode:
            raise RuntimeError(f'Host model compilation failed: {result.stderr}')
    started = time.monotonic()
    tested = subprocess.run([str(out / 'startup_model')], capture_output=True,
                            text=True, timeout=30)
    (out / 'model.stdout').write_text(tested.stdout)
    (out / 'model.stderr').write_text(tested.stderr)
    rows = [json.loads(line) for line in tested.stdout.splitlines()]
    expected_names = {
        'valid_zero_eax_zero_exit', 'valid_positive_eax_full_nonzero_exit',
        'valid_negative_eax_negative_exit', 'valid_argc_upper_bound_arbitrary_eax',
        'unwritten_outputs_zero_eax_refused', 'zero_argc_refused',
        'negative_argc_refused', 'argc_above_upper_bound_refused',
        'null_argv_refused', 'null_environment_refused', 'null_argv0_refused',
        'missing_argv_argc_terminator_refused',
    }
    source_unchanged = source.read_bytes() == source_bytes
    passed = (tested.returncode == 0 and len(rows) == 12 and
              {row['case'] for row in rows} == expected_names and
              all(row['status'] == 'PASS' for row in rows) and source_unchanged)
    receipt = {
        'schema': 1, 'status': 'PASS' if passed else 'FAIL',
        'scope': 'Actual byte-exact native_crt.c compiled in a Linux host ABI/fault model. No guest execution, native Windows CRT, TLS handshake or application claim.',
        'source': str(source), 'source_sha256': source_sha,
        'source_unchanged_after_test': source_unchanged,
        'source_compiled_byte_exact': frozen.read_bytes() == source_bytes,
        'test_source_sha256': sha(Path(__file__).read_bytes()),
        'fake_windows_header_sha256': sha(header.read_bytes()),
        'harness_sha256': sha(fixture.read_bytes()),
        'model_sha256': sha((out / 'startup_model').read_bytes()),
        'compiler': compiler,
        'compiler_version': subprocess.run([compiler, '--version'], capture_output=True,
                                           text=True, timeout=10).stdout.splitlines()[0],
        'compile_commands': commands, 'sanitizers': ['undefined-trap'],
        'case_count': len(rows), 'cases': rows,
        'model_exit_code': tested.returncode, 'model_stderr': tested.stderr,
        'seconds': round(time.monotonic() - started, 4),
        'upstream_abi_reference': 'https://sourceforge.net/p/mingw-w64/mailman/message/58846398/',
        'upstream_reference_contents_claim': 'Not quoted or independently reverified by this executable model.',
    }
    payload = (json.dumps(receipt, indent=2) + '\n').encode()
    path = out / 'result.json'
    path.write_bytes(payload)
    if not passed:
        raise RuntimeError(f'Native CRT host regression failed; receipt={path}; {tested.stderr}')
    print(json.dumps({'status': 'PASS', 'cases': len(rows), 'source_sha256': source_sha,
                      'receipt': str(path), 'receipt_sha256': sha(payload)}))


if __name__ == '__main__':
    main()
