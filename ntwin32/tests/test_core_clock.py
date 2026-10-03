#!/usr/bin/env python3
"""Bounded production Core clock C tests and optional component builds only.
SPDX-License-Identifier: GPL-2.0-only
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--components', action='store_true')
    parser.add_argument('--gcc-without-sanitizers', action='store_true',
                        help='Record GCC as plain host tests when its installed sanitizer runtime is absent')
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / 'build') or out == ROOT / 'build' or out.exists():
        parser.error('--out must be a fresh component directory under this clone build/')
    if shutil.disk_usage(ROOT).free < 17 * 1024**3:
        parser.error('17 GiB free-space floor; no builds started')
    out.mkdir(parents=True)
    platform_dir = ROOT / 'build/platform'
    if args.components and platform_dir.exists():
        parser.error('Existing build/platform is historical; preserve/move it before a fresh component cohort')
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    new = ['shizukudos/abi/shz_clock.h', 'ntwin32/core_clock.c', 'ntwin32/core_clock.h',
           'ntwin32/core_clock_probe.c', 'ntwin32/README-core-clock.md',
           'ntwin32/tests/test_core_clock.c', 'ntwin32/tests/test_core_clock.py']
    paths = sorted(set(name for name in tracked + new if name and (ROOT / name).is_file()))
    before = {name: digest(ROOT / name) for name in paths}
    commands = []
    def run(command, env=None):
        index = len(commands)
        try:
            result = subprocess.run([str(x) for x in command], cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=180)
        except subprocess.TimeoutExpired as error:
            log = out / f'{index:02d}.log'
            log.write_bytes((error.stdout or b'') + (error.stderr or b''))
            commands.append({'command': [str(x) for x in command], 'exit': None,
                             'timeout_seconds': 180, 'log': str(log.relative_to(ROOT)),
                             'sha256': digest(log)})
            raise
        log = out / f'{index:02d}.log'
        log.write_text(result.stdout + result.stderr)
        commands.append({'command': [str(x) for x in command], 'exit': result.returncode,
                         'log': str(log.relative_to(ROOT)), 'sha256': digest(log)})
        if result.returncode:
            raise RuntimeError(f'command {index} failed; see {log}')
        print(result.stdout.strip() or f'PASS command {index}', flush=True)
    header = out / 'windows.h'
    header.write_text('''#ifndef CLOCK_TEST_WINDOWS_H
#define CLOCK_TEST_WINDOWS_H
#include <stdint.h>
typedef uint32_t DWORD;
typedef int32_t LONG;
typedef int BOOL;
typedef void *HANDLE;
typedef uintptr_t SIZE_T;
typedef union { int64_t QuadPart; } LARGE_INTEGER, *PLARGE_INTEGER;
typedef struct { void *BaseAddress, *AllocationBase; DWORD AllocationProtect;
                 SIZE_T RegionSize; DWORD State, Protect, Type; } MEMORY_BASIC_INFORMATION;
#define WINAPI
#define TRUE 1
#define FALSE 0
#ifndef NULL
#define NULL ((void *)0)
#endif
#define INVALID_HANDLE_VALUE ((HANDLE)(uintptr_t)-1)
#define OPEN_EXISTING 3u
#define FILE_FLAG_DELETE_ON_CLOSE 0x04000000u
#define MEM_COMMIT 0x1000u
#define PAGE_NOACCESS 0x01u
#define PAGE_READONLY 0x02u
#define PAGE_READWRITE 0x04u
#define PAGE_WRITECOPY 0x08u
#define PAGE_EXECUTE_READWRITE 0x40u
#define PAGE_EXECUTE_WRITECOPY 0x80u
#define PAGE_GUARD 0x100u
DWORD GetLastError(void);
void SetLastError(DWORD);
HANDLE CreateFileA(const char *,DWORD,DWORD,void *,DWORD,DWORD,HANDLE);
BOOL DeviceIoControl(HANDLE,DWORD,void *,DWORD,void *,DWORD,DWORD *,void *);
BOOL CloseHandle(HANDLE);
SIZE_T VirtualQuery(const void *,MEMORY_BASIC_INFORMATION *,SIZE_T);
void OutputDebugStringA(const char *);
#endif
''')
    tool_versions = {}
    status = 'FAIL'
    components_built = False
    try:
        for cc in ('gcc', 'clang'):
            tool_versions[cc] = subprocess.check_output([cc, '--version'], text=True).splitlines()[0]
            common = [cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
                      '-Wconversion', '-Wshadow', '-fno-omit-frame-pointer', '-fno-pie', '-no-pie', '-pthread']
            if cc != 'gcc' or not args.gcc_without_sanitizers:
                common += ['-fsanitize=address,undefined']
            for native in (False, True):
                binary = out / f'client-{cc}-{int(native)}'
                define = '-DNTW_CORE_CLOCK_NATIVE_TEST' if native else '-DNTW_CORE_CLOCK_HOST'
                run([*common, define, '-I', out, ROOT / 'ntwin32/core_clock.c',
                     ROOT / 'ntwin32/tests/test_core_clock.c', '-o', binary])
                run([binary])
            binary = out / f'bridge-{cc}'
            run([*common, ROOT / 'ntwrapper/vxd/bridge.c', ROOT / 'ntwrapper/vxd/pma_endpoint.c',
                 ROOT / 'ntwrapper/core.c', ROOT / 'ntwrapper/vxd/tests/test_bridge.c', '-o', binary])
            run([binary])
        if args.components:
            run([sys.executable, '-B', ROOT / 'platform/build.py'])
            run([sys.executable, '-B', ROOT / 'ntwrapper/vxd/build.py', '--out', out / 'vxd'])
            run([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'ntwin32/tests', '-p', 'test_routes.py'])
            run([sys.executable, '-B', '-m', 'unittest', 'discover', '-s', 'platform/tests', '-p', 'test_prepare.py'])
            env = dict(os.environ, NTWV_HOST_TEST_OUT=str(out / 'vxd'))
            run([sys.executable, '-B', '-m', 'unittest',
                 'ntwrapper.vxd.tests.test_vxd.VxDTests.test_win64_bridge_dioc_against_kernel64_wire_library_under_sanitizers',
                 'ntwrapper.vxd.tests.test_vxd.VxDTests.test_parallel_win64_admission_under_sanitizers',
                 'ntwrapper.vxd.tests.test_vxd.VxDTests.test_native_control_dispatch_abi_in_i386_user_harness'], env)
            spec = importlib.util.spec_from_file_location('clock_supervisor_build', ROOT / 'shizukudos/supervisor/build.py')
            module = importlib.util.module_from_spec(spec)
            sys.path.insert(0, str(ROOT / 'shizukudos/supervisor'))
            spec.loader.exec_module(module)
            run(['gcc', *module.CFLAGS, '-I', ROOT / 'shizukudos/supervisor/src',
                 '-I', ROOT / 'shizukudos/abi', '-c', ROOT / 'shizukudos/supervisor/src/domain.c',
                 '-o', out / 'domain64.o'])
            run(['clang', *[flag for flag in module.CFLAGS if flag != '-fno-tree-loop-distribute-patterns'],
                 '-I', ROOT / 'shizukudos/supervisor/src', '-I', ROOT / 'shizukudos/abi',
                 '-c', ROOT / 'shizukudos/supervisor/src/domain.c', '-o', out / 'domain64-clang.o'])
            components_built = True
        after = {name: digest(ROOT / name) for name in paths}
        if after != before:
            raise RuntimeError('Source changed during tests')
        status = 'PASS_COMPONENT_SOURCE_ONLY'
    except Exception:
        status = 'FAIL'
        raise
    finally:
        artifacts = {str(p.relative_to(ROOT)): {'bytes': p.stat().st_size, 'sha256': digest(p)}
                     for p in out.rglob('*') if p.is_file()}
        for directory in ((ROOT / 'build/platform',) if args.components and (ROOT / 'build/platform').is_dir() else ()):
            artifacts.update({str(p.relative_to(ROOT)): {'bytes': p.stat().st_size, 'sha256': digest(p)}
                              for p in directory.iterdir() if p.is_file()})
        receipt = {'status': status, 'head': subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
                   'source_before': before, 'source_after': {name:digest(ROOT/name) for name in paths},
                   'commands': commands, 'tools': tool_versions, 'artifacts': artifacts,
                   'artifact_origin': ('Fresh component output; build/platform was absent before this cohort'
                                       if args.components else
                                       'Fresh host output only; existing build/platform is excluded and untouched'),
                   'components_requested': args.components, 'components_built': components_built,
                   'sanitizers': {'gcc': not args.gcc_without_sanitizers, 'clang': True},
                   'scope': 'Real production C/client/VxD plus modeled TSC, Win32 imports, VMM pages and hypervisor callbacks.',
                   'guest_executed': False, 'native_boot': False, 'clock_hardware_resolution_verified': False}
        (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print(f'{status}: {out / "result.json"}')

if __name__ == '__main__':
    main()
