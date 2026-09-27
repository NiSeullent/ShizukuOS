#!/usr/bin/env python3
"""Run independent host contracts, sanitizers and linked PE structure checks.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import json
import hashlib
import os
import subprocess
import sys
ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build/platform'
def run(*args):
    subprocess.run([str(x) for x in args], cwd=ROOT, check=True, timeout=90)
def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    (BUILD/'host-tests.json').unlink(missing_ok=True)
    manifest = json.loads((BUILD/'manifest.json').read_text())
    for name, digest in manifest['sources_sha256'].items():
        if hashlib.sha256((ROOT/name).read_bytes()).hexdigest() != digest:
            raise RuntimeError(f'Stale build source: {name}; run platform/build.py')
    for name, info in manifest['artifacts'].items():
        if hashlib.sha256((BUILD/name).read_bytes()).hexdigest() != info['sha256']:
            raise RuntimeError(f'Changed build artifact: {name}; run platform/build.py')
    sources = ['platform/tests/core_test.c', 'ntwrapper/core.c', 'ntwin32/sync.c']
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-pedantic', '-pthread']
    run(os.environ.get('CC','cc'), *flags, '-fsyntax-only', 'platform/tests/headers.c')
    run(os.environ.get('CC','cc'), *flags, '-O2', *sources, '-o', BUILD/'core_test')
    run(BUILD/'core_test')
    run(os.environ.get('NTW_SANITIZER_CC','clang'), *flags, '-g', '-O1',
        '-fsanitize=address,undefined', '-fno-omit-frame-pointer', *sources,
        '-o', BUILD/'core_test_sanitized')
    run(BUILD/'core_test_sanitized')
    run(sys.executable, '-m', 'unittest', 'discover', '-s', 'platform/tests', '-p', 'test_*.py', '-v')
    # Independent binutils reader also needs to recognize the rebuilt import table.
    output = subprocess.check_output(['i686-w64-mingw32-objdump','-p', str(BUILD/'NTWPROBE.EXE')], text=True)
    if 'NTW32.DLL' not in output or 'KERNEL32.dll' not in output:
        raise RuntimeError('independent PE reader did not recognize both import libraries')
    (BUILD/'pe-objdump.txt').write_text(output)
    (BUILD/'host-tests.json').write_text(json.dumps({'schema':'ntw.host-tests.v1',
        'kernel_lifetime_events':'pass', 'srw_concurrency':'pass', 'sanitizers':'pass',
        'pe_routing':'pass', 'independent_pe_reader':'pass', 'win98_guest':'not_run',
        'build_manifest_sha256': hashlib.sha256((BUILD/'manifest.json').read_bytes()).hexdigest(),
        'test_sources_sha256': {name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest()
            for name in ('platform/test.py','platform/tests/core_test.c','platform/tests/test_prepare.py',
                         'platform/tests/headers.c')}}, indent=2)+'\n')
    print('PASS: independent platform host contracts; Windows 98 guest not run')
if __name__ == '__main__':
    main()
