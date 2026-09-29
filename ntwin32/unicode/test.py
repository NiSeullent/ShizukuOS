#!/usr/bin/env python3
"""Build/test original UTF core; no installs, downloads, or guest processes.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import hashlib
import json
import os
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / 'build'


def run(command, **options):
    result = subprocess.run([str(part) for part in command], cwd=HERE, check=True,
                            capture_output=True, text=True, timeout=90, **options)
    if result.stdout:
        print(result.stdout, end='')
    return result


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    receipt = BUILD / 'host-tests.json'
    receipt.unlink(missing_ok=True)
    sources = [HERE / name for name in ('utf.h', 'utf.c', 'test_utf.c', 'test.py', 'oracle.py')]

    def hashes():
        return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in sources}

    before = hashes()
    compiler = os.environ.get('NTWU_CC', 'clang')
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-Wconversion',
             '-Wsign-conversion', '-Wshadow', '-Wstrict-prototypes']
    host = BUILD / 'test_utf'
    sanitized = BUILD / 'test_utf_sanitize'
    run([compiler, *flags, '-O2', '-g', HERE / 'utf.c', HERE / 'test_utf.c', '-o', host])
    normal = run([host])
    run([compiler, *flags, '-O1', '-g', '-fsanitize=address,undefined',
         '-fno-omit-frame-pointer', HERE / 'utf.c', HERE / 'test_utf.c', '-o', sanitized])
    environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:halt_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1')
    sanitizer = run([sanitized], env=environment)
    if normal.stdout != sanitizer.stdout:
        raise RuntimeError('Normal and sanitizer test summaries differ')
    match = re.fullmatch(r'UTF core: ([0-9]+) checks passed; ([0-9]+) Unicode scalars '
                         r'exhaustively roundtripped; host only\.\n', normal.stdout)
    if match is None or int(match.group(2)) != 1112064:
        raise RuntimeError('Exhaustive Unicode scalar evidence missing')
    obj = BUILD / 'utf-i486.o'
    run([compiler, '--target=i486-none-elf', *flags, '-O2', '-ffreestanding',
         '-fno-builtin', '-fno-stack-protector', '-c', HERE / 'utf.c', '-o', obj])
    undefined = run(['nm', '-u', obj]).stdout
    if undefined.strip():
        raise RuntimeError('Freestanding core has unresolved runtime dependencies')
    (BUILD / 'undefined-symbols.txt').write_text(undefined)
    shared = BUILD / 'utf-oracle.so'
    run([compiler, *flags, '-O2', '-shared', '-fPIC', '-nostdlib', '-ffreestanding',
         '-fno-builtin', '-fno-stack-protector', HERE / 'utf.c', '-o', shared])
    if run(['nm', '-u', shared]).stdout.strip():
        raise RuntimeError('Host oracle library has unresolved runtime dependencies')
    oracle = json.loads(run([sys.executable, HERE / 'oracle.py', shared]).stdout)
    if oracle['status'] != 'PASS':
        raise RuntimeError('Independent host codec comparison failed')
    if hashes() != before:
        raise RuntimeError('Unicode sources changed during validation')
    result = {'schema': 'ntwin32.unicode.host.v1', 'passed': True,
              'sources_sha256': before, 'checks': int(match.group(1)),
              'unicode_scalars': int(match.group(2)), 'strict_host': 'pass',
              'asan_ubsan': 'pass', 'i486_undefined_symbols': [],
              'independent_host_oracle': oracle,
              'native_windows_differential': 'not_run', 'win98_guest': 'not_run',
              'win32_adapter': 'not_tested_by_this_runner', 'stdout': normal.stdout,
              'artifacts_sha256': {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in (host, sanitized, obj, shared)}}
    receipt.write_text(json.dumps(result, indent=2) + '\n')
    print('PASS: UTF core only; Win32 adapter execution is tested by platform/abi32')


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or '', end='')
        print(error.stderr or '', end='')
        raise
