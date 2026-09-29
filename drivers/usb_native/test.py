#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded host tests only. Writes this module's build directory; no USB I/O."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
BUILD = HERE / 'build'
STRICT = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
          '-Wconversion', '-Wsign-conversion', '-fno-builtin']
FREESTANDING = ['-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                '-fno-pie', '-fno-pic', '-fno-asynchronous-unwind-tables',
                '-march=i486', '-mno-sse', '-mno-sse2', '-mno-mmx', '-msoft-float']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, env=None):
    completed = subprocess.run([str(value) for value in command], cwd=HERE,
                               capture_output=True, text=True, timeout=60, env=env)
    if completed.returncode:
        raise RuntimeError(f'{command[0]} exited {completed.returncode}:\n'
                           f'{completed.stdout}{completed.stderr}')
    return completed.stdout


def main():
    for tool in ('gcc', 'clang', 'nm'):
        if not shutil.which(tool):
            raise RuntimeError('Existing compiler/tool required: ' + tool)
    BUILD.mkdir(exist_ok=True)
    receipt = BUILD / 'test-result.json'
    receipt.unlink(missing_ok=True)
    sources = {name: digest(HERE / name) for name in
               ('ntwu_usb.c', 'ntwu_usb.h', 'test_usb.c', 'test.py')}
    result = {'module': 'Windows 98 Shizuku\'s Second Edition USB descriptor parser',
              'sources_sha256': sources, 'host': {}, 'i486': {},
              'source_provenance': 'original project code; specification facts only',
              'guest': 'not_run', 'hardware_io': 'none'}
    for compiler, label, extra in (
        ('gcc', 'gcc', []), ('clang', 'clang', []),
        ('clang', 'clang_sanitized', ['-fsanitize=address,undefined',
                                    '-fno-omit-frame-pointer'])
    ):
        executable = BUILD / (label + '-test')
        run([compiler, *STRICT, *extra, 'ntwu_usb.c', 'test_usb.c', '-o', executable])
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                           UBSAN_OPTIONS='halt_on_error=1')
        counts = json.loads(run([executable], environment))
        result['host'][label] = {'compiler': run([compiler, '--version']).splitlines()[0],
                                 'passed': True, **counts}
    for compiler, target in (('gcc', ['-m32']),
                             ('clang', ['--target=i386-unknown-none-elf'])):
        obj = BUILD / (compiler + '-i486-usb.o')
        run([compiler, *STRICT, *FREESTANDING, *target, '-c', 'ntwu_usb.c', '-o', obj])
        undefined = run(['nm', '-u', obj]).strip()
        if undefined:
            raise RuntimeError('USB parser requires external runtime helpers: ' + undefined)
        data = obj.read_bytes()
        if data[:7] != b'\x7fELF\x01\x01\x01' or int.from_bytes(data[18:20], 'little') != 3:
            raise RuntimeError('Expected little-endian ELF32 i386 parser object')
        result['i486'][compiler] = {'flags': STRICT + FREESTANDING + target,
                                   'object_sha256': digest(obj), 'size_bytes': len(data),
                                   'undefined_symbols': [], 'passed': True}
    if any(digest(HERE / name) != expected for name, expected in sources.items()):
        raise RuntimeError('USB source changed during validation')
    result['pass'] = True
    receipt.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
