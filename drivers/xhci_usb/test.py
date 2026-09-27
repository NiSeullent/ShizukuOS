#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Original USB2 EP0 host model; no VM, MMIO, USB device or network access."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BUILD = HERE / 'build'
STRICT = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
          '-Wconversion', '-Wsign-conversion', '-Wshadow', '-fno-builtin']
FREESTANDING = ['-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                '-fno-pie', '-fno-pic', '-fno-asynchronous-unwind-tables',
                '-march=i486', '-mno-sse', '-mno-sse2', '-mno-mmx', '-msoft-float']
SOURCES = [ROOT / 'drivers/xhci_native/xhci.c', HERE / 'xhci_usb.c',
           ROOT / 'drivers/usb_native/ntwu_usb.c']
MANIFEST = SOURCES + [ROOT / 'drivers/xhci_native/xhci.h',
    ROOT / 'drivers/xhci_native/xhci_internal.h', ROOT / 'drivers/usb_native/ntwu_usb.h',
    HERE / 'xhci_usb.h', HERE / 'test_usb_xhci.c', HERE / 'test.py', HERE / 'README.md']


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
    for tool in ('gcc', 'clang', 'nm', 'ld'):
        if not shutil.which(tool):
            raise RuntimeError('Existing compiler/tool required: ' + tool)
    BUILD.mkdir(exist_ok=True)
    receipt = BUILD / 'test-result.json'
    receipt.unlink(missing_ok=True)
    sources = {str(path.relative_to(ROOT)): digest(path) for path in MANIFEST}
    result = {'module': 'original xHCI USB2 EP0', 'sources_sha256': sources,
              'host': {}, 'i486': {}, 'guest': 'not_run', 'hardware_io': 'none'}
    for compiler, label, extra in (
        ('gcc', 'gcc', []), ('clang', 'clang', []),
        ('clang', 'clang_sanitized', ['-fsanitize=address,undefined',
                                    '-fno-omit-frame-pointer'])
    ):
        executable = BUILD / (label + '-test')
        run([compiler, *STRICT, *extra, *SOURCES, HERE / 'test_usb_xhci.c', '-o', executable])
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                           UBSAN_OPTIONS='halt_on_error=1')
        output = run([executable], environment)
        (BUILD / (label + '.log')).write_text(output)
        result['host'][label] = {'compiler': run([compiler, '--version']).splitlines()[0],
                                 'passed': True, 'output': output,
                                 'log_sha256': digest(BUILD / (label + '.log'))}
    for compiler, target in (('gcc', ['-m32']),
                             ('clang', ['--target=i386-unknown-none-elf'])):
        objects = []
        for index, source in enumerate(SOURCES):
            obj = BUILD / (compiler + '-i486-' + str(index) + '.o')
            run([compiler, *STRICT, *FREESTANDING, *target, '-c', source, '-o', obj])
            objects.append(obj)
        linked = BUILD / (compiler + '-i486-linked.o')
        run(['ld', '-m', 'elf_i386', '-r', *objects, '-o', linked])
        undefined = run(['nm', '-u', linked]).strip()
        if undefined:
            raise RuntimeError('EP0 path requires external runtime helpers: ' + undefined)
        result['i486'][compiler] = {'flags': STRICT + FREESTANDING + target,
                                   'linked_object_sha256': digest(linked),
                                   'size_bytes': linked.stat().st_size,
                                   'undefined_symbols': [], 'passed': True}
    if sources != {str(path.relative_to(ROOT)): digest(path) for path in MANIFEST}:
        raise RuntimeError('EP0 source changed during validation')
    result['pass'] = True
    receipt.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
