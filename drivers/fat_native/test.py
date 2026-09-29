#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/run original synthetic FAT32 host tests; never open a device or VM.

Writes only drivers/fat_native/build/. Requires existing GCC, Clang, nm and
Python. The sector model is compiled into a host executable, not a disk image.
"""
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
BUILD = HERE / 'build'
SOURCES = ('fat.h', 'fat.c', 'test_fat.c', 'test.py', 'README.md', 'REFERENCES.md')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, timeout=120):
    result = subprocess.run([str(item) for item in command], capture_output=True,
                            text=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError('Command failed: ' + ' '.join(map(str, command)) + '\n' +
                           result.stdout + result.stderr)
    return result


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    receipt = BUILD / 'test-result.json'
    receipt.unlink(missing_ok=True)
    before = {name: digest(HERE / name) for name in SOURCES}
    strict = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
              '-Wconversion', '-Wshadow']
    variants, objects = {}, {}
    for name, compiler, extra in (
            ('gcc', 'gcc', []), ('clang', 'clang', []),
            ('asan_ubsan', 'clang', ['-fsanitize=address,undefined',
                                   '-fno-sanitize-recover=all', '-fno-omit-frame-pointer'])):
        executable = BUILD / ('test-' + name)
        command = [compiler, *strict, *extra, HERE / 'fat.c', HERE / 'test_fat.c',
                   '-o', executable]
        compiled = run(command)
        tested = run([executable])
        if tested.stderr:
            raise RuntimeError('Unexpected host test diagnostics: ' + tested.stderr)
        counts = json.loads(tested.stdout)
        if (not isinstance(counts, dict) or set(counts) != {
                'status', 'checks', 'scenarios', 'injected_callbacks', 'mutation_cases'} or
                counts.get('status') != 'PASS'):
            raise RuntimeError('Missing independent model counters')
        numeric = {key: value for key, value in counts.items() if key != 'status'}
        if (any(not isinstance(value, int) or value < 0 for value in numeric.values()) or
                numeric['checks'] < 1000 or numeric['scenarios'] < 100 or
                numeric['injected_callbacks'] < 20):
            raise RuntimeError('Invalid independent model counter')
        log = BUILD / (name + '.log')
        log.write_text(' '.join(map(str, command)) + '\n' + compiled.stdout +
                       compiled.stderr + tested.stdout + tested.stderr)
        variants[name] = {'passed': True, **counts, 'log_sha256': digest(log),
                          'compiler': run([compiler, '--version']).stdout.splitlines()[0]}
        print(name, tested.stdout.strip(), flush=True)
    for compiler, target in (('gcc', ['-m32']), ('clang', ['--target=i386-none-elf'])):
        output = BUILD / (compiler + '-i486.o')
        command = [compiler, '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                   '-Wpedantic', '-Wconversion', '-Wshadow', *target, '-march=i486',
                   '-mno-sse', '-mno-sse2', '-mno-mmx', '-msoft-float', '-ffreestanding',
                   '-fno-builtin', '-fno-pie', '-fno-pic', '-fno-stack-protector', '-fno-asynchronous-unwind-tables',
                   '-fstack-usage', '-c', HERE / 'fat.c', '-o', output]
        compiled = run(command)
        undefined = run(['nm', '-u', output]).stdout.strip()
        if undefined:
            raise RuntimeError('Freestanding compiler helpers: ' + undefined)
        usage = output.with_suffix('.su')
        frames = []
        for line in usage.read_text().splitlines():
            fields = line.split('\t')
            if len(fields) != 3 or fields[2] not in ('static', 'dynamic,bounded'):
                raise RuntimeError('Unbounded/unrecognized stack usage: ' + line)
            frames.append(int(fields[1]))
        if not frames or max(frames) > 2048:
            raise RuntimeError('Unexpected boot stack frame size')
        log = BUILD / (compiler + '-i486.log')
        log.write_text(' '.join(map(str, command)) + '\n' + compiled.stdout + compiled.stderr +
                       'nm -u: empty\n' + usage.read_text())
        objects[compiler] = {'passed': True, 'sha256': digest(output),
                             'bytes': output.stat().st_size, 'undefined_symbols': [],
                             'max_stack_frame': max(frames),
                             'conservative_all_frames_sum': sum(frames),
                             'log_sha256': digest(log)}
        print(compiler, 'i486 zero helpers; largest frame', max(frames), flush=True)
    if any(digest(HERE / name) != value for name, value in before.items()):
        raise RuntimeError('FAT32 source changed during validation')
    result = {'schema': 'ntw.fat_native.host.v1', 'passed': True,
              'sources_sha256': before, 'variants': variants, 'i486_objects': objects,
              'media': 'synthetic sparse sectors only', 'private_windows_accessed': False,
              'guest_executed': False, 'boot_file_execution': False,
              'writes_supported': False}
    receipt.write_text(json.dumps(result, indent=2) + '\n')
    print('FAT32 host model PASS; no guest or Windows disk accessed.', flush=True)


if __name__ == '__main__':
    main()
