#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build/test original memory helpers; writes only this module's build directory."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent
BUILD = HERE / 'build'
NAMES = ('memset', 'memcpy', 'memmove', 'memcmp')
STRICT = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
          '-Wconversion', '-Wsign-conversion', '-fno-builtin']
FREESTANDING = ['-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                '-fno-pie', '-fno-pic', '-fno-asynchronous-unwind-tables',
                '-march=i486', '-mno-sse', '-mno-sse2', '-mno-mmx', '-msoft-float']


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(command, env=None):
    result = subprocess.run([str(arg) for arg in command], cwd=HERE,
                            capture_output=True, text=True, timeout=60, env=env)
    if result.returncode:
        raise RuntimeError(f'{command[0]} exited {result.returncode}:\n{result.stdout}{result.stderr}')
    return result.stdout


def main():
    for tool in ('gcc', 'clang', 'nm', 'ld'):
        if not shutil.which(tool):
            raise RuntimeError('Existing compiler/tool required: ' + tool)
    BUILD.mkdir(exist_ok=True)
    receipt = BUILD / 'test-result.json'
    receipt.unlink(missing_ok=True)
    sources = {name: digest(HERE / name) for name in ('memory.c','memory.h','test_memory.c','test.py')}
    result = {'source_provenance': 'original project implementation; no external libc source',
              'sources_sha256': sources, 'host': {}, 'i486': {}, 'guest': 'not_run'}
    for compiler, label, extra in (('gcc','gcc',[]),('clang','clang',[]),
                                   ('clang','clang_sanitized',['-fsanitize=address,undefined',
                                                              '-fno-omit-frame-pointer'])):
        obj = BUILD / (label + '-test-memory.o')
        executable = BUILD / (label + '-test')
        rename = ['-D' + name + '=ntwm_test_' + name for name in NAMES]
        run([compiler,*STRICT,*extra,*rename,'-c','memory.c','-o',obj])
        defined = {line.split()[-1] for line in run(['nm','--defined-only',obj]).splitlines()
                   if len(line.split()) >= 3 and line.split()[-2] == 'T'}
        if defined != {'ntwm_test_' + name for name in NAMES}:
            raise RuntimeError('Host test object would interpose libc functions')
        run([compiler,*STRICT,*extra,'test_memory.c',obj,'-o',executable])
        environment = dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                           UBSAN_OPTIONS='halt_on_error=1')
        counts = json.loads(run([executable], environment))
        result['host'][label] = {'compiler': run([compiler,'--version']).splitlines()[0],
                                 'passed': True, **counts}
    # A synthetic caller forces all four standard symbols to be resolved by
    # this support object. It never runs as a host executable.
    probe = BUILD / 'link_probe.c'
    probe.write_text('#include "memory.h"\nvoid *memory_link_probe(void *a,const void *b,size_t n) {\n'
                     ' memset(a,0,n); memcpy(a,b,n); memmove(a,b,n);\n'
                     ' return memcmp(a,b,n) ? a : (void *)b;\n}\n')
    for compiler, target in (('gcc',['-m32']),('clang',['--target=i386-unknown-none-elf'])):
        obj = BUILD / (compiler + '-i486-memory.o')
        call = BUILD / (compiler + '-i486-probe.o')
        linked = BUILD / (compiler + '-i486-linked.o')
        command = [compiler,*STRICT,*FREESTANDING,*target]
        run([*command,'-c','memory.c','-o',obj])
        if run(['nm','-u',obj]).strip():
            raise RuntimeError('Compiler-support object itself has unresolved symbols')
        run([*command,'-I',HERE,'-c',probe,'-o',call])
        run(['ld','-m','elf_i386','-r',call,obj,'-o',linked])
        if run(['nm','-u',linked]).strip():
            raise RuntimeError('i486 compiler-support link left unresolved symbols')
        if obj.read_bytes()[:7] != b'\x7fELF\x01\x01\x01':
            raise RuntimeError('Expected little-endian ELF32 support object')
        result['i486'][compiler] = {'flags': STRICT + FREESTANDING + target,
                                   'memory_object_sha256': digest(obj),
                                   'linked_object_sha256': digest(linked),
                                   'undefined_symbols': [], 'passed': True}
    if any(digest(HERE / name) != expected for name, expected in sources.items()):
        raise RuntimeError('Source changed while validating compiler support')
    result['pass'] = True
    receipt.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
