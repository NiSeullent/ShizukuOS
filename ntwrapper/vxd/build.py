#!/usr/bin/env python3
"""Build original NTWRAP9X.VXD; no installation or guest execution.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
from le import package

HERE = Path(__file__).resolve().parent
BUILD = HERE / 'build'
ROOT = HERE.parents[1]

def run(args):
    subprocess.run([str(x) for x in args], check=True, cwd=HERE)

def main():
    BUILD.mkdir(exist_ok=True)
    compiler = os.environ.get('CLANG', 'clang')
    mingw = os.environ.get('MINGW_CC', 'i686-w64-mingw32-gcc')
    common = ['--target=i386-unknown-none-elf', '-march=i486', '-std=c11', '-Oz',
              '-ffreestanding', '-fno-builtin', '-fno-pic', '-fno-pie',
              '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
              '-mno-sse', '-mno-mmx', '-msoft-float', '-mstack-alignment=4',
              '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-Wconversion', '-Wshadow']
    run(['nasm', '-f', 'elf32', HERE/'control.asm', '-o', BUILD/'control.o'])
    for source, name in ((HERE/'bridge.c','bridge'), (HERE/'native.c','native'), (HERE.parent/'core.c','core')):
        run([compiler, *common, '-c', source, '-o', BUILD/(name+'.o')])
    run(['ld', '-m', 'elf_i386', '-T', HERE/'link.ld', '--emit-relocs', '--no-undefined',
         '-o', BUILD/'NTWRAP9X.elf', *[BUILD/(n+'.o') for n in ('control','bridge','native','core')]])
    binary, info = package((BUILD/'NTWRAP9X.elf').read_bytes())
    (BUILD/'NTWRAP9X.VXD').write_bytes(binary)
    run([mingw, '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror', '-march=i486',
         '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-nostdlib',
         '-Wl,--subsystem,console:4.10', '-Wl,--major-os-version,4', '-Wl,--minor-os-version,10',
         '-Wl,--disable-dynamicbase', '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware',
         '-Wl,--no-insert-timestamp', '-Wl,--entry,_mainCRTStartup',
         HERE/'query_probe.c', '-o', BUILD/'NTWQUERY.EXE', '-lkernel32'])
    info['sha256'] = hashlib.sha256(binary).hexdigest()
    info['bytes'] = len(binary)
    info['tools'] = {tool: subprocess.check_output([tool, '--version'], text=True).splitlines()[0]
                     for tool in (compiler, mingw, 'nasm', 'ld')}
    info['probe'] = {'name': 'NTWQUERY.EXE',
                     'sha256': hashlib.sha256((BUILD/'NTWQUERY.EXE').read_bytes()).hexdigest(),
                     'bytes': (BUILD/'NTWQUERY.EXE').stat().st_size,
                     'guest_executed': False}
    info['sources'] = {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                       for p in (HERE/'control.asm', HERE/'bridge.c', HERE/'bridge.h', HERE/'native.c',
                                 HERE/'link.ld', HERE/'le.py', HERE/'build.py', HERE/'query_probe.c',
                                 HERE.parent/'core.c', HERE.parent/'include/ntwrapper.h')}
    (BUILD/'manifest.json').write_text(json.dumps(info, indent=2)+'\n')
    print(json.dumps(info, indent=2))
    return 0

if __name__ == '__main__':
    sys.exit(main())
