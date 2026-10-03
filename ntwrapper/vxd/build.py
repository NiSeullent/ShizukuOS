#!/usr/bin/env python3
"""Build original NTWRAP9X.VXD; no installation or guest execution.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys
from le import package

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / 'build'

def run(args):
    subprocess.run([str(x) for x in args], check=True, cwd=HERE)

def main():
    global BUILD
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=BUILD,
                        help='Isolated refreshed build directory under project build/')
    args=parser.parse_args()
    BUILD=args.out.resolve()
    if BUILD!=(HERE/'build').resolve() and (BUILD==(ROOT/'build').resolve() or not BUILD.is_relative_to((ROOT/'build').resolve())):
        parser.error('--out must be the normal build directory or a component directory under project build/')
    BUILD.mkdir(parents=True,exist_ok=True)
    source_paths=(HERE/'control.asm',HERE/'vmm_callbacks.asm',HERE/'bridge.c',HERE/'bridge.h',HERE/'native.c',
                  HERE/'pma_endpoint.c',HERE/'pma_endpoint.h',
                  HERE/'link.ld',HERE/'le.py',HERE/'inspect_le.py',HERE/'build.py',HERE/'query_probe.c',
                  ROOT/'ntwin32/pma/client.c',ROOT/'ntwin32/pma/client.h',ROOT/'ntwin32/pma/probe.c',
                  HERE.parent/'core.c',HERE.parent/'include/ntwrapper.h',
                  ROOT/'platform/freestanding/memory.c',ROOT/'platform/freestanding/memory.h',
                  ROOT/'shizukudos/boot_profile/storage/provenance.h',
                  ROOT/'shizukudos/abi/shz_abi.h',ROOT/'shizukudos/abi/shz_clock.h',ROOT/'shizukudos/abi/shz_ipc.h',ROOT/'shizukudos/abi/shz_vmm_pma.h')
    source_hashes={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}
    compiler = os.environ.get('CLANG', 'clang')
    mingw = os.environ.get('MINGW_CC', 'i686-w64-mingw32-gcc')
    # Clang may fold large IOCTL indices into a lookup-table displacement with
    # an ELF addend outside its object (e.g. table - 4 * 0x4e540010). Keep the
    # narrow LE relocation contract by lowering switches to branches instead.
    common = ['--target=i386-unknown-none-elf', '-march=i486', '-std=c11', '-Oz', '-fno-jump-tables',
              '-ffreestanding', '-fno-builtin', '-fno-pic', '-fno-pie',
              '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
              '-mno-sse', '-mno-mmx', '-msoft-float', '-mstack-alignment=4',
              '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-Wconversion', '-Wshadow']
    for source in ('control', 'vmm_callbacks'):
        run(['nasm', '-f', 'elf32', HERE/(source+'.asm'), '-o', BUILD/(source+'.o')])
    # Freestanding aggregate lowering can still emit memory calls. Resolve
    # those with the project's original byte helpers, using the same ABI.
    for source, name in ((HERE/'bridge.c','bridge'), (HERE/'native.c','native'), (HERE/'pma_endpoint.c','pma_endpoint'),
                         (HERE.parent/'core.c','core'), (ROOT/'platform/freestanding/memory.c','memory')):
        run([compiler, *common, '-c', source, '-o', BUILD/(name+'.o')])
    run(['ld', '-m', 'elf_i386', '-T', HERE/'link.ld', '--emit-relocs', '--no-undefined',
         '-o', BUILD/'NTWRAP9X.elf', *[BUILD/(n+'.o') for n in ('control','vmm_callbacks','bridge','native','pma_endpoint','core','memory')]])
    binary, info = package((BUILD/'NTWRAP9X.elf').read_bytes())
    (BUILD/'NTWRAP9X.VXD').write_bytes(binary)
    run([mingw, '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror', '-march=i486',
         '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-nostdlib',
         '-Wl,--subsystem,console:4.10', '-Wl,--major-os-version,4', '-Wl,--minor-os-version,10',
         '-Wl,--disable-dynamicbase', '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware',
         '-Wl,--no-insert-timestamp', '-Wl,--entry,_mainCRTStartup',
         HERE/'query_probe.c', '-o', BUILD/'NTWQUERY.EXE', '-lkernel32'])
    run([mingw, '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-march=i486',
         '-mno-sse', '-mno-mmx', '-msoft-float', '-ffreestanding', '-fno-builtin',
         '-fno-stack-protector', '-fno-unwind-tables', '-fno-asynchronous-unwind-tables',
         '-fno-tree-loop-distribute-patterns', '-DWINVER=0x0410', '-D_WIN32_WINNT=0x0400',
         '-I', HERE, ROOT/'ntwin32/pma/client.c', ROOT/'ntwin32/pma/probe.c', '-nostdlib',
         '-Wl,--entry,_mainCRTStartup', '-Wl,--subsystem,console:4.0',
         '-Wl,--major-os-version,4,--minor-os-version,0,--disable-dynamicbase,--disable-nxcompat,--no-insert-timestamp',
         '-lkernel32', '-o', BUILD/'PMAQUERY.EXE'])
    info['sha256'] = hashlib.sha256(binary).hexdigest()
    info['bytes'] = len(binary)
    info['compiler_flags'] = common
    info['tools'] = {tool: subprocess.check_output([tool, '--version'], text=True).splitlines()[0]
                     for tool in (compiler, mingw, 'nasm', 'ld')}
    info['probe'] = {'name': 'NTWQUERY.EXE',
                     'sha256': hashlib.sha256((BUILD/'NTWQUERY.EXE').read_bytes()).hexdigest(),
                     'bytes': (BUILD/'NTWQUERY.EXE').stat().st_size,
                     'guest_executed': False}
    info['pma_probe'] = {'name': 'PMAQUERY.EXE',
                         'sha256': hashlib.sha256((BUILD/'PMAQUERY.EXE').read_bytes()).hexdigest(),
                         'bytes': (BUILD/'PMAQUERY.EXE').stat().st_size,
                         'guest_executed': False}
    if source_hashes!={str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in source_paths}:
        raise RuntimeError('Build inputs changed while compiling; no manifest written')
    info['sources'] = source_hashes
    info['output_directory'] = str(BUILD.relative_to(ROOT))
    info['status'] = 'HOST-BUILD-PASS'
    info['native_validation'] = 'pending for production driver; control-only fixture success is not production load/VMM/query proof'
    (BUILD/'manifest.json').write_text(json.dumps(info, indent=2)+'\n')
    print(json.dumps(info, indent=2))
    return 0

if __name__ == '__main__':
    sys.exit(main())
