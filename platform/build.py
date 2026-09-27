#!/usr/bin/env python3
"""Build original independent components; no package installs or guest changes.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import hashlib
import importlib.util
import json
import os
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / 'build' / 'platform'

def run(*command):
    subprocess.run([str(arg) for arg in command], cwd=ROOT, check=True)

def load_prepare():
    spec = importlib.util.spec_from_file_location('ntw_prepare', ROOT / 'ntwin32/prepare.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    (BUILD / 'manifest.json').unlink(missing_ok=True)
    sources = ['ntwrapper/core.c', 'ntwrapper/include/ntwrapper.h', 'ntwin32/runtime.c',
               'ntwin32/sync.c', 'ntwin32/sync.h', 'ntwin32/resolve.c',
               'ntwin32/resolve.h', 'ntwin32/exports.def',
               'ntwin32/initonce.c', 'ntwin32/initonce.h', 'ntwin32/version.rc',
               'ntwin32/routes.json', 'ntwin32/prepare.py', 'platform/tests/probe.c',
               'platform/build.py']
    def source_hashes():
        return {name: hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in sources}
    before = source_hashes()
    cc = os.environ.get('NTW_CC', 'i686-w64-mingw32-gcc')
    route_names = json.loads((ROOT/'ntwin32/routes.json').read_text())['exports']
    if any(not name.isascii() or not name.isidentifier() for name in route_names):
        raise RuntimeError('Invalid route export identifier')
    (BUILD/'routes.inc').write_text(''.join(
        f'NTW_ROUTE("{name}", Ntw{name})\n' for name in sorted(route_names)))
    flags = ['-std=c11', '-Os', '-Wall', '-Wextra', '-Werror', '-march=i486',
             '-fno-builtin', '-ffreestanding', '-fno-stack-protector', '-nostdlib']
    link = ['-Wl,--subsystem,console:4.10', '-Wl,--disable-dynamicbase',
            '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware', '-Wl,--no-insert-timestamp',
            '-Wl,--major-os-version,4', '-Wl,--minor-os-version,10']
    run(cc, *flags, '-c', 'ntwrapper/core.c', '-o', BUILD / 'ntwrapper9x.o')
    run('i686-w64-mingw32-ar', 'rcsD', BUILD / 'ntwrapper9x.a', BUILD / 'ntwrapper9x.o')
    run('i686-w64-mingw32-windres', '-i', 'ntwin32/version.rc', '-o', BUILD/'version.o', '-O', 'coff')
    run(cc, *flags, *link, '-shared', '-Wl,--entry,_DllMain@12',
        '-Wl,--image-base,0x68000000',
        '-Wl,--subsystem,windows:4.10', '-o', BUILD / 'NTW32.DLL',
        '-I', BUILD, 'ntwin32/runtime.c', 'ntwin32/sync.c', 'ntwin32/resolve.c',
        'ntwin32/initonce.c', 'ntwin32/exports.def', BUILD/'version.o', '-lkernel32')
    run(cc, *flags, *link, '-Wl,--entry,_mainCRTStartup', '-o', BUILD / 'probe-original.exe',
        'platform/tests/probe.c', '-lkernel32')
    prepared, report = load_prepare().prepare((BUILD / 'probe-original.exe').read_bytes())
    (BUILD / 'NTWPROBE.EXE').write_bytes(prepared)
    (BUILD / 'prepare-report.json').write_text(json.dumps(report, indent=2) + '\n')
    manifest = {'product': "Windows 98 Shizuku's Second Edition", 'schema': 'ntw.build.v1',
                'guest_verified': False, 'sources_sha256': before,
                'compiler': subprocess.check_output([cc, '--version'], text=True).splitlines()[0],
                'artifacts': {}}
    for name in ('ntwrapper9x.o', 'ntwrapper9x.a', 'NTW32.DLL', 'NTWPROBE.EXE'):
        artifact = BUILD / name
        manifest['artifacts'][name] = {'sha256': hashlib.sha256(artifact.read_bytes()).hexdigest(),
                                       'bytes': artifact.stat().st_size}
    if source_hashes() != before:
        raise RuntimeError('Sources changed during build; no valid manifest emitted')
    (BUILD / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest['artifacts'], indent=2))

if __name__ == '__main__':
    main()
