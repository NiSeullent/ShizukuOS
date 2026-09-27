#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build and inspect original NTWRUN.EXE; never execute a Windows binary/VM.

Writes platform/win98lab/build/native_runner/ by default. MinGW supplies
interface declarations/import thunks only. No CRT or external implementation
is linked. Host construction/import checks are not native Windows evidence.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / 'build' / 'native_runner'
SOURCES = ('platform/win98lab/native_runner.c', 'platform/win98lab/build_native.py',
           'ntwin32/prepare.py')
ALLOWED = set('CloseHandle CreateFileA CreateProcessA ExitProcess FlushFileBuffers '
              'GetExitCodeProcess GetFileAttributesA GetLastError GetModuleFileNameA '
              'GetVersionExA TerminateProcess WaitForSingleObject WriteFile'.split())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(output_dir=BUILD):
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    receipt = output_dir / 'build-result.json'
    receipt.unlink(missing_ok=True)
    before = {name: sha(ROOT / name) for name in SOURCES}
    artifact = output_dir / 'NTWRUN.EXE'
    temporary = output_dir / 'NTWRUN.EXE.tmp'
    command = ['i686-w64-mingw32-gcc', '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror',
               '-march=i486', '-mno-sse', '-mno-sse2', '-mno-mmx', '-msoft-float',
               '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mno-stack-arg-probe',
               '-fno-ident', '-fno-asynchronous-unwind-tables', '-nostdlib',
               '-Wl,--subsystem,console:4.10', '-Wl,--major-os-version,4',
               '-Wl,--minor-os-version,10', '-Wl,--disable-dynamicbase',
               '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware', '-Wl,--no-insert-timestamp',
               '-Wl,--entry,_mainCRTStartup', '-Wl,--strip-all', str(HERE / 'native_runner.c'),
               '-lkernel32', '-o', str(temporary)]
    result = subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
    spec = importlib.util.spec_from_file_location('ntw_runner_pe', ROOT / 'ntwin32/prepare.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pe = module.PE(temporary.read_bytes())
    if (pe.u16(pe.opt + 68) != 3 or (pe.u16(pe.opt + 48), pe.u16(pe.opt + 50)) != (4, 10)
            or (pe.u16(pe.opt + 40), pe.u16(pe.opt + 42)) != (4, 10)
            or pe.u16(pe.pe + 22) & 0x2000 or pe.u16(pe.opt + 70) & 0xc140
            or not pe.u32(pe.opt + 16)):
        raise RuntimeError('Runner must be an executable PE32 console image for Windows 4.10')
    pe.offset(pe.u32(pe.opt + 16))
    for index in (0, 4, 9, 10, 13, 14):
        if any(pe.directory(index)):
            raise RuntimeError('Unexpected export/security/TLS/load-config/delay/CLR directory')
    imports = {}
    for descriptor in pe.imports():
        dll = descriptor['dll'].upper()
        names = [entry[1] for entry in descriptor['entries']]
        if dll != 'KERNEL32.DLL' or not set(names).issubset(ALLOWED):
            raise RuntimeError('Non-classic/CRT import in native supervisor')
        imports.setdefault(dll, []).extend(names)
    if set(imports) != {'KERNEL32.DLL'} or set(imports['KERNEL32.DLL']) != ALLOWED:
        raise RuntimeError('Missing required native supervisor imports')
    imports['KERNEL32.DLL'].sort()
    if any(sha(ROOT / name) != digest for name, digest in before.items()):
        raise RuntimeError('Build sources changed')
    temporary.replace(artifact)
    log = output_dir / 'build.log'
    log.write_text(' '.join(command) + '\n' + result.stdout + result.stderr)
    record = {'schema': 'ntw.native_runner.build.v1', 'passed': True,
              'artifact': artifact.name, 'sha256': sha(artifact), 'bytes': artifact.stat().st_size,
              'machine': 'i386', 'cpu_flags': 'i486, no SSE/MMX, soft-float',
              'subsystem': 'console 4.10', 'imports': imports, 'sources_sha256': before,
              'build_log_sha256': sha(log), 'crt_linked': False, 'kernelex_linked': False,
              'native_win98': 'not_tested', 'guest_executed': False,
              'compiler': subprocess.check_output([command[0], '--version'], text=True,
                                                  timeout=10).splitlines()[0]}
    receipt.write_text(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=BUILD)
    arguments = parser.parse_args()
    print(json.dumps(build(arguments.output), indent=2))
