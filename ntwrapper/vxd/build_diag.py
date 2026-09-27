#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a separate original VxD diagnostic; never rewrite the driver/probe."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / 'build' / 'diag'
VXD = HERE / 'build' / 'NTWRAP9X.VXD'
VXD_SHA256 = 'aff7acf54cd0323fe4dce9aab7d93da16df7b8cf345220ee9d2dafa95b0bc537'
VXD_BYTES = 9390
SOURCES = ('ntwrapper/vxd/diag_probe.c', 'ntwrapper/vxd/build_diag.py',
           'ntwrapper/vxd/test_diag.py', 'ntwrapper/vxd/diag_test.c',
           'ntwrapper/vxd/diag_mock.h', 'ntwrapper/vxd/DIAGNOSTIC.md',
           'ntwrapper/vxd/bridge.h', 'ntwrapper/include/ntwrapper.h', 'ntwin32/prepare.py')
PRESERVED = ('ntwrapper/vxd/query_probe.c', 'ntwrapper/vxd/build.py',
             'ntwrapper/vxd/build/NTWRAP9X.VXD', 'ntwrapper/vxd/build/NTWQUERY.EXE',
             'ntwrapper/vxd/build/manifest.json')
IMPORTS = set('CloseHandle CreateFileA DeviceIoControl ExitProcess FlushFileBuffers '
              'GetFileSize GetLastError GetVersionExA ReadFile WriteFile'.split())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(names):
    return {name: sha(ROOT / name) for name in names}


def expected_header():
    data = VXD.read_bytes()
    if len(data) != VXD_BYTES or hashlib.sha256(data).hexdigest() != VXD_SHA256:
        raise RuntimeError('Frozen diagnostic input VxD differs; do not rebuild/replace it implicitly')
    if data[:2] != b'MZ' or data[0x80:0x82] != b'LE':
        raise RuntimeError('Unexpected diagnostic fixture format')
    BUILD.mkdir(parents=True, exist_ok=True)
    path = BUILD / 'diag_expected.h'
    lines = ['/* Generated solely from this project\'s frozen original VxD. */',
             '#ifndef NTWVDIAG_EXPECTED_H', '#define NTWVDIAG_EXPECTED_H',
             f'#define NTWVDIAG_EXPECTED_SHA256 "{VXD_SHA256}"',
             'static const unsigned char ntwdiag_expected[] = {']
    for start in range(0, len(data), 16):
        lines.append('    ' + ','.join(f'0x{byte:02x}' for byte in data[start:start+16]) + ',')
    lines += ['};', '_Static_assert(sizeof(ntwdiag_expected) >= 260 && '
              'sizeof(ntwdiag_expected) <= 65536, "bounded whole-file preflight");', '#endif', '']
    path.write_text('\n'.join(lines))
    return path


def main():
    before, preserved = capture(SOURCES), capture(PRESERVED)
    header = expected_header()
    receipt = BUILD / 'build-result.json'
    receipt.unlink(missing_ok=True)
    target, temporary = BUILD / 'NTWVDIAG.EXE', BUILD / 'NTWVDIAG.EXE.tmp'
    command = ['i686-w64-mingw32-gcc', '-std=c11', '-Os', '-Wall', '-Wextra', '-Werror',
               '-march=i486', '-mno-sse', '-mno-sse2', '-mno-mmx', '-msoft-float',
               '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mno-stack-arg-probe',
               '-fno-ident', '-fno-asynchronous-unwind-tables', '-nostdlib',
               '-Wl,--subsystem,console:4.10', '-Wl,--major-os-version,4',
               '-Wl,--minor-os-version,10', '-Wl,--disable-dynamicbase',
               '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware', '-Wl,--no-insert-timestamp',
               '-Wl,--entry,_mainCRTStartup', '-Wl,--strip-all', '-I', str(BUILD),
               str(HERE / 'diag_probe.c'), '-lkernel32', '-o', str(temporary)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=60)
    log = BUILD / 'build.log'
    log.write_text(' '.join(command) + '\n' + result.stdout + result.stderr)
    if result.returncode or result.stderr:
        raise RuntimeError(f'Diagnostic compile failed or emitted diagnostics: {log}')
    spec = importlib.util.spec_from_file_location('ntw_diag_pe', ROOT / 'ntwin32/prepare.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    pe = module.PE(temporary.read_bytes())
    if (pe.u16(pe.opt + 68) != 3 or (pe.u16(pe.opt + 48), pe.u16(pe.opt + 50)) != (4, 10)
            or (pe.u16(pe.opt + 40), pe.u16(pe.opt + 42)) != (4, 10)
            or pe.u16(pe.pe + 22) & 0x2000 or pe.u16(pe.opt + 70) & 0xc140
            or not pe.u32(pe.opt + 16)):
        raise RuntimeError('Diagnostic must be an executable PE32 console 4.10 image')
    pe.offset(pe.u32(pe.opt + 16))
    for index in (0, 4, 9, 10, 13, 14):
        if any(pe.directory(index)):
            raise RuntimeError('Unexpected export/security/TLS/load-config/delay/CLR directory')
    imports = {}
    for entry in pe.imports():
        names = [item[1] for item in entry['entries']]
        dll = entry['dll'].upper()
        if dll != 'KERNEL32.DLL' or not set(names).issubset(IMPORTS):
            raise RuntimeError('Non-classic or unexpected diagnostic import')
        imports.setdefault(dll, []).extend(names)
    if set(imports) != {'KERNEL32.DLL'} or set(imports['KERNEL32.DLL']) != IMPORTS:
        raise RuntimeError('Missing required diagnostic imports')
    if capture(SOURCES) != before or capture(PRESERVED) != preserved:
        raise RuntimeError('Sources or frozen driver/probe changed during build')
    temporary.replace(target)
    record = {'schema': 'ntw.vxd.diagnostic.build.v1', 'passed': True,
              'artifact': target.name, 'sha256': sha(target), 'bytes': target.stat().st_size,
              'expected_vxd_sha256': VXD_SHA256, 'expected_vxd_bytes': VXD_BYTES,
              'generated_header_sha256': sha(header), 'sources_sha256': before,
              'preserved_inputs_sha256': preserved, 'build_log_sha256': sha(log),
              'imports': {'KERNEL32.DLL': sorted(imports['KERNEL32.DLL'])},
              'machine': 'i386/i486', 'subsystem': 'console 4.10', 'crt_linked': False,
              'kernelex_linked': False, 'guest_executed': False,
              'compiler': subprocess.check_output([command[0], '--version'], text=True,
                                                  timeout=10).splitlines()[0]}
    receipt.write_text(json.dumps(record, indent=2) + '\n')
    return record


if __name__ == '__main__':
    print(json.dumps(main(), indent=2))
