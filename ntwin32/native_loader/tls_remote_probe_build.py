#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the native existing-worker TLS proof; never execute a Windows target."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
import pefile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / 'build'):
        parser.error('use a new private directory under build/')
    cc = shutil.which('i686-w64-mingw32-gcc')
    clang = shutil.which('clang')
    if not cc or not clang:
        parser.error('existing MinGW GCC and Clang compilers are required')
    names = ('tls_remote_probe.c', 'tls_remote.c', 'tls_remote.h', 'tls_runtime.c',
             'tls_runtime.h', 'tls_compiler_fixture.c', 'tls_remote_probe_build.py')
    sources = {str((HERE / name).relative_to(ROOT)): sha(HERE / name) for name in names}
    out.mkdir(parents=True)
    obj, exe = out / 'compiler.obj', out / 'NTWLATE.EXE'
    commands = [
        [clang, '--no-default-config', '--target=i686-pc-windows-msvc', '-march=i486',
         '-O2', '-fno-stack-protector', '-c', str(HERE / 'tls_compiler_fixture.c'), '-o', str(obj)],
        [cc, '-std=c11', '-march=i486', '-Os', '-Wall', '-Wextra', '-Werror',
         '-Wno-misleading-indentation', '-fno-builtin', '-fno-tree-loop-distribute-patterns',
         '-fno-stack-protector', '-nostdlib', '-Wl,--entry,_entry@0',
         '-Wl,--subsystem,windows:4.10', '-Wl,--disable-dynamicbase', '-Wl,--disable-nxcompat',
         '-Wl,--disable-tsaware', '-Wl,--no-insert-timestamp', '-Wl,--defsym,__tls_array=0x2c',
         '-o', str(exe), str(HERE / 'tls_remote_probe.c'), str(HERE / 'tls_runtime.c'),
         str(HERE / 'tls_remote.c'), str(obj), '-lkernel32', '-lgcc']]
    receipt = {'status': 'FAIL', 'native_executed': False, 'sources': sources,
               'commands': commands, 'compilers': {p: sha(Path(p)) for p in (cc, clang)},
               'scope': 'Compiled native ABI and original OEM import gate only; actual '
                        'existing-worker compiler TLS/CAS/TDB lifetime proof pending private Win98 trial.'}
    try:
        with (out / 'build.log').open('w') as log:
            for command in commands:
                subprocess.run(command, check=True, stdout=log, stderr=log, cwd=ROOT, timeout=120)
        native = json.loads((ROOT / 'benchmarks/win98se-ko-oem-native-exports-v1.json').read_text())['dlls']
        imports, operands = {}, []
        with pefile.PE(str(exe)) as pe:
            opt = pe.OPTIONAL_HEADER
            if (pe.FILE_HEADER.Machine, opt.Magic, opt.MajorSubsystemVersion,
                opt.MinorSubsystemVersion) != (0x14c, 0x10b, 4, 10) or pe.is_dll():
                raise ValueError('native Win98 architecture/subsystem gate failed')
            if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)):
                raise ValueError('proof must have no automatic TLS, loadconfig, delay or CLR directory')
            relocations = {e.rva for block in pe.DIRECTORY_ENTRY_BASERELOC for e in block.entries if e.type}
            for section in pe.sections:
                if not section.Characteristics & 0x20000000:
                    continue
                data = section.get_data()
                for opcode in (b'\x64\x8b\x0d\x2c\0\0\0', b'\x64\x8b\x15\x2c\0\0\0'):
                    start = 0
                    while (at := data.find(opcode, start)) >= 0:
                        operand = section.VirtualAddress + at + 3
                        if operand in relocations:
                            raise ValueError('absolute FS TLS operand was incorrectly relocated')
                        operands.append(operand)
                        start = at + 1
            if len(operands) != 2:
                raise ValueError('actual compiler read/write FS:0x2c accesses missing')
            for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
                dll = descriptor.dll.decode().upper()
                if dll != 'KERNEL32.DLL':
                    raise ValueError('proof cannot import compatibility providers')
                entries = []
                for entry in descriptor.imports:
                    if not entry.name or entry.name.decode() not in native[dll]:
                        raise ValueError('import outside original OEM export inventory')
                    entries.append(entry.name.decode())
                imports[dll] = sorted(entries)
        if any(sha(ROOT / name) != digest for name, digest in sources.items()):
            raise ValueError('source changed during proof build')
        snapshot = out / 'source'
        snapshot.mkdir()
        for name in names:
            shutil.copyfile(HERE / name, snapshot / name)
            if sha(snapshot / name) != sources[str((HERE / name).relative_to(ROOT))]:
                raise ValueError('frozen source copy differs')
        receipt.update(status='PASS', sources_unchanged=True,
                       artifact={'path': str(exe), 'bytes': exe.stat().st_size,
                                 'sha256': sha(exe), 'imports': imports,
                                 'automatic_tls_directory': False,
                                 'real_ms_abi_compiler_fs_2c_operands': operands,
                                 'oem_import_gate': 'PASS'})
    except (OSError, ValueError, subprocess.SubprocessError, pefile.PEFormatError) as error:
        receipt['error'] = str(error)
    path = out / 'build-result.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'receipt': str(path), 'sha256': sha(path),
                      'native_executed': False, 'error': receipt.get('error')}))
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
