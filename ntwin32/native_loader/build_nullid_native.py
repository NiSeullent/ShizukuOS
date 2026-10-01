#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build the owned mapped-TLS NULL thread-ID fixture and native OS exit observer."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import datetime
import pefile

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / 'build'):
        parser.error('new private build directory required')
    compiler = shutil.which('i686-w64-mingw32-gcc')
    clang = shutil.which('clang')
    if not compiler or not clang:
        parser.error('existing native and MS-ABI compilers required')
    names = ('native.c', 'pe.c', 'pe.h', 'tls_runtime.c', 'tls_runtime.h',
             'tls_compiler_fixture.c', 'tls_fixture.c', 'tls_nullid_fixture.c',
             'nullid_native_wait.c', 'fixture.def', 'build_nullid_native.py')
    source_paths = [HERE / name for name in names]
    inventory = ROOT / 'benchmarks/win98se-ko-oem-native-exports-v1.json'
    source_paths.append(inventory)
    pins = {str(p.relative_to(ROOT)): sha(p) for p in source_paths}
    out.mkdir(parents=True)
    frozen = out / 'frozen'
    for path in source_paths:
        target = frozen / path.relative_to(ROOT)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
        if sha(target) != pins[str(path.relative_to(ROOT))]:
            raise RuntimeError('source changed during freezing')
    source = frozen / HERE.relative_to(ROOT)
    flags = [compiler, '-std=c11', '-march=i486', '-Os', '-Wall', '-Wextra', '-Werror',
             '-Wno-misleading-indentation', '-fno-builtin', '-fno-tree-loop-distribute-patterns',
             '-fno-stack-protector', '-ffunction-sections', '-fdata-sections', '-nostdlib',
             '-Wl,--gc-sections', '-Wl,--subsystem,windows:4.10', '-Wl,--major-os-version,4',
             '-Wl,--minor-os-version,0', '-Wl,--major-image-version,4', '-Wl,--minor-image-version,10',
             '-Wl,--disable-dynamicbase', '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware',
             '-Wl,--no-insert-timestamp', '-Xlinker', '--stack', '-Xlinker', '4194304,65536']
    commands = [
        [clang, '--no-default-config', '--target=i686-pc-windows-msvc', '-march=i486', '-O2',
         '-fno-stack-protector', '-c', str(source / 'tls_compiler_fixture.c'), '-o', str(out / 'compiler.obj')],
        flags + ['-Wl,--entry,_entry@0', '-o', str(out / 'NTWNULL.EXE'),
                 str(source / 'native.c'), str(source / 'pe.c'), str(source / 'tls_runtime.c'), '-lkernel32', '-lgcc'],
        flags + ['-shared', '-Wl,--entry,_DllMain@12', '-Wl,--undefined,__tls_used',
                 '-Wl,--defsym,__tls_array=0x2c', '-o', str(out / 'TLSNULL.DLL'),
                 str(source / 'tls_nullid_fixture.c'), str(out / 'compiler.obj'),
                 str(source / 'fixture.def'), '-lkernel32'],
        flags + ['-Wl,--entry,_entry@0', '-o', str(out / 'PENWAIT.EXE'),
                 str(source / 'nullid_native_wait.c'), '-lkernel32'],
    ]
    receipt = {'status': 'FAIL', 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'sources': pins, 'compiler': {'path': compiler, 'sha256': sha(compiler)},
               'ms_abi_compiler': {'path': clang, 'sha256': sha(clang)}, 'commands': commands,
               'native_executed': False, 'application_success': False,
               'scope': 'Owned closed mapped TLS graph with caller NULL thread-ID and real native child OS exit. '
                        'Does not admit latest applications, widen execution gates, or establish the original NULL failure cause.'}
    with (out / 'build.log').open('w') as log:
        for command in commands:
            result = subprocess.run(command, cwd=ROOT, stdout=log, stderr=log, timeout=120)
            if result.returncode:
                receipt['compile_exit'] = result.returncode
                (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
                return result.returncode
    available = json.loads((frozen / inventory.relative_to(ROOT)).read_text())['dlls']
    available = {name.upper(): set(symbols) for name, symbols in available.items()}
    artifacts = []
    for name in ('NTWNULL.EXE', 'TLSNULL.DLL', 'PENWAIT.EXE'):
        path = out / name
        with pefile.PE(str(path)) as pe:
            opt = pe.OPTIONAL_HEADER
            if (pe.FILE_HEADER.Machine, opt.Magic, opt.Subsystem, opt.MajorSubsystemVersion,
                    opt.MinorSubsystemVersion) != (0x14c, 0x10b, 2, 4, 10):
                raise RuntimeError('classic GUI4.10 native profile required')
            if opt.DllCharacteristics & 0x140 or pe.is_dll() != name.endswith('.DLL'):
                raise RuntimeError('native image flags differ')
            if any(opt.DATA_DIRECTORY[i].VirtualAddress for i in (10, 13, 14)):
                raise RuntimeError('unexpected runtime directory')
            if bool(opt.DATA_DIRECTORY[9].VirtualAddress) != (name == 'TLSNULL.DLL'):
                raise RuntimeError('actual own fixture TLS only')
            imports = {}
            for descriptor in getattr(pe, 'DIRECTORY_ENTRY_IMPORT', ()):
                dll = descriptor.dll.decode('ascii').upper()
                symbols = []
                for entry in descriptor.imports:
                    if not entry.name or entry.name.decode('ascii') not in available.get(dll, set()):
                        raise RuntimeError('outside actual OEM native exports')
                    symbols.append(entry.name.decode('ascii'))
                imports[dll] = sorted(symbols)
            if set(imports) != {'KERNEL32.DLL'}:
                raise RuntimeError('native Kernel32-only fixture required')
            exports = [x.name.decode('ascii') for x in getattr(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', None), 'symbols', ()) if x.name]
            if set(exports) != ({'NtwPeFixture'} if name == 'TLSNULL.DLL' else set()):
                raise RuntimeError('exact own fixture export ABI required')
            artifact = {'path': str(path), 'bytes': path.stat().st_size, 'sha256': sha(path),
                        'imports': imports, 'exports': exports, 'native_import_gate': 'PASS'}
            if name == 'TLSNULL.DLL':
                operands = []
                for section in pe.sections:
                    if not section.Characteristics & 0x20000000:
                        continue
                    code = section.get_data()
                    for offset in range(len(code) - 5):
                        if code[offset:offset + 2] == b'\x64\xa1' and int.from_bytes(code[offset + 2:offset + 6], 'little') == 0x2c:
                            operands.append(section.VirtualAddress + offset + 2)
                        if offset + 7 <= len(code) and code[offset:offset + 2] == b'\x64\x8b' and code[offset + 2] & 0xc7 == 5 and int.from_bytes(code[offset + 3:offset + 7], 'little') == 0x2c:
                            operands.append(section.VirtualAddress + offset + 3)
                relocations = {entry.rva for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', ()) for entry in block.entries if entry.type}
                if len(operands) != 2 or any(address in relocations for address in operands) or opt.DATA_DIRECTORY[9].Size != 24:
                    raise RuntimeError('actual MS-ABI FS2c and TLS directory proof differs')
                artifact['actual_ms_abi_fs_operands'] = operands
        artifacts.append(artifact)
    if any(sha(ROOT / name) != pin for name, pin in pins.items()):
        raise RuntimeError('source changed during isolated build')
    receipt.update(status='HOST_BUILD_PASS_NATIVE_PENDING', compile_exit=0, artifacts=artifacts)
    result_path = out / 'result.json'
    result_path.write_text(json.dumps(receipt, indent=2) + '\n')
    manifest = {'schema': 1, 'kind': 'isolated-guest-file-inputs',
                'inputs': [{'source': item['path'], 'guest': 'C:\\VXDLAB\\' + Path(item['path']).name,
                            'bytes': item['bytes'], 'sha256': item['sha256']} for item in artifacts],
                'outputs': ['C:\\VXDLAB\\PENULL.LOG', 'C:\\VXDLAB\\PENWAIT.LOG'], 'backups': [],
                'source_receipts': [{'path': str(result_path), 'sha256': sha(result_path)}],
                'command': 'C:\\VXDLAB\\PENWAIT.EXE', 'scope': receipt['scope']}
    manifest_path = out / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'producer_sha256': sha(result_path),
                      'manifest': str(manifest_path), 'manifest_sha256': sha(manifest_path)}))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
