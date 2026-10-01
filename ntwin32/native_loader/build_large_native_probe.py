#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a fixed-input native read-only Chromium structure probe; no VM starts."""
import argparse
import datetime
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import pefile

ROOT = Path(__file__).resolve().parents[2]
HOST = ROOT / 'build/chromium-large-image-budget-controls-20261001T0003-v3/result.json'
HOST_SHA = 'ff1391d152f05ea5ee64b369ddf133f06505f7e48c8f6b7c4ebf596a456d6aa8'
INPUT = ROOT / 'build/chromium-large-image-20260930T2336/input.json'
INPUT_SHA = 'edd54ab0258f6b04b035928fb1527264d68ca0f980a8f35c5efd21d33005cda2'
PROFILE = ROOT / 'benchmarks/win98se-ko-oem-native-exports-v1.json'
PROFILE_SHA = '3854198a9b2bf9f54fe0383330d09ed2ea3d0d510c3d7ba24eb13426e37b4f0d'
CORE_SHA = 'f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158'
FILES = ('ntwin32/native_loader/large_native_probe.c', 'ntwin32/native_loader/large_native_wait.c',
         'ntwin32/native_loader/build_large_native_probe.py', 'ntwin32/native_loader/pe.c',
         'ntwin32/native_loader/pe.h', 'shizukufs/v1/tools/sha256.c', 'shizukufs/v1/tools/sha256.h',
         'platform/freestanding/memory.c', 'platform/freestanding/memory.h')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(1048576), b''):
            h.update(chunk)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or out == ROOT / 'build' or not out.is_relative_to(ROOT / 'build'):
        parser.error('fresh isolated project build output required')
    compiler = shutil.which('i686-w64-mingw32-gcc')
    if not compiler:
        parser.error('existing i486-capable cross compiler required')
    pins = {str(path): pin for path, pin in ((HOST, HOST_SHA), (INPUT, INPUT_SHA), (PROFILE, PROFILE_SHA))}
    if any(sha(Path(name)) != pin for name, pin in pins.items()):
        parser.error('frozen host/input/OEM receipt changed')
    host = json.loads(HOST.read_text())
    original = json.loads(INPUT.read_text())
    core = Path(original['file']).resolve(strict=True)
    if (host['status'] != 'PASS' or host['controls']['checks'] != 55 or
            host['native_executed'] or host['entry_points_called'] or host['runtime_admission_changed'] or
            original['sha256'] != CORE_SHA or original['bytes'] != 283207168 or
            original['entry_points_called'] or original['native_executed'] or
            not core.is_relative_to(ROOT / 'build') or sha(core) != CORE_SHA or
            core.stat().st_size != 283207168):
        parser.error('exact original core and host structural controls required')
    sources = {name: sha(ROOT / name) for name in FILES}
    for name in ('ntwin32/native_loader/pe.c', 'ntwin32/native_loader/pe.h'):
        if host['input_pins'].get(str(ROOT / name)) != sources[name]:
            parser.error('parser differs from tested frozen source')
    pins[str(core)] = CORE_SHA
    pins[str(Path(compiler))] = sha(Path(compiler))
    pins.update({str(ROOT / name): pin for name, pin in sources.items()})
    out.mkdir(parents=True)
    for name, pin in sources.items():
        target = out / 'frozen' / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        if sha(target) != pin:
            raise ValueError('source changed while freezing')
    f = out / 'frozen'
    flags = [compiler, '-std=c11', '-march=i486', '-Os', '-Wall', '-Wextra', '-Werror',
             '-Wno-misleading-indentation', '-fno-builtin', '-fno-stack-protector',
             '-fno-tree-loop-distribute-patterns', '-nostdlib', '-Wl,--entry,_entry@0',
             '-Wl,--no-insert-timestamp', '-Wl,--subsystem,windows:4.10',
             '-Wl,--major-os-version,4', '-Wl,--minor-os-version,0',
             '-Wl,--disable-dynamicbase', '-Wl,--disable-nxcompat', '-Wl,--disable-tsaware']
    commands = [flags + ['-I', str(f / 'shizukufs/v1/tools'),
                str(f / 'ntwin32/native_loader/large_native_probe.c'), str(f / 'ntwin32/native_loader/pe.c'),
                str(f / 'shizukufs/v1/tools/sha256.c'), str(f / 'platform/freestanding/memory.c'),
                '-o', str(out / 'CHRLARGE.EXE'), '-lkernel32', '-lgcc'],
                flags + [str(f / 'ntwin32/native_loader/large_native_wait.c'),
                '-o', str(out / 'CHLWAIT.EXE'), '-lkernel32', '-lgcc']]
    result = {'status': 'FAIL', 'utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'schema': 'win98modern.native-large-readonly-probe-build.v1',
              'input_pins': pins, 'sources': sources, 'commands': commands,
              'native_executed': False, 'entry_points_called': 0,
              'application_functionality_verified': False, 'runtime_admission_changed': False,
              'scope': 'Original Chromium file SHA/EOF, native read-only file mapping, bounded metadata/import-record/TLS-structure/HIGHLOW validation only. No target loading/import resolution/callback execution.',
              'native_effects': 'Private CHRLAB inputs plus fresh CHRLARGE.LOG/CHLWAIT.LOG; no registry/provider/OS file writes. Real child exit observed by300s wait; any guard termination FAIL.'}
    try:
        for i, command in enumerate(commands):
            run = subprocess.run(command, capture_output=True, text=True, timeout=120)
            (out / f'compile-{i}.log').write_text(run.stdout + run.stderr)
            run.check_returncode()
        exports = json.loads(PROFILE.read_text())['dlls']
        artifacts = []
        for name in ('CHRLARGE.EXE', 'CHLWAIT.EXE'):
            path = out / name
            with pefile.PE(str(path)) as pe:
                o = pe.OPTIONAL_HEADER
                if (pe.FILE_HEADER.Machine, o.Magic, o.Subsystem, o.MajorSubsystemVersion,
                        o.MinorSubsystemVersion, o.MajorOperatingSystemVersion,
                        o.MinorOperatingSystemVersion) != (0x14c, 0x10b, 2, 4, 10, 4, 0):
                    raise ValueError('native classic GUI profile mismatch')
                if o.DllCharacteristics or any(o.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)):
                    raise ValueError('unsupported runtime state')
                imports = {}
                for desc in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = desc.dll.decode('ascii').upper()
                    names = [item.name.decode('ascii') if item.name else '#' + str(item.ordinal)
                             for item in desc.imports]
                    if dll != 'KERNEL32.DLL' or set(names) - set(exports[dll]):
                        raise ValueError('exact native OEM import gate failed')
                    imports[dll] = names
            artifacts.append({'source': str(path), 'guest': 'C:\\CHRLAB\\' + name,
                              'sha256': sha(path), 'bytes': path.stat().st_size, 'native_imports': imports})
        if any(sha(Path(name)) != pin for name, pin in pins.items()):
            raise ValueError('held input changed during compile')
        result.update(status='HOST_BUILD_PASS_NATIVE_PENDING', artifacts=artifacts)
    except Exception as error:
        result['error'] = str(error)
    receipt = out / 'result.json'
    receipt.write_text(json.dumps(result, indent=2) + '\n')
    if result['status'] != 'FAIL':
        manifest = {'schema': 1, 'kind': 'isolated-guest-file-inputs', 'staging_prefix': 'CHRLAB',
                    'inputs': [{k: a[k] for k in ('source', 'guest', 'sha256', 'bytes')} for a in result['artifacts']] +
                              [{'source': str(core), 'guest': 'C:\\CHRLAB\\CHROME.DLL',
                                'sha256': CORE_SHA, 'bytes': 283207168}],
                    'outputs': ['C:\\CHRLAB\\CHRLARGE.LOG', 'C:\\CHRLAB\\CHLWAIT.LOG'],
                    'backups': [], 'commands': ['C:\\CHRLAB\\CHLWAIT.EXE'],
                    'source_receipts': [{'path': str(receipt), 'sha256': sha(receipt)},
                                        {'path': str(HOST), 'sha256': HOST_SHA}],
                    'scope': result['scope'], 'requires_exact_large_input_staging_policy': True}
        (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps({'status': result['status'], 'receipt': str(receipt),
                      'sha256': sha(receipt), 'error': result.get('error')}))
    return 1 if result['status'] == 'FAIL' else 0


if __name__ == '__main__':
    raise SystemExit(main())
