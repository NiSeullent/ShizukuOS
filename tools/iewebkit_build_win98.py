#!/usr/bin/env python3
"""Build the independent IE host for the pinned Win98 SE / IE5.0 guest.

Creates a new private source snapshot and development bundle; starts no guest
and registers no component. The exact target is experimental and never falls
back to the canonical IE5.5/Windows ME variant.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCES = (
    'AGENTS.md', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'variants.json',
    'include/engine.h', 'host/engine_loader.h', 'host/engine_loader.cpp',
    'host/engine_contract.c', 'host/docobject.cpp', 'host/navigation_bho.cpp',
    'host/navigation_handoff.cpp', 'host/navigation_handoff.h',
    'host/navigation_trace.h', 'test/docobject_lifecycle_test.cpp',
    'test/navigation_handoff_test.cpp', 'test/navigation_values_test.cpp',
)
TARGET = {'os': 'win98se', 'os_version': '4.10.2222', 'ie': '5.0',
          'ie_version': '5.00.2614.3500', 'arch': 'x86', 'mode': 'classic'}
DEFINES = ['-DWINVER=0x0410', '-D_WIN32_WINDOWS=0x0410',
           '-D_WIN32_WINNT=0x0400', '-D_WIN32_IE=0x0500',
           '-DIEWK_TARGET_IE=50', '-DIEWK_TARGET_SECURITY_MODE=0',
           '-DIEWK_HOST_DEVELOPMENT=1']


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def audit(path: Path, baseline: dict) -> dict:
    from app_preflight import analyze
    report = analyze(path)
    absent = [row for row in report['imports']
              if row['symbol'] not in baseline['dlls'].get(row['dll'], [])]
    return {'sha256': report['input']['sha256'], 'size_bytes': report['input']['size_bytes'],
            'pe': report['pe'], 'import_count': len(report['imports']),
            'import_inventory_complete': report['import_inventory_complete'],
            'absent_from_media_export_baseline': absent,
            'static_gate_passed': report['pe']['machine'] == 0x14c and
                report['pe']['format'] == 'PE32' and
                report['pe']['subsystem_version'] <= [4, 10] and
                report['import_inventory_complete'] and not absent,
            'installed_dependency_or_behavior_verified': False}


def build(checkout: Path, output: Path, baseline_path: Path, diagnostic_handoff: bool = False) -> dict:
    checkout = checkout.resolve()
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise ValueError('output already exists; choose a new private directory')
    if output.resolve().is_relative_to(checkout):
        raise ValueError('output must be outside the independent checkout')
    if not (checkout / '.git').exists():
        raise ValueError('an independent IEWebkit git checkout is required')
    # Read all source bytes before compiling; preserve dirty peer changes.
    snapshot = {name: (checkout / name).read_bytes() for name in SOURCES}
    probe = (ROOT / 'tools/iewebkit_target_probe.cpp').read_bytes()
    baseline_bytes = baseline_path.read_bytes()
    baseline = json.loads(baseline_bytes)
    if baseline.get('schema') != 'w98mod.export-manifest.v1':
        raise ValueError('unexpected native export baseline')
    tools = {name: shutil.which('i686-w64-mingw32-' + suffix)
             for name, suffix in [('cc', 'gcc'), ('cxx', 'g++')]}
    if not all(tools.values()):
        raise ValueError('the x86 MinGW GCC/G++ toolchain is required')
    head = subprocess.run(['git', '-C', str(checkout), 'rev-parse', 'HEAD'],
                          check=True, text=True, capture_output=True).stdout.strip()
    output.mkdir(parents=True, mode=0o700)
    source = output / 'source'
    artifacts = output / 'bundle'
    objects = output / 'objects'
    for directory in (source, artifacts, objects):
        directory.mkdir()
    for name, data in snapshot.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    (source / 'test/iewebkit_target_probe.cpp').write_bytes(probe)
    common = ['-Os', '-Wall', '-Wextra', '-Werror', *DEFINES,
              '-I', str(source / 'include'), '-I', str(source / 'host')]
    link = ['-static', '-static-libgcc', '-static-libstdc++',
            '-Wl,--kill-at,--no-insert-timestamp,--major-os-version,4,--minor-os-version,0,'
            '--major-subsystem-version,4,--minor-subsystem-version,0']
    libraries = ['-ladvapi32', '-luser32', '-lole32', '-loleaut32', '-luuid', '-lurlmon']
    commands = []

    def run(command: list[str]) -> None:
        commands.append(command)
        with (output / 'build.log').open('a') as log:
            result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, timeout=120)
        if result.returncode:
            raise ValueError('compile failed; see ' + str(output / 'build.log'))

    for filename, compiler, standard in [('engine_contract.c', 'cc', 'c99'),
                                         ('engine_loader.cpp', 'cxx', 'c++11')]:
        run([tools[compiler], '-std=' + standard, *common, '-c', str(source / 'host' / filename),
             '-o', str(objects / (Path(filename).stem + '.o'))])
    core = [str(objects / 'engine_loader.o'), str(objects / 'engine_contract.o')]
    for name, files, extra in (
        ('iewebkit-host.dll', ['host/docobject.cpp'], ['-shared']),
        ('iewebkit-navigation.dll', ['host/navigation_bho.cpp', 'host/navigation_handoff.cpp'], ['-shared']),
        ('IETARGET.EXE', ['test/iewebkit_target_probe.cpp'], ['-lversion']),
        ('HOSTTEST.EXE', ['test/docobject_lifecycle_test.cpp'], []),
        ('NAVTEST.EXE', ['test/navigation_handoff_test.cpp', 'host/navigation_handoff.cpp'], []),
        ('NAVVALUE.EXE', ['test/navigation_values_test.cpp', 'host/navigation_handoff.cpp'], []),
    ):
        # Link libraries after their callers, including the version probe.
        flags = [item for item in extra if not item.startswith('-l')]
        libs = [item for item in extra if item.startswith('-l')]
        run([tools['cxx'], '-std=c++11', *common, *link, *flags,
             *[str(source / name) for name in files], *core, '-o', str(artifacts / name),
             *libraries, *libs])
    if diagnostic_handoff:
        for name, files in (
            ('IEWKHOST.DLL', ['host/docobject.cpp']),
            ('NAVBHO.DLL', ['host/navigation_bho.cpp', 'host/navigation_handoff.cpp']),
        ):
            run([tools['cxx'], '-std=c++11', *common, '-DIEWK_NAV_DIAGNOSTIC',
                 *link, '-shared', *[str(source / name) for name in files], *core,
                 '-o', str(artifacts / name), *libraries])
    audits = {path.name: audit(path, baseline) for path in sorted(artifacts.iterdir())}
    receipt = {'schema': 'win98modern.iewebkit-build.v1', 'target': TARGET,
        'artifact_kind': 'experimental-native-ie-host', 'canonical_checkout': str(checkout),
        'canonical_head': head, 'canonical_target_declared': False,
        'source_sha256': {name: sha(data) for name, data in snapshot.items()},
        'probe_source_sha256': sha(probe), 'native_export_baseline_sha256': sha(baseline_bytes),
        'compiler_definitions': DEFINES, 'commands': commands, 'artifacts': audits,
        'engine_included': False, 'guest_executed': False, 'rendering_verified': False,
        'diagnostic_handoff_included': diagnostic_handoff,
        'release_eligible': False,
        'static_gate_passed': all(item['static_gate_passed'] for item in audits.values()),
        'blockers': ['No complete adjacent iewebkit-engine.dll is available.',
                     'The exact Win98 SE / IE5.0 target has no native browser evidence.',
                     'POST/header ingress, TLS, history, input and teardown need engine guest tests.']}
    (output / 'build.json').write_text(json.dumps(receipt, indent=2) + '\n')
    # No automatic registration: this batch is for a disposable owned guest.
    (artifacts / 'CHECK.BAT').write_bytes(b'@echo off\r\nIETARGET.EXE 83bd\r\n'
        b'echo Target/provider probe exit code: %errorlevel%\r\n')
    (artifacts / 'README.TXT').write_bytes(
        b'Experimental Windows 98 SE 4.10.2222 / IE 5.00.2614.3500 host.\r\n'
        b'Run CHECK.BAT first in a disposable guest; inspect IETARGET.LOG.\r\n'
        b'Exit 3 means provider absent/incomplete; exit 4 means wrong target.\r\n'
        b'HOSTTEST/NAVTEST/NAVVALUE are COM diagnostics, not WebKit rendering.\r\n'
        b'No engine is included. Do not register this as a working renderer.\r\n')
    return receipt


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--checkout', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--native-exports', type=Path,
                        default=ROOT / 'benchmarks/win98se-ko-oem-native-exports-v1.json')
    parser.add_argument('--diagnostic-handoff', action='store_true',
                        help='Include explicitly named offline BHO/DocObject diagnostics; no renderer')
    args = parser.parse_args(argv)
    try:
        report = build(args.checkout, args.output, args.native_exports, args.diagnostic_handoff)
        print(json.dumps({'output': str(args.output), 'target': TARGET,
                          'static_gate_passed': report['static_gate_passed'],
                          'engine_included': False, 'guest_executed': False}, indent=2))
        return 0 if report['static_gate_passed'] else 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
