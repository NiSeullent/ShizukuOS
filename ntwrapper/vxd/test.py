#!/usr/bin/env python3
"""Run host validation and bind its receipt to exact source/artifact hashes.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / 'build'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def project_source(name):
    path = (ROOT / name).resolve()
    if not path.is_relative_to(ROOT) or not path.is_file():
        raise SystemExit('Invalid or missing project build input: ' + str(name))
    return path

def dependency_closure(manifest):
    """Ask the actual C/assembly preprocessors for current project dependencies.
    -MM excludes system/toolchain headers; those are outside this receipt's scope.
    No object, executable, or generated dependency file is written here.
    """
    bridge, core, broker = HERE / 'bridge.c', HERE.parent / 'core.c', HERE / 'pma_endpoint.c'
    clang = os.environ.get('CLANG', 'clang')
    mingw = os.environ.get('MINGW_CC', 'i686-w64-mingw32-gcc')
    host = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
            '-Wpedantic', '-Wshadow', '-fno-omit-frame-pointer']
    cases = (
        ('native_i486', clang, manifest['compiler_flags'], [bridge, HERE / 'native.c', broker, core]),
        ('probe_mingw', mingw, ['-std=c11', '-Os', '-Wall', '-Wextra', '-Werror', '-march=i486',
                              '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-nostdlib'],
         [HERE / 'query_probe.c']),
        ('pma_probe_mingw', mingw, ['-std=c11', '-Os', '-Wall', '-Wextra', '-Werror', '-Wpedantic',
                                   '-march=i486', '-mno-sse', '-mno-mmx', '-msoft-float',
                                   '-ffreestanding', '-fno-builtin', '-fno-stack-protector',
                                   '-DWINVER=0x0410', '-D_WIN32_WINNT=0x0400', '-I', str(HERE)],
         [ROOT / 'ntwin32/pma/client.c', ROOT / 'ntwin32/pma/probe.c']),
        ('host_bridge_asan_ubsan', 'clang', [*host, '-Wconversion', '-fsanitize=address,undefined'],
         [bridge, broker, core, HERE / 'tests/test_bridge.c']),
        ('host_w64_asan_ubsan', 'clang', [*host, '-fsanitize=address,undefined'],
         [bridge, broker, core, HERE / 'tests/test_w64vxd.c']),
        ('host_admission_asan_ubsan', 'clang', [*host, '-fsanitize=address,undefined', '-pthread'],
         [bridge, broker, core, HERE / 'tests/test_w64_admission.c']),
        ('host_pma_gcc', 'gcc', host,
         [bridge, broker, core, HERE / 'tests/test_pma_native.c']),
        ('host_pma_asan_ubsan', 'clang', [*host, '-fsanitize=address,undefined'],
         [bridge, broker, core, HERE / 'tests/test_pma_native.c']),
        ('host_native_lifetime_asan_ubsan', 'clang', [*host, '-fsanitize=address,undefined', '-fno-pie'],
         [HERE / 'native.c', HERE / 'tests/test_native_lifetime.c']),
        ('host_admission_tsan', 'clang', [*host, '-fsanitize=thread', '-pthread'],
         [bridge, broker, core, HERE / 'tests/test_w64_admission.c']),
    )
    commands, closure = [], {}

    def scan(label, command):
        commands.append(command)
        result = subprocess.run(command, cwd=ROOT, check=True, capture_output=True, text=True)
        paths = set()
        for line in result.stdout.replace('\\\n', ' ').splitlines():
            if not line.strip():
                continue
            _, separator, dependencies = line.partition(':')
            if not separator:
                raise SystemExit('Malformed compiler dependency output for ' + label)
            for name in shlex.split(dependencies):
                path = (ROOT / name).resolve()
                if path.is_relative_to(ROOT):
                    paths.add(project_source(path))
        closure.setdefault(label, set()).update(paths)

    for label, compiler, flags, sources in cases:
        scan(label, [compiler, *flags, '-MM', '-MT', 'ntwv-inputs', *map(str, sources)])
    for source in (HERE / 'control.asm', HERE / 'vmm_callbacks.asm', HERE / 'tests/control_harness.asm'):
        scan('assembly_i386', ['nasm', '-M', '-MT', 'ntwv-inputs', '-f', 'elf32', str(source)])
    return closure, commands

def changed_inputs(paths, before):
    changed = []
    for path in sorted(paths):
        try:
            same = path.is_file() and digest(path) == before[str(path.relative_to(ROOT))]
        except OSError:
            same = False
        if not same:
            changed.append(str(path.relative_to(ROOT)))
    return changed

def preserve_previous_receipt():
    previous = [BUILD / name for name in ('host-tests.json', 'host-tests.log') if (BUILD / name).is_file()]
    if not previous:
        return None
    history = BUILD / 'host-test-history'
    history.mkdir(exist_ok=True)
    saved = Path(tempfile.mkdtemp(prefix='previous-', dir=history))
    for path in previous:
        shutil.copy2(path, saved / path.name)
    return str(saved.relative_to(ROOT))

def main():
    global BUILD
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,default=BUILD)
    args=parser.parse_args()
    BUILD=args.out.resolve()
    if BUILD!=(HERE/'build').resolve() and (BUILD==(ROOT/'build').resolve() or not BUILD.is_relative_to((ROOT/'build').resolve())):
        parser.error('--out must be the normal build directory or a component directory under project build/')
    manifest_path = BUILD/'manifest.json'
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    paths = {p for p in HERE.rglob('*') if p.is_file() and
             'build' not in p.relative_to(HERE).parts and
             '__pycache__' not in p.relative_to(HERE).parts}
    paths.update(project_source(name) for name in manifest['sources'])
    # Pin the externally located ABI even before preprocessing, so a persistent
    # change during dependency discovery cannot acquire a later initial hash.
    paths.update((HERE.parent/'core.c', HERE.parent/'include/ntwrapper.h',
                  ROOT/'shizukudos/abi/shz_abi.h', ROOT/'shizukudos/abi/shz_ipc.h',
                  BUILD/'NTWRAP9X.VXD', BUILD/'NTWRAP9X.elf', BUILD/'NTWQUERY.EXE', manifest_path))
    if 'pma_probe' in manifest:
        paths.add(BUILD/'PMAQUERY.EXE')
    before = {str(p.relative_to(ROOT)): digest(p) for p in sorted(paths)}
    if before[str(manifest_path.relative_to(ROOT))] != hashlib.sha256(manifest_bytes).hexdigest():
        raise SystemExit('Build manifest changed; rebuild before testing')
    for name, expected in manifest['sources'].items():
        if before[str(project_source(name).relative_to(ROOT))] != expected:
            raise SystemExit('Build inputs changed; rebuild before testing: '+name)
    if digest(BUILD/'NTWRAP9X.VXD') != manifest['sha256'] or digest(BUILD/'NTWQUERY.EXE') != manifest['probe']['sha256']:
        raise SystemExit('Build artifact hash does not match manifest')
    if 'pma_probe' in manifest and digest(BUILD/'PMAQUERY.EXE') != manifest['pma_probe']['sha256']:
        raise SystemExit('PMA probe artifact hash does not match manifest')
    dependencies, dependency_commands = dependency_closure(manifest)
    for dependency_paths in dependencies.values():
        for path in dependency_paths - paths:
            before[str(path.relative_to(ROOT))] = digest(path)
        paths.update(dependency_paths)
    changed = changed_inputs(paths, before)
    if changed:
        raise SystemExit('Build inputs changed during dependency discovery: ' + ', '.join(changed))
    previous_receipt = preserve_previous_receipt()
    result = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover',
                             '-s', str(HERE/'tests'), '-v'], cwd=ROOT,
                            env=dict(os.environ,NTWV_HOST_TEST_OUT=str(BUILD)),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(result.stdout, end='')
    (BUILD/'host-tests.log').write_text(result.stdout)
    changed = changed_inputs(paths, before)
    unchanged = not changed
    passed = result.returncode == 0 and unchanged
    report = {
        'schema': 1,
        'passed': passed,
        'inputs_unchanged_during_test': unchanged,
        'artifact_sha256': manifest['sha256'],
        'probe_sha256': manifest['probe']['sha256'],
        'pma_probe_sha256': manifest.get('pma_probe', {}).get('sha256'),
        'hashes': before,
        'changed_inputs': changed,
        'project_dependencies': {name: sorted(str(p.relative_to(ROOT)) for p in paths)
                                 for name, paths in dependencies.items()},
        'project_dependency_commands': dependency_commands,
        'project_dependency_scope': 'Project files; compiler dependency mode excludes system/toolchain headers.',
        'previous_receipt_directory': previous_receipt,
        'log_sha256': digest(BUILD/'host-tests.log'),
        'statuses': {name: ('passed' if passed else 'failed-or-unverified') for name in
                     ('host_bridge_asan_ubsan', 'i386_control_harness', 'static_le_relocations',
                      'native_contract_constants', 'win32_probe_pe_contract', 'win64_bridge_dioc_asan_ubsan',
                      'strict_object_flag_policy', 'win64_parallel_admission_asan_ubsan_tsan',
                      'win64_epoch_response_pool_validation', 'win64_corrupt_ring_bounded_failure', 'native_pma_broker_actual_rings_gcc_asan_ubsan',
                      'native_pma_service_thunks_static', 'native_image_residency_model')},
        'win64_bridge_supervisor_run': False,
        'guest_loaded': False,
        'native_vmm_calls_verified': False,
        'win98_probe_executed': False,
        'scope': 'Host ABI/model evidence only; not Windows VMM or loader execution.'
    }
    (BUILD/'host-tests.json').write_text(json.dumps(report, indent=2)+'\n')
    if changed:
        print('Input drift during tests: ' + ', '.join(changed))
    return 0 if passed else 1

if __name__ == '__main__':
    sys.exit(main())
