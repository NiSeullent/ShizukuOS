#!/usr/bin/env python3
"""Run host validation and bind its receipt to exact source/artifact hashes.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / 'build'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

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
    paths = [p for p in HERE.rglob('*') if p.is_file() and
             'build' not in p.relative_to(HERE).parts and
             '__pycache__' not in p.relative_to(HERE).parts]
    paths += [HERE.parent/'core.c', HERE.parent/'include/ntwrapper.h',
              BUILD/'NTWRAP9X.VXD', BUILD/'NTWRAP9X.elf', BUILD/'NTWQUERY.EXE', BUILD/'manifest.json']
    # Build dependencies outside this directory are also live host-test inputs.
    # Pin the complete manifest closure before the child runs and check it again
    # afterwards; a one-time build check cannot detect changes during testing.
    paths = sorted(set(paths + [ROOT/name for name in manifest['sources']]))
    before = {str(p.relative_to(ROOT)): digest(p) for p in paths}
    if before[str(manifest_path.relative_to(ROOT))] != hashlib.sha256(manifest_bytes).hexdigest():
        raise SystemExit('Build manifest changed; rebuild before testing')
    for name, expected in manifest['sources'].items():
        if before[name] != expected:
            raise SystemExit('Build inputs changed; rebuild before testing: '+name)
    if digest(BUILD/'NTWRAP9X.VXD') != manifest['sha256'] or digest(BUILD/'NTWQUERY.EXE') != manifest['probe']['sha256']:
        raise SystemExit('Build artifact hash does not match manifest')
    result = subprocess.run([sys.executable, '-B', '-m', 'unittest', 'discover',
                             '-s', str(HERE/'tests'), '-v'], cwd=ROOT,
                            env=dict(os.environ,NTWV_HOST_TEST_OUT=str(BUILD)),
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(result.stdout, end='')
    (BUILD/'host-tests.log').write_text(result.stdout)
    unchanged = all(p.is_file() and digest(p) == before[str(p.relative_to(ROOT))] for p in paths)
    passed = result.returncode == 0 and unchanged
    report = {
        'schema': 1,
        'passed': passed,
        'inputs_unchanged_during_test': unchanged,
        'artifact_sha256': manifest['sha256'],
        'probe_sha256': manifest['probe']['sha256'],
        'hashes': before,
        'log_sha256': digest(BUILD/'host-tests.log'),
        'statuses': {name: ('passed' if passed else 'failed-or-unverified') for name in
                     ('host_bridge_asan_ubsan', 'i386_control_harness', 'static_le_relocations',
                      'native_contract_constants', 'win32_probe_pe_contract', 'win64_bridge_dioc_asan_ubsan',
                      'strict_object_flag_policy', 'win64_parallel_admission_asan_ubsan_tsan',
                      'win64_epoch_response_pool_validation', 'win64_corrupt_ring_bounded_failure')},
        'win64_bridge_supervisor_run': False,
        'guest_loaded': False,
        'native_vmm_calls_verified': False,
        'win98_probe_executed': False,
        'scope': 'Host ABI/model evidence only; not Windows VMM or loader execution.'
    }
    (BUILD/'host-tests.json').write_text(json.dumps(report, indent=2)+'\n')
    return 0 if passed else 1

if __name__ == '__main__':
    sys.exit(main())
