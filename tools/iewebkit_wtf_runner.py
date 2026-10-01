#!/usr/bin/env python3
"""Build/freeze an external Win98 WTF exit observer; never starts a guest."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import shutil
import signal
import subprocess
import time

from iewebkit_build_win98 import audit

HERE = Path(__file__).resolve().parent
FLOOR = 20 * 1024**3
ALLOWANCE = 8 * 1024**2


def compiler_limits():
    resource.setrlimit(resource.RLIMIT_CPU, (45, 45))
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024**2, 2 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build(baseline, output):
    if output.exists() or output.is_symlink():
        raise FileExistsError('Preserve previous build')
    source = HERE / 'iewebkit_wtf_runner.c'
    source_sha, baseline_sha = digest(source), digest(baseline)
    compiler = shutil.which('i686-w64-mingw32-gcc')
    if not compiler:
        raise ValueError('The installed x86 MinGW compiler is required')
    ancestor = output.absolute().parent
    while not ancestor.exists():
        ancestor = ancestor.parent
    if shutil.disk_usage(ancestor).free < FLOOR + 256 * 1024**2 + ALLOWANCE:
        raise ValueError('Preserve the 20 GiB reserve plus bounded observer output and margin')
    output.mkdir(parents=True)
    frozen_source = output / source.name
    frozen_source.write_bytes(source.read_bytes())
    temporary = output / 'tmp'
    temporary.mkdir()
    binary = output / 'WTFWAIT.EXE'
    argv = [compiler, '-pipe', '-std=c99', '-Wall', '-Wextra', '-Werror', '-Os', '-g0',
            '-static', '-static-libgcc', '-DWINVER=0x0410', '-D_WIN32_WINDOWS=0x0410',
            '-D_WIN32_WINNT=0x0400', '-Wl,--subsystem,windows:4.0',
            '-Wl,--no-insert-timestamp,--major-os-version,4,--minor-os-version,0',
            str(frozen_source), '-o', str(binary)]
    child = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             env=dict(os.environ, TMPDIR=str(temporary.resolve())),
                             start_new_session=True, preexec_fn=compiler_limits)
    minimum_free = shutil.disk_usage(output).free
    started = time.monotonic()
    failure = None
    while True:
        free = shutil.disk_usage(output).free
        minimum_free = min(minimum_free, free)
        size = sum(p.stat().st_size for p in output.rglob('*') if p.is_file())
        if free < FLOOR or size > ALLOWANCE or time.monotonic() - started > 90:
            failure = 'Owned observer compiler stopped at its reserve/output/time bound'
            os.killpg(child.pid, signal.SIGTERM)
            try:
                log, _ = child.communicate(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                log, _ = child.communicate()
            break
        try:
            log, _ = child.communicate(timeout=.1)
            break
        except subprocess.TimeoutExpired:
            continue
    (output / 'build.log').write_bytes(log[-1024**2:])
    receipt = {'schema': 'iewebkit-win98-wtf-owned-exit-observer-v1',
        'source': {'path': str(source), 'sha256': source_sha},
        'baseline': {'path': str(baseline.resolve()), 'sha256': baseline_sha},
        'compiler_argv': argv, 'compile_returncode': child.returncode,
        'resource_guard': {'minimum_free_bytes': minimum_free, 'reserve_bytes': FLOOR,
                           'output_limit_bytes': ALLOWANCE, 'cpu_limit_seconds': 45,
                           'file_limit_bytes': 2 * 1024**2, 'core_dumps_disabled': True},
        'closed_handle_checkpoints': True,
        'guest_execution': 'NOT-VERIFIED', 'rendering_verified': False}
    if failure:
        receipt['failure'] = failure
    if not child.returncode and not failure:
        receipt['binary'] = audit(binary, json.loads(baseline.read_text()))
    (output / 'WTFWAIT.receipt.json').write_text(json.dumps(receipt, indent=2) + '\n')
    if (child.returncode or failure or not receipt['binary']['static_gate_passed']
            or digest(source) != source_sha or digest(frozen_source) != source_sha
            or digest(baseline) != baseline_sha
            or shutil.disk_usage(output).free < FLOOR
            or sum(p.stat().st_size for p in output.rglob('*') if p.is_file()) > ALLOWANCE):
        raise ValueError('Observer compile/import/source gate failed; retained build evidence')
    return {'binary': str(binary.resolve()), 'sha256': digest(binary),
            'receipt': str((output / 'WTFWAIT.receipt.json').resolve())}


def freeze(manifest_path, observer, output):
    if output.exists():
        raise FileExistsError('Preserve prior frozen fixture')
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    if (len(manifest['inputs']) != 1
            or manifest['inputs'][0]['guest'] != r'C:\GOPLAB\WTFNAT.EXE'
            or manifest['outputs'] not in ([r'C:\GOPLAB\WTFNAT.LOG'],
                                          [r'C:\GOPLAB\WTFNAT.LOG', r'C:\GOPLAB\WTFABRT.LOG'])):
        raise ValueError('Require a WTF-only parent fixture')
    receipt_path = observer / 'WTFWAIT.receipt.json'
    receipt = json.loads(receipt_path.read_text())
    binary = observer / 'WTFWAIT.EXE'
    if (receipt['schema'] != 'iewebkit-win98-wtf-owned-exit-observer-v1'
            or not receipt['binary']['static_gate_passed']
            or digest(binary) != receipt['binary']['sha256']
            or digest(Path(receipt['source']['path'])) != receipt['source']['sha256']):
        raise ValueError('Observer binary/source gate failed')
    origins = []
    output.mkdir(parents=True)
    (output / 'receipts').mkdir()
    for item in manifest['inputs']:
        original = Path(item['source'])
        if digest(original) != item['sha256']:
            raise ValueError('Parent input changed')
        copy = output / original.name
        subprocess.run(['cp', '--reflink=always', '--sparse=auto', str(original), str(copy)], check=True)
        if copy.stat().st_ino == original.stat().st_ino or digest(copy) != item['sha256']:
            raise ValueError('Require exact distinct private COW input')
        origins.append({'origin': str(original), 'frozen': str(copy.resolve()), 'sha256': item['sha256']})
        item['source'] = str(copy.resolve())
    for item in manifest['source_receipts']:
        original = Path(item['path'])
        if digest(original) != item['sha256']:
            raise ValueError('Parent receipt changed')
        copy = output / 'receipts' / original.name
        copy.write_bytes(original.read_bytes())
        if digest(copy) != item['sha256']:
            raise ValueError('Receipt copy changed')
        item['path'] = str(copy.resolve())
        origins.append({'origin': str(original), 'frozen': str(copy.resolve()), 'sha256': item['sha256']})
    observer_copy = output / binary.name
    observer_copy.write_bytes(binary.read_bytes())
    if digest(observer_copy) != receipt['binary']['sha256']:
        raise ValueError('Observer copy changed')
    manifest['inputs'].append({'source': str(observer_copy.resolve()), 'guest': r'C:\GOPLAB\WTFWAIT.EXE',
        'bytes': observer_copy.stat().st_size, 'sha256': digest(observer_copy)})
    origins.append({'origin': str(binary.resolve()), 'frozen': str(observer_copy.resolve()), 'sha256': digest(observer_copy)})
    for original in (receipt_path, Path(receipt['source']['path']), manifest_path):
        copy = output / 'receipts' / original.name
        if copy.exists():
            raise ValueError('Ambiguous frozen receipt basename')
        copy.write_bytes(original.read_bytes())
        manifest['source_receipts'].append({'path': str(copy.resolve()), 'sha256': digest(copy)})
        origins.append({'origin': str(original.resolve()), 'frozen': str(copy.resolve()), 'sha256': digest(copy)})
    manifest['source_receipt_origins'] = origins
    manifest['outputs'].append(r'C:\GOPLAB\WTFEXIT.LOG')
    manifest['command'] = r'C:\GOPLAB\WTFWAIT.EXE ' + manifest['nonce']
    manifest['post_crt_exit_required'] = True
    manifest['parent_fixture_sha256'] = hashlib.sha256(manifest_raw).hexdigest()
    destination = output / 'guest-files.json'
    destination.write_text(json.dumps(manifest, indent=2) + '\n')
    return {'manifest': str(destination.resolve()), 'sha256': digest(destination),
            'nonce': manifest['nonce'], 'command': manifest['command']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action', required=True)
    b = sub.add_parser('build')
    b.add_argument('--baseline', type=Path, required=True)
    b.add_argument('--output', type=Path, required=True)
    f = sub.add_parser('freeze')
    f.add_argument('--manifest', type=Path, required=True)
    f.add_argument('--observer', type=Path, required=True)
    f.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = build(args.baseline, args.output) if args.action == 'build' else freeze(args.manifest, args.observer, args.output)
    print(json.dumps(result))


if __name__ == '__main__':
    main()
