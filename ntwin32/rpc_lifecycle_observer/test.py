#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Actual portable C profile/DR/lifetime controls, normal and ASan/UBSan."""
import argparse
import hashlib
import json
import shutil
import subprocess
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--build', type=Path, required=True); ap.add_argument('--out', type=Path, required=True)
    a = ap.parse_args(); build = a.build.resolve(); out = a.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / 'build'): ap.error('fresh private host directory required')
    result_path = build / 'build-result.json'; receipt = json.loads(result_path.read_text())
    if receipt['status'] != 'PASS' or receipt['native_executed']: ap.error('unexecuted frozen build required')
    for path, p in receipt['sources_and_immutable_inputs'].items():
        if sha(Path(path)) != p['sha256']: ap.error('current source/input changed since build: ' + path)
    for name, p in receipt['frozen_sources'].items():
        if sha(build / 'source' / name) != p['sha256']: ap.error('frozen source changed: ' + name)
    own = build / 'source' / HERE.name; env = build / 'source/native_environment/environment.c'
    rpc = Path(receipt['profiles']['original_rpc']['path']); fixture = build / 'RPFIX.DLL'
    for p, digest in ((rpc, receipt['profiles']['original_rpc']['sha256']), (fixture, receipt['profiles']['owned_fixture']['sha256'])):
        if sha(p) != digest: ap.error('profile binary changed')
    cc = shutil.which('clang')
    if not cc: ap.error('existing clang required')
    before = {str(p): sha(p) for p in (Path(cc).resolve(), result_path, rpc, fixture, *own.glob('*'), env)}
    out.mkdir(parents=True); runs = []; commands = []
    try:
        for mode in ('normal', 'sanitized'):
            exe = out / ('host-' + mode); cmd = [cc, '--no-default-config', '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wno-misleading-indentation']
            if mode == 'sanitized': cmd += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            cmd += [str(own / 'observer.c'), str(own / 'host_test.c'), str(env), '-o', str(exe)]; commands.append(cmd)
            r = subprocess.run(cmd, capture_output=True, timeout=120); (out / (mode + '-compile.log')).write_bytes(r.stdout + r.stderr); r.check_returncode()
            run = subprocess.run([str(exe), str(rpc), str(fixture)], capture_output=True, timeout=120)
            (out / (mode + '-run.log')).write_bytes(run.stdout + run.stderr); run.check_returncode()
            runs.append({'mode': mode, 'stdout': run.stdout.decode(), 'exit_code': run.returncode, 'binary_sha256': sha(exe)})
        if any(sha(Path(p)) != digest for p, digest in before.items()): raise ValueError('host inputs changed')
        result = {'schema': 1, 'status': 'PASS', 'native_executed': False, 'application_success': False,
                  'build_result': {'path': str(result_path), 'sha256': sha(result_path)}, 'inputs': before, 'commands': commands, 'runs': runs,
                  'scope': 'Actual portable profile/parser/relocation/context/coverage/lifetime C controls only; Win98 DR/RF and genuine module/debug-event proof pending'}
        (out / 'host-result.json').write_text(json.dumps(result, indent=2) + '\n'); print(json.dumps({'status': 'PASS', 'receipt': str(out / 'host-result.json'), 'sha256': sha(out / 'host-result.json'), 'runs': runs}))
    except Exception as e:
        (out / 'host-result.json').write_text(json.dumps({'status': 'FAIL', 'error': str(e), 'inputs': before, 'commands': commands, 'runs': runs, 'native_executed': False}, indent=2) + '\n'); raise
if __name__ == '__main__': main()
