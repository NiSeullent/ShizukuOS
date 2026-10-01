#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Record actual TLS remote engine fault controls under ASan/UBSan."""
import argparse
import json
import shutil
import subprocess
from pathlib import Path
from test_tls_runtime import sha

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    compiler = shutil.which('clang')
    if not compiler or out.exists() or not out.is_relative_to(ROOT / 'build'):
        parser.error('existing Clang and a new private build/ output are required')
    compiler = Path(compiler).resolve()
    names = ('tls_runtime.c', 'tls_runtime.h', 'tls_remote.c', 'tls_remote.h',
             'tls_remote_test.c', 'test_tls_remote.py', 'test_tls_runtime.py')
    sources = {name: sha(HERE / name) for name in names}
    out.mkdir(parents=True)
    exe = out / 'tls-remote-host-test'
    command = [str(compiler), '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-Wno-misleading-indentation', '-fsanitize=address,undefined',
               '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
               str(HERE / 'tls_runtime.c'), str(HERE / 'tls_remote.c'),
               str(HERE / 'tls_remote_test.c'), '-o', str(exe)]
    receipt = {'status': 'FAIL', 'native_executed': False, 'sources': sources,
               'commands': [command, [str(exe)]],
               'compiler': {'path': str(compiler), 'sha256': sha(compiler)},
               'scope': 'Actual TLS engine remote publication, original-plan preservation, '
                        'atomic-replace rejection and retained rollback ownership; native '
                        'Win98 CAS/TDB lifetime and application behavior require guest proof.'}
    try:
        build = subprocess.run(command, capture_output=True, text=True, cwd=ROOT, timeout=60)
        (out / 'build.log').write_text(build.stdout + build.stderr)
        receipt['build_exit'] = build.returncode
        if build.returncode:
            raise RuntimeError('host compilation failed')
        run = subprocess.run([str(exe)], capture_output=True, text=True, cwd=ROOT, timeout=15)
        (out / 'run.log').write_text(run.stdout + run.stderr)
        receipt['test_exit'] = run.returncode
        lines = run.stdout.splitlines()
        if run.returncode or run.stderr or len(lines) != 2 or not lines[0].startswith('TLS_REMOTE_HOST_CHECKS=') or lines[1] != 'NATIVE_WIN98_REMOTE_ABI_VERIFIED=0':
            raise RuntimeError('actual engine or sanitizer controls failed')
        count = int(lines[0].split('=')[1])
        if count <= 0 or any(sha(HERE / name) != digest for name, digest in sources.items()):
            raise RuntimeError('invalid check count or source changed')
        snapshot = out / 'source'
        snapshot.mkdir()
        for name in names:
            shutil.copyfile(HERE / name, snapshot / name)
            if sha(snapshot / name) != sources[name]:
                raise RuntimeError('frozen source copy differs')
        receipt.update(status='PASS', checks=count, sources_unchanged=True,
                       executable_sha256=sha(exe), run_log_sha256=sha(out / 'run.log'))
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        receipt['error'] = str(error)
    path = out / 'host-result.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'checks': receipt.get('checks'),
                      'receipt': str(path), 'sha256': sha(path)}))
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
