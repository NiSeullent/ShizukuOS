#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Record fault-injection tests of the actual TLS engine under sanitizers.

This host receipt validates allocation and publication ownership. Actual Win98
FS-based compiler TLS and native thread behavior need a separate guest receipt.
"""
import argparse
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--compiler', default='clang')
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to(ROOT / 'build') or out == ROOT / 'build':
        parser.error('output must be a new directory under this checkout build/')
    if out.exists():
        parser.error('use a new output directory; existing receipts are immutable')
    compiler = shutil.which(args.compiler)
    if not compiler:
        parser.error('compiler is unavailable')
    compiler = Path(compiler).resolve()
    sources = {name: sha(HERE / name) for name in
               ('tls_runtime.c', 'tls_runtime.h', 'tls_test.c', 'test_tls_runtime.py')}
    out.mkdir(parents=True)
    executable = out / 'tls-runtime-host-test'
    command = [str(compiler), '-std=c11', '-O1', '-g', '-Wall', '-Wextra',
               '-Werror', '-Wno-misleading-indentation', '-fsanitize=address,undefined',
               '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
               str(HERE / 'tls_runtime.c'), str(HERE / 'tls_test.c'),
               '-o', str(executable)]
    receipt = {
        'schema': 1, 'status': 'FAIL', 'native_executed': False,
        'native_win98_abi_verified': False, 'sources': sources,
        'compiler': {'path': str(compiler), 'sha256': sha(compiler)},
        'commands': [command, [str(executable)]],
        'scope': 'Actual portable TLS engine under ASan/UBSan with slot, allocation, '
                 'publication, rollback, thread-ownership and retry fault controls; '
                 'no native Windows or latest application execution claim.'
    }
    try:
        version = subprocess.run([str(compiler), '--version'], check=True,
                                 text=True, capture_output=True, timeout=10)
        receipt['compiler']['version'] = version.stdout.splitlines()[0]
        build = subprocess.run(command, cwd=ROOT, text=True, capture_output=True,
                               timeout=60)
        (out / 'build.log').write_text(build.stdout + build.stderr)
        receipt['build_exit'] = build.returncode
        if build.returncode:
            raise RuntimeError('TLS host test compilation failed; inspect build.log')
        if any(sha(HERE / name) != digest for name, digest in sources.items()):
            raise RuntimeError('source changed during compilation')
        result = subprocess.run([str(executable)], cwd=ROOT, text=True,
                                capture_output=True, timeout=15)
        (out / 'run.log').write_text(result.stdout + result.stderr)
        receipt['test_exit'] = result.returncode
        count = re.fullmatch(r'TLS_RUNTIME_HOST_CHECKS=([1-9][0-9]*)\n'
                             r'NATIVE_WIN98_ABI_VERIFIED=0\n', result.stdout)
        if result.returncode or not count or result.stderr:
            raise RuntimeError('TLS host test failed or sanitizer emitted diagnostics')
        if any(sha(HERE / name) != digest for name, digest in sources.items()):
            raise RuntimeError('source changed during testing')
        receipt.update(status='PASS', checks=int(count[1]), sources_unchanged=True,
                       executable_sha256=sha(executable),
                       build_log_sha256=sha(out / 'build.log'),
                       run_log_sha256=sha(out / 'run.log'))
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        receipt['error'] = str(error)
    path = out / 'host-result.json'
    path.write_text(json.dumps(receipt, indent=2) + '\n')
    print(json.dumps({'status': receipt['status'], 'checks': receipt.get('checks'),
                      'receipt': str(path), 'sha256': sha(path)}))
    return 0 if receipt['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
