#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify production shell theme records, I/O failures, sanitizers and AMD64 compilation."""
import argparse
import hashlib
import json
import subprocess
import tempfile
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-dir', type=Path)
    parser.add_argument('--runtime-root', type=Path, default=Path(__file__).resolve().parents[3],
                        help='Root of the source checkout containing Win64 include/ and crt/.')
    args = parser.parse_args()
    out = args.build_dir or Path(tempfile.mkdtemp(prefix='shzdesk-theme-'))
    out.mkdir(parents=True, exist_ok=True)
    test = Path(__file__).with_suffix('.c')
    shell = test.parent.parent / 'apps' / 'shzdesk'
    runtime = args.runtime_root / 'shizukudos' / 'win64'
    results = {}
    flags = ['-std=c11', '-Wall', '-Wextra', '-Werror']
    for cc, extra, name in [('gcc', ['-O2'], 'host'),
                            ('clang', ['-O1', '-g', '-fsanitize=address,undefined',
                                       '-fno-sanitize-recover=all'], 'sanitized')]:
        exe = out / name
        subprocess.run([cc, *flags, *extra, str(test), '-o', str(exe)], check=True, timeout=60)
        run = subprocess.run([str(exe)], capture_output=True, text=True, timeout=60)
        if run.returncode:
            raise SystemExit(run.stdout + run.stderr)
        print(name + ': ' + run.stdout.strip())
        results[name] = {'status': 'PASS', 'output': run.stdout.strip()}
    obj = out / 'shzdesk-theme.o'
    subprocess.run(['x86_64-w64-mingw32-gcc', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-ffreestanding', '-fno-builtin', '-fno-stack-protector', '-mno-red-zone',
                    '-fno-ident', '-fno-tree-loop-distribute-patterns', '-Wno-unused-function',
                    '-Wno-unused-parameter', '-Wno-cast-function-type',
                    '-I', str(runtime / 'include'), '-I', str(runtime / 'crt'),
                    '-c', str(shell / 'main.c'), '-o', str(obj)], check=True, timeout=60)
    sources = [shell / 'main.c', shell / 'theme.h', test, Path(__file__)]
    results.update({'amd64_shell_compile': 'PASS', 'native_windows98_acceptance': False,
                    'system_wide_theme_acceptance': False, 'cold_boot_theme_persistence_acceptance': False,
                    'sources': {str(path.relative_to(test.parent.parent.parent.parent)):
                                hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
                    'object_sha256': hashlib.sha256(obj.read_bytes()).hexdigest()})
    (out / 'result.json').write_text(json.dumps(results, indent=2) + '\n')
    print('AMD64 shell compilation: PASS; native Windows98/system-wide/cold-boot acceptance remains unverified')
    print('Isolated outputs:', out)


if __name__ == '__main__':
    main()
