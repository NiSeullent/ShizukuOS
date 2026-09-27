#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check the original lab clock arithmetic without starting a guest."""
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BUILD = HERE / 'build'

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    BUILD.mkdir(exist_ok=True)
    receipt = BUILD / 'host-tests.json'
    receipt.unlink(missing_ok=True)
    paths = [HERE / name for name in ('clock.c', 'layout.h', 'test_clock.c', 'test.py')]
    paths.append(HERE.parent / 'uefi32/layout.h')
    before = {str(path.relative_to(ROOT)): digest(path) for path in paths}
    commands, logs = [], []
    flags = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic']
    for name, extra in (('strict', []), ('sanitized',
            ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'])):
        output = BUILD / ('test-clock-' + name)
        command = ['clang', *flags, *extra, str(HERE/'clock.c'),
                   str(HERE/'test_clock.c'), '-o', str(output)]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        result = subprocess.run([str(output)], check=True, capture_output=True,
                                text=True, timeout=60)
        if not result.stdout.startswith('PASS: 100031 '):
            raise RuntimeError('Clock arithmetic test did not report success')
        commands.append(command)
        logs.append(name + '\n' + result.stdout + result.stderr)
    if any(digest(ROOT/name) != expected for name, expected in before.items()):
        raise RuntimeError('Clock test inputs changed during execution')
    log = BUILD / 'host-tests.log'
    log.write_text('\n'.join(logs))
    receipt.write_text(json.dumps({'pass': True, 'cases_per_variant': 100031,
        'variants': ['strict', 'asan_ubsan'], 'sources_sha256': before,
        'commands': commands, 'log_sha256': digest(log),
        'scope': 'lab TSC conversion arithmetic; no timing accuracy or guest claim'}, indent=2)+'\n')
    print(log.read_text(), end='')

if __name__ == '__main__':
    main()
