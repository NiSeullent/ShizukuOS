#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check original USB evidence validation and lab-clock arithmetic; no guest."""
import hashlib
import json
from pathlib import Path
import re
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
    clock = HERE.parent / 'uefi_xhci'
    paths = [HERE / name for name in ('layout.h','test.py','test_qemu.py','verify.py','test_verify.py','README.md')]
    paths += [HERE.parent/'uefi_usb'/name for name in ('layout.h','verify.py','test_verify.py')]
    paths += [clock / name for name in ('clock.c','layout.h','test_clock.c','test_qemu.py','test_inventory.py')]
    paths += [HERE.parent / ('uefi32/' + name) for name in ('layout.h','test_qemu.py')]
    before = {str(path.relative_to(ROOT)): digest(path) for path in paths}
    commands, logs = [], []
    flags = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-pedantic']
    for name, extra in (('strict', []), ('sanitized',
            ['-fsanitize=address,undefined', '-fno-sanitize-recover=all'])):
        output = BUILD / ('test-clock-' + name)
        command = ['clang', *flags, *extra, str(clock/'clock.c'),
                   str(clock/'test_clock.c'), '-o', str(output)]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        result = subprocess.run([str(output)], check=True, capture_output=True,
                                text=True, timeout=60)
        if not result.stdout.startswith('PASS: 100031 '):
            raise RuntimeError('Clock arithmetic test did not report success')
        commands.append(command)
        logs.append(name + '\n' + result.stdout + result.stderr)
    inventory = subprocess.run(['python3', '-B', str(clock/'test_inventory.py')], check=True,
                               capture_output=True, text=True, timeout=30)
    logs.append('QMP inventory\n' + inventory.stdout + inventory.stderr)
    verified = subprocess.run(['python3', '-B', str(HERE/'test_verify.py')], check=True,
                              capture_output=True, text=True, timeout=60)
    logs.append('USB physical-evidence verifier\n' + verified.stdout + verified.stderr)
    count = re.search(r'Ran (\d+) tests? in ', verified.stdout + verified.stderr)
    if not count or int(count.group(1)) < 1:
        raise RuntimeError('USB evidence verifier did not report executed tests')
    if any(digest(ROOT/name) != expected for name, expected in before.items()):
        raise RuntimeError('Clock test inputs changed during execution')
    log = BUILD / 'host-tests.log'
    log.write_text('\n'.join(logs))
    receipt.write_text(json.dumps({'pass': True, 'cases_per_variant': 100031,
        'variants': ['strict', 'asan_ubsan'], 'sources_sha256': before,
        'commands': commands, 'log_sha256': digest(log),
        'inventory_tests': 6,
        'usb_evidence_tests': int(count.group(1)),
        'scope': 'USB evidence rejection, lab TSC arithmetic, QMP inventory; no guest claim'}, indent=2)+'\n')
    print(log.read_text(), end='')

if __name__ == '__main__':
    main()
