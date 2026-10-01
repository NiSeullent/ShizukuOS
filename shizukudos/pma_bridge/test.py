#!/usr/bin/env python3
"""Validate the actual freestanding PMA event service, with sanitizer and ABI builds.
SPDX-License-Identifier: GPL-2.0-only
"""
from pathlib import Path
import argparse
from datetime import datetime, timezone
import hashlib
import json
import subprocess

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, default=ROOT / 'build/pma-bridge')
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to((ROOT / 'build').resolve()):
        parser.error('--out must be inside the worktree build/ directory')
    out.mkdir(parents=True, exist_ok=True)
    tracked = [ROOT / 'shizukudos/abi/shz_abi.h', ROOT / 'shizukudos/abi/shz_ipc.h',
               ROOT / 'shizukudos/abi/shz_vmm_pma.h', HERE / 'service.h',
               HERE / 'tests/test_service.c', HERE / 'test.py', HERE / 'README.md']
    def hashes():
        return {str(path.relative_to(ROOT)): hashlib.sha256(path.read_bytes()).hexdigest()
                for path in tracked if path.is_file()}
    before = hashes()
    report = {'schema': 1, 'passed': False, 'started_utc': datetime.now(timezone.utc).isoformat(),
              'source_sha256': before, 'commands': [], 'tests': [],
              'scope': 'Host service and freestanding layouts; actual Windows VMM and hardware integration pending.'}
    receipt = out / 'result.json'
    receipt.write_text(json.dumps(report, indent=2) + '\n')
    def run(command):
        entry = {'argv': list(map(str, command))}
        report['commands'].append(entry)
        result = subprocess.run(entry['argv'], text=True, capture_output=True, timeout=120)
        entry.update({'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
        if result.returncode:
            print(result.stdout + result.stderr, end='')
            raise RuntimeError('command failed: ' + entry['argv'][0])
        return result.stdout
    flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-Wshadow']
    try:
        for compiler, extra in [('gcc', []), ('clang', ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
            run([compiler, '--version'])
            binary = out / ('service-' + compiler)
            run([compiler, *flags, *extra, str(HERE / 'tests/test_service.c'), '-o', str(binary)])
            result = run([binary])
            print(compiler + ': ' + result.strip())
            report['tests'].append({'compiler': compiler, 'result': result.strip()})
        source = out / 'layout.c'
        source.write_text('#include "' + str(HERE / 'service.h') + '"\n'
                          'int layout(void) { return sizeof(shz_pma_request_t) == 64 && sizeof(shz_pma_completion_t) == 64; }\n')
        for target in ['i486-unknown-none-elf', 'x86_64-unknown-none-elf']:
            run(['clang', '-target', target, '-ffreestanding', '-fno-builtin', '-std=c11', '-Wall', '-Wextra', '-Werror',
                 '-c', source, '-o', out / (target + '.o')])
            print(target + ': freestanding layout PASS')
        after = hashes()
        report['source_sha256_after'] = after
        report['inputs_unchanged_during_test'] = before == after
        if before != after:
            raise RuntimeError('source inputs changed during testing')
        report['artifact_sha256'] = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                                   for path in out.iterdir() if path.is_file() and path.suffix != '.json'}
        report['passed'] = True
    except Exception as error:
        report['error'] = str(error)
        raise
    finally:
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        receipt.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
