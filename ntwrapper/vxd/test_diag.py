#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded original host API fault model and separate diagnostic PE build.

Writes only ntwrapper/vxd/build/diag/. No guest, media, driver rewrite or network.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
import build_diag

HERE = Path(__file__).resolve().parent
BUILD = build_diag.BUILD


def main():
    before = build_diag.capture(build_diag.SOURCES)
    preserved = build_diag.capture(build_diag.PRESERVED)
    BUILD.mkdir(parents=True, exist_ok=True)
    receipt = BUILD / 'test-result.json'
    receipt.unlink(missing_ok=True)
    build = build_diag.main()
    results = []
    common = ['-std=c11', '-Wall', '-Wextra', '-Werror', '-Wpedantic', '-Wconversion',
              '-Wshadow', '-DNTWVDIAG_HOST_TEST', '-I', str(BUILD), '-I', str(HERE),
              str(HERE / 'diag_probe.c'), str(HERE / 'diag_test.c')]
    for label, compiler, flags in (
            ('gcc', 'gcc', ['-O2']), ('clang', 'clang', ['-O2']),
            ('sanitized', 'clang', ['-O1', '-g', '-fno-omit-frame-pointer',
                                   '-fsanitize=address,undefined', '-fno-sanitize-recover=all'])):
        artifact = BUILD / ('host-' + label)
        command = [compiler, *common, *flags, '-o', str(artifact)]
        compiled = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (BUILD / f'{label}-compile.log').write_text(' '.join(command) + '\n' + compiled.stdout + compiled.stderr)
        if compiled.returncode or compiled.stderr:
            raise RuntimeError(f'{label} compilation failed: {compiled.stderr}')
        environment = dict(os.environ, ASAN_OPTIONS='abort_on_error=1:detect_leaks=1',
                           UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
        executed = subprocess.run([str(artifact)], capture_output=True, text=True, env=environment, timeout=60)
        log = BUILD / f'{label}-run.log'
        log.write_text(executed.stdout + executed.stderr)
        if executed.returncode or executed.stderr:
            raise RuntimeError(f'{label} model failed: {log}\n{executed.stdout}{executed.stderr}')
        counters = json.loads(executed.stdout)
        if not isinstance(counters, dict) or not counters.get('assertions') or not counters.get('scenarios'):
            raise RuntimeError('Model did not report meaningful coverage')
        results.append({'variant': label, 'counters': counters, 'binary_sha256': build_diag.sha(artifact),
                        'log_sha256': build_diag.sha(log), 'compiler': subprocess.check_output(
                            [compiler, '--version'], text=True, timeout=10).splitlines()[0]})
    if build_diag.capture(build_diag.SOURCES) != before or build_diag.capture(build_diag.PRESERVED) != preserved:
        raise RuntimeError('Diagnostic sources or preserved driver artifacts changed during tests')
    record = {'schema': 'ntw.vxd.diagnostic.tests.v1', 'passed': True, 'variants': results,
              'sources_sha256': before, 'preserved_inputs_sha256': preserved,
              'build_receipt_sha256': build_diag.sha(BUILD / 'build-result.json'),
              'diagnostic_sha256': build['sha256'], 'guest_executed': False}
    receipt.write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
