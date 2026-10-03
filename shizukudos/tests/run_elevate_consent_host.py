#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise literal elevation entry/UI code, with explicit host boundaries.

Optional baseline must compile and exhibit runtime assertion failures. The same
fixture and current literal consent/secret helpers are used in both cohorts.
No host adapter validates a credential or returns successful authentication.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
APP = ROOT / 'shizukudos/win64/apps/elevate'
FIXTURE = ROOT / 'shizukudos/tests/test_elevate_consent.c'
SHIMS = ROOT / 'shizukudos/tests/host/elevate_consent'


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(arguments):
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL=os.devnull, GIT_OPTIONAL_LOCKS='0')
    return subprocess.check_output(
        ['git', '--no-replace-objects', '-c', 'core.fsmonitor=false', '-C', str(ROOT), *arguments],
        env=env, timeout=30)


def execute(command, log, timeout):
    started = time.monotonic()
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout,
                                env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1'))
        status = result.returncode
        output = (result.stdout + result.stderr).decode(errors='replace')
    except subprocess.TimeoutExpired as error:
        status = 124
        output = ((error.stdout or b'') + (error.stderr or b'')).decode(errors='replace') + '\nTIMEOUT\n'
    log.write_text(output)
    return status, output, time.monotonic() - started


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', type=Path, default=ROOT / 'build/elevate-consent/host')
    parser.add_argument('--baseline-commit', help='full original commit; compile succeeds and runtime controls must fail')
    args = parser.parse_args()
    if args.baseline_commit and not re.fullmatch(r'[0-9a-f]{40}', args.baseline_commit):
        parser.error('--baseline-commit must be a full 40-character lowercase SHA')
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    files = sorted(APP.glob('*.[ch]')) + sorted(SHIMS.glob('*.h')) + [
        FIXTURE, Path(__file__).resolve(), ROOT / 'shizukudos/abi/shz_auth.h',
        ROOT / 'shizukudos/accounts/account.h']
    before = {str(path.relative_to(ROOT)): sha(path) for path in files}
    cohorts = [('fixed', APP, 0)]
    baseline = {}
    if args.baseline_commit:
        identity = git(['rev-parse', '--verify', args.baseline_commit + '^{commit}']).decode().strip()
        if identity != args.baseline_commit:
            raise RuntimeError('baseline identity changed')
        baseline_root = out / 'baseline-source'
        for rel in ['shizukudos/win64/apps/elevate/' + name for name in
                    ['main.c', 'prompt.c', 'prompt.h', 'secret.h']] + [
                        'shizukudos/abi/shz_auth.h', 'shizukudos/accounts/account.h']:
            path = baseline_root / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(git(['show', args.baseline_commit + ':' + rel]))
            baseline[rel] = sha(path)
        cohorts.insert(0, ('baseline', baseline_root / 'shizukudos/win64/apps/elevate', 2))
    results = []
    for cohort, source, expected in cohorts:
        for compiler in ['gcc', 'clang']:
            stem = cohort + '-' + compiler
            exe = out / stem
            flags = ['-std=c11', '-O1', '-g', '-fshort-wchar', '-Wall', '-Wextra', '-Werror']
            if compiler == 'clang':
                flags += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
            command = [compiler, *flags, '-I', str(SHIMS),
                       '-DSHZ_ELEVATE_MAIN_SOURCE="' + str(source / 'main.c') + '"',
                       '-DSHZ_ELEVATE_PROMPT_SOURCE="' + str(source / 'prompt.c') + '"',
                       str(FIXTURE), str(APP / 'secret.c'), str(APP / 'consent.c'), '-o', str(exe)]
            status, _, elapsed = execute(command, out / (stem + '-compile.log'), 60)
            item = {'cohort': cohort, 'compiler': compiler, 'compile_exit': status,
                    'compile_seconds': elapsed, 'command': command, 'expected_runtime_exit': expected}
            if status:
                item['pass'] = False
            else:
                status, output, elapsed = execute([str(exe)], out / (stem + '-run.log'), 30)
                match = re.search(r'elevation consent: (\d+) controls, (\d+) failures;', output)
                item.update(run_exit=status, runtime_seconds=elapsed, binary_sha256=sha(exe))
                if match:
                    item.update(controls=int(match[1]), failed_controls=int(match[2]))
                item['pass'] = status == expected and match is not None and (
                    int(match[2]) > 0 if expected else int(match[2]) == 0)
            results.append(item)
            print(stem, 'PASS' if item['pass'] else 'FAIL', item.get('controls'),
                  item.get('failed_controls'), flush=True)
    after = {str(path.relative_to(ROOT)): sha(path) for path in files}
    baseline_after = {rel: sha(out / 'baseline-source' / rel) for rel in baseline}
    receipt = {'source_sha256': before, 'source_stable': before == after,
               'baseline_commit': args.baseline_commit, 'baseline_source_sha256': baseline,
               'baseline_stable': baseline == baseline_after, 'results': results,
               'scope': 'literal production main/prompt/consent/secret C bodies; modeled USER/GDI/event and ASCII conversion adapters; IPC always ACCESS_DENIED; no credential verification, native Win98 GUI or VM execution'}
    (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    raise SystemExit(not all(item['pass'] for item in results) or before != after or baseline != baseline_after)


if __name__ == '__main__':
    main()
