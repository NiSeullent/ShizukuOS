#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Execute complete production registry, authority and object-manager bodies."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = ROOT / 'shizukudos/tests/test_registry_accounts.c'
CASES = ('own', 'cross', 'create', 'machine', 'legacy', 'integrity',
         'unbound', 'notify', 'thread', 'stale_notify', 'activation', 'provision', 'path')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--cases', nargs='+', choices=CASES, default=list(CASES))
    parser.add_argument('--compiler', choices=('gcc', 'clang', 'all'), default='all')
    parser.add_argument('--production-at', help='full commit SHA for immutable RED production sources')
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error('fresh output directory required')
    if args.production_at and not re.fullmatch(r'[0-9a-f]{40}', args.production_at):
        parser.error('--production-at requires a full lowercase commit SHA')
    harness = (FIXTURE, Path(__file__).resolve())
    pending = [*harness, ROOT / 'shizukudos/kernel64/sysk32_sec.c']
    pending += [ROOT / 'shizukudos/accounts' / name for name in ('account.c', 'kdf.c', 'sha256.c')]
    data = {}
    while pending:
        source = pending.pop().resolve()
        relative = source.relative_to(ROOT)
        if relative in data:
            continue
        if args.production_at and source not in harness:
            captured = subprocess.run(['git', 'show', args.production_at + ':' + str(relative)],
                                      cwd=ROOT, capture_output=True, check=True, timeout=30).stdout
        else:
            captured = source.read_bytes()
        data[relative] = captured
        pending.extend(source.parent / name.decode() for name in
                       re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"', captured, re.M))
    token_source = data[Path('shizukudos/kernel64/sysk32_sec.c')].decode()
    token_bodies = 'typedef struct shz_token_info {' + token_source.split(
        'typedef struct shz_token_info {', 1)[1].split('static int32_t sys_token(', 1)[0]
    snapshot = out / 'source'
    for relative, captured in data.items():
        target = snapshot / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(captured)
    unit = snapshot / FIXTURE.relative_to(ROOT)
    unit.write_text(data[FIXTURE.relative_to(ROOT)].decode().replace(
        '/* @PRODUCTION_TOKEN_BINDING@ */', token_bodies))
    results = []
    binaries = []
    compilers = ('gcc', 'clang') if args.compiler == 'all' else (args.compiler,)
    # Compile both before expensive real KDF enrollment, so a fixture warning is
    # discovered without repeating enrollment for every isolated test case.
    for compiler in compilers:
        flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                 '-Wno-unused-function', '-pthread', '-ffunction-sections', '-fdata-sections']
        if compiler == 'clang':
            flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                      '-fno-omit-frame-pointer']
        executable = out / (compiler + '-registry')
        command = [compiler, *flags, str(unit)]
        command += [str(snapshot / 'shizukudos/accounts' / name)
                    for name in ('account.c', 'kdf.c', 'sha256.c')]
        command += ['-Wl,--gc-sections', '-o', str(executable)]
        run = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out / (compiler + '-compile.log')).write_text(run.stdout + run.stderr)
        results.append({'compiler': compiler, 'phase': 'compile',
                        'exit': run.returncode, 'command': command})
        if run.returncode:
            print(run.stdout + run.stderr, flush=True)
        else:
            binaries.append((compiler, executable))
    for compiler, executable in binaries:
        command = [str(executable), *args.cases]
        try:
            run = subprocess.run(command, capture_output=True, text=True, timeout=180,
                                 env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1'))
        except subprocess.TimeoutExpired as error:
            def decode(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            (out / (compiler + '-run.log')).write_text(
                decode(error.stdout) + decode(error.stderr) + '\nTIMEOUT\n')
            results.append({'compiler': compiler, 'phase': 'run', 'exit': 124})
            continue
        (out / (compiler + '-run.log')).write_text(run.stdout + run.stderr)
        case_exits = {name: int(code) for name, code in
                      re.findall(r'^CASE (\w+) EXIT (\d+)$', run.stdout, re.M)}
        results.append({'compiler': compiler, 'phase': 'run', 'exit': run.returncode,
                        'command': command, 'case_exits': case_exits,
                        'all_cases_reported': set(case_exits) == set(args.cases),
                        'binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest()})
        print(compiler, run.returncode, run.stdout + run.stderr, flush=True)
    stable = all((ROOT / relative).read_bytes() == captured
                 for relative, captured in data.items()
                 if not args.production_at or ROOT / relative in harness)
    passed = (stable and len(binaries) == len(compilers)
              and all(not row['exit'] and row.get('all_cases_reported', True) for row in results))
    receipt = {'passed': passed, 'production_at': args.production_at,
               'source_stable': stable,
               'source_sha256': {str(relative): hashlib.sha256(captured).hexdigest()
                                 for relative, captured in data.items()},
               'generated_fixture_sha256': hashlib.sha256(unit.read_bytes()).hexdigest(),
               'results': results,
               'scope': 'complete production registry/sysreg/authority/object bodies and exact primary-token bodies; '
                        'hardware/user-memory/loader adapters; transferred handles use actual handle-manager primitives; '
                        'real enrollment once then fork isolated cases; volatile heap; '
                        'no native Windows98 boot or persisted hive evidence'}
    (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
