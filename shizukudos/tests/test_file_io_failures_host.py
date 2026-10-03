#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Kernel64 file I/O failure-path regression: real fs.c/sysfile.c/sysk32_auth.c/objects.c bodies, explicit host adapters.

Each scenario runs as its own bounded process (a non-terminating baseline becomes TIMEOUT, not a hung runner).
Built with Clang ASan/UBSan and GCC UBSan (trap mode; --gcc-asan where GCC's runtimes exist). Host component evidence only: no guest, VM or native Windows98 run.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_suffix('.c')
NOTIFY = Path(__file__).with_name('test_file_io_failures_notify.c')
SCENARIOS = ('ram_valid', 'ram_limit_edge', 'ram_position_max', 'create_truncate', 'read_failure')
BASELINE_FILES = ('fs.c', 'sysfile.c')


def definition(data, name):
    match = re.search(r'^[^\n;{}]*\b' + name + r'\([^;{}]*\)\s*\{', data, re.M)
    if not match:
        raise ValueError('production function missing: ' + name)
    depth = 1
    for end in range(match.end(), len(data)):
        depth += (data[end] == '{') - (data[end] == '}')
        if not depth:
            return data[match.start():end + 1]
    raise ValueError('unterminated production function: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path, help='fresh output directory (must not exist)')
    parser.add_argument('--baseline', help='Git revision supplying fs.c and sysfile.c (RED reproduction)')
    parser.add_argument('--timeout', type=float, default=20.0, help='seconds per scenario process')
    parser.add_argument('--gcc-asan', action='store_true', help='GCC with ASan/UBSan runtimes (when installed)')
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists():
        parser.error('fresh output directory required: ' + str(out))
    out.mkdir(parents=True)
    pending = [FIXTURE, NOTIFY, Path(__file__).resolve()] + [ROOT / 'shizukudos/kernel64' / name for name in
                                                            ('objects.c', 'auth_core.c')]
    sources = {}
    while pending:
        path = pending.pop().resolve()
        rel = path.relative_to(ROOT)
        if rel in sources:
            continue
        data = path.read_bytes()
        sources[rel] = data
        pending.extend(path.parent / name.decode() for name in
                       re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"', data, re.M))
    original = dict(sources)
    baseline = None
    if args.baseline:
        baseline = subprocess.run(['git', 'rev-parse', args.baseline + '^{commit}'], cwd=ROOT, capture_output=True,
                                  text=True, check=True, timeout=10).stdout.strip()
        for name in BASELINE_FILES:
            sources[Path('shizukudos/kernel64') / name] = subprocess.run(
                ['git', 'show', baseline + ':shizukudos/kernel64/' + name], cwd=ROOT, capture_output=True,
                check=True, timeout=10).stdout
    snap = out / 'source'
    for rel, data in sources.items():
        path = snap / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    fixture = sources[FIXTURE.relative_to(ROOT)].decode()
    objects = sources[Path('shizukudos/kernel64/objects.c')].decode()
    funcs = '\n'.join(definition(objects, n) for n in
                      ('ob_create', 'ob_ref', 'ob_deref', 'handle_insert', 'handle_lookup', 'handle_ref', 'handle_close'))
    # Declarations for unavailable services, not replacement behavior.
    decls = 'void reg_key_object_free(kobject_t *);\nvoid ipc_object_free(kobject_t *);\nvoid ipc_handle_closed(process_t *,kobject_t *);\n'
    fixture = fixture.replace('/* @PRODUCTION_OBJECT_FUNCTIONS@ */', decls + funcs)
    unit = snap / FIXTURE.relative_to(ROOT)
    unit.write_text(fixture)
    results = []
    for compiler in ('gcc', 'clang'):
        cc = shutil.which(compiler)
        if not cc:
            raise RuntimeError('required compiler missing: ' + compiler)
        version = subprocess.run([cc, '--version'], capture_output=True, text=True, timeout=10).stdout.splitlines()[0]
        exe = out / (compiler + '-file-io-failures')
        flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-ffunction-sections', '-fdata-sections',
                 '-fno-omit-frame-pointer']
        if compiler == 'gcc' and not args.gcc_asan:
            # This host's GCC libasan/libubsan runtimes are absent: UBSan in trap mode needs no runtime.
            flags += ['-fsanitize=undefined', '-fsanitize-trap=all', '-fstack-protector-strong']
        else:
            flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all']
        cmd = [cc, *flags, str(unit), str(snap / NOTIFY.relative_to(ROOT)),
               str(snap / 'shizukudos/kernel64/auth_core.c'), '-Wl,--gc-sections', '-o', str(exe)]
        built = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        (out / (compiler + '-compile.log')).write_text(' '.join(cmd) + '\n' + built.stdout + built.stderr)
        row = {'compiler': compiler, 'version': version, 'command': cmd, 'compile_exit': built.returncode,
               'sanitizers': 'asan+ubsan' if '-fsanitize=address,undefined' in flags else 'ubsan-trap+stack-protector',
               'scenarios': {}}
        if built.returncode:
            print(built.stderr)
        else:
            row['binary_sha256'] = hashlib.sha256(exe.read_bytes()).hexdigest()
            for name in SCENARIOS:
                start = time.monotonic()
                try:
                    ran = subprocess.run([str(exe), name], capture_output=True, text=True, timeout=args.timeout,
                                         env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1',
                                                  UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=1'))
                    text, code = ran.stdout + ran.stderr, ran.returncode
                    verdict = 'PASS' if code == 0 else 'FAIL'
                except subprocess.TimeoutExpired as exc:
                    text = (exc.stdout or b'').decode(errors='replace') if isinstance(exc.stdout, bytes) else (exc.stdout or '')
                    text += '\nTIMEOUT after %.1fs (killed)\n' % args.timeout
                    code, verdict = None, 'TIMEOUT'
                (out / ('%s-%s.log' % (compiler, name))).write_text(text)
                row['scenarios'][name] = {'verdict': verdict, 'exit': code, 'seconds': round(time.monotonic() - start, 3),
                                          'checks_failed': [l[6:] for l in text.splitlines() if l.startswith('FAIL: ')]}
                print('%s %-18s %s' % (compiler, name, verdict))
        results.append(row)
    stable = all((ROOT / rel).read_bytes() == data for rel, data in original.items())
    passed = stable and all(r['compile_exit'] == 0 and r['scenarios'] and
                            all(s['verdict'] == 'PASS' for s in r['scenarios'].values()) for r in results)
    receipt = {'source_stable': stable, 'baseline_commit': baseline, 'baseline_files': list(BASELINE_FILES) if baseline else [],
               'all_passed': passed, 'timeout_seconds': args.timeout, 'results': results,
               'source_sha256': {str(rel): hashlib.sha256(data).hexdigest() for rel, data in sorted(sources.items())},
               'generated_fixture_sha256': hashlib.sha256(unit.read_bytes()).hexdigest(),
               'scope': 'actual Kernel64 fs.c/sysfile.c/sysk32_auth.c/objects.c code; explicit IRQ, user memory, heap, '
                        'clock, token, notification and disk-volume (fsvol_t) adapters; no guest, VM or native Windows98 run'}
    (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    print('all_passed=%s source_stable=%s result=%s' % (passed, stable, out / 'result.json'))
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
