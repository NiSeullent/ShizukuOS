#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Check production IPC EPT leaves without starting a VM or disk image.

The IPC constructor, peer plan and liveness function are copied byte-for-byte
from the selected source. The EPT mapper and ABI headers compile unchanged.
Pool/console/Windows foundation publication are declared host adapters.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[4]


def function(text, prefix):
    start = text.index(prefix)
    opening = text.index('{', start)
    depth = 0
    for end in range(opening, len(text)):
        depth += (text[end] == '{') - (text[end] == '}')
        if depth == 0:
            return text[start:end + 1]
    raise ValueError(prefix)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--source-root', type=Path, default=ROOT)
    ap.add_argument('--out', type=Path, required=True)
    args = ap.parse_args()
    root, out = args.source_root.resolve(), args.out.resolve()
    if out.exists(): ap.error('fresh output directory required')
    out.mkdir(parents=True)
    pending = [root / 'shizukudos/supervisor/src/kdom.c',
               root / 'shizukudos/supervisor/src/ept.c',
               root / 'shizukudos/supervisor/build.py']
    sources = {}
    while pending:
        path = pending.pop().resolve()
        rel = path.relative_to(root)
        if rel in sources: continue
        data = path.read_bytes()
        sources[rel] = data
        pending.extend(path.parent / name.decode() for name in
                       re.findall(rb'^\s*#\s*include\s*"([^"\n]+)"', data, re.M))
    snap = out / 'source'
    for rel, data in sources.items():
        dest = snap / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    src = snap / 'shizukudos/supervisor/src'
    kdom = sources[Path('shizukudos/supervisor/src/kdom.c')].decode()
    plan_start = kdom.index('static const struct { uint32_t a, b; } channel_plan')
    plan_end = kdom.index('};', plan_start) + 2
    actual = '\n\n'.join([kdom[plan_start:plan_end], function(kdom, 'static int alive('),
                          function(kdom, 'int ipc_channels_create(')])
    (out / 'ipc_constructor.inc').write_text(actual + '\n')
    test = Path(__file__).with_name('ipc_ept_nx_host.c')
    test_sha = digest(test)
    runs = []
    for compiler, extra in [('gcc', []), ('clang', ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
        cc = shutil.which(compiler)
        if cc is None: raise RuntimeError('compiler unavailable: ' + compiler)
        binary = out / compiler
        command = [cc, '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   *extra, '-I', str(out), '-I', str(src),
                   '-I', str(snap / 'shizukudos/abi'), str(test), '-o', str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        (out / (compiler + '.compile.log')).write_text(result.stdout + result.stderr)
        run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=60) if not result.returncode else None
        log = run.stdout + run.stderr if run else result.stdout + result.stderr
        (out / (compiler + '.run.log')).write_text(log)
        print(compiler + ': ' + log, end='')
        runs.append({'compiler': str(Path(cc).resolve()), 'command': command,
                     'compile_exit': result.returncode, 'exit': run.returncode if run else None,
                     'binary_sha256': digest(binary) if binary.exists() else None})
    # Compile the full production unit as well as the extracted constructor.
    flags = None
    for node in ast.parse(sources[Path('shizukudos/supervisor/build.py')]).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'CFLAGS' for t in node.targets):
            flags = ast.literal_eval(node.value)
    if flags is None: raise RuntimeError('production Supervisor flags absent')
    for compiler in ['gcc', 'clang']:
        effective = [f for f in flags if not (compiler == 'clang' and f == '-fno-tree-loop-distribute-patterns')]
        for unit in ['kdom', 'ept']:
            command = [compiler, *effective, '-I', str(src), '-I', str(snap / 'shizukudos/abi'),
                       '-c', str(src / (unit + '.c')), '-o', str(out / (compiler + '-' + unit + '.o'))]
            result = subprocess.run(command, capture_output=True, text=True, timeout=60)
            (out / (compiler + '-' + unit + '.compile.log')).write_text(result.stdout + result.stderr)
            if result.returncode: print(result.stderr, end='')
            runs.append({'compiler': compiler, 'unit': unit, 'command': command, 'compile_exit': result.returncode})
    stable = all((root / rel).read_bytes() == data for rel, data in sources.items()) and digest(test) == test_sha
    passed = stable and all(row['compile_exit'] == 0 and row.get('exit', 0) == 0 for row in runs)
    receipt = {'passed': passed, 'source_stable': stable, 'runs': runs,
               'sources_sha256': {str(rel): hashlib.sha256(data).hexdigest() for rel, data in sources.items()},
               'host_test_sha256': test_sha, 'vmx_execution_verified': False,
               'native_windows98_verified': False,
               'scope': 'production constructor and real EPT leaf checks, full production object compilation; host adapters for pool/console/foundation publication; no VM, Windows or hardware execution',
               'reference': 'https://cdrdv2-public.intel.com/774497/326019-sdm-vol-3c.pdf'}
    (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
