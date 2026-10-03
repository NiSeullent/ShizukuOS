#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Production file/handle/authority regression with explicit host boundaries."""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURE = Path(__file__).with_suffix('.c')


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
    parser.add_argument('--label', required=True)
    parser.add_argument('--baseline', help='immutable Git revision for sysfile.c and ipc_io.c')
    parser.add_argument('--reuse-control', action='store_true', help='also close and reuse the file handle during IRP preparation')
    args = parser.parse_args()
    out = ROOT / 'build/accounts-file-rights' / args.label
    if out.exists():
        parser.error('fresh output label required')
    pending = [FIXTURE, Path(__file__).resolve()] + [ROOT / 'shizukudos/kernel64' / name for name in
              ('objects.c', 'ipc_core.c', 'ipc_proc.c', 'ipc_io.c', 'auth_core.c')]
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
        for name in ('sysfile.c', 'ipc_io.c'):
            sources[Path('shizukudos/kernel64') / name] = subprocess.run(
                ['git', 'show', baseline + ':shizukudos/kernel64/' + name], cwd=ROOT, capture_output=True, check=True, timeout=10).stdout
    snap = out / 'source'
    for rel, data in sources.items():
        path = snap / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    fixture = sources[FIXTURE.relative_to(ROOT)].decode()
    objects = sources[Path('shizukudos/kernel64/objects.c')].decode()
    core = sources[Path('shizukudos/kernel64/ipc_core.c')].decode()
    proc = sources[Path('shizukudos/kernel64/ipc_proc.c')].decode()
    funcs = '\n'.join(definition(objects, n) for n in
                      ('ob_create', 'ob_ref', 'ob_deref', 'handle_insert', 'handle_lookup', 'handle_ref', 'handle_close'))
    # These are declarations for unavailable services, not replacement behavior.
    decls = 'void reg_key_object_free(kobject_t *);\nvoid ipc_object_free(kobject_t *);\nvoid ipc_handle_closed(process_t *,kobject_t *);\n'
    fixture = fixture.replace('/* @PRODUCTION_OBJECT_FUNCTIONS@ */', decls + funcs)
    duplicate = '\n'.join(definition(core, n) for n in
                          ('ipc_handle_opened', 'ipc_give_handle', 'ipc_ref_handle', 'ipc_ref_process'))
    duplicate += '\n' + '\n'.join(definition(proc, n) for n in ('handle_flags_of', 'duplicate_failure_trace', 'sys_duplicate'))
    duplicate = '#define DUPLICATE_CLOSE_SOURCE 1u\n#define DUPLICATE_SAME_ACCESS 2u\n#define DUPLICATE_SAME_ATTRIBUTES 4u\n#define MAXIMUM_ALLOWED_ACCESS 0x02000000u\n' + duplicate
    fixture = fixture.replace('/* @PRODUCTION_DUPLICATE_FUNCTIONS@ */', duplicate)
    io = sources[Path('shizukudos/kernel64/ipc_io.c')].decode()
    fixture = fixture.replace('/* @PRODUCTION_IO_FUNCTIONS@ */',
                              '#define NT_ERROR(s) ((uint32_t)(s) >= 0xC0000000u)\n' +
                              '\n'.join(definition(io, n) for n in
                                        (('irp_free', 'file_rw') if baseline else ('irp_free', 'file_io_release', 'file_rw'))))
    unit = snap / FIXTURE.relative_to(ROOT)
    unit.write_text(fixture)
    results = []
    for compiler in ('gcc', 'clang'):
        cc = shutil.which(compiler)
        if not cc:
            raise RuntimeError('required compiler missing: ' + compiler)
        exe = out / (compiler + '-file-rights')
        flags = ['-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-ffunction-sections', '-fdata-sections']
        if compiler == 'clang':
            flags += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
        cmd = [cc, *flags, str(unit), str(snap / 'shizukudos/kernel64/auth_core.c'), '-Wl,--gc-sections', '-o', str(exe)]
        built = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        (out / (compiler + '-compile.log')).write_text(built.stdout + built.stderr)
        row = {'compiler': compiler, 'compile_exit': built.returncode}
        if built.returncode:
            print(built.stderr)
        else:
            ran = subprocess.run([str(exe), *(['reuse'] if args.reuse_control else [])], capture_output=True, text=True, timeout=30,
                                 env=dict(os.environ, ASAN_OPTIONS='detect_leaks=1:abort_on_error=1'))
            (out / (compiler + '-run.log')).write_text(ran.stdout + ran.stderr)
            row.update(run_exit=ran.returncode, binary_sha256=hashlib.sha256(exe.read_bytes()).hexdigest())
            print(compiler + ':\n' + ran.stdout + ran.stderr, end='')
        results.append(row)
    stable = all((ROOT / rel).read_bytes() == data for rel, data in original.items())
    receipt = {'source_stable': stable, 'baseline_commit': baseline, 'results': results,
               'source_sha256': {str(rel): hashlib.sha256(data).hexdigest() for rel, data in sources.items()},
               'generated_fixture_sha256': hashlib.sha256(unit.read_bytes()).hexdigest(),
               'scope': 'actual Kernel64 sysfile/filesystem/account policy/object lifetime/handle duplication code; explicit IRQ, user memory, heap, clock and token/device adapters; no native Windows98 execution or isolation'}
    (out / 'result.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return 0 if stable and all(row.get('run_exit', 1) == 0 for row in results) else 1


if __name__ == '__main__':
    raise SystemExit(main())
