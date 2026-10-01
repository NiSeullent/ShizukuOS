#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Reproduce the isolated source proposal and host/object checks. Never starts a VM."""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

HERE = Path(__file__).resolve().parent
ALLOW = {'shizukudos/kernel32/main.c', 'shizukudos/kernel32/ipc.c',
         'shizukudos/kernel32/service_policy.h', 'shizukudos/supervisor/src/kdom.c'}
FLOOR = 17 << 30


def digest(data):
    return hashlib.sha256(data).hexdigest()


def floor(path):
    st = os.statvfs(path)
    if st.f_bavail * st.f_frsize < FLOOR + (16 << 20):
        raise ValueError('17GiB floor plus bounded16MiB preparation budget required')


def source_path(name):
    p = Path(name)
    if p.is_absolute() or '..' in p.parts or not name.startswith('shizukudos/'):
        raise ValueError('project source path refused')
    return p


def tool_binding(alias):
    if not alias.is_absolute() or not alias.is_file() or not os.access(alias, os.X_OK):
        raise ValueError('explicit absolute executable alias required')
    target = alias.resolve()
    return alias, target, identity(alias.lstat()), identity(target.stat()), digest(target.read_bytes())


def identity(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def verify_tool(binding):
    alias, target, alias_stat, target_stat, pin = binding
    if alias.resolve() != target or identity(alias.lstat()) != alias_stat or identity(target.stat()) != target_stat:
        raise ValueError('executable alias/target changed')
    if digest(target.read_bytes()) != pin:
        raise ValueError('executable target bytes changed')


def flags(source, rel, name):
    for node in ast.parse((source / rel).read_text()).body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise ValueError('pinned builder flags absent')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--source-commit', required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--gcc', type=Path, required=True)
    parser.add_argument('--patch-tool', type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((HERE / 'manifest.json').read_bytes())
    if args.source_commit != manifest['source_commit'] or not re.fullmatch('[0-9a-f]{40}', args.source_commit):
        raise ValueError('exact reviewed8508 source epoch required; changed source needs review/rebase')
    if set(manifest['changed_allowlist']) != ALLOW:
        raise ValueError('four-path proposal allowlist changed')
    if not args.source_root.is_absolute() or args.source_root.resolve() != args.source_root:
        raise ValueError('canonical absolute Git source root required')
    out = args.out
    if not out.is_absolute() or out.resolve() != out or out.exists() or not out.parent.is_dir():
        raise ValueError('new canonical output with existing parent required')
    if ('.git' in out.parts or args.source_root.is_relative_to(out) or
            (out.is_relative_to(args.source_root) and not out.is_relative_to(args.source_root / 'build'))):
        raise ValueError('output overlaps source repository metadata')
    floor(out.parent)
    gcc = tool_binding(args.gcc)
    patch_tool = tool_binding(args.patch_tool)
    assets = {}
    for name, pin in manifest['payloads'].items():
        if Path(name).name != name or (HERE / name).is_symlink():
            raise ValueError('public asset path refused')
        data = (HERE / name).read_bytes()
        if len(data) != pin['bytes'] or digest(data) != pin['sha256']:
            raise ValueError('public fixture/patch bytes changed')
        assets[name] = data
    original = {}
    for name, pin in manifest['original_sources_sha256'].items():
        source_path(name)
        command = ['git', '-C', str(args.source_root), 'show', args.source_commit + ':' + name]
        blob = subprocess.run(command, capture_output=True, check=True, timeout=15).stdout
        if digest(blob) != pin:
            raise ValueError('committed preimage mismatch: ' + name)
        original[name] = blob
    patch_headers = []
    for line in assets['proposal.patch'].decode().splitlines():
        if line.startswith(('--- ', '+++ ')):
            path = line[4:]
            if path == '/dev/null':
                continue
            if path[:2] not in ('a/', 'b/') or path[2:] not in ALLOW:
                raise ValueError('patch attempts unreviewed path')
            if line.startswith('+++ '):
                patch_headers.append(path[2:])
    if len(patch_headers) != 4 or set(patch_headers) != ALLOW:
        raise ValueError('patch file sections differ from reviewedallowlist')
    out.mkdir()
    source = out / 'source'
    for name, blob in original.items():
        p = source / source_path(name)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(blob)
    for name in ('proposal.patch', 'host_fixture.c', 'test_lifetime.py'):
        (out / name).write_bytes(assets[name])
    verify_tool(patch_tool)
    result = subprocess.run([str(args.patch_tool), '--batch', '--fuzz=0', '--forward', '-p1',
                             '-i', str(out / 'proposal.patch')], executable=str(patch_tool[1]),
                            cwd=source, capture_output=True, text=True, timeout=15)
    verify_tool(patch_tool)
    (out / 'apply.log').write_text(result.stdout + result.stderr)
    if result.returncode or 'offset' in result.stdout.lower() or 'fuzz' in result.stdout.lower():
        raise ValueError('exact patch application refused')
    inventory = {str(p.relative_to(source)): digest(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
    if inventory != manifest['sources_sha256']:
        raise ValueError('proposed source inventory mismatch')
    env = dict(os.environ, SHZ_K32_GCC=str(args.gcc))
    verify_tool(gcc)
    result = subprocess.run([sys.executable, '-B', '-m', 'unittest', '-v', 'test_lifetime.py'],
                            cwd=out, env=env, capture_output=True, text=True, timeout=45)
    verify_tool(gcc)
    (out / 'tests.log').write_text(result.stdout + result.stderr)
    if result.returncode:
        raise ValueError('production-C host suite failed; ownedoutput retained')
    artifacts, commands = {}, []
    objects = out / 'objects'
    objects.mkdir()
    for rel, name, options in (
        ('shizukudos/kernel32/main.c', 'k32-main.o', flags(source, 'shizukudos/kbuild.py', 'K32_FLAGS')),
        ('shizukudos/kernel32/ipc.c', 'k32-ipc.o', flags(source, 'shizukudos/kbuild.py', 'K32_FLAGS')),
        ('shizukudos/supervisor/src/kdom.c', 'supervisor-kdom.o', flags(source, 'shizukudos/supervisor/build.py', 'CFLAGS')),
    ):
        floor(out)
        verify_tool(gcc)
        command = [str(args.gcc), *options, '-c', str(source / rel), '-o', str(objects / name)]
        result = subprocess.run(command, executable=str(gcc[1]), capture_output=True, text=True, timeout=30)
        verify_tool(gcc)
        (objects / (name + '.log')).write_text(result.stdout + result.stderr)
        if result.returncode:
            raise ValueError('native object compile failed')
        data = (objects / name).read_bytes()
        artifacts[name] = {'bytes': len(data), 'sha256': digest(data)}
        commands.append([x.replace(str(out), '${STAGE}') for x in command])
    after = {str(p.relative_to(source)): digest(p.read_bytes()) for p in source.rglob('*') if p.is_file()}
    if after != inventory:
        raise ValueError('source changed while building')
    receipt = {'schema': 1, 'source_commit': args.source_commit, 'source_inventory_before_sha256': inventory,
               'source_inventory_after_sha256': after, 'actual_commands': commands, 'artifacts': artifacts,
               'compiler_sha256': gcc[-1], 'patch_tool_sha256': patch_tool[-1],
               'patch_sha256': digest(assets['proposal.patch']), 'host_tests_exit': 0,
               'host_test_methods': 12, 'host_boot_scenarios': 25, 'host_scheduler_time_is_simulated': True,
               'VM_executed': False, 'Windows98_boot_verified': False, 'native_apps_verified': False,
               'ShizukuDOS_replaces_MSDOS_verified': False, 'full_native_link_performed': False}
    (out / 'result.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    print('PASS exact52 committed preimages/53 proposed sources;12 host tests/25 scenarios;3 native objects;NO VM')


if __name__ == '__main__':
    main()
