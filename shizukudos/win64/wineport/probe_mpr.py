#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build genuine pinned Wine MPR in fresh isolated outputs for Office imports.

Registered network-provider loading/enumeration comes from Wine's real code.
An absent provider stays unavailable; this tool never invents a network share.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

PIN = 'db11d0fe6a169c457e23d007e20404643d067aa8'
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git(source, *args):
    return subprocess.run(['git', '-C', str(source), *args], check=True,
                          capture_output=True, timeout=30).stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prepared-wine', type=Path, required=True)
    parser.add_argument('--runtime', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    source = args.prepared_wine.resolve(strict=True)
    runtime = args.runtime.resolve(strict=True)
    out = args.out.resolve()
    if out.exists() or out == ROOT/'build' or not out.is_relative_to(ROOT/'build'):
        parser.error('fresh isolated build output required')
    if git(source, 'rev-parse', 'HEAD').decode().strip() != PIN:
        parser.error('actual prepared Wine revision differs')
    headers = [p for p in (source/'include').rglob('*') if p.is_file()]
    wrc = source/'tools/wrc/wrc'
    inputs = [*headers, wrc, Path(__file__).resolve(), HERE/'build.py', HERE/'mpr-module.json',
              HERE/'winespec.py', HERE.parent/'tools/verres.py', ROOT/'shizukudos/tools/shzlib.py']
    inputs += [p for p in (HERE/'glue').glob('*.[ch]')]
    inputs += sorted(runtime.glob('*.a'))
    inputs += sorted(runtime.glob('*.def'))
    inputs += [runtime/'wineport/lib'/name for name in ('libshzwine0.a', 'libshzwcrt.a', 'libuuid.a')]
    pins = {str(p): sha(p) for p in inputs}
    out.mkdir(parents=True)
    receipt = {'status': 'FAIL', 'upstream_commit': PIN, 'sources': [], 'inputs': pins,
               'normal_cache_unchanged': True, 'guest_started': False, 'app_functionality_verified': False}
    try:
        shadow = out/'source'; module_dir = shadow/'dlls/mpr'; module_dir.mkdir(parents=True)
        for name in git(source, 'ls-tree', '--name-only', PIN+':dlls/mpr').decode().splitlines():
            if '/' in name or name == 'tests': continue
            data = git(source, 'show', PIN+':dlls/mpr/'+name)
            (module_dir/name).write_bytes(data)
            receipt['sources'].append({'path': 'dlls/mpr/'+name, 'sha256': sha(module_dir/name)})
        # Preserve the four upstream ordinal-only exports in the equivalent
        # syntax understood by this project's MinGW .spec adapter.
        spec_path = module_dir/'mpr.spec'
        original = spec_path.read_text()
        adapted = original
        substitutions = {
            '22 stdcall @(long) MPR_Alloc': '22 stdcall -noname MPR_Alloc(long)',
            '23 stdcall @(ptr long) MPR_ReAlloc': '23 stdcall -noname MPR_ReAlloc(ptr long)',
            '24 stdcall @(ptr) MPR_Free': '24 stdcall -noname MPR_Free(ptr)',
            '25 stdcall @(ptr long) _MPR_25': '25 stdcall -noname _MPR_25(ptr long)',
        }
        for before, after in substitutions.items():
            if adapted.splitlines().count(before) != 1:
                raise ValueError('upstream anonymous ordinal anchor differs: '+before)
            adapted = adapted.replace(before, after, 1)
        spec_path.write_text(adapted)
        receipt['ordinal_syntax_adaptation'] = {
            'before_sha256': hashlib.sha256(original.encode()).hexdigest(),
            'after_sha256': sha(spec_path), 'exact_substitutions': substitutions,
            'implementation_sources_changed': False,
        }
        (shadow/'include').symlink_to(source/'include', target_is_directory=True)
        (shadow/'tools').mkdir(); (shadow/'tools/wrc').symlink_to(source/'tools/wrc', target_is_directory=True)
        output = out/'runtime'; lib = output/'wineport/lib'; lib.mkdir(parents=True)
        for path in sorted(runtime.glob('*.a')):
            shutil.copyfile(path, output/path.name)
            if sha(output/path.name) != pins[str(path)]: raise ValueError('copied import library changed')
        for name in ('libshzwine0.a', 'libshzwcrt.a', 'libuuid.a'):
            path = runtime/'wineport/lib'/name; shutil.copyfile(path, lib/name)
            if sha(lib/name) != pins[str(path)]: raise ValueError('copied Wine glue library changed')
        spec = importlib.util.spec_from_file_location('mpr_isolated_builder', HERE/'build.py')
        builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
        builder.OUT, builder.WOUT = output, output/'wineport'
        provided = {p.stem.lower(): builder.def_exports(p) for p in runtime.glob('*.def')}
        flags = [*builder.WINE_CFLAGS, '-I', shadow/'include', '-I', shadow/'include/msvcrt']
        rt = {'shzwine0': lib/'libshzwine0.a', 'shzwcrt': lib/'libshzwcrt.a', 'glue_flags': flags}
        module = json.loads((HERE/'mpr-module.json').read_text())
        built = builder.build_module(shadow, rt, module, 0x7ffb60000000, provided, {'wine': shadow})
        if any(sha(Path(path)) != pin for path, pin in pins.items()): raise ValueError('held source/library changed')
        receipt.update(status='NATIVE_BUILD_PASS_GUEST_PENDING', build={k: str(v) if isinstance(v, Path) else v for k, v in built.items()}, sha256=sha(built['dll']))
    except (Exception, SystemExit) as error:
        receipt['build_failure'] = str(error)
    (out/'mpr-probe-result.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print('MPR isolated native result:', receipt['status'], out/'mpr-probe-result.json')
    return 1 if 'build_failure' in receipt else 0


if __name__ == '__main__':
    raise SystemExit(main())
