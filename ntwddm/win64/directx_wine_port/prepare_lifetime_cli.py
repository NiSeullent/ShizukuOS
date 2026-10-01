#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare the two exact pinned HLSL repairs in fresh owned output.

This is source preparation, not compilation or a runtime acceptance test.
The source input may live anywhere; original files are never changed.
"""
import argparse
import json
import shutil
from pathlib import Path

from prepare_lifetime import prepare, sha

HERE = Path(__file__).resolve().parent
PIN = 'db11d0fe6a169c457e23d007e20404643d067aa8'
ORIGINAL = {
    'hlsl_codegen.c': 'f2594b5914565317ea167de6acf9edb86b5d79edd06b52b1f9db7fd8acd1b787',
    'hlsl.y': 'b88f4a34a9e93f36e8c84e25bfd3a6268241df03b6a820cc3b261a8d19d09b50',
}
RESERVE = 20 * 1024**3
WRITE = 256 * 1024**2


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def usage():
    files = [p for p in (HERE / 'build').rglob('*') if p.is_file() and not p.is_symlink()]
    return max(sum(p.stat().st_size for p in files),
               sum(p.stat().st_blocks * 512 for p in files))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--wine', required=True, help='read-only Wine source tree at the documented pin')
    parser.add_argument('--out', required=True, help='fresh directory beneath this module/build')
    args = parser.parse_args()
    wine = Path(args.wine).resolve(strict=True)
    output = Path(args.out).resolve()
    require(output.is_relative_to(HERE / 'build') and not output.exists(), 'fresh owned output required')
    shader = wine / 'libs/vkd3d/libs/vkd3d-shader'
    for name, expected in ORIGINAL.items():
        require(sha(shader / name) == expected, 'exact pinned original required: ' + name)
    require(shutil.disk_usage(HERE).free - 2 * 1024**2 >= RESERVE, '20 GiB reserve and preparation margin')
    require(usage() + 2 * 1024**2 <= WRITE, 'aggregate 256 MiB preparation budget')
    output.parent.mkdir(parents=True, exist_ok=True)
    records, patch = prepare(wine, output)
    for name, expected in ORIGINAL.items():
        require(sha(shader / name) == expected, 'original changed during preparation: ' + name)
    receipt = {
        'schema': 1,
        'status': 'SOURCE_PREPARATION_PASS_RUNTIME_UNVERIFIED',
        'wine_commit': PIN,
        'original_identity_scope': 'SHA-256 of two changed source files; other upstream files not checked by this helper',
        'prepared_sources': records,
        'patch': patch,
        'recipe_sha256': sha(HERE / 'prepare_lifetime.py'),
        'cli_sha256': sha(Path(__file__)),
        'repair_compiled': False,
        'repair_sanitizer_verified': False,
        'amd64_shader_library_built': False,
        'directx_runtime_verified': False,
    }
    (output / 'prepared.json').write_text(json.dumps(receipt, sort_keys=True, indent=2) + '\n')
    require(usage() <= WRITE and shutil.disk_usage(HERE).free >= RESERVE, 'final preparation budget/reserve')
    print(json.dumps({'out': str(output), 'status': receipt['status'], 'patch_sha256': patch['sha256']}))


if __name__ == '__main__':
    main()
