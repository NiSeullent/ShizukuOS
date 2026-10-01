#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the ordinary standalone kernel builder into fresh owned outputs."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def inventory():
    files = [Path(__file__).resolve(), ROOT/'shizukudos/kbuild.py',
             ROOT/'shizukudos/tools/shzlib.py', ROOT/'shizukudos/win64/pe_parse.c',
             ROOT/'shizukudos/win64/pe_parse.h',
             ROOT/'shizukudos/supervisor/src/font8x8_basic.h']
    for directory in ('shizukudos/kernel64', 'shizukudos/kcommon', 'shizukudos/abi',
                      'shizukufs/v1/libsfs', 'drivers/ahci_native', 'shizukudos/win64/include'):
        files.extend(p for p in (ROOT/directory).rglob('*') if p.is_file()
                     and '__pycache__' not in p.parts and 'build' not in p.relative_to(ROOT/directory).parts)
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or out == ROOT/'build' or not out.is_relative_to(ROOT/'build'):
        parser.error('fresh owned output below this worktree build required')
    spec = importlib.util.spec_from_file_location('isolated_kernel_builder', ROOT/'shizukudos/kbuild.py')
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    pins = inventory()
    builder.BUILD = out
    extra = [builder.SHZ/'win64/pe_parse.c', builder.STUB_DIR/'standalone64.c',
             ROOT/'drivers/ahci_native/ahci.c', *sorted((ROOT/'shizukufs/v1/libsfs').glob('*.c'))]
    kernel = builder.build_kernel('kernel64s', 'kernel64', builder.K64_FLAGS+['-DSHZ_STANDALONE'],
                                  'elf64', 'elf_x86_64', 'KERNEL64S.BIN', extra_c=extra)
    stub = builder.build_standalone_stub()
    if inventory() != pins:
        raise SystemExit('kernel source inventory changed during build')
    def serializable(value):
        if isinstance(value, Path): return str(value)
        if isinstance(value, dict): return {k: serializable(v) for k, v in value.items()}
        if isinstance(value, list): return [serializable(v) for v in value]
        return value
    proof = {'status': 'PASS', 'mode': 'ordinary-standalone-kernel-build-frozen-source',
             'sources': pins, 'kernel': serializable(kernel), 'stub': serializable(stub)}
    (out/'kernel-build-receipt.json').write_text(json.dumps(proof, indent=2)+'\n')
    print('Ordinary isolated kernel build PASS:', kernel['sha256'], flush=True)


if __name__ == '__main__':
    main()
