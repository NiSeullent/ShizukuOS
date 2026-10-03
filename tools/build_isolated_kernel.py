#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run the ordinary standalone kernel builder into fresh owned outputs."""
import argparse
import hashlib
import importlib.util
import json
import shlex
import subprocess
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
    # Shared sources the official standalone profile compiles or includes by
    # relative path (xHCI/USB core, laptop protocols, Dead Screen, device
    # sessions). Source/header types only, so outputs and bytecode are excluded.
    for directory in ('drivers/common', 'drivers/shz_laptop', 'drivers/usb_native',
                      'drivers/xhci_native', 'shizukudos/dead_screen', 'shizukudos/accounts',
                      'shizukudos/boot_profile', 'shizukudos/pma_bridge'):
        files.extend(p for p in (ROOT/directory).rglob('*') if p.is_file()
                     and p.suffix in ('.c', '.h', '.asm', '.ld') and '__pycache__' not in p.parts
                     and 'build' not in p.relative_to(ROOT/directory).parts)
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}


def check_include_closure(builder, extra, flags, pins):
    """Pin the local C dependencies of each standalone Kernel64 unit."""
    units = [*sorted((builder.SHZ/'kernel64').glob('*.c')), *extra]
    missing = set()
    for src in units:
        cmd = ['gcc', *flags, '-I', str(builder.SHZ), '-I', str(builder.SHZ/'kernel64'),
               '-MM', '-MT', 'kernel-deps', str(src)]
        text = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=60).stdout
        body = text.replace('\\\n', ' ').partition(':')[2]
        if not body:
            raise SystemExit('compiler produced no dependency rule: ' + str(src))
        for dep in shlex.split(body):
            path = Path(dep).resolve(strict=True)
            if not path.is_relative_to(ROOT):
                raise SystemExit('compiled local include outside source inventory: ' + str(path))
            if str(path.relative_to(ROOT)) not in pins:
                missing.add(str(path.relative_to(ROOT)))
    if missing:
        raise SystemExit('compiled includes missing from source inventory: ' + ', '.join(sorted(missing)))


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
             ROOT/'drivers/ahci_native/ahci.c', ROOT/'drivers/xhci_native/xhci.c',
             *sorted((ROOT/'shizukufs/v1/libsfs').glob('*.c')), *builder.dead_screen_sources()]
    flags = builder.K64_FLAGS+['-DSHZ_STANDALONE']
    check_include_closure(builder, extra, flags, pins)
    kernel = builder.build_kernel('kernel64s', 'kernel64', flags,
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
