#!/usr/bin/env python3
"""Read installed Win98 dependencies from an owned stopped raw disk.

The disk is opened read-only; Microsoft DLL copies stay in a new private
artifact directory. This verifies export presence, not API behavior or loading.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

from app_preflight import analyze
from measure_pe_coverage import pe_exports


def partition_start(mbr: bytes) -> int:
    if len(mbr) != 512 or mbr[510:] != b'\x55\xaa':
        raise ValueError('raw disk has no signed MBR')
    selected = []
    for index in range(4):
        entry = mbr[446 + index * 16:462 + index * 16]
        if entry[0] == 0x80 and entry[4] in (0x0b, 0x0c):
            start, sectors = struct.unpack_from('<II', entry, 8)
            if not start or not sectors:
                raise ValueError('invalid active FAT32 partition')
            selected.append(start)
    if len(selected) != 1:
        raise ValueError('exactly one active FAT32 partition is required')
    return selected[0]


def audit_guest(disk: Path, bundle: Path, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError('output already exists; select a new private directory')
    if output.resolve().is_relative_to(bundle.resolve()):
        raise ValueError('guest audit output must be separate from the tested bundle')
    with disk.open('rb') as source:
        start = partition_start(source.read(512))
    binaries = sorted(path for path in bundle.iterdir() if path.suffix.lower() in ('.dll', '.exe'))
    if not binaries:
        raise ValueError('bundle contains no target binaries')
    reports = {path.name: analyze(path) for path in binaries}
    names = sorted({row['dll'] for report in reports.values() for row in report['imports']})
    if any(not re.fullmatch(r'[A-Z0-9_-]{1,40}\.DLL', name) for name in names):
        raise ValueError('unexpected imported module filename')
    output.mkdir(parents=True, mode=0o700)
    modules = {}
    exports = {}
    for name in names:
        result = subprocess.run(['mtype', '-i', f'{disk}@@{start * 512}',
                                 '::WINDOWS/SYSTEM/' + name],
                                capture_output=True, timeout=30)
        if result.returncode:
            modules[name] = {'installed': False, 'export_presence_verified': False}
            continue
        target = output / name
        with target.open('xb') as copy:
            copy.write(result.stdout)
        exported = pe_exports(target, name)[name]
        exports[name] = exported
        modules[name] = {'installed': True, 'sha256': hashlib.sha256(result.stdout).hexdigest(),
                         'size_bytes': len(result.stdout), 'export_count': len(exported)}
    checked = {}
    for name, report in reports.items():
        missing = [row for row in report['imports']
                   if row['symbol'] not in exports.get(row['dll'], set())]
        checked[name] = {'sha256': report['input']['sha256'],
                         'import_inventory_complete': report['import_inventory_complete'],
                         'unresolved_in_installed_guest': missing,
                         'export_presence_verified': report['import_inventory_complete'] and not missing}
    receipt = {'schema': 'win98modern.iewebkit-installed-imports.v1',
               'source_disk': str(disk.resolve()), 'partition_start_lba': start,
               'source_access': 'read-only', 'modules': modules, 'artifacts': checked,
               'static_gate_passed': all(item['export_presence_verified'] for item in checked.values()),
               'guest_executed': False, 'api_behavior_verified': False,
               'rendering_verified': False, 'release_eligible': False}
    (output / 'installed-imports.json').write_text(json.dumps(receipt, indent=2) + '\n')
    return receipt


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disk', required=True, type=Path)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit_guest(args.disk, args.bundle, args.output)
        print(json.dumps({'output': str(args.output), 'static_gate_passed': report['static_gate_passed'],
                          'guest_executed': False, 'rendering_verified': False}, indent=2))
        return 0 if report['static_gate_passed'] else 1
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
