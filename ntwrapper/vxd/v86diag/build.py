#!/usr/bin/env python3
"""Build an original DOS COM for the frozen one-bit VxD experiment only."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
VXD = HERE.parent
ROOT = VXD.parents[1]
DEFAULT_BUILD = VXD / 'build/v86diag'
CANDIDATE = VXD / 'build/flag-diagnostic/NTWRAP9X.VXD'
BASELINE = VXD / 'build/NTWRAP9X.VXD'
CANDIDATE_SHA = '83952d5c220272d4dbd724e309e29fcc431d2eefa0e59253d3283a116fc0801e'
BASELINE_SHA = 'aff7acf54cd0323fe4dce9aab7d93da16df7b8cf345220ee9d2dafa95b0bc537'
SOURCES = (VXD / 'dos_loader_diag.asm', HERE / 'build.py', HERE / 'test.py',
           HERE / 'README.md', HERE / 'REFERENCES.md')


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_map() -> dict[str, str]:
    return {str(p.relative_to(ROOT)): digest(p.read_bytes()) for p in SOURCES}


def build(out: Path) -> dict:
    sources = source_map()
    candidate, baseline = CANDIDATE.read_bytes(), BASELINE.read_bytes()
    if (len(candidate) != 9390 or digest(candidate) != CANDIDATE_SHA or
            digest(baseline) != BASELINE_SHA):
        raise ValueError('frozen experimental/baseline VxD identity mismatch')
    diffs = [i for i, (a, b) in enumerate(zip(baseline, candidate)) if a != b]
    if len(baseline) != len(candidate) or diffs != [0x164] or candidate[0x164] != 0x63:
        raise ValueError('expected only the previously authorized data SHARABLE bit')
    out.mkdir(parents=True, exist_ok=True)
    (out / 'expected.vxd').write_bytes(candidate)
    (out / 'expected.inc').write_text(
        '%define EXPECTED_SIZE 9390\n'
        f'%define EXPECTED_SHA256 "{CANDIDATE_SHA}"\n', encoding='ascii')
    command = ['nasm', '-f', 'bin', '-Wall', '-Werror', '-I', str(out) + '/',
               '-l', str(out / 'NTWLDR.lst'), '-o', str(out / 'NTWLDR.COM'),
               str(VXD / 'dos_loader_diag.asm')]
    subprocess.run(command, check=True, capture_output=True, text=True)
    code = (out / 'NTWLDR.COM').read_bytes()
    if not 9390 < len(code) < 0xfe00 or code.count(candidate) != 1:
        raise ValueError('COM layout/embedded candidate check failed')
    dis = subprocess.run(['ndisasm', '-b', '16', '-o', '0x100',
                          str(out / 'NTWLDR.COM')], check=True, capture_output=True)
    (out / 'NTWLDR.disasm').write_bytes(dis.stdout)
    if sources != source_map() or CANDIDATE.read_bytes() != candidate or BASELINE.read_bytes() != baseline:
        raise ValueError('input changed during build')
    receipt = {
        'schema': 1, 'kind': 'original-dos-v86-loader-diagnostic-build',
        'native_execution_verified': False, 'sources': sources,
        'candidate': {'size': len(candidate), 'sha256': CANDIDATE_SHA,
                      'baseline_sha256': BASELINE_SHA, 'changed_offset': 0x164},
        'artifact': {'name': 'NTWLDR.COM', 'size': len(code), 'sha256': digest(code)},
        'command': command,
        'nasm': subprocess.run(['nasm', '-v'], check=True, capture_output=True, text=True).stdout.strip(),
        'outputs': {p.name: digest(p.read_bytes()) for p in
                    (out / 'expected.vxd', out / 'expected.inc', out / 'NTWLDR.lst', out / 'NTWLDR.disasm')},
        'limits': {'candidate_bytes': 9390, 'stack_bytes': 2048,
                   'max_version_calls': 1, 'max_load_calls': 1, 'max_unload_calls': 1,
                   'guest_watchdog_required': True},
    }
    (out / 'build-result.json').write_text(json.dumps(receipt, indent=2, sort_keys=True) + '\n')
    return receipt


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=DEFAULT_BUILD)
    args = parser.parse_args()
    print(json.dumps(build(args.output), indent=2, sort_keys=True))
