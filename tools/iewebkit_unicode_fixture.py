#!/usr/bin/env python3
"""Freeze the native WTF Unicode/ANSI comparison on a new Win98 guest clone."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid


def create(probe: Path, expected_sha: str, bundle: Path, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError('output exists; choose a new private fixture directory')
    if not re.fullmatch(r'[0-9a-f]{64}', expected_sha):
        raise ValueError('an exact expected native-probe digest is required')
    native = probe.read_bytes()
    if hashlib.sha256(native).hexdigest() != expected_sha:
        raise ValueError('Unicode probe differs from its selected digest')
    receipt_path = bundle.parent / 'build.json'
    receipt_raw = receipt_path.read_bytes()
    receipt = json.loads(receipt_raw)
    target = (bundle / 'IETARGET.EXE').read_bytes()
    if (receipt.get('schema') != 'win98modern.iewebkit-build.v1' or
        not receipt.get('static_gate_passed') or
        receipt.get('target', {}).get('ie_version') != '5.00.2614.3500' or
        hashlib.sha256(target).hexdigest() != receipt['artifacts']['IETARGET.EXE']['sha256']):
        raise ValueError('target probe is not bound to a successful host build')
    nonce = '83bd-unicode-' + uuid.uuid4().hex
    batch = ('@echo off\r\ncd \\GOPLAB\r\nIETARGET.EXE ' + nonce + '\r\n'
             'RLCMP.EXE C:\\GOPLAB\\RLCMP.LOG\r\necho ' + nonce +
             '>C:\\GOPLAB\\RLDONE.TXT\r\nexit\r\n').encode('ascii')
    files = {'IETARGET.EXE': target, 'RLCMP.EXE': native, 'RUNUNI.BAT': batch}
    if any(not 0 < len(data) <= 1024 ** 2 for data in files.values()):
        raise ValueError('native fixture exceeds the bounded input size')
    output.mkdir(parents=True, mode=0o700)
    inputs = []
    for name, data in files.items():
        path = output / name
        path.write_bytes(data)
        inputs.append({'source': str(path.resolve()), 'guest': 'C:\\GOPLAB\\' + name,
                       'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})
    manifest = {'schema': 1, 'kind': 'isolated-guest-file-inputs', 'inputs': inputs,
                'outputs': ['C:\\GOPLAB\\' + name for name in
                            ('IETARGET.LOG', 'RLCMP.LOG', 'RLDONE.TXT')],
                'source_receipts': [{'path': str(receipt_path.resolve()),
                                     'sha256': hashlib.sha256(receipt_raw).hexdigest()}],
                'backups': [], 'nonce': nonce, 'probe_sha256': expected_sha,
                'command': 'C:\\GOPLAB\\RUNUNI.BAT',
                'acceptance_limit': 'Actual Windows98 API comparison; no engine/provider/rendering pass.'}
    raw = (json.dumps(manifest, indent=2) + '\n').encode()
    path = output / 'guest-files.json'
    path.write_bytes(raw)
    return {'manifest': str(path.resolve()), 'sha256': hashlib.sha256(raw).hexdigest(),
            'nonce': nonce, 'command': manifest['command']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--probe', type=Path, required=True)
    parser.add_argument('--probe-sha256', required=True)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(create(args.probe, args.probe_sha256, args.bundle, args.output), indent=2))
        return 0
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
