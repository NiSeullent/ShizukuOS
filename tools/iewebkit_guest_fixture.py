#!/usr/bin/env python3
"""Freeze a bounded IE5/Win98 native diagnostic manifest for a new guest clone."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import uuid


def create(bundle: Path, output: Path, runloop: Path | None = None,
           browser_handoff: bool = False) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError('fixture output exists; select a new directory')
    report_path = bundle.parent / 'build.json'
    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    if report.get('schema') != 'win98modern.iewebkit-build.v1' or not report.get('static_gate_passed'):
        raise ValueError('an exact-target successful host build receipt is required')
    if report.get('target', {}).get('ie_version') != '5.00.2614.3500':
        raise ValueError('fixture target must be the installed Win98 IE5.0 version')
    data = {}
    for name in ('IETARGET.EXE', 'HOSTTEST.EXE', 'NAVTEST.EXE', 'NAVVALUE.EXE'):
        content = (bundle / name).read_bytes()
        if hashlib.sha256(content).hexdigest() != report['artifacts'][name]['sha256']:
            raise ValueError('binary differs from its build receipt: ' + name)
        data[name] = content
    if runloop is not None:
        data['RUNLOOP.EXE'] = runloop.read_bytes()
    if browser_handoff:
        if not report.get('diagnostic_handoff_included'):
            raise ValueError('build receipt has no diagnostic handoff')
        for name in ('IEWKHOST.DLL', 'NAVBHO.DLL'):
            content = (bundle / name).read_bytes()
            if hashlib.sha256(content).hexdigest() != report['artifacts'][name]['sha256']:
                raise ValueError('diagnostic differs from its build receipt: ' + name)
            data[name] = content
    if any(not 0 < len(content) <= 1024 ** 2 for content in data.values()):
        raise ValueError('native fixture exceeds the runner input size limit')
    nonce = '83bd-' + uuid.uuid4().hex
    # Existing independent harnesses write fresh CREATE_ALWAYS logs to ZUKUQA;
    # copy their results into the runner's bounded readback directory.
    lines = ['@echo off', 'if "%1"=="cleanup" goto cleanup', 'cd \\GOPLAB', 'md C:\\ZUKUQA',
             'IETARGET.EXE ' + nonce, 'HOSTTEST.EXE', 'NAVTEST.EXE', 'NAVVALUE.EXE',
             'copy C:\\ZUKUQA\\HOSTTEST.LOG C:\\GOPLAB\\HOSTTEST.LOG',
             'copy C:\\ZUKUQA\\NAVTEST.LOG C:\\GOPLAB\\NAVTEST.LOG',
             'copy C:\\ZUKUQA\\NAVVALUE.LOG C:\\GOPLAB\\NAVVALUE.LOG']
    outputs = ['IETARGET.LOG', 'HOSTTEST.LOG', 'NAVTEST.LOG', 'NAVVALUE.LOG', 'IEDONE.TXT']
    if runloop is not None:
        lines.append('RUNLOOP.EXE C:\\GOPLAB\\RL9X.LOG')
        outputs.append('RL9X.LOG')
    lines += ['echo ' + nonce + '>C:\\GOPLAB\\IEDONE.TXT']
    if browser_handoff:
        lines += ['del C:\\ZUKUQA\\IENAV.LOG',
                  'C:\\WINDOWS\\SYSTEM\\REGSVR32.EXE /s C:\\GOPLAB\\IEWKHOST.DLL',
                  'C:\\WINDOWS\\SYSTEM\\REGSVR32.EXE /s C:\\GOPLAB\\NAVBHO.DLL',
                  '"C:\\Program Files\\Internet Explorer\\IEXPLORE.EXE" https://www.zuzunza.com/']
        outputs += ['IENAV.LOG', 'IEUNREG.TXT']
    lines += ['exit', ':cleanup']
    if browser_handoff:
        lines += ['C:\\WINDOWS\\SYSTEM\\REGSVR32.EXE /u /s C:\\GOPLAB\\NAVBHO.DLL',
                  'C:\\WINDOWS\\SYSTEM\\REGSVR32.EXE /u /s C:\\GOPLAB\\IEWKHOST.DLL',
                  'copy C:\\ZUKUQA\\IENAV.LOG C:\\GOPLAB\\IENAV.LOG',
                  'echo ' + nonce + '>C:\\GOPLAB\\IEUNREG.TXT']
    lines.append('exit')
    data['RUNIE.BAT'] = ('\r\n'.join(lines) + '\r\n').encode('ascii')
    output.mkdir(parents=True, mode=0o700)
    inputs = []
    for name, content in data.items():
        path = output / name
        path.write_bytes(content)
        inputs.append({'source': str(path.resolve()), 'guest': 'C:\\GOPLAB\\' + name,
                       'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()})
    manifest = {'schema': 1, 'kind': 'isolated-guest-file-inputs', 'inputs': inputs,
                'outputs': ['C:\\GOPLAB\\' + name for name in outputs],
                'source_receipts': [{'path': str(report_path.resolve()),
                                     'sha256': hashlib.sha256(report_bytes).hexdigest()}],
                'backups': [], 'nonce': nonce,
                'command': 'C:\\COMMAND.COM /C C:\\GOPLAB\\RUNIE.BAT',
                'acceptance_limit': 'Actual Win98 target/COM/API diagnostics; no WebKit rendering claim.'}
    raw = (json.dumps(manifest, indent=2) + '\n').encode()
    path = output / 'guest-files.json'
    path.write_bytes(raw)
    return {'manifest': str(path.resolve()), 'sha256': hashlib.sha256(raw).hexdigest(),
            'nonce': nonce, 'command': manifest['command']}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--runloop', type=Path)
    parser.add_argument('--browser-handoff', action='store_true',
                        help='Opt in to diagnostic BHO registration on the disposable guest')
    args = parser.parse_args(argv)
    try:
        print(json.dumps(create(args.bundle, args.output, args.runloop, args.browser_handoff), indent=2))
        return 0
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
