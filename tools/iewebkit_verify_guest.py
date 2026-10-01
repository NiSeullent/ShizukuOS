#!/usr/bin/env python3
"""Verify digest-bound native IE/RunLoop diagnostic results, not rendering."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


def key_values(raw: bytes) -> dict[str, str]:
    result = {}
    for line in raw.decode('ascii').splitlines():
        if '=' not in line:
            continue
        key, value = line.split('=', 1)
        # URLMon traces intentionally repeat per-binding fields; callers use
        # only the final aggregate plus the two independently counted results.
        result[key] = value
    return result


def verify(run: Path, manifest_path: Path) -> dict:
    raw_result = (run / 'result.json').read_bytes()
    result = json.loads(raw_result)
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get('schema') != 1 or manifest.get('kind') != 'isolated-guest-file-inputs':
        raise ValueError('unexpected frozen guest fixture schema')
    files = result['guest_files']
    if (result.get('profile') != 'actual-win98-uefi-csmwrap' or
            result.get('qemu_exit_code') != 0 or result.get('originals_unchanged') is not True or
            result.get('prepared_source_unchanged') is not True or
            files.get('immutable_sources_unchanged') is not True or
            files.get('manifest_sha256') != hashlib.sha256(manifest_bytes).hexdigest()):
        raise ValueError('owned native run, shutdown, original preservation or fixture binding failed')
    command = result['command']
    if '-nic' not in command or command[command.index('-nic') + 1] != 'none':
        raise ValueError('diagnostic guest must have no NIC')
    planned = {item['guest']: item for item in manifest['inputs']}
    required = {'C:\\GOPLAB\\' + name for name in
                ('IETARGET.EXE', 'HOSTTEST.EXE', 'NAVTEST.EXE', 'NAVVALUE.EXE')}
    observed = {item['guest'] for item in files['inputs']}
    if not required <= planned.keys() or observed != planned.keys() or len(observed) != len(files['inputs']):
        raise ValueError('required native executables are not bound to the guest inputs')
    binaries = {}
    for item in files['inputs']:
        selected = planned[item['guest']]
        if item['sha256'] != selected['sha256'] or item['private_copy_sha256'] != selected['sha256']:
            raise ValueError('guest input differs from the frozen fixture')
        if item['guest'].lower().endswith(('.exe', '.dll')):
            binaries[item['guest'].rsplit('\\', 1)[1]] = item['sha256']
    captured = {item['guest'].rsplit('\\', 1)[1]: item for item in files['readback']}
    logs = {}
    evidence = {}
    for name in ('IETARGET.LOG', 'HOSTTEST.LOG', 'NAVTEST.LOG', 'NAVVALUE.LOG', 'IEDONE.TXT'):
        item = captured[name]
        if item['status'] != 'captured' or item.get('freshness') != 'new-in-owned-run':
            raise ValueError('missing fresh guest result: ' + name)
        path = Path(item['path']).resolve()
        if not path.is_relative_to(run.resolve()):
            raise ValueError('result path escapes the owned run')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise ValueError('returned result digest changed: ' + name)
        logs[name] = raw
        evidence[name] = {'path': str(path), 'sha256': item['sha256']}
    target = key_values(logs['IETARGET.LOG'])
    exact = (target.get('schema') == 'win98modern.iewebkit-target.v1' and
             target.get('nonce') == manifest['nonce'] and target.get('os') == '4.10.2222' and
             target.get('platform') == '1' and target.get('shdocvw_version') == '5.0.2614.3500' and
             target.get('iexplore_version') == '5.0.2614.3500' and target.get('target_matched') == '1' and
             logs['IEDONE.TXT'].strip() == manifest['nonce'].encode('ascii'))
    moniker = key_values(logs['NAVTEST.LOG'])
    checks = {'exact_native_target': exact,
              'com_lifecycle': b'PASS DocObject site replacement' in logs['HOSTTEST.LOG'] and
                               b'reentrant deactivation ownership' in logs['HOSTTEST.LOG'],
              'remote_moniker': moniker.get('all_moniker_checks') == '0x00000001' and
                                logs['NAVTEST.LOG'].count(b'remote_moniker_equal=0x00000001') == 2,
              'request_value_rejection': b'PASS nested IE variants, cyclic rejection, nonempty headers and POST rejection'
                                         in logs['NAVVALUE.LOG']}
    if 'RL9X.LOG' in captured:
        item = captured['RL9X.LOG']
        path = Path(item.get('path', '')).resolve()
        if item['status'] != 'captured' or item.get('freshness') != 'new-in-owned-run' or not path.is_relative_to(run.resolve()):
            raise ValueError('missing fresh native runloop result')
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != item['sha256']:
            raise ValueError('runloop result digest changed')
        loop = key_values(raw)
        checks['win98_runloop_helper'] = all(loop.get(key) == value for key, value in {
            'os.major': '4', 'os.minor': '10', 'os.platform': '1', 'os.build': '2222',
            'port.visible': '0', 'port.context': '1', 'worker.exit': '0',
            'work.delivered': '1', 'thread.delivered': '96', 'timer.delivered': '1',
            'destroy.delivered': '1', 'quit.code': '37', 'exit': '0'}.items())
        evidence['RL9X.LOG'] = {'path': str(path), 'sha256': item['sha256']}
    return {'schema': 'win98modern.iewebkit-native-review.v1',
            'run_result_sha256': hashlib.sha256(raw_result).hexdigest(),
            'fixture_sha256': hashlib.sha256(manifest_bytes).hexdigest(),
            'nonce': manifest['nonce'], 'binary_sha256': binaries, 'evidence': evidence,
            'checks': checks, 'native_diagnostics_passed': all(checks.values()),
            'guest_executed': True, 'provider_status': int(target.get('provider_status', '-1')),
            'browser_docobject_activation_verified': False,
            'browser_first_run': 'Internet Connection Wizard interrupted the visible browser trial',
            'diagnostic_unregistration_verified': False,
            'shutdown': 'owned QEMU exited cleanly; graceful Windows shutdown was not established',
            'engine_rendering_verified': False, 'tls_verified': False, 'release_eligible': False}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = verify(args.run, args.manifest)
        with args.output.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'native_diagnostics_passed': report['native_diagnostics_passed'],
                          'guest_executed': True, 'engine_rendering_verified': False}, indent=2))
        return 0 if report['native_diagnostics_passed'] else 1
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
