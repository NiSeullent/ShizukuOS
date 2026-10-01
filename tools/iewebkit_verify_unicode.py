#!/usr/bin/env python3
"""Verify a source/digest-bound native Win98 Unicode/ANSI API comparison."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

from iewebkit_verify_guest import key_values


def digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def verify(run: Path, manifest_path: Path, probe_receipt: Path,
           probe_source: Path) -> dict:
    raw_result = (run / 'result.json').read_bytes()
    result = json.loads(raw_result)
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    receipt_raw = probe_receipt.read_bytes()
    receipt = json.loads(receipt_raw)
    source_sha = digest(probe_source.read_bytes())
    if (manifest.get('schema') != 1 or
            manifest.get('kind') != 'isolated-guest-file-inputs'):
        raise ValueError('unexpected frozen native fixture schema')
    if (receipt.get('schema') != 'iewebkit-native-runloop-api-comparison-v1' or
            receipt.get('binary_sha256') != manifest.get('probe_sha256') or
            receipt.get('source_sha256') != source_sha or
            receipt.get('import_gate') != 'PASS' or receipt.get('missing_exports') != {}):
        raise ValueError('selected probe binary/source/import receipt binding failed')
    files = result['guest_files']
    if (result.get('profile') != 'actual-win98-uefi-csmwrap' or
            result.get('qemu_exit_code') != 0 or
            result.get('originals_unchanged') is not True or
            result.get('prepared_source_unchanged') is not True or
            files.get('immutable_sources_unchanged') is not True or
            files.get('manifest_sha256') != digest(manifest_raw)):
        raise ValueError('owned native run, QEMU exit, source preservation or fixture binding failed')
    command = result['command']
    if '-nic' not in command or command[command.index('-nic') + 1] != 'none':
        raise ValueError('native comparison guest must have no NIC')
    planned = {item['guest']: item for item in manifest['inputs']}
    expected = {'C:\\GOPLAB\\' + name for name in
                ('IETARGET.EXE', 'RLCMP.EXE', 'RUNUNI.BAT')}
    observed = {item['guest']: item for item in files['inputs']}
    if (planned.keys() != expected or observed.keys() != expected or
            len(planned) != len(manifest['inputs']) or len(observed) != len(files['inputs'])):
        raise ValueError('native comparison input set is not exactly the frozen fixture')
    for guest, item in observed.items():
        sha = planned[guest]['sha256']
        if item['sha256'] != sha or item['private_copy_sha256'] != sha:
            raise ValueError('guest input differs from the frozen fixture')
    if planned['C:\\GOPLAB\\RLCMP.EXE']['sha256'] != receipt['binary_sha256']:
        raise ValueError('executed native probe differs from its source build receipt')
    captured = {item['guest'].rsplit('\\', 1)[1]: item for item in files['readback']}
    logs, evidence = {}, {}
    for name in ('IETARGET.LOG', 'RLCMP.LOG', 'RLDONE.TXT'):
        item = captured[name]
        path = Path(item['path']).resolve()
        if (item['status'] != 'captured' or item.get('freshness') != 'new-in-owned-run' or
                not path.is_relative_to(run.resolve())):
            raise ValueError('missing fresh result inside the owned run: ' + name)
        raw = path.read_bytes()
        if digest(raw) != item['sha256']:
            raise ValueError('returned result digest changed: ' + name)
        logs[name] = raw
        evidence[name] = {'path': str(path), 'sha256': item['sha256']}
    target = key_values(logs['IETARGET.LOG'])
    loop = key_values(logs['RLCMP.LOG'])
    exact = (target.get('schema') == 'win98modern.iewebkit-target.v1' and
             target.get('nonce') == manifest['nonce'] and
             target.get('os') == '4.10.2222' and target.get('platform') == '1' and
             target.get('shdocvw_version') == '5.0.2614.3500' and
             target.get('iexplore_version') == '5.0.2614.3500' and
             target.get('target_matched') == '1' and
             logs['RLDONE.TXT'].strip() == manifest['nonce'].encode('ascii'))
    port = all(loop.get(key) == value for key, value in {
        'scope': 'Actual-WTF-RunLoop-Windows-API-comparison',
        'os.major': '4', 'os.minor': '10', 'os.win9x': '1',
        'ported.RegisterClassA.error': '0', 'ported.CreateWindowExA.created': '1',
        'ported.CreateWindowExA.error': '0', 'ported.GetWindowLongA.context': '1',
        'ported.WM_CREATE': '1', 'exit': '0'}.items())
    original_atom = int(loop['original.RegisterClassW.atom'])
    original_error = int(loop['original.RegisterClassW.error'])
    skipped = loop.get('original.CreateWindowExW.skipped')
    checks = {'exact_native_target': exact, 'ansi_window_context_and_create': port}
    return {
        'schema': 'win98modern.iewebkit-unicode-native-review.v1',
        'run_result_sha256': digest(raw_result), 'fixture_sha256': digest(manifest_raw),
        'probe_receipt_sha256': digest(receipt_raw), 'probe_source_sha256': source_sha,
        'backend_source_sha256': receipt['backend_sha256'],
        'probe_binary_sha256': receipt['binary_sha256'], 'nonce': manifest['nonce'],
        'evidence': evidence, 'checks': checks,
        'native_diagnostics_passed': all(checks.values()), 'guest_executed': True,
        'original_RegisterClassW': {'atom': original_atom, 'error': original_error,
            'error_name': 'ERROR_CALL_NOT_IMPLEMENTED' if original_error == 120 else None},
        'original_CreateWindowExW': {'attempted': skipped is None,
            'skipped_reason': skipped,
            'created': loop.get('original.CreateWindowExW.created')},
        'provider_status': int(target.get('provider_status', '-1')),
        'browser_trial_performed': False, 'browser_docobject_activation_verified': False,
        'engine_rendering_verified': False, 'tls_verified': False, 'release_eligible': False,
        'shutdown': 'owned QEMU exited cleanly; graceful Windows shutdown was not established',
        'acceptance_limit': 'Native API fixture using the shared port helper; not linked WTF callback or full-engine proof.'}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--probe-receipt', type=Path, required=True)
    parser.add_argument('--probe-source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = verify(args.run, args.manifest, args.probe_receipt, args.probe_source)
        with args.output.open('x') as output:
            output.write(json.dumps(report, indent=2) + '\n')
        print(json.dumps({'native_diagnostics_passed': report['native_diagnostics_passed'],
                          'original_RegisterClassW': report['original_RegisterClassW'],
                          'engine_rendering_verified': False}, indent=2))
        return 0 if report['native_diagnostics_passed'] else 1
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
