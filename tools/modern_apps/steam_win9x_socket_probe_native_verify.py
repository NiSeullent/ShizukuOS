#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Review exact stopped Steam socket artifacts; parent provenance review remains required."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

import steam_win9x_socket_probe_native_control as control
from steam_win9x_socket_probe_native_allocation import allocation_gate
from steam_win9x_socket_probe_verify import review as review_probe_log

ENTRY_CHECKS = {'gdb_capture_completed', 'entry_consumed_gop_serial', 'original_msload_resume_registers',
                'entry_redirects_to_hook', 'gop_descriptor_at_resume', 'original_vbr_stack_context',
                'original_archive_unchanged', 'emulator_healthy', 'gop_consumed_marker', 'original_io_file_unchanged'}
OBSERVER_FIELDS = ('scope', 'nonce', 'source.version', 'steam.application-executed', 'os.platform', 'os.major',
                   'os.minor', 'os.build-low', 'os.exact-target', 'child.created', 'child.create-error', 'child.pid',
                   'child.thread-handle-closed', 'child.deadline-ms', 'child.wait', 'child.wait-error',
                   'child.exit-query', 'child.exit-code', 'child.process-handle-closed',
                   'child.post-CRT-exit-verified', 'steam.application-passed', 'exit')


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bound(path: Path, expected: str, root: Path, limit: int) -> bytes:
    path = path.resolve(strict=True)
    if not path.is_relative_to(root.resolve(strict=True)) or not path.is_file() or path.stat().st_size > limit:
        raise ValueError('Evidence must remain a bounded regular file in its exact directory')
    data = path.read_bytes()
    if sha(data) != expected:
        raise ValueError('Saved native evidence digest changed')
    return data


def review_observer_log(data: bytes, nonce: str) -> dict:
    if not re.fullmatch(r'83bd-steam-socket-[0-9a-f]{32}', nonce):
        raise ValueError('Expected the exact Steam socket trial nonce shape')
    if not data or len(data) > 65536 or not data.endswith(b'\r\n'):
        raise ValueError('Observer log is empty, oversized or incomplete')
    try:
        lines = data.decode('ascii').split('\r\n')[:-1]
    except UnicodeDecodeError as error:
        raise ValueError('Observer log must be ASCII') from error
    fields = {}
    for line in lines:
        if line.count('=') != 1:
            raise ValueError('Malformed observer checkpoint')
        key, value = line.split('=', 1)
        if key not in OBSERVER_FIELDS or key in fields:
            raise ValueError('Unknown or duplicate observer checkpoint')
        fields[key] = value
    if set(fields) != set(OBSERVER_FIELDS) or lines[-1] != 'exit=0':
        raise ValueError('Missing required observer checkpoint or final zero exit')
    expected = {'scope': 'steam-native-win98-loopback-owned-child-exit', 'nonce': nonce, 'source.version': '1',
                'steam.application-executed': '0', 'os.platform': '1', 'os.major': '4', 'os.minor': '10',
                'os.build-low': '2222', 'os.exact-target': '1', 'child.created': '1', 'child.create-error': '0',
                'child.thread-handle-closed': '1', 'child.deadline-ms': '90000', 'child.wait': '0',
                'child.wait-error': '0', 'child.exit-query': '1', 'child.exit-code': '0',
                'child.process-handle-closed': '1', 'child.post-CRT-exit-verified': '1',
                'steam.application-passed': '0', 'exit': '0'}
    if any(fields[key] != value for key, value in expected.items()):
        raise ValueError('Observer target, owned child or post-CRT exit checkpoint failed')
    if not re.fullmatch(r'[1-9][0-9]{0,9}', fields['child.pid']) or int(fields['child.pid']) > 0xFFFFFFFF:
        raise ValueError('Observer child PID is invalid')
    return {'complete_consistent_observer_log': True, 'child_pid': int(fields['child.pid']),
            'post_crt_zero_exit_claim_consistent': True, 'log_sha256': sha(data), 'log_size_bytes': len(data),
            'metadata_origin': 'self-reported stopped observer log', 'native_execution_verified': False,
            'steam_application_passed': False}


def receipt_bindings(manifest: dict) -> tuple[list, list]:
    rows, headers = [], []
    by_path = {}
    for item in manifest['source_receipts']:
        path = Path(item['path'])
        raw = bound(path, item['sha256'], control.FIXTURE.parent / 'receipts', 4 * 1024**2)
        by_path[str(path)] = (raw, item['sha256'])
        rows.append({'path': str(path), 'sha256': item['sha256'], 'bytes': len(raw)})
    origin_map = {item['origin']: item for item in manifest['source_receipt_origins']}
    if len(origin_map) != len(manifest['source_receipt_origins']) or len(rows) != 17:
        raise ValueError('Frozen source/header/import receipt binding is ambiguous')
    for item in manifest['source_receipt_origins']:
        frozen = Path(item['frozen'])
        bound(frozen, item['sha256'], control.FIXTURE.parent, 4 * 1024**2)
        original = Path(item['origin'])
        if not original.is_file() or sha(original.read_bytes()) != item['sha256']:
            raise ValueError('Genuine build/source origin changed')
    for label, name, schema in (('probe', 'SPROB.EXE', 'steam.win9x-socket-prerequisite-build.v1'),
                               ('observer', 'SPWAIT.EXE', 'steam.win9x-socket-owned-observer-build.v1')):
        path = control.FIXTURE.parent / 'receipts' / (label + '-09-receipt.json')
        receipt = json.loads(by_path[str(path)][0])
        if (receipt.get('schema') != schema or receipt.get('source_and_static_gate_passed') is not True
                or receipt.get('inputs_unchanged_after_build') is not True or receipt.get('compiler_exit') != 0
                or receipt.get('abort_reason') is not None or receipt.get('steam_application_passed') is not False):
            raise ValueError('Actual compiler/source/import receipt gate failed')
        binary = receipt['pe_audit']['binary']
        actual = next(item for item in manifest['inputs'] if item['guest'].endswith('\\' + name))
        audit = receipt['pe_audit']
        if (binary['sha256'] != actual['sha256'] or binary['size_bytes'] != actual['bytes']
                or audit['pe']['machine'] != 0x14C or audit['pe']['format'] != 'PE32'
                or audit['pe']['subsystem'] != 2 or audit['pe']['subsystem_version'] != [4, 0]
                or audit['os_version'] != [4, 0] or audit['import_inventory_complete'] is not True
                or audit['absent_from_native_media_exports']):
            raise ValueError('Actual native PE/import baseline gate failed')
        for source in receipt['source_inputs']:
            item = origin_map.get(source['path'])
            if item is None or item['sha256'] != source['sha256']:
                raise ValueError('Actual compiled source is absent from frozen origin bindings')
        item = origin_map.get(receipt['actual_header_inventory']['path'])
        if item is None or item['sha256'] != receipt['actual_header_inventory']['sha256']:
            raise ValueError('Actual transitive header inventory is unbound')
        inventory = json.loads(by_path[item['frozen']][0])
        if len(inventory) != receipt['actual_header_count'] or len(inventory) != 166:
            raise ValueError('Actual MinGW header inventory count changed')
        headers.append({'build': label, 'actual_header_count': len(inventory), 'inventory_sha256': item['sha256'],
                        'compiler_sha256': receipt['compiler']['sha256'], 'complete_implicit_archive_closure_verified': False})
    return rows, headers


def verify(run: Path, manifest_path: Path) -> dict:
    run = run.resolve(strict=True)
    if run.parent != control.RUNS or not re.fullmatch(r'win98-iosys-gop-steam-socket-83bd-[a-z0-9]+', run.name):
        raise ValueError('Review requires an exact owned Steam socket run directory')
    if manifest_path.resolve(strict=True) != control.FIXTURE:
        raise ValueError('Only the exact frozen-native-v1 fixture is permitted')
    manifest, command = control.validate_manifest(control.FIXTURE, control.FIXTURE_SHA)
    result_raw, entry_raw = (run / 'result.json').read_bytes(), (run / 'iosys-entry-result.json').read_bytes()
    if len(result_raw) > 4 * 1024**2 or len(entry_raw) > 4 * 1024**2:
        raise ValueError('Stopped trial records exceed their bounded scope')
    result, entry = json.loads(result_raw), json.loads(entry_raw)
    files = result['guest_files']
    if (result.get('profile') != 'actual-win98-uefi-csmwrap' or type(result.get('qemu_exit_code')) is not int or result['qemu_exit_code'] != 0
            or result.get('status') not in ('PASS', 'NEEDS-VISUAL-REVIEW')
            or result.get('originals_unchanged') is not True or result.get('prepared_source_unchanged') is not True
            or files.get('immutable_sources_unchanged') is not True or files.get('manifest') != str(control.FIXTURE)
            or files.get('manifest_sha256') != control.FIXTURE_SHA or files.get('outputs') != manifest['outputs']
            or files.get('output_baseline') != 'all absent before private injection'
            or files.get('installed_gop_replacement') != [] or files.get('backups') != []
            or not control.owned_qemu_args(result['command'], run)
            or entry.get('native_result_sha256') != sha(result_raw)
            or type(entry.get('native_runner_exit_code')) is not int or entry['native_runner_exit_code'] != 0
            or entry.get('native_result_status') != result['status'] or entry.get('status') != 'PASS'
            or set(entry.get('checks', {})) != ENTRY_CHECKS or not all(value is True for value in entry['checks'].values())
            or entry.get('capsule', {}).get('io_sys', {}).get('sha256') != manifest['target']['original_io_sys_sha256']
            or entry.get('cow_allocation_review', {}).get('status') != 'PASS' or not allocation_gate(result, entry)):
        raise ValueError('Stopped guest, actual IO.SYS/GOP, preservation or unchanged allocation gate failed')
    planned = {row['guest']: row for row in files['inputs']}
    if len(files['inputs']) != 2 or set(planned) != control.INPUTS:
        raise ValueError('Observed guest input scope differs from exact two PEs')
    for item in manifest['inputs']:
        row = planned[item['guest']]
        if any(row.get(key) != item[key] for key in ('source', 'bytes', 'sha256')) or row.get('private_copy_sha256') != item['sha256']:
            raise ValueError('Executed input differs from its frozen exact PE')
    bindings, headers = receipt_bindings(manifest)
    driver = control.read_json(run / 'steam-socket-control-driver.json')
    if (driver.get('schema') != 'win98modern.steam-socket-owned-control.v1'
            or driver.get('manifest_sha256') != control.FIXTURE_SHA or driver.get('application_pass') is not False
            or driver.get('steam_application_passed') is not False or driver.get('native_probe_execution_verified') is not False
            or driver.get('launch_command_acknowledged') is not True
            or driver.get('control_source_sha256') != sha(Path(control.__file__).read_bytes())
            or type(driver.get('qemu_pid')) is not int or driver['qemu_pid'] < 2
            or (Path('/proc') / str(driver['qemu_pid'])).exists()):
        raise ValueError('Missing exact finished owned-controller provenance')
    driver_actions = driver.get('actions', [])
    runner_actions = result.get('gui_interaction', {}).get('actions', [])
    launches = [row for row in driver_actions if row.get('name') == 'launch-exact-frozen-steam-socket-observer']
    if len(launches) != 1 or launches[0].get('typed') != command:
        raise ValueError('Missing unique exact observer launch acknowledgement')
    if not driver_actions or len(driver_actions) > 32:
        raise ValueError('Owned GUI acknowledgement scope is missing or oversized')
    prior = 0
    for action in driver_actions:
        if type(action.get('sequence')) is not int or action['sequence'] <= prior:
            raise ValueError('Owned GUI sequence is ambiguous')
        prior = action['sequence']
        matches = [row for row in runner_actions if row.get('sequence') == prior]
        if len(matches) != 1 or any(matches[0].get(key) != action.get(key) for key in ('name', 'keys', 'typed', 'screenshot', 'status')):
            raise ValueError('Controller acknowledgement differs from actual runner record')
        if action.get('status') != 'sent; application effect requires screenshot/readback verification':
            raise ValueError('An owned GUI action did not complete')
        image = Path(action['screenshot'])
        data = bound(image, action['review_driver_screenshot_sha256'], run, 16 * 1024**2)
        if image.parent != run or not data.startswith(b'\x89PNG\r\n\x1a\n'):
            raise ValueError('Acknowledged GUI screenshot is invalid')
    rows = files.get('readback', [])
    if len(rows) != 2 or {row.get('guest') for row in rows} != control.OUTPUTS:
        raise ValueError('Stopped readback must contain exactly the two diagnostic logs')
    reviews, errors = {}, {}
    for guest, function in ((r'C:\GOPLAB\SPROB.LOG', review_probe_log), (r'C:\GOPLAB\SPWAIT.LOG', review_observer_log)):
        row = next(row for row in rows if row['guest'] == guest)
        if row.get('status') != 'captured' or row.get('freshness') != 'new-in-owned-run':
            errors[guest] = 'Missing fresh stopped diagnostic log'
            continue
        raw = bound(Path(row['path']), row['sha256'], run, 65536)
        if len(raw) != row.get('bytes'):
            raise ValueError('Stopped log length differs from readback record')
        try:
            reviews[guest] = function(raw, manifest['nonce'])
        except ValueError as error:
            errors[guest] = str(error)
    consistent = len(reviews) == 2 and not errors
    return {'schema': 'steam.win9x-socket-stopped-artifact-review.v1',
            'status': 'CONSISTENT_STOPPED_ARTIFACTS_REQUIRING_PARENT_REVIEW' if consistent else 'FAIL',
            'fixture_sha256': control.FIXTURE_SHA, 'nonce': manifest['nonce'], 'run_result_sha256': sha(result_raw),
            'io_entry_result_sha256': sha(entry_raw), 'driver_sha256': sha((run / 'steam-socket-control-driver.json').read_bytes()),
            'source_and_import_receipt_bindings': bindings, 'actual_header_provenance': headers,
            'consistent_stopped_trial_artifacts': consistent, 'log_reviews': reviews, 'log_errors': errors,
            'actual_target_os_checkpoint_consistent': consistent, 'owned_child_post_crt_zero_exit_checkpoint_consistent': consistent,
            'native_probe_execution_verified': False, 'native_prerequisite_passed': False, 'steam_application_executed': False,
            'steam_application_passed': False, 'requires_independent_parent_provenance_review': True,
            'scope': 'Digest-bound saved artifacts and self-reported native checkpoints; synthetic logs never become native evidence.'}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, default=control.FIXTURE)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    try:
        result = verify(args.run, args.manifest)
        with args.output.open('x') as stream:
            stream.write(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'status': result['status'], 'native_probe_execution_verified': False, 'steam_application_passed': False}))
        return 0 if result['consistent_stopped_trial_artifacts'] else 1
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
