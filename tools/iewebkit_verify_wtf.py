#!/usr/bin/env python3
"""Review a stopped, frozen genuine-WTF Win98 trial without starting a guest."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

ENTRY_CHECKS = {
    'gdb_capture_completed', 'entry_consumed_gop_serial',
    'original_msload_resume_registers', 'entry_redirects_to_hook',
    'gop_descriptor_at_resume', 'original_vbr_stack_context',
    'original_archive_unchanged', 'emulator_healthy',
    'gop_consumed_marker', 'original_io_file_unchanged',
}
IMMUTABLE_ARCHIVE_FIELDS = (
    'archive', 'member_inventory_sha256', 'extra_object_inventory_sha256',
    'compiler_input_inventory_sha256', 'configuration', 'source_basis',
    'toolchain', 'tools', 'compiled_sources', 'inspector',
)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def bound_file(path: Path, expected: str, root: Path, limit: int) -> bytes:
    path = path.resolve()
    if not path.is_relative_to(root.resolve()) or not path.is_file():
        raise ValueError('Evidence must be a regular file inside its frozen/run directory')
    if path.stat().st_size > limit:
        raise ValueError('Evidence exceeds its bounded review size')
    raw = path.read_bytes()
    if sha(raw) != expected:
        raise ValueError('Evidence digest changed: ' + path.name)
    return raw


def log_values(raw: bytes) -> dict[str, str]:
    values = {}
    for line in raw.decode('ascii').splitlines():
        if not line or '=' not in line:
            raise ValueError('Malformed native WTF log')
        key, value = line.split('=', 1)
        if not key or key in values:
            raise ValueError('Duplicate or empty native WTF log key')
        values[key] = value
    return values


def allocation_gate(result: dict, entry: dict) -> bool:
    budget = result['sparse_budget']
    quota = budget['dirty_budget_bytes']
    reserve = budget['reserve_bytes']
    review = entry['cow_allocation_review']
    baseline, latest, final = budget['cow_baseline'], budget['cow_latest'], review['observation']
    observations = (baseline, latest, final)
    identity = ('device', 'inode', 'file_bytes', 'block_bytes', 'helper_sha256')
    helper = entry['cow_accounting_helper_sha256']
    if not isinstance(helper, str) or not re.fullmatch(r'[0-9a-f]{64}', helper):
        return False
    for item in observations:
        if (item.get('schema') != 'xfs-fiemap-exclusive-data-v1' or item.get('filesystem') != 'xfs'
                or item.get('stable_scans') != 2
                or item.get('helper_sha256') != entry['cow_accounting_helper_sha256']
                or any(type(item.get(key)) is not int or item[key] <= 0 for key in identity[:-1])
                or any(item.get(key) != baseline.get(key) for key in identity)
                or type(item.get('exclusive_bytes')) is not int or item['exclusive_bytes'] < 0):
            return False
    latest_growth = latest['exclusive_bytes'] - baseline['exclusive_bytes']
    final_growth = final['exclusive_bytes'] - baseline['exclusive_bytes']
    peak = budget['cow_peak_net_exclusive_growth_bytes']
    if (type(quota) is not int or quota != 128 * 1024 * 1024
            or entry.get('private_dirty_allocation_quota_mib') != 128
            or type(reserve) is not int or reserve < 20 * 1024 ** 3
            or budget.get('cow_net_exclusive_growth_bytes') != latest_growth
            or review.get('net_exclusive_growth_bytes') != final_growth
            or type(peak) is not int or peak < max(0, latest_growth, final_growth)
            or peak > quota or final_growth > quota
            or type(budget.get('cow_quiescent_samples')) is not int or budget['cow_quiescent_samples'] < 1):
        return False
    return all(type(value) is int and value >= reserve for value in (
        result.get('minimum_free_bytes'), result.get('free_after_run'), budget.get('free_before_vm')))


def verify(run: Path, manifest_path: Path) -> dict:
    manifest_raw = manifest_path.read_bytes()
    manifest = json.loads(manifest_raw)
    result_raw = (run / 'result.json').read_bytes()
    result = json.loads(result_raw)
    entry_raw = (run / 'iosys-entry-result.json').read_bytes()
    entry = json.loads(entry_raw)
    if (manifest.get('schema') != 1
            or manifest.get('kind') != 'isolated-guest-file-inputs'
            or manifest.get('target') != {'os': 'win98se', 'os_version': '4.10.2222', 'arch': 'x86'}
            or manifest.get('requires_nic_absent') is not True
            or manifest.get('requires_absent_guest_paths') is not True):
        raise ValueError('Require the exact isolated WTF Win98 target fixture')
    files = result['guest_files']
    command = result['command']
    if (result.get('profile') != 'actual-win98-uefi-csmwrap'
            or result.get('qemu_exit_code') != 0
            or result.get('originals_unchanged') is not True
            or result.get('prepared_source_unchanged') is not True
            or files.get('immutable_sources_unchanged') is not True
            or files.get('manifest_sha256') != sha(manifest_raw)
            or '-nic' not in command or command[command.index('-nic') + 1] != 'none'
            or entry.get('native_result_sha256') != sha(result_raw)
            or entry.get('native_runner_exit_code') != 0
            or entry.get('native_result_status') != result.get('status')
            or result.get('status') not in ('PASS', 'NEEDS-VISUAL-REVIEW')
            or entry.get('status') != 'PASS'
            or set(entry.get('checks', {})) != ENTRY_CHECKS
            or not all(value is True for value in entry['checks'].values())
            or entry.get('cow_allocation_review', {}).get('status') != 'PASS'
            or not allocation_gate(result, entry)):
        raise ValueError('Stopped run, IO.SYS, allocation, fixture or source-preservation gate failed')
    inputs = {item['guest']: item for item in manifest['inputs']}
    observed = {item['guest']: item for item in files['inputs']}
    expected_inputs = {r'C:\GOPLAB\WTFNAT.EXE', r'C:\GOPLAB\WTFWAIT.EXE'}
    diagnostic = manifest.get('diagnostic_scope')
    expected_outputs = [r'C:\GOPLAB\WTFNAT.LOG', r'C:\GOPLAB\WTFEXIT.LOG']
    if diagnostic is not None:
        if (not isinstance(diagnostic, dict)
                or diagnostic.get('closed_checkpoint_handles') is not True
                or diagnostic.get('engine_behavior_modified') is not False):
            raise ValueError('Invalid genuine closed-checkpoint diagnostic scope')
        expected_outputs.insert(1, r'C:\GOPLAB\WTFABRT.LOG')
    if (set(inputs) != expected_inputs or set(observed) != expected_inputs
            or len(manifest['inputs']) != 2 or len(files['inputs']) != 2
            or manifest['outputs'] != expected_outputs
            or manifest.get('backups') != []
            or manifest.get('post_crt_exit_required') is not True
            or any(type(item.get('bytes')) is not int or item['bytes'] <= 0 for item in inputs.values())
            or sum(item['bytes'] for item in inputs.values()) > 64 * 1024 * 1024):
        raise ValueError('Require the WTF-only input/output scope')
    for guest, item in inputs.items():
        if (observed[guest]['sha256'] != item['sha256']
                or observed[guest]['private_copy_sha256'] != item['sha256']):
            raise ValueError('Executed PE differs from the frozen fixture')
        raw = bound_file(Path(item['source']), item['sha256'], manifest_path.parent, 64 * 1024 * 1024)
        if len(raw) != item['bytes']:
            raise ValueError('Frozen PE length changed')
    planned = inputs[r'C:\GOPLAB\WTFNAT.EXE']
    if manifest['probe_sha256'] != planned['sha256']:
        raise ValueError('Executed PE differs from the frozen fixture')
    receipts = {}
    bindings = []
    for item in manifest['source_receipts']:
        path = Path(item['path'])
        if path.name in receipts:
            raise ValueError('Ambiguous frozen receipt name')
        raw = bound_file(path, item['sha256'], manifest_path.parent / 'receipts', 4 * 1024 * 1024)
        receipts[path.name] = (raw, item['sha256'])
        bindings.append({'path': str(path), 'sha256': item['sha256'], 'bytes': len(raw)})
    linked = json.loads(receipts['WTFNAT.receipt.json'][0])
    observer = json.loads(receipts['WTFWAIT.receipt.json'][0])
    if (observer.get('schema') != 'iewebkit-win98-wtf-owned-exit-observer-v1'
            or observer.get('compile_returncode') != 0
            or observer['binary'].get('static_gate_passed') is not True
            or observer['binary']['sha256'] != inputs[r'C:\GOPLAB\WTFWAIT.EXE']['sha256']
            or observer['source']['sha256'] != receipts[Path(observer['source']['path']).name][1]):
        raise ValueError('External exit observer binary/source/import gate failed')
    pe = linked['binary']
    if (linked.get('schema') != 'iewebkit-real-wtf-linked-native-v1'
            or linked.get('link_provenance_passed') is not True
            or pe.get('provenance_gate_passed') is not True
            or pe.get('static_gate_passed') is not True
            or pe['sha256'] != planned['sha256']
            or pe.get('absent_from_media_export_baseline')
            or pe['pe']['subsystem'] != 2):
        raise ValueError('Genuine linked PE provenance/import gate failed')
    if diagnostic is not None:
        wrapper = linked.get('abort_wrapper_audit', {})
        required = {'___wrap_abort', '___cxa_thread_atexit', '___emutls_get_address'}
        rows = wrapper.get('symbols', [])
        if (linked.get('diagnostic_scope') != diagnostic or wrapper.get('passed') is not True
                or observer.get('closed_handle_checkpoints') is not True
                or len(rows) != 3 or {row.get('symbol') for row in rows} != required):
            raise ValueError('Missing exact compiled diagnostic/observer routing evidence')
        for row in rows:
            name = Path(row['log']).name
            if name not in receipts or receipts[name][1] != row['log_sha256']:
                raise ValueError('Unbound actual abort-routing disassembly')
            if row['symbol'] == '___wrap_abort':
                if row.get('forward_real_abort') is not True:
                    raise ValueError('Diagnostic wrapper does not forward real abort')
            elif type(row.get('wrapped_calls')) is not int or row['wrapped_calls'] < 1:
                raise ValueError('Missing actual paired-runtime abort callsite')
    snapshots = linked['thin_archive_snapshots']
    if len(snapshots['pre']) != 2 or len(snapshots['post']) != 2:
        raise ValueError('Missing complete pre/post WTF and bmalloc snapshots')
    stages = []
    for stage in ('pre', 'post'):
        archives = {}
        for snapshot in snapshots[stage]:
            raw, receipt_sha = receipts[Path(snapshot['receipt']).name]
            member = json.loads(raw)
            name = Path(member['archive']['path']).name
            if (receipt_sha != snapshot['sha256']
                    or member.get('schema') != 'iewebkit-thin-archive-members-v1'
                    or member.get('ninja_order_verified') is not True
                    or member.get('before_after_unchanged') is not True
                    or member['member_count'] != snapshot['members']
                    or member['member_inventory_sha256'] != snapshot['member_inventory_sha256']
                    or name in archives):
                raise ValueError('Frozen archive-member snapshot gate failed')
            # Progress-only core-build context is not a link input. Bind every
            # frozen receipt's own digest above, then compare the linker's
            # complete required immutable subset across the two observations.
            archives[name] = {key: member[key] for key in IMMUTABLE_ARCHIVE_FIELDS}
        if set(archives) != {'libWTF.a', 'libbmalloc.a'}:
            raise ValueError('Wrong genuine archive set')
        stages.append(archives)
    if stages[0] != stages[1]:
        raise ValueError('Genuine linked members changed between pre/post observations')
    outputs = [item for item in files['readback'] if item['guest'] == r'C:\GOPLAB\WTFNAT.LOG']
    if len(outputs) != 1:
        raise ValueError('Missing or ambiguous stopped-disk readback record')
    output = outputs[0]
    values, evidence = {}, {'status': output['status']}
    if output['status'] == 'captured':
        if output.get('freshness') != 'new-in-owned-run':
            raise ValueError('Require a fresh log in the owned run')
        raw = bound_file(Path(output['path']), output['sha256'], run, 64 * 1024)
        values = log_values(raw)
        if values.get('nonce') != manifest['nonce']:
            raise ValueError('Native nonce belongs to a different trial')
        evidence.update({'path': output['path'], 'sha256': output['sha256'], 'bytes': len(raw)})
    exit_outputs = [item for item in files['readback'] if item['guest'] == r'C:\GOPLAB\WTFEXIT.LOG']
    if len(exit_outputs) != 1:
        raise ValueError('Missing or ambiguous external exit observation')
    exit_output = exit_outputs[0]
    exit_values, exit_evidence = {}, {'status': exit_output['status']}
    if exit_output['status'] == 'captured':
        if exit_output.get('freshness') != 'new-in-owned-run':
            raise ValueError('External exit observer log is not fresh')
        raw = bound_file(Path(exit_output['path']), exit_output['sha256'], run, 64 * 1024)
        exit_values = log_values(raw)
        if exit_values.get('nonce') != manifest['nonce']:
            raise ValueError('External exit observer nonce belongs to a different trial')
        exit_evidence.update({'path': exit_output['path'], 'sha256': exit_output['sha256'], 'bytes': len(raw)})
    checks = {
        'exact_target': all(values.get(k) == v for k, v in {
            'scope': 'actual-pinned-WTF-archive-runtime', 'os.major': '4',
            'os.minor': '10', 'os.build': '2222', 'os.exact-target': '1'}.items()),
        'ansi_crypto': values.get('rng.A.acquired') == '1' and values.get('rng.A.generated') == '1',
        'genuine_wtf_initialization': values.get('wtf.initialize') == '1',
        'main_runloop_current': values.get('runloop.main-current') == '1',
        'repeat_pressure_install': values.get('memory-pressure.install-repeat') == '1',
        'worker_dispatch_and_join': all(values.get(k) == v for k, v in {
            'worker.joined': '1', 'worker.done': '1', 'dispatch.count': '96'}.items()),
        'worker_wtf_cpp_tls_cleanup': all(values.get(k) == '1' for k in (
            'worker.wtf-context', 'worker.cpp-tls-cleanup',
            'worker.cpp-tls-growth', 'worker.cpp-tls-chained')),
        'timer_without_deadline': values.get('timer.fired') == '1' and values.get('timer.deadline-fired') == '0',
        'periodic_monitor_stopped': values.get('memory-pressure.periodic-monitor-stopped') == '1',
        'native_exit_zero': values.get('exit') == '0',
        'external_post_crt_exit_zero': all(exit_values.get(k) == v for k, v in {
            'scope': 'actual-WTF-owned-child-post-CRT-exit', 'os.exact-target': '1',
            'child.created': '1', 'child.wait': '0', 'child.exit-query': '1',
            'child.exit-code': '0', 'child.post-CRT-exit-verified': '1', 'exit': '0'}.items()),
    }
    abort_evidence = None
    if diagnostic is not None:
        abort_rows = [row for row in files['readback'] if row['guest'] == r'C:\GOPLAB\WTFABRT.LOG']
        if len(abort_rows) != 1:
            raise ValueError('Missing or ambiguous stopped abort-output observation')
        item = abort_rows[0]
        abort_evidence = {'status': item['status'], 'scope': 'Direct wrapped abort only; no system CRT internal coverage'}
        if item['status'] == 'captured':
            raw = bound_file(Path(item['path']), item['sha256'], run, 64 * 1024)
            fields = log_values(raw)
            if fields and (fields.get('nonce') != manifest['nonce']
                           or fields.get('scope') != 'GNU-wrapped-direct-abort'):
                raise ValueError('Abort record belongs to another scope or nonce')
            abort_evidence.update(path=item['path'], sha256=item['sha256'], bytes=len(raw), fields=fields)
        checks['diagnostic_closed_checkpoints'] = values.get('diagnostic.closed-checkpoints') == '1'
        # An absent abort file alone never establishes success. All real
        # initializer/thread/observer exit gates above must also pass.
        checks['no_direct_abort_record'] = item['status'] != 'captured'
    return {'schema': 'win98modern.genuine-wtf-native-review.v1',
            'status': 'PASS' if all(checks.values()) else 'FAIL',
            'run_result_sha256': sha(result_raw), 'io_entry_result_sha256': sha(entry_raw),
            'fixture_sha256': sha(manifest_raw), 'probe_sha256': planned['sha256'],
            'nonce': manifest['nonce'], 'receipt_bindings': bindings, 'log': evidence,
            'checks': checks, 'observed_native_fields': values,
            'external_exit_log': exit_evidence, 'observed_external_exit_fields': exit_values,
            'diagnostic_abort_log': abort_evidence,
            'guest_executed': bool(values), 'jsc_execution_verified': False,
            'engine_provider_verified': False, 'rendering_verified': False,
            'tls_verified': False, 'release_eligible': False,
            'scope': 'Genuine frozen WTF/allocator/ICU runtime caller only; VM health does not imply application success.',
            'cleanup_limit': 'Owned child OS exit observed after CRT/TLS teardown; separate DLL lifetime and full allocator leak accounting are unverified.'}


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
        print(json.dumps({'status': report['status'], 'checks': report['checks'], 'rendering_verified': False}))
        return 0 if report['status'] == 'PASS' else 1
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
