"""Authored evidence controls; these tests do not execute WTF or Windows."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / 'iewebkit_verify_wtf.py'
SPEC = importlib.util.spec_from_file_location('wtf_review', SOURCE)
REVIEW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(REVIEW)


class EvidenceControls(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.run, self.frozen = root / 'run', root / 'frozen'
        self.run.mkdir()
        (self.frozen / 'receipts').mkdir(parents=True)
        binary = self.frozen / 'WTFNAT.EXE'
        binary.write_bytes(b'authored binary control; not a native PE')
        binary_sha = REVIEW.sha(binary.read_bytes())
        self.manifest = {'schema': 1, 'kind': 'isolated-guest-file-inputs',
            'target': {'os': 'win98se', 'os_version': '4.10.2222', 'arch': 'x86'},
            'requires_nic_absent': True, 'requires_absent_guest_paths': True,
            'inputs': [{'source': str(binary), 'guest': r'C:\GOPLAB\WTFNAT.EXE',
                        'bytes': binary.stat().st_size, 'sha256': binary_sha}],
            'outputs': [r'C:\GOPLAB\WTFNAT.LOG'], 'backups': [],
            'probe_sha256': binary_sha, 'nonce': 'authored-control', 'source_receipts': []}
        linked = {'schema': 'iewebkit-real-wtf-linked-native-v1', 'link_provenance_passed': True,
            'binary': {'sha256': binary_sha, 'provenance_gate_passed': True,
                       'static_gate_passed': True, 'absent_from_media_export_baseline': [],
                       'pe': {'subsystem': 2}}, 'thin_archive_snapshots': {'pre': [], 'post': []}}
        for phase in ('pre', 'post'):
            for name in ('wtf', 'bmalloc'):
                member = {'schema': 'iewebkit-thin-archive-members-v1',
                    'archive': {'path': 'libWTF.a' if name == 'wtf' else 'libbmalloc.a'},
                    'ninja_order_verified': True, 'before_after_unchanged': True,
                    'member_count': 1, 'member_inventory_sha256': name}
                for field in REVIEW.IMMUTABLE_ARCHIVE_FIELDS:
                    member.setdefault(field, {'authored': field})
                p = self.frozen / 'receipts' / (phase + '-' + name + '-members.json')
                self.write_json(p, member)
                digest = REVIEW.sha(p.read_bytes())
                self.manifest['source_receipts'].append({'path': str(p), 'sha256': digest})
                linked['thin_archive_snapshots'][phase].append({'receipt': str(p),
                    'sha256': digest, 'members': 1, 'member_inventory_sha256': name})
        self.link_path = self.frozen / 'receipts' / 'WTFNAT.receipt.json'
        self.write_json(self.link_path, linked)
        self.manifest['source_receipts'].append({'path': str(self.link_path),
            'sha256': REVIEW.sha(self.link_path.read_bytes())})
        observer = self.frozen / 'WTFWAIT.EXE'
        observer.write_bytes(b'authored external exit observer')
        observer_sha = REVIEW.sha(observer.read_bytes())
        self.manifest['inputs'].append({'source': str(observer), 'guest': r'C:\GOPLAB\WTFWAIT.EXE',
            'bytes': observer.stat().st_size, 'sha256': observer_sha})
        observer_source = self.frozen / 'receipts' / 'iewebkit_wtf_runner.c'
        observer_source.write_bytes(b'authored C source')
        source_sha = REVIEW.sha(observer_source.read_bytes())
        observer_receipt = self.frozen / 'receipts' / 'WTFWAIT.receipt.json'
        self.write_json(observer_receipt, {'schema': 'iewebkit-win98-wtf-owned-exit-observer-v1',
            'compile_returncode': 0, 'binary': {'sha256': observer_sha, 'static_gate_passed': True},
            'source': {'path': str(observer_source), 'sha256': source_sha}})
        self.manifest['source_receipts'].extend([
            {'path': str(observer_source), 'sha256': source_sha},
            {'path': str(observer_receipt), 'sha256': REVIEW.sha(observer_receipt.read_bytes())}])
        self.manifest['outputs'].append(r'C:\GOPLAB\WTFEXIT.LOG')
        self.manifest['post_crt_exit_required'] = True
        self.values = {'scope': 'actual-pinned-WTF-archive-runtime', 'nonce': 'authored-control',
            'os.major': '4', 'os.minor': '10', 'os.build': '2222', 'os.exact-target': '1',
            'rng.A.acquired': '1', 'rng.A.generated': '1', 'wtf.initialize': '1',
            'runloop.main-current': '1', 'memory-pressure.install-repeat': '1',
            'worker.joined': '1', 'worker.done': '1', 'dispatch.count': '96',
            'worker.wtf-context': '1', 'worker.cpp-tls-cleanup': '1',
            'worker.cpp-tls-growth': '1', 'worker.cpp-tls-chained': '1',
            'timer.fired': '1', 'timer.deadline-fired': '0',
            'memory-pressure.periodic-monitor-stopped': '1', 'exit': '0'}
        self.log_path = self.run / 'guest-output-WTFNAT.LOG'
        self.exit_log_path = self.run / 'guest-output-WTFEXIT.LOG'
        self.exit_values = {'scope': 'actual-WTF-owned-child-post-CRT-exit', 'nonce': 'authored-control',
            'os.exact-target': '1', 'child.created': '1', 'child.wait': '0',
            'child.exit-query': '1', 'child.exit-code': '0', 'child.post-CRT-exit-verified': '1', 'exit': '0'}
        self.result = {'profile': 'actual-win98-uefi-csmwrap', 'qemu_exit_code': 0,
            'originals_unchanged': True, 'prepared_source_unchanged': True,
            'command': ['qemu', '-nic', 'none'], 'guest_files': {
                'immutable_sources_unchanged': True,
                'inputs': [dict(item, private_copy_sha256=item['sha256']) for item in self.manifest['inputs']],
                'readback': [{'guest': r'C:\GOPLAB\WTFNAT.LOG', 'status': 'captured',
                    'freshness': 'new-in-owned-run', 'path': str(self.log_path)},
                    {'guest': r'C:\GOPLAB\WTFEXIT.LOG', 'status': 'captured',
                    'freshness': 'new-in-owned-run', 'path': str(self.exit_log_path)}]}}
        observation = {'schema': 'xfs-fiemap-exclusive-data-v1', 'filesystem': 'xfs',
            'stable_scans': 2, 'device': 1, 'inode': 2, 'file_bytes': 2147483648,
            'block_bytes': 4096, 'helper_sha256': 'a' * 64, 'exclusive_bytes': 4096}
        self.entry = {'status': 'PASS', 'checks': {key: True for key in REVIEW.ENTRY_CHECKS},
            'cow_allocation_review': {'status': 'PASS', 'net_exclusive_growth_bytes': 0,
                                      'observation': copy.deepcopy(observation)},
            'cow_accounting_helper_sha256': 'a' * 64, 'native_runner_exit_code': 0,
            'native_result_status': 'NEEDS-VISUAL-REVIEW', 'private_dirty_allocation_quota_mib': 128}
        self.result.update({'status': 'NEEDS-VISUAL-REVIEW',
            'minimum_free_bytes': 20 * 1024 ** 3, 'free_after_run': 20 * 1024 ** 3,
            'sparse_budget': {'reserve_bytes': 20 * 1024 ** 3, 'dirty_budget_bytes': 128 * 1024 ** 2,
                'free_before_vm': 20 * 1024 ** 3, 'cow_baseline': copy.deepcopy(observation),
                'cow_latest': copy.deepcopy(observation), 'cow_net_exclusive_growth_bytes': 0,
                'cow_peak_net_exclusive_growth_bytes': 0, 'cow_quiescent_samples': 1}})
        self.flush()

    @staticmethod
    def write_json(path, value):
        path.write_text(json.dumps(value, indent=2) + '\n')

    def flush(self, extra_log=''):
        self.log_path.write_text(''.join(k + '=' + v + '\r\n' for k, v in self.values.items()) + extra_log)
        self.result['guest_files']['readback'][0]['sha256'] = REVIEW.sha(self.log_path.read_bytes())
        self.exit_log_path.write_text(''.join(k + '=' + v + '\r\n' for k, v in self.exit_values.items()))
        self.result['guest_files']['readback'][1]['sha256'] = REVIEW.sha(self.exit_log_path.read_bytes())
        self.write_json(self.frozen / 'guest-files.json', self.manifest)
        self.result['guest_files']['manifest_sha256'] = REVIEW.sha((self.frozen / 'guest-files.json').read_bytes())
        self.write_json(self.run / 'result.json', self.result)
        self.entry['native_result_sha256'] = REVIEW.sha((self.run / 'result.json').read_bytes())
        self.write_json(self.run / 'iosys-entry-result.json', self.entry)

    def review(self):
        return REVIEW.verify(self.run, self.frozen / 'guest-files.json')

    def rebind_receipt(self, path, value):
        self.write_json(path, value)
        for item in self.manifest['source_receipts']:
            if item['path'] == str(path):
                item['sha256'] = REVIEW.sha(path.read_bytes())

    def enable_diagnostic_control(self):
        scope = {'closed_checkpoint_handles': True, 'engine_behavior_modified': False}
        self.manifest['diagnostic_scope'] = scope
        self.manifest['outputs'].insert(1, r'C:\GOPLAB\WTFABRT.LOG')
        linked = json.loads(self.link_path.read_text())
        linked['diagnostic_scope'] = scope
        rows = []
        for symbol in ('___wrap_abort', '___cxa_thread_atexit', '___emutls_get_address'):
            path = self.frozen / 'receipts' / ('diagnostic-' + symbol + '.txt')
            path.write_text('authored routing boundary control; not actual disassembly')
            digest = REVIEW.sha(path.read_bytes())
            self.manifest['source_receipts'].append({'path': str(path), 'sha256': digest})
            rows.append({'symbol': symbol, 'log': str(path), 'log_sha256': digest,
                         'forward_real_abort': symbol == '___wrap_abort',
                         'wrapped_calls': 0 if symbol == '___wrap_abort' else 1})
        linked['abort_wrapper_audit'] = {'passed': True, 'symbols': rows}
        self.rebind_receipt(self.link_path, linked)
        observer_path = self.frozen / 'receipts' / 'WTFWAIT.receipt.json'
        observer = json.loads(observer_path.read_text())
        observer['closed_handle_checkpoints'] = True
        self.rebind_receipt(observer_path, observer)
        self.values['diagnostic.closed-checkpoints'] = '1'
        self.result['guest_files']['readback'].append({'guest': r'C:\GOPLAB\WTFABRT.LOG', 'status': 'unavailable'})
        self.flush()

    def test_diagnostic_control_preserves_full_engine_false(self):
        self.enable_diagnostic_control()
        result = self.review()
        self.assertEqual(result['status'], 'PASS')
        self.assertFalse(result['rendering_verified'])
        self.assertFalse(result['engine_provider_verified'])

    def test_diagnostic_missing_runtime_callsite_is_rejected(self):
        self.enable_diagnostic_control()
        linked = json.loads(self.link_path.read_text())
        linked['abort_wrapper_audit']['symbols'][2]['wrapped_calls'] = 0
        self.rebind_receipt(self.link_path, linked)
        self.flush()
        with self.assertRaisesRegex(ValueError, 'abort callsite'):
            self.review()

    def test_diagnostic_routing_text_tamper_is_rejected(self):
        self.enable_diagnostic_control()
        path = self.frozen / 'receipts' / 'diagnostic-___wrap_abort.txt'
        path.write_text('changed')
        with self.assertRaisesRegex(ValueError, 'digest changed'):
            self.review()

    def test_direct_abort_record_prevents_success_from_other_logs(self):
        self.enable_diagnostic_control()
        path = self.run / 'guest-output-WTFABRT.LOG'
        path.write_text('scope=GNU-wrapped-direct-abort\r\nnonce=authored-control\r\nabort.wrapper=1\r\n')
        self.result['guest_files']['readback'][-1].update(status='captured', path=str(path),
                                                        sha256=REVIEW.sha(path.read_bytes()))
        self.flush()
        result = self.review()
        self.assertTrue(result['checks']['external_post_crt_exit_zero'])
        self.assertFalse(result['checks']['no_direct_abort_record'])
        self.assertEqual(result['status'], 'FAIL')

    def test_complete_control_keeps_full_engine_false(self):
        result = self.review()
        self.assertEqual(result['status'], 'PASS')
        for field in ('jsc_execution_verified', 'engine_provider_verified', 'rendering_verified', 'tls_verified', 'release_eligible'):
            self.assertIs(result[field], False)

    def test_vm_health_cannot_promote_partial_native_log(self):
        self.values = {k: v for k, v in self.values.items() if k.startswith(('scope', 'nonce', 'os.', 'rng.'))}
        self.flush()
        result = self.review()
        self.assertEqual(result['status'], 'FAIL')
        self.assertTrue(result['checks']['exact_target'])
        self.assertFalse(result['checks']['genuine_wtf_initialization'])

    def test_wrong_target_deadline_join_and_dispatch_fail(self):
        original = copy.deepcopy(self.values)
        for field, value in [('os.build', '3000'), ('timer.deadline-fired', '1'),
                             ('worker.joined', '0'), ('dispatch.count', '95'),
                             ('worker.wtf-context', '0'), ('worker.cpp-tls-cleanup', '0'),
                             ('worker.cpp-tls-growth', '0'), ('worker.cpp-tls-chained', '0')]:
            with self.subTest(field=field):
                self.values = dict(original, **{field: value})
                self.flush()
                self.assertEqual(self.review()['status'], 'FAIL')

    def test_duplicate_log_field_rejected(self):
        self.flush('exit=0\r\n')
        with self.assertRaisesRegex(ValueError, 'Duplicate'):
            self.review()

    def test_reused_nonce_rejected(self):
        self.values['nonce'] = 'older-run'
        self.flush()
        with self.assertRaisesRegex(ValueError, 'nonce'):
            self.review()

    def test_returned_log_and_binary_tampering_rejected(self):
        self.log_path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'digest changed'):
            self.review()
        self.flush()
        (self.frozen / 'WTFNAT.EXE').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'digest changed'):
            self.review()

    def test_prepost_snapshot_tampering_rejected(self):
        (self.frozen / 'receipts' / 'post-wtf-members.json').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'digest changed'):
            self.review()

    def test_missing_link_provenance_rejected_even_with_valid_hashes(self):
        linked = json.loads(self.link_path.read_text())
        linked['link_provenance_passed'] = False
        self.write_json(self.link_path, linked)
        for item in self.manifest['source_receipts']:
            if Path(item['path']) == self.link_path:
                item['sha256'] = REVIEW.sha(self.link_path.read_bytes())
        self.flush()
        with self.assertRaisesRegex(ValueError, 'provenance'):
            self.review()

    def test_outside_run_readback_rejected(self):
        self.result['guest_files']['readback'][0]['path'] = str(self.frozen / 'WTFNAT.EXE')
        self.flush()
        with self.assertRaisesRegex(ValueError, 'inside'):
            self.review()

    def test_failed_owned_shutdown_or_entry_rejected(self):
        self.result['qemu_exit_code'] = 1
        self.flush()
        with self.assertRaisesRegex(ValueError, 'Stopped run'):
            self.review()
        self.result['qemu_exit_code'] = 0
        self.entry['checks']['gop_consumed_marker'] = False
        self.flush()
        with self.assertRaisesRegex(ValueError, 'Stopped run'):
            self.review()

    def test_success_log_cannot_promote_failed_post_crt_exit(self):
        self.exit_values['child.exit-code'] = '3221225477'
        self.exit_values['child.post-CRT-exit-verified'] = '0'
        self.exit_values['exit'] = '5'
        self.flush()
        result = self.review()
        self.assertTrue(result['checks']['native_exit_zero'])
        self.assertFalse(result['checks']['external_post_crt_exit_zero'])
        self.assertEqual(result['status'], 'FAIL')

    def test_allocation_and_native_runner_contradictions_rejected(self):
        original_result, original_entry = copy.deepcopy(self.result), copy.deepcopy(self.entry)
        for field in ('runner_exit', 'native_status', 'floor', 'peak', 'growth', 'identity'):
            with self.subTest(field=field):
                self.result, self.entry = copy.deepcopy(original_result), copy.deepcopy(original_entry)
                if field == 'runner_exit':
                    self.entry['native_runner_exit_code'] = 1
                elif field == 'native_status':
                    self.result['status'] = self.entry['native_result_status'] = 'FAIL'
                elif field == 'floor':
                    self.result['minimum_free_bytes'] -= 1
                elif field == 'peak':
                    self.result['sparse_budget']['cow_peak_net_exclusive_growth_bytes'] = 129 * 1024 ** 2
                elif field == 'growth':
                    self.entry['cow_allocation_review']['net_exclusive_growth_bytes'] = 1
                else:
                    self.entry['cow_allocation_review']['observation']['inode'] = 3
                self.flush()
                with self.assertRaisesRegex(ValueError, 'Stopped run'):
                    self.review()

    def test_missing_allocation_identity_cannot_pass_none_equality(self):
        for item in (self.result['sparse_budget']['cow_baseline'],
                     self.result['sparse_budget']['cow_latest'],
                     self.entry['cow_allocation_review']['observation']):
            for field in ('device', 'inode', 'file_bytes', 'block_bytes'):
                del item[field]
        self.flush()
        with self.assertRaisesRegex(ValueError, 'Stopped run'):
            self.review()

    def test_progress_context_changes_preserve_immutable_member_gate(self):
        snapshot_path = self.frozen / 'receipts' / 'post-wtf-members.json'
        linked = json.loads(self.link_path.read_text())
        member = json.loads(snapshot_path.read_text())
        for change in ('progress_only', 'immutable_input'):
            with self.subTest(change=change):
                member['core_receipt'] = {'context_progress': change}
                if change == 'immutable_input':
                    member['toolchain'] = {'changed': True}
                self.write_json(snapshot_path, member)
                snapshot_sha = REVIEW.sha(snapshot_path.read_bytes())
                linked['thin_archive_snapshots']['post'][0]['sha256'] = snapshot_sha
                self.write_json(self.link_path, linked)
                for item in self.manifest['source_receipts']:
                    if Path(item['path']) in (snapshot_path, self.link_path):
                        item['sha256'] = REVIEW.sha(Path(item['path']).read_bytes())
                self.flush()
                if change == 'progress_only':
                    self.assertEqual(self.review()['status'], 'PASS')
                else:
                    with self.assertRaisesRegex(ValueError, 'changed between'):
                        self.review()


if __name__ == '__main__':
    unittest.main()
