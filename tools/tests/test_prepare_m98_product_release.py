#!/usr/bin/env python3
"""Small synthetic receipts test admission logic; no guest or product proof."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

TOOL = Path(__file__).resolve().parents[1] / 'prepare_m98_product_release.py'
spec = importlib.util.spec_from_file_location('release_prep', TOOL) if TOOL.exists() else None
prep = importlib.util.module_from_spec(spec) if spec else None
if spec:
    spec.loader.exec_module(prep)

CHECKS = {
    'public_iso': ['no Microsoft media or secrets', 'project installer and corresponding source closure', 'builder artifact and source identities verified'],
    'windows98_boot': ['actual Windows 98 started on ShizukuDOS', 'original Microsoft DOS absent from boot chain'],
    'windows98_vmm': ['VMM schedules Windows threads', 'actual asynchronous PMA wait and wake', 'actual DOS executor context'],
    'native_smp': ['two or more native PMA CPUs execute work', 'concurrent work progresses on separate CPUs', 'VMM scheduling authority preserved'],
    'iso_bios': ['exact public ISO boots through BIOS'],
    'iso_uefi': ['exact public ISO boots through UEFI'],
    'installation': ['project installer executes', 'cancel writes no target bytes', 'installed Windows 98 on ShizukuDOS cold boots', 'installed data persists after restart'],
    'full_goal': ['Fixture App executes required functions', 'fixture wrapper support and rejection',
                  'fixture Win16 and Win32 regression', 'fixture UP AP failure and epoch cleanup',
                  'fixture required web features'],
}
ARTIFACTS = ('public_iso', 'boot_loader', 'dos_foundation', 'kernel32', 'kernel64', 'vxd', 'installer')


def pin(path):
    data = path.read_bytes()
    return {'path': str(path), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}


class ReleasePreparationTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(prep, 'full product release admission gate is missing')
        self.tmp = tempfile.TemporaryDirectory(prefix='m98-prep-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / 'source'
        self.source.mkdir()
        (self.source / 'runner.py').write_text('# test fixture runner identity only\n')
        (self.source / 'kernel.c').write_text('int test_fixture;\n')
        specs = []
        for role in ('win98_architecture', 'shizukudos10_integration'):
            name = role + '.txt'
            (self.source / name).write_text('synthetic original spec fixture for ' + role + '\n')
            specs.append({'role': role, 'path': name, 'sha256': pin(self.source / name)['sha256']})
        categories = {'public_iso': 'distribution', 'windows98_boot': 'windows98_integration',
                      'windows98_vmm': 'vmm_authority', 'native_smp': 'pma_scheduling_smp',
                      'iso_bios': 'dos_foundation', 'iso_uefi': 'display_gop',
                      'installation': 'installer', 'full_goal': 'modern_applications'}
        requirements = [{'id': 'goal.' + role, 'category': categories[role], 'description': 'Concrete fixture behavior for ' + role,
                         'gate': role, 'checks': [labels[0]],
                         'applications': [{'name': 'Fixture App', 'version': None}] if role == 'full_goal' else []}
                        for role, labels in CHECKS.items()]
        for category, label in zip(('nt_wrapper_compatibility', 'legacy_win16_win32', 'failure_lifecycle', 'modern_web_features'), CHECKS['full_goal'][1:]):
            requirements.append({'id': 'goal.' + category, 'category': category, 'description': label,
                                 'gate': 'full_goal', 'checks': [label], 'applications': []})
        self.contract = {'schema': 'shizukuos.requirements.v1', 'scope': 'product-ShizukuOS-1.0.0',
                         'source_specs': specs, 'requirements': requirements}
        (self.source / 'goal.json').write_text(json.dumps(self.contract))
        subprocess.run(['git', 'init', '-q', str(self.source)], check=True)
        subprocess.run(['git', '-C', str(self.source), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(self.source), '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture'], check=True)
        self.commit = subprocess.check_output(['git', '-C', str(self.source), 'rev-parse', 'HEAD'], text=True).strip()
        self.sources = {name: pin(self.source / name)['sha256'] for name in
                        ('runner.py', 'kernel.c', 'goal.json', 'win98_architecture.txt', 'shizukudos10_integration.txt')}
        self.artifacts = {}
        for role in ARTIFACTS:
            path = self.root / (role + ('.iso' if role == 'public_iso' else '.bin'))
            path.write_bytes(('project test fixture ' + role).encode())
            self.artifacts[role] = pin(path)
        self.gates = {}
        self.proofs = {}
        for role, labels in CHECKS.items():
            output = self.root / (role + '.log')
            output.write_text('synthetic unit fixture for ' + role + '; this is not execution evidence\n')
            proof = {'schema': 'shizukuos.full-release-gate.v1', 'scope': 'product-ShizukuOS-1.0.0',
                     'gate': role, 'status': 'PASS', 'source_commit': self.commit, 'goal_contract_sha256': self.sources['goal.json'],
                     'execution': 'actual-readback' if role == 'public_iso' else 'actual-guest',
                     'modeled': False, 'component_only': False,
                     'runner': {'path': 'runner.py', 'sha256': self.sources['runner.py']},
                     'sources_sha256': self.sources,
                     'artifacts_sha256': {name: row['sha256'] for name, row in self.artifacts.items()},
                     'outputs': [pin(output)],
                     'checks': [{'check': label, 'status': 'PASS', 'output_sha256': [pin(output)['sha256']]}
                                for label in labels]}
            path = self.root / (role + '.json')
            path.write_text(json.dumps(proof))
            self.proofs[role] = proof
            self.gates[role] = {'receipt': pin(path), 'runner': proof['runner'], 'sources_sha256': self.sources}
        self.manifest = {'schema': 'shizukuos.full-release-index.v1', 'scope': 'product-ShizukuOS-1.0.0',
                         'release_id': 'shizukuos-1.0.0-test', 'source_commit': self.commit,
                         'goal_contract': {'path': 'goal.json', 'sha256': self.sources['goal.json']},
                         'artifacts': self.artifacts, 'gates': self.gates}
        self.proofs['full_goal']['requirements'] = [
            {'id': r['id'], 'status': 'PASS',
             'checks': [{'check': label, 'status': 'PASS', 'output_sha256': [self.proofs[r['gate']]['outputs'][0]['sha256']]} for label in r['checks']],
             'applications': [{'name': a['name'], 'version': a['version'] or '1.2.3',
                               'output_sha256': [self.proofs[r['gate']]['outputs'][0]['sha256']]}
                              for a in r['applications']]}
            for r in requirements]
        self.replace_proof('full_goal')

    def inspect(self):
        path = self.root / 'index.json'
        path.write_text(json.dumps(self.manifest))
        return prep.inspect_index(path, pin(path)['sha256'], self.source)

    def replace_proof(self, role):
        path = Path(self.gates[role]['receipt']['path'])
        path.write_text(json.dumps(self.proofs[role]))
        self.gates[role]['receipt'] = pin(path)

    def reseal_contract(self):
        (self.source / 'goal.json').write_text(json.dumps(self.contract))
        subprocess.run(['git', '-C', str(self.source), 'add', 'goal.json'], check=True)
        subprocess.run(['git', '-C', str(self.source), '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'changed test contract'], check=True)
        self.commit = subprocess.check_output(['git', '-C', str(self.source), 'rev-parse', 'HEAD'], text=True).strip()
        self.sources['goal.json'] = pin(self.source / 'goal.json')['sha256']
        self.manifest['source_commit'] = self.commit
        self.manifest['goal_contract']['sha256'] = self.sources['goal.json']
        for role, proof in self.proofs.items():
            proof['source_commit'] = self.commit; proof['goal_contract_sha256'] = self.sources['goal.json']
            self.replace_proof(role)

    def test_complete_bound_receipts_validate_without_execution_or_publication(self):
        report = self.inspect()
        self.assertEqual(report['status'], 'ACCEPTANCE_RECEIPTS_VALIDATED')
        self.assertFalse(report['guest_executed'])
        self.assertFalse(report['published'])
        self.assertEqual(set(report['gates']), set(CHECKS))
        self.assertEqual(report['goal_contract'], self.manifest['goal_contract'])
        self.assertEqual(report['requirements'], {'total': 12, 'passed': 12, 'blocked': []})

    def test_repeated_unpinned_hash_and_generic_full_goal_are_not_acceptance(self):
        self.manifest['goal_contract_sha256'] = self.manifest.pop('goal_contract')['sha256']
        self.proofs['full_goal'].pop('requirements')
        self.proofs['full_goal']['checks'] = [{'check': 'every requested requirement and application passed', 'status': 'PASS'}]
        self.replace_proof('full_goal')
        with self.assertRaises(ValueError):
            self.inspect()

    def test_missing_gate_blocks_instead_of_certifying_component_results(self):
        del self.manifest['gates']['windows98_vmm']
        report = self.inspect()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertIn('windows98_vmm', report['missing_gates'])

    def test_failed_check_blocks_even_when_receipt_top_level_says_pass(self):
        self.proofs['native_smp']['checks'][0]['status'] = 'FAIL'
        self.replace_proof('native_smp')
        self.assertEqual(self.inspect()['status'], 'BLOCKED')

    def test_boolean_only_scope_and_modeled_receipts_are_rejected(self):
        for field, bad in (('modeled', True), ('component_only', True), ('execution', 'host-model'), ('scope', 'Kernel64-standalone')):
            with self.subTest(field=field):
                original = self.proofs['windows98_boot'][field]
                self.proofs['windows98_boot'][field] = bad
                self.replace_proof('windows98_boot')
                with self.assertRaises(ValueError): self.inspect()
                self.proofs['windows98_boot'][field] = original
                self.replace_proof('windows98_boot')

    def test_stale_source_commit_and_different_goal_cannot_pass(self):
        for field in ('source_commit', 'goal_contract_sha256'):
            original = self.proofs['full_goal'][field]
            self.proofs['full_goal'][field] = 'f' * len(original)
            self.replace_proof('full_goal')
            with self.assertRaises(ValueError): self.inspect()
            self.proofs['full_goal'][field] = original
            self.replace_proof('full_goal')

    def test_wrong_artifact_or_omitted_transitive_source_rejected(self):
        self.proofs['installation']['artifacts_sha256']['public_iso'] = 'b' * 64
        self.replace_proof('installation')
        with self.assertRaises(ValueError): self.inspect()
        self.proofs['installation']['artifacts_sha256']['public_iso'] = self.artifacts['public_iso']['sha256']
        self.proofs['installation']['sources_sha256'] = {'runner.py': self.sources['runner.py']}
        self.replace_proof('installation')
        with self.assertRaises(ValueError): self.inspect()

    def test_changed_output_bytes_and_runner_bytes_rejected(self):
        path = Path(self.proofs['windows98_vmm']['outputs'][0]['path']); original = path.read_bytes()
        path.write_text('changed')
        with self.assertRaises(ValueError): self.inspect()
        path.write_bytes(original)
        (self.source / 'runner.py').write_text('changed')
        with self.assertRaises(ValueError): self.inspect()

    def test_empty_outputs_duplicate_checks_or_missing_required_check_rejected(self):
        original = self.proofs['iso_bios']['checks']
        for key, value in (('outputs', []), ('checks', []), ('checks', original * 2), ('checks', [{'check': 'unrelated', 'status': 'PASS'}])):
            with self.subTest(key=key, value=value):
                old = self.proofs['iso_bios'][key]
                self.proofs['iso_bios'][key] = value
                self.replace_proof('iso_bios')
                with self.assertRaises(ValueError): self.inspect()
                self.proofs['iso_bios'][key] = old
                self.replace_proof('iso_bios')

    def test_symlink_and_manifest_drift_rejected(self):
        artifact = self.artifacts['installer']
        link = self.root / 'alias.bin'
        link.symlink_to(artifact['path'])
        artifact['path'] = str(link)
        with self.assertRaises(ValueError): self.inspect()
        path = self.root / 'drift.json'; path.write_text(json.dumps(self.manifest))
        with self.assertRaises(ValueError): prep.inspect_index(path, 'f' * 64, self.source)

    def test_official_bilingual_pages_and_checksum_do_not_leak_private_paths(self):
        report = self.inspect()
        assets = prep.download_assets(report)
        ko = assets['index.html'].decode(); en = assets['en.html'].decode()
        self.assertIn('lang="ko"', ko); self.assertIn('lang="en"', en)
        self.assertIn('SHA256SUMS', ko); self.assertIn('SHA256SUMS', en)
        self.assertIn('https://m98.nyase.kr/downloads/shizukuos-1.0.0-test/public_iso.iso', ko)
        self.assertEqual(assets['SHA256SUMS'].decode(), self.artifacts['public_iso']['sha256'] + '  public_iso.iso\n')
        for data in assets.values(): self.assertNotIn(str(self.root).encode(), data)

    def test_resource_floor_kept_and_no_write_to_live_release(self):
        self.assertFalse(prep.publication_capacity(18_932_678_656, 1)['ready'])
        self.assertFalse(prep.publication_capacity(22_058_516_480 + 16 * 1024 * 1024, 1)['ready'])
        self.assertTrue(prep.publication_capacity(22_058_516_480 + 16 * 1024 * 1024 + 1, 1)['ready'])
        report = self.inspect()
        with self.assertRaises(ValueError): prep.write_preparation(report, Path('/srv/m98/invalid-test-output'))

    def test_all_existing_routes_preserved_and_concurrent_current_change_rejected(self):
        base = self.root / 'origin'
        release = base / 'releases' / 'old'
        site = release / 'site'
        (site / 'en').mkdir(parents=True)
        (site / 'continuation').mkdir()
        (site / 'index.html').write_text('reviewed Korean home')
        (site / 'en/index.html').write_text('reviewed English home')
        (site / 'continuation/guide.html').write_text('preserve older continuation route')
        (base / 'current').symlink_to(release)
        config = self.root / 'locations.conf'; config.write_text('reviewed route configuration')
        snapshot = prep.preservation_snapshot(base, release, config)
        self.assertEqual(set(snapshot['body_hashes']), {'/index.html', '/en/index.html', '/continuation/guide.html'})
        self.assertEqual(snapshot['body_hashes']['/continuation/guide.html']['sha256'], hashlib.sha256(b'preserve older continuation route').hexdigest())
        with self.assertRaises(ValueError): prep.preservation_snapshot(base, base / 'releases' / 'other', config)
        report = self.inspect(); report['preservation'] = snapshot
        (base / 'current').unlink(); (base / 'current').symlink_to(base / 'releases' / 'other')
        with self.assertRaises(ValueError): prep.write_preparation(report, self.root / 'should-not-exist')
        self.assertFalse((self.root / 'should-not-exist').exists())

    def test_old_route_byte_drift_rejected_before_any_output(self):
        base = self.root / 'origin'; release = base / 'releases' / 'old'
        (release / 'site').mkdir(parents=True)
        home = release / 'site/index.html'; home.write_text('old bytes')
        (base / 'current').symlink_to(release)
        config = self.root / 'locations.conf'; config.write_text('fixed routes')
        report = self.inspect(); report['preservation'] = prep.preservation_snapshot(base, release, config)
        home.write_text('changed bytes')
        with self.assertRaises(ValueError): prep.write_preparation(report, self.root / 'should-not-exist')
        self.assertFalse((self.root / 'should-not-exist').exists())

    def test_malformed_output_size_is_rejected_explicitly(self):
        self.proofs['iso_bios']['outputs'][0]['bytes'] = 'invalid'
        self.replace_proof('iso_bios')
        with self.assertRaises(ValueError): self.inspect()

    def test_actual_cli_missing_goal_writes_only_blocked_private_receipt(self):
        self.manifest['gates'] = {}
        index = self.root / 'index.json'; index.write_text(json.dumps(self.manifest))
        out = self.root / 'blocked-preparation'
        command = ['python3', '-B', str(TOOL), '--index', str(index), '--index-sha256', pin(index)['sha256'],
                   '--source-root', str(self.source), '--out', str(out)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads((out / 'readiness.json').read_text())
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertFalse(report['published']); self.assertFalse(report['iso_copied'])
        self.assertFalse((out / 'site').exists())

    def test_custom_live_origin_cannot_be_used_as_private_staging(self):
        base = self.root / 'custom-origin'; release = base / 'releases' / 'old'
        (release / 'site').mkdir(parents=True)
        (release / 'site/index.html').write_text('reviewed bytes')
        (base / 'current').symlink_to(release)
        config = self.root / 'routes.conf'; config.write_text('reviewed config')
        report = self.inspect(); report['preservation'] = prep.preservation_snapshot(base, release, config)
        out = release / 'site' / 'should-never-be-written'
        with self.assertRaises(ValueError): prep.write_preparation(report, out)
        self.assertFalse(out.exists())

    def test_missing_changed_or_zero_hash_goal_contract_rejected(self):
        original = dict(self.manifest['goal_contract'])
        for bad in ({'path': 'missing.json', 'sha256': original['sha256']}, {'path': 'goal.json', 'sha256': '0' * 64}):
            self.manifest['goal_contract'] = bad
            with self.assertRaises(ValueError): self.inspect()
        self.manifest['goal_contract'] = original
        (self.source / 'goal.json').write_text('{}')
        with self.assertRaises(ValueError): self.inspect()

    def test_empty_contract_or_missing_original_spec_role_rejected(self):
        self.contract['requirements'] = []
        self.reseal_contract()
        with self.assertRaises(ValueError): self.inspect()

    def test_original_spec_hash_is_actually_read(self):
        self.contract['source_specs'][0]['sha256'] = '0' * 64
        self.reseal_contract()
        with self.assertRaises(ValueError): self.inspect()

    def test_omitted_unknown_duplicate_requirement_ids_rejected(self):
        rows = self.proofs['full_goal']['requirements']
        for bad in (rows[:-1], rows + [rows[0]], [dict(rows[0], id='unknown.requirement'), *rows[1:]]):
            self.proofs['full_goal']['requirements'] = bad
            self.replace_proof('full_goal')
            with self.assertRaises(ValueError): self.inspect()
        self.proofs['full_goal']['requirements'] = rows

    def test_behavior_check_requires_actual_output_from_its_producer_gate(self):
        row = self.proofs['full_goal']['requirements'][0]['checks'][0]
        for bad in ([], ['0' * 64], [self.proofs['windows98_vmm']['outputs'][0]['sha256']]):
            row['output_sha256'] = bad
            self.replace_proof('full_goal')
            with self.assertRaises(ValueError): self.inspect()

    def test_generic_full_goal_check_cannot_replace_concrete_requirement_checks(self):
        self.proofs['full_goal']['checks'] = [{'check': 'every requested requirement and application passed', 'status': 'PASS'}]
        self.replace_proof('full_goal')
        with self.assertRaises(ValueError): self.inspect()

    def test_unresolved_application_version_and_missing_requirement_category_rejected(self):
        app = next(r for r in self.proofs['full_goal']['requirements'] if r['applications'])['applications'][0]
        app['version'] = 'unknown'
        self.replace_proof('full_goal')
        with self.assertRaises(ValueError): self.inspect()
        app['version'] = '1.2.3'
        self.contract['requirements'] = [r for r in self.contract['requirements'] if r['category'] != 'nt_wrapper_compatibility']
        self.reseal_contract()
        with self.assertRaises(ValueError): self.inspect()

    def test_application_version_requires_its_own_producer_output_identity(self):
        app = next(r for r in self.proofs['full_goal']['requirements'] if r['applications'])['applications'][0]
        for bad in ([], ['0' * 64], [self.proofs['iso_bios']['outputs'][0]['sha256']]):
            with self.subTest(output_sha256=bad):
                app['output_sha256'] = bad
                self.replace_proof('full_goal')
                with self.assertRaises(ValueError): self.inspect()

    def test_pinned_application_version_cannot_be_replaced_with_another_version(self):
        next(r for r in self.contract['requirements'] if r['applications'])['applications'][0]['version'] = '2.0.0'
        self.reseal_contract()
        with self.assertRaises(ValueError): self.inspect()

    def test_requirement_receipt_cannot_claim_unknown_or_partial_checks(self):
        row = self.proofs['full_goal']['requirements'][0]
        original = row['checks']
        for bad in ([], original * 2, [dict(original[0], check='unrelated')]):
            with self.subTest(checks=bad):
                row['checks'] = bad
                self.replace_proof('full_goal')
                with self.assertRaises(ValueError): self.inspect()

    def test_failed_requirement_blocks_even_if_full_goal_receipt_claims_pass(self):
        self.proofs['full_goal']['requirements'][0]['status'] = 'FAIL'
        self.replace_proof('full_goal')
        report = self.inspect()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertIn('goal.public_iso', report['requirements']['blocked'])

    def test_required_gate_behavior_is_not_optional_in_contract(self):
        self.contract['requirements'] = [r for r in self.contract['requirements'] if r['gate'] != 'iso_uefi']
        self.reseal_contract()
        with self.assertRaises(ValueError): self.inspect()

    def test_original_spec_roles_must_be_complete_unique_and_bound(self):
        original = self.contract['source_specs']
        for bad in (original[:1], [original[0], original[0]], [dict(original[0], role='invented'), original[1]]):
            with self.subTest(source_specs=bad):
                self.contract['source_specs'] = bad
                self.reseal_contract()
                with self.assertRaises(ValueError): self.inspect()

    def test_contract_and_original_specs_must_be_tracked_safe_source_paths(self):
        original = dict(self.manifest['goal_contract'])
        for bad in ('../goal.json', str(self.source / 'goal.json'), 'untracked.json'):
            with self.subTest(path=bad):
                (self.source / 'untracked.json').write_text(json.dumps(self.contract))
                self.manifest['goal_contract'] = dict(original, path=bad)
                with self.assertRaises(ValueError): self.inspect()

    def test_contract_requirement_ids_are_unique_and_categories_known(self):
        self.contract['requirements'].append(dict(self.contract['requirements'][0]))
        self.reseal_contract()
        with self.assertRaises(ValueError): self.inspect()

    def test_behavior_cannot_use_an_unrelated_output_from_the_same_gate(self):
        other = self.root / 'unrelated-public-iso.log'
        other.write_text('unrelated fixture output, not the required behavior\n')
        self.proofs['public_iso']['outputs'].append(pin(other))
        self.replace_proof('public_iso')
        self.proofs['full_goal']['requirements'][0]['checks'][0]['output_sha256'] = [pin(other)['sha256']]
        self.replace_proof('full_goal')
        with self.assertRaises(ValueError): self.inspect()

    def test_gate_check_must_bind_actual_output_not_only_pass_string(self):
        self.proofs['iso_bios']['checks'][0].pop('output_sha256')
        self.replace_proof('iso_bios')
        with self.assertRaises(ValueError): self.inspect()

    def test_draft_contract_without_application_inventory_stays_blocked(self):
        requirement = next(r for r in self.contract['requirements'] if r['category'] == 'modern_applications')
        requirement['applications'] = []
        observed = next(r for r in self.proofs['full_goal']['requirements'] if r['id'] == requirement['id'])
        observed['applications'] = []
        self.reseal_contract()
        report = self.inspect()
        self.assertEqual(report['status'], 'BLOCKED')
        self.assertEqual(report['missing_application_inventory'], ['goal.full_goal'])
        self.assertIn('goal.full_goal', report['requirements']['blocked'])
        with self.assertRaises(ValueError): prep.download_assets(report)

    def test_source_commit_change_during_private_staging_never_certifies_predecessor(self):
        report = self.inspect()
        original = prep.download_assets
        def concurrent_commit(accepted):
            assets = original(accepted)
            subprocess.run(['git', '-C', str(self.source), '-c', 'user.name=fixture',
                            '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty',
                            '-qm', 'concurrent source epoch'], check=True)
            return assets
        out = self.root / 'private-staging'
        with patch.object(prep, 'download_assets', concurrent_commit), patch.object(prep.shutil, 'disk_usage',
                return_value=type('OwnedCapacity', (), {'free': 1 << 40})()):
            with self.assertRaisesRegex(ValueError, 'source checkout differs'):
                prep.write_preparation(report, out)
        self.assertFalse((out / 'readiness.json').exists())


if __name__ == '__main__':
    unittest.main()
