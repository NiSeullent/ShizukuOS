# SPDX-License-Identifier: GPL-2.0-only
"""Synthetic metadata and guardian admission; no Windows disk or VM executes."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


parser = load('original_lineage_test', HERE / 'disk_lineage.py')
guardian = load('original_guardian_test', HERE / 'task_custody.py')


def pin(path, size=12, digest='a' * 64):
    return {'path': str(path), 'bytes': size, 'sha256': digest}


def record(path, row):
    raw = json.dumps(row).encode()
    return raw, pin(path, len(raw), hashlib.sha256(raw).hexdigest())


class OriginalLineageTests(unittest.TestCase):
    def setUp(self):
        self.root = Path('/original-phase-fixture')
        self.disk = pin(self.root / 'original.img', 2 << 30, 'b' * 64)
        self.producers = [pin(self.root / 'native_original_userland.py', 123, 'c' * 64),
                          pin(self.root / 'prepare_replacement.py', 456, 'd' * 64)]
        self.request = {'schema': parser.ORIGINAL_REQUEST_SCHEMA, 'source_disk': self.disk,
                        'windows_directory': 'WINDOWS', 'boot_policy': 'shz.foundation=win98',
                        'producer_inputs': self.producers}
        names = ['IO.SYS', 'MSDOS.SYS', 'COMMAND.COM',
                 *['WINDOWS/' + name for name in
                   ('WIN.COM', 'SYSTEM.INI', 'SYSTEM/VMM32.VXD', 'IFSHLP.SYS')]]
        self.profile = {'schema': parser.ORIGINAL_SCHEMA,
                        'status': 'ORIGINAL_USERLAND_SOURCE_OBSERVED_NOT_BOOTED',
                        'phase': 'original-userland-legacy-adapter', 'source_disk': self.disk,
                        'request': None, 'producer_inputs': self.producers,
                        'boot_policy': 'shz.foundation=win98', 'observed_windows_path': 'C:\\WINDOWS',
                        'observed_members': {name: {'bytes': 32, 'sha256': 'e' * 64,
                                                    'metadata_sha256': 'f' * 64, 'cluster': 2}
                                             for name in names},
                        'boot_sectors': {name: {'bytes': 512, 'sha256': '1' * 64}
                                         for name in ('mbr', 'vbr')},
                        'source_before_after_match': True,
                        **{name: False for name in parser.ORIGINAL_FLAGS}}

    def inputs(self):
        request_raw, request_pin = record(self.root / 'request.json', self.request)
        profile = copy.deepcopy(self.profile)
        profile['request'] = request_pin
        raw, identity = record(self.root / 'original-userland-profile.json', profile)
        return raw, identity, request_raw

    def call(self, disk=None, producers=None):
        raw, identity, request_raw = self.inputs()
        return parser.admit_original([raw], [identity], self.disk if disk is None else disk,
                                     self.producers if producers is None else producers,
                                     request_raw=request_raw)

    def test_explicit_original_phase_keeps_runtime_claims_false(self):
        proof = self.call()
        self.assertEqual(proof['source_disk'], proof['selected_disk'])
        self.assertEqual(proof['disk_origin'], 'private-original-userland-observed-not-booted')
        self.assertNotIn('replacement_disk', proof)
        for name in parser.ORIGINAL_FLAGS:
            self.assertIs(proof[name], False)

    def test_old_replacement_admission_does_not_accept_original_metadata(self):
        raw, identity, _ = self.inputs()
        with self.assertRaises(ValueError):
            parser.admit([raw], [identity], self.disk, self.producers)

    def test_profile_schema_status_phase_and_extra_field_refused(self):
        for name, value in [('schema', 'shizukuos.private-replacement-profile.v1'),
                            ('status', 'PASS'), ('phase', 'hybrid-complete'), ('extra', True),
                            ('source_before_after_match', 1)]:
            with self.subTest(name=name):
                old = copy.deepcopy(self.profile)
                self.profile[name] = value
                with self.assertRaises(ValueError): self.call()
                self.profile = old

    def test_selected_disk_path_bytes_digest_must_match(self):
        for key, value in [('path', str(self.root / 'replacement.img')), ('bytes', 1),
                           ('sha256', '2' * 64), ('bytes', True)]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.call(disk=dict(self.disk, **{key: value}))

    def test_every_runtime_flag_missing_numeric_or_true_is_refused(self):
        for name in parser.ORIGINAL_FLAGS:
            for value in (None, 0, True):
                self.profile[name] = value
                with self.subTest(name=name, value=value), self.assertRaises(ValueError): self.call()
            del self.profile[name]
            with self.assertRaises(ValueError): self.call()
            self.profile[name] = False

    def test_raw_extent_sha_duplicate_json_and_one_profile_required(self):
        raw, identity, request_raw = self.inputs()
        for data, pins in [([raw + b' '], [identity]), ([raw[:-1]], [identity]),
                           ([], []), ([raw, raw], [identity, identity])]:
            with self.assertRaises(ValueError):
                parser.admit_original(data, pins, self.disk, self.producers, request_raw=request_raw)
        duplicate = b'{"schema":"x","schema":"y"}'
        bad = pin(identity['path'], len(duplicate), hashlib.sha256(duplicate).hexdigest())
        with self.assertRaises(ValueError):
            parser.admit_original([duplicate], [bad], self.disk, self.producers, request_raw=request_raw)
        with self.assertRaises(ValueError):
            parser.admit_original([raw], [identity], self.disk, self.producers, request_raw=request_raw + b' ')

    def test_request_schema_disk_policy_and_producer_binding_required(self):
        for key, value in [('schema', 'other'), ('source_disk', dict(self.disk, sha256='2' * 64)),
                           ('boot_policy', 'other'), ('producer_inputs', self.producers[::-1]),
                           ('extra', True)]:
            old = copy.deepcopy(self.request)
            self.request[key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.call()
            self.request = old

    def test_bad_windows_directory_or_observed_path_refused(self):
        for directory in ('CON', 'LPT1', 'windows', 'TOOLONGDIR', '../X', 'C:\\X', True):
            self.request['windows_directory'] = directory
            with self.subTest(directory=directory), self.assertRaises(ValueError): self.call()
        self.request['windows_directory'] = 'WINDOWS'
        self.profile['observed_windows_path'] = 'D:\\WINDOWS'
        with self.assertRaises(ValueError): self.call()

    def test_exact_seven_nonempty_regular_members_required(self):
        original = copy.deepcopy(self.profile['observed_members'])
        for name in original:
            self.profile['observed_members'] = copy.deepcopy(original)
            del self.profile['observed_members'][name]
            with self.assertRaises(ValueError): self.call()
        for key, value in [('bytes', 0), ('bytes', True), ('cluster', 1), ('cluster', True),
                           ('directory', False), ('sha256', '0' * 64), ('metadata_sha256', 'bad')]:
            self.profile['observed_members'] = copy.deepcopy(original)
            self.profile['observed_members']['IO.SYS'][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.call()
        self.profile['observed_members'] = dict(original, EXTRA=original['IO.SYS'])
        with self.assertRaises(ValueError): self.call()

    def test_boot_observations_and_exact_producer_roles_required(self):
        sectors = copy.deepcopy(self.profile['boot_sectors'])
        for key, value in [('bytes', 511), ('bytes', True), ('sha256', '0' * 64), ('extra', False)]:
            self.profile['boot_sectors'] = copy.deepcopy(sectors)
            self.profile['boot_sectors']['mbr'][key] = value
            with self.assertRaises(ValueError): self.call()
        self.profile['boot_sectors'] = sectors
        for producers in ([], self.producers[::-1], self.producers * 2,
                          [dict(self.producers[0], path='/original-phase-fixture/other.py'), self.producers[1]]):
            with self.assertRaises(ValueError): self.call(producers=producers)


class MemoryUnion:
    """Metadata transport model; actual lease lifetime has separate host tests."""
    def __init__(self): self.data = {}; self.rows = {}
    def add(self, identity):
        self.rows[identity['path']] = copy.deepcopy(identity)
        return {'pin': self.rows[identity['path']], 'fd': -1}
    def check(self): pass
    def raw(self, identity, maximum):
        self.add(identity)
        raw = self.data[identity['path']]
        if len(raw) != identity['bytes'] or len(raw) > maximum or hashlib.sha256(raw).hexdigest() != identity['sha256']:
            raise ValueError('model snapshot pin mismatch')
        return raw
    def json(self, identity, maximum=16 << 20):
        return json.loads(self.raw(identity, maximum))
    def put(self, path, row):
        raw, identity = record(path, row)
        self.data[identity['path']] = raw
        return identity


class GuardianOriginalPhaseTests(OriginalLineageTests):
    # Execute the complete production admit_manifest(), modelling only external
    # bootstrap/module transport and small unexecuted plan metadata.
    def setUp(self):
        super().setUp()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.union = MemoryUnion()
        profile_raw, profile_pin, request_raw = self.inputs()
        self.union.data[profile_pin['path']] = profile_raw
        self.union.data[json.loads(profile_raw)['request']['path']] = request_raw
        self.header = 'shizukudos/supervisor/include/shz_info.h'
        header_path = self.root / 'source' / self.header
        header_path.parent.mkdir(parents=True)
        header_path.write_bytes(b'/* host fixture only */')
        self.sources = {name: pin(self.root / name) for name in guardian.SOURCES}
        self.built = {'status': 'PASS_PRIVATE_WIN98_DOMAIN_ESP_PREPARED_NOT_RUN',
                      'VM_executed': False, 'source_before_after_match': True,
                      'originals_before_after_match': True,
                      'input_pins': {name: self.disk if name == 'DISK.IMG' else pin(self.root / name)
                                     for name in ('DISK.IMG', 'SEABIOS.BIN', 'WIN98CFG.BIN',
                                                  'KERNEL32.BIN', 'KERNEL64.BIN', 'WIN64.IMG')},
                      'artifact': {'bytes': 12, 'sha256': 'a' * 64},
                      'sources_sha256': {self.header: hashlib.sha256(header_path.read_bytes()).hexdigest()}}
        self.builder_pin = self.union.put(self.root / 'builder.json', self.built)
        self.argv = [str(self.root / 'qemu'), '-serial', 'file:serial.log']
        self.plan = {'status': 'PASS_FRESH_PRIVATE_VM_INPUTS_PREPARED_NOT_RUN',
                     'private': True, 'VM_executed': False, 'source_bound_ESP': True,
                     'originals_before_after_match': True,
                     'input_pins': {'esp': pin(self.root / 'esp.img'), 'build_receipt': self.builder_pin,
                                    **{name: pin(self.root / name) for name in
                                       ('firmware_code', 'firmware_vars', 'qemu')}},
                     'qemu_argv': self.argv}
        self.plan_pin = self.union.put(self.root / 'vm-plan.json', self.plan)
        self.manifest = {'schema': guardian.ORIGINAL_MANIFEST_SCHEMA, 'plan': self.plan_pin,
                         'repo': str(self.root), 'sources': self.sources, 'lineage': [profile_pin],
                         'producers': self.producers, 'limits': {}, 'timeout': 20}
        self.prep = SimpleNamespace(recipe=lambda *a: list(self.argv))
        original = json.loads(profile_raw)
        self.observer = SimpleNamespace(observe=lambda *a: {
            name: copy.deepcopy(original[name]) for name in
            ('observed_windows_path', 'observed_members', 'boot_sectors')})
        self.fat_reader = SimpleNamespace()

    def admit(self, epoch_context=None):
        def module(name, *_):
            if name == 'admitted_disk_lineage': return parser
            if name == 'admitted_preparation': return self.prep
            if name == 'admitted_original_observer': return self.observer
            if name == 'admitted_original_fat': return self.fat_reader
            raise AssertionError('unexpected source module ' + name)
        with patch.object(guardian, 'admit_runtime_sources', side_effect=lambda repo, sources, union: sources), \
             patch.object(guardian, 'admitted_module', side_effect=module):
            return guardian.admit_manifest(self.manifest, self.union, epoch_context=epoch_context)

    def test_complete_guardian_branch_retains_all_original_pins_and_common_recipe(self):
        _, _, sources, proof, argv, _ = self.admit()
        self.assertEqual(proof['source_disk'], self.disk)
        for identity in [self.disk, *self.producers, self.manifest['lineage'][0], proof['request'],
                         *self.plan['input_pins'].values(), *self.built['input_pins'].values()]:
            self.assertEqual(self.union.rows[identity['path']], identity)
        self.assertIn(self.header, sources)
        self.assertEqual(argv[argv.index('-serial') + 1], 'file:/proc/self/fd/0')
        self.assertIn('file:/proc/self/fd/1', argv)
        self.assertNotIn('DOS3_patch_pins', proof)

    def test_explicit_original_schema_required_and_mixed_cohorts_refused(self):
        self.manifest['schema'] = 'shizukuos.native-custody-manifest.v1'
        with self.assertRaises(ValueError): self.admit()
        self.manifest['schema'] = guardian.ORIGINAL_MANIFEST_SCHEMA
        self.manifest['gop_cohort'] = {}
        with self.assertRaises(ValueError): self.admit()
        del self.manifest['gop_cohort']
        with self.assertRaises(ValueError): self.admit(epoch_context={})

    def test_extra_dos_receipts_or_different_selected_disk_refused(self):
        self.manifest['lineage'] *= 3
        with self.assertRaises(ValueError): self.admit()
        self.manifest['lineage'] = self.manifest['lineage'][:1]
        self.built['input_pins']['DISK.IMG'] = dict(self.disk, sha256='3' * 64)
        self.plan['input_pins']['build_receipt'] = self.union.put(self.root / 'builder.json', self.built)
        self.manifest['plan'] = self.union.put(self.root / 'vm-plan.json', self.plan)
        with self.assertRaises(ValueError): self.admit()

    def test_recipe_mismatch_still_refuses_after_original_admission(self):
        self.prep.recipe = lambda *a: self.argv + ['-nic', 'user']
        with self.assertRaises(ValueError): self.admit()

    def test_actual_observation_mismatch_or_failure_prevents_recipe_admission(self):
        original = self.observer.observe
        for field in ('observed_members', 'boot_sectors', 'observed_windows_path'):
            changed = original()
            changed[field] = {} if field != 'observed_windows_path' else 'C:\\OTHER'
            self.observer.observe = lambda *a, result=changed: result
            with self.subTest(field=field), self.assertRaises(ValueError): self.admit()
        def fail(*a): raise ValueError('held disk read failed')
        self.observer.observe = fail
        with self.assertRaises(ValueError): self.admit()


class ActualGuardianObservation(unittest.TestCase):
    def test_held_source_modules_rederive_real_synthetic_disk_and_refuse_forgery(self):
        # Real sparse FAT bytes and production descriptor admission. The files
        # explicitly contain synthetic non-executable contents, not Windows.
        root = HERE.parents[2]
        fixture = load('original_guardian_fat_fixture', root / 'tools/tests/test_native_original_userland.py')
        with tempfile.TemporaryDirectory(dir='/var/tmp', prefix='shz-original-guardian-') as temporary:
            disk = Path(temporary) / 'synthetic.img'
            fixture.make_disk(disk)
            disk_pin = fixture.file_pin(disk)
            producers = [fixture.file_pin(root / 'tools/native_original_userland.py'),
                         fixture.file_pin(root / 'shizukudos/win98_boot/prepare_replacement.py')]
            union = guardian.LeaseUnion()
            try:
                entry = union.add(disk_pin)
                for item in producers: union.add(item)
                observed = fixture.tool.observe(entry['fd'], disk_pin['bytes'], 'WINDOWS',
                                                fixture.reader, union.check)
                proof = {'source_disk': disk_pin, 'observed_windows_path': 'C:\\WINDOWS'}
                guardian.check_original_observation(observed, proof, producers, union)
                for field in ('observed_members', 'boot_sectors', 'observed_windows_path'):
                    forged = copy.deepcopy(observed)
                    if field == 'observed_members': forged[field]['IO.SYS']['sha256'] = 'f' * 64
                    elif field == 'boot_sectors': forged[field]['mbr']['sha256'] = 'f' * 64
                    else: forged[field] = 'D:\\WINDOWS'
                    with self.subTest(field=field), self.assertRaises(ValueError):
                        guardian.check_original_observation(forged, proof, producers, union)
                self.assertFalse(union.broken)
            finally:
                union.close()


if __name__ == '__main__': unittest.main()
