# SPDX-License-Identifier: GPL-2.0-only
"""Original-observation device epoch admission with a real live Attempt.

Host controls only: real native_epoch_host.Attempt over real leased config/ROM
descriptors and the production admit_manifest(). No Windows disk, QEMU or
HostGrant exchange executes, so no boot/display/persistence result is claimed.
"""
import copy
import fcntl
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_original_disk_lineage as lineage  # noqa: E402
import test_native_epoch_host as epoch_tests  # noqa: E402

guardian = lineage.guardian
host = epoch_tests.host


class OriginalDeviceEpochAdmission(lineage.GuardianOriginalPhaseTests):
    def setUp(self):
        super().setUp()
        self.leased = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.leased.cleanup)
        self.path = Path(self.leased.name).resolve()
        os.chmod(self.path, 0o700)
        self.fds = []
        self.addCleanup(self.release_fds)
        vga, rom, pers, bars = epoch_tests.configs()
        self.raw = {'VGACFG.BIN': vga, 'VGAROM.BIN': rom, 'W98PERS.BIN': pers}
        self.bars = bars
        self.attempt = self.mint()
        self.attempt.reserve_staging()
        self.optional = {name: source.pin for name, source in
                         zip(('VGACFG.BIN', 'VGAROM.BIN', 'W98PERS.BIN'), self.attempt.sources)}
        self.provenance = {'vga-build-receipt': lineage.pin(self.root / 'vga-build.json')}
        self.binding = {'policy_fd': self.attempt.policy_fd, 'listener_path': str(self.root / 'vm/epoch.sock')}
        self.policy = self.live_policy(self.attempt)
        self.sources[guardian.NATIVE_EPOCH_SOURCE] = lineage.pin(self.root / guardian.NATIVE_EPOCH_SOURCE)
        self.built.update(optional_native_inputs=self.optional, optional_native_provenance=self.provenance,
                          members={'SHZDOS/' + n: {'bytes': r['bytes'], 'sha256': r['sha256']}
                                   for n, r in self.optional.items()})
        self.republish()
        self.manifest.update(optional_native_inputs=self.optional, optional_native_provenance=self.provenance,
                             original_device_epoch={'live_policy': self.policy, 'selected_roles': [1, 2],
                                                    **{n: False for n in guardian.ORIGINAL_EPOCH_FALSE}})
        self.prep.recipe = lambda *a, epoch_binding=None: list(self.argv) if epoch_binding == self.binding else ['refused']
        self.context = {'module': host, 'attempt': self.attempt, 'listener': None, 'recipe_binding': self.binding,
                        'live_policy': self.policy, 'guard': lambda: None, 'phase': guardian.ORIGINAL_MANIFEST_SCHEMA}

    def release_fds(self):
        for fd in self.fds:
            try:
                if fcntl.fcntl(fd, fcntl.F_GETLEASE) != fcntl.F_UNLCK:
                    fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
            finally: os.close(fd)

    def source(self, name, data):
        p = self.path / (name + '.' + str(len(self.fds))); p.write_bytes(data); p.chmod(0o600)
        fd = os.open(p, os.O_RDONLY | os.O_NOFOLLOW); self.fds.append(fd)
        fcntl.fcntl(fd, fcntl.F_SETOWN, os.getpid()); fcntl.fcntl(fd, fcntl.F_SETLEASE, fcntl.F_RDLCK)
        return host.PinnedFD(fd, {'path': str(p), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()})

    def mint(self, storage=True):
        attempt = host.Attempt(self.source('vga', self.raw['VGACFG.BIN']), self.source('rom', self.raw['VGAROM.BIN']),
                               self.source('pers', self.raw['W98PERS.BIN']) if storage else None,
                               self.bars if storage else {1: self.bars[1]}, time.monotonic_ns() + 30_000_000_000)
        self.addCleanup(attempt.close)
        return attempt

    @staticmethod
    def live_policy(attempt):
        return {'policy_sha256': hashlib.sha256(attempt.policy).hexdigest(),
                'nonce_sha256': hashlib.sha256(attempt.nonce).hexdigest(),
                'original_host_deadline_ns': attempt.original_deadline_ns}

    def republish(self):
        self.plan['prospective_native_epoch_recipe'] = self.binding
        self.plan['input_pins']['build_receipt'] = self.union.put(self.root / 'builder.json', self.built)
        self.plan_pin = self.union.put(self.root / 'vm-plan.json', self.plan)
        self.manifest['plan'] = self.plan_pin

    def admit(self, epoch_context=None):
        builder = SimpleNamespace(VGA_RECEIPT_MAX=1 << 20, optional_native_names=lambda *a: None,
                                  validate_optional_native=lambda *a: None)
        def module(name, *_):
            if name == 'admitted_disk_lineage': return lineage.parser
            if name == 'admitted_preparation': return self.prep
            if name == 'admitted_original_observer': return self.observer
            if name == 'admitted_original_fat': return self.fat_reader
            if name == 'admitted_optional_builder': return builder
            raise AssertionError('unexpected source module ' + name)
        with patch.object(guardian, 'admit_runtime_sources', side_effect=lambda repo, sources, union: sources), \
             patch.object(guardian, 'admitted_module', side_effect=module):
            return guardian.admit_manifest(self.manifest, self.union, epoch_context=epoch_context)

    def refuse(self, context=None):
        with self.assertRaises(ValueError): self.admit(self.context if context is None else context)

    def test_real_retained_attempt_admitted_with_false_grants(self):
        plan, _, _, proof, argv, _ = self.admit(self.context)
        self.assertEqual(plan['prospective_native_epoch_recipe'], self.binding)
        self.assertEqual(proof['source_disk'], self.disk)
        self.assertNotIn('DOS3_patch_pins', proof)
        self.assertTrue(all(proof[name] is False for name in lineage.parser.ORIGINAL_FLAGS))
        self.assertIn('file:/proc/self/fd/0', argv)
        self.assertIsNone(self.attempt.owner)

    def test_vga_only_selection_without_persistence(self):
        attempt = self.mint(storage=False); attempt.reserve_staging()
        optional = {n: s.pin for n, s in zip(('VGACFG.BIN', 'VGAROM.BIN'), attempt.sources)}
        self.binding['policy_fd'] = attempt.policy_fd
        self.built.update(optional_native_inputs=optional, members={'SHZDOS/' + n: {'bytes': r['bytes'], 'sha256': r['sha256']}
                                                                    for n, r in optional.items()})
        self.republish()
        policy = self.live_policy(attempt)
        self.manifest['optional_native_inputs'] = optional
        self.manifest['original_device_epoch'].update(live_policy=policy, selected_roles=[1])
        self.admit(dict(self.context, attempt=attempt, live_policy=policy))

    def test_declared_epoch_requires_live_context_and_context_requires_declaration(self):
        with self.assertRaises(ValueError): self.admit()
        declared = self.manifest.pop('original_device_epoch')
        self.refuse()
        self.manifest['original_device_epoch'] = declared
        self.manifest['gop_cohort'] = {}
        self.refuse()

    def test_dos3_context_or_fake_attempt_refused(self):
        self.refuse({k: v for k, v in self.context.items() if k != 'phase'})
        self.refuse(dict(self.context, phase='shizukuos.native-custody-manifest.v1'))
        fake = SimpleNamespace(**{k: getattr(self.attempt, k) for k in ('policy', 'nonce', 'original_deadline_ns', 'sources',
                                                                         'expected', 'staging_claim', 'owner', 'consumed')},
                               check=lambda: None)
        self.refuse(dict(self.context, attempt=fake))

    def test_stale_or_foreign_policy_refused(self):
        other = self.mint(); other.reserve_staging()
        self.manifest['original_device_epoch']['live_policy'] = self.live_policy(other)
        self.refuse()
        self.manifest['original_device_epoch']['live_policy'] = self.policy
        self.refuse(dict(self.context, live_policy=self.live_policy(other)))
        self.refuse(dict(self.context, attempt=other))

    def test_unstaged_bound_consumed_or_closed_attempt_refused(self):
        fresh = self.mint()
        policy = self.live_policy(fresh)
        self.manifest['original_device_epoch']['live_policy'] = policy
        self.refuse(dict(self.context, attempt=fresh, live_policy=policy))
        self.manifest['original_device_epoch']['live_policy'] = self.policy
        self.attempt.consumed = True
        self.refuse()
        self.attempt.consumed = False
        self.attempt.owner = object()
        self.refuse()
        self.attempt.owner = None
        self.attempt.close()
        self.refuse()

    def test_dropped_source_lease_refused(self):
        fcntl.fcntl(self.attempt.sources[0].fd, fcntl.F_SETLEASE, fcntl.F_UNLCK)
        self.refuse()

    def test_true_grant_flag_or_wrong_roles_refused(self):
        for name in guardian.ORIGINAL_EPOCH_FALSE:
            self.manifest['original_device_epoch'][name] = True
            with self.subTest(name=name): self.refuse()
            self.manifest['original_device_epoch'][name] = False
        self.manifest['original_device_epoch']['selected_roles'] = [1]
        self.refuse()

    def test_declared_pins_must_match_held_attempt_sources(self):
        swapped = copy.deepcopy(self.optional)
        swapped['VGACFG.BIN'] = dict(swapped['VGACFG.BIN'], path=str(self.path / 'other.bin'))
        self.manifest['optional_native_inputs'] = swapped
        self.built['optional_native_inputs'] = swapped
        self.built['members']['SHZDOS/VGACFG.BIN'] = {'bytes': swapped['VGACFG.BIN']['bytes'],
                                                     'sha256': swapped['VGACFG.BIN']['sha256']}
        self.republish()
        self.refuse()

    def test_dos3_gop_staging_sources_refused_in_original_phase(self):
        self.sources[guardian.GOP_NONCE_SOURCE] = lineage.pin(self.root / guardian.GOP_NONCE_SOURCE)
        self.sources[guardian.GOP_CONSTRUCTOR_SOURCE] = lineage.pin(self.root / guardian.GOP_CONSTRUCTOR_SOURCE)
        self.refuse()

    def test_recipe_binding_mismatch_refused(self):
        self.refuse(dict(self.context, recipe_binding={'policy_fd': self.attempt.policy_fd,
                                                       'listener_path': str(self.root / 'other.sock')}))

    def test_dos3_manifest_cannot_carry_original_epoch(self):
        self.manifest['schema'] = 'shizukuos.native-custody-manifest.v1'
        self.refuse()
        del self.manifest['original_device_epoch']
        self.refuse()


# Reuse the production original-phase fixture, not its unrelated test bodies.
for _name in dir(lineage.GuardianOriginalPhaseTests):
    if _name.startswith('test_') and _name not in vars(OriginalDeviceEpochAdmission):
        setattr(OriginalDeviceEpochAdmission, _name, None)


class OriginalIntentShape(unittest.TestCase):
    def intent(self):
        root = '/original-phase-fixture'
        p = lambda name: lineage.pin(root + '/' + name)
        return {'schema': guardian.ORIGINAL_EPOCH_INTENT_SCHEMA, 'repo': root, 'sources': {}, 'limits': {}, 'timeout': 60,
                'lineage': [p('profile.json')], 'producers': [p('a.py'), p('b.py')],
                'native_inputs': {n: p(n) for n in ('DISK.IMG', 'SEABIOS.BIN', 'WIN98CFG.BIN', 'KERNEL32.BIN',
                                                    'KERNEL64.BIN', 'WIN64.IMG')},
                'optional_native_inputs': {n: p(n) for n in ('VGACFG.BIN', 'VGAROM.BIN')},
                'optional_native_provenance': {'vga-build-receipt': p('vga.json')},
                'raw_bars': {'1': [0xe0000008, 0, 0, 0, 0, 0]},
                'firmware': {n: p(n) for n in ('firmware_code', 'firmware_vars', 'qemu')},
                'private_root': root + '/private', 'assembly_scratch': None}

    def refuse(self, intent, sources):
        union = lineage.MemoryUnion()
        with self.assertRaises(ValueError): guardian.prepare_original_intent(intent, union, sources, lambda: None)
        self.assertEqual(union.rows, {}, 'shape refusal must precede any lease or Attempt')

    def test_shape_refusals_precede_any_admission(self):
        epoch = {guardian.NATIVE_EPOCH_SOURCE: {}}
        cases = []
        bad = self.intent(); bad['schema'] = 'shizukuos.native-custody-gop-intent.v1'; cases.append((bad, epoch))
        bad = self.intent(); del bad['optional_native_inputs']['VGAROM.BIN']; cases.append((bad, epoch))
        bad = self.intent(); bad['raw_bars']['2'] = [0] * 6; cases.append((bad, epoch))
        bad = self.intent(); bad['optional_native_inputs']['W98PERS.BIN'] = bad['optional_native_inputs']['VGACFG.BIN']
        cases.append((bad, epoch))
        bad = self.intent(); bad['lineage'] *= 3; cases.append((bad, epoch))
        bad = self.intent(); bad['gop'] = {}; cases.append((bad, epoch))
        cases.append((self.intent(), {}))
        cases.append((self.intent(), {**epoch, guardian.GOP_NONCE_SOURCE: {}, guardian.GOP_CONSTRUCTOR_SOURCE: {}}))
        for intent, sources in cases:
            with self.subTest(intent=sorted(intent), sources=sorted(sources)): self.refuse(intent, sources)


if __name__ == '__main__':
    unittest.main()
