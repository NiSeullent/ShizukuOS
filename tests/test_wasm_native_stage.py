#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Real byte-read/decoder and synthetic copy-failure controls; no native VM."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import wasm_native_stage_evidence as evidence
import stage_wasm_native as stager


class ReadControls(unittest.TestCase):
    def test_duplicate_and_nonfinite_json(self):
        for raw in (b'{"schema":1,"schema":1}', b'{"nested":{"a":0,"a":1}}',
                    b'{"x":NaN}', b'{"x":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                evidence.json_data(raw)

    def test_canonical_members(self):
        for name in ('../escape', '/absolute', 'a/../b', 'a//b', './a', 'a\\b', ''):
            with self.subTest(name=name), self.assertRaises(ValueError):
                evidence.relative(name)
        self.assertEqual(evidence.relative('build/source/.clang-format'), Path('build/source/.clang-format'))

    def test_real_file_bounds_symlink_nonregular(self):
        with tempfile.TemporaryDirectory() as d:
            directory = Path(d)
            p = directory / 'regular'
            p.write_bytes(b'original')
            self.assertEqual(evidence.read(p, 8), b'original')
            with self.assertRaises(ValueError):
                evidence.read(p, 7)
            (directory / 'alias').symlink_to(p)
            with self.assertRaises(ValueError):
                evidence.read(directory / 'alias')
            with self.assertRaises(ValueError):
                evidence.read(directory)

    def test_late_actual_file_drift(self):
        with tempfile.TemporaryDirectory() as d, patch.object(evidence, 'ROOT', Path(d)):
            p = Path(d) / 'sample'
            p.write_bytes(b'one')
            closure = evidence.Closure()
            closure.take(p, evidence.sha(b'one'))
            p.write_bytes(b'two')
            with self.assertRaisesRegex(ValueError, 'late closure drift'):
                closure.unchanged()

    def test_wrong_pin_before_side_effect(self):
        paths = {n: evidence.ROOT / 'build' / evidence.BUILD_DIRS[n] / 'result.json'
                 for n in evidence.RECEIPTS}
        pins = dict(evidence.APPROVED, **{'probe-build.json': '0' * 64})
        with self.assertRaisesRegex(ValueError, 'exact approved source generations'):
            evidence.collect(paths, pins)

    def test_numeric_host_oracle_rejects_partial_failure_or_false_native(self):
        original = (evidence.ROOT / 'build/wasm-native-probe-v6/host-test.log').read_bytes()
        self.assertEqual(evidence.host_oracle(original), original)
        for raw in (original[:-2], original.replace(b'CHECKS=244', b'CHECKS=243'),
                    original.replace(b'NATIVE_EXECUTION=0', b'NATIVE_EXECUTION=1'),
                    original.replace(b'=1\r\n', b'=0\r\n', 1),
                    original.replace(b'\r\n', b'\n'), original + b'STATUS=PASS\r\n'):
            with self.subTest(raw=raw[:70]), self.assertRaises(ValueError):
                evidence.host_oracle(raw)

    def test_real_feature_and_original_crt_preprocessor_controls(self):
        path = evidence.ROOT / 'build/wasm-runtime-v24/result.json'
        runtime = evidence.receipt(path, evidence.APPROVED['runtime-build.json'])
        logs = {('runtime-build.json', s['name']): Path(s['log']).read_bytes()
                for s in runtime['steps'] if s['name'].endswith('-effective-engine-config')
                or s['name'] == 'native-original-crt-macros'}
        evidence.engine_configuration(runtime, logs)
        changed = dict(logs)
        key = ('runtime-build.json', 'native-effective-engine-config')
        changed[key] = logs[key].replace(b'#define WASM_ENABLE_INTERP 1', b'#define WASM_ENABLE_INTERP 0')
        with self.assertRaisesRegex(ValueError, 'feature macro'):
            evidence.engine_configuration(runtime, changed)
        changed = dict(logs)
        key = ('runtime-build.json', 'native-original-crt-macros')
        changed[key] = logs[key].replace(b'#define PRId64 "I64d"', b'#define PRId64 "lld"')
        with self.assertRaisesRegex(ValueError, 'original-CRT'):
            evidence.engine_configuration(runtime, changed)


class NativeByteControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        root = evidence.ROOT
        cls.probe = evidence.receipt(root / 'build/wasm-native-probe-v6/result.json',
                                    evidence.APPROVED['probe-build.json'])
        cls.binary = (root / 'build/wasm-native-probe-v6/WAS13PR.EXE').read_bytes()
        cls.raw = (root / 'build/wasm-native-probe-v6/WAS13PR.EXE-disassembly.log').read_bytes()
        cls.item = cls.probe['artifacts']['WAS13PR.EXE']
        cls.table = evidence.policy((root / 'tools/i486_instruction_gate.py').read_bytes())
        cls.installed = json.loads((root / 'benchmarks/win98se-ko-oem-native-exports-v1.json').read_text())['dlls']

    def gate(self, raw, item=None, binary=None):
        item = copy.deepcopy(self.item if item is None else item)
        item['i486_instructions']['disassembly_sha256'] = evidence.sha(raw)
        evidence.raw_gate(self.binary if binary is None else binary, raw, item,
                          self.table, [], 65536, self.installed)

    def test_genuine_saved_executable_byte_gate(self):
        self.gate(self.raw)

    def test_missing_instruction_even_with_rebound_log_hash(self):
        rows = self.raw.splitlines(keepends=True)
        position = next(i for i, r in enumerate(rows) if b':\t' in r)
        del rows[position]
        with self.assertRaisesRegex(ValueError, 'byte/address gap'):
            self.gate(b''.join(rows))

    def test_unknown_modern_mnemonic_even_with_rebound_log_hash(self):
        import re
        modified, count = re.subn(rb'([0-9a-f]+:\s+(?:[0-9a-f]{2}\s+)+)push\s+', rb'\1mfence ', self.raw, count=1)
        self.assertEqual(count, 1)
        with self.assertRaisesRegex(ValueError, 'post-i486'):
            self.gate(modified)

    def test_code_byte_drift(self):
        import pefile
        modified = bytearray(self.binary)
        pe = pefile.PE(data=self.binary)
        section = next(s for s in pe.sections if s.Characteristics & 0x20000000)
        modified[section.PointerToRawData] ^= 1
        pe.close()
        item = copy.deepcopy(self.item)
        item['sha256'] = evidence.sha(modified)
        item['i486_instructions']['artifact_sha256'] = evidence.sha(modified)
        with self.assertRaisesRegex(ValueError, 'byte/address gap'):
            self.gate(self.raw, item, bytes(modified))

    def test_loader_stack_or_metadata_drift(self):
        item = copy.deepcopy(self.item)
        item['i486_instructions']['instructions_decoded'] += 1
        with self.assertRaisesRegex(ValueError, 'metadata differs'):
            self.gate(self.raw, item)
        with self.assertRaisesRegex(ValueError, 'stack'):
            evidence.raw_gate(self.binary, self.raw, self.item, self.table, [], 524288, self.installed)


@unittest.skipIf(sys.flags.optimize, 'stager explicitly rejects optimized execution before mutation')
class StageTransactionControls(unittest.TestCase):
    """Small synthetic evidence only; a mocked collector never proves native execution."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.boot = self.root / 'boot'
        self.boot.mkdir()
        self.source = self.root / 'source'
        self.source.write_bytes(b'original immutable synthetic copy input')
        self.digest = evidence.sha(self.source.read_bytes())
        self.copies = {'evidence/source': (self.source, self.digest)}
        for name in evidence.INPUTS:
            self.copies[name] = (self.source, self.digest)
        self.builds = {'observer-build.json': {'nonce': evidence.NONCE}}
        self.destination = self.boot / 'fresh'
        self.patches = [patch.object(evidence, 'ROOT', self.root),
                        patch.object(evidence, 'BOOT_BUILD', self.boot),
                        patch.object(stager, 'BOOT_BUILD', self.boot)]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_failed_preflight_creates_no_stage(self):
        with patch.object(stager, 'collect', side_effect=ValueError('reject mixed generation')):
            with self.assertRaises(ValueError):
                stager.stage({}, {}, self.destination)
        self.assertFalse(self.destination.exists())
        self.assertEqual(self.source.read_bytes(), b'original immutable synthetic copy input')

    def test_source_drift_during_copy_retains_failed_private_stage(self):
        def collect(paths, pins):
            self.source.write_bytes(b'changed actual source bytes')
            return self.builds, self.copies, {}
        with patch.object(stager, 'collect', side_effect=collect):
            with self.assertRaisesRegex(ValueError, 'changed immediately'):
                stager.stage({}, {}, self.destination)
        self.assertTrue(self.destination.exists())
        self.assertFalse((self.destination / 'guest-files.json').exists())

    def test_after_copy_drift_cannot_publish_manifest(self):
        changed = {'evidence/source': (self.source, '0' * 64)}
        with patch.object(stager, 'collect', side_effect=[(self.builds, self.copies, {}),
                                                         (self.builds, changed, {})]):
            with self.assertRaisesRegex(ValueError, 'changed during copy'):
                stager.stage({}, {}, self.destination)
        self.assertTrue((self.destination / 'evidence/source').is_file())
        self.assertFalse((self.destination / 'guest-files.json').exists())

    def test_existing_stage_preserved(self):
        self.destination.mkdir()
        marker = self.destination / 'untouched'
        marker.write_bytes(b'original stage')
        with self.assertRaisesRegex(ValueError, 'fresh canonical'):
            stager.stage({}, {}, self.destination)
        self.assertEqual(marker.read_bytes(), b'original stage')

    def test_source_budget_before_directory_creation(self):
        with patch.object(stager, 'collect', return_value=(self.builds, self.copies, {})), \
             patch.object(stager, 'MAX_STAGE', 1):
            with self.assertRaisesRegex(ValueError, 'exceeds bound'):
                stager.stage({}, {}, self.destination)
        self.assertFalse(self.destination.exists())

    def test_successful_copy_keeps_native_flags_false(self):
        with patch.object(stager, 'collect', return_value=(self.builds, self.copies, {})), \
             patch.object(stager, 'check_stage', return_value=({}, {}, b'SYNTHETIC', {}, {})):
            result = stager.stage({}, {n: self.digest for n in evidence.RECEIPTS}, self.destination)
        self.assertIs(result['native_execution'], False)
        self.assertIs(result['native_numeric_execution'], False)
        manifest = json.loads((self.destination / 'guest-files.json').read_text())
        self.assertEqual(manifest['command'], evidence.PROFILE['self'])
        self.assertIs(manifest['network_required'], False)
        self.assertEqual({r['guest'] for r in manifest['inputs']}, {evidence.PREFIX + n for n in evidence.INPUTS})


class ActualClosureControl(unittest.TestCase):
    def test_complete_original_build_closure_read_only(self):
        paths = {n: evidence.ROOT / 'build' / evidence.BUILD_DIRS[n] / 'result.json'
                 for n in evidence.RECEIPTS}
        builds, copies, merged = evidence.collect(paths, evidence.APPROVED)
        self.assertEqual(set(builds), evidence.RECEIPTS)
        self.assertTrue(evidence.INPUTS <= set(copies))
        self.assertEqual(len(builds['probe-build.json']['checked_evidence_sha256']), 707)
        self.assertEqual(len(builds['runtime-build.json']['original_source_files']), 2001)
        self.assertTrue(set(evidence.STAGE_SOURCES) <= set(merged))
        self.assertGreater(len(copies), 2700)
        self.assertLess(sum(p.stat().st_size for p, h in copies.values()), evidence.MAX_STAGE)


class FrozenStageControls(unittest.TestCase):
    """Synthetic manifest/provenance adversaries; PE/build checks remain mocked."""
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.boot = self.root / 'boot'
        self.stage = self.boot / 'synthetic-stage'
        self.stage.mkdir(parents=True)
        self.pins, self.copies = {}, {}
        for name in evidence.RECEIPTS:
            data = json.dumps({'synthetic_only': name}).encode()
            (self.stage / name).write_bytes(data)
            self.pins[name] = evidence.sha(data)
            self.copies[name] = (self.root / name, evidence.sha(data))
        for name in evidence.INPUTS:
            data = b'SYNTHETIC-ONLY:' + name.encode()
            (self.stage / name).write_bytes(data)
            self.copies[name] = (self.root / name, evidence.sha(data))
        self.manifest = dict(schema=1, kind='isolated-guest-file-inputs',
            command=evidence.PROFILE['self'], nonce=evidence.NONCE, network_required=False,
            outputs=[evidence.PREFIX + n for n in sorted(evidence.OUTPUTS)],
            inputs=[dict(source=str(self.stage / n), guest=evidence.PREFIX + n,
                         bytes=(self.stage / n).stat().st_size, sha256=self.copies[n][1])
                    for n in sorted(evidence.INPUTS)],
            source_receipts=[dict(path=str(self.stage / n), sha256=h)
                             for n, h in sorted(self.pins.items())])
        self.patches = [patch.object(evidence, 'ROOT', self.root),
            patch.object(evidence, 'BOOT_BUILD', self.boot),
            patch.object(evidence, 'APPROVED', self.pins)]
        for p in self.patches:
            p.start()
        self.write()

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def write(self):
        self.path = self.stage / 'guest-files.json'
        self.path.write_text(json.dumps(self.manifest))
        self.digest = evidence.sha(self.path.read_bytes())
        self.prov = evidence.provenance(self.digest, self.copies, {})
        (self.stage / 'provenance.json').write_text(json.dumps(self.prov))
        self.prov_digest = evidence.sha((self.stage / 'provenance.json').read_bytes())

    def collect(self, paths, pins, closure):
        closure.copies = self.copies
        closure.checked = {str(self.stage / n): h for n, (p, h) in self.copies.items()}
        return {}, {}, b'SYNTHETIC-NO-NATIVE-ACCEPTANCE'

    def verify(self):
        with patch.object(evidence, '_collect', side_effect=self.collect):
            return evidence.check_stage(self.path, self.digest, self.pins, self.prov_digest)

    def test_synthetic_control_path_explicitly_no_guest_claim(self):
        builds, inputs, raw, merged, checked = self.verify()
        self.assertEqual(builds, {})
        self.assertEqual(set(inputs), evidence.INPUTS)
        self.assertIn(b'NO-NATIVE-ACCEPTANCE', raw)
        self.assertIn(str(self.stage / 'provenance.json'), checked)

    def test_wrong_nonce_command_network_or_duplicate_outputs(self):
        original = copy.deepcopy(self.manifest)
        for key, value in (('nonce', 'stale-generation'), ('command', evidence.PROFILE['child']),
                           ('network_required', 0), ('outputs', [evidence.PREFIX + 'WA13.LOG'] * 3),
                           ('schema', True)):
            with self.subTest(key=key):
                self.manifest = dict(original, **{key: value})
                self.write()
                with self.assertRaises(ValueError):
                    self.verify()

    def test_input_missing_or_path_size_alias(self):
        original = copy.deepcopy(self.manifest)
        for mutation in ('duplicate', 'path', 'size', 'hash'):
            with self.subTest(mutation=mutation):
                self.manifest = copy.deepcopy(original)
                row = self.manifest['inputs'][0]
                if mutation == 'duplicate':
                    self.manifest['inputs'][1] = dict(row)
                elif mutation == 'path':
                    row['source'] = str(self.root / 'outside')
                elif mutation == 'size':
                    row['bytes'] += 1
                else:
                    row['sha256'] = '0' * 64
                self.write()
                with self.assertRaises(ValueError):
                    self.verify()

    def test_false_provenance_flags_cannot_be_numeric_zero(self):
        for key in ('native_execution', 'native_numeric_execution', 'webgpu', 'full_modern_wasm'):
            with self.subTest(key=key):
                self.write()
                self.prov[key] = 0
                (self.stage / 'provenance.json').write_text(json.dumps(self.prov))
                self.prov_digest = evidence.sha((self.stage / 'provenance.json').read_bytes())
                with self.assertRaisesRegex(ValueError, 'provenance'):
                    self.verify()

    def test_late_provenance_replacement_fails(self):
        original = self.collect
        def late(paths, pins, closure):
            result = original(paths, pins, closure)
            (self.stage / 'provenance.json').write_bytes(b'{}')
            return result
        with patch.object(evidence, '_collect', side_effect=late):
            with self.assertRaisesRegex(ValueError, 'late provenance'):
                evidence.check_stage(self.path, self.digest, self.pins, self.prov_digest)

    def test_actual_frozen_member_missing_or_modified_fails(self):
        target = self.stage / 'WAS13PR.EXE'
        target.write_bytes(b'changed')
        with self.assertRaises(ValueError):
            self.verify()
        target.unlink()
        with self.assertRaises(OSError):
            self.verify()

    def test_wrong_explicit_provenance_pin_before_collector(self):
        with patch.object(evidence, '_collect') as collector:
            with self.assertRaisesRegex(ValueError, 'unapproved stage provenance'):
                evidence.check_stage(self.path, self.digest, self.pins, '0' * 64)
            collector.assert_not_called()

    def test_coherent_source_and_provenance_rewrite_cannot_keep_manifest_approval(self):
        # Both live and frozen copies and the provenance agree with the attacker;
        # the independently approved provenance pin must still reject the rewrite.
        source = self.root / 'new-helper.py'
        frozen = self.stage / 'evidence/new-helper.py'
        frozen.parent.mkdir()
        source.write_bytes(b'coherent changed source')
        frozen.write_bytes(source.read_bytes())
        digest = evidence.sha(source.read_bytes())
        self.prov['source_sha256']['new-helper.py'] = digest
        self.prov['stage_sha256']['evidence/new-helper.py'] = digest
        (self.stage / 'provenance.json').write_text(json.dumps(self.prov))
        self.assertEqual(evidence.sha(self.path.read_bytes()), self.digest)
        with patch.object(evidence, '_collect') as collector:
            with self.assertRaisesRegex(ValueError, 'unapproved stage provenance'):
                evidence.check_stage(self.path, self.digest, self.pins, self.prov_digest)
            collector.assert_not_called()


class OptimizationControl(unittest.TestCase):
    @unittest.skipUnless(sys.flags.optimize, 'optimized interpreter control')
    def test_optimized_stager_refuses_before_mutation(self):
        with tempfile.TemporaryDirectory() as d:
            destination = Path(d) / 'must-not-exist'
            with self.assertRaisesRegex(ValueError, 'optimization rejected'):
                stager.stage({}, {}, destination)
            self.assertFalse(destination.exists())


if __name__ == '__main__':
    unittest.main()
