# SPDX-License-Identifier: GPL-2.0-only
"""Generated original-epoch manifest -> admit_original_epoch (no hand-made epoch block).

The production task_custody.prepare_original_intent() runs with a real
LeaseUnion, real read leases, the real native_epoch_host.Attempt/PrivateListener
and the real persist(); only the external native builder/VM preparer producers
are small stand-ins that write their receipts.  The manifest admitted is the
one actually generated and persisted, read back through JSON.  No QEMU, disk
media or HostGrant exchange executes; nothing here is boot/display evidence.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import test_original_disk_lineage as lineage  # noqa: E402
import test_native_epoch_host as epoch_tests  # noqa: E402

guardian = lineage.guardian
host = epoch_tests.host


def _arg(args, flag):
    return args[args.index(flag) + 1]


class GeneratedOriginalEpochManifest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR'))
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); os.chmod(self.root, 0o700)
        (self.root / 'in').mkdir(mode=0o700)
        self.union = guardian.LeaseUnion(); self.addCleanup(self.union.close)
        self.sources = {guardian.NATIVE_EPOCH_SOURCE: {}, guardian.HELPERS[0]: {}, guardian.HELPERS[1]: {}}

    def write(self, name, data):
        p = self.root / 'in' / name
        if not p.exists(): p.write_bytes(data); p.chmod(0o600)
        return {'path': str(p), 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest()}

    def generate(self, tag, persistence=True):
        vga, rom, pers, bars = epoch_tests.configs()
        disk = self.write('DISK.IMG', b'D' * 4096)
        optional = {'VGACFG.BIN': self.write('VGACFG.BIN', vga), 'VGAROM.BIN': self.write('VGAROM.BIN', rom)}
        if persistence: optional['W98PERS.BIN'] = self.write('W98PERS.BIN', pers)
        private = self.root / ('private-' + tag); private.mkdir(mode=0o700)
        intent = {'schema': guardian.ORIGINAL_EPOCH_INTENT_SCHEMA, 'repo': str(self.root), 'sources': {}, 'limits': {},
                  'timeout': 60, 'lineage': [self.write('profile.json', json.dumps({'source_disk': disk}).encode())],
                  'producers': [self.write('observer.py', b'#o\n'), self.write('fat.py', b'#f\n')],
                  'native_inputs': {'DISK.IMG': disk, **{n: self.write(n, n.encode()) for n in
                                    ('SEABIOS.BIN', 'WIN98CFG.BIN', 'KERNEL32.BIN', 'KERNEL64.BIN', 'WIN64.IMG')}},
                  'optional_native_inputs': optional,
                  'optional_native_provenance': {'vga-build-receipt': self.write('vga-build.json', b'{}')},
                  # JSON intent keys are strings; the live Attempt keys are ints.
                  'raw_bars': {str(role): list(words) for role, words in bars.items() if persistence or role == 1},
                  'firmware': {n: self.write(n, n.encode()) for n in ('firmware_code', 'firmware_vars', 'qemu')},
                  'private_root': str(private), 'assembly_scratch': None}
        def builder_main(args, receipt_sink):
            out = Path(_arg(args, '--out')); out.mkdir(mode=0o700)
            (out / 'esp.img').write_bytes(b'E' * 4096)
            raw = json.dumps({'VM_executed': False, 'input_pins': {'DISK.IMG': disk},
                              'artifact': {'path': 'esp.img', 'bytes': 4096,
                                           'sha256': hashlib.sha256(b'E' * 4096).hexdigest()}}).encode()
            (out / 'result.json').write_bytes(raw); receipt_sink(raw)
        def preparer_main(args, receipt_sink, epoch_binding):
            out = Path(_arg(args, '--out')); out.mkdir(mode=0o700)
            raw = json.dumps({'prospective_native_epoch_recipe': epoch_binding}).encode()
            (out / 'vm-plan.json').write_bytes(raw); receipt_sink(raw)
        modules = {'original_epoch_live_policy': host,
                   'original_epoch_native_builder': SimpleNamespace(source_files=lambda: [], main=builder_main),
                   'original_epoch_vm_preparer': SimpleNamespace(main=preparer_main)}
        with patch.object(guardian, 'admitted_module', side_effect=lambda name, row, union: modules[name]):
            manifest, context = guardian.prepare_original_intent(intent, self.union, self.sources, lambda: None)
        self.addCleanup(context['attempt'].close); self.addCleanup(context['listener'].close)
        persisted = json.loads((private / 'generated-custody-manifest.json').read_bytes())
        self.assertEqual(persisted, manifest)
        return persisted, context

    def admit(self, manifest, context):
        return guardian.admit_original_epoch(manifest, self.sources, context)

    def refuse(self, manifest, context):
        with self.assertRaises(ValueError): self.admit(manifest, context)

    def test_generated_manifest_admitted_with_integer_roles(self):
        manifest, context = self.generate('a')
        self.assertEqual(manifest['original_device_epoch']['selected_roles'], [1, 2])
        self.assertIsNone(self.admit(manifest, context))
        self.assertTrue(all(manifest['original_device_epoch'][n] is False for n in guardian.ORIGINAL_EPOCH_FALSE))

    def test_generated_vga_only_manifest_admitted(self):
        manifest, context = self.generate('v', persistence=False)
        self.assertEqual(manifest['original_device_epoch']['selected_roles'], [1])
        self.assertIsNone(self.admit(manifest, context))

    def test_tampered_or_stale_generated_variants_refused(self):
        manifest, context = self.generate('a')
        other, other_context = self.generate('b')
        cases = []
        bad = copy.deepcopy(manifest); bad['original_device_epoch']['selected_roles'] = ['1', '2']; cases.append((bad, context))
        bad = copy.deepcopy(manifest); bad['original_device_epoch']['selected_roles'] = [1]; cases.append((bad, context))
        bad = copy.deepcopy(manifest); bad['original_device_epoch']['VM_executed'] = True; cases.append((bad, context))
        bad = copy.deepcopy(manifest); del bad['optional_native_inputs']['W98PERS.BIN']; cases.append((bad, context))
        bad = copy.deepcopy(manifest); bad['original_device_epoch']['live_policy']['nonce_sha256'] = '0' * 64
        cases.append((bad, context))
        cases.append((manifest, other_context))   # stale: another live Attempt's policy
        cases.append((other, context))
        cases.append((manifest, {**context, 'phase': 'shizukuos.native-custody-gop-intent.v1'}))
        for bad, ctx in cases:
            with self.subTest(case=len(cases)): self.refuse(bad, ctx)
        context['attempt'].close()
        self.refuse(manifest, context)   # closed/consumed Attempt cannot be admitted


if __name__ == '__main__':
    unittest.main()
