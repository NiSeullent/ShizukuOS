# SPDX-License-Identifier: GPL-2.0-only
"""producer-b11: explicit owned-machine input option -> live Attempt -> W98INPT.BIN.

Real task_custody.prepare_original_intent / admit_original_epoch with a real
LeaseUnion (real read leases) and the real native_epoch_host.Attempt; the
external native builder / VM preparer are the same small stand-ins as
test_original_epoch_generated_manifest, except that the builder stand-in runs
the REAL build.py input validators over the held file. The produced bytes are
then parsed by the REAL native_input.c parser (compiled here) and the actual
native_device_gate.c binding is exercised by input_gate_host.c. No QEMU, no
media, no guest: nothing here is keyboard/mouse delivery evidence.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
NATIVE = HERE.parent
sys.path.insert(0, str(HERE))
import test_original_epoch_generated_manifest as gen  # noqa: E402

guardian = gen.guardian
host = gen.host
sys.path.insert(0, str(NATIVE))
import build as builder  # noqa: E402

OPTION = {'schema': 'shizukuos.w98-owned-input-option.v1', 'machine': 'q35-i8042', 'keyboard': True, 'mouse': True}
CFLAGS = ['-std=c11', '-D_GNU_SOURCE', '-O1', '-Wall', '-Wextra', '-Werror', '-I', str(NATIVE.parents[1] / 'csmwrap')]


def compile_c(out, name, *extra):
    if not shutil.which('gcc'):
        raise RuntimeError('gcc required; validation incomplete')
    binary = Path(out) / name
    subprocess.run(['gcc', *CFLAGS, str(HERE / (name + '.c')), *map(str, extra), '-o', str(binary)],
                   check=True, timeout=60, capture_output=True)
    return binary


class OwnedInputProducer(gen.GeneratedOriginalEpochManifest):
    @classmethod
    def setUpClass(cls):
        cls.cbin = tempfile.TemporaryDirectory()
        cls.parser = compile_c(cls.cbin.name, 'input_parser_host')

    @classmethod
    def tearDownClass(cls):
        cls.cbin.cleanup()

    def setUp(self):
        super().setUp()
        self.builder_args = []

    def generate_input(self, tag, option=OPTION, persistence=False):
        original = guardian.prepare_original_intent
        outer = self
        def with_option(intent, *rest):
            if option is not None:
                intent = {**intent, 'owned_input': copy.deepcopy(option)}
            return original(intent, *rest)
        real_patch = patch.object
        def wrap_builder(name, row, union):
            module = modules_seen[name]
            if name != 'original_epoch_native_builder':
                return module
            def builder_main(args, receipt_sink):
                outer.builder_args.append(list(args))
                if '--input-policy' in args:
                    vga = Path(gen._arg(args, '--vga-config')).read_bytes()
                    raw = Path(gen._arg(args, '--input-policy')).read_bytes()
                    builder.validate_input_policy(raw, vga)        # real builder ABI admission
                    builder.optional_native_names({'VGACFG.BIN', 'VGAROM.BIN', 'W98INPT.BIN'}, {'vga-build-receipt'})
                    outer.boot = builder.boot_policy({'VGACFG.BIN', 'VGAROM.BIN', 'W98INPT.BIN'})
                captured = []
                module.main(args, captured.append)
                raw = json.loads(captured[0])
                flag = {'--vga-config': 'VGACFG.BIN', '--vga-rom': 'VGAROM.BIN', '--persistence-config': 'W98PERS.BIN',
                        '--input-policy': 'W98INPT.BIN'}
                raw['optional_native_inputs'] = {flag[f]: {'path': gen._arg(args, f), 'sha256': gen._arg(args, f + '-sha256'),
                                                           'bytes': os.stat(gen._arg(args, f)).st_size}
                                                 for f in flag if f in args}
                data = json.dumps(raw).encode()
                (Path(gen._arg(args, '--out')) / 'result.json').write_bytes(data); receipt_sink(data)
            return type('B', (), {'main': staticmethod(builder_main), 'source_files': staticmethod(lambda: [])})
        modules_seen = {}
        def capture_patch(target, attribute, side_effect=None, **kw):
            if target is guardian and attribute == 'admitted_module':
                def chained(name, row, union):
                    modules_seen[name] = side_effect(name, row, union)
                    return wrap_builder(name, row, union)
                return real_patch(target, attribute, side_effect=chained, **kw)
            return real_patch(target, attribute, side_effect=side_effect, **kw)
        with patch.object(guardian, 'prepare_original_intent', side_effect=with_option), \
             patch.object(gen, 'patch', type('P', (), {'object': staticmethod(capture_patch)})):
            return self.generate(tag, persistence=persistence)

    def parse(self, blob, policy):
        with tempfile.TemporaryDirectory() as d:
            b, p = Path(d) / 'b', Path(d) / 'p'
            b.write_bytes(blob); p.write_bytes(policy)
            run = subprocess.run([str(self.parser), str(b), str(p)], capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        return run.stdout.strip()

    def held(self, manifest):
        row = manifest['optional_native_inputs']['W98INPT.BIN']
        return Path(row['path']).read_bytes(), row

    def test_selected_produces_live_bound_file_parsed_by_real_consumer(self):
        manifest, ctx = self.generate_input('sel')
        attempt = ctx['attempt']
        blob, row = self.held(manifest)
        self.assertEqual(len(blob), 96)
        self.assertEqual(blob[16:48], attempt.nonce)
        self.assertEqual(blob[48:80], attempt.policy[48:80])
        self.assertEqual(attempt.policy[216:248], hashlib.sha256(blob).digest())
        self.assertEqual(row['sha256'], hashlib.sha256(blob).hexdigest())
        self.assertEqual(manifest['owned_input'], OPTION)
        self.assertEqual(self.parse(blob, attempt.policy), 'ADMIT flags=3 machine=1')
        args = self.builder_args[-1]
        self.assertEqual(args.count('--input-policy'), 1)
        self.assertEqual(gen._arg(args, '--input-policy-sha256'), row['sha256'])
        self.assertIn(b'win98_input=yes\r\n', self.boot)
        self.assertIn(row['path'], self.union.rows)          # held under the guardian read lease
        self.assertIsNone(self.admit(manifest, ctx))
        self.assertEqual(os.stat(row['path']).st_mode & 0o777, 0o400)

    def test_mouse_only_and_option_validation(self):
        manifest, ctx = self.generate_input('m', option={**OPTION, 'keyboard': False})
        blob, _ = self.held(manifest)
        self.assertEqual(self.parse(blob, ctx['attempt'].policy), 'ADMIT flags=2 machine=1')
        for bad in ({**OPTION, 'extra': 1}, {**OPTION, 'keyboard': False, 'mouse': False}, {**OPTION, 'schema': 'v2'},
                    {**OPTION, 'machine': 'usb'}, {**OPTION, 'mouse': 1}, {k: v for k, v in OPTION.items() if k != 'mouse'}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                guardian.owned_input_flags(bad)

    def test_absent_option_is_unchanged(self):
        manifest, ctx = self.generate_input('abs', option=None)
        attempt = ctx['attempt']
        self.assertNotIn('owned_input', manifest)
        self.assertNotIn('W98INPT.BIN', manifest['optional_native_inputs'])
        self.assertFalse(any('--input-policy' in a for a in self.builder_args))
        self.assertFalse((Path(manifest['plan']['path']).parents[1] / 'input').exists())
        self.assertEqual(attempt.policy[216:256], bytes(40))
        vga, rom, pers, bars = gen.epoch_tests.configs()
        legacy = host.Expectations(vga, rom, None, {1: bars[1]})
        self.assertEqual(legacy.policy(attempt.nonce, 10**18), host.Expectations(vga, rom, None, {1: bars[1]}, 0).policy(attempt.nonce, 10**18))
        self.assertNotIn(b'win98_input', builder.boot_policy({'VGACFG.BIN', 'VGAROM.BIN'}))
        with self.assertRaises(ValueError):
            attempt.input_policy()                     # no option -> no producer
        self.assertIsNone(self.admit(manifest, ctx))
        bad = copy.deepcopy(manifest); bad['owned_input'] = dict(OPTION)
        self.refuse(bad, ctx)                          # option claimed after the fact

    def test_wrong_nonce_wrong_vga_hash_and_foreign_context(self):
        manifest, ctx = self.generate_input('a')
        other, octx = self.generate_input('b')
        blob, _ = self.held(manifest)
        self.assertEqual(self.parse(blob, octx['attempt'].policy), 'REFUSE')          # another Attempt's nonce
        vga = bytearray(blob); vga[48] ^= 1
        self.assertEqual(self.parse(bytes(vga), ctx['attempt'].policy), 'REFUSE')
        with self.assertRaises(ValueError):
            builder.validate_input_policy(bytes(vga), Path(manifest['optional_native_inputs']['VGACFG.BIN']['path']).read_bytes())
        for mutate in ((8, 4), (12, 2), (4, 2), (80, 1)):
            raw = bytearray(blob); raw[mutate[0]] = mutate[1]
            self.assertEqual(self.parse(bytes(raw), ctx['attempt'].policy), 'REFUSE')
            with self.assertRaises(ValueError): builder.validate_input_policy(bytes(raw))
        self.assertEqual(self.parse(blob + b'\0', ctx['attempt'].policy), 'REFUSE')
        self.refuse(manifest, octx)                     # foreign live Attempt
        self.refuse(other, ctx)
        _, plain = self.generate_input('c', option=None)
        self.refuse(manifest, plain)                    # context without the option
        swapped = copy.deepcopy(manifest); swapped['optional_native_inputs']['W98INPT.BIN'] = other['optional_native_inputs']['W98INPT.BIN']
        self.refuse(swapped, ctx)

    def test_old_generation_and_late_expiry(self):
        manifest, ctx = self.generate_input('g')
        attempt = ctx['attempt']
        d = time.monotonic_ns() + 50_000_000
        attempt.original_deadline_ns = attempt._deadline = d
        time.sleep(0.08)
        with self.assertRaises(ValueError): attempt.input_policy()
        self.refuse(manifest, ctx)
        manifest2, ctx2 = self.generate_input('h')
        ctx2['attempt'].close()
        self.refuse(manifest2, ctx2)                    # closed (old) Attempt
        with self.assertRaises((ValueError, TypeError)): ctx2['attempt'].input_policy()

    def test_builder_duplicate_and_unbound_input_refused(self):
        with self.assertRaises(SystemExit):
            builder.main(['--input-policy', '/x', '--input-policy=/y', '--validate-only'])
        with self.assertRaises(ValueError):
            builder.optional_native_names({'W98INPT.BIN', 'W98PERS.BIN'}, set())   # input without the VGA pair
        self.assertEqual(builder.OPTIONAL_NATIVE_SIZES['W98INPT.BIN'], 96)

    def test_actual_gate_binding(self):
        out = compile_c(self.cbin.name, 'input_gate_host', NATIVE / 'native_device_gate.c',
                        NATIVE / 'native_device_epoch.c', NATIVE / 'l1_vga.c')
        run = subprocess.run([str(out)], capture_output=True, text=True, timeout=60)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertIn('PASS', run.stdout)
        self.assertIn('refusal108', run.stdout)


if __name__ == '__main__':
    unittest.main()
