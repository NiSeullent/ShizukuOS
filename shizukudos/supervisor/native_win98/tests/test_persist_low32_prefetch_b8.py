#!/usr/bin/env python3
"""Physical-shape regressions for the modern virtio-blk W98PERS expectation.

Fixtures are the persist-b8 lane's own firmware-only paused Q35 probes
(qemu-kvm 10.1.0-16.el10_2.5, edk2-ovmf-20251114, no Windows media, no NIC,
empty 2304 MiB disk). They are EXPECTATION inputs, never a device grant or
evidence that Win98 persistence works.

* default recipe: modern BAR4 raw 0x0000000c/0x00003800 (0x380000000000).
* X-PciMmio64Mb=0: modern BAR4 raw 0x8101000c/0x00000000 (64-bit prefetch,
  assigned 0x81010000 below 4 GiB).
The probe read 'xp /16wx' of each selected ECAM function; fixtures keep only
the first 10 observed DWORDs (the encoder's exact 40-byte window), unchanged.
"""
import copy
import importlib.util
import json
import struct
import sys
import unittest
from pathlib import Path

NATIVE = Path(__file__).resolve().parents[1]
FIXTURES = Path(__file__).resolve().parent / 'fixtures'


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


expectation = load('persist_b8_expectation', NATIVE / 'original_epoch_expectation.py')
host = expectation.host
prepare = load('persist_b8_prepare', NATIVE / 'prepare_vm.py')
ROM = b'R' * 65536
RECEIPT = {'source_tree_digest_sha256': '5a' * 32, 'generated_configuration_sha256': 'c3' * 32}


def observation(name):
    return json.loads((FIXTURES / name).read_text())


class ModernLow32Prefetch(unittest.TestCase):
    def setUp(self):
        self.low = observation('persist_b8_observation_mmio64_off.json')
        self.high = observation('persist_b8_observation_default.json')

    def derive(self, obs):
        flat, selected = expectation.select(obs['snapshots'][0], True)
        vga = expectation.encode_vga(selected[1]['row']['bdf'], selected[1]['base'], ROM, RECEIPT)
        pers = expectation.encode_persistence(selected[2]['row'])
        bars = {role: tuple(s['words'][4:10]) for role, s in selected.items()}
        return flat, vga, pers, bars

    def test_observed_low32_modern_prefetch_bar_is_admitted_and_pinned(self):
        flat, vga, pers, bars = self.derive(self.low)
        self.assertEqual(bars[2], (0x6001, 0x81015000, 0, 0, 0x8101000c, 0))
        self.assertEqual(struct.unpack_from('<QQII', pers, 40 + 4 * 24), (0x81010000, 16384, 2, 0))
        expected = host.Expectations(vga, ROM, pers, bars)
        storage = [d for d in expected.devices if d.role == 2][0]
        self.assertIn((4, 0x81010000, 16384, 'memory', True, True), storage.regions)
        policy = expected.policy(bytes(range(1, 33)), 1 << 40)
        self.assertEqual(struct.unpack_from('<6I', policy, 168 + 24), bars[2])
        for snapshot in self.low['snapshots']:
            found = host.validate_pci(snapshot['query-pci'], expected, host.parse_flatview(snapshot['info-mtree-f']))
            self.assertIn((4, 0x81010000, 16384, 'memory', True, True), found[16])

    def test_default_recipe_high_bar_is_refused(self):
        with self.assertRaisesRegex(Exception, 'above 4 GiB.*X-PciMmio64Mb'):
            expectation.select(self.high['snapshots'][0], True)

    def test_probe_recipe_knob_must_match_persistence_selection(self):
        with self.assertRaisesRegex(Exception, 'aperture knob must match'):
            expectation.encode(self.high, ROM, RECEIPT, persistence=True)
        with self.assertRaisesRegex(Exception, 'aperture knob must match'):
            expectation.encode(self.low, ROM, RECEIPT, persistence=False)

    def test_raw_prefetch_bit_cleared_is_refused_by_current_pci(self):
        flat, vga, pers, bars = self.derive(self.low)
        bars[2] = bars[2][:4] + (0x81010004, 0)
        expected = host.Expectations(vga, ROM, pers, bars)  # non-prefetch Mem64 shape
        snapshot = self.low['snapshots'][0]
        with self.assertRaisesRegex(Exception, 'configured BAR base/size/type differs'):
            host.validate_pci(snapshot['query-pci'], expected, host.parse_flatview(snapshot['info-mtree-f']))

    def test_prefetch_only_for_modern_mem64_below_4g(self):
        flat, vga, pers, bars = self.derive(self.low)
        self.assertEqual(struct.unpack_from('<H', pers, 12)[0], 0x1001)  # observed transitional function
        modern = bytearray(pers); struct.pack_into('<H', modern, 12, 0x1042)
        host.Expectations(vga, ROM, bytes(modern), bars)
        cases = []
        cases.append((pers, bars[2][:5] + (1,), 'upper BAR differs'))
        mem32 = bytearray(pers); struct.pack_into('<QQII', mem32, 40 + 4 * 24, 0x81010000, 16384, 1, 0)
        cases.append((bytes(mem32), bars[2][:5] + (0,), 'raw BAR differs'))
        high = bytearray(pers); struct.pack_into('<QQII', high, 40 + 4 * 24, 0x380000000000, 16384, 2, 0)
        cases.append((bytes(high), bars[2][:4] + (0x0000000c, 0x3800), 'address bound'))
        cases.append((pers, bars[2][:4] + (0x8101001c, 0), 'raw BAR differs'))
        for config, raw, message in cases:
            with self.subTest(message=message, raw=raw):
                with self.assertRaisesRegex(Exception, message):
                    host.Expectations(vga, ROM, config, {1: bars[1], 2: raw})

    def test_prefetch_on_mem32_observation_is_refused(self):
        obs = copy.deepcopy(self.low['snapshots'][0])
        for bus in obs['query-pci']:
            for dev in bus['devices']:
                if dev['slot'] == 2: dev['regions'][1]['prefetch'] = True  # BAR1 MSI-X MEM32
        with self.assertRaisesRegex(Exception, 'BAR1 is not the 64-bit virtio-pci capability BAR shape'):
            expectation.select(obs, True)

    def test_recipe_producer_emits_knob_only_for_selected_persistence(self):
        out = Path('/dev/shm/persist-b8-recipe')
        binding = {'policy_fd': 7, 'listener_path': str(out / 'epoch.sock')}
        plain = prepare.recipe(Path('/usr/libexec/qemu-kvm'), out, binding)
        self.assertNotIn('name=opt/ovmf/X-PciMmio64Mb,string=0', plain)
        argv = prepare.recipe(Path('/usr/libexec/qemu-kvm'), out, {**binding, 'modern_persistence_low32': True})
        self.assertEqual(argv[-2:], ['-fw_cfg', host.MMIO64_OFF])
        self.assertEqual(argv.count('-fw_cfg'), 2)
        for bad in (False, 1, None):
            with self.assertRaises(ValueError):
                prepare.recipe(Path('/usr/libexec/qemu-kvm'), out, {**binding, 'modern_persistence_low32': bad})

    def test_hostgrant_recipe_pin_matches_producer_and_role_selection(self):
        out = Path('/dev/shm/persist-b8-recipe'); listener = str(out / 'epoch.sock')
        binding = {'policy_fd': 9, 'listener_path': listener}
        plain = tuple(prepare.recipe(Path('/usr/libexec/qemu-kvm'), out, binding))
        low = tuple(prepare.recipe(Path('/usr/libexec/qemu-kvm'), out, {**binding, 'modern_persistence_low32': True}))
        host.admit_recipe(plain, 1, 9, listener)
        host.admit_recipe(low, 3, 9, listener)
        host.admit_recipe(low, 2, 9, listener)
        refused = [(plain, 3), (plain, 2), (low, 1),
                   (low[:-1] + ('name=opt/ovmf/X-PciMmio64Mb,string=1',), 3),
                   (low + ('-fw_cfg', host.MMIO64_OFF), 3),
                   (plain + ('-fw_cfg', 'name=opt/ovmf/X-PciMmio64Mb,string=0'), 1),
                   (low + ('-fw_cfg',), 3),
                   (plain + ('-fw_cfg', 'name=opt/other,string=1'), 1)]
        for argv, roles in refused:
            with self.subTest(roles=roles, tail=argv[-3:]):
                with self.assertRaisesRegex(Exception, 'low32 PCI aperture recipe'):
                    host.admit_recipe(argv, roles, 9, listener)


if __name__ == '__main__':
    unittest.main()
