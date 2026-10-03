# SPDX-License-Identifier: GPL-2.0-only
"""BIOS format and producer-output boundary controls; no guest proof."""
import importlib.util
from pathlib import Path
import sys
import unittest

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location('system_bios', TOOLS/'build_seabios.py')
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


class BIOSControls(unittest.TestCase):
    def test_bounded_system_reset_layout(self):
        raw = bytearray(256 << 10); raw[-16:] = bytes.fromhex('ea5be000f030362f32332f393900fc00')
        self.assertEqual(p.bios_metadata(raw)['reset_segment'], 0xf000)
        for offset in (-16, -12, -10, -2):
            changed = bytearray(raw); changed[offset] ^= 0x40
            with self.subTest(offset=offset), self.assertRaises(ValueError):
                p.bios_metadata(changed)
        for size in (65536, 131072, (256 << 10)-1, (256 << 10)+1):
            with self.subTest(size=size), self.assertRaises(ValueError):
                p.bios_metadata(bytes(size))

    def test_source_map_digest_is_order_independent_and_binds_values(self):
        self.assertEqual(p.map_digest({'b': '2', 'a': '1'}), p.map_digest({'a': '1', 'b': '2'}))
        self.assertNotEqual(p.map_digest({'a': '1'}), p.map_digest({'a': '2'}))

    def test_generated_kconfig_disabled_features_must_be_absent(self):
        raw = b'CONFIG_QEMU=y\nCONFIG_ROM_SIZE=256\n# CONFIG_BOOTMENU is not set\n# CONFIG_XEN is not set\n'
        p.verify_configuration(raw)
        for before, after in ((b'CONFIG_ROM_SIZE=256', b'CONFIG_ROM_SIZE=128'),
                              (b'# CONFIG_BOOTMENU is not set', b'CONFIG_BOOTMENU=y'),
                              (b'# CONFIG_XEN is not set', b'CONFIG_XEN=y')):
            with self.subTest(before=before), self.assertRaises(ValueError):
                p.verify_configuration(raw.replace(before, after))


if __name__ == '__main__':
    unittest.main()
