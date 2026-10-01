# SPDX-License-Identifier: GPL-2.0-only
"""Media-selection and diagnostic-policy regressions; these do not boot a VM."""
import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import test_shizuku_se_boot_matrix as matrix


class MatrixInputs(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='shz-matrix-input-')
        self.root = Path(self.temporary.name)
        self.dos = self.root / 'DOS10.IMG'
        self.dos.write_bytes(b'owned synthetic DOS10 fixture')
        self.iso = self.medium('iso')
        self.disk = self.medium('disk')

    def tearDown(self):
        self.temporary.cleanup()

    def medium(self, name):
        path = self.root / (name + '.fixture')
        path.write_bytes(b'owned medium ' + name.encode())
        receipt = {'sha256': matrix.shzlib.sha256_file(path), 'boot_profile': 'desktop',
                   'menu': {'keys': {'kernel64': 'k', 'dos16': 'd'}, 'k64_dir': '/SHZ/K64',
                            'dos16': '/SHZDOS/DISK.IMG', 'setup_entry': False,
                            'uefi': {'boot_ini': {'mode': 'kernel64', 'menu_timeout': 5}}},
                   'inputs': [{'name': 'DISK.IMG', 'path': str(self.dos),
                               'sha256': matrix.shzlib.sha256_file(self.dos)}]}
        path.with_suffix('.json').write_text(json.dumps(receipt))
        return path

    def test_current_menu_does_not_require_retired_input(self):
        ctx = matrix.media_context(self.iso, self.disk)
        self.assertEqual(set(ctx['loads']['iso-cd']), {'kernel64', 'dos16'})
        self.assertNotIn('shzdos01', matrix.ENTRIES)
        self.assertNotIn('install', matrix.ENTRIES)

    def test_iso_only_does_not_require_a_disk_image(self):
        ctx = matrix.media_context(self.iso, self.root / 'missing.disk', ['iso-cd'])
        self.assertNotIn('disk', ctx)
        self.assertEqual(set(ctx['loads']), {'iso-cd'})
        self.assertEqual(ctx['dos16_image'], self.dos.read_bytes())

    def test_disk_only_does_not_require_an_iso(self):
        ctx = matrix.media_context(self.root / 'missing.iso', self.disk, ['disk'])
        self.assertNotIn('iso', ctx)
        self.assertEqual(set(ctx['loads']), {'disk'})

    def test_iso_usb_uses_only_the_selected_iso(self):
        ctx = matrix.media_context(self.iso, self.root / 'missing.disk', ['iso-usb'])
        self.assertEqual(set(ctx['loads']), {'iso-usb'})

    def test_conflicting_menu_keys_refuse_a_mixed_media_set(self):
        receipt = self.disk.with_suffix('.json')
        data = json.loads(receipt.read_text()); data['menu']['keys']['dos16'] = 'x'
        receipt.write_text(json.dumps(data))
        with self.assertRaisesRegex(SystemExit, 'disagree'):
            matrix.media_context(self.iso, self.disk)

    def test_changed_medium_is_refused(self):
        self.iso.write_bytes(b'changed after receipt')
        with self.assertRaisesRegex(SystemExit, 'does not match'):
            matrix.media_context(self.iso, self.disk, ['iso-cd'])

    def test_changed_component_image_is_refused(self):
        self.dos.write_bytes(b'changed after media assembly')
        with self.assertRaisesRegex(SystemExit, 'changed since'):
            matrix.media_context(self.iso, self.disk, ['iso-cd'])

    def test_absolute_dos_receipt_names_load_the_recorded_image(self):
        receipt = self.iso.with_suffix('.json')
        data = json.loads(receipt.read_text())
        for name in (r'\SHZDOS\DISK.IMG', '/SHZDOS/DISK.IMG'):
            with self.subTest(name=name):
                data['inputs'][0]['name'] = name
                receipt.write_text(json.dumps(data))
                ctx = matrix.media_context(self.iso, self.disk, ['iso-cd'])
                self.assertEqual(ctx['dos16_image'], b'owned synthetic DOS10 fixture')

    def test_missing_dos_receipt_input_is_explicitly_refused(self):
        receipt = self.iso.with_suffix('.json')
        data = json.loads(receipt.read_text())
        data['inputs'][0]['name'] = r'\OTHER\DISK.IMG'
        receipt.write_text(json.dumps(data))
        with self.assertRaisesRegex(SystemExit, 'no DOS16.*input'):
            matrix.media_context(self.iso, self.disk, ['iso-cd'])

    def test_ambiguous_dos_receipt_inputs_are_refused(self):
        receipt = self.iso.with_suffix('.json')
        data = json.loads(receipt.read_text())
        data['inputs'].append(dict(data['inputs'][0], name=r'\SHZDOS\DISK.IMG'))
        receipt.write_text(json.dumps(data))
        with self.assertRaisesRegex(SystemExit, 'ambiguous DOS16.*inputs'):
            matrix.media_context(self.iso, self.disk, ['iso-cd'])

    def test_qualified_dos_receipt_still_refuses_changed_image(self):
        receipt = self.iso.with_suffix('.json')
        data = json.loads(receipt.read_text())
        data['inputs'][0]['name'] = r'\SHZDOS\DISK.IMG'
        receipt.write_text(json.dumps(data))
        self.dos.write_bytes(b'changed after media assembly')
        with self.assertRaisesRegex(SystemExit, 'changed since'):
            matrix.media_context(self.iso, self.disk, ['iso-cd'])

    def test_empty_or_unknown_selection_is_refused(self):
        for selected in ([], ['physical-usb']):
            with self.assertRaises(ValueError):
                matrix.media_context(self.iso, self.disk, selected)

    def test_production_desktop_cannot_pass_as_direct_diagnostic_exit(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            matrix.main(['--iso', str(self.iso), '--media', 'iso-cd', '--firmware', 'ovmf',
                         '--entries', 'k64direct'])
        self.assertEqual(raised.exception.code, 2)

    def test_retired_entry_is_rejected_before_vm_launch(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as raised:
            matrix.main(['--entries', 'shzdos01'])
        self.assertEqual(raised.exception.code, 2)

    def test_uefi_legacy_selection_checks_the_shipped_policy_and_explicit_key(self):
        text = '\n'.join([
            'BdsDxe: starting Boot0002 "UEFI QEMU DVD-ROM',
            'ShizukuOS development Supervisor loader (UEFI x64) - ShizukuDOS 10',
            r'Boot manager: \EFI\SHIZUKU\BOOT.INI mode=kernel64, csm_path=\EFI\SHIZUKU\CSMWRAP.EFI, auto_kernel64=no, menu_timeout=5',
            'Shizuku boot manager menu: press a key within 5 seconds',
            "Boot manager menu: key 'C': mode=csm for this boot",
            'CSM legacy boot (mode=csm): chain-loading CSMWrap',
            'BIOS proxy ready (AP 1)', 'bootdev: Boot device: PCI 00:1f.2 type=CD', 'ISOLINUX 6.04'])
        policy = {'mode': 'kernel64', 'menu_timeout': 5}
        checks = matrix.boot_path_checks('ovmf', 'iso-cd', 'dos16', text, ['if=pflash'], policy)
        self.assertTrue(all(row['status'] == 'PASS' for row in checks), checks)
        bad = matrix.boot_path_checks('ovmf', 'iso-cd', 'dos16', text.replace('mode=kernel64,', 'mode=auto,'),
                                      ['if=pflash'], policy)
        self.assertTrue(any(row['status'] == 'FAIL' for row in bad))


if __name__ == '__main__':
    unittest.main()
