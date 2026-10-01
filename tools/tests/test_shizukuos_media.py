# SPDX-License-Identifier: GPL-2.0-only
"""Production/QA policy, UEFI installer visibility and stale-source refusals.

These exercise real media assembly helpers with owned synthetic input bytes;
they do not claim that an ISO or Windows 98 has booted.
"""
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import shizuku_se_media as media


class MediaContract(unittest.TestCase):
    def test_default_boot_is_persistent_desktop_and_dos01_is_retired(self):
        menu = media.boot_menu('/DOS10.IMG').decode('ascii')
        self.assertIn('DEFAULT desktop\n', menu)
        self.assertIn('BOOT.ELF shz.desktop ---', menu)
        self.assertIn('INITRD /DOS10.IMG', menu)
        self.assertIn('PROMPT 0\n', menu)
        self.assertNotIn('shzdos01', menu.lower())
        self.assertNotIn('0.1', menu)

    def test_public_installation_is_interactive_and_qa_requires_explicit_choice(self):
        normal = media.boot_menu('/DOS10.IMG', setup=True)
        qa = media.boot_menu('/DOS10.IMG', setup=True, desktop=False, unattended=True)
        self.assertIn(b'shz.setup=interactive shz.noapps', normal)
        self.assertNotIn(b'shz.setup=auto', normal)
        self.assertIn(b'DEFAULT kernel64\n', qa)
        self.assertIn(b'shz.setup=auto shz.noapps', qa)
        self.assertNotIn(b'LABEL desktop\n', qa)

    def test_no_setup_profile_has_no_install_menu_entry(self):
        menu = media.boot_menu('/DOS10.IMG', setup=False)
        self.assertNotIn(b'LABEL setup\n', menu)
        self.assertNotIn(b'INSTALL.IMG', menu)

    def test_install_policy_is_explicit_and_bounded(self):
        self.assertIn(b'mode = install\r\n', media.boot_ini('install'))
        for mode in ('installer', 'legacy', ''):
            with self.assertRaises(ValueError): media.boot_ini(mode)
        for timeout in (-1, 31):
            with self.assertRaises(ValueError): media.boot_ini('install', timeout)

    def inputs(self, root):
        paths = {}
        for name in ('loader', 'csm', 'dos'):
            path = root / (name + '.fixture')
            path.write_bytes(('owned synthetic ' + name).encode('ascii'))
            paths[name] = media.Input(name, path, 'host fixture')
        return paths

    def test_installer_is_inside_the_uefi_fat_file_set(self):
        with tempfile.TemporaryDirectory() as directory:
            files = self.inputs(Path(directory))
            archive = b'owned installer archive fixture'
            members = media.efi_members(files['loader'], files['csm'], {'DISK.IMG': files['dos']},
                                        'install', {'SHZ/SETUP/INSTALL.IMG': archive})
            self.assertEqual(members['SHZ/SETUP/INSTALL.IMG'], archive)
            self.assertEqual(members['SHZDOS/DISK.IMG'], files['dos'].data)
            self.assertIn(b'mode = install', members['EFI/SHIZUKU/BOOT.INI'])

    def test_missing_or_empty_uefi_installer_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            files = self.inputs(Path(directory))
            for setup in (None, {}, {'SHZ/SETUP/INSTALL.IMG': b''}, {'SHZ/SETUP/README.TXT': b'doc only'}):
                with self.assertRaises(RuntimeError):
                    media.efi_members(files['loader'], files['csm'], {}, 'install', setup)
            normal = media.efi_members(files['loader'], files['csm'], {}, 'kernel64')
            self.assertNotIn('SHZ/SETUP/INSTALL.IMG', normal)

    def test_stale_source_cannot_be_packaged_beside_an_old_binary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'kernel.c'; source.write_bytes(b'compiled source')
            pins = {'kernel.c': hashlib.sha256(source.read_bytes()).hexdigest()}
            with patch.object(media, 'ROOT', root):
                self.assertEqual(media.verify_source_pins(pins, 'fixture'), 1)
                source.write_bytes(b'changed source')
                with self.assertRaisesRegex(RuntimeError, 'source changed'): media.verify_source_pins(pins, 'fixture')
                source.unlink()
                with self.assertRaisesRegex(RuntimeError, 'source changed'): media.verify_source_pins(pins, 'fixture')

    def test_missing_receipt_and_escaping_source_paths_are_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(media, 'ROOT', Path(directory)):
                for pins in (None, {}, {'../outside.c': 'x' * 64}, {'/outside.c': 'x' * 64}):
                    with self.assertRaises(RuntimeError): media.verify_source_pins(pins, 'fixture')

    def test_loader_static_gate_requires_actual_installer_path_and_command(self):
        data = ('\\EFI\\SHIZUKU\\BOOT.INI'.encode('utf-16-le') +
                b'Shizuku boot manager menu firmware hole(s) handed over at 0x6000')
        self.assertFalse(media.loader_features(data)['installer'])
        data += '\\SHZ\\SETUP\\INSTALL.IMG'.encode('utf-16-le')
        self.assertFalse(media.loader_features(data)['installer'])
        data += b'shz.setup=interactive shz.noapps'
        self.assertTrue(all(media.loader_features(data).values()))


if __name__ == '__main__':
    unittest.main()
