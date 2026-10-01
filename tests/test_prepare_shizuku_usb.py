# SPDX-License-Identifier: GPL-2.0-only
"""Host fixtures only: no Windows binaries, VM or device write/boot evidence."""
import argparse
from contextlib import redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile

PATH = Path(__file__).resolve().parents[1] / 'tools/prepare_shizuku_usb.py'
SPEC = importlib.util.spec_from_file_location('prepare_shizuku_usb', PATH)
usb = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(usb)


def run(args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def fake_cab(names):
    # Synthetic CFFILE name metadata only. Not a Windows installation CAB.
    header = bytearray(36)
    header[:4] = b'MSCF'
    struct.pack_into('<I', header, 16, 36)
    struct.pack_into('<H', header, 28, len(names))
    return bytes(header) + b''.join(b'\0' * 16 + n.encode('cp437') + b'\0' for n in names)


@unittest.skipUnless(all(shutil.which(n) for n in ('xorriso', 'mcopy', 'mmd', 'mkfs.vfat')),
                     'Host ISO/FAT fixture tools are required')
class PreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix='shizuku-usb-host-fixtures-')
        cls.root = Path(cls.tmp.name)
        tree = cls.root / 'iso-tree'
        efi = {name: ('synthetic host fixture: ' + name).encode() for name in usb.REQUIRED_EFI}
        efi['SHZDOS/KERNEL64.INI'] = b'cmdline = shz.desktop\r\n'
        efi['EFI/SHIZUKU/BOOT.INI'] = b'mode = kernel64\r\nmenu_timeout = 5\r\n'
        image = cls.root / 'efi-fixture.img'
        with image.open('wb') as out:
            out.truncate(16 << 20)
        run(['mkfs.vfat', '--invariant', '-F', '16', str(image)])
        for name in ('EFI', 'EFI/BOOT', 'EFI/SHIZUKU', 'SHZDOS'):
            run(['mmd', '-i', str(image), '::/' + name])
        for i, (name, data) in enumerate(sorted(efi.items())):
            local = cls.root / ('efi-' + str(i))
            local.write_bytes(data)
            run(['mcopy', '-i', str(image), str(local), '::/' + name])
        for name in usb.REQUIRED_PUBLIC:
            write(tree / name, ('synthetic public fixture: ' + name).encode())
        shutil.copyfile(image, tree / 'ShizukuDOS10/efiboot.img')
        payload = usb.folder_records(tree)
        lines = ['sha256  bytes  path'] + [f"{r['sha256']}  {r['bytes']}  {n}" for n, r in sorted(payload.items())]
        write(tree / 'HASHES.TXT', ('\r\n'.join(lines) + '\r\n').encode('ascii'))
        cls.iso = cls.root / 'public-fixture.iso'
        run(['xorriso', '-as', 'mkisofs', '-R', '-J', '-V', 'SHIZUKU_FIXTURE', '-o', str(cls.iso), str(tree)])
        cls.receipt = cls.root / 'builder.json'
        cls.gate = cls.root / 'gate.json'
        pin = usb.record(cls.iso)
        cls.proof = {**pin, 'private': False, 'boot_profile': 'desktop', 'setup': {'present': True},
                     'git': {'revision': 'a' * 40, 'dirty': False},
                     'efi_members': {n: {'bytes': len(d), 'sha256': hashlib.sha256(d).hexdigest()} for n, d in efi.items()}}
        usb.json_write(cls.receipt, cls.proof)
        usb.json_write(cls.gate, {**pin, 'status': usb.ISO_GATE, 'source_commit': 'a' * 40,
                                  'Windows98_media_or_publisher_binary_in_inventory': False})
        cls.public = cls.root / 'public-files'
        cls.archive = cls.root / 'public-files.zip'
        with redirect_stdout(io.StringIO()):
            usb.prepare_public(argparse.Namespace(iso=cls.iso, receipt=cls.receipt, verification=cls.gate,
                                                  output=cls.public, zip=cls.archive))
        media = cls.root / 'win98-fixture-tree'
        write(media / 'WIN98/BASE4.CAB', fake_cab(['IO.SYS', 'MSDOS.SYS', 'COMMAND.COM']))
        write(media / 'WIN98/SETUP.EXE', b'NOT WINDOWS; HOST FIXTURE ONLY')
        cls.win98 = cls.root / 'win98-fixture.iso'
        run(['xorriso', '-as', 'mkisofs', '-R', '-J', '-V', 'WIN98_FIXTURE', '-o', str(cls.win98), str(media)])

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_public_closure_and_original_boot_configuration(self):
        folder, proof = usb.verify_bundle(self.public)
        self.assertFalse(proof['private'])
        self.assertFalse(proof['USB_boot_verified'])
        self.assertFalse(proof['Windows98_setup_boot_supported'])
        self.assertEqual(proof['architecture_goal']['primary_os'], 'Windows 98')
        self.assertEqual(proof['architecture_goal']['MS_DOS_replacement'], 'ShizukuDOS')
        self.assertFalse(proof['architecture_goal']['replacement_Windows98_boot_connection_complete'])
        self.assertEqual((folder / 'SHZDOS/KERNEL64.INI').read_bytes(), b'cmdline = shz.desktop\r\n')
        self.assertEqual((folder / 'EFI/SHIZUKU/BOOT.INI').read_bytes(), b'mode = kernel64\r\nmenu_timeout = 5\r\n')
        self.assertTrue(usb.REQUIRED_PUBLIC | usb.REQUIRED_EFI <= proof['files'].keys())

    def test_public_zip_contains_every_file_and_no_private_media(self):
        with zipfile.ZipFile(self.archive) as archive:
            names = archive.namelist()
            usb.public_names(names)
            self.assertIn(usb.MANIFEST, names)
            self.assertIn('ShizukuDOS10/SOURCE/shizukudos-source.tar.gz', names)
            self.assertIn('START-KO.txt', names)
            for name in names:
                self.assertEqual(archive.read(name), (self.public / name).read_bytes())

    def test_personal_root_iso_exact_hash_and_media_identity(self):
        dest = self.root / 'personal-files'
        public_hash = usb.file_hash(self.public / usb.MANIFEST)
        source_hash = usb.file_hash(self.win98)
        with redirect_stdout(io.StringIO()):
            usb.add_win98(argparse.Namespace(bundle=self.public, win98_iso=self.win98, output=dest))
        self.assertEqual(usb.file_hash(dest / 'WIN98.ISO'), source_hash)
        self.assertEqual(usb.file_hash(self.win98), source_hash)
        self.assertEqual(usb.file_hash(self.public / usb.MANIFEST), public_hash)
        metadata = usb.json_read(dest / 'WIN98-MEDIA.json')
        self.assertEqual(metadata['iso9660']['volume_id'], 'WIN98_FIXTURE')
        self.assertEqual(metadata['sha256'], source_hash)
        self.assertEqual(metadata['required_files'].keys(), usb.MS_FILES)
        self.assertTrue(metadata['setup_exe_present'])
        self.assertFalse(metadata['installation_supported_by_preparer'])
        self.assertIn('temporary existing-media path', metadata['original_DOS_media_scope'])
        private = usb.json_read(dest / usb.MANIFEST)
        self.assertTrue(private['private'])
        self.assertEqual(private['files'], usb.folder_records(dest))
        with self.assertRaises(ValueError):
            usb.verify_bundle(dest)

    def test_mismatching_receipt_rejected_before_output(self):
        bad = self.root / 'bad-receipt.json'
        usb.json_write(bad, {**self.proof, 'sha256': '0' * 64})
        dest = self.root / 'bad-output'
        with self.assertRaises(ValueError):
            usb.prepare_public(argparse.Namespace(iso=self.iso, receipt=bad, verification=self.gate, output=dest, zip=None))
        self.assertFalse(dest.exists())

    def test_private_receipt_cannot_generate_public_bundle(self):
        bad = self.root / 'private-receipt.json'
        usb.json_write(bad, {**self.proof, 'private': True})
        dest = self.root / 'private-as-public'
        with self.assertRaises(ValueError):
            usb.prepare_public(argparse.Namespace(iso=self.iso, receipt=bad, verification=self.gate, output=dest, zip=None))
        self.assertFalse(dest.exists())

    def test_efi_byte_mismatch_rolls_back_new_output(self):
        bad = self.root / 'efi-bad-receipt.json'
        proof = json.loads(json.dumps(self.proof))
        proof['efi_members']['EFI/BOOT/BOOTX64.EFI']['sha256'] = '0' * 64
        usb.json_write(bad, proof)
        dest = self.root / 'bad-efi-output'
        with self.assertRaises(ValueError):
            usb.prepare_public(argparse.Namespace(iso=self.iso, receipt=bad, verification=self.gate, output=dest, zip=None))
        self.assertFalse(dest.exists())
        self.assertFalse(list(self.root.glob('.bad-efi-output-prepare-*')))

    def test_unusable_windows_iso_is_rejected(self):
        work = self.root / 'not-win98-work'
        work.mkdir()
        with self.assertRaisesRegex(ValueError, 'No WIN98 cabinet'):
            usb.inspect_own_iso(self.iso, work)

    def test_added_private_media_invalidates_public_manifest(self):
        folder = self.root / 'tampered-public'
        shutil.copytree(self.public, folder)
        (folder / 'WIN98.ISO').write_bytes(b'private fixture')
        with self.assertRaises(ValueError):
            usb.verify_bundle(folder)

    def test_receipt_change_during_preparation_is_rejected(self):
        changed = self.root / 'changing-receipt.json'
        usb.json_write(changed, self.proof)
        original = usb.extract
        def extraction_then_change(*args, **kwargs):
            original(*args, **kwargs)
            usb.json_write(changed, {**self.proof, 'changed': True})
        dest = self.root / 'receipt-changed-output'
        with patch.object(usb, 'extract', side_effect=extraction_then_change), self.assertRaisesRegex(ValueError, 'receipt changed'):
            usb.prepare_public(argparse.Namespace(iso=self.iso, receipt=changed, verification=self.gate, output=dest, zip=None))
        self.assertFalse(dest.exists())

    def test_command_preview_does_not_execute_builder(self):
        repo = self.root / 'source-checkout'
        write(repo / 'tools/build_shizuku_se_iso.py', b'# fixture only; never execute\n')
        output = self.root / 'owned-with-spaces-private.iso'
        with patch.object(usb.subprocess, 'run') as called, redirect_stdout(io.StringIO()) as capture:
            usb.private_command(argparse.Namespace(action='private-command', repo=repo, win98_iso=self.win98,
                                                  output=output, reuse_builds=False))
        called.assert_not_called()
        self.assertIn('--desktop', capture.getvalue())
        self.assertIn('--win98-media', capture.getvalue())
        self.assertIn('not executed', capture.getvalue())
        self.assertFalse(output.exists())

    def test_explicit_private_builder_isolated_from_host_devices(self):
        repo = self.root / 'builder-checkout'
        write(repo / 'tools/build_shizuku_se_iso.py', b'# mocked fixture only\n')
        output = self.root / 'mocked-integration-private.iso'
        invocations = []
        def fake_builder(argv, **kwargs):
            invocations.append((argv, kwargs))
            write(output, b'PRIVATE MOCKED BUILDER OUTPUT; NOT A BOOTABLE ISO')
            usb.json_write(output.with_suffix('.json'), {**usb.record(output), 'private': True})
        with patch.object(usb, 'inspect_own_iso', return_value={'fixture': True}), \
                patch.object(usb.subprocess, 'run', side_effect=fake_builder), redirect_stdout(io.StringIO()):
            usb.private_command(argparse.Namespace(action='private-iso', repo=repo, win98_iso=self.win98,
                                                  output=output, reuse_builds=True))
        self.assertEqual(len(invocations), 1)
        argv, kwargs = invocations[0]
        self.assertEqual(argv[0], 'python3')
        self.assertEqual(kwargs['cwd'], repo)
        self.assertIn('--reuse-builds', argv)
        self.assertEqual(argv[argv.index('--win98-media') + 1], str(self.win98))
        self.assertTrue(usb.json_read(output.with_suffix('.media.json'))['private'])


class GuardTests(unittest.TestCase):
    def test_unsafe_case_collision_and_private_names(self):
        for names in (['../x'], ['/x'], ['x\\y'], ['x:y'], ['x.'], ['a', 'A'],
                      ['WIN98.ISO'], ['PRIVATE/a'], ['WIN98/a'], ['STEAM.EXE'],
                      ['WIN98-MEDIA.json'], ['a?b'], ['x' * 256]):
            with self.subTest(names=names), self.assertRaises(ValueError):
                usb.public_names(names)

    def test_refuse_device_existing_output_and_links(self):
        for path in ('/dev/null', '/root/../dev/forbidden', '/root/../proc/forbidden', '/root/../sys/forbidden'):
            with self.subTest(path=path), self.assertRaises(ValueError):
                usb.plain_path(path)
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            data = base / 'file'
            data.write_bytes(b'fixture')
            link = base / 'link'
            link.symlink_to(data)
            with self.assertRaises(ValueError):
                usb.regular_file(link)
            with self.assertRaises(ValueError):
                usb.fresh_path(data)

    def test_fat32_size_rejected_without_reading_sparse_payload(self):
        with tempfile.TemporaryDirectory() as tmp:
            large = Path(tmp) / 'large'
            with large.open('wb') as stream:
                stream.truncate(usb.FAT32_MAX + 1)
            with self.assertRaisesRegex(ValueError, 'FAT32'):
                usb.record(large)


if __name__ == '__main__':
    unittest.main(verbosity=2)
