# SPDX-License-Identifier: GPL-2.0-only
"""Native package closure, real corrupted inputs, exclusions and ZIP integrity."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('npp_package', ROOT / 'tools/package_native_npp.py')
package = importlib.util.module_from_spec(spec); spec.loader.exec_module(package)


class NativePackageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if any(not (ROOT / name).is_file() for name in (*package.PROOFS, *package.BUILD_PINS)):
            raise unittest.SkipTest('Private licensed native acceptance/build corpus is unavailable; package acceptance is not claimed')
        cls.inputs = {}
        original_read = package.read

        def capture(root, name, expected=None):
            raw = original_read(root, name, expected)
            cls.inputs[name] = raw
            return raw

        with patch.object(package, 'read', side_effect=capture):
            cls.members = package.assemble()

    def test_actual_zip_closure_and_determinism(self):
        first = package.zip_bytes(self.members)
        self.assertEqual(first, package.zip_bytes(dict(reversed(list(self.members.items())))))
        manifest = json.loads(self.members['MANIFEST.json'])
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(len(archive.namelist()), len(set(archive.namelist())))
            self.assertEqual(set(archive.namelist()), set(manifest['members']) | {'MANIFEST.json'})
            for name, record in manifest['members'].items():
                raw = archive.read(name)
                self.assertEqual(len(raw), record['bytes'])
                self.assertEqual(hashlib.sha256(raw).hexdigest(), record['sha256'])
            binaries = [name for name in archive.namelist() if name.endswith(('.DLL', '.EXE'))]
            self.assertEqual(len(binaries), 13)
            self.assertEqual({Path(name).name for name in binaries if name.endswith('.EXE')}, {'NTWPENV.EXE', 'ENVFIX.EXE'})
        evidence = json.loads(self.members['EVIDENCE.json'])
        self.assertTrue(evidence['requires_field_interpreter'])
        self.assertFalse(evidence['fresh_zip_install_verified'])
        self.assertFalse(evidence['other_modern_apps_verified'])

    def test_real_corrupted_native_provider_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name, raw in self.inputs.items():
                path = root / name; path.parent.mkdir(parents=True, exist_ok=True); path.write_bytes(raw)
            target = root / package.PREREQ / 'M98WRAP.DLL'
            raw = bytearray(target.read_bytes()); raw[-1] ^= 1; target.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, 'hash or size differs'):
                package.assemble(root)
            self.assertFalse((root / 'SHZNPP.zip').exists())

class PackageBoundaryTests(unittest.TestCase):
    def test_licensed_binary_and_traversal_exclusions(self):
        for name in ('native/NPP.EXE', 'native/KERNEL32.DLL', 'UNICOWS.DLL',
                     'disk.img', '../source/x.c', '/source/x.c', 'source//x.c', 'source\\x.c'):
            with self.subTest(name=name), self.assertRaises(ValueError):
                package.zip_bytes({name: b'not allowed'})

    def test_symlink_input_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root / 'source.c').write_bytes(b'source')
            (root / 'alias.c').symlink_to('source.c')
            with self.assertRaises(ValueError):
                package.read(root, 'alias.c')


if __name__ == '__main__':
    unittest.main()
