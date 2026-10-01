#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host PE import/version gate negatives; never execute/register the Win32 provider."""
import importlib.util
import pathlib
import struct
import tempfile
import unittest
import pefile

ROOT = pathlib.Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("native_dialog_builder", ROOT / "tools/build_file_dialog.py")
builder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(builder)


class GateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dll = (ROOT / "build/native-file-dialog/M98FDLG.DLL").read_bytes()
        cls.exe = (ROOT / "build/native-file-dialog/FDPROBE.EXE").read_bytes()

    def inspect(self, data, dll=True):
        with tempfile.TemporaryDirectory(dir=ROOT / "build/native-file-dialog") as temp:
            path = pathlib.Path(temp) / "negative.dll"
            path.write_bytes(data)
            return builder.inspect(path, dll)[0]

    def changed_field(self, field, value):
        image = pefile.PE(data=self.dll)
        if hasattr(image.OPTIONAL_HEADER, field):
            setattr(image.OPTIONAL_HEADER, field, value)
        else:
            setattr(image.FILE_HEADER, field, value)
        return image.write()

    def test_real_artifacts(self):
        self.assertEqual([], self.inspect(self.dll))
        self.assertEqual([], self.inspect(self.exe, False))

    def test_64bit_machine_rejected(self):
        self.assertTrue(self.inspect(self.changed_field("Machine", 0x8664)))

    def test_modern_subsystem_rejected(self):
        self.assertTrue(self.inspect(self.changed_field("MajorSubsystemVersion", 6)))

    def test_aslr_rejected(self):
        self.assertTrue(self.inspect(self.changed_field("DllCharacteristics", 0x40)))

    def test_nonrelocatable_dll_rejected(self):
        with pefile.PE(data=self.dll) as image:
            image.OPTIONAL_HEADER.DATA_DIRECTORY[5].VirtualAddress = 0
            image.OPTIONAL_HEADER.DATA_DIRECTORY[5].Size = 0
            self.assertTrue(self.inspect(image.write()))

    def test_tls_rejected(self):
        with pefile.PE(data=self.dll) as image:
            image.OPTIONAL_HEADER.DATA_DIRECTORY[9].VirtualAddress = image.OPTIONAL_HEADER.AddressOfEntryPoint
            image.OPTIONAL_HEADER.DATA_DIRECTORY[9].Size = 24
            self.assertTrue(self.inspect(image.write()))

    def test_unknown_export_rejected(self):
        self.assertTrue(self.inspect(self.dll.replace(b"DllCanUnloadNow\0", b"DllFakeUnloadXX\0")))

    def test_absent_oem_import_rejected(self):
        self.assertTrue(b"GetSaveFileNameA\0" in self.dll, "real backend import absent")
        self.assertTrue(self.inspect(self.dll.replace(b"GetSaveFileNameA\0", b"GetSaveFileNameW\0")))

    def test_absent_library_rejected(self):
        self.assertTrue(b"COMDLG32.DLL\0" in self.dll, "real backend library absent")
        self.assertTrue(self.inspect(self.dll.replace(b"COMDLG32.DLL\0", b"COMDLG99.DLL\0")))

    def test_truncated_image_rejected(self):
        with self.assertRaises(pefile.PEFormatError):
            self.inspect(self.dll[:60])


if __name__ == "__main__":
    unittest.main()
