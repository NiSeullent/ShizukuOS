# SPDX-License-Identifier: GPL-2.0-only
"""Production install must preserve its built shell, DLLs and font bytes."""
import hashlib
import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from desktop_profile import desktop_runtime


def archive(entries):
    table_end = 16 + 136 * len(entries)
    header = bytearray(b"SHZARC01" + struct.pack("<II", len(entries), 0))
    payload = bytearray()
    for name, data in entries:
        offset = table_end + len(payload)
        header += name.encode("ascii").ljust(120, b"\0") + struct.pack("<QQ", offset, len(data))
        payload += data
    return bytes(header + payload)


class ProductionInstallTests(unittest.TestCase):
    def setUp(self):
        self.files = [("\\SHZ\\SYS64\\" + name, name.encode("ascii")) for name in
                      ("ntdll.dll", "kernel32.dll", "user32.dll", "gdi32.dll", "SHZDESK.EXE")]
        self.files.append(("\\SHZ\\TESTS\\T_HELLO.EXE", b"bundled launcher demo"))

    def select(self, files):
        data = archive(files)
        return desktop_runtime(data, hashlib.sha256(data).hexdigest())

    def test_installed_runtime_preserves_shell_wine_and_fonts_and_excludes_qa(self):
        additions = [("\\SHZ\\SYS64\\dwrite.dll", b"wine implementation"),
                     ("\\SHZ\\FONTS\\tahoma.ttf", b"font bytes"),
                     ("\\SHZ\\SYS64\\SHZPNP.EXE", b"driver manager"),
                     ("\\SHZ\\TESTS\\T_GUI_STATUS.EXE", b"timed diagnostic")]
        selected = dict(self.select(self.files + additions))
        for path, data in self.files + additions[:-1]:
            self.assertEqual(selected[path], data)
        self.assertNotIn(additions[-1][0], selected)

    def test_missing_shell_is_an_error_instead_of_an_empty_desktop_package(self):
        with self.assertRaisesRegex(ValueError, "SHZDESK.EXE"):
            self.select([p for p in self.files if not p[0].endswith("SHZDESK.EXE")])

    def test_missing_bundled_app_rejects_a_broken_installed_launcher(self):
        with self.assertRaisesRegex(ValueError, "T_HELLO.EXE"):
            self.select(self.files[:-1])

    def test_receipt_rejects_changed_archive(self):
        data = archive(self.files)
        digest = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(ValueError, "receipt"):
            desktop_runtime(data[:-1] + b"!", digest)

    def test_member_bounds_are_checked_before_shipping(self):
        data = bytearray(archive(self.files))
        struct.pack_into("<Q", data, 16 + 120, len(data) + 1)
        with self.assertRaisesRegex(ValueError, "outside"):
            desktop_runtime(data, hashlib.sha256(data).hexdigest())

    def test_case_aliases_do_not_replace_a_built_system_file(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.select(self.files + [("\\SHZ\\SYS64\\NTDLL.DLL", b"replacement")])


if __name__ == "__main__":
    unittest.main()
