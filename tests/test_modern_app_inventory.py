"""Verify loader evidence, including metadata that earlier x86 tools excluded."""
import importlib.util
import struct
import tempfile
import unittest
import hashlib
import zipfile
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("modern_inventory", ROOT / "tools/modern_app_inventory.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def fixture(x64=False, va_delay=False):
    data = bytearray(4096)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    size, width = (240, 8) if x64 else (224, 4)
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if x64 else 0x14C, 1, 0, 0, 0, size, 0x102)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B if x64 else 0x10B)
    image_base = 0x140000000 if x64 else 0x400000
    struct.pack_into("<Q" if x64 else "<I", data, opt + (24 if x64 else 28), image_base)
    struct.pack_into("<HH", data, opt + 40, 10, 0)
    struct.pack_into("<HH", data, opt + 48, 10, 0)
    struct.pack_into("<I", data, opt + 56, 0x3000)
    struct.pack_into("<I", data, opt + 60, 0x200)
    struct.pack_into("<H", data, opt + 68, 2)
    directory = opt + (112 if x64 else 96)
    struct.pack_into("<I", data, directory - 4, 16)
    section = opt + size
    data[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x2000, 0x1000, len(data) - 0x200, 0x200)
    raw = lambda rva: rva - 0x1000 + 0x200
    struct.pack_into("<II", data, directory + 8, 0x1100, 40)
    struct.pack_into("<5I", data, raw(0x1100), 0x1300, 0, 0, 0x1200, 0x1300)
    data[raw(0x1200):raw(0x1200) + 13] = b"KERNEL32.dll\0"
    struct.pack_into("<QQQ" if x64 else "<III", data, raw(0x1300), 0x1400, (1 << (width * 8 - 1)) | 7, 0)
    data[raw(0x1400):raw(0x1400) + 14] = b"\0\0CreateFileW\0"
    struct.pack_into("<II", data, directory + 13 * 8, 0x1500, 64)
    address = lambda rva: rva + image_base if va_delay else rva
    struct.pack_into("<8I", data, raw(0x1500), 0 if va_delay else 1, address(0x1700), 0, address(0x1800), address(0x1800), 0, 0, 0)
    data[raw(0x1700):raw(0x1700) + 12] = b"WINHTTP.dll\0"
    struct.pack_into("<QQ" if x64 else "<II", data, raw(0x1800), address(0x1900), 0)
    name = b"\0\0WinHttpOpen\0"
    data[raw(0x1900):raw(0x1900) + len(name)] = name
    return data


class InventoryTests(unittest.TestCase):
    def test_both_architectures_preserve_direct_and_delay_imports(self):
        for x64, expected in ((False, "ia32"), (True, "x64")):
            with self.subTest(architecture=expected):
                report = module.PEInventory(fixture(x64)).report()
                self.assertEqual(report["architecture"], expected)
                self.assertEqual(report["direct_imports"][0]["symbols"], ["CreateFileW", "#7"])
                self.assertEqual(report["delay_imports"][0]["symbols"], ["WinHttpOpen"])
                self.assertEqual(report["declared_subsystem_version"], [10, 0])
                self.assertFalse(report["guest_execution_verified"])

    def test_old_va_delay_descriptor(self):
        self.assertEqual(module.PEInventory(fixture(va_delay=True)).report()["delay_imports"][0]["module"], "WINHTTP.DLL")

    def test_machine_magic_mismatch_is_rejected(self):
        data = fixture()
        struct.pack_into("<H", data, 0x84, 0x8664)
        with self.assertRaises(module.PEError):
            module.PEInventory(data)

    def test_truncation_never_becomes_empty_success(self):
        data = fixture()
        for length in (0, 2, 63, 0x80, 0x98, 300, 1024):
            with self.subTest(length=length), self.assertRaises(module.PEError):
                module.PEInventory(data[:length]).report()

    def test_unmapped_delay_import_is_rejected(self):
        data = fixture()
        struct.pack_into("<I", data, 0x98 + 96 + 13 * 8, 0xDEAD0000)
        with self.assertRaises(module.PEError):
            module.PEInventory(data).report()

    def test_virtual_only_import_symbol_is_rejected(self):
        data = fixture()
        struct.pack_into("<I", data, 0x500, 0x2F00)
        with self.assertRaises(module.PEError):
            module.PEInventory(data).report()

    def test_directory_requires_terminator_inside_extent(self):
        data = fixture()
        struct.pack_into("<I", data, 0x98 + 96 + 12, 20)
        with self.assertRaises(module.PEError):
            module.PEInventory(data).report()

    def test_oversized_direct_directory_is_rejected(self):
        data = fixture()
        struct.pack_into("<I", data, 0x98 + 96 + 12, 0xFFFFFFFE)
        with self.assertRaises(module.PEError):
            module.PEInventory(data).report()

    def test_invalid_direct_and_delay_iat_destinations_are_rejected(self):
        for at, invalid in ((0x300 + 16, 0), (0x300 + 16, 0xDEAD0000),
                            (0x700 + 12, 0), (0x700 + 12, 0xDEAD0000)):
            with self.subTest(at=at, invalid=invalid):
                data = fixture()
                struct.pack_into("<I", data, at, invalid)
                with self.assertRaises(module.PEError):
                    module.PEInventory(data).report()

    def test_iat_destination_can_be_mapped_zero_filled_memory(self):
        data = fixture()
        struct.pack_into("<I", data, 0x300 + 16, 0x2F00)
        report = module.PEInventory(data).report()
        self.assertEqual(report["direct_imports"][0]["symbols"], ["CreateFileW", "#7"])

    def test_native_addons_and_errors_remain_visible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Signal.EXE").write_bytes(fixture(True))
            (root / "libsignal.NODE").write_bytes(fixture(True))
            (root / "bad.dll").write_bytes(b"MZ")
            report = module.inventory(root, "signal", {"apps": [{"id": "signal"}]})
            self.assertEqual(report["architectures"], ["x64"])
            self.assertEqual(len(report["files"]), 2)
            self.assertTrue(any(item["native_addon"] for item in report["files"]))
            self.assertEqual(len(report["errors"]), 1)
            self.assertFalse(report["app_functionality_verified"])

    def test_empty_package_is_not_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = module.inventory(Path(temporary), "legcord", {"apps": [{"id": "legcord"}]})
            self.assertTrue(report["errors"])

    def test_unix_addons_are_retained_without_changing_windows_architecture(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Legcord.exe").write_bytes(fixture())
            elf = bytearray(64)
            elf[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", elf, 18, 183)
            (root / "linux.node").write_bytes(elf)
            mach = bytearray(32)
            mach[:4] = b"\xcf\xfa\xed\xfe"
            struct.pack_into("<I", mach, 4, 0x1000007)
            (root / "darwin.node").write_bytes(mach)
            report = module.inventory(root, "legcord", {"apps": [{"id": "legcord", "entry_point": "Legcord.exe"}]})
            self.assertFalse(report["errors"])
            self.assertEqual(report["architectures"], ["ia32"])
            self.assertEqual(len(report["files"]), 3)
            self.assertEqual(report["entry_point"]["architecture"], "ia32")
            self.assertFalse(report["target_identity_verified"])

    def test_missing_entry_point_is_not_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "helper.exe").write_bytes(fixture())
            report = module.inventory(root, "legcord", {"apps": [{"id": "legcord", "entry_point": "Legcord.exe"}]})
            self.assertTrue(report["errors"])
            self.assertIsNone(report["entry_point"])

    def test_publisher_archive_verification_binds_actual_binary_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            binary = fixture()
            (root / "Legcord.exe").write_bytes(binary)
            archive = Path(temporary) / "app.zip"
            with zipfile.ZipFile(archive, "w") as package:
                package.writestr("Legcord.exe", binary)
            target = {"id": "legcord", "entry_point": "Legcord.exe", "first_probe": {
                "architecture": "ia32", "publisher_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "url": "https://example.invalid/app.zip", "publisher_digest_source": "https://example.invalid/digest"}}
            report = module.inventory(root, "legcord", {"apps": [target]})
            module.verify_archive(report, archive)
            self.assertTrue(report["target_identity_verified"])
            self.assertFalse(report["guest_execution_verified"])
            binary[-1] ^= 1
            (root / "Legcord.exe").write_bytes(binary)
            changed = module.inventory(root, "legcord", {"apps": [target]})
            with self.assertRaises(ValueError):
                module.verify_archive(changed, archive)

    def test_archive_verification_binds_nonbinary_application_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            binary = fixture()
            (root / "Legcord.exe").write_bytes(binary)
            (root / "app.asar").write_bytes(b"original application")
            archive = Path(temporary) / "app.zip"
            with zipfile.ZipFile(archive, "w") as package:
                package.writestr("Legcord.exe", binary)
                package.writestr("app.asar", b"original application")
            target = {"id": "legcord", "entry_point": "Legcord.exe", "first_probe": {
                "architecture": "ia32", "publisher_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "url": "https://example.invalid/app.zip", "publisher_digest_source": "https://example.invalid/digest"}}
            report = module.inventory(root, "legcord", {"apps": [target]})
            module.verify_archive(report, archive)
            (root / "app.asar").write_bytes(b"different application")
            report = module.inventory(root, "legcord", {"apps": [target]})
            with self.assertRaises(ValueError):
                module.verify_archive(report, archive)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX special files")
    def test_archive_verification_rejects_extra_nonbinary_special_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            binary = fixture()
            (root / "Legcord.exe").write_bytes(binary)
            archive = Path(temporary) / "app.zip"
            with zipfile.ZipFile(archive, "w") as package:
                package.writestr("Legcord.exe", binary)
            target = {"id": "legcord", "entry_point": "Legcord.exe", "first_probe": {
                "architecture": "ia32", "publisher_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                "url": "https://example.invalid/app.zip", "publisher_digest_source": "https://example.invalid/digest"}}
            os.mkfifo(root / "extra-resource")
            report = module.inventory(root, "legcord", {"apps": [target]})
            with self.assertRaises(ValueError):
                module.verify_archive(report, archive)

    def test_directory_symlink_is_not_silently_omitted(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            (root / "Legcord.exe").write_bytes(fixture())
            outside = Path(temporary) / "outside"
            outside.mkdir()
            (outside / "addon.node").write_bytes(fixture())
            (root / "addons").symlink_to(outside, target_is_directory=True)
            report = module.inventory(root, "legcord", {"apps": [{"id": "legcord"}]})
            self.assertTrue(report["errors"])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX special files")
    def test_fifo_is_rejected_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            os.mkfifo(root / "addon.node")
            report = module.inventory(root, "legcord", {"apps": [{"id": "legcord"}]})
            self.assertTrue(report["errors"])


if __name__ == "__main__":
    unittest.main()
