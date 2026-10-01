"""Bounded host rejection controls; none of these are native application tests.
SPDX-License-Identifier: GPL-2.0-only
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
import zipfile
import xml.etree.ElementTree as ET

import office_steam_acceptance as acceptance
import office_steam_preflight as preflight
import office_steam_sal_clock as clock


def pe_image(*, wide: bool = False) -> bytes:
    data = bytearray(0x800)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    optional = 0x98
    optional_size, base = (240, 112) if wide else (224, 96)
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if wide else 0x14c,
                     1, 0, 0, 0, optional_size, 0x102)
    struct.pack_into("<H", data, optional, 0x20b if wide else 0x10b)
    if wide:
        struct.pack_into("<Q", data, optional + 24, 0x140000000)
    else:
        struct.pack_into("<I", data, optional + 28, 0x400000)
    struct.pack_into("<II", data, optional + 32, 0x1000, 0x200)
    struct.pack_into("<HH", data, optional + 48, 4, 10)
    struct.pack_into("<II", data, optional + 56, 0x2000, 0x200)
    struct.pack_into("<H", data, optional + 68, 2)
    struct.pack_into("<I", data, optional + base - 4, 16)
    struct.pack_into("<II", data, optional + base + 8, 0x1000, 40)
    struct.pack_into("<II", data, optional + base + 13 * 8, 0x1100, 64)
    section = optional + optional_size
    data[section:section + 8] = b".rdata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x600, 0x1000, 0x600, 0x200)
    at = lambda rva: rva - 0x1000 + 0x200
    struct.pack_into("<IIIII", data, at(0x1000), 0x1060, 0, 0, 0x1050, 0x1080)
    data[at(0x1050):at(0x1050) + 13] = b"KERNEL32.DLL\0"
    fmt = "<QQ" if wide else "<II"
    struct.pack_into(fmt, data, at(0x1060), 0x10a0, 0)
    name = b"\0\0GetVersionExA\0"
    data[at(0x10a0):at(0x10a0) + len(name)] = name
    struct.pack_into("<IIIIIIII", data, at(0x1100), 1, 0x1160, 0, 0x1190, 0x1170, 0, 0, 0)
    data[at(0x1160):at(0x1160) + 12] = b"VERSION.DLL\0"
    ordinal = (1 << (63 if wide else 31)) | 17
    struct.pack_into("<QQQ" if wide else "<III", data, at(0x1170), 0x11b0, ordinal, 0)
    name = b"\0\0GetFileVersionInfoA\0"
    data[at(0x11b0):at(0x11b0) + len(name)] = name
    return bytes(data)


class SALClockControls(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / clock.SOURCE
        self.source.parent.mkdir(parents=True)
        self.original = clock.ORIGINAL.read_bytes()
        self.source.write_bytes(self.original)

    def tearDown(self):
        self.temporary.cleanup()

    def test_exact_source_patch_preserves_full_remainder_and_license(self):
        result = clock.apply(self.root)
        current = self.source.read_bytes()
        self.assertEqual(current.replace(clock.AFTER, clock.BEFORE, 1), self.original)
        self.assertIn(b"Mozilla Public", current)
        self.assertIn(b"Apache Software Foundation", current)
        self.assertFalse(result["native_application_executed"])
        self.assertEqual(result["native_application_compatibility"], "unverified")

    def test_idempotent_and_check_mode_do_not_change_inode_or_bytes(self):
        inode = self.source.stat().st_ino
        report = clock.apply(self.root, check_only=True)
        self.assertFalse(report["source_port_applied"])
        self.assertEqual(self.source.stat().st_ino, inode)
        self.assertEqual(self.source.read_bytes(), self.original)
        clock.apply(self.root)
        inode = self.source.stat().st_ino
        self.assertTrue(clock.apply(self.root)["already_applied"])
        self.assertEqual(self.source.stat().st_ino, inode)

    def test_other_source_revision_is_rejected_without_writing(self):
        changed = self.original + b"// separate owner edit\n"
        self.source.write_bytes(changed)
        with self.assertRaisesRegex(ValueError, "neither"):
            clock.apply(self.root)
        self.assertEqual(self.source.read_bytes(), changed)

    def test_file_symlink_and_parent_symlink_are_rejected(self):
        external = self.root / "external.cxx"
        self.source.rename(external)
        self.source.symlink_to(external)
        with self.assertRaisesRegex(ValueError, "symlink"):
            clock.apply(self.root)
        self.source.unlink()
        external.rename(self.source)
        directory = self.root / "sal/osl/w32"
        directory.rename(self.root / "shared")
        directory.symlink_to(self.root / "shared", target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "symlink"):
            clock.apply(self.root)

    def test_hardlinked_source_is_rejected_and_preserved(self):
        alias = self.root / "alias.cxx"
        os.link(self.source, alias)
        with self.assertRaisesRegex(ValueError, "one link"):
            clock.apply(self.root)
        self.assertEqual(alias.read_bytes(), self.original)


class PEAndApplicationControls(unittest.TestCase):
    def test_pe32_and_64_delay_thunks_are_complete_without_execution_claim(self):
        for wide in (False, True):
            report = preflight.inspect(pe_image(wide=wide), "actual-component-control")
            delay = [row for row in report["imports"] if row["kind"] == "delay"]
            self.assertEqual([row["symbol"] for row in delay], ["GetFileVersionInfoA", "#17"])
            self.assertTrue(report["ordinary_and_delay_inventory_complete"])
            self.assertEqual(report["runtime_compatibility"], "unverified")
            self.assertEqual(report["requires_additional_64_bit_execution_path"], wide)

    def test_malformed_64_bit_delay_ordinal_is_rejected(self):
        data = bytearray(pe_image(wide=True))
        struct.pack_into("<Q", data, 0x378, (1 << 63) | (1 << 24) | 17)
        with self.assertRaisesRegex(ValueError, "ordinal"):
            preflight.inspect(bytes(data), "malformed-control")

    def test_delay_name_in_virtual_tail_is_rejected(self):
        data = bytearray(pe_image(wide=True))
        struct.pack_into("<I", data, 0x304, 0x1600)
        with self.assertRaisesRegex(ValueError, "file-backed"):
            preflight.inspect(bytes(data), "virtual-tail-control")

    def test_missing_real_suite_is_not_application_presence_or_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "soffice.exe").write_bytes(pe_image())
            report = preflight.analyze("libreoffice", root)
            self.assertFalse(report["application_payload_present"])
            self.assertEqual(report["component_failures"][0]["role"], "application")
            self.assertFalse(report["native_application_passed"])
            self.assertFalse(report["guest_executed"])

    def test_complete_synthetic_payload_still_never_claims_native_app_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("steam.exe", "steamclient64.dll", "steamwebhelper.exe"):
                (root / name).write_bytes(pe_image(wide=True))
            before = {path.name: path.read_bytes() for path in root.iterdir()}
            report = preflight.analyze("steam", root)
            self.assertTrue(report["application_payload_present"])
            self.assertFalse(report["native_application_passed"])
            self.assertFalse(report["guest_executed"])
            self.assertEqual(before, {path.name: path.read_bytes() for path in root.iterdir()})

    def test_ambiguous_product_components_require_exact_explicit_path(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "a").mkdir()
            (root / "b").mkdir()
            for relative in ("soffice.exe", "a/soffice.bin", "b/soffice.bin"):
                (root / relative).write_bytes(pe_image())
            report = preflight.analyze("libreoffice", root)
            self.assertFalse(report["application_payload_present"])
            self.assertIn("ambiguous", report["component_failures"][0]["reason"])
            report = preflight.analyze("libreoffice", root, {"application": [Path("b/soffice.bin")]})
            self.assertTrue(report["application_payload_present"])

    def test_explicit_path_cannot_escape_deployment(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "relative path"):
                preflight.component_path(Path(directory), Path("../soffice.bin"))


class SavedArtifactControls(unittest.TestCase):
    nonce = "office_fresh_83bd_0123456789"

    def save_control(self, path, kind, flat, *, generator=None):
        # Deliberately synthetic saved files exercise the checker only. A passing
        # result must still refuse any native application execution claim.
        document = ET.fromstring(flat)
        body = document.find("office:body", acceptance.NS)
        root = ET.Element("{" + acceptance.NS["office"] + "}document-content")
        root.append(body)
        metadata = ('<?xml version="1.0" encoding="UTF-8"?>'
                    f'<office:document-meta xmlns:office="{acceptance.NS["office"]}" xmlns:meta="{acceptance.NS["meta"]}">'
                    '<office:meta><meta:generator>' + (generator or "LibreOffice/26.8.0.3$synthetic-host-control")
                    + '</meta:generator></office:meta></office:document-meta>')
        with zipfile.ZipFile(path, "w") as archive:
            archive.writestr("mimetype", (acceptance.MIME + kind).encode(), compress_type=zipfile.ZIP_STORED)
            archive.writestr("content.xml", ET.tostring(root), compress_type=zipfile.ZIP_DEFLATED)
            archive.writestr("meta.xml", metadata.encode(), compress_type=zipfile.ZIP_DEFLATED)

    def documents(self, root, *, stale=False, value="42", generator=None, no_formula=False):
        writer, calc = acceptance.fixture_data("office_stale_83bd_0123456789" if stale else self.nonce)
        writer = writer.replace(b"Change this line to EDIT-SAVED before saving and reopening in Writer.", b"EDIT-SAVED")
        calc = calc.replace(b'office:value="0"', ('office:value="' + value + '"').encode())
        if no_formula:
            calc = calc.replace(b'table:formula="of:=SUM([.A1:.A2])"', b'')
        a, b = root / "saved.odt", root / "saved.ods"
        self.save_control(a, "text", writer, generator=generator)
        self.save_control(b, "spreadsheet", calc, generator=generator)
        return a, b

    def test_consistent_synthetic_saved_files_cannot_claim_native_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = self.documents(Path(directory))
            result = acceptance.inspect_office(a, b, self.nonce)
            self.assertTrue(result["saved_artifact_checks_passed"])
            self.assertTrue(result["writer"]["generator_is_self_reported_metadata"])
            self.assertFalse(result["native_application_passed"])
            self.assertFalse(result["native_application_executed"])

    def test_stale_output_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            a, b = self.documents(Path(directory), stale=True)
            with self.assertRaisesRegex(ValueError, "fresh"):
                acceptance.inspect_office(a, b, self.nonce)

    def test_unrecalculated_or_constant_formula_result_rejected(self):
        for value, no_formula in (("0", False), ("42", True)):
            with tempfile.TemporaryDirectory() as directory:
                a, b = self.documents(Path(directory), value=value, no_formula=no_formula)
                with self.assertRaisesRegex(ValueError, "formula"):
                    acceptance.inspect_office(a, b, self.nonce)

    def test_wrong_office_version_and_helper_metadata_rejected(self):
        for generator in ("LibreOffice/25.8.0.3$older-build", "Win98-Modern fixture"):
            with tempfile.TemporaryDirectory() as directory:
                a, b = self.documents(Path(directory), generator=generator)
                with self.assertRaisesRegex(ValueError, "pinned LibreOffice"):
                    acceptance.inspect_office(a, b, self.nonce)

    def test_external_or_internal_entities_rejected_before_parse(self):
        for data in (b'<!DOCTYPE a [<!ENTITY x "value">]><a>&x;</a>',
                     '<!DOCTYPE a [<!ENTITY x "value">]><a>&x;</a>'.encode("utf-16")):
            with self.assertRaises((ValueError, UnicodeError)):
                acceptance.xml(data)

    def test_new_inputs_have_zero_cached_formula_and_reuse_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            out = Path(directory) / "fresh"
            result = acceptance.create_inputs(out, self.nonce)
            self.assertEqual(len(result["files"]), 2)
            self.assertIn(b'office:value="0"', (out / "CALC.FODS").read_bytes())
            self.assertFalse(result["native_application_executed"])
            with self.assertRaisesRegex(ValueError, "new directory"):
                acceptance.create_inputs(out, self.nonce)


if __name__ == "__main__":
    unittest.main(verbosity=2)
