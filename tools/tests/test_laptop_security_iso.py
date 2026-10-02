#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Real filesystem and xorriso fixtures; never select the live project tree."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest

MODULE = Path(__file__).resolve().parents[1] / "build_laptop_security_iso.py"
spec = importlib.util.spec_from_file_location("laptop_iso", MODULE)
iso = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = iso
spec.loader.exec_module(iso)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def pe(machine, magic, subsystem):
    data = bytearray(512)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3c, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 1, 0, 0, 0, 0xe0, 2)
    struct.pack_into("<H", data, 0x98, magic)
    struct.pack_into("<H", data, 0x98 + 68, subsystem)
    return bytes(data)


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fd5c-iso-fixture-", dir="/dev/shm")
        self.base = Path(self.temp.name)
        self.root = self.base / "project"
        self.root.mkdir()
        # These are invented fixtures, never project binaries or native receipts.
        self.write("LICENSE", "GNU GENERAL PUBLIC LICENSE\nVersion 2, June 1991\n")
        self.source = {
            "ntwddm/win98/personalization/native.c": b"/* fixture native */\n",
            "ntwddm/win98/personalization/verify.py": b"# fixture recipe\n",
            "platform/freestanding/memory.c": b"/* fixture own runtime */\n",
            "shizukudos/win64/apps/elevate/main.c": b"/* fixture elevate */\n",
            "shizukudos/win64/apps/elevate/secret.c": b"/* credential input CODE */\n",
            "shizukudos/win64/apps/elevate/build.py": b"# fixture build recipe\n",
            "shizukudos/win64/crt/shzcrt.c": b"/* fixture static CRT */\n",
            "shizukudos/abi/shz_auth.h": b"/* fixture ABI */\n",
            "drivers/common/device.c": b"/* fixture protocol */\n",
            "shizukudos/win64/ntdll/ordinals.json": b"{\"NtShzToken\":1}\n",
        }
        for path, value in self.source.items():
            self.write(path, value)
        pers = pe(0x14c, 0x10b, 2)
        elevate = pe(0x8664, 0x20b, 3)
        self.write("build/gui/SHZPERS.EXE", pers)
        self.write("build/elevate/ELEVATE.EXE", elevate)
        self.gui_receipt = {
            "passed": True, "source_before_after_match": True,
            "scope": "fixture compile only; native Windows98 not run",
            "external_toolchain_closure_complete": False,
            "sources_sha256": {p: digest(self.source[p]) for p in self.source if p.startswith(("ntwddm/", "platform/"))},
            "executable": {"file": str(self.root / "build/gui/SHZPERS.EXE"), "sha256": digest(pers), "bytes": len(pers)},
        }
        self.elevate_receipt = {
            "source_stable": True, "missing_import_providers": [],
            "scope": "fixture PE64 compile only",
            "source_sha256": {p: digest(self.source[p]) for p in self.source if p.startswith("shizukudos/")},
            "exe_sha256": digest(elevate),
        }
        self.driver_receipt = {
            "passed": True, "scope": {"physical_hardware": False},
            "sources_sha256": {"drivers/common/device.c": digest(self.source["drivers/common/device.c"])},
        }
        self.save_receipts()
        self.binaries = (
            iso.BinarySpec("SHZPERS.EXE", Path("build/gui/SHZPERS.EXE"), "personalization"),
            iso.BinarySpec("ELEVATE.EXE", Path("build/elevate/ELEVATE.EXE"), "elevate"),
        )
        self.receipts = (
            iso.ReceiptSpec("personalization", Path("build/gui/result.json")),
            iso.ReceiptSpec("elevate", Path("build/elevate/result.json")),
            iso.ReceiptSpec("drivers", Path("build/drivers/result.json")),
        )

    def tearDown(self):
        self.temp.cleanup()

    def write(self, path, data):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.encode() if isinstance(data, str) else data)

    def save_receipts(self):
        for path, value in [("build/gui/result.json", self.gui_receipt), ("build/elevate/result.json", self.elevate_receipt), ("build/drivers/result.json", self.driver_receipt)]:
            self.write(path, json.dumps(value, sort_keys=True))

    def select(self):
        return iso.select_inputs(self.root, self.binaries, self.receipts)


class SelectionTests(Fixture):
    def test_explicit_binaries_receipt_sources_static_runtime_and_recipes(self):
        self.write("build/unselected/MICROSOFT.EXE", b"private, never globbed")
        self.write("unselected/guest.iso", b"private media outside public roots")
        selection = self.select()
        self.assertEqual(set(selection.manifest["binaries"]), {"SHZPERS.EXE", "ELEVATE.EXE"})
        for path in self.source:
            self.assertIn("SOURCE/" + path, selection.payloads)
        self.assertIn("SOURCE/LICENSE", selection.payloads)
        self.assertEqual(selection.manifest["sources"]["shizukudos/win64/crt/shzcrt.c"]["sha256"], digest(self.source["shizukudos/win64/crt/shzcrt.c"]))
        self.assertFalse(selection.manifest["scope"]["bootable"])
        self.assertFalse(selection.manifest["scope"]["native_windows98_validated"])
        self.assertEqual(selection.payloads["VALIDATION/personalization.json"], (self.root / "build/gui/result.json").read_bytes())
        self.assertNotIn("MICROSOFT.EXE", str(selection.manifest))

    def test_unexpected_media_config_secret_and_binary_in_source_are_rejected(self):
        for name, data in [("guest.iso", b"media"), ("disk.qcow2", b"media"), ("setup.cab", b"MS media"), ("unexpected.exe", b"MZ"), (".env", b"PASSWORD=secret"), ("credentials.json", b'{"password":"secret"}'), ("private.pem", b"-----BEGIN PRIVATE KEY-----\nsecret")]:
            with self.subTest(name=name):
                self.write("shizukudos/" + name, data)
                with self.assertRaises(iso.PackageError):
                    self.select()
                (self.root / "shizukudos" / name).unlink()

    def test_source_symlink_file_and_directory_rejected(self):
        for name, target in [("drivers/linked.c", "common/device.c"), ("drivers/link", "common")]:
            p = self.root / name
            p.symlink_to(target)
            with self.assertRaises(iso.PackageError):
                self.select()
            p.unlink()

    def test_receipt_rejects_false_empty_digest_traversal_and_omitted_source(self):
        changes = [
            {"passed": False}, {"sources_sha256": {}},
            {"sources_sha256": {"drivers/common/device.c": "0" * 64}},
            {"sources_sha256": {"../private.c": "0" * 64}},
            {"sources_sha256": {"tools/not_allowlisted.c": "0" * 64}},
            {"source_stable": False},
            {"password": "do-not-publish"},
        ]
        original = self.driver_receipt.copy()
        for change in changes:
            with self.subTest(change=change):
                self.driver_receipt = dict(original, **change)
                self.save_receipts()
                with self.assertRaises(iso.PackageError):
                    self.select()
        self.driver_receipt = original
        self.save_receipts()

    def test_receipt_and_binary_paths_and_architecture_rejected(self):
        alternatives = [
            iso.BinarySpec("OTHER.EXE", Path("build/gui/SHZPERS.EXE"), "personalization"),
            iso.BinarySpec("SHZPERS.EXE", Path("../SHZPERS.EXE"), "personalization"),
            iso.BinarySpec("SHZPERS.EXE", self.base / "outside/SHZPERS.EXE", "personalization"),
            iso.BinarySpec("SHZPERS.EXE", Path("build/gui/SHZPERS.EXE"), "missing"),
            iso.BinarySpec("SHZPERS.EXE", Path("build/elevate/ELEVATE.EXE"), "elevate"),
        ]
        for binary in alternatives:
            with self.subTest(binary=binary), self.assertRaises(iso.PackageError):
                iso.select_inputs(self.root, [binary], self.receipts)
        with self.assertRaises(iso.PackageError):
            iso.select_inputs(self.root, self.binaries, [iso.ReceiptSpec("drivers", Path("../result.json"))])
        self.gui_receipt["executable"]["sha256"] = "0" * 64
        self.save_receipts()
        with self.assertRaises(iso.PackageError):
            self.select()

    def test_binary_valid_hash_but_wrong_pe_architecture_rejected(self):
        wrong = pe(0x8664, 0x20b, 2)
        self.write("build/gui/SHZPERS.EXE", wrong)
        self.gui_receipt["executable"]["sha256"] = digest(wrong)
        self.save_receipts()
        with self.assertRaises(iso.PackageError):
            self.select()

    def test_missing_gpl_license_rejected(self):
        (self.root / "LICENSE").unlink()
        with self.assertRaises(iso.PackageError):
            self.select()

    def test_frozen_selection_rejects_changes_to_sources_receipts_and_binaries(self):
        for path in ["drivers/common/device.c", "build/drivers/result.json", "build/gui/SHZPERS.EXE"]:
            with self.subTest(path=path):
                selection = self.select()
                p = self.root / path
                original = p.read_bytes()
                p.write_bytes(original + b"changed")
                output = self.base / "changed.iso"
                with self.assertRaises(iso.PackageError):
                    iso.build_iso(selection, output, self.base / "work")
                self.assertFalse(output.exists())
                p.write_bytes(original)

    def test_receipt_path_symlink_rejected(self):
        p = self.root / "build/drivers/result.json"
        data = p.read_bytes()
        p.unlink()
        self.write("build/drivers/target.json", data)
        p.symlink_to("target.json")
        with self.assertRaises(iso.PackageError):
            self.select()

    def test_false_passed_cannot_be_overridden_by_compile_fields(self):
        self.elevate_receipt["passed"] = False
        self.save_receipts()
        with self.assertRaises(iso.PackageError):
            self.select()

    def test_binary_receipt_must_pin_its_production_and_runtime_sources(self):
        self.elevate_receipt["source_sha256"] = {"drivers/common/device.c": digest(self.source["drivers/common/device.c"])}
        self.save_receipts()
        with self.assertRaises(iso.PackageError):
            self.select()

    def test_duplicate_labels_and_changed_new_source_are_rejected(self):
        with self.assertRaises(iso.PackageError):
            iso.select_inputs(self.root, self.binaries, self.receipts + (self.receipts[0],))
        selection = self.select()
        self.write("shizukudos/new.c", b"/* post-freeze source */\n")
        with self.assertRaises(iso.PackageError):
            iso.build_iso(selection, self.base / "changed.iso", self.base / "work")

    def test_binary_content_and_private_key_disguised_as_source_rejected(self):
        for data in (b"MZ\0\0binary", b"-----BEGIN RSA PRIVATE KEY-----\nprivate\n-----END RSA PRIVATE KEY-----\n"):
            self.write("drivers/disguised.c", data)
            with self.assertRaises(iso.PackageError):
                self.select()

    def test_oversized_source_and_bad_epoch_are_rejected(self):
        with (self.root / "shizukudos/too-large.c").open("wb") as handle:
            handle.truncate(iso.MAX_FILE_BYTES + 1)
        with self.assertRaises(iso.PackageError):
            self.select()
        for epoch in (True, -1, "now", 5000000000):
            with self.assertRaises(iso.PackageError):
                iso.select_inputs(self.root, epoch=epoch)

    def test_public_certificate_fixture_rejects_private_key_substitution(self):
        path = "shizukudos/win64/tests/fixtures/public-trust/server-0.pem"
        self.write(path, "# Public fixture certificate label\n-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n")
        self.assertIn("SOURCE/" + path, self.select().payloads)
        self.write(path, "-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n")
        with self.assertRaises(iso.PackageError):
            self.select()

    def test_ap_original_before_after_dialect_and_optional_blocked_gui_suite(self):
        pins = self.driver_receipt["sources_sha256"]
        self.driver_receipt = {
            "status": "PASS", "scope": "actual C host only; no AP", "inputs_stable": True,
            "sources_before": pins, "sources_after": pins.copy(),
            "results": [{"unit": "fixture", "passed": True, "exit": 0}],
        }
        self.gui_receipt["host_tests"] = {"gcc-san": {"status": "BLOCKED_NOT_RUN"}, "clang-asan": {"status": "PASS"}}
        self.save_receipts()
        self.assertEqual(self.select().payloads["VALIDATION/drivers.json"], (self.root / "build/drivers/result.json").read_bytes())
        original = self.driver_receipt.copy()
        for patch in ({"inputs_stable": False}, {"sources_after": {}}, {"status": "FAIL"}, {"results": []}, {"results": [{"passed": False, "exit": 1}]}):
            self.driver_receipt = dict(original, **patch)
            self.save_receipts()
            with self.assertRaises(iso.PackageError):
                self.select()

    def test_duplicate_json_keys_cannot_hide_failed_verdict(self):
        original = (self.root / "build/drivers/result.json").read_bytes()
        self.write("build/drivers/result.json", b'{"passed":false,' + original[1:])
        with self.assertRaises(iso.PackageError):
            self.select()

    def test_original_accounts_token_auth_sandbox_identity_and_kdf_result_rows(self):
        pins = self.driver_receipt["sources_sha256"]
        row_schemas = [
            [{"compiler": "gcc", "test": "auth", "exit": 0}],
            [{"compiler": "gcc", "compile_exit": 0, "run_exit": 0}],
            [{"compiler": "clang", "run_exit": 0}],
            [{"compiler": "gcc", "compile_exit": 0, "run_exit": 0, "compile_timeout": False, "run_timeout": False}, {"compiler": "mingw64", "object_only": True, "compile_exit": 0, "compile_timeout": False, "object_sha256": "a" * 64}],
            [{"compiler": "gcc", "status": "PASS", "vectors": 57, "binary_sha256": "b" * 64}],
        ]
        for rows in row_schemas:
            with self.subTest(rows=rows):
                self.driver_receipt = {"source_sha256": pins, "source_stable": True, "scope": "portable host validation only", "results": rows}
                self.save_receipts()
                self.assertEqual(self.select().payloads["VALIDATION/drivers.json"], (self.root / "build/drivers/result.json").read_bytes())

    def test_result_rows_reject_missing_failed_boolean_exit_timeout_and_bad_object(self):
        pins = self.driver_receipt["sources_sha256"]
        bad_rows = [
            {}, {"compile_exit": 0}, {"run_exit": False}, {"run_exit": 1},
            {"compile_exit": 2, "run_exit": 0}, {"run_exit": 0, "run_timeout": True},
            {"run_exit": 0, "passed": False}, {"run_exit": 0, "status": "FAIL"},
            {"object_only": True, "compile_exit": 0, "object_sha256": "bad"},
            {"status": "PASS", "vectors": 57}, {"status": "PASS", "vectors": False, "binary_sha256": "b" * 64},
        ]
        for row in bad_rows:
            with self.subTest(row=row):
                self.driver_receipt = {"source_sha256": pins, "source_stable": True, "scope": "portable host validation only", "results": [{"run_exit": 0}, row]}
                self.save_receipts()
                with self.assertRaises(iso.PackageError):
                    self.select()
        self.driver_receipt["results"] = [{"run_exit": 0}]
        self.driver_receipt["source_stable"] = False
        self.save_receipts()
        with self.assertRaises(iso.PackageError):
            self.select()

    def test_public_install_configuration_rejects_real_credential_value(self):
        self.write("shizukudos/install/shzsetup.ini", "[System]\nPassword=private-secret\n")
        with self.assertRaises(iso.PackageError):
            self.select()


@unittest.skipUnless(shutil.which("xorriso"), "installed xorriso required")
class ISOTests(Fixture):
    def test_two_builds_reproduce_and_extracted_payload_matches_manifest(self):
        selected = self.select()
        output1, output2 = self.base / "one.iso", self.base / "two.iso"
        result1 = iso.build_iso(selected, output1, self.base / "work-one")
        # Caller source metadata and different staging paths must not affect bytes.
        for path in self.source:
            os.utime(self.root / path, (1900000000, 1900000000))
            (self.root / path).chmod(0o600)
        result2 = iso.build_iso(self.select(), output2, self.base / "work-two")
        self.assertEqual(output1.read_bytes(), output2.read_bytes())
        self.assertEqual(result1["iso_sha256"], result2["iso_sha256"])
        self.assertTrue(result1["reproducible"])
        self.assertTrue(result1["extracted_manifest_verified"])
        self.assertLess(output1.stat().st_size, 30 * 1024 * 1024)
        extract = self.base / "extract"
        proc = subprocess.run(["xorriso", "-no_rc", "-osirrox", "on", "-indev", "stdio:" + str(output1), "-extract", "/", str(extract)], capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        manifest = json.loads((extract / "MANIFEST.json").read_bytes())
        self.assertEqual(manifest, selected.manifest)
        for relative, info in manifest["files"].items():
            self.assertEqual(digest((extract / relative).read_bytes()), info["sha256"])
        for p in extract.rglob("*"):
            self.assertFalse(p.is_symlink())
        # There is no type-0 boot record in the ISO9660 volume descriptors.
        with output1.open("rb") as handle:
            handle.seek(16 * 2048)
            for _ in range(16):
                block = handle.read(2048)
                self.assertNotEqual(block[0], 0)
                if block[0] == 255:
                    break

    def test_existing_output_and_symlink_workspace_are_rejected(self):
        selection = self.select()
        output = self.base / "existing.iso"
        output.write_bytes(b"preserve this")
        with self.assertRaises(iso.PackageError):
            iso.build_iso(selection, output, self.base / "work")
        self.assertEqual(output.read_bytes(), b"preserve this")
        work = self.base / "linked-work"
        work.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(iso.PackageError):
            iso.build_iso(selection, self.base / "new.iso", work)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--receipt", type=Path)
    arguments, remaining = parser.parse_known_args()
    project = MODULE.parents[1]
    owned_sources = (MODULE, Path(__file__).resolve(), project / "docs/releases/LAPTOP_SECURITY_ADDON_ISO.md")
    before = {p.relative_to(project).as_posix(): digest(p.read_bytes()) for p in owned_sources}
    program = unittest.main(argv=[sys.argv[0], *remaining], verbosity=2, exit=False)
    after = {p.relative_to(project).as_posix(): digest(p.read_bytes()) for p in owned_sources}
    success = program.result.wasSuccessful() and before == after
    if arguments.receipt:
        receipt = {
            "schema": 1, "passed": success, "source_before_after_match": before == after,
            "sources_sha256": before, "tests_run": program.result.testsRun,
            "failures": len(program.result.failures), "errors": len(program.result.errors),
            "skipped": len(program.result.skipped),
            "scope": {"invented_filesystem_and_pe_fixtures": True, "real_xorriso_reproducibility_and_extraction": shutil.which("xorriso") is not None, "live_project_frozen": False, "native_windows98_executed": False, "hardware_executed": False},
        }
        arguments.receipt.parent.mkdir(parents=True, exist_ok=True)
        # Never overwrite another validation record.
        with arguments.receipt.open("xb") as handle:
            handle.write((json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode())
    raise SystemExit(0 if success else 1)
