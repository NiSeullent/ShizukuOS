"""Static comparison fixtures exercise parser boundaries and uncertain providers."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("required_app_import_gaps", ROOT / "tools/required_app_import_gaps.py")
gaps = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gaps)


def export_fixture(architecture="x64", symbols=("Visible",), base=7, hole=False, forwarder=None):
    data = bytearray(4096)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    x64 = architecture == "x64"
    size = 240 if x64 else 224
    struct.pack_into("<HHIIIHH", data, 0x84, 0x8664 if x64 else 0x14C, 1, 0, 0, 0, size, 0x2022)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x20B if x64 else 0x10B)
    struct.pack_into("<Q" if x64 else "<I", data, opt + (24 if x64 else 28), 0x140000000 if x64 else 0x400000)
    struct.pack_into("<I", data, opt + 56, 0x3000)
    struct.pack_into("<I", data, opt + 60, 0x200)
    dirs = opt + (112 if x64 else 96)
    struct.pack_into("<I", data, dirs - 4, 16)
    struct.pack_into("<II", data, dirs, 0x1100, 0x300)
    section = opt + size
    data[section:section + 8] = b".edata\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x2000, 0x1000, len(data) - 0x200, 0x200)
    raw = lambda rva: rva - 0x1000 + 0x200
    struct.pack_into("<IIHHIIIIIII", data, raw(0x1100), 0, 0, 0, 0, 0x1180, base, 2 if hole else 1,
                     len(symbols), 0x1140, 0x1150, 0x1170)
    data[raw(0x1180):raw(0x1180) + 12] = b"fixture.dll\0"
    struct.pack_into("<I", data, raw(0x1140), 0x1300 if forwarder else 0x1800)
    if hole:
        struct.pack_into("<I", data, raw(0x1144), 0)
    for index, symbol in enumerate(symbols):
        name_rva = 0x1200 + index * 64
        struct.pack_into("<I", data, raw(0x1150) + index * 4, name_rva)
        struct.pack_into("<H", data, raw(0x1170) + index * 2, 0)
        value = symbol.encode("ascii") + b"\0"
        data[raw(name_rva):raw(name_rva) + len(value)] = value
    if forwarder:
        value = forwarder.encode("ascii") + b"\0"
        data[raw(0x1300):raw(0x1300) + len(value)] = value
    return data


def receipt():
    return {"schema": 1, "status": "PASS", "app": "signal", "installer_or_application_executed": False,
            "app_functionality_verified": False, "artifact": {"publisher_digest_verified": True, "sha256": "a" * 64},
            "native_files": [{"path": "Signal.exe", "sha256": "b" * 64, "architecture": "x64", "format": "PE32+",
                              "direct_imports": [{"module": "KERNEL32.DLL", "symbols": ["Visible", "Absent", "#7", "#8"]}],
                              "delay_imports": [{"module": "NODE.EXE", "symbols": ["napi_create_function"]}]}]}


class ExportTests(unittest.TestCase):
    def test_named_export_and_full_ordinal_base(self):
        parsed = gaps.exports(export_fixture(base=300))
        self.assertEqual(parsed["names"]["Visible"]["ordinal"], 300)
        self.assertIn("#300", parsed["ordinals"])
        self.assertEqual(parsed["format"], "PE32+")

    def test_ordinal_holes_are_unavailable(self):
        self.assertNotIn("#8", gaps.exports(export_fixture(hole=True))["ordinals"])

    def test_multiple_names_for_one_function_are_valid(self):
        parsed = gaps.exports(export_fixture(symbols=("Visible", "Alias")))
        self.assertEqual(len(parsed["names"]), 2)
        self.assertEqual(len(parsed["ordinals"]), 1)

    def test_forwarder_including_explicit_extension_and_ordinal(self):
        parsed = gaps.exports(export_fixture(forwarder="other.dll.#300"))
        self.assertEqual(parsed["names"]["Visible"]["forwarder"], "other.dll.#300")
        self.assertEqual(gaps.forwarder_target("KERNELBASE.Real"), ("KERNELBASE.dll", "Real"))
        self.assertEqual(gaps.forwarder_target("OTHER.#0007"), ("OTHER.dll", "#7"))

    def test_oversized_export_count_rejected(self):
        data = export_fixture()
        struct.pack_into("<I", data, 0x300 + 20, 65537)
        with self.assertRaises(gaps.inventory.PEError):
            gaps.exports(data)

    def test_invalid_name_ordinal_rejected(self):
        data = export_fixture()
        struct.pack_into("<H", data, 0x370, 3)
        with self.assertRaises(gaps.inventory.PEError):
            gaps.exports(data)

    def test_duplicate_export_names_rejected(self):
        with self.assertRaises(gaps.inventory.PEError):
            gaps.exports(export_fixture(symbols=("Visible", "Visible")))

    def test_forwarder_cannot_extend_past_export_directory(self):
        data = export_fixture(forwarder="OTHER.Real")
        struct.pack_into("<II", data, 0x98 + 112, 0x1100, 0x202)
        with self.assertRaises(gaps.inventory.PEError):
            gaps.exports(data)


class ResolutionTests(unittest.TestCase):
    def provider(self, **kwargs):
        item = gaps.exports(export_fixture(**kwargs))
        item["receipt"] = {"sha256": "c" * 64}
        return item

    def test_export_match_does_not_assert_behavior(self):
        result = gaps.resolve("KERNEL32.DLL", "Visible", "x64", "PE32+", {"kernel32.dll": self.provider()}, {})
        self.assertEqual(result["status"], "runtime_export_candidate_present")
        self.assertNotIn("implemented", result)

    def test_symbol_names_remain_case_sensitive(self):
        result = gaps.resolve("kernel32.dll", "visible", "x64", "PE32+", {"kernel32.dll": self.provider()}, {})
        self.assertEqual(result["status"], "runtime_export_absent")

    def test_architecture_mismatch_is_not_presence(self):
        result = gaps.resolve("kernel32.dll", "Visible", "x64", "PE32+", {"kernel32.dll": self.provider(architecture="ia32")}, {})
        self.assertEqual(result["status"], "runtime_architecture_mismatch")

    def test_api_set_and_executable_aliases_are_uncertain(self):
        for module, expected in (("API-MS-WIN-CORE-FILE-L1-1-0.DLL", "api_set_mapping_unverified"),
                                 ("NODE.EXE", "executable_host_alias_unverified")):
            self.assertEqual(gaps.resolve(module, "Whatever", "x64", "PE32+", {}, {})["status"], expected)

    def test_packaged_provider_wins_uncertainty_over_runtime_name(self):
        result = gaps.resolve("KERNEL32.DLL", "Visible", "x64", "PE32+", {"kernel32.dll": self.provider()},
                              {"kernel32.dll": [{"path": "private/kernel32.dll", "sha256": "d" * 64}]})
        self.assertEqual(result["status"], "packaged_provider_exports_uninspected")
        self.assertTrue(result["runtime_exact_name_present"])

    def test_forwarder_ordinal_resolution(self):
        result = gaps.resolve("one.dll", "Visible", "x64", "PE32+", {
            "one.dll": self.provider(forwarder="two.#7"), "two.dll": self.provider()}, {})
        self.assertEqual(result["target"]["status"], "runtime_export_candidate_present")

    def test_forwarder_cycle_is_not_success(self):
        result = gaps.resolve("one.dll", "Visible", "x64", "PE32+", {
            "one.dll": self.provider(forwarder="two.Visible"), "two.dll": self.provider(forwarder="one.Visible")}, {})
        self.assertEqual(result["target"]["target"]["status"], "forwarder_cycle_or_depth")


class DiagnosticTests(unittest.TestCase):
    def setup_inputs(self, root):
        source = root / "inventory.json"
        source.write_text(json.dumps(receipt()))
        runtime = root / "runtime"
        runtime.mkdir()
        (runtime / "kernel32.dll").write_bytes(export_fixture(hole=True))
        return source, runtime

    def test_full_receipt_is_deterministic_static_and_content_bound(self):
        with tempfile.TemporaryDirectory() as temp:
            source, runtime = self.setup_inputs(Path(temp))
            report = gaps.diagnose(source, runtime)
            self.assertEqual(report, gaps.diagnose(source, runtime))
            self.assertEqual(report["source_inventory"]["sha256"], hashlib.sha256(source.read_bytes()).hexdigest())
            self.assertEqual(report["summary"]["statuses"]["runtime_export_absent"], 2)
            self.assertEqual(report["summary"]["statuses"]["executable_host_alias_unverified"], 1)
            for flag in ("runtime_execution_verified", "windows98_execution_verified", "standalone_kernel64_execution_verified",
                         "app_functionality_verified", "installer_or_application_executed", "loader_resolution_verified"):
                self.assertIs(report[flag], False)

    def test_forwarder_target_gap_remains_in_concrete_gaps(self):
        with tempfile.TemporaryDirectory() as temp:
            source, runtime = self.setup_inputs(Path(temp))
            (runtime / "kernel32.dll").write_bytes(export_fixture(forwarder="MISSING.Real"))
            report = gaps.diagnose(source, runtime)
            visible = next(row for row in report["imports"] if row["symbol"] == "Visible")
            self.assertEqual(visible["terminal_status"], "runtime_module_absent_in_selected_directory")
            self.assertTrue(any(row["symbol"] == "Visible" for row in report["concrete_gaps_in_selected_runtime"]))

    def test_malformed_provider_does_not_become_missing_symbol(self):
        with tempfile.TemporaryDirectory() as temp:
            source, runtime = self.setup_inputs(Path(temp))
            (runtime / "kernel32.dll").write_bytes(b"MZ")
            report = gaps.diagnose(source, runtime)
            self.assertEqual(report["summary"]["runtime_export_table_errors"], 1)
            self.assertFalse(report["concrete_gaps_in_selected_runtime"])

    def test_symlink_provider_is_rejected_without_following(self):
        with tempfile.TemporaryDirectory() as temp:
            source, runtime = self.setup_inputs(Path(temp))
            (runtime / "alias.dll").symlink_to(runtime / "kernel32.dll")
            with self.assertRaises(OSError):
                gaps.diagnose(source, runtime)

    def test_cpl_and_drv_providers_are_inspected_without_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            source, runtime = self.setup_inputs(Path(temp))
            (runtime / "device.cpl").write_bytes(export_fixture())
            (runtime / "spool.drv").write_bytes(export_fixture())
            report = gaps.diagnose(source, runtime)
            self.assertEqual(report["summary"]["runtime_dlls"], 3)

    def test_changed_provider_invalidates_whole_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            source, runtime = self.setup_inputs(Path(temp))
            original = gaps.resolve
            changed = False
            def edit(*args, **kwargs):
                nonlocal changed
                if not changed:
                    changed = True
                    (runtime / "kernel32.dll").write_bytes(export_fixture(base=99))
                return original(*args, **kwargs)
            with patch.object(gaps, "resolve", side_effect=edit):
                with self.assertRaises(gaps.GapError):
                    gaps.diagnose(source, runtime)

    def test_directory_membership_changes_invalidate_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            source, runtime = self.setup_inputs(Path(temp))
            original = gaps.resolve
            def edit(*args, **kwargs):
                (runtime / "new.dll").write_bytes(export_fixture())
                return original(*args, **kwargs)
            with patch.object(gaps, "resolve", side_effect=edit):
                with self.assertRaises(gaps.GapError):
                    gaps.diagnose(source, runtime)

    def test_malformed_inventory_rejected(self):
        variants = []
        bad = receipt(); bad["native_files"][0]["direct_imports"][0]["symbols"] = ["#99999"]; variants.append(bad)
        bad = receipt(); bad["native_files"][0]["path"] = "../Signal.exe"; variants.append(bad)
        bad = receipt(); bad["native_files"][0]["format"] = "PE32"; variants.append(bad)
        bad = receipt(); bad["native_files"].append(copy.deepcopy(bad["native_files"][0])); variants.append(bad)
        bad = receipt(); bad["artifact"]["publisher_digest_verified"] = False; variants.append(bad)
        bad = receipt(); bad["artifact"] = []; variants.append(bad)
        bad = receipt(); bad["native_files"][0]["direct_imports"][0]["symbols"] = ["#07"]; variants.append(bad)
        for bad in variants:
            with self.subTest(bad=bad), self.assertRaises(gaps.GapError):
                gaps.validate_inventory(bad)

    def test_output_is_exclusive(self):
        with tempfile.TemporaryDirectory() as temp:
            source, runtime = self.setup_inputs(Path(temp))
            output = Path(temp) / "result.json"
            output.write_text("preserve")
            with self.assertRaises(SystemExit):
                gaps.main(["--inventory", str(source), "--runtime-dir", str(runtime), "--output", str(output)])
            self.assertEqual(output.read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
