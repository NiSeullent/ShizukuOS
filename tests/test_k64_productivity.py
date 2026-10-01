# SPDX-License-Identifier: GPL-2.0-only
"""Evidence gates and package boundaries for real productivity-app probes."""
import importlib.util
import contextlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parents[1] / "shizukudos" / "tests"
sys.path.insert(0, str(HERE))
import run_k64_productivity as probe
import run_k64_electron as runner


class EvidenceGate(unittest.TestCase):
    def classify(self, lines):
        return probe.classify_product("\n".join(lines), "LibreOffice 26.8.0", runner.classify)

    def test_boot_output_cannot_prove_product_command(self):
        result = self.classify(["LibreOffice 26.8.0", "K64 autorun: starting office", "K64 autorun: result exited exit=0 faulted=0"])
        self.assertIsNone(result["exit_code"])

    def test_real_version_output_and_exit_are_distinguishable(self):
        result = self.classify(["K64 autorun: starting office", "[win64 office pid 3] LibreOffice 26.8.0",
                                "K64 autorun: result exited exit=0 faulted=0"])
        self.assertEqual(result["exit_code"], 0)
        self.assertFalse(result["faulted"])

    def test_version_output_does_not_hide_loader_or_runtime_failure(self):
        for failure in ("K64 ldr: soffice.bin needs missing.dll!Fn: not loaded", "FATAL ERROR: allocation failure", "FATAL: CHECK failed"):
            with self.subTest(failure=failure):
                result = self.classify(["K64 autorun: starting office", "LibreOffice 26.8.0", failure,
                                        "K64 autorun: result exited exit=0 faulted=0"])
                self.assertTrue(result["faulted"])

    def test_guest_fault_is_not_success(self):
        result = self.classify(["K64 autorun: starting office", "LibreOffice 26.8.0",
                                "K64: process 3 killed", "K64 autorun: result exited exit=0 faulted=1"])
        self.assertTrue(result["faulted"])
        self.assertTrue(result["exceptions"])

    def test_required_gpu_child_failure_survives_parent_exit_gate(self):
        result = self.classify([
            "K64 autorun: starting office", "LibreOffice 26.8.0",
            "K64 exc: pid 216 tid 228 first-chance 80000003 at legcord.exe+5831fba (0 0)",
            "[user Legcord.exe pid 60] GPU process exited unexpectedly: exit_code=-2147483645",
            "[win64 Legcord.exe pid 60] GPU process exited unexpectedly: exit_code=-2147483645",
            "K64 autorun: result exited exit=0 faulted=0"])
        self.assertTrue(result["faulted"])
        self.assertEqual(len(result["child_process_failures"]), 1)
        self.assertEqual(len(result["first_chance_exceptions"]), 1)
        self.assertIn("required GPU child failed", result["furthest"])

    def test_handled_exception_and_optional_probes_do_not_invent_fatal(self):
        result = self.classify([
            "K64 autorun: starting office", "LibreOffice 26.8.0",
            "K64 ldr: dxcore.dll not loaded: LoadLibrary needs dxcore.dll: file not found [c0000135]",
            "K64 exc: pid 216 tid 228 first-chance 80000003 at legcord.exe+5831fba (0 0)",
            "K64 autorun: result exited exit=0 faulted=0"])
        self.assertFalse(result["faulted"])
        self.assertFalse(result["child_process_failures"])
        self.assertEqual(len(result["first_chance_exceptions"]), 1)

    def test_boot_child_failure_is_not_attributed_to_product(self):
        result = self.classify([
            "GPU process exited unexpectedly: exit_code=-2147483645",
            "K64 exc: pid 216 tid 228 first-chance 80000003 at boot.exe+10 (0 0)",
            "K64 autorun: starting office", "LibreOffice 26.8.0",
            "K64 autorun: result exited exit=0 faulted=0"])
        self.assertFalse(result["child_process_failures"])
        self.assertFalse(result["first_chance_exceptions"])


class PackageBoundary(unittest.TestCase):
    def test_nested_case_insensitive_launcher_is_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            (tree / "Program").mkdir()
            (tree / "Program" / "SOffice.COM").write_bytes(b"sample")
            name, path = probe.find_product_exe(tree, ("program/soffice.com",))
            self.assertEqual(name, "Program\\SOffice.COM")
            self.assertEqual(path, tree / "Program" / "SOffice.COM")

    def test_path_escape_and_ambiguous_case_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            for name in ("Legcord.exe", "legcord.exe"):
                (tree / name).write_bytes(b"sample")
            with self.assertRaises(ValueError):
                probe.find_product_exe(tree, ("../outside.exe",))
            with self.assertRaises(ValueError):
                probe.find_product_exe(tree, ("LEGcord.exe",))

    def test_symlink_to_foreign_package_refused(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as foreign:
            outside = Path(foreign) / "Legcord.exe"
            outside.write_bytes(b"sample")
            tree = Path(directory)
            (tree / "Legcord.exe").symlink_to(outside)
            with self.assertRaises(ValueError):
                probe.find_product_exe(tree, ("Legcord.exe",))


class PackageCache(unittest.TestCase):
    def test_same_size_replacement_rebuilds_image(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = root / "package"
            tree.mkdir()
            executable = tree / "Legcord.exe"
            executable.write_bytes(b"AAAA")
            image = root / "legcord.img"
            stamp = Path(str(image) + ".json")
            builds = []

            def builder(image, tree, volume_dir, overlay):
                if not image.exists() or not stamp.exists():
                    builds.append(executable.read_bytes())
                    image.write_bytes(executable.read_bytes())
                    stamp.write_text('{"key":"same-name-and-size"}')
                return [("Legcord.exe", 4)]

            probe.build_product_image(image, tree, "legcord", builder)
            probe.build_product_image(image, tree, "legcord", builder)
            self.assertEqual(builds, [b"AAAA"])
            executable.write_bytes(b"BBBB")
            probe.build_product_image(image, tree, "legcord", builder)
            self.assertEqual(builds, [b"AAAA", b"BBBB"])
            self.assertEqual(image.read_bytes(), b"BBBB")

    def test_package_mutation_during_copy_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tree = root / "package"
            tree.mkdir()
            executable = tree / "Legcord.exe"
            executable.write_bytes(b"AAAA")
            image = root / "legcord.img"
            stamp = Path(str(image) + ".json")

            def builder(image, tree, volume_dir, overlay):
                stamp.write_text('{"key":"same-name-and-size"}')
                executable.write_bytes(b"BBBB")
                return []

            with self.assertRaises(ValueError):
                probe.build_product_image(image, tree, "legcord", builder)
            self.assertFalse(stamp.exists())

    def test_scenario_overrides_refused_before_guest_work(self):
        for flag in ("--args=--version", "--arg=--version", "--expect=pretend", "--env=ELECTRON_RUN_AS_NODE=1", "--exe=helper.exe",
                     "--disable-direct-composition", "--args=--disable-direct-composition"):
            with self.subTest(flag=flag), patch.object(runner, "main") as guest, contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    probe.main(["--app", "legcord", "--tree", "/missing", flag])
                self.assertEqual(caught.exception.code, 2)
                guest.assert_not_called()

    def test_fixed_legcord_profile_reaches_runner_with_gdi_software_switch(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory)
            (tree / "Legcord.exe").write_bytes(b"unit-test placeholder")
            observed = []

            def guest():
                observed.append(dict(runner.APPS["legcord"]))
                self.assertIn("--tree", sys.argv)
                return 2

            with patch.object(probe, "pe_machine", return_value=0x8664), patch.object(runner, "main", side_effect=guest):
                code = probe.main(["--app", "legcord", "--tree", str(tree), "--out", str(tree / "result")])
            self.assertEqual(code, 2)
            self.assertEqual(len(observed), 1)
            self.assertEqual(observed[0]["exe"], "Legcord.exe")
            self.assertEqual(observed[0]["args"], probe.PRODUCTS["legcord"]["args"])
            self.assertIn("--disable-gpu", observed[0]["args"].split())
            self.assertEqual(observed[0]["args"].split().count("--disable-direct-composition"), 1)
            self.assertNotIn("legcord", runner.APPS)


if __name__ == "__main__":
    unittest.main()
