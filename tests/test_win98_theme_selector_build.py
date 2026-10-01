# SPDX-License-Identifier: GPL-2.0-only
"""A failed resource admission must never leave a successful build receipt."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "ntwddm/win98/theme_selector/build.py"
SPEC = importlib.util.spec_from_file_location("win98_selector_build", SOURCE)
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class BuildAdmissionTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.space = patch.object(build.shutil, "disk_usage", return_value=SimpleNamespace(
            free=build.RESERVE + build.OUTPUT_LIMIT + 32768))
        self.space.start()
        self.addCleanup(self.space.stop)

    def test_initial_admission_reserves_entire_permitted_output(self):
        with patch.object(build.shutil, "disk_usage", return_value=SimpleNamespace(
                free=build.RESERVE + build.OUTPUT_LIMIT - 1)):
            with self.assertRaisesRegex(RuntimeError, "reserve"):
                build.guard(admission=True)

    def test_receipt_counts_itself_and_existing_artifacts(self):
        (self.root / "artifact").write_bytes(b"12345")
        receipt = build.finish_report({"status": "PASS"}, self.root)
        saved = json.loads(receipt.read_text())
        total = sum(path.stat().st_size for path in self.root.iterdir())
        self.assertEqual(saved["resource_guard"]["output_bytes"], total)
        self.assertFalse((self.root / "result.pending").exists())

    def test_receipt_over_budget_is_never_published_as_pass(self):
        with patch.object(build, "OUTPUT_LIMIT", 128):
            with self.assertRaisesRegex(RuntimeError, "receipt would exceed"):
                build.finish_report({"status": "PASS", "evidence": "x" * 200}, self.root)
        self.assertFalse((self.root / "result.json").exists())
        self.assertFalse((self.root / "result.pending").exists())

    def test_disk_floor_loss_after_write_removes_pass_receipt(self):
        real_guard = build.guard
        calls = []

        def changing_guard(directory=None, admission=False):
            calls.append(directory)
            if len(calls) > 1:
                raise RuntimeError("20 GiB reserve lost during publication")
            return real_guard(directory, admission)

        with patch.object(build, "guard", side_effect=changing_guard):
            with self.assertRaisesRegex(RuntimeError, "reserve lost"):
                build.finish_report({"status": "PASS"}, self.root)
        self.assertEqual(len(calls), 2)
        self.assertFalse((self.root / "result.json").exists())
        self.assertFalse((self.root / "result.pending").exists())


class ObserverImportGateTests(unittest.TestCase):
    """A setter or resolver must not be accepted as an independent observer."""
    def fake_pe(self, extra=None, missing=None, relocation_type=3, relocation_size=12):
        class FakePE:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def is_dll(self):
                return False

        pe = FakePE()
        pe.FILE_HEADER = SimpleNamespace(Machine=0x14c, TimeDateStamp=0, Characteristics=0)
        directories = [SimpleNamespace(VirtualAddress=0, Size=0) for _ in range(15)]
        directories[5] = SimpleNamespace(VirtualAddress=0x3000, Size=relocation_size)
        pe.OPTIONAL_HEADER = SimpleNamespace(Magic=0x10b, MajorOperatingSystemVersion=4,
            MinorOperatingSystemVersion=10, MajorSubsystemVersion=4, MinorSubsystemVersion=10,
            Subsystem=2, AddressOfEntryPoint=0x1000, DllCharacteristics=0,
            DATA_DIRECTORY=directories)
        pe.DIRECTORY_ENTRY_BASERELOC = [SimpleNamespace(entries=[SimpleNamespace(type=relocation_type)])]
        names = {"KERNEL32.DLL": ["CreateProcessA", "WaitForSingleObject", "GetExitCodeProcess"],
                 "USER32.DLL": ["GetSysColor"], "GDI32.DLL": ["GetPixel"],
                 "ADVAPI32.DLL": ["RegQueryValueExA"]}
        if extra:
            names[extra[0]].append(extra[1])
        if missing:
            names[missing[0]].remove(missing[1])
        pe.DIRECTORY_ENTRY_IMPORT = [SimpleNamespace(dll=dll.encode("ascii"),
            imports=[SimpleNamespace(name=name.encode("ascii")) for name in members])
            for dll, members in names.items()]
        return pe

    def test_minimal_real_readers_and_child_observation_are_required(self):
        with patch.object(build.pefile, "PE", return_value=self.fake_pe()):
            self.assertEqual(build.native_gate("fixture", "observer")["role"], "observer")
        with patch.object(build.pefile, "PE", return_value=self.fake_pe(
                missing=("KERNEL32.DLL", "GetExitCodeProcess"))):
            with self.assertRaisesRegex(RuntimeError, "child APIs missing"):
                build.native_gate("fixture", "observer")

    def test_setters_resolvers_and_termination_cannot_pass_observer_gate(self):
        for extra in (("USER32.DLL", "SetSysColors"), ("ADVAPI32.DLL", "RegSetValueExA"),
                      ("ADVAPI32.DLL", "RegCreateKeyExA"), ("KERNEL32.DLL", "GetProcAddress"),
                      ("KERNEL32.DLL", "TerminateProcess")):
            with self.subTest(extra=extra), patch.object(build.pefile, "PE", return_value=self.fake_pe(extra)):
                with self.assertRaisesRegex(RuntimeError, "forbidden mutation/resolver"):
                    build.native_gate("fixture", "observer")

    def test_flushing_registry_is_not_read_only_observation(self):
        with patch.object(build.pefile, "PE", return_value=self.fake_pe(("ADVAPI32.DLL", "RegFlushKey"))):
            with self.assertRaisesRegex(RuntimeError, "registry imports must be read-only"):
                build.native_gate("fixture", "observer")

    def test_zero_sized_or_non_highlow_relocations_cannot_pass(self):
        for pe, reason in ((self.fake_pe(relocation_size=0), "relocations required"),
                           (self.fake_pe(relocation_type=0), "HIGHLOW")):
            with patch.object(build.pefile, "PE", return_value=pe):
                with self.assertRaisesRegex(RuntimeError, reason):
                    build.native_gate("fixture", "observer")


if __name__ == "__main__":
    unittest.main()
