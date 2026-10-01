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
        names = {"KERNEL32.DLL": ["CreateProcessA", "WaitForSingleObject", "GetExitCodeProcess", "GetCurrentProcessId"],
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

    def test_observer_identity_must_bind_to_the_parent_owned_process(self):
        with patch.object(build.pefile, "PE", return_value=self.fake_pe(
                missing=("KERNEL32.DLL", "GetCurrentProcessId"))):
            with self.assertRaisesRegex(RuntimeError, "child APIs missing"):
                build.native_gate("fixture", "observer")

    def test_zero_sized_or_non_highlow_relocations_cannot_pass(self):
        for pe, reason in ((self.fake_pe(relocation_size=0), "relocations required"),
                           (self.fake_pe(relocation_type=0), "HIGHLOW")):
            with patch.object(build.pefile, "PE", return_value=pe):
                with self.assertRaisesRegex(RuntimeError, reason):
                    build.native_gate("fixture", "observer")


class BootstrapImportGateTests(unittest.TestCase):
    """A parent must observe a real process with only the fixed OEM kernel APIs."""
    def fake_pe(self, missing=None, extra=None):
        pe = ObserverImportGateTests().fake_pe()
        names = ["CloseHandle", "CreateFileA", "CreateProcessA", "ExitProcess",
                 "FlushFileBuffers", "GetCommandLineA", "GetCurrentProcessId",
                 "GetExitCodeProcess", "GetModuleFileNameA", "GetVersionExA",
                 "ReadFile", "WaitForSingleObject", "WriteFile"]
        if missing:
            names.remove(missing)
        modules = {"KERNEL32.DLL": names}
        if extra:
            modules.setdefault(extra[0], []).append(extra[1])
        pe.DIRECTORY_ENTRY_IMPORT = [SimpleNamespace(dll=dll.encode("ascii"),
            imports=[SimpleNamespace(name=name.encode("ascii")) for name in members])
            for dll, members in modules.items()]
        return pe

    def test_oem_parent_observes_owned_child_and_final_file_io(self):
        with patch.object(build.pefile, "PE", return_value=self.fake_pe()):
            result = build.native_gate("fixture", "bootstrap")
        self.assertEqual(result["role"], "bootstrap")
        self.assertFalse(result["native_execution_verified"])

    def test_parent_cannot_lose_wait_exit_or_case_log_apis(self):
        for name in ("CreateProcessA", "WaitForSingleObject", "GetExitCodeProcess",
                     "GetCurrentProcessId", "ReadFile", "WriteFile", "FlushFileBuffers",
                     "CloseHandle", "GetCommandLineA"):
            with self.subTest(name=name), patch.object(build.pefile, "PE", return_value=self.fake_pe(missing=name)):
                with self.assertRaisesRegex(RuntimeError, "bootstrap.*missing"):
                    build.native_gate("fixture", "bootstrap")

    def test_duplicate_descriptors_cannot_hide_a_setter_or_termination(self):
        fixtures = (("bootstrap", self.fake_pe(), "kernel32.dll", "TerminateProcess"),
                    ("observer", ObserverImportGateTests().fake_pe(), "advapi32.dll", "RegSetValueExA"))
        for role, pe, module, name in fixtures:
            hidden = SimpleNamespace(dll=module.encode("ascii"),
                imports=[SimpleNamespace(name=name.encode("ascii"))])
            pe.DIRECTORY_ENTRY_IMPORT.insert(0, hidden)
            with self.subTest(role=role), patch.object(build.pefile, "PE", return_value=pe):
                with self.assertRaisesRegex(RuntimeError, "duplicate.*descriptor"):
                    build.native_gate("fixture", role)

    def test_parent_cannot_load_resolve_kill_or_mutate_theme(self):
        for extra in (("KERNEL32.DLL", "GetProcAddress"), ("KERNEL32.DLL", "LoadLibraryA"),
                      ("KERNEL32.DLL", "TerminateProcess"), ("USER32.DLL", "SetSysColors"),
                      ("ADVAPI32.DLL", "RegSetValueExA"), ("GDI32.DLL", "SetPixel")):
            with self.subTest(extra=extra), patch.object(build.pefile, "PE", return_value=self.fake_pe(extra=extra)):
                with self.assertRaisesRegex(RuntimeError, "bootstrap"):
                    build.native_gate("fixture", "bootstrap")


if __name__ == "__main__":
    unittest.main()
