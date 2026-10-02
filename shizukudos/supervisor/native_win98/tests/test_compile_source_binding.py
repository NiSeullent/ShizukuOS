#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise compile.py source binding with copied sources and a mocked build.

No compiler, private media, native build, network or VM is invoked. Mock artifact
bytes are confined to a temporary copied tree and never constitute build evidence.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
GLYPHS = tuple("shizukudos/csmwrap/video/" + name for name in
               ("cp437.c", "cp437.h", "font8x8_basic.h"))
AP_INPUTS = ("shizukudos/kernel32/service_policy.h", "shizukudos/kernel64/smp_acpi.c",
             "shizukudos/kernel64/smp_acpi.h", "shizukudos/boot_profile/win98_foundation.h")


class CompileSourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="c957-font-binding-")
        self.root = Path(self.temporary.name) / "copied-source"
        # Copy public source only; no binaries, media, build outputs or .git.
        suffixes = {".c", ".h", ".asm", ".ld", ".py"}
        sources = {p for folder in ("shizukudos/supervisor", "shizukudos/abi", "shizukudos/uefi", "shizukudos/boot_profile")
                   for p in (ROOT / folder).rglob("*") if p.is_file() and p.suffix in suffixes}
        sources.update(ROOT / p for p in (*GLYPHS, *AP_INPUTS, "shizukudos/tools/shzlib.py",
                                         "shizukudos/kernel64/standalone/memholes.h",
                                         "shizukudos/kernel32/service_policy.h"))
        for source in sources:
            copied = self.root / source.relative_to(ROOT)
            copied.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, copied)
        (self.root / "build").mkdir()
        self.out = self.root / "build/mock-components"
        self.original_glyphs = {p: (ROOT / p).read_bytes() for p in GLYPHS}

    def tearDown(self):
        try:
            for path, original in self.original_glyphs.items():
                self.assertEqual((ROOT / path).read_bytes(), original, "real source changed: " + path)
        finally:
            self.temporary.cleanup()

    def compile_control(self, changed=None):
        compile_path = self.root / "shizukudos/supervisor/native_win98/compile.py"
        spec_from_file = importlib.util.spec_from_file_location
        spec = spec_from_file("copied_compile_control", compile_path)
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        mocked_payload = b"mock payload: no compiler was executed\n"
        built_calls = []

        def vbios():
            built_calls.append("vbios")
            (self.out / "vbios.bin").write_bytes(b"mock vbios\n")

        def ap_trampoline():
            built_calls.append("ap_trampoline")
            data = b"mock trampoline: no compiler was executed\n"
            (self.out / "ap-trampoline.bin").write_bytes(data)
            return data, ["mock-build-boundary", "ap_trampoline"]

        def payload():
            built_calls.append("payload")
            (self.out / "payload.bin").write_bytes(mocked_payload)
            (self.out / "payload.elf").write_bytes(b"mock elf\n")
            if changed:
                target = self.root / changed
                target.write_bytes(target.read_bytes() + b"\n/* copied source mutation */\n")
            return mocked_payload, [["mock-build-boundary", "payload"]]

        def loader(data):
            built_calls.append("loader")
            self.assertEqual(data, mocked_payload)
            target = self.out / "BOOTX64.EFI"
            target.write_bytes(b"mock loader\n")
            return target, ["mock-build-boundary", "loader"]

        class BuildBoundaryLoader:
            def __init__(self, real_loader):
                self.real_loader = real_loader

            def create_module(self, spec):
                return None

            def exec_module(self, module):
                # Import the actual copied ordinary builder, then substitute only
                # its compiler boundary. compile.py and source_files stay real.
                self.real_loader.exec_module(module)
                module.build_vbios = vbios
                module.build_ap_trampoline = ap_trampoline
                module.build_payload = payload
                module.build_loader = loader

        def bounded_spec(name, location, *args, **kwargs):
            result = spec_from_file(name, location, *args, **kwargs)
            if name == "ordinary_supervisor":
                result.loader = BuildBoundaryLoader(result.loader)
            return result

        error = None
        with mock.patch.dict(sys.modules), mock.patch.object(sys, "path", list(sys.path)), \
             mock.patch.object(sys, "argv", [str(compile_path), "--out", str(self.out)]), \
             mock.patch.object(importlib.util, "spec_from_file_location", bounded_spec), \
             mock.patch.object(shutil, "which", return_value="mocked-tool-discovery"), \
             mock.patch.object(subprocess, "run", side_effect=AssertionError("external command forbidden")), \
             mock.patch.object(subprocess, "Popen", side_effect=AssertionError("external process forbidden")), \
             contextlib.redirect_stdout(io.StringIO()):
            sys.modules.pop("shzlib", None)
            try:
                runner.main()
            except ValueError as caught:
                error = caught
        self.assertEqual(built_calls, ["vbios", "ap_trampoline", "payload", "loader"])
        result = json.loads((self.out / "result.json").read_text())
        self.assertFalse(result["VM_executed"])
        self.assertFalse(result["Windows98_executed"])
        self.assertEqual((self.out / "payload.bin").read_bytes(), mocked_payload)
        return error, result

    def test_unchanged_copied_sources_reach_mocked_success_control(self):
        error, result = self.compile_control()
        self.assertIsNone(error)
        self.assertEqual(result["status"], "PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN")
        self.assertIn("shizukudos/boot_profile/win98_foundation.h", result["sources_sha256"])

        self.assertTrue(result["source_before_after_match"])
        self.assertEqual(result["commands"], [["mock-build-boundary", "ap_trampoline"],
                                              ["mock-build-boundary", "payload"],
                                              ["mock-build-boundary", "loader"]])

    def assert_mutation_fails(self, changed):
        before = hashlib.sha256((self.root / changed).read_bytes()).hexdigest()
        error, result = self.compile_control(changed)
        self.assertIsInstance(error, ValueError, "changed source was accepted: " + changed)
        self.assertEqual(result["status"], "FAIL_COMPILE_PRESERVED")
        self.assertIn("source changed during compilation", result["error"])
        self.assertEqual(result["sources_sha256"][changed], before)
        self.assertNotIn("source_before_after_match", result)
        self.assertNotIn("artifacts", result)
        self.assertNotEqual(hashlib.sha256((self.root / changed).read_bytes()).hexdigest(), before)

    def test_existing_video_source_mutation_is_rejected(self):
        self.assert_mutation_fails("shizukudos/supervisor/src/video.c")

    def test_foundation_policy_mutation_is_rejected(self):
        self.assert_mutation_fails("shizukudos/boot_profile/win98_foundation.h")

    def test_kernel32_service_policy_mutation_is_rejected(self):
        self.assert_mutation_fails("shizukudos/kernel32/service_policy.h")

    def test_cp437_implementation_mutation_is_rejected(self):
        self.assert_mutation_fails(GLYPHS[0])

    def test_cp437_header_mutation_is_rejected(self):
        self.assert_mutation_fails(GLYPHS[1])

    def test_cp437_font_mutation_is_rejected(self):
        self.assert_mutation_fails(GLYPHS[2])

    def test_kernel32_service_policy_mutation_is_rejected(self):
        self.assert_mutation_fails(AP_INPUTS[0])

    def test_smp_acpi_implementation_mutation_is_rejected(self):
        self.assert_mutation_fails(AP_INPUTS[1])

    def test_smp_acpi_header_mutation_is_rejected(self):
        self.assert_mutation_fails(AP_INPUTS[2])

    def test_win98_foundation_header_mutation_is_rejected(self):
        self.assert_mutation_fails(AP_INPUTS[3])


if __name__ == "__main__":
    unittest.main(verbosity=2)
