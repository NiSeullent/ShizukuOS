#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile the actual private builder's public source snapshot without media.

Uses installed native toolchains and fresh temporary component outputs. This
checks source closure; it does not execute firmware, a VM or Windows.
"""
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

NATIVE = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("snapshot_native_builder", NATIVE / "build.py")
BUILDER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILDER)
TOOLS = ("gcc", "nasm", "ld", "nm", "readelf", "objcopy", "x86_64-w64-mingw32-gcc")


@unittest.skipUnless(all(shutil.which(tool) for tool in TOOLS), "installed native toolchains required")
class SnapshotCompileTests(unittest.TestCase):
    def test_actual_snapshot_compiles_and_pins_cross_kernel_policy(self):
        with tempfile.TemporaryDirectory(prefix="shz-source-snapshot-") as temporary:
            output = Path(temporary)
            snapshot = output / "source"
            before = {}
            for source in BUILDER.source_files():
                relative = source.relative_to(BUILDER.ROOT)
                before[str(relative)] = BUILDER.file_sha(source)
                destination = snapshot / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                self.assertEqual(BUILDER.file_sha(destination), before[str(relative)])
            components = output / "components"
            child = subprocess.run(
                [sys.executable, snapshot / "shizukudos/supervisor/native_win98/compile.py",
                 "--out", components], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, timeout=100)
            self.assertEqual(child.returncode, 0, child.stderr[-12000:])
            result = json.loads((components / "result.json").read_text())
            self.assertEqual(result["status"], "PASS_NATIVE_SUPERVISOR_COMPONENT_COMPILE_NOT_RUN")
            self.assertEqual(result["sources_sha256"], before)
            self.assertIn("shizukudos/kernel32/service_policy.h", result["sources_sha256"])
            self.assertFalse(result["VM_executed"])
            self.assertFalse(result["Windows98_executed"])
            for name, pin in result["artifacts"].items():
                artifact = components / name
                self.assertEqual(artifact.stat().st_size, pin["bytes"])
                self.assertEqual(BUILDER.file_sha(artifact), pin["sha256"])
            self.assertEqual({str(p.relative_to(BUILDER.ROOT)): BUILDER.file_sha(p)
                              for p in BUILDER.source_files()}, before)


if __name__ == "__main__":
    unittest.main(verbosity=2)
