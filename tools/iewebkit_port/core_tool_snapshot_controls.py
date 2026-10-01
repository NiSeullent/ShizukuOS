#!/usr/bin/env python3
"""Read-only controls for source-bound host helpers; no PE executes.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
The original linked PE is inspected in memory. Cached-module and changed-source
controls modify this test process only. No build/output/receipt files are written.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
import core_link_jsc


class SnapshotControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[2]
        cls.work = cls.work.resolve(strict=True)
        cls.native = cls.native.resolve(strict=True)
        cls.receipt = json.loads((cls.native / "WTFNAT.receipt.json").read_text())
        cls.binary = cls.native / "WTFNAT.EXE"
        if hashlib.sha256(cls.binary.read_bytes()).hexdigest() != cls.receipt["binary"]["sha256"]:
            raise ValueError("Use the unchanged genuine linked PE for this read-only audit control")

    def test_cached_helper_is_replaced_by_source_snapshot(self):
        cached = types.ModuleType("core_archive_receipt")
        cached.file_pin = lambda *_: (_ for _ in ()).throw(AssertionError("cached source executed"))
        sys.modules["core_archive_receipt"] = cached
        bundle = core_link_jsc.load_tool_bundle()
        self.assertIsNot(bundle.modules["core_archive_receipt"], cached)
        pin, _ = bundle.modules["core_archive_receipt"].file_pin(Path(__file__))
        self.assertGreater(pin["bytes"], 0)
        bundle.verify()

    def test_helper_source_drift_is_rejected(self):
        bundle = core_link_jsc.load_tool_bundle()
        scope = bundle.verify.__globals__
        original_capture = scope["capture"]
        target = Path(bundle.snapshots["core_jsc_profile_gate"][1]["path"])

        def changed_capture(path):
            data, row, identity = original_capture(path)
            if Path(path) == target:
                data += b"\n# in-memory changed-source control\n"
                row = dict(row, sha256=hashlib.sha256(data).hexdigest(), bytes=len(data))
            return data, row, identity

        with patch.dict(scope, capture=changed_capture):
            with self.assertRaisesRegex(ValueError, "Loaded helper source changed"):
                bundle.verify()

    def test_late_dynamic_import_module_replacement_is_rejected(self):
        bundle = core_link_jsc.load_tool_bundle()
        marker = types.ModuleType("app_preflight")
        marker.analyze = lambda *_: (_ for _ in ()).throw(AssertionError("unbound late import executed"))
        sys.modules["app_preflight"] = marker
        with self.assertRaisesRegex(ValueError, "Loaded helper module identity changed: app_preflight"):
            bundle.verify()

    def test_real_pe_audit_uses_the_pinned_late_preparer(self):
        bundle = core_link_jsc.load_tool_bundle()
        baseline = json.loads(Path(self.receipt["baseline"]["path"]).read_text())
        original_read = Path.read_bytes
        preparer = self.root / "ntwin32/prepare.py"

        def read(path):
            if path == preparer:
                raise AssertionError("late mutable preparer read")
            return original_read(path)

        with patch.object(Path, "read_bytes", read):
            report = bundle.modules["iewebkit_build_win98"].audit(self.binary, baseline)
        self.assertTrue(report["static_gate_passed"])
        self.assertFalse(report["absent_from_media_export_baseline"])
        self.assertFalse(report["installed_dependency_or_behavior_verified"])
        bundle.verify()

    def test_actual_unbuilt_jsc_refuses_output_creation(self):
        core = json.loads((self.work / "core-build.json").read_text())
        if core.get("jsc"):
            self.skipTest("Upstream JSC has completed; the incomplete-build control no longer applies")
        output = self.work / "jsc-incomplete-link-rejection-v1"
        self.assertFalse(output.exists())
        result = subprocess.run([sys.executable, "-B", str(Path(core_link_jsc.__file__)),
            "--work", str(self.work), "--output", str(output),
            "--baseline", self.receipt["baseline"]["path"],
            "--runtime", str(self.work / "runtime-win9x-v5"),
            "--iewebkit-repo", str(self.repo)], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Complete and bind the actual upstream jsc executable build first", result.stderr)
        self.assertFalse(output.exists())

    def test_caller_dependency_query_preserves_the_real_command(self):
        rows = json.loads((self.work / "build-jsc-win9x/compile_commands.json").read_text())
        row = next(item for item in rows if item["file"].endswith("/JavaScriptCore/jsc.cpp"))
        command = row.get("arguments") or shlex.split(row["command"])
        command[command.index("-c") + 1] = str(Path(core_link_jsc.__file__).with_name("core_jsc_native.cpp"))
        query = core_link_jsc.caller_dependency_command(command)
        self.assertEqual(query[0], command[0])
        self.assertIn(command[command.index("-c") + 1], query)
        self.assertNotIn("-o", query)
        self.assertNotIn("-c", query)
        self.assertEqual(query[-3:], ["-M", "-MT", core_link_jsc.DEPENDENCY_TARGET])
        for token in command:
            if token.startswith(("-D", "-I", "-std=")):
                self.assertIn(token, query)
        with self.assertRaisesRegex(ValueError, "unsupported existing dependency"):
            core_link_jsc.caller_dependency_command([*command, "-MD"])

    def test_actual_caller_header_dependency_parser_fails_closed(self):
        caller = Path(core_link_jsc.__file__).with_name("core_jsc_native.cpp")
        header = self.work / "build-jsc-win9x/JavaScriptCore/Headers/JavaScriptCore/JavaScript.h"
        self.assertTrue(header.is_file())
        text = core_link_jsc.DEPENDENCY_TARGET + ": " + str(caller) + " \\\n " + str(header) + "\n"
        self.assertEqual(core_link_jsc.caller_dependency_paths(text, self.work), [caller, header])
        for bad in (text.replace(core_link_jsc.DEPENDENCY_TARGET, "unbound-target", 1),
                    text.rstrip("\n"), text + "\x00", text + "$(unbound)\n",
                    core_link_jsc.DEPENDENCY_TARGET + ":\n"):
            with self.assertRaises(ValueError):
                core_link_jsc.caller_dependency_paths(bad, self.work)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--iewebkit-repo", type=Path, required=True)
    args = parser.parse_args()
    SnapshotControls.work, SnapshotControls.native, SnapshotControls.repo = args.work, args.native, args.iewebkit_repo
    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SnapshotControls))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
