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


if __name__ == "__main__":
    unittest.main()
