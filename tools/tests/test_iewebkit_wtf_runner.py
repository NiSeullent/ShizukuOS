"""Host boundary controls only; no compiler, provider or guest execution."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
spec = importlib.util.spec_from_file_location("wtf_runner_controls", TOOLS / "iewebkit_wtf_runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


class ObserverBoundaries(unittest.TestCase):
    def test_reserve_failure_creates_no_output_and_starts_no_child(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = root / "baseline.json"
            baseline.write_text("{}")
            output = root / "refused"
            usage = type("Usage", (), {"free": runner.FLOOR - 1})()
            with patch.object(runner.shutil, "disk_usage", return_value=usage), \
                    patch.object(runner.shutil, "which", return_value="/bin/true"), \
                    patch.object(runner.subprocess, "Popen") as child:
                with self.assertRaises(ValueError):
                    runner.build(baseline, output)
                child.assert_not_called()
            self.assertFalse(output.exists())

    def test_unexpected_guest_output_is_rejected_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "parent.json"
            manifest.write_text(json.dumps({"inputs": [{"guest": r"C:\GOPLAB\WTFNAT.EXE"}],
                                          "outputs": [r"C:\GOPLAB\WTFNAT.LOG", r"C:\WINDOWS\OTHER.LOG"]}))
            output = root / "refused"
            with self.assertRaises(ValueError):
                runner.freeze(manifest, root / "missing-observer", output)
            self.assertFalse(output.exists())

    def test_diagnostic_abort_output_reaches_observer_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = root / "parent.json"
            manifest.write_text(json.dumps({"inputs": [{"guest": r"C:\GOPLAB\WTFNAT.EXE"}],
                                          "outputs": [r"C:\GOPLAB\WTFNAT.LOG", r"C:\GOPLAB\WTFABRT.LOG"]}))
            output = root / "refused"
            # A legitimate additional diagnostic output is allowed, but absent
            # observer provenance still refuses the fixture before any write.
            with self.assertRaises(FileNotFoundError):
                runner.freeze(manifest, root / "missing-observer", output)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
