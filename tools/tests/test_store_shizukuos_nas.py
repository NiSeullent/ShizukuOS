"""Run the exact remote helper against actual private local files, without SSH."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

MODULE = Path(__file__).resolve().parents[1] / "store_shizukuos_nas.py"
spec = importlib.util.spec_from_file_location("nas_archive", MODULE)
nas = importlib.util.module_from_spec(spec)
spec.loader.exec_module(nas)


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)
        self.data = b"private project archive\x00" * 100
        self.sha = hashlib.sha256(self.data).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def run_helper(self, name="component.bin", data=None, pin=None, root=None):
        return subprocess.run([sys.executable, "-c", nas.REMOTE_HELPER, str(root or self.root),
                               name, str(len(self.data)), pin or self.sha],
                              input=self.data if data is None else data, capture_output=True, timeout=10)

    def assert_rejected(self, result):
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "component.bin").exists())
        self.assertFalse(list(self.root.glob(".incoming-*")))

    def test_exact_private_file_and_readback(self):
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        accepted = json.loads(result.stdout)
        self.assertEqual((self.root / "component.bin").read_bytes(), self.data)
        self.assertEqual(accepted["readback_sha256"], self.sha)
        self.assertEqual(accepted["mode"], "0o600")

    def test_existing_file_is_preserved(self):
        original = self.root / "component.bin"
        original.write_bytes(b"previous evidence")
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(original.read_bytes(), b"previous evidence")

    def test_wrong_digest(self):
        self.assert_rejected(self.run_helper(pin="0" * 64))

    def test_truncated_stream(self):
        self.assert_rejected(self.run_helper(data=self.data[:-1]))

    def test_extra_stream(self):
        self.assert_rejected(self.run_helper(data=self.data + b"x"))

    def test_path_traversal(self):
        self.assert_rejected(self.run_helper(name="../component.bin"))

    def test_group_readable_private_root(self):
        self.root.chmod(0o750)
        self.assert_rejected(self.run_helper())

    def test_symlink_root(self):
        nested = self.root / "nested"
        nested.mkdir(mode=0o700)
        alias = self.root / "alias"
        alias.symlink_to(nested, target_is_directory=True)
        self.assert_rejected(self.run_helper(root=alias))

    def test_shell_artifact_name(self):
        self.assert_rejected(self.run_helper(name="$(id).bin"))

    def test_source_symlink_rejected(self):
        original = self.root / "source"
        original.write_bytes(self.data)
        alias = self.root / "source-link"
        alias.symlink_to(original)
        with self.assertRaises(ValueError):
            nas.validate_input(alias, self.sha)

    def store_fixture(self, boundary):
        source = self.root / "source-artifact"
        source.write_bytes(self.data * 1000)
        expected = hashlib.sha256(source.read_bytes()).hexdigest()
        remote = self.root / "remote"
        remote.mkdir(mode=0o700)
        receipt = self.root / "receipt.json"
        with mock.patch.object(nas, "REMOTE_ROOT", str(remote)), mock.patch.object(
                nas.subprocess, "Popen", boundary):
            result = nas.store(source, expected, "archive.bin", receipt, timeout=30)
        return result, source, remote, receipt

    def test_host_transport_actual_pipes_and_leases(self):
        original = subprocess.Popen

        def local_ssh(argv, **kwargs):
            self.assertEqual(argv[0], "ssh")
            args = nas.shlex.split(argv[-1])
            return original([sys.executable, "-c", args[2], *args[3:]], **kwargs)

        result, source, remote, receipt = self.store_fixture(local_ssh)
        self.assertEqual(result["status"], "PASS_PRIVATE_NAS_ARCHIVE")
        self.assertEqual(source.read_bytes(), (remote / "archive.bin").read_bytes())
        self.assertTrue(receipt.exists())

    def test_host_transport_output_saturation(self):
        original = subprocess.Popen

        def noisy_boundary(_argv, **kwargs):
            return original([sys.executable, "-c", "import sys,time; sys.stdout.write('x'*20000); sys.stdout.flush(); time.sleep(20)"], **kwargs)

        with self.assertRaisesRegex(ValueError, "output exceeded"):
            self.store_fixture(noisy_boundary)
        self.assertFalse((self.root / "receipt.json").exists())
        self.assertFalse((self.root / "remote" / "archive.bin").exists())

    def test_host_transport_writer_break_refused(self):
        original = subprocess.Popen
        writers = []

        def blocked_boundary(_argv, **kwargs):
            writers.append(original([sys.executable, "-c",
                "import pathlib,sys,time; time.sleep(.05); pathlib.Path(sys.argv[1]).write_bytes(b'writer')",
                str(self.root / "source-artifact")]))
            return original([sys.executable, "-c", "import time; time.sleep(20)"], **kwargs)

        try:
            with self.assertRaisesRegex(ValueError, "lease/identity changed"):
                self.store_fixture(blocked_boundary)
            self.assertFalse((self.root / "receipt.json").exists())
            self.assertFalse((self.root / "remote" / "archive.bin").exists())
        finally:
            for writer in writers:
                writer.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
