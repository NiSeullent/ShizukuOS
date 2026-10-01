# SPDX-License-Identifier: GPL-2.0-only
"""Consumer contract/failure tests: no VM, peer edits or disk-image writes."""
import importlib.util
import contextlib
import io
import sys
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

PATH = Path(__file__).resolve().parents[1] / "tools/theme_native_runner.py"
SPEC = importlib.util.spec_from_file_location("theme_consumer_test_module", PATH)
consumer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(consumer)

ADAPTER = b'''raise RuntimeError("top-level IO.SYS activation must not execute")
def private_reflink_runner(source):
    if source.count(b"COPY_NEVER") != 1:
        raise ValueError("Native copy contract changed")
    return source.replace(b"COPY_NEVER", b"COPY_ALWAYS")
def quiescent_cow_observation(*args):
    return ("observation", 12, 0.25)
'''


def arguments():
    result = []
    for name in ("archive", "checkpoint-record", "qemu", "firmware-code", "firmware-vars",
                 "resume-owned-run", "csm-dir", "guest-files-manifest"):
        result += ["--" + name, "/synthetic/" + name]
    return result + ["--guest-files-manifest-sha", "a" * 64, "--run-name", "win98-gop-theme-6970-test",
                     "--manual-gui", "--firmware-gop", "--replace-csmwrap"]


class NativeArguments(unittest.TestCase):
    def test_consumer_defaults_are_forwarded_to_different_canonical_defaults(self):
        parsed, forwarded = consumer.native_arguments(arguments())
        for name, expected in (("reserve-gib", "20"), ("timeout", "900"),
                               ("capture-interval", "5"), ("manual-purpose", "diagnostic")):
            self.assertEqual(forwarded[forwarded.index("--" + name) + 1], expected)
        self.assertEqual(parsed.reserve_gib, 20)

    def test_floor_below_twenty_is_rejected(self):
        with self.assertRaises(consumer.ConsumerError):
            consumer.native_arguments(arguments() + ["--reserve-gib", "19"])

    def test_ambiguous_repeated_reserve_is_rejected_even_when_both_safe(self):
        with self.assertRaises(consumer.ConsumerError):
            consumer.native_arguments(arguments() + ["--reserve-gib=20", "--reserve-gib", "21"])

    def test_other_staging_and_native_bios_options_are_rejected(self):
        for extra in (("--application-manifest", "/elsewhere"), ("--native-bios-control",), ("--prepared-run", "/other")):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                consumer.native_arguments(arguments() + list(extra))

    def test_other_sessions_name_and_path_traversal_are_rejected(self):
        for name in ("win98-gop-tls-7707-test", "win98-gop-theme-6970-../peer"):
            argv = arguments()
            argv[argv.index("--run-name") + 1] = name
            with self.subTest(name=name), self.assertRaises(consumer.ConsumerError):
                consumer.native_arguments(argv)

    def test_timeout_and_machine_stay_bounded(self):
        with self.assertRaises(consumer.ConsumerError):
            consumer.native_arguments(arguments() + ["--timeout", "901"])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            consumer.native_arguments(arguments() + ["--accel", "tcg"])


class FrozenSources(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.peer, self.frozen = self.root / "peer", self.root / "frozen"
        sources = {name: b"# source\n" for name in consumer.SOURCE_FILES}
        sources.update(adapter=ADAPTER, canonical=b"COPY_NEVER = True\n")
        for name, data in sources.items():
            path = self.peer / consumer.SOURCE_FILES[name]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
        self.pins = {name: consumer.digest(sources[name]) for name in ("canonical", "adapter", "cow")}

    def test_freezing_does_not_execute_adapter_main_and_preserves_source_lineage(self):
        frozen, private, functions = consumer.freeze_sources(self.peer, self.frozen, self.pins)
        self.assertEqual(private.read_bytes(), b"COPY_ALWAYS = True\n")
        for name, value in frozen.items():
            self.assertEqual(consumer.digest(Path(value["frozen"]).read_bytes()), value["sha256"])
            self.assertEqual(Path(value["origin"]).read_bytes(), Path(value["frozen"]).read_bytes())
        self.assertEqual(functions["quiescent_cow_observation"](), ("observation", 12, 0.25))

    def test_wrong_pin_fails_before_any_consumer_directory_is_created(self):
        pins = dict(self.pins, cow="0" * 64)
        with self.assertRaises(consumer.ConsumerError):
            consumer.freeze_sources(self.peer, self.frozen, pins)
        self.assertFalse(self.frozen.exists())

    def test_missing_copy_anchor_fails_before_freezing(self):
        canonical = self.peer / consumer.SOURCE_FILES["canonical"]
        canonical.write_bytes(b"COPY_CHANGED = True\n")
        pins = dict(self.pins, canonical=consumer.digest(canonical.read_bytes()))
        with self.assertRaises(ValueError):
            consumer.freeze_sources(self.peer, self.frozen, pins)
        self.assertFalse(self.frozen.exists())

    def test_duplicate_reviewed_function_is_rejected_without_top_level_activation(self):
        with self.assertRaises(consumer.ConsumerError):
            consumer.reviewed_functions(ADAPTER + b"\ndef private_reflink_runner(source): return source\n")

    def test_symlink_ancestor_and_relative_paths_are_rejected(self):
        real = self.root / "real"
        real.mkdir()
        link = self.root / "link"
        link.symlink_to(real, target_is_directory=True)
        with self.assertRaises(consumer.ConsumerError):
            consumer.safe_path(link / "new", existing=False)
        with self.assertRaises(consumer.ConsumerError):
            consumer.safe_path(Path("relative"), existing=False)
        with self.assertRaises(consumer.ConsumerError):
            consumer.safe_path(self.root / "disk.raw,readonly=off", existing=False)

    def test_source_that_is_open_is_refused_and_closed_source_is_accepted(self):
        path = self.root / "retained.raw"
        path.write_bytes(b"retained")
        with path.open("rb"), self.assertRaises(consumer.ConsumerError):
            consumer.ensure_unopened(path)
        consumer.ensure_unopened(path)

    def test_runtime_receipt_distinguishes_cow_and_frozen_private_source(self):
        names = ("qemu", "shzlib", "theme_native_pinned_runner", "theme_native_pinned_cow")
        previous_modules = {name: sys.modules.get(name) for name in names}
        previous_path = list(sys.path)

        def restore_imports():
            sys.path[:] = previous_path
            for name, previous in previous_modules.items():
                if previous is None:
                    sys.modules.pop(name, None)
                else:
                    sys.modules[name] = previous

        self.addCleanup(restore_imports)
        files = {
            "canonical": b'''from pathlib import Path
import qemu, shzlib
BUILD = shzlib.BUILD
COPY_NEVER = True
RESERVE = 20 * 1024 ** 3
DIRTY_BUDGET = 256 * 1024 ** 2
def reuse_prepared(*args, **kwargs): return {}, {}
''',
            "qemu": b"def launch(*args, **kwargs): raise AssertionError('VM must not launch')\n",
            "shzlib": b"BUILD = None\ndef write_json(path, data): return data\n",
        }
        for name, data in files.items():
            (self.peer / consumer.SOURCE_FILES[name]).write_bytes(data)
        pins = dict(self.pins, canonical=consumer.digest(files["canonical"]))
        frozen, private, functions = consumer.freeze_sources(self.peer, self.frozen, pins)
        runner, cow, state = consumer.configure_runner(private, Path(frozen["cow"]["frozen"]), functions, self.peer)
        data = {"profile": "actual-win98-uefi-csmwrap", "sparse_budget": {"policy": "old sparse policy"}}
        receipt = runner.shzlib.write_json(Path("/synthetic/result.json"), data)
        self.assertEqual(receipt["private_cow_consumer"]["copy_mode"], "cp --reflink=always --sparse=auto")
        self.assertEqual(receipt["private_cow_consumer"]["private_runner_sha256"], consumer.digest(private.read_bytes()))
        self.assertIn("FIEMAP", receipt["sparse_budget"]["policy"])
        self.assertFalse(receipt["private_cow_consumer"]["io_sys_entry_adapter_executed"])
        self.assertEqual(state, {})


class StoppedAllocation(unittest.TestCase):
    def setUp(self):
        self.disk = Mock(spec=Path)
        self.disk.exists.return_value = True
        self.disk.parent = Path("/synthetic/owned-run")
        self.runner = SimpleNamespace(DIRTY_BUDGET=256 * 1024 ** 2, RESERVE=20 * 1024 ** 3)
        self.observation = SimpleNamespace(to_dict=lambda: {"stable_scans": 2})
        self.cow = Mock()
        self.cow.observe_allocations.return_value = self.observation
        self.cow.net_exclusive_growth_bytes.return_value = 12
        self.child = Mock()
        self.child.poll.return_value = 0
        self.state = {"child": self.child, "baseline": "baseline"}

    def test_active_owned_writer_is_killed_and_receipt_is_rejected(self):
        self.child.poll.return_value = None
        with self.assertRaises(consumer.ConsumerError):
            consumer.stopped_observation(self.runner, self.cow, self.state, self.disk)
        self.child.kill.assert_called_once_with()
        self.child.wait.assert_called_once_with(timeout=5)
        self.cow.observe_allocations.assert_not_called()

    def test_final_space_floor_failure_is_never_accepted(self):
        with patch.object(consumer.shutil, "disk_usage", return_value=SimpleNamespace(free=self.runner.RESERVE - 1)):
            result = consumer.stopped_observation(self.runner, self.cow, self.state, self.disk)
        self.assertEqual(result["status"], "FAIL")
        self.child.kill.assert_not_called()

    def test_final_quota_failure_is_never_accepted(self):
        self.cow.net_exclusive_growth_bytes.return_value = self.runner.DIRTY_BUDGET + 1
        with patch.object(consumer.shutil, "disk_usage", return_value=SimpleNamespace(free=self.runner.RESERVE)):
            result = consumer.stopped_observation(self.runner, self.cow, self.state, self.disk)
        self.assertEqual(result["status"], "FAIL")

    def test_missing_baseline_is_absent_not_a_zero_growth_success(self):
        self.assertIsNone(consumer.stopped_observation(self.runner, self.cow, {}, self.disk))
        self.cow.observe_allocations.assert_not_called()

    def test_fiemap_failure_is_propagated_without_fallback(self):
        self.cow.observe_allocations.side_effect = RuntimeError("unstable FIEMAP")
        with self.assertRaisesRegex(RuntimeError, "unstable FIEMAP"):
            consumer.stopped_observation(self.runner, self.cow, self.state, self.disk)


if __name__ == "__main__":
    unittest.main()
