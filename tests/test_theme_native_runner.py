# SPDX-License-Identifier: GPL-2.0-only
"""Consumer contract/failure tests: no VM, peer edits or disk-image writes."""
import importlib.util
import contextlib
import io
import json
import os
import socket
import subprocess
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


class HostOutputBudget(unittest.TestCase):
    def setUp(self):
        self.assertTrue(hasattr(consumer, "HostOutputGuard"), "Aggregate host-output guard is missing")
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.roots = [self.base / name for name in ("stage", "consumer", "run", "bootstrap")]
        for path in self.roots:
            path.mkdir()
        self.disk = self.roots[2] / "windows-uefi.raw"

    def guard(self, limit=16):
        return consumer.HostOutputGuard(self.roots, self.disk, limit=limit)

    def test_combined_four_roots_fail_even_when_every_file_is_under_limit(self):
        for root in self.roots:
            (root / "output").write_bytes(b"12345")
        guard = self.guard()
        with self.assertRaises(consumer.HostOutputError):
            guard.check("before-launch")
        self.assertEqual(guard.to_dict()["used_bytes"], 20)
        self.assertEqual(guard.to_dict()["status"], "FAIL")

    def test_only_exact_private_cow_is_excluded_and_vars_sources_and_other_raw_count(self):
        self.disk.write_bytes(b"x" * 8192)
        (self.roots[0] / "source.py").write_bytes(b"1234")
        (self.roots[2] / "OVMF_VARS.fd").write_bytes(b"5678")
        guard = self.guard(limit=8)
        self.assertEqual(guard.check("preparation")["used_bytes"], 8)
        (self.roots[1] / "other.raw").write_bytes(b"9")
        with self.assertRaises(consumer.HostOutputError):
            guard.check("poll")
        self.assertEqual(guard.to_dict()["peak_bytes"], 9)

    def test_overshoot_remains_failed_after_output_is_deleted(self):
        guard = self.guard(limit=8)
        path = self.roots[2] / "serial.log"
        path.write_bytes(b"123456789")
        with self.assertRaises(consumer.HostOutputError):
            guard.check("poll")
        path.unlink()
        with self.assertRaises(consumer.HostOutputError):
            guard.check("final")
        self.assertEqual(guard.to_dict()["peak_bytes"], 9)

    def test_zero_byte_unix_socket_allowed_but_symlinks_always_refused(self):
        with socket.socket(socket.AF_UNIX) as ipc:
            ipc.bind(str(self.roots[2] / "qmp.sock"))
            self.assertEqual(self.guard().check("poll")["used_bytes"], 0)
        (self.roots[2] / "link").symlink_to(self.roots[0], target_is_directory=True)
        with self.assertRaises(consumer.HostOutputError):
            self.guard().check("poll")

    def test_replaced_root_cow_inode_or_cow_alias_is_refused(self):
        guard = self.guard()
        guard.check("initial")
        self.roots[0].rename(self.base / "saved-stage")
        self.roots[0].mkdir()
        with self.assertRaises(consumer.HostOutputError):
            guard.check("replaced-root")
        self.disk.write_bytes(b"cow")
        guard = self.guard()
        guard.check("initial")
        self.disk.rename(self.roots[2] / "saved-cow")
        self.disk.write_bytes(b"cow")
        with self.assertRaises(consumer.HostOutputError):
            guard.check("replaced-cow")
        os.link(self.disk, self.roots[2] / "alias")
        with self.assertRaises(consumer.HostOutputError):
            self.guard().check("aliased-cow")

    def test_unsafe_overlapping_scopes_wrong_exclusion_or_relaxed_limit_refused(self):
        for roots, disk, limit in [([Path("relative")], self.disk, 16),
                                   ([self.roots[0], self.roots[0]], self.disk, 16),
                                   ([self.base, self.roots[2]], self.disk, 16),
                                   (self.roots, self.base / "peer.raw", 16),
                                   (self.roots, self.disk, 16 * 1024**2 + 1)]:
            with self.subTest(roots=roots, limit=limit), self.assertRaises(consumer.ConsumerError):
                consumer.HostOutputGuard(roots, disk, limit=limit)

    def configured(self, guard):
        private = self.roots[1] / "runner.py"
        private.write_bytes(b"# private\n")
        cow_path = self.roots[1] / "cow.py"
        cow_path.write_bytes(b"# cow\n")
        qemu = SimpleNamespace(launch=Mock(side_effect=AssertionError("VM must not launch")))
        self.original_launch = qemu.launch
        shzlib = SimpleNamespace(write_json=lambda path, data: Path(path).write_text(__import__('json').dumps(data)))
        self.shzlib = shzlib
        runner = SimpleNamespace(reuse_prepared=Mock(), DIRTY_BUDGET=256 * 1024**2, RESERVE=20 * 1024**3,
                                 capture=lambda *a, **k: (self.roots[2] / "capture").write_bytes(b"x" * 64),
                                 collect_guest_files=lambda *a, **k: (self.roots[2] / "readback").write_bytes(b"x" * 64))
        cow = SimpleNamespace(__file__=str(cow_path))
        modules = {"qemu": qemu, "shzlib": shzlib, "theme_native_pinned_runner": runner, "theme_native_pinned_cow": cow}
        with patch.object(consumer, "load_module", side_effect=lambda name, path: modules[name]):
            configured, _, state = consumer.configure_runner(private, cow_path, {}, self.base,
                                                              host_guard=guard)
        return configured, qemu, state

    def test_runtime_capture_and_readback_enforce_combined_budget(self):
        for operation in ("capture", "collect_guest_files"):
            with self.subTest(operation=operation):
                guard = self.guard(limit=32)
                runner, _, _ = self.configured(guard)
                with self.assertRaises(consumer.HostOutputError):
                    getattr(runner, operation)()
                self.assertGreater(guard.to_dict()["peak_bytes"], 32)
                for name in ("capture", "readback"):
                    (self.roots[2] / name).unlink(missing_ok=True)

    def test_prelaunch_and_resource_poll_reject_growth_without_launching_vm(self):
        guard = self.guard(limit=32)
        runner, qemu, _ = self.configured(guard)
        (self.roots[2] / "serial.log").write_bytes(b"x" * 64)
        with self.assertRaises(consumer.HostOutputError):
            qemu.launch([], self.roots[2])
        with self.assertRaises(consumer.HostOutputError):
            runner._iosys_cow_growth(self.disk, {}, object())

    def test_final_native_result_is_fail_when_result_write_itself_exceeds_cap(self):
        guard = self.guard(limit=32)
        self.configured(guard)
        result = self.roots[2] / "result.json"
        with self.assertRaises(consumer.HostOutputError):
            self.shzlib.write_json(result, {"profile": "actual-win98-uefi-csmwrap", "status": "PASS"})
        data = json.loads(result.read_text())
        self.assertEqual(data["status"], "FAIL")
        self.assertEqual(data["host_output_budget"]["status"], "FAIL")
        self.assertGreater(data["host_output_budget"]["peak_bytes"], 32)
        self.assertIn("Resource host-output FAIL", data["resource_failure"])

    def test_other_json_payload_schema_is_preserved_and_still_guarded(self):
        guard = self.guard(limit=32)
        self.configured(guard)
        target = self.roots[2] / "other.json"
        value = ["ok"]
        self.shzlib.write_json(target, value)
        self.assertEqual(json.loads(target.read_text()), value)
        with self.assertRaises(consumer.HostOutputError):
            self.shzlib.write_json(target, ["x" * 64])

    def test_source_freeze_overshoot_records_resource_fail_before_vm_or_lock(self):
        roots = self.roots
        roots[1].rmdir()
        guard = self.guard(limit=32)
        def freeze(*args, **kwargs):
            roots[1].mkdir()
            private = roots[1] / "runner.py"
            private.write_bytes(b"x" * 64)
            return {}, private, {}
        argv = ["--peer-root", str(self.base), "--consumer-dir", str(roots[1])]
        for name in ("canonical", "adapter", "cow"):
            argv += ["--" + name + "-sha256", "a" * 64]
        argv += ["--", *arguments()]
        with patch.object(consumer, "validate_paths", return_value=(self.base, roots[1], roots[2])), \
                patch.object(consumer, "freeze_sources", side_effect=freeze), \
                patch.object(consumer, "acquire_native_lock") as lock, contextlib.redirect_stdout(io.StringIO()):
            code = consumer.main(argv, host_guard=guard)
        self.assertEqual(code, 1)
        lock.assert_not_called()
        data = json.loads((roots[1] / "consumer-result.json").read_text())
        self.assertEqual(data["status"], "FAIL")
        self.assertFalse(data["vm_started"])
        self.assertGreater(data["host_output_budget"]["peak_bytes"], 32)

    def test_guard_for_other_arguments_cannot_hide_actual_consumer_output(self):
        argv = ["--peer-root", str(self.base), "--consumer-dir", str(self.roots[1])]
        for name in ("canonical", "adapter", "cow"):
            argv += ["--" + name + "-sha256", "a" * 64]
        argv += ["--", *arguments()]
        with patch.object(consumer, "validate_paths", return_value=(self.base, self.base / "unwatched", self.roots[2])), \
                patch.object(consumer, "freeze_sources") as freeze, \
                self.assertRaisesRegex(consumer.ConsumerError, "does not cover"):
            consumer.main(argv, host_guard=self.guard())
        freeze.assert_not_called()

    def test_postlaunch_overshoot_stops_only_returned_owned_child_handle(self):
        self.disk.write_bytes(b"cow")
        guard = self.guard(limit=32)
        _, qemu, state = self.configured(guard)
        child = SimpleNamespace(poll=Mock(return_value=None), kill=Mock(), wait=Mock())
        def fake_launch(*args, **kwargs):
            (self.roots[2] / "qemu.stderr").write_bytes(b"x" * 64)
            return child
        self.original_launch.side_effect = fake_launch
        with self.assertRaises(consumer.HostOutputError):
            qemu.launch([], self.roots[2])
        self.assertIs(state["child"], child)
        child.kill.assert_called_once_with()
        child.wait.assert_called_once_with(timeout=5)

    def test_success_receipt_includes_its_own_final_bytes_in_measured_peak(self):
        guard = self.guard(limit=4096)
        self.configured(guard)
        path = self.roots[2] / "result.json"
        self.shzlib.write_json(path, {"profile": "actual-win98-uefi-csmwrap", "status": "PASS"})
        record = json.loads(path.read_text())
        actual = sum(p.stat().st_size for root in self.roots for p in root.rglob("*") if p.is_file() and p != self.disk)
        self.assertEqual(record["host_output_budget"]["used_bytes"], actual)
        self.assertEqual(record["host_output_budget"]["peak_bytes"], actual)

    def test_failure_receipt_does_not_follow_refused_symlink(self):
        guard = self.guard(limit=4096)
        self.configured(guard)
        original = self.base / "peer-result.json"
        original.write_bytes(b"unchanged peer")
        path = self.roots[2] / "result.json"
        path.symlink_to(original)
        with self.assertRaises(consumer.ConsumerError):
            self.shzlib.write_json(path, {"profile": "actual-win98-uefi-csmwrap", "status": "PASS"})
        self.assertEqual(original.read_bytes(), b"unchanged peer")

    def test_failure_receipt_does_not_write_to_replaced_root(self):
        guard = self.guard(limit=4096)
        self.configured(guard)
        guard.check("before-root-change")
        self.roots[2].rename(self.base / "original-run")
        self.roots[2].mkdir()
        path = self.roots[2] / "result.json"
        with self.assertRaises(consumer.ConsumerError):
            self.shzlib.write_json(path, {"profile": "actual-win98-uefi-csmwrap", "status": "PASS"})
        self.assertFalse(path.exists())

    def test_fifo_receipt_is_refused_without_blocking_failure_reporting(self):
        os.mkfifo(self.roots[2] / "result.json")
        code = """import importlib.util,json,pathlib,sys
spec=importlib.util.spec_from_file_location('fifo_guard',sys.argv[1])
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
roots=[pathlib.Path(p) for p in json.loads(sys.argv[2])]
guard=module.HostOutputGuard(roots,roots[2]/'windows-uefi.raw',limit=4096)
try: guard.write_receipt(roots[2]/'result.json',{'status':'PASS'},'fifo-test')
except module.ConsumerError: sys.exit(0)
sys.exit(3)
"""
        completed = subprocess.run([sys.executable, "-B", "-c", code, str(PATH),
                                    json.dumps([str(p) for p in self.roots])], capture_output=True, timeout=2)
        self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors="replace"))


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


class NativeLock(unittest.TestCase):
    def test_busy_lane_times_out_without_touching_the_owner(self):
        # Separate opens of one file exercise actual flock ownership.
        with tempfile.NamedTemporaryFile() as file, open(file.name, 'rb') as contender:
            consumer.fcntl.flock(file, consumer.fcntl.LOCK_EX | consumer.fcntl.LOCK_NB)
            with self.assertRaisesRegex(consumer.ConsumerError, 'remained busy'):
                consumer.acquire_native_lock(contender, 0)
            consumer.fcntl.flock(file, consumer.fcntl.LOCK_UN)
            consumer.acquire_native_lock(contender, 0)

    def test_released_lane_can_be_acquired_after_bounded_wait(self):
        calls = Mock(side_effect=[BlockingIOError(), None])
        with patch.object(consumer.fcntl, 'flock', calls), patch.object(consumer.time, 'sleep') as sleep:
            consumer.acquire_native_lock(Mock(), 1)
        self.assertEqual(calls.call_count, 2)
        sleep.assert_called_once()
        self.assertLessEqual(sleep.call_args.args[0], 0.2)

    def test_invalid_wait_bound_fails_before_lock_access(self):
        with patch.object(consumer.fcntl, 'flock') as lock:
            for bound in (-1, 1201):
                with self.assertRaises(consumer.ConsumerError):
                    consumer.acquire_native_lock(Mock(), bound)
        lock.assert_not_called()


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
