# SPDX-License-Identifier: GPL-2.0-or-later
"""Fault-path tests of the actual quiescent COW function, without a VM.

The function AST comes directly from boot.py. A deterministic QMP state model,
clock and free-space provider expose ordering and failure behavior. The actual
COW helper's identity check is used. No runner main, filesystem writes to disk
images, real monitor socket, guest, network or VM is used.

Run: python3 -B /root/Win98-Modern-boot/shizukudos/iosys_uefi/test_quiescent_cow.py
"""

import ast
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace
import unittest

import cow_accounting as real_cow


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUTPUT = ROOT / "build/shizukudos/iosys-uefi-port/quiescent-cow-tests"
RESERVE = 20 * 1024 ** 3
QUOTA = 128 * 1024 ** 2
DISK = Path("/synthetic-private-run/windows-uefi.raw")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def baseline_observation():
    return real_cow.AllocationObservation(
        schema="xfs-fiemap-exclusive-data-v1", path=str(DISK), observed_ns=1,
        filesystem="xfs", device=123, inode=456, file_bytes=2 * 1024 ** 3,
        block_bytes=4096, mapped_bytes=512 * 1024 ** 2, exclusive_bytes=4096,
        shared_bytes=512 * 1024 ** 2 - 4096, unwritten_bytes=0,
        extent_count=3, extents_sha256="1" * 64, ioctl_calls=2, stable_scans=2,
        helper_sha256=digest(Path(real_cow.__file__).read_bytes()))


class MonitorModel:
    def __init__(self, events, *, before=None, paused=None, resumed=None,
                 fault_at=None, fault=None):
        self.events = events
        self.before = before if before is not None else {"running": True, "status": "running"}
        self.paused = paused if paused is not None else {"running": False, "status": "paused"}
        self.resumed = resumed if resumed is not None else {"running": True, "status": "running"}
        self.fault_at, self.fault = fault_at, fault
        self.query_count = 0
        self.status = dict(self.before)
        self.commands = []

    def call(self, command):
        self.events.append(command)
        self.commands.append(command)
        key = command
        if command == "query-status":
            self.query_count += 1
            key += ":" + str(self.query_count)
        if key == self.fault_at:
            raise self.fault
        if command == "stop":
            self.status = dict(self.paused)
            return {}
        if command == "cont":
            self.status = dict(self.resumed)
            return {}
        if command == "query-status":
            return dict(self.status)
        raise AssertionError("the quiescent guard issued an unexpected command")


class QuiescentCowChecks(unittest.TestCase):
    receipt = {"schema": "iosys-quiescent-cow-host-fault-tests-v1", "status": "NOT-RUN",
               "vm_execution": False, "guest_execution": False, "cases": []}

    @classmethod
    def setUpClass(cls):
        path = HERE / "boot.py"
        source = path.read_bytes()
        parsed = ast.parse(source)
        functions = [node for node in parsed.body if isinstance(node, ast.FunctionDef)
                     and node.name == "quiescent_cow_observation"]
        if len(functions) != 1:
            raise AssertionError("one actual top-level quiescent COW function is required")
        cls.program = compile(ast.Module(body=functions, type_ignores=[]), str(path), "exec")
        cls.receipt.update({"wrapper_sha256": digest(source),
                            "function_ast_sha256": digest(ast.dump(functions[0], include_attributes=False).encode()),
                            "cow_helper_sha256": digest(Path(real_cow.__file__).read_bytes()),
                            "reserve_bytes": RESERVE, "quota_bytes": QUOTA})

    def scenario(self, name, *, growth=0, free=RESERVE, ticks=(0.0, 0.2, 0.3),
                 observation_error=None, space_error=None, different_identity=False,
                 different_helper=False, **monitor_options):
        events = []
        monitor = MonitorModel(events, **monitor_options)
        baseline = baseline_observation()
        observation = replace(baseline, observed_ns=2,
                              exclusive_bytes=baseline.exclusive_bytes + growth,
                              shared_bytes=baseline.shared_bytes - growth)
        if different_identity:
            observation = replace(observation, inode=baseline.inode + 1)
        if different_helper:
            observation = replace(observation, helper_sha256="0" * 64)
        tick_iterator = iter(ticks)

        def clock():
            events.append("clock")
            return next(tick_iterator)

        def observe(disk):
            events.append("observe")
            self.assertEqual(disk, DISK)
            self.assertEqual(monitor.status, {"running": False, "status": "paused"})
            if observation_error is not None:
                raise observation_error
            return observation

        def identity(before, after):
            events.append("identity")
            self.assertIs(before, baseline)
            self.assertIs(after, observation)
            return real_cow.net_exclusive_growth_bytes(before, after)

        def disk_usage(parent):
            events.append("disk-free")
            self.assertEqual(parent, DISK.parent)
            if space_error is not None:
                raise space_error
            return SimpleNamespace(free=free)

        environment = {"time": SimpleNamespace(monotonic=clock),
                       "shutil": SimpleNamespace(disk_usage=disk_usage)}
        exec(self.program, environment)
        cow = SimpleNamespace(observe_allocations=observe, net_exclusive_growth_bytes=identity)
        try:
            outcome = environment["quiescent_cow_observation"](DISK, monitor, cow, baseline, QUOTA, RESERVE)
            error = None
        except BaseException as caught:
            outcome, error = None, caught
        self.receipt["cases"].append({"name": name, "events": list(events),
                                       "monitor_commands": list(monitor.commands),
                                       "final_state": dict(monitor.status),
                                       "error_type": type(error).__name__ if error is not None else None,
                                       "error_message": str(error) if error is not None else None,
                                       "resumption_attempted": "cont" in monitor.commands})
        return SimpleNamespace(events=events, monitor=monitor, outcome=outcome,
                               error=error, observation=observation)

    def assert_not_resumed(self, result, *, paused=True):
        self.assertIsNotNone(result.error)
        self.assertNotIn("cont", result.monitor.commands)
        self.assertIsNone(result.outcome)
        if paused:
            self.assertEqual(result.monitor.status, {"running": False, "status": "paused"})

    def test_success_stops_observes_validates_then_resumes_in_order(self):
        result = self.scenario("success", growth=4096)
        self.assertIsNone(result.error)
        self.assertIs(result.outcome[0], result.observation)
        self.assertEqual(result.outcome[1:], (4096, 0.3))
        self.assertEqual(result.events, ["clock", "query-status", "stop", "query-status",
                                         "observe", "identity", "disk-free", "clock",
                                         "cont", "query-status", "clock"])
        self.assertEqual(result.monitor.status, {"running": True, "status": "running"})

    def test_already_paused_or_inconsistent_initial_states_are_rejected(self):
        states = [{"running": False, "status": "paused"},
                  {"running": True, "status": "paused"},
                  {"running": False, "status": "running"}]
        for state in states:
            with self.subTest(state=state):
                result = self.scenario("unsafe-initial-" + str(state), before=state)
                self.assert_not_resumed(result, paused=False)
                self.assertNotIn("stop", result.monitor.commands)
                self.assertNotIn("observe", result.events)

    def test_failed_pause_state_never_observes_or_resumes(self):
        result = self.scenario("pause-not-confirmed", paused={"running": True, "status": "running"})
        self.assert_not_resumed(result, paused=False)
        self.assertNotIn("observe", result.events)

    def test_allocation_uncertainty_preserves_the_same_exception_and_stays_paused(self):
        expected = real_cow.AccountingError("FIEMAP physical mapping is ambiguous")
        result = self.scenario("ambiguous-allocation", observation_error=expected)
        self.assert_not_resumed(result)
        self.assertIs(result.error, expected)
        self.assertNotIn("identity", result.events)

    def test_wrong_inode_or_helper_identity_never_resumes(self):
        for argument in ("different_identity", "different_helper"):
            with self.subTest(argument=argument):
                result = self.scenario(argument, **{argument: True})
                self.assert_not_resumed(result)
                self.assertIsInstance(result.error, real_cow.AccountingError)

    def test_over_budget_never_resumes_and_reports_the_selected_quota(self):
        result = self.scenario("over-128-MiB", growth=QUOTA + 1)
        self.assert_not_resumed(result)
        self.assertIn("128 MiB", str(result.error))
        self.assertNotIn("disk-free", result.events)

    def test_free_floor_is_rechecked_after_observation_without_resuming(self):
        result = self.scenario("floor-after-stop", free=RESERVE - 1)
        self.assert_not_resumed(result)
        self.assertLess(result.events.index("observe"), result.events.index("disk-free"))
        self.assertIn("reserve floor", str(result.error))

    def test_over_five_second_measurement_never_resumes(self):
        result = self.scenario("five-second-expired", ticks=(0.0, 5.0001))
        self.assert_not_resumed(result)
        self.assertIn("five-second", str(result.error))

    def test_exact_quota_and_five_second_boundary_are_accepted(self):
        result = self.scenario("exact-boundaries", growth=QUOTA, free=RESERVE,
                               ticks=(0.0, 5.0, 5.0))
        self.assertIsNone(result.error)
        self.assertEqual(result.outcome[1:], (QUOTA, 5.0))

    def test_original_monitor_and_free_space_faults_are_not_masked(self):
        for point in ("query-status:1", "stop", "query-status:2"):
            with self.subTest(point=point):
                expected = ConnectionError("owned monitor fault at " + point)
                result = self.scenario(point, fault_at=point, fault=expected)
                self.assert_not_resumed(result, paused=point == "query-status:2")
                self.assertIs(result.error, expected)
        expected = OSError("free-space provider failed")
        result = self.scenario("space-provider-fault", space_error=expected)
        self.assert_not_resumed(result)
        self.assertIs(result.error, expected)

    def test_post_cont_status_failure_is_rejected_without_claiming_success(self):
        result = self.scenario("resume-not-confirmed", resumed={"running": False, "status": "paused"})
        self.assertIsNone(result.outcome)
        self.assertIsInstance(result.error, RuntimeError)
        self.assertEqual(result.monitor.commands.count("cont"), 1)
        self.assertIn("did not resume", str(result.error))


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(QuiescentCowChecks)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    receipt = QuiescentCowChecks.receipt
    receipt.update({"status": "PASS" if result.wasSuccessful() and not result.skipped else "FAIL",
                    "tests_run": result.testsRun, "failures": len(result.failures),
                    "errors": len(result.errors), "skipped": len(result.skipped),
                    "observed_ns": time.time_ns(), "test_source_sha256": digest(Path(__file__).read_bytes())})
    OUTPUT.mkdir(parents=True, exist_ok=True)
    target = OUTPUT / f"receipt-{time.time_ns()}.json"
    target.write_text(json.dumps(receipt, sort_keys=True, indent=2) + "\n")
    print(target)
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
