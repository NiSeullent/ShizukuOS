# SPDX-License-Identifier: GPL-2.0-or-later
"""Exercise the actual adapted VM guard/abort AST using only host subprocesses.

This extracts the pure adaptation functions from boot.py, then extracts the
real floor/COW guards, BaseException handler and following finally block from
their generated native runner. No runner main, VM, network or guest is used.
An unrelated control subprocess must survive each induced failure. Source and
AST hashes bind the JSON receipt to the reviewed implementation.

Run: python3 -B /root/Win98-Modern-boot/shizukudos/iosys_uefi/test_runtime_stop.py
"""

import ast
import copy
import hashlib
import json
from pathlib import Path
import selectors
import subprocess
import sys
import time
import unittest

from cow_accounting import AccountingError


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
OUTPUT = ROOT / "build/shizukudos/iosys-uefi-port/runtime-stop-tests"
RESERVE_BYTES = 20 * 1024 ** 3
QUOTA_BYTES = 128 * 1024 ** 2
# A real sleeper should be killed well before the old 15-second deferred stop.
# A five-second bound also permits a loaded build host to schedule wait/reaping.
STOP_LIMIT_SECONDS = 5.0


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def guarded_harness():
    boot_path = HERE / "boot.py"
    native_path = HERE.parent / "csm/test_win98_uefi.py"
    boot_raw, native_raw = boot_path.read_bytes(), native_path.read_bytes()
    parsed = ast.parse(boot_raw, filename=str(boot_path))
    names = ("private_reflink_runner", "private_native_limits")
    functions = [node for node in parsed.body if isinstance(node, ast.FunctionDef) and node.name in names]
    if len(functions) != 2 or {node.name for node in functions} != set(names):
        raise AssertionError("the two explicit pure native adapters are required")
    # Only these byte-substitution functions execute; no boot.py imports/main.
    namespace = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(boot_path), "exec"), namespace)
    adapted = namespace["private_reflink_runner"](native_raw)
    adapted = namespace["private_native_limits"](adapted, 64, 128)
    compile(adapted, "actual-private-native-runner", "exec")
    tree = ast.parse(adapted)
    abort_tries = [node for node in ast.walk(tree) if isinstance(node, ast.Try)
                   and any(isinstance(handler.type, ast.Name) and handler.type.id == "BaseException"
                           and any(isinstance(value, ast.Constant) and value.value == "private_owned_abort"
                                   for value in ast.walk(handler)) for handler in node.handlers)]
    if len(abort_tries) != 1:
        raise AssertionError("one real monitored private abort handler is required")
    monitored = abort_tries[0]
    loops = [node for node in monitored.body if isinstance(node, ast.While)]
    if len(loops) != 1:
        raise AssertionError("the guarded monitored loop must be unique")
    floor = [node for node in loops[0].body if isinstance(node, ast.If)
             and ast.unparse(node.test) == "free < RESERVE"]
    allocation = [node for node in loops[0].body if isinstance(node, ast.If)
                  and "_iosys_cow_growth" in ast.unparse(node.test)]
    if len(floor) != 1 or len(allocation) != 1:
        raise AssertionError("actual reserve and FIEMAP guards must be present")
    # Capture the exact failure object before the real outer handler rethrows it.
    observed = ast.parse("try:\n    pass\nexcept BaseException as original:\n"
                         "    failures.append(original)\n    raise\n").body[0]
    observed.body = [copy.deepcopy(floor[0]), copy.deepcopy(allocation[0]),
                     ast.Raise(exc=ast.Name(id="fallback", ctx=ast.Load()), cause=None)]
    actual_try = ast.Try(body=[observed], handlers=copy.deepcopy(monitored.handlers),
                         orelse=[], finalbody=copy.deepcopy(monitored.finalbody))
    function = ast.parse("def invoke(child, result, failures, free, disk, fallback, monitor, run_dir, args, csm16):\n"
                         "    pass\n").body[0]
    function.body = [actual_try]
    module = ast.fix_missing_locations(ast.Module(body=[function], type_ignores=[]))
    capture_attempts = []

    def forbidden_live_diagnostic(*args, **kwargs):
        capture_attempts.append(True)
        raise AssertionError("diagnostics ran before the owned process stopped")

    environment = {"RESERVE": RESERVE_BYTES, "DIRTY_BUDGET": QUOTA_BYTES,
                   "subprocess": subprocess, "capture_failure_cpus": forbidden_live_diagnostic,
                   "capture_proxy_diagnostics": forbidden_live_diagnostic}
    exec(compile(module, "real-private-stop-handler-harness", "exec"), environment)
    receipt = {"wrapper_sha256": digest(boot_raw), "native_origin_sha256": digest(native_raw),
               "native_adapted_sha256": digest(adapted), "adapted_compile": "PASS",
               "handler_ast_sha256": digest(ast.dump(monitored.handlers[0], include_attributes=False).encode()),
               "finally_ast_sha256": digest(ast.dump(ast.Module(body=monitored.finalbody, type_ignores=[]),
                                                      include_attributes=False).encode()),
               "reserve_bytes": RESERVE_BYTES, "quota_bytes": QUOTA_BYTES,
               "selected_total_guest_input_mib": 64, "selected_max_guest_inputs": 8}
    return environment["invoke"], environment, capture_attempts, receipt


class StoppedMonitor:
    """Observe the real finally's close call without creating QMP or a socket."""

    def __init__(self, child):
        self.child = child
        self.closed_after_stop = False

    def close(self):
        if self.child.poll() is None:
            raise AssertionError("monitor closed while the owned subprocess remained alive")
        self.closed_after_stop = True


def sleeper():
    child = subprocess.Popen([sys.executable, "-B", "-u", "-c",
                              "import sys,time; print('READY', flush=True); time.sleep(60)"],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(child.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=5) or child.stdout.readline() != b"READY\n":
                raise AssertionError("owned sleeping subprocess did not become ready")
        return child
    except BaseException:
        dispose(child)
        raise


def dispose(child):
    if child.poll() is None:
        child.kill()
    child.wait(timeout=5)
    child.stdout.close()
    child.stderr.close()


class RuntimeStopChecks(unittest.TestCase):
    receipt = {"schema": "iosys-private-runtime-stop-host-test-v1", "status": "NOT-RUN",
               "vm_execution": False, "guest_execution": False, "cases": []}

    @classmethod
    def setUpClass(cls):
        invoke, environment, capture_attempts, provenance = guarded_harness()
        cls.invoke = staticmethod(invoke)
        cls.environment = environment
        cls.capture_attempts = capture_attempts
        cls.receipt.update(provenance)
        cls.control = sleeper()
        cls.receipt["unrelated_control_pid"] = cls.control.pid

    @classmethod
    def tearDownClass(cls):
        cls.receipt["control_alive_before_test_cleanup"] = cls.control.poll() is None
        dispose(cls.control)
        cls.receipt["all_test_processes_reaped"] = cls.control.poll() is not None

    def exercise(self, name, *, free=RESERVE_BYTES, growth=0, failure=None, fallback=None):
        owned = sleeper()
        self.assertNotEqual(owned.pid, self.control.pid)
        monitor = StoppedMonitor(owned)
        result, failures = {}, []
        fallback = fallback or AssertionError("fixture unexpectedly passed both resource guards")

        def observed_growth(disk, result, observed_monitor):
            self.assertIs(observed_monitor, monitor)
            if failure is not None:
                raise failure
            return growth

        self.environment["_iosys_cow_growth"] = observed_growth
        started = time.monotonic()
        try:
            try:
                self.invoke(owned, result, failures, free, object(), fallback, monitor,
                            object(), type("PrivateArguments", (), {"smp": 2, "memory": 128})(), None)
            except BaseException as actual:
                elapsed = time.monotonic() - started
                self.assertEqual(len(failures), 1)
                self.assertIs(actual, failures[0], "the stop path replaced the original failure")
                if failure is not None:
                    self.assertIs(actual, failure)
                self.assertEqual(result.get("private_owned_abort"), str(actual))
                self.assertEqual(owned.returncode, -9)
                self.assertLess(elapsed, STOP_LIMIT_SECONDS)
                self.assertIsNone(self.control.poll(), "the unrelated control subprocess was stopped")
                self.assertTrue(monitor.closed_after_stop)
                self.assertFalse(self.capture_attempts)
                self.receipt["cases"].append({"name": name, "owned_pid": owned.pid,
                                               "owned_exit_code": owned.returncode,
                                               "stop_elapsed_seconds": elapsed,
                                               "failure_type": type(actual).__name__,
                                               "failure_message": str(actual),
                                               "original_failure_identity_preserved": True,
                                               "private_owned_abort": result["private_owned_abort"],
                                               "unrelated_control_alive": self.control.poll() is None,
                                               "monitor_closed_after_stop": monitor.closed_after_stop,
                                               "live_diagnostics_attempted": False})
                return actual
            self.fail("actual resource guard/handler did not preserve the failure")
        finally:
            dispose(owned)

    def test_allocation_uncertainty_stops_only_owned_process(self):
        self.exercise("allocation-uncertainty", failure=AccountingError("FIEMAP mapping changed during observation"))

    def test_actual_reserve_floor_guard_stops_only_owned_process(self):
        actual = self.exercise("reserve-floor", free=RESERVE_BYTES - 1)
        self.assertIsInstance(actual, RuntimeError)
        self.assertIn("selected reserve floor", str(actual))

    def test_actual_selected_quota_guard_reports_128_mib(self):
        actual = self.exercise("quota-128-MiB", growth=QUOTA_BYTES + 1)
        self.assertIsInstance(actual, RuntimeError)
        self.assertIn("128 MiB", str(actual))
        self.assertNotIn("256 MiB", str(actual))

    def test_uncaught_base_exception_preserves_original_failure(self):
        actual = self.exercise("uncaught-base-exception", fallback=KeyboardInterrupt("host-only test interruption"))
        self.assertIsInstance(actual, KeyboardInterrupt)


def main():
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(RuntimeStopChecks)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    receipt = RuntimeStopChecks.receipt
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
