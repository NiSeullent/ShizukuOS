# SPDX-License-Identifier: GPL-2.0-only
"""Explicit hosted stale stop-schedule controls; importing runs no control.

The existing pidfd helper prepares one pinned raw-syscall ELF.  This separate
driver adds two closed child Guard epochs and no parent preparation command.
The positive scheduling gap waits on actual numeric process absence before
the first leader STOP.  REAP_OK is verified in the final physical capture;
the hook does not drain, peek at, or claim to have read the subprocess pipe.
The negative case omits one real child from one observation boundary only.
Production's dedicated numeric process read, counters and signals stay real.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import stat
import time
import types

CONTROL_NAMES = ("positive-stale-order-reaped-child", "negative-stale-order-live-omission")
CONTROL_EXPECTATIONS = {
    CONTROL_NAMES[0]: {"child_epoch": "PASS_CONTROL_CHILD", "command_count": 1,
                       "injected_fault": False, "stop_request_expected": True,
                       "reason": None},
    CONTROL_NAMES[1]: {"child_epoch": "FAIL", "command_count": 1,
                       "injected_fault": True, "stop_request_expected": True,
                       "reason": "owned stale stop candidate remains present"},
}
FIXTURE_BYTES_LIMIT = 8 * 1024**2
CASE_SECONDS = 5.0
TOTAL_SECONDS = 60.0
PAYLOAD_LIMIT = 4096
SOURCE_BYTES_LIMIT = 8192
OBJECT_BYTES_LIMIT = 2 * 1024**2
MAP_BYTES_LIMIT = 256 * 1024
SOURCE_PIN_LIMIT = 200 * 1024
TOOL_PIN_LIMIT = 256 * 1024**2
CASE_SCHEMA = "native-tls-stale-order-control-child-6970-v1"
REPORT_SCHEMA = "native-tls-stale-order-controls-6970-v1"
TOKEN_KEYS = ("pid", "startticks", "pgrp", "session", "uid")
ROW_KEYS = ("pid", "ppid", "state", "pgrp", "session", "startticks", "uid")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _canonical(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    _require(len(raw) <= 16384, "stale-order numeric observation diagnostic bound")
    return raw


def _small_read(path, maximum, resources):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 <= before.st_size <= maximum, "bounded regular stale-order proof read required")
        raw = bytearray()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            raw.extend(block)
            _require(len(raw) <= maximum, "stale-order proof grew beyond bound")
        _require(len(raw) == before.st_size
                 and resources.identity(os.fstat(fd)) == resources.identity(before)
                 and resources.identity(Path(path).lstat()) == resources.identity(before),
                 "stale-order proof held/named identity changed during read")
        return bytes(raw)
    finally:
        os.close(fd)


def _proof_pin(guard, path, maximum):
    return {"path": str(path), "relative_path": str(path.relative_to(guard.output)),
            **guard.pin(path, maximum=maximum)}


def _token(row):
    return tuple(row[key] for key in TOKEN_KEYS)


def _stopped(snapshot):
    return (isinstance(snapshot, dict) and bool(snapshot.get("members"))
            and bool(snapshot.get("tasks"))
            and all(row.get("state") in ("T", "Z") for row in snapshot["members"])
            and all(row.get("state") in ("T", "Z") for row in snapshot["tasks"]))


def _readiness(snapshot, leader_pid):
    """Require the actual stable single-thread fork parent and its live child."""
    if (not isinstance(snapshot, dict) or snapshot.get("stable") is not True
            or not isinstance(snapshot.get("leader"), dict)
            or snapshot["leader"].get("pid") != leader_pid
            or not isinstance(snapshot.get("members"), list)
            or not isinstance(snapshot.get("tasks"), list)
            or len(snapshot["members"]) != 2 or len(snapshot["tasks"]) != 2):
        return None
    members, tasks = snapshot["members"], snapshot["tasks"]
    by_pid = {row.get("pid"): row for row in members}
    if len(by_pid) != 2 or leader_pid not in by_pid or snapshot["leader"] != by_pid[leader_pid]:
        return None
    if any(row.get("state") not in ("S", "R") or row.get("pgrp") != leader_pid
           or row.get("session") != leader_pid or row.get("uid") != os.getuid()
           or not isinstance(row.get("ppid"), int) or isinstance(row.get("ppid"), bool)
           for row in members):
        return None
    if any(row.get("pid") != row.get("tid") or row.get("pid") not in by_pid
           or any(row.get(key) != by_pid[row["pid"]].get(key) for key in ROW_KEYS)
           for row in tasks):
        return None
    children = [row for row in members if row["pid"] != leader_pid and row["ppid"] == leader_pid]
    if len(children) != 1:
        return None
    return {"leader_pid": leader_pid, "child_pid": children[0]["pid"],
            "leader_row": dict(by_pid[leader_pid]), "child_row": dict(children[0])}


class _Monitor:
    """Observe real process transitions; inject only the declared omission."""
    def __init__(self, guard, resources, index):
        self.guard, self.resources, self.index = guard, resources, index
        self.original_observer = guard._group_observer
        self.original_member_signal = resources._OwnedGroupObservation._signal_member
        self.original_confirm = resources._OwnedGroupObservation._confirm_absent_schedule_member
        self.original_send = resources.signal.pidfd_send_signal
        self.original_killpg = resources.os.killpg
        self.ready = None
        self.gap_done = False
        self.metrics = {"scans": 0, "paused_scans": 0, "readiness_wait_seconds": 0.0,
                        "readiness_snapshot": None, "readiness_sha256": None,
                        "observed_fork_ppid_ready": False, "ready_before_any_stop": False,
                        "stop_requests": 0, "stale_child_stop_requests": 0,
                        "wrong_target_stop_requests": 0, "all_zombie_group_stop_requests": 0,
                        "early_continue_requests": 0, "injected_fault_count": 0,
                        "scheduling_gap_exercised": False, "gap_wait_seconds": 0.0,
                        "gap_child_absence_observed": False, "gap_absence_exception_class": None,
                        "gap_absence_errno": None, "gap_surviving_leader_row": None,
                        "gap_marker_observed_before_stop": False,
                        "reap_marker_verified_in_final_physical_capture": False,
                        "omitted_child_pid": None, "omission_actual_snapshot": None,
                        "omission_actual_snapshot_sha256": None,
                        "omission_returned_snapshot": None,
                        "omission_returned_snapshot_sha256": None,
                        "reconciliation_calls": 0, "reconciliation_inputs": [],
                        "signal_samples": [], "signal_samples_truncated": False,
                        "dedicated_numeric_process_read_modified": False,
                        "resource_counter_or_signal_result_modified": False,
                        "schedule_gap_is_not_production_exit_cause_attestation": True,
                        "omission_is_not_actual_process_group_escape_attestation": True}

    def __enter__(self):
        monitor = self

        def observe(_self, proc):
            group = monitor.guard._active_group
            _require(group is not None and group.proc is proc, "stale fixture requires its active owned observer")
            snapshot = monitor.original_observer(proc)
            monitor.metrics["scans"] += 1
            if monitor.ready is None:
                _require(group.pause_deadline is not None and group.pause_started is not None
                         and group.telemetry["stop_requests"] == 0 and not group.paused,
                         "stale readiness must precede every STOP inside original pause deadline")
                began = time.monotonic()
                while True:
                    group.check_time()
                    ready = _readiness(snapshot, proc.pid)
                    if ready is not None:
                        break
                    time.sleep(0.001)
                    snapshot = monitor.original_observer(proc)
                    monitor.metrics["scans"] += 1
                raw = _canonical(snapshot)
                monitor.ready = ready
                monitor.metrics["readiness_snapshot"] = json.loads(raw)
                monitor.metrics["readiness_sha256"] = _sha(raw)
                monitor.metrics["readiness_wait_seconds"] = time.monotonic() - began
                monitor.metrics["observed_fork_ppid_ready"] = True
                monitor.metrics["ready_before_any_stop"] = True
            if (monitor.index == 1 and monitor.metrics["stop_requests"] > 0
                    and monitor.metrics["injected_fault_count"] == 0):
                child_pid = monitor.ready["child_pid"]
                # Accepted SIGSTOP is asynchronous.  Do not return a pre-T
                # snapshot that might permit a later ancestry read to advance
                # the child send before this single declared omission.
                while True:
                    group.check_time()
                    by_pid = {row["pid"]: row for row in snapshot["members"]}
                    leader_tasks = [row for row in snapshot["tasks"] if row["pid"] == proc.pid]
                    child_tasks = [row for row in snapshot["tasks"] if row["pid"] == child_pid]
                    if (snapshot["stable"] and len(snapshot["members"]) == 2
                            and len(snapshot["tasks"]) == 2 and child_pid in by_pid
                            and by_pid[proc.pid]["state"] == "T"
                            and len(leader_tasks) == 1 and leader_tasks[0]["state"] == "T"
                            and by_pid[child_pid]["state"] in ("S", "R")
                            and len(child_tasks) == 1 and child_tasks[0]["state"] in ("S", "R")
                            and all(task.get("tid") == task["pid"]
                                    and all(task[key] == by_pid[task["pid"]][key] for key in ROW_KEYS)
                                    for task in snapshot["tasks"])):
                        _require(_token(by_pid[proc.pid]) == _token(monitor.ready["leader_row"])
                                 and _token(by_pid[child_pid]) == _token(monitor.ready["child_row"])
                                 and by_pid[child_pid]["ppid"] == proc.pid,
                                 "one-boundary omission observed birth/ancestry drift")
                        break
                    time.sleep(0.001)
                    snapshot = monitor.original_observer(proc)
                    monitor.metrics["scans"] += 1
                actual_raw = _canonical(snapshot)
                copied = {**snapshot,
                          "members": [dict(row) for row in snapshot["members"] if row["pid"] != child_pid],
                          "tasks": [dict(row) for row in snapshot["tasks"] if row["pid"] != child_pid]}
                returned_raw = _canonical(copied)
                monitor.metrics["injected_fault_count"] += 1
                monitor.metrics["omitted_child_pid"] = child_pid
                monitor.metrics["omission_actual_snapshot"] = json.loads(actual_raw)
                monitor.metrics["omission_actual_snapshot_sha256"] = _sha(actual_raw)
                monitor.metrics["omission_returned_snapshot"] = json.loads(returned_raw)
                monitor.metrics["omission_returned_snapshot_sha256"] = _sha(returned_raw)
                return copied
            if monitor.guard._quiescence_depth > 0:
                _require(_stopped(snapshot), "verified stale-order pause contains a non-T/Z process/task")
                monitor.metrics["paused_scans"] += 1
            return snapshot

        def member_signal(observer, row, snapshot):
            if (observer.guard is monitor.guard and monitor.index == 0 and not monitor.gap_done):
                _require(monitor.ready is not None and row["pid"] == observer.proc.pid
                         and monitor.metrics["stop_requests"] == 0 and observer.telemetry["stop_requests"] == 0,
                         "stale scheduling gap must occur immediately before the first leader STOP")
                began = time.monotonic()
                child_row = monitor.ready["child_row"]
                while True:
                    observer.check_time()
                    try:
                        current, _tasks, stable = observer._read_process(child_row["pid"], tasks=False)
                    except (FileNotFoundError, ProcessLookupError) as error:
                        monitor.metrics["gap_child_absence_observed"] = True
                        monitor.metrics["gap_absence_exception_class"] = type(error).__name__
                        monitor.metrics["gap_absence_errno"] = error.errno
                        break
                    _require(stable and _token(current) == _token(child_row)
                             and current["ppid"] == observer.proc.pid,
                             "positive scheduling gap observed child identity/ancestry drift")
                    time.sleep(0.001)
                observer.check_time()
                leader, tasks, stable = observer._read_process(observer.proc.pid, tasks=True)
                _require(stable and _token(leader) == _token(monitor.ready["leader_row"])
                         and leader["state"] in ("S", "R") and len(tasks) == 1
                         and tasks[0]["state"] in ("S", "R"),
                         "positive scheduling gap requires actual surviving live leader")
                monitor.metrics["gap_surviving_leader_row"] = dict(leader)
                monitor.metrics["gap_wait_seconds"] = time.monotonic() - began
                monitor.metrics["scheduling_gap_exercised"] = True
                monitor.gap_done = True
            return monitor.original_member_signal(observer, row, snapshot)

        def confirm(observer, stale_row, fresh_snapshot):
            if observer.guard is monitor.guard:
                _require(monitor.ready is not None and stale_row["pid"] == monitor.ready["child_pid"],
                         "stale control reconciliation addressed an unrelated schedule member")
                _require(len(monitor.metrics["reconciliation_inputs"]) < 8,
                         "stale reconciliation input diagnostic bound")
                raw = _canonical(fresh_snapshot)
                monitor.metrics["reconciliation_calls"] += 1
                monitor.metrics["reconciliation_inputs"].append({"scheduled_row": dict(stale_row),
                    "fresh_snapshot": json.loads(raw), "fresh_snapshot_sha256": _sha(raw)})
            return monitor.original_confirm(observer, stale_row, fresh_snapshot)

        def send(fd, number, siginfo=None, flags=0):
            group = monitor.guard._active_group
            if number == signal.SIGSTOP and group is not None:
                bindings = [(pid, row) for pid, row in group._pidfds.items() if row["fd"] == fd]
                if len(bindings) != 1 or flags != 0 or siginfo is not None or monitor.ready is None:
                    monitor.metrics["wrong_target_stop_requests"] += 1
                    raise AssertionError("stale fixture refused unbound/non-process pidfd STOP")
                pid = bindings[0][0]
                if pid == monitor.ready["child_pid"]:
                    monitor.metrics["stale_child_stop_requests"] += 1
                    raise AssertionError("stale fixture refused STOP to the scheduled stale child")
                if pid != group.proc.pid:
                    monitor.metrics["wrong_target_stop_requests"] += 1
                    raise AssertionError("stale fixture refused STOP to an unrelated member")
                result = monitor.original_send(fd, number, siginfo, flags)
                monitor.metrics["stop_requests"] += 1
                if len(monitor.metrics["signal_samples"]) < 8:
                    monitor.metrics["signal_samples"].append({"pid": pid, "flags": flags,
                                                              "accepted_process_targeted_request": True})
                else:
                    monitor.metrics["signal_samples_truncated"] = True
                return result
            return monitor.original_send(fd, number, siginfo, flags)

        def killpg(pgid, number):
            active = monitor.guard._active_group
            if active is not None and pgid == active.proc.pid:
                if number == signal.SIGSTOP:
                    actual = monitor.original_observer(active.proc)
                    if (actual["stable"] and actual["members"] and actual["tasks"]
                            and all(row["state"] == "Z" for row in actual["members"])
                            and all(row["state"] == "Z" for row in actual["tasks"])):
                        monitor.metrics["all_zombie_group_stop_requests"] += 1
                    else:
                        monitor.metrics["wrong_target_stop_requests"] += 1
                        raise AssertionError("active stale fixture STOP must use a process pidfd")
                if number == signal.SIGCONT and monitor.guard._quiescence_depth > 0:
                    monitor.metrics["early_continue_requests"] += 1
                    raise AssertionError("stale fixture resumed during an owned recursive count")
            return monitor.original_killpg(pgid, number)

        self.guard._group_observer = types.MethodType(observe, self.guard)
        self.resources._OwnedGroupObservation._signal_member = member_signal
        self.resources._OwnedGroupObservation._confirm_absent_schedule_member = confirm
        self.resources.signal.pidfd_send_signal = send
        self.resources.os.killpg = killpg
        return self

    def __exit__(self, *_):
        self.guard._group_observer = self.original_observer
        self.resources._OwnedGroupObservation._signal_member = self.original_member_signal
        self.resources._OwnedGroupObservation._confirm_absent_schedule_member = self.original_confirm
        self.resources.signal.pidfd_send_signal = self.original_send
        self.resources.os.killpg = self.original_killpg


def _run_case(child, resources, fixture, index, remaining):
    expectation = CONTROL_EXPECTATIONS[CONTROL_NAMES[index]]
    observed_error = None
    with _Monitor(child, resources, index) as monitor:
        try:
            result = child.run([fixture, "reap" if index == 0 else "reap-live"], "control",
                               timeout=min(3.0, remaining))
            _require(index == 0 and result.returncode == 0, "negative stale case unexpectedly completed")
            _require(result.stdout == b"REAP_OK\n" and result.stderr == b"",
                     "positive actual fork/wait4 marker differs")
            monitor.metrics["reap_marker_verified_in_final_physical_capture"] = True
        except resources.ResourceFailure as error:
            observed_error = str(error)
            _require(index == 1 and expectation["reason"] in observed_error,
                     "stale control failed for an unrelated reason: " + observed_error[:256])
        _require(len(child.commands) == 1, "stale case must retain exactly one actual command")
        command = child.commands[0]
        quiescence = command.get("quiescence") or {}
        cleanup = command["group_kill"] == "REQUESTED_BEFORE_REAP"
        if index == 0 and command["group_kill"] == "NO_SUCH_GROUP_BEFORE_REAP":
            cleanup = (quiescence.get("stop_no_live_group_observations", 0) > 0
                       and monitor.metrics["all_zombie_group_stop_requests"] > 0)
        _require(command["reaped"] and cleanup and child._quiescence_depth == 0,
                 "stale fixture lacks owned kill-before-reap cleanup")
        _require(monitor.metrics["observed_fork_ppid_ready"] and monitor.metrics["ready_before_any_stop"]
                 and monitor.metrics["stop_requests"] > 0
                 and quiescence.get("pidfd_stop_requests") == monitor.metrics["stop_requests"]
                 and monitor.metrics["stale_child_stop_requests"] == 0
                 and monitor.metrics["wrong_target_stop_requests"] == 0
                 and monitor.metrics["early_continue_requests"] == 0
                 and monitor.metrics["reconciliation_calls"] == 1,
                 "stale fixture readiness/actual leader STOP/reconciliation is unverified")
        record = quiescence.get("last_stale_schedule_observation") or {}
        _require(quiescence.get("stale_schedule_absence_checks") == 1
                 and quiescence.get("stale_schedule_birth_refusals") == 0
                 and record.get("scheduled_row") == monitor.ready["child_row"]
                 and record.get("scheduled_birth_token") == list(_token(monitor.ready["child_row"]))
                 and record.get("fresh_snapshot_sha256")
                     == monitor.metrics["reconciliation_inputs"][0]["fresh_snapshot_sha256"]
                 and record.get("numeric_process_read_performed") is True
                 and record.get("candidate_STOP_sent_during_reconciliation") is False
                 and record.get("exit_verified") is False and record.get("reap_verified") is False
                 and record.get("historical_escape_cause_verified") is False,
                 "actual stale reconciliation record differs from real call input")
        if index == 0:
            _require(observed_error is None and command["returncode"] == 0 and command["aborted"] is None
                     and monitor.metrics["paused_scans"] > 0
                     and quiescence.get("verified_pauses", 0) > 0
                     and quiescence.get("continue_requests", 0) > 0
                     and quiescence.get("failure_stop_retained_until_owned_kill") is False
                     and monitor.metrics["scheduling_gap_exercised"]
                     and monitor.metrics["gap_child_absence_observed"]
                     and monitor.metrics["reap_marker_verified_in_final_physical_capture"]
                     and quiescence.get("confirmed_nonleader_proc_absences") == 1
                     and quiescence.get("stale_schedule_completed_rescans", 0) > 0
                     and quiescence.get("stale_schedule_live_refusals") == 0
                     and record.get("classification") == "CONFIRMED_NONLEADER_PROC_ABSENCE"
                     and record.get("process_absence_observed") is True
                     and record.get("absence_exception_class") in ("FileNotFoundError", "ProcessLookupError")
                     and record.get("current_row") is None,
                     "positive stale case lacks actual absence, rescan, strict count and final marker")
        else:
            _require(observed_error is not None and command["returncode"] == -signal.SIGKILL
                     and command["aborted"] and quiescence.get("failure_stop_retained_until_owned_kill") is True
                     and quiescence.get("verified_pauses") == 0 and quiescence.get("continue_requests") == 0
                     and quiescence.get("confirmed_nonleader_proc_absences") == 0
                     and quiescence.get("stale_schedule_completed_rescans") == 0
                     and quiescence.get("stale_schedule_live_refusals") == 1
                     and record.get("classification") == "REFUSED_STILL_PRESENT"
                     and record.get("process_absence_observed") is False
                     and record.get("absence_exception_class") is None
                     and isinstance(record.get("current_row"), dict)
                     and _token(record["current_row"]) == _token(monitor.ready["child_row"])
                     and record["current_row"]["state"] in ("S", "R"),
                     "negative stale omission did not find the actual live child and kill/reap")
        _require(monitor.metrics["injected_fault_count"] == int(expectation["injected_fault"]),
                 "stale case injection count differs")
    return {"observation": dict(monitor.metrics), "observed_error": observed_error}


def _recheck_fixture(parent, fixture):
    _require(fixture.get("binary_transfer_authorized") is False
             and fixture.get("metadata_only_host_binaries") is True
             and fixture.get("private_stack_memory_bytes") == 65536,
             "existing fixture host-binary bounds/envelope differ")
    for name, maximum in (("source", SOURCE_BYTES_LIMIT), ("map", MAP_BYTES_LIMIT),
                          ("object", OBJECT_BYTES_LIMIT), ("elf", OBJECT_BYTES_LIMIT)):
        before = fixture[name]
        _require(_proof_pin(parent, Path(before["path"]), maximum) == before,
                 "existing pinned fixture " + name + " changed across stale controls")
    for name, before in fixture["tools_before"].items():
        _require(name in ("as", "ld")
                 and parent.pin(Path(fixture["argvs"][0 if name == "as" else 1][0]),
                     maximum=TOOL_PIN_LIMIT, readonly_system_input=True) == before,
                 "existing native fixture tool changed across stale controls")


def _command_row(command):
    keys = ("label", "returncode", "reaped", "aborted", "group_kill",
            "nonreaping_leader_exit_observed", "full_stdout_bytes", "full_stderr_bytes",
            "full_stdout_sha256", "full_stderr_sha256", "captured_bytes", "captured_sha256",
            "raw_stdout_stream", "stdout_delivered_to_consumer_bytes")
    row = {key: command[key] for key in keys}
    row["argv_sha256"] = _sha(json.dumps(command["argv"], separators=(",", ":")).encode())
    row["quiescence"] = command.get("quiescence")
    return row


def _closed_argvs(receipt):
    table = receipt.get("command_argv_string_table")
    commands = receipt.get("commands")
    _require(isinstance(table, list) and all(isinstance(text, str) for text in table)
             and isinstance(commands, list), "actual stale child lossless argv envelope absent")
    vectors = []
    for command in commands:
        indexes = command.get("argv_refs")
        _require(isinstance(indexes, list) and 0 < len(indexes) <= 256
                 and all(isinstance(index, int) and not isinstance(index, bool)
                         and 0 <= index < len(table) for index in indexes)
                 and "argv" not in command, "actual stale child argv references malformed")
        vectors.append([table[index] for index in indexes])
    return vectors


def run_controls(parent_guard, resources_module, fixture_build):
    """Direct hosted driver; PASS requires the two separately closed epochs."""
    resources = resources_module
    started = time.monotonic()
    _require(not parent_guard._running and parent_guard._quiescence_depth == 0,
             "stale controls must run directly outside a parent command")
    _require(hasattr(resources._OwnedGroupObservation, "_confirm_absent_schedule_member")
             and hasattr(resources._OwnedGroupObservation, "_signal_member"),
             "actual production stale reconciliation API unavailable")
    source_path = Path(resources.__file__)
    source_pin = parent_guard.pin(source_path, maximum=SOURCE_PIN_LIMIT)
    _require(getattr(resources, "__6970_bound_source_sha256__", None) == source_pin["sha256"]
             and getattr(resources, "__6970_bound_source_bytes__", None) == source_pin["bytes"],
             "resource module has no matching verified-buffer loader envelope")
    helper_path = Path(__file__)
    helper_pin = parent_guard.pin(helper_path, maximum=SOURCE_PIN_LIMIT)
    _require(globals().get("__6970_bound_source_sha256__") == helper_pin["sha256"]
             and globals().get("__6970_bound_source_bytes__") == helper_pin["bytes"],
             "stale helper has no matching verified-buffer loader envelope")
    _require(parent_guard.capture_bytes + PAYLOAD_LIMIT <= resources.CAPTURE_LIMIT,
             "stale four-KiB payload reservation does not fit shared normal pool")
    fixture = fixture_build
    _recheck_fixture(parent_guard, fixture)
    parent_guard.check(FIXTURE_BYTES_LIMIT)
    initial_bytes = parent_guard.count()
    parent_commands_before = len(parent_guard.commands)
    cases = []
    proof_files = []
    payload_total = charged_capture = charged_decoder = 0
    for index, name in enumerate(CONTROL_NAMES):
        remaining = TOTAL_SECONDS - (time.monotonic() - started)
        _require(remaining > 0, "stale controls total wall deadline")
        _recheck_fixture(parent_guard, fixture)
        parent_guard.check(PAYLOAD_LIMIT)
        case_started = time.monotonic()
        child = resources.Guard(parent_guard.tmp / ("stale-order-%02d" % index), parent_guard.repository)
        capture_offset, decoder_offset = parent_guard.capture_bytes, parent_guard.decoder_bytes
        child.capture_bytes, child.decoder_bytes = capture_offset, decoder_offset
        expected = CONTROL_EXPECTATIONS[name]
        row = {"name": name, "result": "FAIL", "executed": True,
               "expected_child_epoch": expected["child_epoch"], "injected_fault": expected["injected_fault"],
               "stop_request_expected": True, "expected_negative_reason": expected["reason"],
               "expected_command_count": 1}
        details = error = closed = None
        try:
            details = _run_case(child, resources, fixture["elf"]["path"], index, remaining)
        except BaseException as failure:
            error = type(failure).__name__ + ": " + str(failure)[:512]
        finally:
            try:
                _require(child.capture_bytes >= capture_offset and child.decoder_bytes >= decoder_offset,
                         "stale inherited pool counter moved backwards")
                capture_delta = child.capture_bytes - capture_offset
                decoder_delta = child.decoder_bytes - decoder_offset
                parent_guard.capture_bytes, parent_guard.decoder_bytes = child.capture_bytes, child.decoder_bytes
                charged_capture += capture_delta
                charged_decoder += decoder_delta
                if child.minimum_free is not None:
                    parent_guard.minimum_free = (child.minimum_free if parent_guard.minimum_free is None
                                                 else min(parent_guard.minimum_free, child.minimum_free))
                _require(parent_guard.capture_bytes <= resources.CAPTURE_LIMIT
                         and parent_guard.decoder_bytes <= resources.DECODER_LIMIT,
                         "nested stale case crossed actual shared pool bounds")
                _require(parent_guard.minimum_free is not None and parent_guard.minimum_free >= resources.RESERVE,
                         "nested stale case observed a below-reserve floor")
                child_receipt = {"schema": CASE_SCHEMA,
                                 "result": "PASS_CONTROL_CHILD" if error is None and index == 0 else "FAIL",
                                 "control": name, "expected_negative": index == 1,
                                 "injected_fault": expected["injected_fault"], "stop_request_expected": True,
                                 "inherited_parent_capture_bytes": capture_offset,
                                 "inherited_parent_decoder_bytes": decoder_offset,
                                 "control_capture_pool_delta": capture_delta,
                                 "control_decoder_pool_delta": decoder_delta,
                                 "control_capture_accounting_scope": "inherited global pools; commands retain actual case bytes",
                                 "observed_control_error": error,
                                 "actual_control_observation": details["observation"] if details else None,
                                 "expected_fault_observed": details["observed_error"] if details else None,
                                 "fixture_elf_sha256": fixture["elf"]["sha256"],
                                 "source_flags_are_not_readiness_attestation": True,
                                 "native_execution_verified": False, "windows98_integration_verified": False,
                                 "tls_execution_verified": False}
                closed = child.close_receipt(child_receipt, child.output / "result.json")
            except BaseException as failure:
                error = error or (type(failure).__name__ + ": " + str(failure)[:512])
            finally:
                if child.minimum_free is not None:
                    parent_guard.minimum_free = (child.minimum_free if parent_guard.minimum_free is None
                                                 else min(parent_guard.minimum_free, child.minimum_free))
                    if child.minimum_free < resources.RESERVE:
                        parent_guard._fail("stale case observed below-reserve floor at closure")
                child.close()
        row.update({"child_epoch": closed["result"] if closed is not None else None,
                    "observed_error": details["observed_error"] if details else error,
                    "observation": details["observation"] if details else None,
                    "command_count": len(child.commands), "capture_pool_offset": capture_offset,
                    "decoder_pool_offset": decoder_offset,
                    "capture_pool_delta": child.capture_bytes - capture_offset,
                    "decoder_pool_delta": child.decoder_bytes - decoder_offset,
                    "commands": [_command_row(command) for command in child.commands],
                    "capture_payloads": [], "child_receipt_path": str(child.output / "result.json"),
                    "child_receipt_sha256": closed["sha256"] if closed else None})
        actual_paths = [child.output / "result.json", child.output / "control.stdout", child.output / "control.stderr"]
        for command in child.commands:
            payloads = {}
            _require(command["label"] == "control", "stale child command label differs")
            for stream in ("stdout", "stderr"):
                raw = _small_read(child.output / ("control." + stream), PAYLOAD_LIMIT, resources)
                payload_total += len(raw)
                _require(payload_total <= PAYLOAD_LIMIT and _sha(raw) == command["captured_sha256"][stream],
                         "physical stale capture exceeds bound or differs from closed command")
                _require(raw == (b"REAP_OK\n" if index == 0 and stream == "stdout" else b""),
                         "actual physical stale control stdout/stderr payload differs")
                payloads[stream + "_hex"] = raw.hex()
            row["capture_payloads"].append(payloads)
        for path in actual_paths:
            if not path.exists():
                error = error or "actual stale closed receipt/capture absent"
                continue
            pin = _proof_pin(parent_guard, path, resources.RECEIPT_LIMIT)
            proof_files.append(pin)
            if path == child.output / "result.json" and closed is not None:
                _require(pin["sha256"] == closed["sha256"] and pin["bytes"] == closed["bytes"]
                         and pin["identity"] == closed["identity"], "closed stale child receipt pin changed")
                actual = json.loads(_small_read(path, resources.RECEIPT_LIMIT, resources))
                _require(actual["control"] == name and actual["result"] == closed["result"]
                         and actual["receipt_accounting_verified"] is True,
                         "actual stale child receipt lacks closed self-inclusive accounting")
                _require(_closed_argvs(actual) == [command["argv"] for command in child.commands],
                         "physical closed stale argv vectors differ from actual commands")
                row["child_receipt_bytes"] = pin["bytes"]
        row["elapsed_seconds"] = time.monotonic() - case_started
        _recheck_fixture(parent_guard, fixture)
        parent_guard.check()
        _require(parent_guard.count() - initial_bytes <= FIXTURE_BYTES_LIMIT,
                 "actual cumulative stale cases exceed internal8MiB profile")
        if (error is None and closed is not None and row["child_epoch"] == expected["child_epoch"]
                and row["command_count"] == 1 and row["elapsed_seconds"] <= CASE_SECONDS):
            row["result"] = "PASS"
        else:
            row["error"] = error or "closed stale child epoch/count/case wall bound differs"
        cases.append(row)
        if row["result"] != "PASS":
            break
    _require(parent_guard.pin(source_path, maximum=SOURCE_PIN_LIMIT) == source_pin,
             "resource source changed across actual stale controls")
    _require(parent_guard.pin(helper_path, maximum=SOURCE_PIN_LIMIT) == helper_pin,
             "stale helper source changed across actual cases")
    _recheck_fixture(parent_guard, fixture)
    for before in proof_files:
        _require(_proof_pin(parent_guard, Path(before["path"]), resources.RECEIPT_LIMIT) == before,
                 "actual selected stale text proof changed before return")
    _require(payload_total == charged_capture and charged_decoder == 0,
             "physical stale capture bytes differ from inherited normal/raw charge")
    _require(len(parent_guard.commands) == parent_commands_before,
             "stale driver unexpectedly added a parent command")
    parent_guard.check()
    elapsed = time.monotonic() - started
    failures = sum(row["result"] != "PASS" for row in cases)
    if elapsed > TOTAL_SECONDS:
        failures += 1
    passed = len(cases) == len(CONTROL_NAMES) and failures == 0
    _require(not passed or len(proof_files) == 6, "two stale cases require exact6 text proof paths")
    return {"schema": REPORT_SCHEMA, "result": "PASS_STALE_ORDER_CONTROLS_ONLY" if passed else "FAIL",
            "completed": len(cases), "failures": failures if not passed else 0,
            "cases": cases, "fixture_build": fixture, "proof_files": proof_files,
            "resource_source": source_pin, "control_source": helper_pin,
            "resource_source_before_after_equal": True, "control_source_before_after_equal": True,
            "fixture_source_before_after_equal": True, "fixture_before_after_equal": True,
            "actual_controls_execution_verified": len(cases) == len(CONTROL_NAMES),
            "capture_bytes_charged_to_parent": charged_capture,
            "raw_bytes_charged_to_parent": charged_decoder, "capture_payload_bytes": payload_total,
            "case_pool_charges_exclude_parent_prepare_commands": True,
            "parent_commands_added": False, "parent_command_count_before": parent_commands_before,
            "parent_command_count_after": len(parent_guard.commands),
            "fixture_bytes_limit": FIXTURE_BYTES_LIMIT, "elapsed_seconds": elapsed,
            "case_timeout_seconds": CASE_SECONDS, "total_timeout_seconds": TOTAL_SECONDS,
            "source_input_count_delta": 1, "original_production_and_support_sources_changed": False,
            "expected_negative_commands_added_to_parent": False,
            "schedule_gap_is_not_production_exit_cause_attestation": True,
            "omission_is_not_actual_process_group_escape_attestation": True,
            "host_elf_object_binary_transfer_authorized": False,
            "tool_dynamic_runtime_closure_verified": False,
            "escaped_writers_excluded_verified": False, "continuous_group_stop_verified": False,
            "filesystem_quota_verified": False, "native_execution_verified": False,
            "windows98_integration_verified": False, "tls_execution_verified": False}


# Separate real unstable-fresh suite. Existing definitions above stay frozen.
REFRESH_CONTROL_NAMES = (
    "positive-actual-unknown-stale-absence-refresh",
    "negative-known-row-resumed-during-refresh",
    "negative-two-unstable-refresh-scans",
    "negative-original-pause-deadline-expiry",
    "negative-escaped-scheduled-child-still-live",
)
REFRESH_REPORT_SCHEMA = "native-tls-unstable-stale-refresh-controls-6970-v1"
REFRESH_CASE_SCHEMA = "native-tls-unstable-stale-refresh-child-6970-v1"
REFRESH_NORMAL_RESERVATION = 8192
REFRESH_REPORT_LIMIT = 16384
REFRESH_RECEIPT_LIMIT = 24576
REFRESH_TEXT_LIMIT = 192 * 1024


def _refresh_select(reads, writes, errors, timeout):
    import select
    return select.select(reads, writes, errors, timeout)


def _refresh_copy(value):
    return json.loads(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                 ensure_ascii=True, allow_nan=False))


def _refresh_assert_case(index, command, observation, error):
    """Test expectations precede fixtures/production; only real proof passes."""
    q = command["quiescence"]
    _require(command["reaped"] is True and observation["cleanup_complete"] is True,
             "actual refresh command or owned actor/escape cleanup incomplete")
    _require(observation["initial_unknown_scan_verified"] is True
             and observation["pending_identity_retained"] is True
             and observation["unknown_production_ownership_verified"] is False,
             "actual complete initial unknown-only/pending proof absent")
    _require(observation["helper_wrong_target_STOP"] == 0
             and observation["production_CONT_while_pending"] == 0,
             "refresh pending process control boundary violated")
    if index == 0:
        _require(error is None and command["returncode"] == 0
                 and q["confirmed_nonleader_proc_absences"] == 1
                 and q["stale_schedule_absence_checks"] == 1
                 and q["stale_schedule_completed_rescans"] > 0
                 and q["verified_pauses"] > 0 and q["continue_requests"] > 0
                 and 1 <= observation["refresh_scan_count"] <= 2
                 and observation["stable_refresh_verified"] is True
                 and observation["quiet_count_postcheck_verified"] is True,
                 "positive actual unknown/stale refresh did not reach original strict count")
    else:
        _require(error is not None and command["returncode"] == -signal.SIGKILL
                 and q["verified_pauses"] == 0 and q["continue_requests"] == 0
                 and observation["count_calls_while_pending"] == 0,
                 "negative refresh failed to refuse/kill/reap before count or CONT")
        if index == 1:
            _require(observation["helper_resume_count"] == 1
                     and observation["known_resumed_row_verified"] is True
                     and observation["refresh_scan_count"] == 1
                     and q["stale_schedule_absence_checks"] == 0,
                     "known held leader resume was not exercised after initial admission")
        elif index == 2:
            _require(observation["unknown_scan_count"] == 3
                     and observation["refresh_scan_count"] == 2
                     and q["stale_schedule_absence_checks"] == 0,
                     "persistent actual instability did not exhaust exactly two refreshes")
        elif index == 3:
            _require(observation["actual_original_deadline_exceeded"] is True
                     and q["stale_schedule_absence_checks"] == 0,
                     "actual original deadline expiry was not exercised")
        else:
            _require(observation["escape"]["transition_verified"] is True
                     and observation["escape"]["cleanup"]["adoption_verified"] is True
                     and observation["stable_refresh_verified"] is True
                     and q["stale_schedule_absence_checks"] == 1
                     and q["stale_schedule_live_refusals"] == 1,
                     "real live escaped pending child was not reconciled/refused/adopted/reaped")

def _refresh_actor_row(pid):
    """Bounded actual numeric stat read independent of the command observer."""
    directory = os.open("/proc/" + str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fd = os.open("stat", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            raw = os.read(fd, 4097)
        finally:
            os.close(fd)
        _require(0 < len(raw) <= 4096 and raw.endswith(b"\n"), "bounded actor proc stat required")
        first, last = raw.find(b" ("), raw.rfind(b")")
        _require(first > 0 and last > first and int(raw[:first]) == pid,
                 "actor numeric stat identity differs")
        fields = raw[last + 1:].split()
        _require(len(fields) >= 20, "actor stat numeric fields absent")
        row = {"pid": pid, "ppid": int(fields[1]), "pgrp": int(fields[2]),
               "session": int(fields[3]), "startticks": int(fields[19]),
               "uid": os.fstat(directory).st_uid, "state": fields[0].decode("ascii")}
        _require(row["state"] in tuple("RSDZTtWXxKPI")
                 and all(isinstance(row[key], int) and row[key] >= 0 for key in ROW_KEYS if key != "state"),
                 "actor stat state/numeric fields invalid")
        return row
    finally:
        os.close(directory)

class _RefreshActor:
    """Owned fork child: one readiness byte, one exit request, exact reap."""
    def __init__(self, guard, resources, metrics, case_deadline):
        self.guard, self.resources, self.metrics = guard, resources, metrics
        self.pid = self.pidfd = self.ready_fd = self.exit_fd = None
        self.ready_row = None
        self.reaped = False
        self.group_verified = False
        self.spawned = time.monotonic()
        self.deadline = min(case_deadline, self.spawned + CASE_SECONDS)
        self.record = {"schema": "native-tls-stale-refresh-actor-6970-v1",
                       "pid": None, "controller_pid": os.getpid(), "initial_row": None,
                       "ready_row": None, "birth_token": None, "pidfd_bound_before_ready": False,
                       "pidfd_flags": 0, "ready_before_native_spawn": False,
                       "outside_group_verified": False, "lexical_before_owned_child": False,
                       "spawned_at_monotonic": self.spawned, "deadline_monotonic": self.deadline,
                       "lifetime_seconds": CASE_SECONDS, "exit_observed": None,
                       "cleanup": {"group_kill": "NOT_REQUESTED", "kill_errno": None,
                                   "group_identity_checked_before_kill": False,
                                   "pidfd_kill_requested": False, "kill_before_reap": False,
                                   "reaped": False, "waitpid_pid": None, "waitpid_status": None,
                                   "waitpid_exitcode": None, "pipe_fds_closed": False,
                                   "pidfd_closed": False}}
        metrics["auxiliary_actor"] = self.record
        ready_r = ready_w = exit_r = exit_w = None
        try:
            # This admission precedes actor creation and any deliberate resume.
            guard.check(2)
            _require(guard.capture_bytes + 2 <= resources.CAPTURE_LIMIT,
                     "actor two-byte IPC reservation exceeds inherited normal pool")
            ready_r, ready_w = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            exit_r, exit_w = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
            pid = os.fork()
            if pid == 0:
                try:
                    # A fork actor inherits anchors but owns none of them.
                    for name in os.listdir("/proc/self/fd"):
                        if name.isdigit() and int(name) not in (ready_w, exit_r):
                            try:
                                os.close(int(name))
                            except OSError:
                                pass
                    os.setsid()
                    until = self.spawned + CASE_SECONDS
                    while True:
                        if time.monotonic() >= until:
                            os._exit(71)
                        try:
                            written = os.write(ready_w, b"R")
                            if written != 1:
                                os._exit(72)
                            break
                        except BlockingIOError:
                            _refresh_select([], [ready_w], [], min(0.01, until - time.monotonic()))
                    os.close(ready_w)
                    while True:
                        left = until - time.monotonic()
                        if left <= 0:
                            os._exit(73)
                        selected, _, _ = _refresh_select([exit_r], [], [], min(0.01, left))
                        if selected:
                            request = os.read(exit_r, 1)
                            os.close(exit_r)
                            os._exit(0 if request == b"E" else 74)
                except BaseException:
                    os._exit(75)
            self.pid, self.ready_fd, self.exit_fd = pid, ready_r, exit_w
            self.record["pid"] = pid
            # Unreaped direct fork ownership pins the numeric child even before
            # setsid succeeds. Exceptional cleanup never signals a guessed PGID.
            self.pidfd = os.pidfd_open(pid, 0)
            _require(not os.get_inheritable(self.pidfd), "actor held pidfd must be close-on-exec")
            self.record["pidfd_bound_before_ready"] = True
            self.record["pidfd_close_on_exec_verified"] = True
            initial = _refresh_actor_row(pid)
            _require(initial["ppid"] == os.getpid() and initial["uid"] == os.getuid(),
                     "actor fork ownership/UID differs before readiness")
            self.record["initial_row"] = initial
            os.close(ready_w)
            ready_w = None
            os.close(exit_r)
            exit_r = None
            self._read_ready()
            ready = _refresh_actor_row(pid)
            _require(ready["pid"] == ready["pgrp"] == ready["session"]
                     and ready["ppid"] == os.getpid() and ready["uid"] == os.getuid()
                     and ready["state"] in ("S", "R")
                     and all(ready[key] == initial[key] for key in ("pid", "startticks", "uid", "ppid")),
                     "actor actual setsid readiness/birth changed")
            self.ready_row, self.group_verified = ready, True
            self.record["ready_row"] = dict(ready)
            self.record["birth_token"] = list(_token(ready))
            self.record["ready_before_native_spawn"] = guard._active_group is None and not guard._running
            _require(self.record["ready_before_native_spawn"], "actor readiness must precede native spawn")
        except BaseException as original_error:
            try:
                self.close()
            except BaseException as cleanup_error:
                self.record["cleanup"]["cleanup_error"] = type(cleanup_error).__name__ + ": " + str(cleanup_error)[:256]
            raise original_error
        finally:
            for fd in (ready_w, exit_r):
                if fd is not None:
                    os.close(fd)
            # A failed fork still owns the original parent pipe endpoints.
            if self.pid is None:
                for fd in (ready_r, exit_w):
                    if fd is not None:
                        os.close(fd)

    def _time(self):
        _require(time.monotonic() <= self.deadline, "actor controller bounded wall deadline crossed")
        self.guard._sample()

    def _charge(self, operation, raw):
        # Charge actual transfers immediately, including a partial transfer on
        # a later failing path. This never invokes recursive count/check/pin.
        self.guard.capture_bytes += len(raw)
        self.metrics["auxiliary_ipc_bytes"] += len(raw)
        row = {"operation": operation, "bytes": len(raw), "sha256": _sha(raw),
               "normal_pool_charge_bytes": len(raw)}
        row["observed_hex" if operation == "read-ready" else "delivered_hex"] = raw.hex()
        self.metrics["auxiliary_ipc"].append(row)
        _require(self.guard.capture_bytes <= self.resources.CAPTURE_LIMIT,
                 "actual actor IPC crossed inherited normal capture limit")

    def _read_ready(self):
        while True:
            self._time()
            selected, _, _ = _refresh_select([self.ready_fd], [], [], 0.001)
            if not selected:
                continue
            try:
                raw = os.read(self.ready_fd, 1)
            except BlockingIOError:
                continue
            self._charge("read-ready", raw)
            _require(raw == b"R", "actor actual readiness byte absent/different")
            return

    def request_exit_and_reap(self, deadline):
        self.deadline = min(self.deadline, deadline)
        self._time()
        _require(self.guard.failure is None and self.group_verified and not self.reaped
                 and self.guard.capture_bytes + 1 <= self.resources.CAPTURE_LIMIT,
                 "actor exit IPC explicit remaining normal pool admission failed")
        before = _refresh_actor_row(self.pid)
        _require(_token(before) == _token(self.ready_row) and before["ppid"] == os.getpid()
                 and before["state"] in ("S", "R"), "actor identity/liveness changed before exit request")
        while True:
            self._time()
            try:
                written = os.write(self.exit_fd, b"E")
                self._charge("write-exit", b"E"[:written])
                _require(written == 1, "actor actual exit request partial transfer")
                break
            except BlockingIOError:
                _refresh_select([], [self.exit_fd], [], 0.001)
        while True:
            self._time()
            result = os.waitid(os.P_PID, self.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
            if result is not None:
                _require(result.si_pid == self.pid and result.si_code == os.CLD_EXITED
                         and result.si_status == 0, "actor did not actually exit normally before reap")
                self.record["exit_observed"] = {"si_pid": result.si_pid, "si_code": result.si_code,
                    "si_status": result.si_status, "nonreaped": True,
                    "options": os.WEXITED | os.WNOHANG | os.WNOWAIT,
                    "option_names": ["WEXITED", "WNOHANG", "WNOWAIT"]}
                break
            time.sleep(0.001)
        self._kill_group_and_reap(expected_zero=True)

    def _kill_group_and_reap(self, *, expected_zero=False):
        cleanup = self.record["cleanup"]
        failure = None
        if self.group_verified:
            try:
                before = _refresh_actor_row(self.pid)
                _require(_token(before) == _token(self.ready_row) and before["ppid"] == os.getpid()
                         and before["pgrp"] == self.pid and before["session"] == self.pid,
                         "unreaped actor group identity changed before cleanup")
                cleanup["group_identity_checked_before_kill"] = True
                try:
                    os.killpg(self.pid, signal.SIGKILL)
                    cleanup["group_kill"] = "REQUESTED_BEFORE_REAP"
                except ProcessLookupError as error:
                    _require(error.errno == 3, "actor group absence has unexpected actual errno")
                    cleanup["group_kill"] = "NO_SUCH_GROUP_BEFORE_REAP"
                    cleanup["kill_errno"] = error.errno
                cleanup["kill_before_reap"] = True
            except BaseException as error:
                failure = error
        if (not self.group_verified or failure is not None) and self.pidfd is not None:
            try:
                signal.pidfd_send_signal(self.pidfd, signal.SIGKILL, None, 0)
                cleanup["pidfd_kill_requested"] = True
                cleanup["kill_before_reap"] = True
            except BaseException as error:
                failure = failure or error
        if not self.group_verified and self.pidfd is None:
            # pidfd_open itself can fail. The actor still has its absolute
            # five-second self-expiry and exact unreaped fork identity. Wait
            # for that child without guessing or signalling its possible PGID.
            cleanup["no_bound_pidfd_waited_for_bounded_self_expiry"] = True
        until = self.deadline
        while True:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                _require(pid == self.pid, "actor cleanup reaped a different child")
                self.reaped = True
                cleanup.update(reaped=True, waitpid_pid=pid, waitpid_status=status,
                               waitpid_exitcode=os.waitstatus_to_exitcode(status))
                if expected_zero:
                    if status != 0:
                        failure = failure or AssertionError("actor exit/reap status differs from actual WNOWAIT zero")
                if failure is not None:
                    raise failure
                return
            _require(time.monotonic() <= until, "actor cleanup exact reap timeout")
            time.sleep(0.001)

    def close(self):
        failure = None
        try:
            if self.pid is not None and not self.reaped:
                self._kill_group_and_reap()
        except BaseException as error:
            failure = error
        finally:
            for name in ("ready_fd", "exit_fd", "pidfd"):
                fd = getattr(self, name)
                if fd is not None:
                    try:
                        os.close(fd)
                    except BaseException as error:
                        failure = failure or error
                    setattr(self, name, None)
            self.record["cleanup"]["pipe_fds_closed"] = self.ready_fd is None and self.exit_fd is None
            self.record["cleanup"]["pidfd_closed"] = self.pidfd is None
        if failure is not None:
            raise failure
