# SPDX-License-Identifier: GPL-2.0-only
"""Real invalidated count-epoch controls; importing executes no control.

Reuse the existing raw-syscall fork fixture and two separately closed Guard
children.  A helper-owned outside-group actor exits at a real numeric scan
read after the first real count.  The original reader supplies the actual
absence exception.  The negative alone resumes a known stopped child through
its retained birth-verified pidfd.  No process row or syscall result is forged.
Auxiliary readiness/exit pipe bytes are explicitly charged to the normal pool
separately from physical native stdout/stderr.  Production ownership of an
unknown disappearing process remains unproved.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import signal
import select
import stat
import time
import types

CONTROL_NAMES = ("positive-count-epoch-actual-unknown-exit", "negative-count-epoch-known-child-resumed")
CONTROL_EXPECTATIONS = {
    CONTROL_NAMES[0]: {"child_epoch": "PASS_CONTROL_CHILD", "command_count": 1,
                       "injected_fault": False, "stop_request_expected": True,
                       "reason": None},
    CONTROL_NAMES[1]: {"child_epoch": "FAIL", "command_count": 1,
                       "injected_fault": True, "stop_request_expected": True,
                       "reason": "owned group changed or resumed during recursive observation"},
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
CASE_SCHEMA = "native-tls-count-epoch-control-child-6970-v1"
REPORT_SCHEMA = "native-tls-count-epoch-controls-6970-v1"
TOKEN_KEYS = ("pid", "startticks", "pgrp", "session", "uid")
ROW_KEYS = ("pid", "ppid", "state", "pgrp", "session", "startticks", "uid")


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _canonical(value):
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    _require(len(raw) <= 16384, "count-epoch numeric observation diagnostic bound")
    return raw


def _small_read(path, maximum, resources):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 <= before.st_size <= maximum, "bounded regular count-epoch proof read required")
        raw = bytearray()
        while True:
            block = os.read(fd, 65536)
            if not block:
                break
            raw.extend(block)
            _require(len(raw) <= maximum, "count-epoch proof grew beyond bound")
        _require(len(raw) == before.st_size
                 and resources.identity(os.fstat(fd)) == resources.identity(before)
                 and resources.identity(Path(path).lstat()) == resources.identity(before),
                 "count-epoch proof held/named identity changed during read")
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



def _copy(value):
    return json.loads(_canonical(value))


def _actor_row(pid):
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


class _Actor:
    """Owned fork child: one readiness byte, one exit request, exact reap."""
    def __init__(self, guard, resources, metrics, case_deadline):
        self.guard, self.resources, self.metrics = guard, resources, metrics
        self.pid = self.pidfd = self.ready_fd = self.exit_fd = None
        self.ready_row = None
        self.reaped = False
        self.group_verified = False
        self.spawned = time.monotonic()
        self.deadline = min(case_deadline, self.spawned + CASE_SECONDS)
        self.record = {"schema": "native-tls-count-epoch-actor-6970-v1",
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
                            select.select([], [ready_w], [], min(0.01, until - time.monotonic()))
                    os.close(ready_w)
                    while True:
                        left = until - time.monotonic()
                        if left <= 0:
                            os._exit(73)
                        selected, _, _ = select.select([exit_r], [], [], min(0.01, left))
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
            initial = _actor_row(pid)
            _require(initial["ppid"] == os.getpid() and initial["uid"] == os.getuid(),
                     "actor fork ownership/UID differs before readiness")
            self.record["initial_row"] = initial
            os.close(ready_w)
            ready_w = None
            os.close(exit_r)
            exit_r = None
            self._read_ready()
            ready = _actor_row(pid)
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
            selected, _, _ = select.select([self.ready_fd], [], [], 0.001)
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
        before = _actor_row(self.pid)
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
                select.select([], [self.exit_fd], [], 0.001)
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
                before = _actor_row(self.pid)
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
        until = time.monotonic() + CASE_SECONDS
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


class _Monitor:
    """Real scanner boundary and counts; only negative CONT is a fault."""
    def __init__(self, guard, resources, index):
        self.guard, self.resources, self.index = guard, resources, index
        self.original_observer = guard._group_observer
        self.original_count = guard._count_files
        self.original_read = resources._OwnedGroupObservation._read_process
        self.original_killpg = resources.os.killpg
        self.original_send = resources.signal.pidfd_send_signal
        self.ready = self.actor = None
        self.in_scanner = False
        self.fault_active = False
        self.fault_done = False
        self.armed = False
        self.target_attempt = None
        self.read_ordinal = 0
        self.metrics = {"scans": 0, "readiness_snapshot": None, "readiness_sha256": None,
                        "observed_fork_ppid_ready": False, "ready_before_any_stop": False,
                        "target_pause_attempt": None, "target_pause_started_at_monotonic": None,
                        "target_deadline_monotonic": None, "target_completed_traversals": 0,
                        "counted_values": [], "first_count_value": None, "recount_value": None,
                        "reference_snapshot": None, "reference_sha256": None,
                        "invalidated_postcount_snapshot": None, "invalidated_postcount_sha256": None,
                        "actual_scan_instability": None, "reconfirmed_snapshots": [],
                        "accepted_postcount_snapshot": None, "accepted_postcount_sha256": None,
                        "scanned_numeric_reads": [], "helper_poll_observations": [],
                        "actual_actor_numeric_absence": None, "fault_boundary_exercised": False,
                        "fault_pidfd_CONT": None, "injected_fault_count": 0,
                        "early_production_CONT_requests": 0, "target_production_CONT_requests": 0,
                        "production_CONT_at_fault": None, "production_CONT_at_recount_start": None,
                        "production_continue_requests_at_fault": None,
                        "production_continue_requests_at_recount": None,
                        "nested_traversals_at_fault": 0, "actual_count_calls": 0,
                        "discarded_count_value": None, "accepted_count_value": None,
                        "pidfd_STOP_requests_at_fault": None, "pidfd_STOP_requests_at_recount": None,
                        "pidfd_STOP_requests_at_accepted_postcount": None,
                        "actor_reaped_before_original_numeric_read": False,
                        "known_child_scan_after_fault_verified": False,
                        "auxiliary_actor": None, "auxiliary_ipc": [], "auxiliary_ipc_bytes": 0,
                        "snapshot_or_row_fabricated": False, "syscall_result_modified": False,
                        "resource_counter_modified": False,
                        "unknown_actor_control_ownership_is_not_production_ownership_attestation": True,
                        "count_epoch_recovery_is_not_production_exit_cause_attestation": True,
                        "whole_group_stayed_stopped_after_intentional_fault_verified": False}

    def _deadline(self, group):
        _require(group.pause_started is not None, "fault scope lost original pause start")
        deadline = min(group.deadline, group.pause_started + 1.0)
        group.check_time()
        _require(time.monotonic() <= deadline, "control original one-second observation deadline crossed")
        self.guard._sample()
        return deadline

    def _fault(self, group):
        _require(self.ready is not None and self.actor is not None
                 and group.pause_stage == "post_count_verification"
                 and group.paused and group.verified and self.guard._quiescence_depth == 1
                 and group.telemetry["pause_attempts"] == self.target_attempt
                 and self.metrics["target_completed_traversals"] == 1,
                 "actor exit must occur only at first actual postcount scan")
        deadline = self._deadline(group)
        self.metrics["reference_snapshot"] = _copy(group.quiet_snapshot)
        self.metrics["reference_sha256"] = _sha(_canonical(group.quiet_snapshot))
        self.metrics["production_CONT_at_fault"] = group.telemetry["continue_requests"]
        self.metrics["production_continue_requests_at_fault"] = group.telemetry["continue_requests"]
        self.metrics["pidfd_STOP_requests_at_fault"] = group.telemetry["pidfd_stop_requests"]
        _require(group.telemetry["continue_requests"] == 0 and _stopped(group.quiet_snapshot)
                 and group.quiet_snapshot["stable"] and len(group.quiet_snapshot["members"]) == 2
                 and len(group.quiet_snapshot["tasks"]) == 2,
                 "target fault lacks first complete two-member stopped reference")
        if self.index == 1:
            pid = self.ready["child_pid"]
            binding = group._pidfds.get(pid)
            _require(binding is not None and binding["token"] == _token(self.ready["child_row"]),
                     "negative fault child has no matching retained birth pidfd")
            leader, lt, ls = self.original_read(group, group.proc.pid, tasks=True)
            child, ct, cs = self.original_read(group, pid, tasks=True)
            _require(ls and cs and leader["state"] == child["state"] == "T"
                     and len(lt) == len(ct) == 1 and lt[0]["state"] == ct[0]["state"] == "T"
                     and _token(child) == _token(self.ready["child_row"])
                     and child["ppid"] == group.proc.pid,
                     "negative fault lacks actual parent/child signal STOP")
            self.original_send(binding["fd"], signal.SIGCONT, None, 0)
            self.metrics["injected_fault_count"] += 1
            self.metrics["fault_pidfd_CONT"] = {"pid": pid, "birth_token": list(binding["token"]),
                "childbirth_token_before": list(_token(child)), "childbirth_token_after": None,
                "signal": int(signal.SIGCONT), "flags": 0, "process_targeted": True,
                "retained_pidfd_birth_verified": True, "accepted_actual_send": True,
                "production_CONT": False}
            while True:
                self._deadline(group)
                leader, lt, ls = self.original_read(group, group.proc.pid, tasks=True)
                child, ct, cs = self.original_read(group, pid, tasks=True)
                if (ls and cs and leader["state"] == "T" and len(lt) == len(ct) == 1
                        and lt[0]["state"] == "T" and child["state"] in ("R", "S")
                        and ct[0]["state"] in ("R", "S")):
                    _require(_token(leader) == _token(self.ready["leader_row"])
                             and _token(child) == _token(self.ready["child_row"])
                             and child["ppid"] == group.proc.pid,
                             "negative resumed known child birth/ancestry drift")
                    self.metrics["helper_poll_observations"].append({"source": "helper_poll",
                        "leader_row": dict(leader), "leader_tasks": _copy(lt),
                        "child_row": dict(child), "child_tasks": _copy(ct),
                        "completed_at_monotonic": time.monotonic()})
                    self.metrics["fault_pidfd_CONT"]["childbirth_token_after"] = list(_token(child))
                    break
                time.sleep(0.001)
        self.actor.request_exit_and_reap(deadline)
        self.metrics["actor_reaped_before_original_numeric_read"] = self.actor.reaped
        self.metrics["fault_boundary_exercised"] = True
        self.fault_done = True

    def __enter__(self):
        monitor = self

        def observe(_self, proc):
            group = monitor.guard._active_group
            _require(group is not None and group.proc is proc, "count control requires active owned group")
            previous = monitor.in_scanner
            monitor.in_scanner = True
            try:
                snapshot = monitor.original_observer(proc)
                monitor.metrics["scans"] += 1
                if monitor.ready is None:
                    _require(group.pause_started is not None and group.pause_deadline is not None
                             and group.telemetry["stop_requests"] == 0 and not group.paused,
                             "count control fork readiness must precede every STOP")
                    while True:
                        group.check_time()
                        ready = _readiness(snapshot, proc.pid)
                        if ready is not None:
                            break
                        time.sleep(0.001)
                        snapshot = monitor.original_observer(proc)
                        monitor.metrics["scans"] += 1
                    monitor.ready = ready
                    _require(monitor.actor is not None and monitor.actor.ready_row["pgrp"] != proc.pid
                             and monitor.actor.ready_row["session"] != proc.pid,
                             "actor belongs to primary native command group")
                    _require(str(monitor.actor.pid) < str(ready["child_pid"]),
                             "actual lexical proc order would sample known child before actor fault")
                    monitor.actor.record["outside_group_verified"] = True
                    monitor.actor.record["lexical_before_owned_child"] = True
                    monitor.metrics["readiness_snapshot"] = _copy(snapshot)
                    monitor.metrics["readiness_sha256"] = _sha(_canonical(snapshot))
                    monitor.metrics["observed_fork_ppid_ready"] = True
                    monitor.metrics["ready_before_any_stop"] = True
                if (monitor.target_attempt == group.telemetry["pause_attempts"]
                        and monitor.fault_done):
                    if (group.pause_stage == "post_count_verification"
                            and monitor.metrics["target_completed_traversals"] == 1):
                        monitor.metrics["invalidated_postcount_snapshot"] = _copy(snapshot)
                        monitor.metrics["invalidated_postcount_sha256"] = _sha(_canonical(snapshot))
                        monitor.metrics["actual_scan_instability"] = _copy(group.last_scan_instability)
                    elif group.pause_stage == "count_epoch_reconfirmation":
                        _require(len(monitor.metrics["reconfirmed_snapshots"]) < 8,
                                 "bounded actual count reconfirmation snapshot history")
                        monitor.metrics["reconfirmed_snapshots"].append({"snapshot": _copy(snapshot),
                            "sha256": _sha(_canonical(snapshot)), "completed_at_monotonic": time.monotonic()})
                    elif (group.pause_stage == "post_count_verification"
                            and monitor.metrics["target_completed_traversals"] == 2):
                        monitor.metrics["accepted_postcount_snapshot"] = _copy(snapshot)
                        monitor.metrics["accepted_postcount_sha256"] = _sha(_canonical(snapshot))
                        monitor.metrics["pidfd_STOP_requests_at_accepted_postcount"] = group.telemetry["pidfd_stop_requests"]
                return snapshot
            finally:
                monitor.in_scanner = previous

        def count(_self, *, failure_evidence=False):
            if monitor.fault_active:
                monitor.metrics["nested_traversals_at_fault"] += 1
                raise AssertionError("recursive filesystem traversal attempted during actor fault admission")
            group = monitor.guard._active_group
            active = group is not None and monitor.guard._quiescence_depth > 0
            if active and monitor.target_attempt is None:
                monitor.target_attempt = group.telemetry["pause_attempts"]
                monitor.metrics["target_pause_attempt"] = monitor.target_attempt
                monitor.metrics["target_pause_started_at_monotonic"] = group.pause_started
                monitor.metrics["target_deadline_monotonic"] = min(group.deadline, group.pause_started + 1.0)
            target = active and monitor.target_attempt == group.telemetry["pause_attempts"]
            if target and monitor.metrics["target_completed_traversals"] == 1:
                _require(group.pause_stage == "count_epoch_recount" and group.verified,
                         "second actual count must use the explicit fresh count-epoch transaction")
                monitor.metrics["production_CONT_at_recount_start"] = group.telemetry["continue_requests"]
                monitor.metrics["production_continue_requests_at_recount"] = group.telemetry["continue_requests"]
                monitor.metrics["pidfd_STOP_requests_at_recount"] = group.telemetry["pidfd_stop_requests"]
                _require(group.telemetry["continue_requests"] == 0,
                         "production continued before target full recount")
            if target:
                monitor.metrics["actual_count_calls"] += 1
            value = monitor.original_count(failure_evidence=failure_evidence)
            if target:
                _require(monitor.metrics["target_completed_traversals"] < 2,
                         "count control observed a third target filesystem traversal")
                monitor.metrics["target_completed_traversals"] += 1
                monitor.metrics["counted_values"].append(value)
                if monitor.metrics["target_completed_traversals"] == 1:
                    monitor.metrics["first_count_value"] = value
                    monitor.metrics["discarded_count_value"] = value
                    monitor.armed = True
                else:
                    monitor.metrics["recount_value"] = value
                    monitor.metrics["accepted_count_value"] = value
            return value

        def read(observer, pid, *, tasks=False):
            scoped = observer.guard is monitor.guard and monitor.in_scanner
            if scoped:
                monitor.read_ordinal += 1
            boundary = (scoped and monitor.armed and not monitor.fault_done
                        and pid == monitor.actor.pid and not tasks
                        and observer.pause_stage == "post_count_verification")
            if boundary:
                _require(len(monitor.metrics["scanned_numeric_reads"]) < 8,
                         "count scanner read chronology bound")
                monitor.metrics["scanned_numeric_reads"].append({"source": "scanner",
                    "ordinal": monitor.read_ordinal, "pid": pid, "tasks": False,
                    "after_fault": False, "actor_fault_boundary": True, "row": None})
                monitor.fault_active = True
                try:
                    monitor._fault(observer)
                finally:
                    monitor.fault_active = False
            try:
                result = monitor.original_read(observer, pid, tasks=tasks)
            except (FileNotFoundError, ProcessLookupError) as error:
                if boundary:
                    monitor.metrics["actual_actor_numeric_absence"] = {
                        "pid": pid, "exception_class": type(error).__name__, "errno": error.errno,
                        "original_reader_forwarded": True, "source": "scanner"}
                raise
            if (scoped and monitor.fault_done and monitor.ready is not None
                    and pid == monitor.ready["child_pid"] and not tasks
                    and observer.telemetry["pause_attempts"] == monitor.target_attempt
                    and not monitor.metrics["known_child_scan_after_fault_verified"]):
                row = result[0]
                _require(_token(row) == _token(monitor.ready["child_row"])
                         and row["ppid"] == observer.proc.pid,
                         "actual scanner known child birth/ancestry drift")
                if monitor.index == 1:
                    _require(row["state"] in ("S", "R"),
                             "negative scanner did not actually sample resumed child after actor fault")
                monitor.metrics["scanned_numeric_reads"].append({"source": "scanner",
                    "ordinal": monitor.read_ordinal, "pid": pid, "tasks": False,
                    "after_fault": True, "actor_fault_boundary": False, "row": dict(row)})
                monitor.metrics["known_child_scan_after_fault_verified"] = True
            return result

        def killpg(pgid, number):
            group = monitor.guard._active_group
            if group is not None and pgid == group.proc.pid and number == signal.SIGCONT:
                if monitor.guard._quiescence_depth > 0:
                    monitor.metrics["early_production_CONT_requests"] += 1
                    raise AssertionError("count control refused production CONT inside target traversal")
                if monitor.target_attempt == group.telemetry["pause_attempts"]:
                    monitor.metrics["target_production_CONT_requests"] += 1
            return monitor.original_killpg(pgid, number)

        self.guard._group_observer = types.MethodType(observe, self.guard)
        self.guard._count_files = types.MethodType(count, self.guard)
        self.resources._OwnedGroupObservation._read_process = read
        self.resources.os.killpg = killpg
        return self

    def __exit__(self, *_):
        self.guard._group_observer = self.original_observer
        self.guard._count_files = self.original_count
        self.resources._OwnedGroupObservation._read_process = self.original_read
        self.resources.os.killpg = self.original_killpg


def _run_case(child, resources, fixture, index, remaining):
    expectation = CONTROL_EXPECTATIONS[CONTROL_NAMES[index]]
    observed_error = None
    monitor = _Monitor(child, resources, index)
    try:
        try:
            actor = _Actor(child, resources, monitor.metrics,
                           time.monotonic() + min(CASE_SECONDS, remaining))
            monitor.actor = actor
            with monitor:
                try:
                    result = child.run([fixture, "reap" if index == 0 else "reap-live"], "control",
                                       timeout=min(3.0, remaining))
                    _require(index == 0 and result.returncode == 0 and result.stdout == b"REAP_OK\n"
                             and result.stderr == b"", "count positive physical fork/wait4 marker differs")
                except resources.ResourceFailure as error:
                    observed_error = str(error)
                    _require(index == 1 and expectation["reason"] in observed_error,
                             "count control failed for unrelated reason: " + observed_error[:256])
        finally:
            if monitor.actor is not None:
                monitor.actor.close()
        _require(len(child.commands) == 1, "count control must retain exactly one native command")
        command = child.commands[0]
        q = command.get("quiescence") or {}
        cleanup = monitor.metrics["auxiliary_actor"]["cleanup"]
        _require(command["reaped"] and command["group_kill"] in
                 ("REQUESTED_BEFORE_REAP", "NO_SUCH_GROUP_BEFORE_REAP")
                 and child._active_group is None and child._quiescence_depth == 0,
                 "native count case lacks owned kill-before-reap closure")
        _require(monitor.metrics["observed_fork_ppid_ready"] and monitor.metrics["ready_before_any_stop"]
                 and monitor.metrics["fault_boundary_exercised"]
                 and monitor.metrics["actor_reaped_before_original_numeric_read"]
                 and monitor.metrics["known_child_scan_after_fault_verified"]
                 and monitor.metrics["early_production_CONT_requests"] == 0
                 and monitor.metrics["auxiliary_ipc_bytes"] == 2
                 and cleanup["reaped"] and cleanup["waitpid_status"] == 0
                 and cleanup["kill_before_reap"] and cleanup["group_identity_checked_before_kill"]
                 and cleanup["pipe_fds_closed"] and cleanup["pidfd_closed"],
                 "count control actual scanner/actor/IPC cleanup proof is incomplete")
        absence = monitor.metrics["actual_actor_numeric_absence"] or {}
        _require((absence.get("exception_class"), absence.get("errno")) in
                 (("FileNotFoundError", 2), ("ProcessLookupError", 3)),
                 "count actor scan did not raise the original typed actual absence")
        reads = monitor.metrics["scanned_numeric_reads"]
        _require(len(reads) == 2 and reads[0]["actor_fault_boundary"]
                 and reads[1]["after_fault"] and reads[1]["ordinal"] > reads[0]["ordinal"],
                 "known scanner child read did not follow the real actor fault boundary")
        ref = monitor.metrics["reference_snapshot"]
        bad = monitor.metrics["invalidated_postcount_snapshot"]
        instability = monitor.metrics["actual_scan_instability"]
        event = instability["events"][0] if instability and instability.get("events") else {}
        _require(ref is not None and ref["stable"] and _stopped(ref)
                 and bad is not None and not bad["stable"]
                 and instability["total_events"] == 1 and not instability["events_truncated"]
                 and len(instability["events"]) == 1
                 and instability["events"][0]["pid"] == actor.pid
                 and instability["events"][0]["classification"] == "before_group_classification_unknown"
                 and instability["events"][0]["reason"] == "numeric_process_or_task_disappeared"
                 and instability["classification_counts"] == {"before_group_classification_unknown": 1}
                 and (event.get("absence_exception_class"), event.get("absence_errno"))
                     == (absence["exception_class"], absence["errno"]),
                 "count case lacks one actual unknown actor disappearance provenance")
        if index == 0:
            pair = monitor.metrics["reconfirmed_snapshots"]
            final = monitor.metrics["accepted_postcount_snapshot"]
            record = q.get("last_count_epoch_discard") or {}
            _require(observed_error is None and command["returncode"] == 0 and command["aborted"] is None
                     and bad == {**ref, "stable": False}
                     and monitor.metrics["target_completed_traversals"] == 2
                     and len(pair) == 2 and all(item["snapshot"] == ref for item in pair)
                     and final == ref and monitor.metrics["target_production_CONT_requests"] == 1
                     and monitor.metrics["production_CONT_at_fault"] == 0
                     and monitor.metrics["production_CONT_at_recount_start"] == 0
                     and monitor.metrics["pidfd_STOP_requests_at_fault"]
                         == monitor.metrics["pidfd_STOP_requests_at_recount"]
                         == monitor.metrics["pidfd_STOP_requests_at_accepted_postcount"]
                     and q.get("count_epoch_discarded_counts") == 1
                     and q.get("count_epoch_recounts_started") == 1
                     and q.get("count_epoch_reconfirmed_pairs") == 1
                     and q.get("count_epoch_unknown_pair_resets") == 0
                     and record.get("discarded_count_value") == monitor.metrics["first_count_value"]
                     and record.get("discarded_count_value_returned") is False
                     and q.get("failure_stop_retained_until_owned_kill") is False
                     and monitor.metrics["injected_fault_count"] == 0,
                     "positive lacks actual discarded count, fresh pair, full recount and exact postcount")
        else:
            child_rows = [row for row in bad["members"] if row["pid"] == monitor.ready["child_pid"]]
            _require(observed_error is not None and command["returncode"] == -signal.SIGKILL
                     and command["aborted"] and len(child_rows) == 1 and child_rows[0]["state"] in ("S", "R")
                     and bad["leader"]["state"] == "T"
                     and monitor.metrics["target_completed_traversals"] == 1
                     and monitor.metrics["recount_value"] is None
                     and not monitor.metrics["reconfirmed_snapshots"]
                     and monitor.metrics["accepted_postcount_snapshot"] is None
                     and monitor.metrics["injected_fault_count"] == 1
                     and monitor.metrics["target_production_CONT_requests"] == 0
                     and q.get("continue_requests") == 0
                     and q.get("count_epoch_discarded_counts") == 0
                     and q.get("count_epoch_recounts_started") == 0
                     and q.get("count_epoch_reconfirmed_pairs") == 0
                     and q.get("count_epoch_unknown_pair_resets") == 0
                     and q.get("last_count_epoch_discard") is None
                     and q.get("failure_stop_retained_until_owned_kill") is True,
                     "negative resumed known child did not hard fail without discard/recount/production CONT")
        return {"observation": _copy(monitor.metrics), "observed_error": observed_error}
    except BaseException as error:
        error.control_observation = _copy(monitor.metrics)
        raise

def _recheck_fixture(parent, fixture):
    _require(fixture.get("binary_transfer_authorized") is False
             and fixture.get("metadata_only_host_binaries") is True
             and fixture.get("private_stack_memory_bytes") == 65536,
             "existing fixture host-binary bounds/envelope differ")
    for name, maximum in (("source", SOURCE_BYTES_LIMIT), ("map", MAP_BYTES_LIMIT),
                          ("object", OBJECT_BYTES_LIMIT), ("elf", OBJECT_BYTES_LIMIT)):
        before = fixture[name]
        _require(_proof_pin(parent, Path(before["path"]), maximum) == before,
                 "existing pinned fixture " + name + " changed across count-epoch controls")
    for name, before in fixture["tools_before"].items():
        _require(name in ("as", "ld")
                 and parent.pin(Path(fixture["argvs"][0 if name == "as" else 1][0]),
                     maximum=TOOL_PIN_LIMIT, readonly_system_input=True) == before,
                 "existing native fixture tool changed across count-epoch controls")


def _command_row(command):
    keys = ("label", "owned_pid", "returncode", "reaped", "aborted", "group_kill",
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
             and isinstance(commands, list), "actual count-epoch child lossless argv envelope absent")
    vectors = []
    for command in commands:
        indexes = command.get("argv_refs")
        _require(isinstance(indexes, list) and 0 < len(indexes) <= 256
                 and all(isinstance(index, int) and not isinstance(index, bool)
                         and 0 <= index < len(table) for index in indexes)
                 and "argv" not in command, "actual count-epoch child argv references malformed")
        vectors.append([table[index] for index in indexes])
    return vectors


def run_controls(parent_guard, resources_module, fixture_build):
    """Direct hosted driver; PASS requires the two separately closed epochs."""
    resources = resources_module
    started = time.monotonic()
    _require(not parent_guard._running and parent_guard._quiescence_depth == 0,
             "count-epoch controls must run directly outside a parent command")
    _require(hasattr(resources, "_CountEpochDiscard")
             and hasattr(resources._OwnedGroupObservation, "reconfirm_count_epoch"),
             "actual production count-epoch API unavailable")
    source_path = Path(resources.__file__)
    source_pin = parent_guard.pin(source_path, maximum=SOURCE_PIN_LIMIT)
    _require(getattr(resources, "__6970_bound_source_sha256__", None) == source_pin["sha256"]
             and getattr(resources, "__6970_bound_source_bytes__", None) == source_pin["bytes"],
             "resource module has no matching verified-buffer loader envelope")
    helper_path = Path(__file__)
    helper_pin = parent_guard.pin(helper_path, maximum=SOURCE_PIN_LIMIT)
    _require(globals().get("__6970_bound_source_sha256__") == helper_pin["sha256"]
             and globals().get("__6970_bound_source_bytes__") == helper_pin["bytes"],
             "count-epoch helper has no matching verified-buffer loader envelope")
    _require(parent_guard.capture_bytes + PAYLOAD_LIMIT <= resources.CAPTURE_LIMIT,
             "count-epoch four-KiB payload reservation does not fit shared normal pool")
    fixture = fixture_build
    _recheck_fixture(parent_guard, fixture)
    parent_guard.check(FIXTURE_BYTES_LIMIT)
    initial_bytes = parent_guard.count()
    parent_commands_before = len(parent_guard.commands)
    cases = []
    proof_files = []
    payload_total = charged_capture = charged_decoder = charged_ipc = 0
    for index, name in enumerate(CONTROL_NAMES):
        remaining = TOTAL_SECONDS - (time.monotonic() - started)
        _require(remaining > 0, "count-epoch controls total wall deadline")
        _recheck_fixture(parent_guard, fixture)
        parent_guard.check(PAYLOAD_LIMIT)
        case_started = time.monotonic()
        child = resources.Guard(parent_guard.tmp / ("count-epoch-%02d" % index), parent_guard.repository)
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
            if getattr(failure, "control_observation", None) is not None:
                details = {"observation": failure.control_observation, "observed_error": None}
        finally:
            try:
                _require(child.capture_bytes >= capture_offset and child.decoder_bytes >= decoder_offset,
                         "count-epoch inherited pool counter moved backwards")
                capture_delta = child.capture_bytes - capture_offset
                decoder_delta = child.decoder_bytes - decoder_offset
                parent_guard.capture_bytes, parent_guard.decoder_bytes = child.capture_bytes, child.decoder_bytes
                charged_capture += capture_delta
                charged_decoder += decoder_delta
                ipc_delta = (details["observation"]["auxiliary_ipc_bytes"] if details else 0)
                charged_ipc += ipc_delta
                if child.minimum_free is not None:
                    parent_guard.minimum_free = (child.minimum_free if parent_guard.minimum_free is None
                                                 else min(parent_guard.minimum_free, child.minimum_free))
                _require(parent_guard.capture_bytes <= resources.CAPTURE_LIMIT
                         and parent_guard.decoder_bytes <= resources.DECODER_LIMIT,
                         "nested count-epoch case crossed actual shared pool bounds")
                _require(parent_guard.minimum_free is not None and parent_guard.minimum_free >= resources.RESERVE,
                         "nested count-epoch case observed a below-reserve floor")
                child_receipt = {"schema": CASE_SCHEMA,
                                 "result": "PASS_CONTROL_CHILD" if error is None and index == 0 else "FAIL",
                                 "control": name, "expected_negative": index == 1,
                                 "injected_fault": expected["injected_fault"], "stop_request_expected": True,
                                 "inherited_parent_capture_bytes": capture_offset,
                                 "inherited_parent_decoder_bytes": decoder_offset,
                                 "control_capture_pool_delta": capture_delta,
                                 "control_decoder_pool_delta": decoder_delta,
                                 "control_capture_accounting_scope": "inherited global normal pool: physical native captures plus explicit auxiliary IPC",
                                 "auxiliary_ipc_bytes": ipc_delta,
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
                        parent_guard._fail("count-epoch case observed below-reserve floor at closure")
                child.close()
        row.update({"child_epoch": closed["result"] if closed is not None else None,
                    "observed_error": details["observed_error"] if details else error,
                    "observation": details["observation"] if details else None,
                    "command_count": len(child.commands), "capture_pool_offset": capture_offset,
                    "decoder_pool_offset": decoder_offset,
                    "capture_pool_delta": child.capture_bytes - capture_offset,
                    "decoder_pool_delta": child.decoder_bytes - decoder_offset,
                    "commands": [_command_row(command) for command in child.commands],
                    "auxiliary_ipc_bytes": details["observation"]["auxiliary_ipc_bytes"] if details else 0,
                    "capture_payloads": [], "child_receipt_path": str(child.output / "result.json"),
                    "child_receipt_sha256": closed["sha256"] if closed else None})
        actual_paths = [child.output / "result.json", child.output / "control.stdout", child.output / "control.stderr"]
        for command in child.commands:
            payloads = {}
            _require(command["label"] == "control", "count-epoch child command label differs")
            for stream in ("stdout", "stderr"):
                raw = _small_read(child.output / ("control." + stream), PAYLOAD_LIMIT, resources)
                payload_total += len(raw)
                _require(payload_total <= PAYLOAD_LIMIT and _sha(raw) == command["captured_sha256"][stream],
                         "physical count-epoch capture exceeds bound or differs from closed command")
                _require(raw == (b"REAP_OK\n" if index == 0 and stream == "stdout" else b""),
                         "actual physical count-epoch control stdout/stderr payload differs")
                payloads[stream + "_hex"] = raw.hex()
            row["capture_payloads"].append(payloads)
        for path in actual_paths:
            if not path.exists():
                error = error or "actual count-epoch closed receipt/capture absent"
                continue
            pin = _proof_pin(parent_guard, path, resources.RECEIPT_LIMIT)
            proof_files.append(pin)
            if path == child.output / "result.json" and closed is not None:
                _require(pin["sha256"] == closed["sha256"] and pin["bytes"] == closed["bytes"]
                         and pin["identity"] == closed["identity"], "closed count-epoch child receipt pin changed")
                actual = json.loads(_small_read(path, resources.RECEIPT_LIMIT, resources))
                _require(actual["control"] == name and actual["result"] == closed["result"]
                         and actual["receipt_accounting_verified"] is True,
                         "actual count-epoch child receipt lacks closed self-inclusive accounting")
                _require(_closed_argvs(actual) == [command["argv"] for command in child.commands],
                         "physical closed count-epoch argv vectors differ from actual commands")
                row["child_receipt_bytes"] = pin["bytes"]
        row["elapsed_seconds"] = time.monotonic() - case_started
        _recheck_fixture(parent_guard, fixture)
        parent_guard.check()
        _require(parent_guard.count() - initial_bytes <= FIXTURE_BYTES_LIMIT,
                 "actual cumulative count-epoch cases exceed internal8MiB profile")
        if (error is None and closed is not None and row["child_epoch"] == expected["child_epoch"]
                and row["command_count"] == 1 and row["elapsed_seconds"] <= CASE_SECONDS):
            row["result"] = "PASS"
        else:
            row["error"] = error or "closed count-epoch child epoch/count/case wall bound differs"
        cases.append(row)
        if row["result"] != "PASS":
            break
    _require(parent_guard.pin(source_path, maximum=SOURCE_PIN_LIMIT) == source_pin,
             "resource source changed across actual count-epoch controls")
    _require(parent_guard.pin(helper_path, maximum=SOURCE_PIN_LIMIT) == helper_pin,
             "count-epoch helper source changed across actual cases")
    _recheck_fixture(parent_guard, fixture)
    for before in proof_files:
        _require(_proof_pin(parent_guard, Path(before["path"]), resources.RECEIPT_LIMIT) == before,
                 "actual selected count-epoch text proof changed before return")
    _require(payload_total + charged_ipc == charged_capture and charged_decoder == 0,
             "physical native count-epoch captures plus explicit auxiliary IPC differ from inherited pools")
    _require(len(parent_guard.commands) == parent_commands_before,
             "count-epoch driver unexpectedly added a parent command")
    parent_guard.check()
    elapsed = time.monotonic() - started
    failures = sum(row["result"] != "PASS" for row in cases)
    if elapsed > TOTAL_SECONDS:
        failures += 1
    passed = len(cases) == len(CONTROL_NAMES) and failures == 0
    _require(not passed or len(proof_files) == 6, "two count-epoch cases require exact6 text proof paths")
    return {"schema": REPORT_SCHEMA, "result": "PASS_COUNT_EPOCH_CONTROLS_ONLY" if passed else "FAIL",
            "completed": len(cases), "failures": failures if not passed else 0,
            "cases": cases, "fixture_build": fixture, "proof_files": proof_files,
            "resource_source": source_pin, "control_source": helper_pin,
            "resource_source_before_after_equal": True, "control_source_before_after_equal": True,
            "fixture_source_before_after_equal": True, "fixture_before_after_equal": True,
            "actual_controls_execution_verified": len(cases) == len(CONTROL_NAMES),
            "capture_bytes_charged_to_parent": charged_capture,
            "raw_bytes_charged_to_parent": charged_decoder, "capture_payload_bytes": payload_total,
            "auxiliary_ipc_bytes_charged_to_parent": charged_ipc,
            "capture_charge_scope": "native physical captures plus explicit parent-side auxiliary IPC",
            "case_pool_charges_exclude_parent_prepare_commands": True,
            "parent_commands_added": False, "parent_command_count_before": parent_commands_before,
            "parent_command_count_after": len(parent_guard.commands),
            "fixture_bytes_limit": FIXTURE_BYTES_LIMIT, "elapsed_seconds": elapsed,
            "case_timeout_seconds": CASE_SECONDS, "total_timeout_seconds": TOTAL_SECONDS,
            "source_input_count_delta": 1, "original_production_and_support_sources_changed": False,
            "expected_negative_commands_added_to_parent": False,
            "unknown_actor_control_ownership_is_not_production_ownership_attestation": True,
            "count_epoch_recovery_is_not_production_exit_cause_attestation": True,
            "host_elf_object_binary_transfer_authorized": False,
            "tool_dynamic_runtime_closure_verified": False,
            "escaped_writers_excluded_verified": False, "continuous_group_stop_verified": False,
            "filesystem_quota_verified": False, "native_execution_verified": False,
            "windows98_integration_verified": False, "tls_execution_verified": False}
