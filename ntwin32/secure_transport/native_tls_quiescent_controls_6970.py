# SPDX-License-Identifier: GPL-2.0-only
"""Explicit hosted controls for the new TLS guard's owned-group observations.

Importing this file runs no control.  The build's verified-buffer loader must
bind this file and the resource module before calling run_controls directly.
The parent must not wrap these controls in parent_guard.run(): each actual
child Guard deliberately owns its own session.  Expected FAIL child epochs
remain separate from the production parent's successful command inventory.

The process controls use actual STOP/CONT, forks, threads and file replacement.
Four boundary controls inject observation/pending-byte/consumer faults; the two
inode controls perform real rename operations at a deterministic stat boundary.
They test the unchanged production predicates rather than copying their model.
No control proves escape containment, continuous stop, quota, Windows or TLS.
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

CONTROL_NAMES = (
    "positive-atomic-rename",
    "positive-multithread-late-fork",
    "positive-zombie-leader-pipe-child",
    "positive-nested-check-holds-pause",
    "negative-malformed-observer",
    "negative-unconfirmed-task",
    "negative-paused-pending-cap",
    "negative-paused-consumer-exception",
    "negative-file-inode-substitution",
    "negative-directory-inode-substitution",
)
CONTROL_EXPECTATIONS = {
    name: {"child_epoch": "PASS_CONTROL_CHILD" if index < 4 else "FAIL",
           "command_count": 1 if index < 8 else 0,
           "injected_fault": index >= 4,
           "reason": (
               None if index < 4 else
               "invalid bounded group observation schema" if index == 4 else
               "owned group stop confirmation exceeded one second" if index == 5 else
               "recursive output plus pending bytes exceeds 32 MiB" if index == 6 else
               "CONTROL_CONSUMER_EXCEPTION" if index == 7 else
               "observed file inode/type/link changed" if index == 8 else
               "observed named directory identity changed")}
    for index, name in enumerate(CONTROL_NAMES)
}
FIXTURE_BYTES_LIMIT = 512 * 1024
PAYLOAD_LIMIT = 4096
CASE_SECONDS = 5.0
TOTAL_SECONDS = 60.0

# Every pathname below is relative to that case's fresh Guard root.  The fixed
# scripts retain <= 16 KiB per case; replacement never accumulates old files.
ATOMIC_SCRIPT = r'''import os,time
for i in range(160):
    with open("replacement","wb") as f:f.write(bytes([i%251])*2048)
    os.replace("replacement","rotating")
    time.sleep(.002)
os.write(1,b"ATOMIC_OK\n")
'''
THREAD_FORK_SCRIPT = r'''import os,time,threading
pid=os.fork()
if pid==0:
    time.sleep(.05)
    late=os.fork()
    if late==0:
        for i in range(100):
            with open("fork-temp","wb") as f:f.write(bytes([i%251])*256)
            os.replace("fork-temp","forked")
            time.sleep(.002)
        os._exit(0)
    got,status=os.waitpid(late,0)
    os._exit(0 if got==late and status==0 else 3)
def writer(n):
    for i in range(100):
        with open("thread-temp-"+str(n),"wb") as f:f.write(bytes([n+i%200])*256)
        os.replace("thread-temp-"+str(n),"thread-"+str(n))
        time.sleep(.002)
threads=[threading.Thread(target=writer,args=(n,)) for n in range(3)]
for t in threads:t.start()
for t in threads:t.join()
got,status=os.waitpid(pid,0)
if got!=pid or status!=0:os._exit(3)
os.write(1,b"THREAD_FORK_OK\n")
'''
ZOMBIE_SCRIPT = r'''import os,time
pid=os.fork()
if pid:
    time.sleep(.04)
    os._exit(0)
for i in range(160):
    with open("pipe-child-temp","wb") as f:f.write(bytes([i%251])*128)
    os.replace("pipe-child-temp","pipe-child")
    time.sleep(.003)
os.write(1,b"ZOMBIE_PIPE_OK\n")
os._exit(0)
'''
WAIT_SCRIPT = r'''import os,time
for i in range(1500):
    with open("waiting-temp","wb") as f:f.write(bytes([i%251])*128)
    os.replace("waiting-temp","waiting")
    time.sleep(.002)
'''
STREAM_SCRIPT = r'''import os,time
os.write(1,b"CONTROL_STREAM\n")
for i in range(1500):
    with open("stream-temp","wb") as f:f.write(bytes([i%251])*128)
    os.replace("stream-temp","streaming")
    time.sleep(.002)
'''


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _require(condition, message):
    if not condition:
        raise AssertionError(message)


def _small_read(path, maximum, resources):
    """Read only a fresh controlled file, with held/named full-stat identity."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        _require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                 and 0 <= before.st_size <= maximum, "control regular-file read bound")
        raw = bytearray()
        while True:
            block = os.read(fd, 4096)
            if not block:
                break
            raw.extend(block)
            _require(len(raw) <= maximum, "control file grew beyond bound")
        _require(len(raw) == before.st_size
                 and resources.identity(os.fstat(fd)) == resources.identity(before)
                 and resources.identity(Path(path).lstat()) == resources.identity(before),
                 "control file changed during actual readback")
        return bytes(raw)
    finally:
        os.close(fd)


def _stopped(snapshot):
    return (isinstance(snapshot, dict) and isinstance(snapshot.get("tasks"), list)
            and bool(snapshot["tasks"])
            and all(isinstance(row, dict) and row.get("state") in ("T", "Z")
                    for row in snapshot["tasks"]))


class _Monitor:
    """Observe actual production scan data; inject only the named boundaries."""
    def __init__(self, guard, resources, mode):
        self.guard, self.resources, self.mode = guard, resources, mode
        self.original = guard._group_observer
        self.original_killpg = resources.os.killpg
        self.entered = False
        self.metrics = {"scans": 0, "paused_scans": 0, "maximum_members": 0,
                        "maximum_tasks": 0, "zombie_leader_live_member": False,
                        "nested_checks": 0, "nested_pause_retained": False,
                        "fault_injections": 0, "early_continue_requests": 0}

    def __enter__(self):
        monitor = self

        def observe(_self, proc):
            snapshot = monitor.original(proc)
            monitor.metrics["scans"] += 1
            if isinstance(snapshot, dict):
                members, tasks = snapshot.get("members", []), snapshot.get("tasks", [])
                if isinstance(members, list):
                    monitor.metrics["maximum_members"] = max(monitor.metrics["maximum_members"], len(members))
                if isinstance(tasks, list):
                    monitor.metrics["maximum_tasks"] = max(monitor.metrics["maximum_tasks"], len(tasks))
                leader = snapshot.get("leader")
                if (isinstance(leader, dict) and leader.get("state") == "Z"
                        and any(isinstance(row, dict) and row.get("pid") != proc.pid
                                and row.get("state") != "Z" for row in members)):
                    monitor.metrics["zombie_leader_live_member"] = True
            depth = monitor.guard._quiescence_depth
            if depth > 0:
                _require(_stopped(snapshot), "verified pause contains running/unconfirmed task")
                _require(monitor.guard._active_group is not None
                         and monitor.guard._active_group.paused
                         and proc.returncode is None, "pause lost unreaped group identity")
                monitor.metrics["paused_scans"] += 1
                if monitor.mode == "nested" and not monitor.entered and not monitor.metrics["nested_checks"]:
                    monitor.entered = True
                    try:
                        monitor.guard.check()
                        monitor.metrics["nested_checks"] += 1
                        after = monitor.original(proc)
                        _require(monitor.guard._quiescence_depth >= depth and _stopped(after),
                                 "nested count resumed the outer paused group")
                        monitor.metrics["nested_pause_retained"] = True
                    finally:
                        monitor.entered = False
                if monitor.mode == "cap" and not monitor.entered:
                    monitor.entered = True
                    monitor.metrics["fault_injections"] += 1
                    try:
                        monitor.guard.check(monitor.resources.LIMIT + 1)
                    finally:
                        monitor.entered = False
                if monitor.mode == "consumer" and not monitor.entered:
                    monitor.metrics["fault_injections"] += 1
                    raise RuntimeError("CONTROL_CONSUMER_EXCEPTION")
            if monitor.mode == "malformed":
                monitor.metrics["fault_injections"] += 1
                return {"leader": None, "members": [], "tasks": [], "stable": "invalid"}
            if monitor.mode == "unconfirmed":
                copied = {**snapshot, "tasks": [dict(row) for row in snapshot["tasks"]]}
                _require(bool(copied["tasks"]), "unconfirmed control requires actual task")
                copied["tasks"][0]["state"] = "R"
                monitor.metrics["fault_injections"] += 1
                return copied
            return snapshot

        def killpg(pgid, number):
            active = monitor.guard._active_group
            if (number == signal.SIGCONT and active is not None
                    and pgid == active.proc.pid and monitor.guard._quiescence_depth > 0):
                monitor.metrics["early_continue_requests"] += 1
                raise AssertionError("SIGCONT requested while a nested/outer observation still owns pause")
            return monitor.original_killpg(pgid, number)

        self.guard._group_observer = types.MethodType(observe, self.guard)
        self.resources.os.killpg = killpg
        return self

    def __exit__(self, *_):
        self.guard._group_observer = self.original
        self.resources.os.killpg = self.original_killpg


def _run_process(child, resources, python_path, name):
    index = CONTROL_NAMES.index(name)
    mode = {3: "nested", 4: "malformed", 5: "unconfirmed", 6: "cap"}.get(index, "observe")
    script = {0: ATOMIC_SCRIPT, 1: THREAD_FORK_SCRIPT, 2: ZOMBIE_SCRIPT,
              3: ATOMIC_SCRIPT, 7: STREAM_SCRIPT}.get(index, WAIT_SCRIPT)
    expected_stdout = {0: b"ATOMIC_OK\n", 1: b"THREAD_FORK_OK\n",
                       2: b"ZOMBIE_PIPE_OK\n", 3: b"ATOMIC_OK\n"}.get(index, b"")
    consumer_payload = bytearray()
    observed_error = None
    with _Monitor(child, resources, mode) as monitor:
        def consumer(block):
            _require(len(consumer_payload) + len(block) <= 128,
                     "fixed control stream would exceed 128 bytes")
            if child.capture_bytes + len(block) > resources.CAPTURE_LIMIT:
                raise child._fail("control stream would cross inherited parent capture pool")
            # Retained raw payload is embedded in the control receipt. Charge
            # it to the shared normal pool now, before any subsequent stderr
            # capture; the raw stream also consumes the inherited decoder pool.
            child.capture_bytes += len(block)
            consumer_payload.extend(block)
            monitor.mode = "consumer"
            child.check()
            raise AssertionError("consumer injected pause fault was not encountered")

        try:
            if index == 7:
                result = child.run([python_path, "-B", "-c", script], "control", timeout=3,
                                   stdout_consumer=consumer, raw_limit=128)
            else:
                result = child.run([python_path, "-B", "-c", script], "control", timeout=3)
            _require(index < 4 and result.returncode == 0, "negative process control unexpectedly returned")
            _require(result.stdout == expected_stdout and result.stderr == b"", "actual control process output differs")
        except resources.ResourceFailure as error:
            observed_error = str(error)
            _require(index >= 4 and CONTROL_EXPECTATIONS[name]["reason"] in observed_error,
                     "negative process failed for unrelated reason: " + observed_error[:200])
        _require(len(child.commands) == 1, "control must retain its one actual command")
        command = child.commands[0]
        cleanup = command["group_kill"] == "REQUESTED_BEFORE_REAP"
        if index < 4 and command["group_kill"] == "NO_SUCH_GROUP_BEFORE_REAP":
            cleanup = bool(command.get("quiescence", {}).get("stop_no_live_group_observations"))
        _require(command["reaped"] and cleanup,
                 "control did not clean/reap its owned group before releasing leader")
        _require(child._quiescence_depth == 0 and monitor.metrics["early_continue_requests"] == 0,
                 "control retained pause ownership or resumed too early")
        if index < 4:
            _require(observed_error is None and command["returncode"] == 0 and not command["aborted"],
                     "positive actual command was not successful")
            _require(monitor.metrics["paused_scans"] > 0, "positive did not exercise actual paused traversal")
            _require(command.get("quiescence", {}).get("verified_pauses", 0) > 0
                     and command["quiescence"].get("continue_requests", 0) > 0,
                     "positive command lacks actual pause/continue evidence")
            if index == 1:
                _require(monitor.metrics["maximum_members"] >= 3 and monitor.metrics["maximum_tasks"] >= 5,
                         "actual multithread/fork observation was not collected")
            if index == 2:
                _require(monitor.metrics["zombie_leader_live_member"], "quick leader exit with live pipe child not observed")
            if index == 3:
                _require(monitor.metrics["nested_checks"] == 1 and monitor.metrics["nested_pause_retained"],
                         "nested actual check did not retain the outer pause")
        else:
            _require(observed_error is not None and command["returncode"] == -signal.SIGKILL and command["aborted"],
                     "negative did not kill/reap actual owned command with expected failure")
            _require(monitor.metrics["fault_injections"] > 0, "named injected boundary was not reached")
            _require(command.get("quiescence", {}).get("failure_stop_retained_until_owned_kill") is True,
                     "failed paused group was not held for owned kill")
            if index == 7:
                _require(bytes(consumer_payload) == b"CONTROL_STREAM\n"
                         and command["full_stdout_sha256"] == _sha(bytes(consumer_payload)),
                         "actual raw consumer payload/hash differs")
    return {"observation": dict(monitor.metrics), "observed_error": observed_error,
            "consumer_payload": bytes(consumer_payload)}


def _substitute(child, resources, directory):
    """Actual rename at stat #2, OUTSIDE a command, with original predicates."""
    target = "observed" if directory else "victim"
    if directory:
        os.mkdir(child.output / target, 0o700)
        child.write(child.output / target / "sentinel", b"old directory\n")
    else:
        child.write(child.output / target, b"old inode\n")
        child.write(child.output / "replacement", b"new inode\n")
    original = resources.os.stat
    calls = injections = 0

    def stat_at_boundary(path, *args, **kwargs):
        nonlocal calls, injections
        if path == target and kwargs.get("dir_fd") is not None:
            calls += 1
            if calls == 2:
                if directory:
                    os.rename(child.output / target, child.output / "displaced")
                    os.mkdir(child.output / target, 0o700)
                    with open(child.output / target / "sentinel", "xb") as stream:
                        stream.write(b"new directory\n")
                else:
                    os.replace(child.output / "replacement", child.output / target)
                injections += 1
        return original(path, *args, **kwargs)

    observed = None
    resources.os.stat = stat_at_boundary
    try:
        try:
            child.check()
        except resources.ResourceFailure as error:
            observed = str(error)
    finally:
        resources.os.stat = original
    name = CONTROL_NAMES[9 if directory else 8]
    _require(injections == 1 and observed is not None
             and CONTROL_EXPECTATIONS[name]["reason"] in observed,
             "real rename was not rejected by its original named-inode predicate")
    _require(not child.commands, "stat substitution must not invent an executed command")
    return {"observation": {"fault_injections": injections, "stat_boundary_calls": calls,
                            "actual_rename_performed": True},
            "observed_error": observed, "consumer_payload": b""}


def _files(root):
    """Exact generated case members only; no upload or broad-retention policy."""
    paths = []
    for directory, dirs, files in os.walk(root, followlinks=False):
        for name in dirs:
            s = (Path(directory) / name).lstat()
            _require(stat.S_ISDIR(s.st_mode) and not stat.S_ISLNK(s.st_mode), "unsafe control directory")
        for name in files:
            path = Path(directory) / name
            s = path.lstat()
            _require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, "unsafe control proof file")
            paths.append(path)
            _require(len(paths) <= 32, "control file inventory bound")
    return sorted(paths)


def run_controls(parent_guard, resources_module, python_path):
    """Direct hosted driver.  A returned PASS requires ten actual closed cases."""
    resources = resources_module
    started = time.monotonic()
    _require(not parent_guard._running and parent_guard._quiescence_depth == 0,
             "controls must be directly driven outside a parent command")
    _require(hasattr(resources.Guard, "_group_observer"), "new production quiescence API absent")
    python_path = os.fspath(python_path)
    _require(Path(python_path).is_absolute(), "actual selected Python path must be absolute")
    python_pin = parent_guard.pin(Path(python_path), maximum=256 * 1024**2, readonly_system_input=True)
    source_path = Path(resources.__file__)
    source_pin = parent_guard.pin(source_path, maximum=200 * 1024)
    _require(getattr(resources, "__6970_bound_source_sha256__", None) == source_pin["sha256"]
             and getattr(resources, "__6970_bound_source_bytes__", None) == source_pin["bytes"],
             "resource module has no matching verified-buffer loader envelope")
    helper_path = Path(__file__)
    helper_pin = parent_guard.pin(helper_path, maximum=200 * 1024)
    _require(globals().get("__6970_bound_source_sha256__") == helper_pin["sha256"]
             and globals().get("__6970_bound_source_bytes__") == helper_pin["bytes"],
             "control helper has no matching verified-buffer loader envelope")
    _require(parent_guard.capture_bytes + PAYLOAD_LIMIT <= resources.CAPTURE_LIMIT,
             "four-KiB control payload reservation does not fit shared normal pool")
    parent_guard.check(FIXTURE_BYTES_LIMIT)
    initial = parent_guard.count()
    cases, proof_files = [], []
    payload_total = charged_capture = charged_decoder = 0
    expected_receipt_result = "PASS_CONTROL_CHILD"
    for index, name in enumerate(CONTROL_NAMES):
        _require(time.monotonic() - started < TOTAL_SECONDS, "control total wall deadline")
        parent_guard.check(FIXTURE_BYTES_LIMIT)
        case_started = time.monotonic()
        child = resources.Guard(parent_guard.tmp / ("quiescent-%02d" % index), parent_guard.repository)
        capture_offset, decoder_offset = parent_guard.capture_bytes, parent_guard.decoder_bytes
        child.capture_bytes = capture_offset
        child.decoder_bytes = decoder_offset
        row = {"name": name, "result": "FAIL", "executed": True,
               "expected_child_epoch": CONTROL_EXPECTATIONS[name]["child_epoch"],
               "injected_fault": CONTROL_EXPECTATIONS[name]["injected_fault"],
               "expected_negative_reason": CONTROL_EXPECTATIONS[name]["reason"],
               "expected_command_count": CONTROL_EXPECTATIONS[name]["command_count"]}
        details, error, closed = None, None, None
        try:
            if index < 8:
                details = _run_process(child, resources, python_path, name)
            else:
                details = _substitute(child, resources, index == 9)
        except BaseException as failure:
            error = type(failure).__name__ + ": " + str(failure)[:300]
        finally:
            # No child command is copied into production commands: expected
            # killed negative commands are evidence in a separate FAIL epoch.
            try:
                _require(child.capture_bytes >= capture_offset and child.decoder_bytes >= decoder_offset,
                         "inherited child pool counter moved backwards")
                capture_delta, decoder_delta = child.capture_bytes - capture_offset, child.decoder_bytes - decoder_offset
                parent_guard.capture_bytes = child.capture_bytes
                charged_capture += capture_delta
                parent_guard.decoder_bytes = child.decoder_bytes
                charged_decoder += decoder_delta
                if child.minimum_free is not None:
                    parent_guard.minimum_free = (child.minimum_free if parent_guard.minimum_free is None
                                                 else min(parent_guard.minimum_free, child.minimum_free))
                if (parent_guard.capture_bytes > resources.CAPTURE_LIMIT
                        or parent_guard.decoder_bytes > resources.DECODER_LIMIT):
                    raise parent_guard._fail("nested controls crossed parent capture/raw allowance")
                if parent_guard.minimum_free < resources.RESERVE:
                    raise parent_guard._fail("nested control observed a below-reserve floor")
                child_receipt = {"schema": "native-tls-quiescent-control-child-6970.v1",
                                 "result": expected_receipt_result if error is None and index < 4 else "FAIL",
                                 "control": name, "expected_negative": index >= 4,
                                 "inherited_parent_capture_bytes": capture_offset,
                                 "inherited_parent_decoder_bytes": decoder_offset,
                                 "control_capture_pool_delta": capture_delta,
                                 "control_decoder_pool_delta": decoder_delta,
                                 "normal_pool_includes_retained_consumer_payload": True,
                                 "control_capture_accounting_scope": "inherited global pools; per-command captures are actual case bytes",
                                 "observed_control_error": error,
                                 "actual_control_observation": details["observation"] if details else None,
                                 "native_execution_verified": False,
                                 "windows98_integration_verified": False, "tls_execution_verified": False}
                if details is not None:
                    child_receipt["expected_fault_observed"] = details["observed_error"]
                    child_receipt["consumer_payload_hex"] = details["consumer_payload"].hex()
                closed = child.close_receipt(child_receipt, child.output / "result.json")
            except BaseException as failure:
                error = error or (type(failure).__name__ + ": " + str(failure)[:300])
            finally:
                if child.minimum_free is not None:
                    parent_guard.minimum_free = (child.minimum_free if parent_guard.minimum_free is None
                                                 else min(parent_guard.minimum_free, child.minimum_free))
                    if child.minimum_free < resources.RESERVE:
                        parent_guard._fail("nested control observed a below-reserve floor at closure")
                child.close()
        row["child_epoch"] = closed["result"] if closed is not None else None
        row["observed_error"] = details["observed_error"] if details else error
        row["observation"] = details["observation"] if details else None
        row["command_count"] = len(child.commands)
        row["capture_pool_offset"] = capture_offset
        row["decoder_pool_offset"] = decoder_offset
        row["capture_pool_delta"] = child.capture_bytes - capture_offset
        row["decoder_pool_delta"] = child.decoder_bytes - decoder_offset
        row["commands"] = []
        row["capture_payloads"] = []
        for command in child.commands:
            compact = {key: command[key] for key in ("label", "returncode", "reaped", "aborted", "group_kill",
                       "nonreaping_leader_exit_observed", "full_stdout_bytes", "full_stderr_bytes",
                       "full_stdout_sha256", "full_stderr_sha256", "captured_bytes", "captured_sha256",
                       "raw_stdout_stream", "stdout_delivered_to_consumer_bytes")}
            compact["argv_sha256"] = _sha(json.dumps(command["argv"], separators=(",", ":")).encode())
            compact["quiescence"] = command.get("quiescence")
            row["commands"].append(compact)
            payloads = {}
            for stream in ("stdout", "stderr"):
                path = child.output / (command["label"] + "." + stream)
                raw = _small_read(path, PAYLOAD_LIMIT, resources)
                payload_total += len(raw)
                _require(payload_total <= PAYLOAD_LIMIT, "total actual retained control payload exceeds 4 KiB")
                _require(_sha(raw) == command["captured_sha256"][stream], "actual nested capture SHA differs")
                payloads[stream + "_hex"] = raw.hex()
            row["capture_payloads"].append(payloads)
        if details is not None:
            payload_total += len(details["consumer_payload"])
            _require(payload_total <= PAYLOAD_LIMIT, "total control stream/capture payload exceeds 4 KiB")
            row["consumer_payload_hex"] = details["consumer_payload"].hex()
            row["stream_consumer_raised_before_delivery_commit"] = bool(details["consumer_payload"])
        for path in _files(child.output):
            pin = parent_guard.pin(path, maximum=FIXTURE_BYTES_LIMIT)
            proof_files.append({"path": str(path), "relative_path": str(path.relative_to(parent_guard.output)), **pin})
            if closed is not None and path == child.output / "result.json":
                _require(pin["sha256"] == closed["sha256"] and pin["bytes"] == closed["bytes"]
                         and pin["identity"] == closed["identity"], "closed child receipt pin changed")
                actual_receipt = json.loads(_small_read(path, FIXTURE_BYTES_LIMIT, resources))
                _require(actual_receipt["control"] == name and actual_receipt["result"] == closed["result"]
                         and actual_receipt["receipt_accounting_verified"] is True,
                         "actual child receipt lacks closed self-inclusive accounting")
        row["child_receipt_path"] = str(child.output / "result.json")
        row["child_receipt_sha256"] = closed["sha256"] if closed else None
        row["elapsed_seconds"] = time.monotonic() - case_started
        parent_guard.check()
        _require(parent_guard.count() - initial <= FIXTURE_BYTES_LIMIT, "actual cumulative control files exceed 512 KiB")
        if (error is None and closed is not None
                and row["child_epoch"] == row["expected_child_epoch"]
                and row["command_count"] == row["expected_command_count"]
                and row["elapsed_seconds"] <= CASE_SECONDS):
            row["result"] = "PASS"
        else:
            row["error"] = error or "closed child epoch/count/case wall bound differs"
        cases.append(row)
        if row["result"] != "PASS":
            break
    _require(parent_guard.pin(source_path, maximum=200 * 1024) == source_pin,
             "resource source changed across actual controls")
    _require(parent_guard.pin(helper_path, maximum=200 * 1024) == helper_pin,
             "control helper source changed across actual controls")
    _require(parent_guard.pin(Path(python_path), maximum=256 * 1024**2,
                              readonly_system_input=True) == python_pin,
             "selected Python changed across actual controls")
    parent_guard.check()
    elapsed = time.monotonic() - started
    _require(payload_total == charged_capture,
             "actual capture/consumer payload lengths differ from parent charged normal bytes")
    failures = sum(row["result"] != "PASS" for row in cases)
    if elapsed > TOTAL_SECONDS:
        failures += 1
    passed = len(cases) == len(CONTROL_NAMES) and failures == 0 and elapsed <= TOTAL_SECONDS
    return {"schema": "native-tls-quiescent-controls-6970.v1",
            "result": "PASS_QUIESCENT_GUARD_CONTROLS_ONLY" if passed else "FAIL",
            "completed": len(cases), "failures": failures if not passed else 0,
            "cases": cases, "proof_files": proof_files,
            "resource_source_before_after_equal": True, "resource_source": source_pin,
            "control_source_before_after_equal": True, "control_source": helper_pin,
            "selected_python_before_after_equal": True, "selected_python": python_pin,
            "actual_controls_execution_verified": True,
            "capture_bytes_charged_to_parent": charged_capture,
            "raw_bytes_charged_to_parent": charged_decoder,
            "capture_payload_bytes": payload_total,
            "fixture_bytes_limit": FIXTURE_BYTES_LIMIT, "elapsed_seconds": elapsed,
            "case_timeout_seconds": CASE_SECONDS, "total_timeout_seconds": TOTAL_SECONDS,
            "expected_negative_commands_added_to_parent": False,
            "fault_injection_is_not_unmanaged_writer_attestation": True,
            "escaped_writers_excluded_verified": False, "continuous_group_stop_verified": False,
            "filesystem_quota_verified": False, "native_execution_verified": False,
            "windows98_integration_verified": False, "tls_execution_verified": False}
