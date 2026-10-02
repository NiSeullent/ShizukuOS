#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Observed resource core for the separate 6970 native TLS build profile.

This is not a filesystem quota, continuous minimum-free guarantee, complete
toolchain attestation, or native/TLS execution proof. Named logical files and
50-ms observations cannot cover every transient/unlinked-file allocation.
The older bridge guard and its 8-MiB profile remain separate and unchanged.
No command runs on import. Controls below are a hosted-only test plan.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import signal
import stat
import subprocess
import time

RESERVE = 20 * 1024 ** 3
LIMIT = 32 * 1024 ** 2
CAPTURE_LIMIT = 256 * 1024
RECEIPT_LIMIT = 1024 ** 2
RAW_LIMIT = 16 * 1024 ** 2
DECODER_LIMIT = 64 * 1024 ** 2
INPUT_LIMIT = 256 * 1024 ** 2
MAX_DEPTH = 16
MAX_DIRECTORIES = 256
MAX_FILES = 8192
SAMPLE_SECONDS = 0.05
COMMAND_TIMEOUT_LIMIT = 360  # Explicit new TLS profile; older bridge stays at 60.
QUIESCENCE_TIMEOUT = 1.0
PROC_ENTRY_LIMIT = 4096
GROUP_MEMBER_LIMIT = 128
GROUP_TASK_LIMIT = 1024
PROC_STAT_LIMIT = 8192
GROUP_DIAGNOSTIC_ROW_LIMIT = 8
GROUP_FAILURE_DIAGNOSTIC_LIMIT = 16 * 1024
INVALID_RECEIPT_SCHEMA = "native-tls-resource-invalid-receipt-v1"


class ResourceFailure(RuntimeError):
    """An observed failure remains latched for the whole new proof epoch."""


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_nlink, s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def _inode(s):
    return (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid)


def _path(path):
    value = os.fspath(path)
    if not isinstance(value, str) or not value or any(c in value for c in "\0\r\n"):
        raise ResourceFailure("invalid path text")
    if ".." in value.split("/"):
        raise ResourceFailure("parent path traversal refused")
    return Path(os.path.abspath(value))


def _directory(fd, *, device=None, owned=False):
    s = os.fstat(fd)
    if (not stat.S_ISDIR(s.st_mode) or (device is not None and s.st_dev != device)
            or (owned and (s.st_uid != os.getuid() or s.st_mode & 0o022))):
        raise ResourceFailure("unsafe directory owner/type/filesystem")
    return s


def _absolute_directory(path, *, readonly_system_input=False):
    """Open every component without following symlinks; caller owns the FD."""
    path = _path(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if readonly_system_input:
            initial = _directory(fd)
            if initial.st_uid != 0 or initial.st_mode & 0o022:
                raise ResourceFailure("system input ancestor must be root-owned and not writable by group/other")
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            current = _directory(fd)
            if readonly_system_input and (current.st_uid != 0 or current.st_mode & 0o022):
                raise ResourceFailure("system input ancestor must be root-owned and not writable by group/other")
        if _inode(os.fstat(fd)) != _inode(path.lstat()):
            raise ResourceFailure("absolute directory named identity changed")
        return fd
    except BaseException:
        os.close(fd)
        raise


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        if n <= 0:
            raise ResourceFailure("owned write made no progress")
        view = view[n:]


class _OwnedGroupObservation:
    """Linux observed stop scope; neither a writer census nor a kernel freeze.

    The unreaped Popen leader pins the signal target through normal cleanup.
    Every observed process and thread must be signal-stopped (T) or zombie (Z).
    Tracing-stop (t) is deliberately refused: a tracer owns its restart.
    Escaped descendants and asynchronous kernel writes are not attested.
    """

    def __init__(self, guard, proc, deadline):
        self.guard = guard
        self.proc = proc
        self.deadline = deadline
        self.proc_fd = os.open("/proc", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.paused = False
        self.verified = False
        self.pause_deadline = None
        self.pause_started = None
        self.quiet_snapshot = None
        self.quiet_scan_instability = None
        self.last_scan_instability = None
        self.last_scan_snapshot = None
        self.last_validated_snapshot = None
        self.last_validated_completed_at = None
        self.last_validated_pause_attempt = None
        self.last_validated_pause_iteration = None
        self.last_validated_scan_instability = None
        self.pause_iteration = 0
        self.pause_stop_requests_start = 0
        self.pause_stage = "not_started"
        self.pause_candidate_snapshot = None
        self.telemetry = {"pause_attempts": 0, "verified_pauses": 0,
                          "stop_requests": 0, "continue_requests": 0,
                          "stop_no_live_group_observations": 0,
                          "continue_no_live_group_observations": 0,
                          "maximum_members": 0, "maximum_tasks": 0,
                          "total_pause_seconds": 0.0, "longest_pause_seconds": 0.0,
                          "verified_observation_sha256": None,
                          "observation_digest_scope": "last_completed_postcount_snapshot",
                          "failure_observation": None,
                          "escaped_writers_excluded_verified": False,
                          "continuous_group_stop_verified": False,
                          "failure_stop_retained_until_owned_kill": False,
                          "filesystem_quota_verified": False}
        try:
            leader = self._read_process(proc.pid)[0]
            if (leader["pid"] != proc.pid or leader["pgrp"] != proc.pid
                    or leader["session"] != proc.pid or leader["uid"] != os.getuid()
                    or proc.returncode is not None):
                raise ResourceFailure("owned unreaped session/group leader required")
            self.leader_token = self._token(leader)
        except BaseException:
            os.close(self.proc_fd)
            self.proc_fd = None
            raise

    @staticmethod
    def _token(row):
        return tuple(row[k] for k in ("pid", "startticks", "pgrp", "session", "uid"))

    def check_time(self):
        now = time.monotonic()
        if now > self.deadline:
            raise self.guard._fail("owned command wall timeout crossed during observation")
        if self.pause_deadline is not None and now > self.pause_deadline:
            try:
                self._record_stop_timeout_observation(now)
            except BaseException:
                # Diagnostic failure cannot change the original timeout or
                # its STOP/kill-before-reap cleanup path.
                try:
                    if self.telemetry["failure_observation"] is None:
                        self.telemetry["failure_observation"] = {
                            "scope": "stop_timeout_diagnostic_encoding_refused",
                            "snapshot_temporal_scope": "last_completed_before_timeout",
                            "timeout_instant_snapshot_verified": False,
                            "producer_cause_verified": False, "kernel_cause_verified": False,
                            "new_proc_read_performed_for_diagnostic": False,
                            "retry_or_acceptance_relaxation_applied": False}
                except BaseException:
                    pass
            raise self.guard._fail("owned group stop confirmation exceeded one second")

    def _stat_row(self, directory, expected_pid, *, tgid=None):
        self.check_time()
        fd = os.open("stat", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            raw = os.read(fd, PROC_STAT_LIMIT + 1)
            if len(raw) > PROC_STAT_LIMIT or not raw.endswith(b"\n"):
                raise ResourceFailure("bounded proc stat record required")
        finally:
            os.close(fd)
        end = raw.rfind(b")")
        first = raw.find(b" (")
        if first < 1 or end <= first:
            raise ResourceFailure("malformed proc stat identity")
        try:
            pid = int(raw[:first])
            fields = raw[end + 1:].split()
            if len(fields) < 20:
                raise ValueError("short stat")
            state = fields[0].decode("ascii")
            pgrp, session, ticks = int(fields[2]), int(fields[3]), int(fields[19])
        except (ValueError, UnicodeError) as error:
            raise ResourceFailure("malformed proc stat numeric/state fields") from error
        if (pid != expected_pid or len(state) != 1 or state not in "RSDZTtWXxKPI"
                or pgrp < 0 or session < 0 or ticks < 0):
            raise ResourceFailure("invalid proc stat task identity")
        uid = os.fstat(directory).st_uid
        row = {"pid": pid if tgid is None else tgid, "startticks": ticks,
               "pgrp": pgrp, "session": session, "uid": uid, "state": state}
        if tgid is not None:
            row["tid"] = pid
        return row

    def _read_process(self, pid, *, tasks=False):
        directory = os.open(str(pid), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=self.proc_fd)
        task_root = None
        try:
            row = self._stat_row(directory, pid)
            if not tasks:
                return row, [], True
            task_root = os.open("task", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=directory)
            names = sorted(os.listdir(task_root))
            if len(names) > GROUP_TASK_LIMIT or any(not n.isdigit() for n in names):
                raise ResourceFailure("bounded numeric owned task listing required")
            threads = []
            for name in names:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                dir_fd=task_root)
                try:
                    threads.append(self._stat_row(child, int(name), tgid=pid))
                finally:
                    os.close(child)
            after = self._stat_row(directory, pid)
            stable = (self._token(after) == self._token(row)
                      and sorted(os.listdir(task_root)) == names)
            return after, threads, stable
        finally:
            if task_root is not None:
                os.close(task_root)
            os.close(directory)

    def leader(self):
        if self.proc.returncode is not None or self.proc_fd is None:
            raise self.guard._fail("group observer cannot signal a reaped leader")
        row = self._read_process(self.proc.pid)[0]
        if self._token(row) != self.leader_token:
            raise self.guard._fail("owned group leader identity changed")
        return row

    def observe(self):
        """Only numeric stat metadata; no command line, environment or payload."""
        self.guard._sample()
        leader = self.leader()
        names = sorted(n for n in os.listdir(self.proc_fd) if n.isdigit())
        if len(names) > PROC_ENTRY_LIMIT:
            raise ResourceFailure("proc process-list observation exceeds 4096 entries")
        members, threads = [], []
        stable = True
        instability = {"scope": "last_actual_numeric_proc_scan",
                       "total_events": 0, "classification_counts": {},
                       "events": [], "events_truncated": False}

        def note_instability(pid, reason, classification):
            instability["total_events"] += 1
            counts = instability["classification_counts"]
            counts[classification] = counts.get(classification, 0) + 1
            if len(instability["events"]) < GROUP_DIAGNOSTIC_ROW_LIMIT:
                instability["events"].append({"pid": pid, "reason": reason,
                                              "classification": classification})
            else:
                instability["events_truncated"] = True

        for index, name in enumerate(names):
            self.check_time()
            if index % 32 == 0:
                self.guard._sample()
            pid = int(name)
            initially_classified_owned = False
            try:
                row = self._read_process(pid)[0]
                if row["pgrp"] != self.proc.pid:
                    continue
                initially_classified_owned = True
                row, task_rows, unchanged = self._read_process(pid, tasks=True)
                if row["pgrp"] != self.proc.pid:
                    stable = False
                    note_instability(pid, "group_changed_after_initial_owned_classification",
                                     "after_owned_group_classification")
                    continue
                members.append(row)
                threads.extend(task_rows)
                stable = stable and unchanged
                if not unchanged:
                    note_instability(pid, "owned_task_listing_or_process_token_changed",
                                     "after_owned_group_classification")
            except (FileNotFoundError, ProcessLookupError):
                if pid == self.proc.pid:
                    raise ResourceFailure("owned unreaped leader disappeared during observation")
                stable = False
                note_instability(pid, "numeric_process_or_task_disappeared",
                                 "after_owned_group_classification" if initially_classified_owned
                                 else "before_group_classification_unknown")
                continue
            if len(members) > GROUP_MEMBER_LIMIT or len(threads) > GROUP_TASK_LIMIT:
                raise ResourceFailure("owned group member/task observation bound crossed")
        leader = self.leader()
        observation = {"leader": leader, "members": sorted(members, key=lambda r: r["pid"]),
                       "tasks": sorted(threads, key=lambda r: (r["pid"], r["tid"])),
                       "stable": stable}
        self.last_scan_instability = instability
        self.last_scan_snapshot = observation
        return observation

    def _validated(self, observation):
        if (not isinstance(observation, dict) or set(observation) != {"leader", "members", "tasks", "stable"}
                or not isinstance(observation["stable"], bool)
                or not isinstance(observation["members"], list)
                or not isinstance(observation["tasks"], list)
                or not 1 <= len(observation["members"]) <= GROUP_MEMBER_LIMIT
                or not 1 <= len(observation["tasks"]) <= GROUP_TASK_LIMIT):
            raise ResourceFailure("invalid bounded group observation schema")
        process_keys = {"pid", "startticks", "pgrp", "session", "uid", "state"}
        tagged_rows = [(observation["leader"], process_keys)]
        tagged_rows += [(row, process_keys) for row in observation["members"]]
        tagged_rows += [(row, process_keys | {"tid"}) for row in observation["tasks"]]
        for row, expected in tagged_rows:
            if (not isinstance(row, dict) or set(row) != expected
                    or any(not isinstance(row[k], int) or isinstance(row[k], bool) or row[k] < 0
                           for k in expected - {"state"})
                    or row["pid"] <= 0 or row.get("tid", 1) <= 0
                    or row["pgrp"] != self.proc.pid or row["session"] != self.proc.pid
                    or row["uid"] != os.getuid()
                    or not isinstance(row["state"], str) or row["state"] not in tuple("RSDZTtWXxKPI")):
                raise ResourceFailure("owned group observation identity/state invalid")
            if row["state"] == "t":
                raise ResourceFailure("tracing-stop is not an owned signal-stop")
        members = observation["members"]
        tasks = observation["tasks"]
        pids = [r["pid"] for r in members]
        tids = [r.get("tid") for r in tasks]
        if (len(set(pids)) != len(pids) or None in tids or len(set(tids)) != len(tids)
                or any(r["pid"] not in pids for r in tasks)
                or any(not any(t["pid"] == r["pid"] and t["tid"] == r["pid"]
                               and t["startticks"] == r["startticks"] for t in tasks) for r in members)
                or not any(self._token(r) == self.leader_token for r in members)
                or self._token(observation["leader"]) != self.leader_token):
            raise ResourceFailure("owned group process/task membership identity invalid")
        self.telemetry["maximum_members"] = max(self.telemetry["maximum_members"], len(members))
        self.telemetry["maximum_tasks"] = max(self.telemetry["maximum_tasks"], len(tasks))
        return observation

    def _snapshot(self):
        snapshot = self._validated(self.guard._group_observer(self.proc))
        self.last_validated_snapshot = snapshot
        self.last_validated_completed_at = time.monotonic()
        self.last_validated_pause_attempt = self.telemetry["pause_attempts"]
        self.last_validated_pause_iteration = self.pause_iteration
        self.last_validated_scan_instability = {
            "matches_returned_snapshot": self.last_scan_snapshot == snapshot,
            "metadata": self.last_scan_instability}
        return snapshot

    @staticmethod
    def _quiet(snapshot):
        return snapshot["stable"] and all(r["state"] in ("T", "Z")
                                          for r in snapshot["members"] + snapshot["tasks"])

    def pause(self):
        self.pause_started = time.monotonic()
        self.pause_deadline = min(self.deadline, self.pause_started + QUIESCENCE_TIMEOUT)
        self.telemetry["pause_attempts"] += 1
        self.pause_iteration = 0
        self.pause_stop_requests_start = self.telemetry["stop_requests"]
        self.pause_stage = "pause_entry"
        self.pause_candidate_snapshot = None
        previous = None
        while True:
            self.pause_iteration += 1
            self.pause_candidate_snapshot = previous
            self.pause_stage = "loop_deadline_check"
            self.check_time()
            self.pause_stage = "leader_validation"
            self.leader()
            self.telemetry["stop_requests"] += 1
            self.pause_stage = "stop_signal"
            try:
                os.killpg(self.proc.pid, signal.SIGSTOP)
            except ProcessLookupError:
                # A held zombie leader can outlive every signalable member.
                # Accept no-recipient only with fresh complete all-Z evidence;
                # the same two-scan and post-count checks still apply.
                self.pause_stage = "no_live_recipient_snapshot"
                no_live = self._snapshot()
                if (not no_live["stable"] or any(r["state"] != "Z"
                        for r in no_live["members"] + no_live["tasks"])):
                    raise ResourceFailure("owned group stop had no live recipient without all-zombie evidence")
                self.telemetry["stop_no_live_group_observations"] += 1
            self.paused = True
            self.pause_stage = "stop_confirmation_snapshot"
            current = self._snapshot()
            self.pause_stage = "quiet_candidate_comparison"
            if self._quiet(current) and current == previous:
                self.quiet_snapshot = current
                self.quiet_scan_instability = {
                    "matches_returned_snapshot": self.last_scan_snapshot == current,
                    "metadata": self.last_scan_instability}
                self.verified = True
                self.pause_deadline = None
                self.telemetry["verified_pauses"] += 1
                self.pause_stage = "verified_pause"
                return
            previous = current if self._quiet(current) else None
            self.pause_stage = "existing_between_attempts_sleep"
            time.sleep(0.001)

    def _record_stop_timeout_observation(self, now):
        """Cached completed numeric evidence, never a new timeout-time scan."""
        if self.telemetry["failure_observation"] is not None:
            return
        snapshot = self.last_validated_snapshot
        candidate = self.pause_candidate_snapshot
        samples = []

        def summary(value, retain_samples):
            if value is None:
                return {"available": False}
            raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            counts = {}
            for kind in ("members", "tasks"):
                states = {}
                for row in value[kind]:
                    states[row["state"]] = states.get(row["state"], 0) + 1
                    if retain_samples and len(samples) < GROUP_DIAGNOSTIC_ROW_LIMIT:
                        samples.append({"kind": kind, "row": dict(row)})
                counts[kind] = {"count": len(value[kind]), "state_counts": states}
            return {"available": True,
                    "canonical_full_snapshot_sha256": hashlib.sha256(raw).hexdigest(),
                    "stable": value["stable"],
                    "all_members_and_tasks_T_or_Z": all(row["state"] in ("T", "Z")
                        for row in value["members"] + value["tasks"]),
                    "member_task_state_counts": counts}

        snapshot_summary = summary(snapshot, True)
        scan_instability = self.last_validated_scan_instability
        if scan_instability is not None and scan_instability["metadata"] is not None:
            metadata = scan_instability["metadata"]
            available_rows = GROUP_DIAGNOSTIC_ROW_LIMIT - len(samples)
            retained_events = metadata["events"][:available_rows]
            scan_instability = {
                "matches_returned_snapshot": scan_instability["matches_returned_snapshot"],
                "metadata": {**metadata, "events": retained_events,
                    "events_truncated": (metadata["events_truncated"]
                                         or len(retained_events) < len(metadata["events"]))}}
        diagnostic = {
            "scope": "first_stop_confirmation_timeout_cached_completed_numeric_metadata_only",
            "snapshot_temporal_scope": "last_completed_before_timeout",
            "timeout_instant_snapshot_verified": False,
            "last_completed_validated_snapshot": snapshot_summary,
            "last_completed_snapshot_at_monotonic": self.last_validated_completed_at,
            "last_completed_snapshot_age_seconds": (
                None if self.last_validated_completed_at is None
                else max(0.0, now - self.last_validated_completed_at)),
            "last_completed_snapshot_pause_attempt": self.last_validated_pause_attempt,
            "last_completed_snapshot_pause_iteration": self.last_validated_pause_iteration,
            "last_completed_actual_scan_instability": scan_instability,
            "last_quiet_candidate_for_current_attempt": summary(candidate, False),
            "last_completed_equals_current_attempt_quiet_candidate": (
                None if snapshot is None or candidate is None else snapshot == candidate),
            "sampled_rows": samples,
            "sampled_row_total": (0 if snapshot is None else
                                  len(snapshot["members"]) + len(snapshot["tasks"])),
            "sampled_rows_truncated": (False if snapshot is None else
                len(snapshot["members"]) + len(snapshot["tasks"]) > len(samples)),
            "sampled_numeric_rows_and_instability_events_share_limit": True,
            "timeout_checked_at_monotonic": now,
            "pause_started_at_monotonic": self.pause_started,
            "pause_deadline_monotonic": self.pause_deadline,
            "command_deadline_monotonic": self.deadline,
            "pause_elapsed_seconds": (None if self.pause_started is None
                                       else max(0.0, now - self.pause_started)),
            "current_pause_attempt": self.telemetry["pause_attempts"],
            "current_pause_iteration": self.pause_iteration,
            "current_pause_stop_requests": self.telemetry["stop_requests"] - self.pause_stop_requests_start,
            "total_stop_requests": self.telemetry["stop_requests"],
            "stage": self.pause_stage,
            "diagnostic_row_limit": GROUP_DIAGNOSTIC_ROW_LIMIT,
            "diagnostic_byte_limit": GROUP_FAILURE_DIAGNOSTIC_LIMIT,
            "producer_cause_verified": False, "kernel_cause_verified": False,
            "new_proc_read_performed_for_diagnostic": False,
            "retry_or_acceptance_relaxation_applied": False}
        raw = json.dumps(diagnostic, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > GROUP_FAILURE_DIAGNOSTIC_LIMIT:
            diagnostic = {"scope": "stop_timeout_diagnostic_size_refused",
                          "complete_diagnostic_sha256": hashlib.sha256(raw).hexdigest(),
                          "complete_diagnostic_bytes": len(raw),
                          "diagnostic_byte_limit": GROUP_FAILURE_DIAGNOSTIC_LIMIT,
                          "snapshot_temporal_scope": "last_completed_before_timeout",
                          "timeout_instant_snapshot_verified": False,
                          "producer_cause_verified": False, "kernel_cause_verified": False,
                          "new_proc_read_performed_for_diagnostic": False,
                          "retry_or_acceptance_relaxation_applied": False}
        self.telemetry["failure_observation"] = diagnostic

    def verify_paused(self):
        self.check_time()
        if not self.paused or not self.verified:
            raise ResourceFailure("recursive observation requires a verified owned stop scope")
        current = self._snapshot()
        if not self._quiet(current) or current != self.quiet_snapshot:
            self._record_failure_observation(current)
            raise ResourceFailure("owned group changed or resumed during recursive observation")
        raw = json.dumps(current, sort_keys=True, separators=(",", ":")).encode()
        self.telemetry["verified_observation_sha256"] = hashlib.sha256(raw).hexdigest()

    def _record_failure_observation(self, current):
        """First failure only; bounded metadata never changes acceptance/retry."""
        if self.telemetry["failure_observation"] is not None:
            return
        reference = self.quiet_snapshot
        counts, changes, total = {}, [], 0
        for kind, keys in (("members", ("pid",)), ("tasks", ("pid", "tid"))):
            before = {tuple(row[key] for key in keys): row for row in reference[kind]}
            after = {tuple(row[key] for key in keys): row for row in current[kind]}
            added, removed = set(after) - set(before), set(before) - set(after)
            changed = {key for key in set(before) & set(after) if before[key] != after[key]}
            counts[kind] = {"reference_count": len(before), "current_count": len(after),
                            "added": len(added), "removed": len(removed), "changed": len(changed)}
            for key in sorted(added | removed | changed):
                total += 1
                if len(changes) < GROUP_DIAGNOSTIC_ROW_LIMIT:
                    changes.append({"kind": kind, "key": list(key),
                                    "reference": before.get(key), "current": after.get(key)})

        def snapshot_summary(snapshot):
            raw = json.dumps(snapshot, sort_keys=True, separators=(",", ":")).encode()
            return {"canonical_full_snapshot_sha256": hashlib.sha256(raw).hexdigest(),
                    "stable": snapshot["stable"],
                    "all_members_and_tasks_T_or_Z": all(row["state"] in ("T", "Z")
                        for row in snapshot["members"] + snapshot["tasks"]),
                    "leader": dict(snapshot["leader"])}

        diagnostic = {"scope": "first_verify_paused_mismatch_numeric_metadata_only",
                      "reference": snapshot_summary(reference),
                      "current": snapshot_summary(current),
                      "snapshots_equal": reference == current,
                      "member_task_difference_counts": counts,
                      "member_task_differences": changes,
                      "member_task_difference_total": total,
                      "member_task_differences_truncated": total > len(changes),
                      "reference_last_actual_scan_instability": self.quiet_scan_instability,
                      "current_last_actual_scan_instability": {
                          "matches_returned_snapshot": self.last_scan_snapshot == current,
                          "metadata": self.last_scan_instability},
                      "diagnostic_row_limit": GROUP_DIAGNOSTIC_ROW_LIMIT,
                      "diagnostic_byte_limit": GROUP_FAILURE_DIAGNOSTIC_LIMIT,
                      "producer_cause_verified": False,
                      "kernel_cause_verified": False,
                      "retry_or_acceptance_relaxation_applied": False}
        raw = json.dumps(diagnostic, sort_keys=True, separators=(",", ":")).encode()
        if len(raw) > GROUP_FAILURE_DIAGNOSTIC_LIMIT:
            # Preserve the original failure even if bounded detail cannot fit.
            diagnostic = {"scope": "failure_diagnostic_size_refused",
                          "complete_diagnostic_sha256": hashlib.sha256(raw).hexdigest(),
                          "complete_diagnostic_bytes": len(raw),
                          "diagnostic_byte_limit": GROUP_FAILURE_DIAGNOSTIC_LIMIT,
                          "producer_cause_verified": False, "kernel_cause_verified": False,
                          "retry_or_acceptance_relaxation_applied": False}
        self.telemetry["failure_observation"] = diagnostic

    def finish_pause(self, success):
        try:
            if success:
                self.leader()
                self.telemetry["continue_requests"] += 1
                try:
                    os.killpg(self.proc.pid, signal.SIGCONT)
                except ProcessLookupError:
                    no_live = self._snapshot()
                    if (not no_live["stable"] or any(r["state"] != "Z"
                            for r in no_live["members"] + no_live["tasks"])):
                        raise ResourceFailure("owned group continue had no recipient without all-zombie evidence")
                    self.telemetry["continue_no_live_group_observations"] += 1
                self.paused = False
        finally:
            if success and self.pause_started is not None:
                elapsed = time.monotonic() - self.pause_started
                self.telemetry["total_pause_seconds"] += elapsed
                self.telemetry["longest_pause_seconds"] = max(self.telemetry["longest_pause_seconds"], elapsed)
                self.pause_started = None
            elif self.paused:
                self.telemetry["failure_stop_retained_until_owned_kill"] = True
            self.pause_deadline = None
            self.verified = False

    def close(self):
        # Called only after run's final kill request, before the leader is reaped.
        if self.pause_started is not None:
            elapsed = time.monotonic() - self.pause_started
            self.telemetry["total_pause_seconds"] += elapsed
            self.telemetry["longest_pause_seconds"] = max(self.telemetry["longest_pause_seconds"], elapsed)
            self.pause_started = None
        if self.proc_fd is not None:
            os.close(self.proc_fd)
            self.proc_fd = None


class Guard:
    """One fresh root, one observed 32-MiB budget, one immutable final receipt."""

    def __init__(self, output, repository):
        self.repository = _path(repository)
        self.output = _path(output)
        if not self.output.is_relative_to(self.repository / "build") or self.output == self.repository / "build":
            raise ResourceFailure("fresh output must be a child of repository/build")
        self.failure = None
        self.minimum_free = None
        self.peak = 0
        self.capture_bytes = 0
        self.decoder_bytes = 0
        self.input_pin_failure_observation = None
        self.output_replacement_observation = None
        self.commands = []
        self.root_fd = None
        self._closed = False
        self._sealed = False
        self._running = False
        self._active_group = None
        self._quiescence_depth = 0
        self._labels = set()
        self.repository_fd = _absolute_directory(self.repository)
        try:
            _directory(self.repository_fd, owned=True)
            self.repository_identity = _inode(os.fstat(self.repository_fd))
            # This observation precedes the first mkdir or file creation.
            self._admission()
            parent = _absolute_directory(self.output.parent)
            try:
                parent_stat = _directory(parent, device=self.repository_identity[0], owned=True)
                if parent_stat.st_mode & 0o022:
                    raise ResourceFailure("output parent permits another writer")
                os.mkdir(self.output.name, 0o700, dir_fd=parent)
                self.root_fd = os.open(self.output.name,
                                       os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                       dir_fd=parent)
                root = _directory(self.root_fd, device=self.repository_identity[0], owned=True)
                if identity(root) != identity(os.stat(self.output.name, dir_fd=parent, follow_symlinks=False)):
                    raise ResourceFailure("new root changed before FD anchoring")
                self.root_identity = _inode(root)
            finally:
                os.close(parent)
            os.mkdir("tmp", 0o700, dir_fd=self.root_fd)
            self.tmp = self.output / "tmp"
            self.check()
        except BaseException:
            self.close()
            raise

    def _fail(self, reason):
        self.failure = self.failure or str(reason)
        return ResourceFailure(self.failure)

    def _root(self):
        if self._closed or self.root_fd is None:
            raise ResourceFailure("guard anchor is closed")
        if (_inode(os.fstat(self.root_fd)) != self.root_identity
                or _inode(self.output.lstat()) != self.root_identity):
            raise self._fail("owned root named/FD identity changed")
        fd = _absolute_directory(self.output)
        try:
            if _inode(os.fstat(fd)) != self.root_identity:
                raise self._fail("owned root component identity changed")
        finally:
            os.close(fd)

    def _sample(self, *, failure_evidence=False):
        if self._active_group is not None:
            self._active_group.check_time()
        if (_inode(os.fstat(self.repository_fd)) != self.repository_identity
                or _inode(self.repository.lstat()) != self.repository_identity):
            raise self._fail("repository identity changed")
        fs = os.fstatvfs(self.repository_fd)
        free = fs.f_bavail * fs.f_frsize
        self.minimum_free = free if self.minimum_free is None else min(self.minimum_free, free)
        if free < RESERVE:
            self._fail(f"20 GiB observed floor crossed: available={free}")
            if not failure_evidence:
                raise ResourceFailure(self.failure)
        return free

    def _admission(self):
        free = self._sample()
        if free < RESERVE + LIMIT:
            raise self._fail(f"fresh admission blocked: available={free}, required={RESERVE + LIMIT}")
        if self.failure:
            raise ResourceFailure(self.failure)
        return free

    def _relative(self, path):
        candidate = _path(self.output / path if not Path(path).is_absolute() else path)
        if not candidate.is_relative_to(self.output) or candidate == self.output:
            raise self._fail("path escaped owned output")
        return candidate, candidate.relative_to(self.output).parts

    def _parent(self, path):
        """Return an owned parent FD and leaf; no directories are created."""
        self._root()
        candidate, parts = self._relative(path)
        fd = os.dup(self.root_fd)
        try:
            for name in parts[:-1]:
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    _directory(child, device=self.root_identity[0], owned=True)
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
            s = _directory(fd, device=self.root_identity[0], owned=True)
            if s.st_mode & 0o022:
                raise ResourceFailure("owned parent permits another writer")
            if _inode(s) != _inode(candidate.parent.lstat()):
                raise ResourceFailure("owned parent named identity changed")
            return fd, parts[-1], candidate
        except BaseException as error:
            os.close(fd)
            raise self._fail(error)

    def _group_observer(self, proc):
        """Injectable bounded stat observer; no hook may bypass validation."""
        group = self._active_group
        if group is None or group.proc is not proc or proc.returncode is not None:
            raise self._fail("group observation requires the active unreaped owned command")
        return group.observe()

    def count(self, *, failure_evidence=False):
        """Retain strict inode checks, pausing only the active owned group.

        Nested observations reuse the verified scope and never resume it early.
        A failed observation leaves the group stopped for run's existing kill
        before reap. Outside commands the original traversal is unchanged.
        """
        group = self._active_group
        if group is None:
            if self._quiescence_depth:
                raise self._fail("orphaned recursive stop scope")
            return self._count_files(failure_evidence=failure_evidence)
        if self._quiescence_depth:
            if not group.paused or not group.verified:
                raise self._fail("nested recursive observation lacks verified stop scope")
            self._quiescence_depth += 1
            try:
                return self._count_files(failure_evidence=failure_evidence)
            finally:
                self._quiescence_depth -= 1
        success = False
        try:
            group.pause()
            self._quiescence_depth = 1
            value = self._count_files(failure_evidence=failure_evidence)
            group.verify_paused()
            success = True
            return value
        except (OSError, ResourceFailure) as error:
            raise self._fail(error)
        finally:
            self._quiescence_depth = 0
            try:
                group.finish_pause(success)
            except (OSError, ResourceFailure) as error:
                raise self._fail(error)

    def _replacement(self, reason, parent, name, before, held, named):
        if self.output_replacement_observation is None:
            try:
                directory = os.readlink(f"/proc/self/fd/{parent}")
            except OSError:
                directory = "<unavailable-held-parent>"
            self.output_replacement_observation = {
                "path": (directory + "/" + name)[:4096], "leaf": name[:255],
                "before_identity": identity(before), "held_identity": identity(held),
                "named_identity": identity(named), "reason": reason,
                "specific_producer_operation_verified": False}
        raise ResourceFailure(reason)

    def _count_files(self, *, failure_evidence=False):
        """FD-anchored recursive named-file logical bytes; retry only churn."""
        self._root()
        for attempt in range(4):
            total = 0
            ndirs = 0
            nfiles = 0
            directories = []
            files = []

            def walk(fd, names, depth, parent=None, leaf=None):
                nonlocal total, ndirs, nfiles
                if depth > MAX_DEPTH:
                    raise ResourceFailure("recursive depth exceeds 16")
                info = _directory(fd, device=self.root_identity[0], owned=True)
                ndirs += 1
                if ndirs > MAX_DIRECTORIES:
                    raise ResourceFailure("recursive directory count exceeds 256")
                children = sorted(os.listdir(fd))
                held = os.dup(fd)
                try:
                    held_parent = os.dup(parent) if parent is not None else None
                except BaseException:
                    os.close(held)
                    raise
                # Retain each nested name's parent until the entire observation
                # closes; an unchanged held subtree is insufficient if its named
                # directory was replaced. The root itself is bound by _root().
                directories.append((held, held_parent, leaf, info, children))
                self._sample(failure_evidence=failure_evidence)
                for name in children:
                    entry = os.stat(name, dir_fd=fd, follow_symlinks=False)
                    if entry.st_dev != self.root_identity[0] or entry.st_uid != os.getuid():
                        raise ResourceFailure("foreign filesystem or writer in proof tree")
                    if stat.S_ISDIR(entry.st_mode):
                        child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            if _inode(os.fstat(child)) != _inode(entry):
                                raise ResourceFailure("directory identity changed before traversal")
                            walk(child, names + (name,), depth + 1, fd, name)
                        finally:
                            os.close(child)
                    elif stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1:
                        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
                        opened = os.fstat(child)
                        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                                or _inode(opened) != _inode(entry)):
                            os.close(child)
                            raise ResourceFailure("file identity/link changed before observation")
                        files.append((child, os.dup(fd), name, opened))
                        nfiles += 1
                        if nfiles > MAX_FILES:
                            raise ResourceFailure("recursive file count exceeds 8192")
                        total += max(entry.st_size, opened.st_size)
                        self.peak = max(self.peak, total)
                        if total > LIMIT:
                            raise ResourceFailure("recursive logical output exceeds 32 MiB")
                    else:
                        raise ResourceFailure("symlink, hardlink or special proof entry refused")

            try:
                walk(self.root_fd, (), 0)
                stable = True
                for fd, parent, name, old, names in directories:
                    current = os.fstat(fd)
                    if _inode(current) != _inode(old):
                        raise ResourceFailure("observed directory identity changed")
                    if parent is not None:
                        try:
                            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                        except FileNotFoundError as error:
                            raise ResourceFailure("observed named directory removed/replaced") from error
                        if (not stat.S_ISDIR(named.st_mode)
                                or _inode(named) != _inode(old)
                                or identity(named) != identity(current)):
                            self._replacement("observed named directory identity changed",
                                              parent, name, old, current, named)
                    if sorted(os.listdir(fd)) != names:
                        stable = False
                for fd, parent, name, old in files:
                    current = os.fstat(fd)
                    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if (_inode(current) != _inode(old) or _inode(named) != _inode(old)
                            or current.st_nlink != 1 or named.st_nlink != 1):
                        self._replacement("observed file inode/type/link changed",
                                          parent, name, old, current, named)
                    total += max(0, current.st_size - old.st_size, named.st_size - old.st_size)
                    self.peak = max(self.peak, total)
                    if total > LIMIT:
                        raise ResourceFailure("live recursive logical output exceeds 32 MiB")
                if not stable:
                    continue
                self._root()
                self._sample(failure_evidence=failure_evidence)
                return total
            except FileNotFoundError:
                continue
            except (OSError, ResourceFailure) as error:
                raise self._fail(error)
            finally:
                for fd, parent, _, _, _ in directories:
                    os.close(fd)
                    if parent is not None:
                        os.close(parent)
                for fd, parent, _, _ in files:
                    os.close(fd)
                    os.close(parent)
        raise self._fail("recursive membership did not stabilize after four observations")

    def check(self, extra=0):
        if not isinstance(extra, int) or isinstance(extra, bool) or extra < 0:
            raise self._fail("nonnegative integer pending byte count required")
        try:
            if self.failure:
                raise ResourceFailure(self.failure)
            self._sample()
            if self.count() + extra > LIMIT:
                raise ResourceFailure("recursive output plus pending bytes exceeds 32 MiB")
        except (OSError, ResourceFailure) as error:
            raise self._fail(error)

    def _mutable(self):
        if self._sealed or self._closed:
            raise self._fail("closed proof epoch refuses new writes or commands")

    def write(self, path, data):
        self._mutable()
        if not isinstance(data, bytes):
            raise self._fail("owned write requires immutable bytes")
        self.check(len(data))
        parent, name, candidate = self._parent(path)
        fd = None
        try:
            fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            token = _inode(os.fstat(fd))
            _write_all(fd, data)
            if (_inode(os.fstat(fd)) != token or _inode(candidate.lstat()) != token
                    or os.fstat(fd).st_nlink != 1 or os.fstat(fd).st_size != len(data)):
                raise ResourceFailure("owned write identity/length changed")
            named_parent = _absolute_directory(candidate.parent)
            try:
                if _inode(os.fstat(named_parent)) != _inode(os.fstat(parent)):
                    raise ResourceFailure("owned write parent identity changed")
            finally:
                os.close(named_parent)
            self.check()
        except (OSError, ResourceFailure) as error:
            raise self._fail(error)
        finally:
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def pin(self, path, maximum=INPUT_LIMIT, *, readonly_system_input=False):
        """Actual whole named regular-file bytes, with a held NOFOLLOW FD."""
        parent = fd = before = None
        try:
            if not isinstance(readonly_system_input, bool):
                raise ResourceFailure("readonly_system_input must be an explicit boolean")
            if not isinstance(maximum, int) or isinstance(maximum, bool) or not 0 < maximum <= INPUT_LIMIT:
                raise ResourceFailure("input pin maximum must be within 256 MiB")
            path = _path(path)
            if readonly_system_input and (not path.is_relative_to(Path("/usr"))
                                           or path.is_relative_to(self.output)):
                raise ResourceFailure("readonly system input must be outside proof output and under /usr")
            parent = _absolute_directory(path.parent, readonly_system_input=readonly_system_input)
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            valid_links = before.st_nlink >= 1 if readonly_system_input else before.st_nlink == 1
            if (not stat.S_ISREG(before.st_mode) or not valid_links
                    or not 0 <= before.st_size <= maximum or identity(before) != identity(path.lstat())
                    or (readonly_system_input and (before.st_uid != 0 or before.st_mode & 0o022))):
                raise ResourceFailure("bounded regular input pin link/owner/mode/size/identity precondition failed")
            h = hashlib.sha256()
            total = 0
            start = time.monotonic()
            while True:
                b = os.read(fd, 262144)
                if not b:
                    break
                h.update(b)
                total += len(b)
                if total > maximum or time.monotonic() - start > 60:
                    raise ResourceFailure("input full-hash byte/time bound crossed")
                if (identity(os.fstat(fd)) != identity(before)
                        or identity(path.lstat()) != identity(before)):
                    raise ResourceFailure("input pin identity changed during held-FD hash")
                self.check()
            if (total != before.st_size or identity(os.fstat(fd)) != identity(before)
                    or identity(path.lstat()) != identity(before)):
                raise ResourceFailure("input pin changed during held-FD hash")
            named_parent = _absolute_directory(path.parent, readonly_system_input=readonly_system_input)
            try:
                if _inode(os.fstat(named_parent)) != _inode(os.fstat(parent)):
                    raise ResourceFailure("input parent identity changed during hash")
            finally:
                os.close(named_parent)
            return {"sha256": h.hexdigest(), "bytes": total, "identity": identity(before)}
        except (OSError, ResourceFailure) as error:
            if self.input_pin_failure_observation is None:
                self.input_pin_failure_observation = {
                    "path": str(path)[:4096],
                    "identity": identity(before) if before is not None else None,
                    "readonly_system_input": readonly_system_input is True,
                    "maximum_bytes": maximum if (isinstance(maximum, int) and not isinstance(maximum, bool)
                                                   and 0 < maximum <= INPUT_LIMIT) else None,
                    "regular_file_observed": stat.S_ISREG(before.st_mode) if before is not None else None,
                    "single_link_observed": before.st_nlink == 1 if before is not None else None,
                    "positive_link_count_observed": before.st_nlink >= 1 if before is not None else None,
                    "root_owned_observed": before.st_uid == 0 if before is not None else None,
                    "no_group_other_write_observed": not bool(before.st_mode & 0o022) if before is not None else None,
                    "error": str(error)[:2048],
                    "historical_failed_input_identity_inferred": False,
                }
            raise self._fail(error)
        finally:
            if fd is not None:
                os.close(fd)
            if parent is not None:
                os.close(parent)

    def _environment(self):
        env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
               "TMPDIR": str(self.tmp), "TMP": str(self.tmp), "TEMP": str(self.tmp),
               "PYTHONDONTWRITEBYTECODE": "1"}
        parser = os.environ.get("PYTHONPATH")
        if parser:
            # Explicit single source-parser preparation path; never broad PATH inheritance.
            if ":" in parser:
                raise self._fail("only one explicit parser PYTHONPATH directory is allowed")
            path = _path(parser)
            if not path.is_relative_to(self.repository / "build"):
                raise self._fail("parser PYTHONPATH must be an owned prepared build child")
            fd = _absolute_directory(path)
            try:
                s = _directory(fd)
                if s.st_uid not in (0, os.getuid()) or s.st_mode & 0o022:
                    raise self._fail("unsafe prepared parser directory")
            finally:
                os.close(fd)
            env["PYTHONPATH"] = str(path)
        return env

    def run(self, argv, label, cwd=None, timeout=60, stdout_consumer=None, raw_limit=None):
        """Own group, retained WNOWAIT leader, bounded captures or raw stream.

        The optional consumer owns no implicit extra storage allowance. Every
        block delivered to it has been counted/hashed and fits raw_limit;
        its files must still fit the same recursive 32-MiB proof budget.
        """
        self._mutable()
        if self._running:
            raise self._fail("nested or concurrent guard commands refused")
        if (not isinstance(label, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", label)
                or label in self._labels):
            raise self._fail("unique safe command label required")
        if (not isinstance(argv, (list, tuple)) or not 0 < len(argv) <= 256
                or any(not isinstance(a, str) or "\0" in a for a in argv)
                or sum(len(a.encode()) for a in argv) > 65536):
            raise self._fail("bounded explicit argv required")
        if not isinstance(timeout, (int, float)) or isinstance(timeout, bool) or not 0 < timeout <= COMMAND_TIMEOUT_LIMIT:
            raise self._fail("new TLS command timeout must be in (0,360]")
        streaming = stdout_consumer is not None
        if streaming:
            if not callable(stdout_consumer) or not isinstance(raw_limit, int) or isinstance(raw_limit, bool) or not 0 < raw_limit <= RAW_LIMIT:
                raise self._fail("stdout consumer requires an explicit raw bound <=16 MiB")
        elif raw_limit is not None:
            raise self._fail("raw limit requires a stdout consumer")
        cwd = _path(self.output if cwd is None else cwd)
        if not cwd.is_relative_to(self.repository):
            raise self._fail("command cwd must be within the pinned repository")
        self._admission()
        self.check()
        env = self._environment()
        cwd_fd = _absolute_directory(cwd)
        token = _inode(os.fstat(cwd_fd))
        self._labels.add(label)
        self._running = True
        parent = None
        logs = {}
        selector = None
        proc = None
        aborted = None
        reaped = False
        kill = "NOT_REQUESTED"
        leader_observed = False
        group = None
        rc = None
        start = time.monotonic()
        hashes = {name: hashlib.sha256() for name in ("stdout", "stderr")}
        observed = {name: 0 for name in hashes}
        captured = {name: bytearray() for name in hashes}
        delivered = 0
        try:
            parent, _, _ = self._parent(self.output / (label + ".stdout"))
            for stream in hashes:
                name = label + "." + stream
                fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=parent)
                logs[stream] = (fd, name, _inode(os.fstat(fd)))
            remaining = LIMIT - self.count()
            if remaining <= 0:
                raise self._fail("no remaining recursive command output budget")

            def limits():
                resource.setrlimit(resource.RLIMIT_FSIZE, (remaining, remaining))
                resource.setrlimit(resource.RLIMIT_CORE, (0, 0))

            if _inode(cwd.lstat()) != token:
                raise self._fail("command cwd identity changed before spawn")
            proc = subprocess.Popen(list(argv), cwd=str(cwd), env=env,
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, start_new_session=True,
                                    preexec_fn=limits, close_fds=True)
            group = _OwnedGroupObservation(self, proc, start + timeout)
            self._active_group = group
            selector = selectors.DefaultSelector()
            for name, stream in (("stdout", proc.stdout), ("stderr", proc.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, name)
            while selector.get_map() or not leader_observed:
                self.check()
                if time.monotonic() - start > timeout:
                    raise self._fail("owned command wall timeout crossed")
                if not leader_observed:
                    observed_exit = os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    leader_observed = observed_exit is not None
                for event, _ in selector.select(SAMPLE_SECONDS):
                    name = event.data
                    block = os.read(event.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(event.fileobj)
                        continue
                    hashes[name].update(block)
                    observed[name] += len(block)
                    if name == "stdout" and streaming:
                        self.decoder_bytes += len(block)
                        if observed[name] > raw_limit or self.decoder_bytes > DECODER_LIMIT:
                            raise self._fail("explicit per-command/64-MiB aggregate raw stdout bound crossed")
                        stdout_consumer(block)
                        delivered += len(block)
                        self.check()
                    else:
                        if self.capture_bytes + len(block) > CAPTURE_LIMIT:
                            raise self._fail("global retained normal stdout/stderr exceeds 256 KiB")
                        self.check(len(block))
                        fd, leaf, log_token = logs[name]
                        named = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                        if (_inode(os.fstat(fd)) != log_token
                                or identity(os.fstat(fd)) != identity(named)
                                or os.fstat(fd).st_size != len(captured[name])
                                or os.fstat(fd).st_nlink != 1):
                            raise self._fail("capture named/held inode changed")
                        _write_all(fd, block)
                        captured[name].extend(block)
                        self.capture_bytes += len(block)
                        self.check()
        except BaseException as error:
            aborted = f"{type(error).__name__}: {error}"[:4096]
            self._fail(aborted)
        finally:
            # Never poll()/wait() before this kill request: WNOWAIT holds the
            # owned leader identity even after EOF, including normal success.
            if proc is not None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                    kill = "REQUESTED_BEFORE_REAP"
                except ProcessLookupError:
                    kill = "NO_SUCH_GROUP_BEFORE_REAP"
                except OSError as error:
                    kill = "FAILED_BEFORE_REAP"
                    aborted = aborted or str(error)
                    self._fail(error)
                # Clear the observation/signal boundary only after the final
                # owned-group kill request, and before any operation can reap.
                self._active_group = None
                self._quiescence_depth = 0
                if group is not None:
                    try:
                        group.close()
                    except OSError as error:
                        aborted = aborted or str(error)
                        self._fail(error)
                try:
                    rc = proc.wait(timeout=5)
                    reaped = True
                except BaseException as error:
                    aborted = aborted or str(error)
                    self._fail(error)
                for stream in (proc.stdout, proc.stderr):
                    if stream is not None:
                        stream.close()
            if selector is not None:
                selector.close()
            for stream_name, (fd, leaf, log_token) in logs.items():
                try:
                    before = os.fstat(fd)
                    named = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                    if (_inode(before) != log_token or identity(before) != identity(named)
                            or before.st_nlink != 1 or before.st_size != len(captured[stream_name])):
                        raise self._fail("capture inode changed at closure")
                    os.lseek(fd, 0, os.SEEK_SET)
                    actual = bytearray()
                    while True:
                        block = os.read(fd, 65536)
                        if not block:
                            break
                        actual.extend(block)
                        if len(actual) > CAPTURE_LIMIT:
                            raise self._fail("capture readback exceeds normal global bound")
                    if (actual != captured[stream_name] or identity(os.fstat(fd)) != identity(before)
                            or identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != identity(before)):
                        raise self._fail("actual retained capture bytes/identity changed")
                except BaseException as error:
                    aborted = aborted or str(error)
                    self._fail(error)
                finally:
                    os.close(fd)
            if parent is not None:
                os.close(parent)
            os.close(cwd_fd)
            self._running = False
            self.commands.append({"argv": list(argv), "cwd": str(cwd), "label": label,
                                  "returncode": rc, "reaped": reaped, "aborted": aborted,
                                  "owned_pid": proc.pid if proc is not None else None,
                                  "group_kill": kill, "normal_completion_group_cleanup_requested": proc is not None,
                                  "nonreaping_leader_exit_observed": leader_observed,
                                  "full_stdout_bytes": observed["stdout"], "full_stderr_bytes": observed["stderr"],
                                  "full_stdout_sha256": hashes["stdout"].hexdigest(),
                                  "full_stderr_sha256": hashes["stderr"].hexdigest(),
                                  "captured_bytes": sum(len(b) for b in captured.values()),
                                  "captured_sha256": {k: hashlib.sha256(v).hexdigest() for k, v in captured.items()},
                                  "aggregate_capture_bytes": self.capture_bytes,
                                  "raw_stdout_stream": streaming, "raw_limit": raw_limit,
                                  "stdout_delivered_to_consumer_bytes": delivered,
                                  "decoder_observed_bytes_total": self.decoder_bytes,
                                  "decoder_observed_byte_limit_total": DECODER_LIMIT,
                                  "elapsed_seconds": time.monotonic() - start,
                                  "timeout_seconds": timeout, "reap_timeout_seconds": 5,
                                  "profile_command_timeout_limit_seconds": COMMAND_TIMEOUT_LIMIT,
                                  "quiescence": dict(group.telemetry) if group is not None else None,
                                  "whole_process_group_reaped_verified": False})
        if aborted:
            raise ResourceFailure(aborted)
        self.check()
        return subprocess.CompletedProcess(list(argv), rc, bytes(captured["stdout"]), bytes(captured["stderr"]))

    def close_receipt(self, receipt, path):
        """Stabilize this new owned receipt; never reopen a frozen receipt.

        A floor crossing permits only bounded FAIL evidence at this boundary,
        never another command/write or a revived PASS. If unsafe types or an
        exhausted 32-MiB tree prevent even FAIL evidence, raise and preserve it.
        """
        self._mutable()
        if self._running or not isinstance(receipt, dict):
            raise self._fail("closed command epoch and dictionary receipt required")
        parent, name, candidate = self._parent(path)
        fd = None
        desired = receipt.get("result", "FAIL")
        token = None
        data = b""

        def encoded(base):
            receipt.update(output_bytes_before_receipt=base, final_output_bytes=base)
            for _ in range(32):
                raw = (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
                final = base + len(raw)
                if final == receipt["final_output_bytes"]:
                    if len(raw) > RECEIPT_LIMIT or final > LIMIT:
                        raise ResourceFailure("self-inclusive receipt/32-MiB bound crossed")
                    return raw
                receipt["final_output_bytes"] = final
            raise ResourceFailure("self-inclusive receipt length failed to converge")

        def metadata(verified):
            free = self._sample(failure_evidence=True)
            if free < RESERVE + LIMIT:
                self._fail("fresh final-receipt admission blocked")
            if any(c["returncode"] != 0 or not c["reaped"] or c["aborted"] for c in self.commands):
                self._fail("a prior owned command failed or was not reaped")
            minimal = receipt.get("schema") == INVALID_RECEIPT_SCHEMA
            strings, references, rows = [], {}, []
            string_bytes = 0
            if not minimal:
                try:
                    for command in self.commands:
                        row = dict(command)
                        indices = []
                        for argument in command["argv"]:
                            if argument not in references:
                                if (len(strings) >= 8192
                                        or string_bytes + len(argument.encode("utf-8")) > 256 * 1024):
                                    raise ResourceFailure("lossless command argv table byte/count bound crossed")
                                references[argument] = len(strings)
                                strings.append(argument)
                                string_bytes += len(argument.encode("utf-8"))
                            indices.append(references[argument])
                        del row["argv"]
                        row["argv_refs"] = indices
                        rows.append(row)
                except (KeyError, TypeError, UnicodeError, ResourceFailure) as error:
                    self._fail(error)
                    receipt.clear()
                    receipt.update(schema=INVALID_RECEIPT_SCHEMA, result="FAIL", evidence_complete=False,
                                   error=str(error)[:2048], native_execution_verified=False,
                                   windows98_integration_verified=False, tls_execution_verified=False)
                    minimal = True
                    rows, strings, string_bytes = [], [], 0
            receipt.update(result="FAIL" if self.failure else desired,
                           reserve_bytes=RESERVE, output_limit_bytes=LIMIT,
                           receipt_limit_bytes=RECEIPT_LIMIT, capture_limit_bytes_aggregate=CAPTURE_LIMIT,
                           commands=rows,
                           command_argv_encoding="lossless-string-table-v1",
                           command_argv_string_table=strings,
                           command_argv_string_table_utf8_bytes=string_bytes,
                           command_argv_string_table_count_limit=8192,
                           command_argv_string_table_byte_limit=256 * 1024,
                           command_records_retained=not minimal,
                           command_count=len(self.commands), captured_normal_bytes=self.capture_bytes,
                           decoder_observed_bytes=self.decoder_bytes, resource_failure=self.failure,
                           input_pin_failure_observation=self.input_pin_failure_observation,
                           output_replacement_observation=self.output_replacement_observation,
                           minimum_observed_free_bytes=self.minimum_free,
                           peak_observed_output_bytes=self.peak, available_at_receipt_bytes=free,
                           receipt_accounting_verified=verified,
                           resource_model={"named_recursive_logical_files": True,
                                           "profile_command_timeout_limit_seconds": COMMAND_TIMEOUT_LIMIT,
                                           "input_hash_limit_seconds": 60,
                                           "sample_interval_seconds": SAMPLE_SECONDS,
                                           "owned_group_quiescent_observations_required": True,
                                           "quiescence_model": "Linux owned process-and-task T/Z snapshots before/after strict count",
                                           "continuous_group_stop_verified": False,
                                           "group_stop_confirmation_limit_seconds": QUIESCENCE_TIMEOUT,
                                           "group_member_observation_limit": GROUP_MEMBER_LIMIT,
                                           "group_task_observation_limit": GROUP_TASK_LIMIT,
                                           "proc_process_observation_limit": PROC_ENTRY_LIMIT,
                                           "command_wall_time_includes_group_pauses": True,
                                           "unmanaged_or_escaped_writers_excluded_verified": False,
                                           "pending_asynchronous_kernel_writes_excluded_verified": False,
                                           "filesystem_quota_verified": False,
                                           "continuous_minimum_free_verified": False,
                                           "all_transient_or_unlinked_file_peaks_observed": False,
                                           "implicit_backend_runtime_attestation_verified": False})

        try:
            metadata(False)
            base = self.count(failure_evidence=True)
            try:
                data = encoded(base)
            except (ValueError, TypeError, ResourceFailure) as error:
                self._fail(error)
                receipt.clear()
                receipt.update(schema=INVALID_RECEIPT_SCHEMA, result="FAIL", evidence_complete=False,
                               error=str(error)[:2048], native_execution_verified=False,
                               windows98_integration_verified=False, tls_execution_verified=False)
                metadata(False)
                data = encoded(base)
            fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent)
            token = _inode(os.fstat(fd))
            _write_all(fd, data)
            for _ in range(32):
                if (_inode(os.fstat(fd)) != token or _inode(candidate.lstat()) != token
                        or os.fstat(fd).st_nlink != 1):
                    raise ResourceFailure("new receipt held/named identity changed")
                total = self.count(failure_evidence=True)
                metadata(True)
                replacement = encoded(total - os.fstat(fd).st_size)
                if replacement == data:
                    if total != receipt["final_output_bytes"]:
                        raise ResourceFailure("actual receipt logical accounting mismatch")
                    before = os.fstat(fd)
                    os.lseek(fd, 0, os.SEEK_SET)
                    actual = bytearray()
                    while True:
                        block = os.read(fd, 65536)
                        if not block:
                            break
                        actual.extend(block)
                        if len(actual) > RECEIPT_LIMIT:
                            raise ResourceFailure("actual receipt readback exceeds 1 MiB")
                    if (actual != data or identity(os.fstat(fd)) != identity(before)
                            or identity(candidate.lstat()) != identity(before)):
                        raise ResourceFailure("actual receipt bytes/identity changed at closure")
                    named_parent = _absolute_directory(candidate.parent)
                    try:
                        if _inode(os.fstat(named_parent)) != _inode(os.fstat(parent)):
                            raise ResourceFailure("receipt parent identity changed at closure")
                    finally:
                        os.close(named_parent)
                    self._sample(failure_evidence=True)
                    if self.minimum_free != receipt["minimum_observed_free_bytes"]:
                        continue
                    self._sealed = True
                    return {"path": str(candidate), "sha256": hashlib.sha256(data).hexdigest(),
                            "bytes": len(data), "identity": identity(os.fstat(fd)),
                            "result": receipt["result"]}
                os.lseek(fd, 0, os.SEEK_SET)
                os.ftruncate(fd, 0)
                _write_all(fd, replacement)
                data = replacement
            raise ResourceFailure("final receipt observations failed to stabilize")
        except BaseException as error:
            self._fail(error)
            if fd is not None and token == _inode(os.fstat(fd)):
                try:
                    if (_inode(candidate.lstat()) != token or os.fstat(fd).st_nlink != 1):
                        raise ResourceFailure("refuse replacement of substituted receipt")
                    receipt.update(result="FAIL", resource_failure=self.failure,
                                   receipt_accounting_verified=False)
                    base = self.count(failure_evidence=True) - os.fstat(fd).st_size
                    replacement = encoded(base)
                    os.lseek(fd, 0, os.SEEK_SET)
                    os.ftruncate(fd, 0)
                    _write_all(fd, replacement)
                except BaseException:
                    # Invalidate a prospective PASS through the still-owned FD;
                    # never write an unsafe named replacement or another file.
                    if (token == _inode(os.fstat(fd)) and os.fstat(fd).st_nlink == 1
                            and _inode(candidate.lstat()) == token):
                        os.ftruncate(fd, 0)
            raise
        finally:
            self._sealed = True
            if fd is not None:
                os.close(fd)
            os.close(parent)

    def close(self):
        """Close only owned anchors; no deletion, chmod or source mutation."""
        if getattr(self, "_running", False):
            raise ResourceFailure("cannot close an active owned command")
        if getattr(self, "root_fd", None) is not None:
            os.close(self.root_fd)
            self.root_fd = None
        if getattr(self, "repository_fd", None) is not None:
            os.close(self.repository_fd)
            self.repository_fd = None
        self._closed = True


def hosted_control_plan():
    """Independent future controls; returning this list claims no test PASS."""
    return {"status": "NOT_EXECUTED", "hosted_only": True,
            "cases": [
                {"case": "pre-mkdir-deficit", "expect": "no output created below20GiB+32MiB"},
                {"case": "nested-temp-cap", "expect": "nested files plus candidatewrite exceed32MiB -> latchedFAIL"},
                {"case": "symlink-hardlink-special-foreignfs", "expect": "each observed unsafe entry refusescount"},
                {"case": "named-inode-substitution", "expect": "held/name mismatch refusespin/write/receipt"},
                {"case": "recursive-membership-churn", "expect": "atmost4retry thenlatchedFAIL"},
                {"case": "normal-global-capture", "expect": "multiplecommands stdout+stderr share256KiB"},
                {"case": "stream-overrun-consumer-error", "expect": "raw>explicitlimit orconsumererror killsbeforeleaderreap"},
                {"case": "aggregate-stream-cap", "expect": "multipledecoderstdout streams shareexplicit64MiB input cap"},
                {"case": "timeout-and-silent-descendant", "expect": "failureandsuccess requestownedkillpg beforewait"},
                {"case": "full-stdout-stderr-digests", "expect": "actualobservedhashcounts matchcaptured/stream bytes"},
                {"case": "self-inclusive-receipt", "expect": "actualrecursivebytes includecompact1MiBreceipt exactly"},
                {"case": "late-floor-crossing", "expect": "boundedFAILreceipt only; neverrevivedPASS"},
                {"case": "frozen-receipt-no-overwrite", "expect": "existingreceipt orsealedepoch neverrewritten"},
                {"case": "real-named-directory-replacement", "expect": "replacednestedname withstableoldFD/listing latchesFAIL; everyheldparent closes"}],
            "native_execution_verified": False, "tls_execution_verified": False,
            "filesystem_quota_verified": False}
