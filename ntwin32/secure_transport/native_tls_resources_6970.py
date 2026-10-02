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


def _absolute_directory(path):
    """Open every component without following symlinks; caller owns the FD."""
    path = _path(path)
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for name in path.parts[1:]:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=fd)
            os.close(fd)
            fd = child
            _directory(fd)
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
        self.commands = []
        self.root_fd = None
        self._closed = False
        self._sealed = False
        self._running = False
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

    def count(self, *, failure_evidence=False):
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
                            raise ResourceFailure("observed named directory identity changed")
                    if sorted(os.listdir(fd)) != names:
                        stable = False
                for fd, parent, name, old in files:
                    current = os.fstat(fd)
                    named = os.stat(name, dir_fd=parent, follow_symlinks=False)
                    if (_inode(current) != _inode(old) or _inode(named) != _inode(old)
                            or current.st_nlink != 1 or named.st_nlink != 1):
                        raise ResourceFailure("observed file inode/type/link changed")
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

    def pin(self, path, maximum=INPUT_LIMIT):
        """Actual whole named regular-file bytes, with a held NOFOLLOW FD."""
        if not isinstance(maximum, int) or isinstance(maximum, bool) or not 0 < maximum <= INPUT_LIMIT:
            raise self._fail("input pin maximum must be within 256 MiB")
        path = _path(path)
        parent = _absolute_directory(path.parent)
        fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_size > maximum or identity(before) != identity(path.lstat())):
                raise ResourceFailure("bounded regular singlelink input pin required")
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
                self.check()
            if (total != before.st_size or identity(os.fstat(fd)) != identity(before)
                    or identity(path.lstat()) != identity(before)):
                raise ResourceFailure("input pin changed during held-FD hash")
            named_parent = _absolute_directory(path.parent)
            try:
                if _inode(os.fstat(named_parent)) != _inode(os.fstat(parent)):
                    raise ResourceFailure("input parent identity changed during hash")
            finally:
                os.close(named_parent)
            return {"sha256": h.hexdigest(), "bytes": total, "identity": identity(before)}
        except (OSError, ResourceFailure) as error:
            raise self._fail(error)
        finally:
            if fd is not None:
                os.close(fd)
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
            receipt.update(result="FAIL" if self.failure else desired,
                           reserve_bytes=RESERVE, output_limit_bytes=LIMIT,
                           receipt_limit_bytes=RECEIPT_LIMIT, capture_limit_bytes_aggregate=CAPTURE_LIMIT,
                           commands=[] if minimal else self.commands,
                           command_records_retained=not minimal,
                           command_count=len(self.commands), captured_normal_bytes=self.capture_bytes,
                           decoder_observed_bytes=self.decoder_bytes, resource_failure=self.failure,
                           minimum_observed_free_bytes=self.minimum_free,
                           peak_observed_output_bytes=self.peak, available_at_receipt_bytes=free,
                           receipt_accounting_verified=verified,
                           resource_model={"named_recursive_logical_files": True,
                                           "profile_command_timeout_limit_seconds": COMMAND_TIMEOUT_LIMIT,
                                           "input_hash_limit_seconds": 60,
                                           "sample_interval_seconds": SAMPLE_SECONDS,
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
