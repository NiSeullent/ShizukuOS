#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Consume pinned native-runner and reviewed COW guards for a private theme trial.

The default only freezes sources. --execute additionally acquires the shared
native-guest lock and runs the canonical offline GUI workflow. No IO.SYS entry
surgery, GDB, network, guest installation or peer-source edits are introduced.
The two adaptation/observation functions are consumed unchanged from the pinned
iosys_uefi/boot.py, without executing that wrapper's IO.SYS imports or main.
FIEMAP measures net exclusive file data, not metadata or cumulative writes;
the independent >=20 GiB free-space floor and 256 MiB reserve remain required.
"""
from __future__ import annotations

import argparse
import ast
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = ROOT / "build/theme-native-runs"
SOURCE_FILES = {
    "canonical": "shizukudos/csm/test_win98_uefi.py",
    "adapter": "shizukudos/iosys_uefi/boot.py",
    "cow": "shizukudos/iosys_uefi/cow_accounting.py",
    "qemu": "shizukudos/tools/qemu.py",
    "shzlib": "shizukudos/tools/shzlib.py",
}
FUNCTIONS = ("private_reflink_runner", "quiescent_cow_observation")
HOST_OUTPUT_LIMIT = 16 * 1024**2


class ConsumerError(RuntimeError):
    pass


class HostOutputError(ConsumerError):
    """A latched resource failure, never a native acceptance result."""
    pass


def digest(data):
    return hashlib.sha256(data).hexdigest()


def safe_path(path, *, existing=True):
    """Reject symlink components rather than silently granting their targets."""
    path = Path(path)
    if (not path.is_absolute() or ".." in path.parts
            or any(character in str(path) for character in ("\x00", "\n", "\r", ","))):
        raise ConsumerError("Paths must be absolute and contain no parent traversal")
    for parent in (path, *path.parents):
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode):
            raise ConsumerError("Symlink path components are not accepted")
    if existing:
        path.stat()
    return path


def read_source(path):
    path = safe_path(path)
    before = path.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_size > 2 * 1024 ** 2:
        raise ConsumerError("Source must be a bounded regular file")
    data = path.read_bytes()
    after = path.stat()
    identity = lambda value: (value.st_dev, value.st_ino, value.st_size,
                              value.st_mtime_ns, value.st_ctime_ns)
    if identity(before) != identity(after) or len(data) != before.st_size:
        raise ConsumerError("Source changed while being read")
    return data


class HostOutputGuard:
    """Sample all owned host files; only the exact private COW is excluded.

    Checks are performed at resource polls and before/after output operations.
    An observed overshoot is sticky even if an output subsequently disappears.
    This is measured enforcement, not an atomic filesystem allocation quota.
    """
    def __init__(self, roots, private_cow, *, limit=HOST_OUTPUT_LIMIT, reserve=20 * 1024**3):
        self.roots = tuple(safe_path(path, existing=False) for path in roots)
        self.private_cow = safe_path(private_cow, existing=False)
        if (not self.roots or len(set(self.roots)) != len(self.roots)
                or any(a != b and a.is_relative_to(b) for a in self.roots for b in self.roots)
                or self.private_cow.name != "windows-uefi.raw" or self.private_cow.parent not in self.roots
                or not 1 <= limit <= HOST_OUTPUT_LIMIT or not 20 * 1024**3 <= reserve <= 64 * 1024**3):
            raise ConsumerError("Unsafe host-output scope, exclusion or resource limit")
        self.limit, self.reserve = limit, reserve
        self.identities, self.cow_identity = {}, None
        self.used = self.peak = 0
        self.phase, self.failure, self.checked = "not-checked", None, False
        self.per_root = {}

    def configuration(self):
        return {"schema": 1, "roots": [str(path) for path in self.roots],
                "excluded_private_cow": str(self.private_cow), "limit_bytes": self.limit,
                "reserve_bytes": self.reserve}

    def to_dict(self):
        return {**self.configuration(), "status": "FAIL" if self.failure else "PASS" if self.checked else "NOT-CHECKED",
                "used_bytes": self.used, "peak_bytes": self.peak, "phase": self.phase,
                "per_root_bytes": dict(self.per_root), "failure": self.failure,
                "private_cow_identity": self.cow_identity,
                "measurement": "regular-file logical bytes; zero-byte Unix sockets allowed; sampled checks; overshoot latched",
                "peak_scope": "highest observed sample; final receipt bytes are stabilized by the writer; not an atomic allocation quota"}

    def check(self, phase, *, require_cow=False):
        self.phase = phase
        total, per_root = 0, {}
        try:
            for root in self.roots:
                safe_path(root, existing=False)
                if not root.exists():
                    if root in self.identities:
                        raise ConsumerError("Owned output root disappeared")
                    per_root[str(root)] = 0
                    continue
                info = root.stat()
                if not stat.S_ISDIR(info.st_mode):
                    raise ConsumerError("Owned output root is not a directory")
                identity = (info.st_dev, info.st_ino)
                if self.identities.setdefault(root, identity) != identity:
                    raise ConsumerError("Owned output root inode changed")
                subtotal, pending = 0, [root]
                while pending:
                    directory = safe_path(pending.pop())
                    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                    try:
                        entries = os.scandir(descriptor)
                        with entries:
                            for entry in entries:
                                info = entry.stat(follow_symlinks=False)
                                path = directory / entry.name
                                if stat.S_ISLNK(info.st_mode):
                                    raise ConsumerError("Symlink in owned output scope")
                                if stat.S_ISDIR(info.st_mode):
                                    pending.append(path)
                                elif stat.S_ISREG(info.st_mode):
                                    if info.st_nlink != 1:
                                        raise ConsumerError("Aliased output/private COW inode")
                                    if path == self.private_cow:
                                        identity = (info.st_dev, info.st_ino)
                                        if self.cow_identity is None:
                                            self.cow_identity = identity
                                        if self.cow_identity != identity:
                                            raise ConsumerError("Private COW inode changed")
                                    else:
                                        subtotal += info.st_size
                                elif not (stat.S_ISSOCK(info.st_mode) and info.st_size == 0):
                                    raise ConsumerError("Unsupported file type in owned output scope")
                    finally:
                        os.close(descriptor)
                per_root[str(root)] = subtotal
                total += subtotal
                if (root.stat().st_dev, root.stat().st_ino) != self.identities[root]:
                    raise ConsumerError("Owned output root changed during measurement")
            self.used, self.per_root = total, per_root
            self.peak = max(self.peak, total)
            if require_cow and not self.private_cow.is_file():
                raise ConsumerError("Private COW absent before owned VM launch/poll")
            if total > self.limit:
                raise ConsumerError(f"Combined host output exceeded {self.limit} bytes: observed {total}")
            for root in self.roots:
                existing = root
                while not existing.exists():
                    existing = existing.parent
                if shutil.disk_usage(existing).free < self.reserve:
                    raise ConsumerError("Host-output check reached the unchanged free-space reserve")
            self.checked = True
            if self.failure:
                raise HostOutputError(self.failure)
            return self.to_dict()
        except (OSError, ConsumerError) as error:
            self.failure = self.failure or "Resource host-output FAIL: " + str(error)
            raise HostOutputError(self.failure) from error

    def write_owned_json(self, path, data):
        """Write only beneath an unchanged owned root, without following links."""
        descriptor = None
        try:
            path = safe_path(path, existing=False)
            root = next((root for root in self.roots if path != root and path.is_relative_to(root)), None)
            if root is None or root not in self.identities:
                raise ConsumerError("Receipt is outside a measured owned output root")
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != self.identities[root]:
                raise ConsumerError("Receipt root inode changed")
            relative = path.relative_to(root)
            for component in relative.parts[:-1]:
                child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            output = os.open(relative.name, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
                             0o600, dir_fd=descriptor)
            with os.fdopen(output, "w") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ConsumerError("Receipt must be an unaliased regular file")
                stream.truncate(0)
                stream.write(json.dumps(data, indent=2) + "\n")
        except (OSError, ConsumerError) as error:
            self.failure = self.failure or "Resource host-output FAIL: " + str(error)
            raise HostOutputError(self.failure) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)

    def write_receipt(self, path, data, phase):
        """Persist a bounded, stable sample including this receipt's own bytes."""
        try:
            self.check(phase)
        except HostOutputError:
            pass  # A failure remains latched; an owned FAIL receipt may still be saved.
        for _ in range(8):
            if self.failure:
                data.update(status="FAIL", resource_failure=self.failure)
            snapshot = self.to_dict()
            data["host_output_budget"] = snapshot
            self.write_owned_json(path, data)
            try:
                self.check(phase)
            except HostOutputError:
                pass
            if snapshot == self.to_dict():
                if self.failure:
                    raise HostOutputError(self.failure)
                return
        self.failure = self.failure or "Resource host-output FAIL: final receipt measurement did not stabilize"
        data.update(status="FAIL", resource_failure=self.failure, host_output_budget=self.to_dict())
        self.write_owned_json(path, data)
        raise HostOutputError(self.failure)


def reviewed_functions(source):
    """Compile only unchanged selected function ASTs; no top-level imports run."""
    tree = ast.parse(source)
    selected = []
    for name in FUNCTIONS:
        matches = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name == name]
        if len(matches) != 1 or matches[0].decorator_list:
            raise ConsumerError("Reviewed adapter function contract changed")
        selected.append(matches[0])
    namespace = {"time": time, "shutil": shutil}
    exec(compile(ast.Module(body=selected, type_ignores=[]), "pinned-boot.py", "exec"), namespace)
    return {name: namespace[name] for name in FUNCTIONS}


def native_arguments(argv):
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    for name in ("archive", "checkpoint-record", "qemu", "firmware-code", "firmware-vars",
                 "resume-owned-run", "csm-dir", "guest-files-manifest", "guest-files-manifest-sha", "run-name"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--snapshot", default="windows98-clean-installed")
    parser.add_argument("--machine", choices=("q35",), default="q35")
    parser.add_argument("--accel", choices=("kvm",), default="kvm")
    parser.add_argument("--smp", type=int, default=2)
    parser.add_argument("--memory", type=int, default=128)
    parser.add_argument("--timeout", type=int, default=900)
    parser.add_argument("--capture-interval", type=int, default=5)
    parser.add_argument("--reserve-gib", type=int, default=20)
    parser.add_argument("--manual-purpose", choices=("diagnostic",), default="diagnostic")
    for flag in ("manual-gui", "firmware-gop", "replace-csmwrap"):
        parser.add_argument("--" + flag, action="store_true", required=True)
    # argparse accepts repeated options by taking the last. Reject that ambiguity
    # before forwarding exactly the same bytes to the canonical parser.
    flags = [item.split("=", 1)[0] for item in argv if item.startswith("--")]
    if len(flags) != len(set(flags)):
        raise ConsumerError("Repeated native options are not accepted")
    args = parser.parse_args(argv)
    if not 20 <= args.reserve_gib <= 64 or args.smp != 2 or args.memory != 128:
        raise ConsumerError("Theme trial requires >=20 GiB reserve, 2 CPUs and 128 MiB guest RAM")
    if not 1 <= args.timeout <= 900 or not 5 <= args.capture_interval <= 60:
        raise ConsumerError("Invalid bounded theme trial interval")
    if not re.fullmatch(r"win98-gop-theme-6970-[a-zA-Z0-9_-]+", args.run_name):
        raise ConsumerError("Run name must identify this session's fresh theme trial")
    if not re.fullmatch(r"[0-9a-f]{64}", args.guest_files_manifest_sha):
        raise ConsumerError("Guest files require the exact lowercase SHA-256")
    if "--reserve-gib" not in flags:
        argv = [*argv, "--reserve-gib", str(args.reserve_gib)]
    # Canonical defaults are 180 s / 30 s, so forward our own defaults explicitly.
    for name in ("timeout", "capture-interval", "manual-purpose"):
        if "--" + name not in flags:
            argv = [*argv, "--" + name, str(getattr(args, name.replace("-", "_")))]
    return args, argv


def validate_paths(args, peer, consumer):
    peer = safe_path(peer)
    if not peer.is_dir():
        raise ConsumerError("Peer root must be an existing directory")
    consumer = safe_path(consumer, existing=False)
    if not consumer.is_relative_to(ROOT / "build") or consumer.exists():
        raise ConsumerError("Consumer directory must be a new directory below this worktree's build tree")
    for name in ("archive", "checkpoint_record", "qemu", "firmware_code", "firmware_vars", "guest_files_manifest"):
        if not safe_path(getattr(args, name)).is_file():
            raise ConsumerError("Required input must be a regular file")
    for name in ("resume_owned_run", "csm_dir"):
        if not safe_path(getattr(args, name)).is_dir():
            raise ConsumerError("Required artifact tree must be a directory")
    if not Path(args.resume_owned_run).is_relative_to(peer / "build/shizukudos/csm"):
        raise ConsumerError("Source run must remain inside the selected peer's CSM artifact root")
    for name in ("result.json", "windows-uefi.raw"):
        if not safe_path(Path(args.resume_owned_run) / name).is_file():
            raise ConsumerError("Source run lacks its retained raw disk/receipt")
    safe_path(OUTPUT_ROOT, existing=False)
    destination = OUTPUT_ROOT / args.run_name
    if destination.exists():
        raise ConsumerError("Theme run directory already exists")
    return peer, consumer, destination


def freeze_sources(peer, consumer, pins):
    sources = {name: read_source(peer / relative) for name, relative in SOURCE_FILES.items()}
    for name, expected in pins.items():
        if not re.fullmatch(r"[0-9a-f]{64}", expected) or digest(sources[name]) != expected:
            raise ConsumerError("Pinned source digest mismatch: " + name)
    functions = reviewed_functions(sources["adapter"])
    private = functions["private_reflink_runner"](sources["canonical"])
    # Source adaptation already verifies every exact old/new source anchor.
    compile(private, "private-native-runner.py", "exec")
    if any(read_source(peer / SOURCE_FILES[name]) != data for name, data in sources.items()):
        raise ConsumerError("Peer sources changed before freezing")
    consumer.mkdir(parents=True, mode=0o700)
    frozen = {}
    for name, data in sources.items():
        target = consumer / "original" / SOURCE_FILES[name]
        target.parent.mkdir(parents=True, exist_ok=True)
        with target.open("xb") as stream:
            stream.write(data)
        frozen[name] = {"origin": str(peer / SOURCE_FILES[name]), "sha256": digest(data), "frozen": str(target)}
    target = consumer / "private/shizukudos/csm/test_win98_uefi.py"
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as stream:
        stream.write(private)
    for name in ("qemu", "shzlib"):
        helper = target.parent.parent / "tools" / (name + ".py")
        helper.parent.mkdir(parents=True, exist_ok=True)
        with helper.open("xb") as stream:
            stream.write(sources[name])
    wrapper = consumer / "consumer-source.py"
    wrapper.write_bytes(read_source(Path(__file__).resolve()))
    return frozen, target, functions


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def ensure_unopened(path):
    """A retained source must be quiescent; inspect identities, never commands."""
    info = safe_path(path).stat()
    identity = (info.st_dev, info.st_ino)
    for process in Path("/proc").iterdir():
        if not process.name.isdecimal():
            continue
        try:
            descriptors = list((process / "fd").iterdir())
        except FileNotFoundError:
            continue
        except PermissionError as error:
            raise ConsumerError("Cannot prove retained source is unopened") from error
        for descriptor in descriptors:
            try:
                opened = descriptor.stat()
            except FileNotFoundError:
                continue
            if (opened.st_dev, opened.st_ino) == identity:
                raise ConsumerError("Retained source is opened by process " + process.name)
        try:
            lines = (process / "maps").read_text().splitlines()
        except FileNotFoundError:
            continue
        except PermissionError as error:
            raise ConsumerError("Cannot prove retained source is unmapped") from error
        for line in lines:
            pieces = line.split(None, 5)
            if len(pieces) < 5 or not pieces[4].isdecimal():
                continue
            major, minor = (int(item, 16) for item in pieces[3].split(":"))
            if (major, minor, int(pieces[4])) == (os.major(info.st_dev), os.minor(info.st_dev), info.st_ino):
                raise ConsumerError("Retained source is mapped by process " + process.name)


def configure_runner(private, cow_path, functions, peer, *, host_guard=None):
    helpers = private.parent.parent / "tools"
    qemu = load_module("qemu", helpers / "qemu.py")
    shzlib = load_module("shzlib", helpers / "shzlib.py")
    shzlib.REPO, shzlib.SHZ = peer, peer / "shizukudos"
    shzlib.BUILD = peer / "build/shizukudos"
    runner = load_module("theme_native_pinned_runner", private)
    runner.CSM = OUTPUT_ROOT
    cow = load_module("theme_native_pinned_cow", cow_path)
    state = {}
    original_reuse = runner.reuse_prepared
    original_launch = qemu.launch
    original_write = shzlib.write_json

    def reuse(run, run_dir, disk, *positional, **keywords):
        if host_guard:
            host_guard.check("before-private-source-reuse")
        previous = runner.CSM
        runner.CSM = peer / "build/shizukudos/csm"
        try:
            ensure_unopened(run / "windows-uefi.raw")
            partition, receipt = original_reuse(run, run_dir, disk, *positional, **keywords)
            source = run / "windows-uefi.raw"
            if (disk.stat().st_dev, disk.stat().st_ino) == (source.stat().st_dev, source.stat().st_ino) or disk.stat().st_nlink != 1:
                raise ConsumerError("Reflink clone must have its own private inode")
            receipt.update(method="verified private filesystem COW clone; cold hardware, new VARS, no CPU/RAM state",
                           copy_mode="cp --reflink=always; unsupported filesystems fail closed",
                           copy_metadata_budget_bytes=4 * 1024 ** 2)
            return partition, receipt
        finally:
            runner.CSM = previous
            if host_guard:
                host_guard.check("after-private-source-reuse")

    def capture(disk):
        observation = cow.observe_allocations(disk)
        state["baseline"] = observation
        return observation.to_dict()

    def growth(disk, result, monitor):
        if host_guard:
            host_guard.check("before-resource-poll", require_cow=True)
        observation, used, elapsed = functions["quiescent_cow_observation"](
            disk, monitor, cow, state["baseline"], runner.DIRTY_BUDGET, runner.RESERVE)
        budget = result["sparse_budget"]
        budget.update(cow_latest=observation.to_dict(), cow_net_exclusive_growth_bytes=used,
                      cow_peak_net_exclusive_growth_bytes=max(0, used, budget.get("cow_peak_net_exclusive_growth_bytes", 0)),
                      cow_quiescent_samples=budget.get("cow_quiescent_samples", 0) + 1,
                      cow_maximum_sampling_seconds=max(elapsed, budget.get("cow_maximum_sampling_seconds", 0)))
        if host_guard:
            host_guard.check("after-resource-poll", require_cow=True)
        return used

    def launch(*positional, **keywords):
        if host_guard:
            host_guard.check("before-launch", require_cow=True)
        child = original_launch(*positional, **keywords)
        state["child"] = child
        if host_guard:
            try:
                host_guard.check("after-launch", require_cow=True)
            except HostOutputError:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)
                raise
        return child

    def write_result(path, data):
        native_result = isinstance(data, dict) and data.get("profile") == "actual-win98-uefi-csmwrap"
        if native_result:
            data["private_cow_consumer"] = {
                "consumer_receipt": str(private.parents[3] / "consumer-result.json"),
                "canonical_source_adapted": True, "copy_mode": "cp --reflink=always --sparse=auto",
                "private_runner_sha256": digest(private.read_bytes()),
                "cow_helper_sha256": digest(Path(cow.__file__).read_bytes()),
                "guard": "owned QMP pause; two stable FIEMAP maps; net exclusive data growth; independent free-space floor",
                "io_sys_entry_adapter_executed": False,
            }
            if "sparse_budget" in data:
                data["sparse_budget"]["policy"] = "verified filesystem COW clone; paused FIEMAP net exclusive growth; independent reserve floor"
        if host_guard and native_result:
            return host_guard.write_receipt(path, data, "canonical-final-receipt")
        if host_guard:
            host_guard.check("before-result-write")
            host_guard.write_owned_json(path, data)
            host_guard.check("after-result-write")
            return
        value = original_write(path, data)
        return value

    if host_guard:
        def bounded_operation(name, operation):
            def wrapped(*positional, **keywords):
                host_guard.check("before-" + name)
                try:
                    return operation(*positional, **keywords)
                finally:
                    host_guard.check("after-" + name)
            return wrapped
        for name in ("capture", "capture_vga_scanout", "capture_gop_handover", "capture_cpu0_code",
                     "capture_proxy_diagnostics", "capture_failure_cpus", "collect_boot_logs",
                     "collect_interaction_file", "collect_native_trial", "collect_guest_files", "prepare_guest_files"):
            if hasattr(runner, name):
                setattr(runner, name, bounded_operation(name, getattr(runner, name)))

    runner.reuse_prepared = reuse
    runner._iosys_cow_capture, runner._iosys_cow_growth = capture, growth
    qemu.launch = launch
    shzlib.write_json = write_result
    return runner, cow, state


def stopped_observation(runner, cow, state, disk):
    child = state.get("child")
    if child is not None and child.poll() is None:
        # Fail closed for this handle alone; never use process-name termination.
        child.kill()
        child.wait(timeout=5)
        raise ConsumerError("Canonical runner returned with its owned VM still active")
    if "baseline" not in state or not disk.exists():
        return None
    observation = cow.observe_allocations(disk)
    growth = cow.net_exclusive_growth_bytes(state["baseline"], observation)
    free = shutil.disk_usage(disk.parent).free
    return {"status": "PASS" if growth <= runner.DIRTY_BUDGET and free >= runner.RESERVE else "FAIL",
            "observation": observation.to_dict(), "net_exclusive_growth_bytes": growth,
            "quota_bytes": runner.DIRTY_BUDGET, "free_bytes": free, "reserve_bytes": runner.RESERVE,
            "owned_writer_stopped": child is None or child.poll() is not None}


def acquire_native_lock(stream, wait_seconds):
    """Wait in bounded short intervals; never touch the current lock owner's VM."""
    if not 0 <= wait_seconds <= 1200:
        raise ConsumerError("Native lock wait must be between zero and 1200 seconds")
    deadline = time.monotonic() + wait_seconds
    while True:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return
        except BlockingIOError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ConsumerError("Native guest lane remained busy through the selected wait bound")
            time.sleep(min(0.2, remaining))


def main(argv=None, *, host_guard=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--peer-root", type=Path, required=True)
    parser.add_argument("--consumer-dir", type=Path, required=True)
    for name in ("canonical", "adapter", "cow"):
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--lock-wait-seconds", type=int, default=0)
    parser.add_argument("native", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if not 0 <= args.lock_wait_seconds <= 1200:
        parser.error("Native lock wait must be between zero and 1200 seconds")
    native = args.native[1:] if args.native[:1] == ["--"] else args.native
    trial, native = native_arguments(native)
    peer, consumer, destination = validate_paths(trial, args.peer_root, args.consumer_dir)
    host_guard = host_guard or HostOutputGuard([consumer, destination], destination / "windows-uefi.raw",
                                             reserve=trial.reserve_gib * 1024**3)
    if (consumer not in host_guard.roots or destination not in host_guard.roots
            or host_guard.private_cow != destination / "windows-uefi.raw"
            or host_guard.reserve < trial.reserve_gib * 1024**3):
        raise ConsumerError("Host-output guard does not cover the actual consumer/run and selected reserve")
    receipt = {"schema": 1, "status": "FAIL", "native_arguments": native, "run_directory": str(destination),
               "execute_requested": args.execute, "vm_started": False,
               "lock_wait_bound_seconds": args.lock_wait_seconds, "native_lock_acquired": False,
               "native_theme_acceptance": "not-established", "visual_review_required": True,
               "adapter_functions": list(FUNCTIONS), "io_sys_entry_adapter_executed": False,
               "allocation_scope": "net exclusive FIEMAP file data; metadata/staging excluded; independent free-space floor"}
    receipt_path = consumer / "consumer-result.json"

    def write_receipt():
        host_guard.write_owned_json(receipt_path, receipt)

    code = 1
    lock_stream = None
    try:
        host_guard.check("before-source-freeze")
        frozen, private, functions = freeze_sources(peer, consumer, {
            name: getattr(args, name + "_sha256") for name in ("canonical", "adapter", "cow")})
        receipt.update(status="PREPARED", sources=frozen,
                       consumer_sha256=digest(read_source(Path(__file__).resolve())),
                       private_runner={"path": str(private), "sha256": digest(private.read_bytes())},
                       host_output_budget=host_guard.check("after-source-freeze"))
        write_receipt()
        host_guard.check("after-prepared-receipt")
        if not args.execute:
            code = 0
        else:
            lock_path = safe_path(peer / "build/modern-app-native-guest.lock")
            if not lock_path.is_file():
                raise ConsumerError("Shared native guest lock must already exist")
            lock_stream = lock_path.open("rb")
            receipt["status"] = "WAITING-FOR-NATIVE-LANE"
            write_receipt()
            host_guard.check("before-native-lock-wait")
            acquire_native_lock(lock_stream, args.lock_wait_seconds)
            receipt.update(status="PREPARING", native_lock_acquired=True)
            write_receipt()
            host_guard.check("after-native-lock-acquired")
            runner, cow, state = configure_runner(private, Path(frozen["cow"]["frozen"]), functions, peer,
                                                  host_guard=host_guard)
            original_argv = sys.argv
            try:
                sys.argv = [str(private), *native]
                code = runner.main()
            finally:
                sys.argv = original_argv
                receipt["vm_started"] = "child" in state
                receipt["cow_final"] = stopped_observation(runner, cow, state, destination / "windows-uefi.raw")
            receipt["canonical_exit_code"] = code
            sources_unchanged = all(digest(read_source(Path(item["origin"]))) == item["sha256"] for item in frozen.values())
            receipt["peer_sources_unchanged"] = sources_unchanged
            if not sources_unchanged or not receipt.get("cow_final") or receipt["cow_final"]["status"] != "PASS":
                code = 1
            receipt["status"] = "NEEDS-VISUAL-REVIEW" if code == 0 else "FAIL"
            receipt["host_output_budget"] = host_guard.check("after-owned-run")
    except BaseException as error:
        receipt.update(status="FAIL", error=str(error))
        code = 1
    finally:
        receipt["host_output_budget"] = host_guard.to_dict()
        if host_guard.failure:
            receipt.update(status="FAIL", resource_failure=host_guard.failure)
            code = 1
        try:
            if consumer.exists():
                host_guard.write_receipt(receipt_path, receipt, "consumer-final-receipt")
            else:
                receipt["host_output_budget"] = host_guard.check("consumer-final-receipt")
        except (OSError, ConsumerError) as error:
            receipt.update(status="FAIL", receipt_write_error=str(error), host_output_budget=host_guard.to_dict())
            if host_guard.failure:
                receipt["resource_failure"] = host_guard.failure
            code = 1
        finally:
            if lock_stream is not None:
                lock_stream.close()
    print(json.dumps({"status": receipt["status"], "vm_started": receipt["vm_started"],
                      "receipt": str(receipt_path), "error": receipt.get("error")}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
