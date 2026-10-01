#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded whole-TU Kernel32 IPC host proof and i486 compile-only fact.

Only exact clean fixture success is accepted; watchdog, compile, sanitizer and resource failures are FAIL.
Recursive temporaries, executables, aggregate captures and a self-inclusive
receipt share one new 8 MiB root admitted above the strict 20 GiB floor.
Live sampling and per-file RLIMIT_FSIZE observe output use, not transient peaks
or a filesystem quota. No /dev/shm, compiler or VM admission exception.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import selectors
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 8 * 1024 * 1024
RESERVE = 20 * 1024 * 1024 * 1024
CAPTURE_LIMIT = 256 * 1024
RECEIPT_LIMIT = 256 * 1024
PENDING = CAPTURE_LIMIT + RECEIPT_LIMIT + 64 * 1024
SOURCE_INPUT_LIMIT = 2 * 1024 * 1024
TOOL_INPUT_LIMIT = 256 * 1024 * 1024
DEPENDENCY_LIMIT = 64 * 1024
DEPENDENCY_PATH_LIMIT = 256
COMMAND_TIMEOUT = 60
BASE_GUARD_SHA256 = "1b52856e537b298ea253d564754afefc35eb340bd7f7090fc1b30786bfa4f44e"
FROZEN_PRODUCTION_SHA256 = "aedac9a030f22b379e844a66c72ed159cecc4b8796f22218f32dc85e1bab8bd2"
FROZEN_FIXTURE_SHA256 = "165391eb9704f8e4f0a65b0f2a5d7a9439e710a3bccfd47893dc37b799359e21"
FROZEN_PEER_RUNNER_SHA256 = "6fe78436f8d48c5df143cbf7b3018bd686a4db77004a5bcd68594fa7fcef4531"
CANONICAL_PEER_HEADER_SHA256_REFERENCE = "17c19bcf8295338c02cbcdb83e3ad4c0618e28f78d62ec3568d1ae50b10a2031"
INVALID_RECEIPT_SCHEMA = "k32-ipc-guarded-host-invalid-receipt-v1"
EXPECTED_CASE_CHECKS = {
    "head": 10, "magic": 11, "slots": 11, "size": 11,
    "malformed": 19, "refill": 270, "normal": 33,
}
EXPECTED_CHECKS_PER_MODE = 365
# Exact peer flags from the frozen nonexecuted reference runner. These apply
# only to production ipc.c's relocatable object, never to the host fixtures.
K32_FLAGS = [
    "-m32", "-march=i486", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding",
    "-fno-builtin", "-fno-pic", "-fno-pie", "-mno-sse", "-mno-mmx", "-msoft-float",
    "-fno-stack-protector", "-fno-asynchronous-unwind-tables", "-fno-ident", "-fno-common",
    "-mpreferred-stack-boundary=2", "-fwrapv", "-fno-strict-aliasing",
    "-fno-tree-loop-distribute-patterns",
]


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def hash_regular(path, *, maximum=None, guard=None):
    """Hash only the named regular inode and reject changes during the read."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or (maximum is not None and before.st_size > maximum):
            raise RuntimeError("unbounded or nonregular source/tool input")
        digest = hashlib.sha256()
        read_bytes = 0
        started = time.monotonic()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            read_bytes += len(block)
            if (maximum is not None and read_bytes > maximum) or time.monotonic() - started > COMMAND_TIMEOUT:
                raise RuntimeError("source/tool hash exceeded its byte/time bound")
            digest.update(block)
            if guard is not None:
                guard.check()
        after = os.fstat(fd)
        if identity(before) != identity(after) or identity(after) != identity(path.stat(follow_symlinks=False)):
            raise RuntimeError("input identity changed while hashing")
        return {"sha256": digest.hexdigest(), "identity": list(identity(after))}
    finally:
        os.close(fd)


def snapshot(paths, *, guard=None):
    return {str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path):
            hash_regular(path, maximum=SOURCE_INPUT_LIMIT, guard=guard) for path in paths}


def dependencies(path, target):
    """Parse actual compiler -M output, including all standard/system headers."""
    pinned = hash_regular(path, maximum=DEPENDENCY_LIMIT)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or list(identity(opened)) != pinned["identity"]:
            raise RuntimeError("compiler dependency manifest identity changed before read")
        content = bytearray()
        while True:
            block = os.read(fd, min(16384, DEPENDENCY_LIMIT + 1 - len(content)))
            if not block:
                break
            content.extend(block)
            if len(content) > DEPENDENCY_LIMIT:
                raise RuntimeError("compiler dependency manifest read exceeded 64 KiB")
        raw = bytes(content)
        if (list(identity(os.fstat(fd))) != pinned["identity"]
                or hashlib.sha256(raw).hexdigest() != pinned["sha256"]):
            raise RuntimeError("compiler dependency manifest changed during bounded read")
    finally:
        os.close(fd)
    if hash_regular(path, maximum=DEPENDENCY_LIMIT) != pinned:
        raise RuntimeError("compiler dependency manifest changed during read")
    text = raw.decode("utf-8", errors="strict").replace("\\\n", "")
    prefix = target + ":"
    if not text.startswith(prefix):
        raise RuntimeError("unexpected actual compiler dependency target")
    names = shlex.split(text[len(prefix):], posix=True)
    if not names or len(names) > DEPENDENCY_PATH_LIMIT:
        raise RuntimeError("actual compiler header closure is empty or unbounded")
    paths = []
    for name in names:
        candidate = Path(name.replace("$$", "$"))
        if not candidate.is_absolute():
            candidate = ROOT / candidate
        paths.append(candidate.resolve(strict=True))
    return sorted(set(paths)), {"manifest": str(path), **pinned,
                                "declared_paths": names,
                                "resolved_paths": [str(path) for path in sorted(set(paths))]}


def safe_components(path):
    for component in (path, *path.parents):
        if component.is_symlink():
            raise RuntimeError("symlinked proof path refused")


def admission():
    free = shutil.disk_usage(ROOT).free
    if free < RESERVE + LIMIT:
        raise RuntimeError(f"BLOCKED: available={free}, required={RESERVE + LIMIT}")
    return free


class Guard:
    """Observed recursive enforcement; a crossed guard remains latched."""
    def __init__(self, output):
        self.output = output
        info = output.lstat()
        self.root_identity = (info.st_dev, info.st_ino)
        self.root_fd = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened = os.fstat(self.root_fd)
        if (opened.st_dev, opened.st_ino) != self.root_identity:
            os.close(self.root_fd)
            raise RuntimeError("new proof root changed before ownership anchoring")
        self.failure = None
        self.minimum_free = shutil.disk_usage(ROOT).free
        self.peak = 0
        self.capture_bytes = 0

    def close(self):
        os.close(self.root_fd)

    def sample_free(self, *, failure_evidence=False):
        free = shutil.disk_usage(ROOT).free
        self.minimum_free = min(self.minimum_free, free)
        if free < RESERVE:
            self.failure = self.failure or f"20 GiB reserve crossed: available={free}"
            if not failure_evidence:
                raise RuntimeError(self.failure)
        return free

    def count(self, *, failure_evidence=False):
        """Count all descendant regular-file bytes, including nested TMP output.

        Only membership/ENOENT churn is retried. Both partial and final sums
        enforce the cap; unsafe types, links, mounts or identities fail closed.
        An explicitly failing receipt may count safely after a latched floor
        crossing, but that flag cannot admit a command, capture or success.
        """
        safe_components(self.output)
        root = self.output.lstat()
        if not stat.S_ISDIR(root.st_mode) or (root.st_dev, root.st_ino) != self.root_identity:
            raise RuntimeError("owned proof root identity changed")
        for _ in range(4):
            self.sample_free(failure_evidence=failure_evidence)
            total = 0
            directories = {}
            files = {}
            directory_count = 0
            def walk(directory, depth):
                nonlocal total, directory_count
                if depth > 16:
                    raise RuntimeError("temporary tree depth exceeded 16")
                info = directory.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_dev != self.root_identity[0]:
                    raise RuntimeError("unsafe temporary directory or foreign mount")
                directory_count += 1
                if directory_count > 128:
                    raise RuntimeError("temporary directory count exceeded 128")
                names = sorted(directory.iterdir())
                directories[directory] = ((info.st_dev, info.st_ino), names)
                self.sample_free(failure_evidence=failure_evidence)
                for path in names:
                    entry = path.lstat()
                    if entry.st_dev != self.root_identity[0]:
                        raise RuntimeError("foreign temporary filesystem refused")
                    if stat.S_ISDIR(entry.st_mode):
                        walk(path, depth + 1)
                    elif stat.S_ISREG(entry.st_mode) and entry.st_nlink == 1:
                        files[path] = ((entry.st_dev, entry.st_ino), entry.st_size)
                        if len(files) > 4096:
                            raise RuntimeError("temporary file count exceeded 4096")
                        total += entry.st_size
                        self.peak = max(self.peak, total)
                        if total > LIMIT:
                            raise RuntimeError("recursive combined proof files exceeded 8 MiB")
                    else:
                        raise RuntimeError("unexpected temporary type, symlink or hardlink")
            try:
                walk(self.output, 0)
                stable = True
                for directory, (pinned, names) in directories.items():
                    now = directory.lstat()
                    if not stat.S_ISDIR(now.st_mode) or (now.st_dev, now.st_ino) != pinned:
                        raise RuntimeError("temporary directory identity changed")
                    if sorted(directory.iterdir()) != names:
                        stable = False
                if not stable:
                    continue
                # Existing regular files may grow between live observations;
                # retain the larger size, without pretending to see all peaks.
                for path, (pinned, size) in files.items():
                    now = path.lstat()
                    if (not stat.S_ISREG(now.st_mode) or now.st_nlink != 1
                            or (now.st_dev, now.st_ino) != pinned):
                        raise RuntimeError("temporary file identity/type/link changed")
                    total += max(0, now.st_size - size)
                    self.peak = max(self.peak, total)
                    if total > LIMIT:
                        raise RuntimeError("recursive combined proof files exceeded 8 MiB")
                self.sample_free(failure_evidence=failure_evidence)
                return total
            except FileNotFoundError:
                continue
        raise RuntimeError("recursive compiler temporary membership did not stabilize")

    def check(self, extra=0):
        try:
            self.sample_free()
            if self.count() + extra > LIMIT:
                raise RuntimeError("recursive files plus pending write exceeded 8 MiB")
            if self.failure:
                raise RuntimeError(self.failure)
        except (OSError, RuntimeError) as error:
            self.failure = self.failure or str(error)
            raise

    def write(self, path, data):
        if path.parent != self.output:
            raise RuntimeError("write escaped the owned proof root")
        self.check(len(data))
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=self.root_fd)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
        finally:
            os.close(fd)
        self.check()


def classify_test(completed, case):
    """A watchdog or any extra/missing stdout/diagnostic can never be success."""
    expected = f"Kernel32 IPC {case}: {EXPECTED_CASE_CHECKS[case]} checks passed\n".encode("ascii")
    if completed.returncode != 0 or completed.stderr or completed.stdout != expected:
        raise RuntimeError(f"IPC case {case} did not complete its exact clean assertion contract")
    return {"case": case, "completed_checks": EXPECTED_CASE_CHECKS[case],
            "failed_checks": 0, "expected_stdout": expected.decode("ascii")}


def verify_peer_flags(path, pinned):
    """Read only AST literal data; never import or execute the peer runner."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or list(identity(before)) != pinned["identity"]:
            raise RuntimeError("frozen peer runner identity changed before literal flags read")
        raw = bytearray()
        while True:
            block = os.read(fd, min(16384, SOURCE_INPUT_LIMIT + 1 - len(raw)))
            if not block:
                break
            raw.extend(block)
            if len(raw) > SOURCE_INPUT_LIMIT:
                raise RuntimeError("peer AST input exceeded source bound")
        if (list(identity(os.fstat(fd))) != pinned["identity"]
                or hashlib.sha256(raw).hexdigest() != pinned["sha256"]):
            raise RuntimeError("peer runner changed during literal flags read")
    finally:
        os.close(fd)
    if hash_regular(path, maximum=SOURCE_INPUT_LIMIT) != pinned:
        raise RuntimeError("peer flags reference path changed")
    tree = ast.parse(bytes(raw), filename=str(path))
    rows = [node for node in tree.body if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "K32_FLAGS"
                    for target in node.targets)]
    if len(rows) != 1 or ast.literal_eval(rows[0].value) != K32_FLAGS:
        raise RuntimeError("freestanding compile flags differ from the exact frozen peer literal")


def elf32_i486_object(path, pinned, guard):
    """Validate a pinned object's ELF header; no link, disassembly or execution."""
    guard.check()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_size < 52
                or list(identity(before)) != pinned["identity"]):
            raise RuntimeError("i486 object identity/size is invalid")
        header = os.read(fd, 52)
        if (len(header) != 52 or list(identity(os.fstat(fd))) != pinned["identity"]
                or list(identity(path.lstat())) != pinned["identity"]):
            raise RuntimeError("i486 object changed during ELF header read")
    finally:
        os.close(fd)
    fields = struct.unpack("<16sHHIIIIIHHHHHH", header)
    ident = fields[0]
    if (ident[:4] != b"\x7fELF" or ident[4:7] != b"\x01\x01\x01"
            or fields[1] != 1 or fields[2] != 3 or fields[3] != 1 or fields[8] != 52):
        raise RuntimeError("native compile did not produce ELF32 little-endian EM_386 ET_REL")
    if hash_regular(path, maximum=LIMIT, guard=guard) != pinned:
        raise RuntimeError("i486 object bytes changed after ELF inspection")
    return {"class_bits": 32, "endianness": "little", "elf_type": "ET_REL",
            "elf_type_value": 1, "machine": "EM_386", "machine_value": 3,
            "elf_version": 1, "header_bytes": 52,
            "header_sha256": hashlib.sha256(header).hexdigest(),
            "complete_elf_section_validation": False, "i486_instruction_set_verified": False,
            "linked": False, "executed": False}


def write_receipt(output, receipt, guard):
    """Preserve bounded failure evidence, including after a crossed floor.

    This one evidence write never authorizes another subprocess or a PASS. A
    final floor/identity/cap failure replaces the prospective verdict with FAIL.
    """
    path = output / "result.json"

    def encoded(base, old_size=0):
        receipt["output_bytes_before_receipt"] = base - old_size
        receipt["final_output_bytes"] = base - old_size
        for _ in range(16):
            data = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode()
            final = base - old_size + len(data)
            if final == receipt["final_output_bytes"]:
                if len(data) > RECEIPT_LIMIT or final > LIMIT:
                    raise RuntimeError("self-inclusive final receipt exceeds admitted bound")
                return data
            receipt["final_output_bytes"] = final
        raise RuntimeError("self-inclusive receipt did not stabilize")

    receipt["minimum_observed_free_bytes"] = guard.minimum_free
    receipt["resource_failure"] = guard.failure
    receipt["peak_observed_output_bytes"] = guard.peak
    receipt["receipt_accounting_verified"] = False
    free = shutil.disk_usage(ROOT).free
    guard.minimum_free = min(guard.minimum_free, free)
    receipt["minimum_observed_free_bytes"] = guard.minimum_free
    receipt["available_at_receipt_bytes"] = free
    if free < RESERVE or guard.failure:
        guard.failure = guard.failure or "reserve crossed before final receipt"
        receipt.update(result="FAIL", resource_failure=guard.failure)
    # This bounded FAIL-only evidence path does not relax command admission.
    # In particular an already crossed floor must not bypass a FAIL receipt
    # merely because normal guard.count() refuses that floor.
    base = guard.count(failure_evidence=True)
    if guard.failure:
        receipt.update(result="FAIL", resource_failure=guard.failure,
                       minimum_observed_free_bytes=guard.minimum_free)
    try:
        data = encoded(base)
    except RuntimeError as error:
        guard.failure = guard.failure or str(error)
        # Oversized metadata is infrastructure FAIL, never a truncated PASS.
        receipt.clear()
        receipt.update(schema=INVALID_RECEIPT_SCHEMA, result="FAIL",
                       receipt_accounting_verified=False, evidence_complete=False,
                       resource_failure=guard.failure,
                       error=str(error)[:2048], reserve_bytes=RESERVE, output_limit_bytes=LIMIT,
                       minimum_observed_free_bytes=guard.minimum_free)
        data = encoded(base)
    fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                 0o600, dir_fd=guard.root_fd)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
        pinned = os.fstat(fd)
    except BaseException:
        os.close(fd)
        raise
    try:
        try:
            for _ in range(16):
                guard.check()
                total = guard.count()       # includes this actual receipt
                free = shutil.disk_usage(ROOT).free
                guard.minimum_free = min(guard.minimum_free, free)
                if free < RESERVE:
                    raise RuntimeError("reserve crossed during final receipt sample")
                before = path.lstat()
                if ((before.st_dev, before.st_ino) != (pinned.st_dev, pinned.st_ino)
                        or before.st_nlink != 1):
                    raise RuntimeError("final receipt identity changed")
                receipt.update(minimum_observed_free_bytes=guard.minimum_free,
                               peak_observed_output_bytes=guard.peak,
                               available_at_receipt_bytes=free,
                               receipt_accounting_verified=True)
                replacement = encoded(total, len(data))
                if replacement == data:
                    if total != receipt["final_output_bytes"]:
                        raise RuntimeError("final receipt accounting mismatch")
                    return
                # Keep the same owned FD while stabilizing the actual final
                # minimum/peak and the bytes contributed by the receipt itself.
                os.lseek(fd, 0, os.SEEK_SET)
                os.ftruncate(fd, 0)
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(replacement)
                data = replacement
            raise RuntimeError("final observed receipt metadata did not stabilize")
        except (OSError, RuntimeError) as error:
            guard.failure = guard.failure or str(error)
            free = shutil.disk_usage(ROOT).free
            guard.minimum_free = min(guard.minimum_free, free)
            receipt.update(result="FAIL", resource_failure=guard.failure,
                           minimum_observed_free_bytes=guard.minimum_free,
                           peak_observed_output_bytes=guard.peak,
                           receipt_accounting_verified=False,
                           available_at_receipt_bytes=free)
            # The already-open owned receipt inode remains available even if
            # a path/root check failed. Never reopen or follow an unsafe path.
            opened = os.fstat(fd)
            if ((opened.st_dev, opened.st_ino) != (pinned.st_dev, pinned.st_ino)
                    or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
                raise RuntimeError("unsafe owned FAIL receipt inode") from error
            try:
                replacement = encoded(guard.count(failure_evidence=True), len(data))
            except (OSError, RuntimeError):
                # Unsafe scope/accounting cannot produce a complete proof.
                # Shrink this prospective receipt to an explicit invalid FAIL
                # so no readable success survives final guard failure.
                replacement = (json.dumps({"schema": INVALID_RECEIPT_SCHEMA, "result": "FAIL",
                                           "receipt_accounting_verified": False, "evidence_complete": False,
                                           "error": str(error)[:2048]}) + "\n").encode()
            os.lseek(fd, 0, os.SEEK_SET)
            os.ftruncate(fd, 0)
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(replacement)
            raise RuntimeError(guard.failure) from error
    finally:
        os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_root
    allowed = ROOT / "build" / "k32-ipc-guarded-6970"
    if not output.is_absolute() or output.parent != allowed or output.exists():
        raise SystemExit("output must be one NEW absolute direct child of build/k32-ipc-guarded-6970")
    safe_components(output)
    if ROOT != ROOT.resolve():
        raise SystemExit("source root must be canonical")
    source = ROOT / "shizukudos/kernel32/tests/test_ipc_host.c"
    production = ROOT / "shizukudos/kernel32/ipc.c"
    peer_runner = ROOT / "shizukudos/tests/test_k32_ipc.py"
    base_guard = ROOT / "ntwin32/legacy_provider_bridge/test_native_sspi_6970.py"
    ipc_header = ROOT / "shizukudos/abi/shz_ipc.h"
    project_headers = [
        ROOT / "shizukudos/kernel32/k32.h", ipc_header,
        ROOT / "shizukudos/abi/shz_abi.h", ROOT / "shizukudos/kcommon/khc.h",
    ]
    closure = [source, Path(__file__).resolve(), production, peer_runner, base_guard, *project_headers]
    before = snapshot(closure)
    frozen_inputs = {
        base_guard: (BASE_GUARD_SHA256, 41247),
        production: (FROZEN_PRODUCTION_SHA256, 5327),
        source: (FROZEN_FIXTURE_SHA256, 8044),
        peer_runner: (FROZEN_PEER_RUNNER_SHA256, 5052),
    }
    for frozen, (digest, size) in frozen_inputs.items():
        info = before[str(frozen.relative_to(ROOT))]
        if info["sha256"] != digest or info["identity"][2] != size:
            raise SystemExit("frozen Kernel32 input or guarded provenance source changed")
    if sum(EXPECTED_CASE_CHECKS.values()) != EXPECTED_CHECKS_PER_MODE or len(EXPECTED_CASE_CHECKS) != 7:
        raise SystemExit("invalid independent seven-case IPC stdout contract")
    verify_peer_flags(peer_runner, before[str(peer_runner.relative_to(ROOT))])
    try:
        available = admission()        # no proof directory or compiler before admission
    except RuntimeError as error:
        print(json.dumps({"result": "BLOCKED_NOT_RUN", "reason": str(error)}))
        return 3
    try:
        available = admission()         # fresh full budget immediately before owned mkdir
    except RuntimeError as error:
        print(json.dumps({"result": "BLOCKED_NOT_RUN", "reason": str(error)}))
        return 3
    output.mkdir(parents=True, exist_ok=False)
    guard = Guard(output)
    receipt = {"schema": "k32-ipc-production-host-and-i486-compile-v1", "phase": "green",
               "result": "NOT_COMPLETED", "source_inputs": before,
               "source_hashes": {key: info["sha256"] for key, info in before.items()},
               "available_before_bytes": available, "output_limit_bytes": LIMIT,
               "reserve_bytes": RESERVE, "output_root": str(output), "commands": [],
               "native_execution_verified": False, "windows98_integration_verified": False,
               "network_execution_verified": False, "os_tls_provider_verified": False,
               "application_compatibility_verified": False,
               "scope": "complete production Kernel32 IPC TU with host-only scheduler/hypercall boundaries; separate freestanding i486 production object compile",
               "actual_windows_dll_abi_verified": False, "os_registration_verified": False,
               "kernel64_backend_verified": False, "credential_execution_verified": False,
               "concurrent_join_verified": False, "real_provider_dll_execution_verified": False,
               "reported_hosted_checkout_sha": os.environ.get("GITHUB_SHA"),
               "hosted_checkout_independently_verified_by_runner": False,
               "self_loaded_runner_binding_verified": False,
               "kernel32_native_execution_verified": False, "vmm_execution_verified": False,
               "context_switch_execution_verified": False, "deadline_scheduler_execution_verified": False,
               "cross_domain_execution_verified": False,
               "peer_integration_verified": False, "standalone_boot_execution_verified": False,
               "object_compile_verified": False,
               "peer_receipt_inherited": False, "peer_runner_executed_or_imported": False,
               "peer_flags_literal_ast_verified": True, "native_object_flags": list(K32_FLAGS),
               "ipc_header_context": {
                   "actual_path": str(ipc_header.relative_to(ROOT)),
                   "actual_before": before[str(ipc_header.relative_to(ROOT))],
                   "canonical_peer_header_sha256_reference": CANONICAL_PEER_HEADER_SHA256_REFERENCE,
                   "same_bytes_as_peer_reference":
                   before[str(ipc_header.relative_to(ROOT))]["sha256"] == CANONICAL_PEER_HEADER_SHA256_REFERENCE,
                   "scope": "actual own compiler closure; differing peer headers/results are not inherited"},
               "capture_limit_bytes_aggregate": CAPTURE_LIMIT,
               "receipt_limit_bytes": RECEIPT_LIMIT,
               "guard_model": {
                   "recursive_regular_file_logical_bytes": True,
                   "sample_interval_seconds": 0.05, "per_file_rlimit_fsize": True,
                   "aggregate_filesystem_quota": False,
                   "all_transient_create_unlink_peaks_observed": False,
                   "maximum_directories": 128, "maximum_files": 4096, "maximum_depth": 16,
                   "bounded_fail_receipt_authorizes_further_work": False},
               "provenance_limits": {
                   "source_or_header_bytes_per_file": SOURCE_INPUT_LIMIT,
                   "direct_compiler_bytes_per_file": TOOL_INPUT_LIMIT,
                   "hash_seconds_per_input": COMMAND_TIMEOUT,
                   "dependency_manifest_bytes": DEPENDENCY_LIMIT,
                   "dependency_declared_path_count": DEPENDENCY_PATH_LIMIT,
                   "subprocess_seconds": COMMAND_TIMEOUT,
                   "actual_M_and_MD_include_closures_required": True,
                   "actual_M_and_MD_include_closures_hashed": False,
                   "compiler_backend_linker_dynamic_runtime_kernel_closure_verified": False,
                   "python_runtime_or_self_loaded_code_attestation_verified": False},
               "derived_guard_source_sha256": BASE_GUARD_SHA256,
               "expected_checks_per_mode": EXPECTED_CHECKS_PER_MODE,
               "expected_case_checks": dict(EXPECTED_CASE_CHECKS),
               "standard_header_closure": {}, "standard_header_inputs_before": {},
               "standard_header_inputs_after": {}}
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
           "TMPDIR": str(output), "TMP": str(output), "TEMP": str(output),
           "PYTHONDONTWRITEBYTECODE": "1", "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
           "UBSAN_OPTIONS": "halt_on_error=1"}
    recipes = [("host", "gcc", ["-O1"]),
               ("sanitizer", "clang", ["-O1", "-fsanitize=address,undefined",
                                      "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"])]

    def run(argv, label):
        admission()
        guard.check(PENDING)
        if not all(hasattr(os, name) for name in ("waitid", "P_PID", "WEXITED", "WNOHANG", "WNOWAIT")):
            raise RuntimeError("nonreaping owned process-group observation is unavailable")
        budget = LIMIT - guard.count() - PENDING
        def child_limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (budget, budget))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        start = time.monotonic()
        selector = selectors.DefaultSelector()
        try:
            child = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     start_new_session=True, preexec_fn=child_limits)
        except BaseException:
            selector.close()
            raise
        chunks = {"stdout": bytearray(), "stderr": bytearray()}
        aborted = None
        group_kill = "NOT_REQUESTED"
        leader_exit_observed = False
        try:
            selector.register(child.stdout, selectors.EVENT_READ, "stdout")
            selector.register(child.stderr, selectors.EVENT_READ, "stderr")
            while True:
                guard.check(PENDING)
                if time.monotonic() - start > COMMAND_TIMEOUT:
                    raise RuntimeError("bounded compiler/fixture subprocess timeout")
                # Keep an exited group leader waitable until its owned pipes
                # close or abort teardown completes. poll() would reap it and
                # release the PID/PGID before descendant termination.
                observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                leader_exit_observed = bool(observed and observed.si_pid == child.pid)
                if leader_exit_observed and not selector.get_map():
                    break
                for key, _ in selector.select(0.05):
                    block = os.read(key.fileobj.fileno(), 16384)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        if guard.capture_bytes + len(block) > CAPTURE_LIMIT:
                            raise RuntimeError("whole-run aggregate capture exceeded 256 KiB")
                        guard.capture_bytes += len(block)
                        chunks[key.data].extend(block)
            guard.check(PENDING)
            child.wait(timeout=5)
        except BaseException as error:
            aborted = str(error)[:2048]
            # The compiler driver may already have exited while one of its
            # owned descendants keeps the pipe or a temporary file open.
            # Teardown always targets this launch's process group, never a
            # peer PID and never merely the direct child's running state.
            try:
                os.killpg(child.pid, signal.SIGKILL)
                group_kill = "SIGKILL_SENT_TO_OWNED_GROUP"
            except ProcessLookupError:
                group_kill = "OWNED_GROUP_ALREADY_ABSENT"
            except OSError as kill_error:
                group_kill = "FAILED: " + str(kill_error)
            child.wait(timeout=5)
            if group_kill.startswith("FAILED:"):
                raise RuntimeError("owned process-group teardown failed") from error
            raise
        finally:
            selector.close()
            child.stdout.close()
            child.stderr.close()
            receipt["commands"].append({"label": label, "argv": [str(value) for value in argv],
                                        "returncode": child.returncode, "owned_pid": child.pid,
                                        "reaped": child.returncode is not None, "aborted": aborted,
                                        "owned_group_kill": group_kill,
                                        "nonreaping_leader_exit_observed": leader_exit_observed,
                                        "group_lifetime_observation": "waitid WNOWAIT until EOF/abort then wait",
                                        "elapsed_seconds": time.monotonic() - start,
                                        "rlimit_fsize_bytes": budget,
                                        "captured_bytes": sum(map(len, chunks.values())),
                                        "aggregate_captured_bytes": guard.capture_bytes,
                                        "captured_sha256": {name: hashlib.sha256(data).hexdigest()
                                                            for name, data in chunks.items()},
                                        "aborted_stderr_preview": bytes(chunks["stderr"][:2048]).decode(errors="replace")
                                        if aborted else None})
        guard.write(output / (label + ".stdout"), bytes(chunks["stdout"]))
        guard.write(output / (label + ".stderr"), bytes(chunks["stderr"]))
        return subprocess.CompletedProcess(argv, child.returncode, bytes(chunks["stdout"]), bytes(chunks["stderr"]))

    try:
        compilers = {}
        for _, compiler, _ in recipes:
            found = shutil.which(compiler, path=env["PATH"])
            if not found:
                raise RuntimeError("required actual compiler is unavailable")
            path = Path(found).resolve(strict=True)
            tool = hash_regular(path, maximum=TOOL_INPUT_LIMIT, guard=guard)
            version = run([str(path), "--version"], compiler + "-version")
            if version.returncode or version.stderr or not version.stdout.splitlines():
                raise RuntimeError("actual compiler version query failed")
            compilers[compiler] = {"path": str(path), **tool,
                                   "version": version.stdout.decode(errors="strict").splitlines()[0]}
        receipt["compilers"] = compilers
        results = {}
        artifacts = {}

        def build(label, compiler, flags, translation_unit, artifact_path, *, object_only=False):
            common = [compilers[compiler]["path"], *flags]
            target = "k32_ipc_" + label + "_proof"
            depfile = output / (label + ".includes")
            discovered = run([*common, "-M", "-MT", target, "-MF", str(depfile),
                              str(translation_unit)], label + "-dependencies")
            if discovered.returncode or discovered.stdout or discovered.stderr:
                raise RuntimeError("actual IPC compiler dependency discovery emitted failure/diagnostics")
            included, manifest = dependencies(depfile, target)
            required = {translation_unit, production, *project_headers}
            if not required <= set(included):
                raise RuntimeError("complete IPC TU and own project ABI absent from actual include closure")
            if object_only and source in included:
                raise RuntimeError("native production object unexpectedly included the host fixture")
            includes_before = snapshot(included, guard=guard)
            receipt["standard_header_closure"][label] = manifest
            receipt["standard_header_inputs_before"][label] = includes_before
            compile_depfile = output / (label + "-compile.includes")
            command = [*common, "-MD", "-MT", target, "-MF", str(compile_depfile)]
            if object_only:
                command.append("-c")
            command.extend([str(translation_unit), "-o", str(artifact_path)])
            compiled = run(command, label + "-compile")
            if compiled.returncode:
                raise RuntimeError("IPC compiler failure is not fixture success: "
                                   + compiled.stderr[:2048].decode(errors="replace"))
            if compiled.stdout or compiled.stderr:
                raise RuntimeError("IPC compiler diagnostics are not a clean proof")
            compiled_includes, compile_manifest = dependencies(compile_depfile, target)
            if compiled_includes != included or snapshot(included, guard=guard) != includes_before:
                raise RuntimeError("actual IPC -M/-MD include closure changed before use")
            receipt["standard_header_closure"][label]["compile_manifest"] = compile_manifest
            artifact = hash_regular(artifact_path, maximum=LIMIT, guard=guard)
            artifacts[artifact_path] = artifact
            return included, includes_before, artifact

        host_common = ["-std=gnu11", "-g0", "-Wall", "-Wextra", "-Werror"]
        for kind, compiler, flags in recipes:
            exe = output / ("k32-ipc-" + kind)
            included, includes_before, artifact = build(kind, compiler, [*host_common, *flags], source, exe)
            case_results = {}
            for case in EXPECTED_CASE_CHECKS:
                tested = run([str(exe), case], kind + "-" + case)
                case_results[case] = classify_test(tested, case)
                if hash_regular(exe, maximum=LIMIT, guard=guard) != artifact:
                    raise RuntimeError("actual IPC fixture executable changed during case execution")
            completed = sum(row["completed_checks"] for row in case_results.values())
            if completed != EXPECTED_CHECKS_PER_MODE or len(case_results) != 7:
                raise RuntimeError("IPC host mode did not complete every exact case")
            includes_after = snapshot(included, guard=guard)
            receipt["standard_header_inputs_after"][kind] = includes_after
            if includes_after != includes_before:
                raise RuntimeError("actual IPC header/source closure changed during host cases")
            results[kind] = {"completed_checks": completed, "failed_checks": 0,
                             "cases": case_results, "executable": {"path": str(exe), **artifact}}

        obj = output / "k32-ipc-i486.o"
        included, includes_before, artifact = build("i486", "gcc", K32_FLAGS, production, obj,
                                                   object_only=True)
        elf = elf32_i486_object(obj, artifact, guard)
        includes_after = snapshot(included, guard=guard)
        receipt["standard_header_inputs_after"]["i486"] = includes_after
        if includes_after != includes_before:
            raise RuntimeError("actual freestanding IPC header/source closure changed")
        receipt["native_object"] = {"path": str(obj), **artifact, "elf": elf,
                                    "translation_unit": str(production.relative_to(ROOT)),
                                    "flags": list(K32_FLAGS), "compile_only": True,
                                    "native_execution_verified": False}
        receipt["test_results"] = results
        after = snapshot(closure, guard=guard)
        receipt["source_inputs_after"] = after
        if before != after:
            raise RuntimeError("frozen IPC sources or actual own project headers changed during proof")
        receipt["ipc_header_context"]["actual_after"] = after[str(ipc_header.relative_to(ROOT))]
        for path, artifact in artifacts.items():
            if hash_regular(path, maximum=LIMIT, guard=guard) != artifact:
                raise RuntimeError("IPC executable/native object changed before final closure")
        for info in compilers.values():
            if hash_regular(Path(info["path"]), maximum=TOOL_INPUT_LIMIT, guard=guard) != {
                    "sha256": info["sha256"], "identity": info["identity"]}:
                raise RuntimeError("actual resolved IPC compiler changed during proof")
        receipt["provenance_limits"]["actual_M_and_MD_include_closures_hashed"] = True
        receipt["object_compile_verified"] = True
        guard.check(RECEIPT_LIMIT)
        receipt["result"] = "PASS_HOST_AND_SAN_WITH_I486_OBJECT"
    except BaseException as error:
        receipt.update(result="FAIL", error=str(error)[:2048])
        raise
    finally:
        try:
            write_receipt(output, receipt, guard)
        finally:
            guard.close()
    print(json.dumps({"result": receipt["result"], "receipt": str(output / "result.json")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
