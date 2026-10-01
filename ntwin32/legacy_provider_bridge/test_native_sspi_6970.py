#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded whole-TU native SSPI profile host proof; no Windows/DLL/TLS proof.

Compile, ABI, boundary, sanitizer and resource failures never establish RED.
Recursive temporaries, executables, aggregate captures and a self-inclusive
receipt share one new 8 MiB root admitted above the strict 20 GiB floor.
Live sampling and per-file RLIMIT_FSIZE observe output use, not transient peaks
or a filesystem quota. No /dev/shm, compiler or VM admission exception.
"""
import argparse
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
BASE_GUARD_SHA256 = "97ab3c9f6ce67202b9640e7fac517147e70742cf2d4d450089820a07f7851e2c"
FROZEN_FIXTURE_SHA256 = "fcec701533d8baeafc15d61d858127e09ca97b2fe67c9309053787326228c5f2"
FROZEN_SHIM_SHA256 = "49450ec878a240cd3a21beb5f10b8b0a7945760e6885369de2e264b48c8f01d5"
INVALID_RECEIPT_SCHEMA = "native-sspi-host-invalid-receipt-v1"
UNCHANGED_RED_PRODUCTION_SHA256 = "4457ca742c23368f759ef74ed5e45f3a3a119e1c8ab3a6cd4d3ecbc2e7640968"
UNCHANGED_RED_TABLE_SHA256 = "c6fbe91b0ba24a68b2fcaef1f265b82071a738036ac331fdc6eb6f3986d5004d"
EXPECTED_CHECKS = 651
ABI_PREFLIGHT = ("ABI_PREFLIGHT: host_pointer_bytes=8 wire_word_bytes=4 "
                 "wire_prefix_bytes=108 callable_addresses_fit_u32=1")
SUPPORTED_EXPORTS = (
    "EnumerateSecurityPackagesA", "AcquireCredentialsHandleA", "FreeCredentialsHandle",
    "InitializeSecurityContextA", "DeleteSecurityContext", "ApplyControlToken",
    "QueryContextAttributesA", "FreeContextBuffer", "QuerySecurityPackageInfoA",
    "ExportSecurityContext", "ImportSecurityContextA", "EncryptMessage", "DecryptMessage",
)
EARLY_NAMES = (
    "AcquireCredentialsHandleW", "InitializeSecurityContextW", "EnumerateSecurityPackagesW",
    "QuerySecurityPackageInfoW", "QueryContextAttributesW", "ImportSecurityContextW",
    "InitSecurityInterfaceW", "__ABSENT__", "acquirecredentialshandlea", "get_api_table",
    "ordinal-one", "ordinal-max",
)
INVALID_LABELS = (
    *(f"version-{value}" for value in (0, 2, 4294967295)),
    *(f"{kind}-{number}" for kind in
      ("identity-mismatch", "nonexecutable-slot", "null-supported-slot") for number in range(13)),
    *(f"missing-export-{number}" for number in range(15)),
    *(f"unsupported-slot-{number}" for number in (2, 5, 7, 8, 12, 13, 14, 15, 18, 19, 22, 23, 24)),
    "nonexecutable-init", "nonexecutable-end-input", "unreadable-table", "short-table-read",
    "foreign-table", "bad-dos-magic", "short-dos-read",
)
EXPECTED_RED_TAGS = {
    *(f"sspi/invalid/{label}/{property}" for label in INVALID_LABELS for property in
      ("reject", "partial-unload", "retry-real-identity", "retry-reloads", "retry-close")),
    "sspi/success/ansi-private-profile",
    *(f"sspi/success/identity/{name}" for name in SUPPORTED_EXPORTS),
    *(f"sspi/success/{name}" for name in
      ("init-export-identity", "end-input-export-identity",
       "cached-owned-module-and-init-once", "close-unloads-once")),
    *(f"sspi/reject-early/{name}" for name in EARLY_NAMES),
    "sspi/mixed/sspi-retry-identity", "sspi/mixed/close-only-owned-live-modules",
    *(f"sspi/cached-tamper/{name}" for name in
      ("original-pointer-identity", "reject-current-full-table",
       "previous-pointer-keeps-module-pinned", "repaired-input-revalidated",
       "no-unload-or-reload-before-close", "close-final-reference-once")),
}
# This is the independent literal stdout contract, not a calculation from C.
# Replacing passing controls with arbitrary tags cannot satisfy the runner.
EXPECTED_ALL_TAGS = EXPECTED_RED_TAGS | {
    *(f"legacy/{number}/{name}" for number in range(5) for name in
      ("named-identity", "ordinal-identity", "missing", "cached-live-module",
       "immutable-table", "close-once", "clean-boundaries", "later-malformed-rejected",
       "malformed-unloaded", "no-double-unload")),
    *(f"sspi/success/{name}" for name in
      ("input-strings-immutable", "no-credential-or-tls-invocation",
       "table-and-headers-immutable", "teardown")),
    "sspi/reject-early/unsupported-module", "sspi/reject-early/teardown",
    *(f"sspi/invalid/{label}/{property}" for label in INVALID_LABELS
      for property in ("invalid-input-immutable", "teardown")),
    *(f"sspi/invalid/{label}/init-not-called" for label in
      ("nonexecutable-init", "bad-dos-magic", "short-dos-read")),
    "sspi/cached-tamper/validation-does-not-repair-provider",
    "sspi/cached-tamper/teardown-with-no-credential-calls",
    *(f"context/{name}" for name in
      ("reject-relative-directory", "reject-quoted-directory", "allocation-failure",
       "null-context", "null-module", "null-name", "close-unused-no-provider-load",
       "unused-teardown")),
    *(f"sspi/mixed/{name}" for name in
      ("legacy-live-before-sspi-failure", "sspi-invalid-rejected",
       "invalid-sspi-retains-legacy-module", "second-legacy-profile",
       "teardown-and-no-credential-calls")),
}


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


def classify_test(completed, phase):
    """Require the exact ABI marker, every unique control and exact RED set."""
    stdout = completed.stdout.decode("ascii", errors="strict")
    stderr = completed.stderr.decode("ascii", errors="strict")
    if stderr:
        raise RuntimeError("harness, ABI, sanitizer or diagnostic stderr is never feature RED")
    lines = stdout.split("\n")[:-1]
    if not stdout.endswith("\n") or not lines or lines[0] != ABI_PREFLIGHT:
        raise RuntimeError("missing exact host64/SSPI32 callable ABI preflight")
    summary = re.fullmatch(r"SUMMARY: ([1-9][0-9]*) native SSPI bridge checks, ([0-9]+) failures",
                           lines[-1])
    if not summary or int(summary[1]) != EXPECTED_CHECKS:
        raise RuntimeError("fixture did not complete the exact SSPI assertion count")
    passed, failed = [], []
    for line in lines[1:-1]:
        match = re.fullmatch(r"(PASS|FAIL): ([^\r\n]+)", line)
        if not match or match[2] not in EXPECTED_ALL_TAGS:
            raise RuntimeError("unknown assertion or infrastructure stdout")
        (passed if match[1] == "PASS" else failed).append(match[2])
    tags = passed + failed
    if len(tags) != EXPECTED_CHECKS or len(set(tags)) != len(tags) or set(tags) != EXPECTED_ALL_TAGS:
        raise RuntimeError("fixture omitted, repeated or replaced a required passing control")
    if int(summary[2]) != len(failed):
        raise RuntimeError("assertion status and final failure summary disagree")
    if phase == "red":
        if completed.returncode != 1 or set(failed) != EXPECTED_RED_TAGS:
            raise RuntimeError("RED is not the exact prospective SSPI omission assertions")
    elif completed.returncode != 0 or failed:
        raise RuntimeError("actual HOST/SAN did not finish all SSPI controls cleanly")
    return {"completed_checks": len(tags), "failed_checks": len(failed),
            "abi_preflight": ABI_PREFLIGHT, "passed_tags": passed, "failed_tags": failed}


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
                # so no readable PASS/expected-RED survives final guard failure.
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
    parser.add_argument("--phase", required=True, choices=("red", "green"))
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_root
    allowed = ROOT / "build" / "native-sspi-6970"
    if not output.is_absolute() or output.parent != allowed or output.exists():
        raise SystemExit("output must be one NEW absolute direct child of build/native-sspi-6970")
    safe_components(output)
    if ROOT != ROOT.resolve():
        raise SystemExit("source root must be canonical")
    bridge = ROOT / "ntwin32/legacy_provider_bridge"
    source = bridge / "test_native_sspi_6970.c"
    headers = bridge / "host_sspi_6970"
    production = bridge / "native.c"
    table = bridge / "table.c"
    table_header = bridge / "table.h"
    base_guard = ROOT / "shizukudos/tests/test_winhttp_crackurl_6970.py"
    abi_references = {
        ROOT / "ntwin32/secure_transport/sspi_native.c":
        "32b6bbd23d7ed61c40d86e08711c631140dfeb3ee6e5e1a6427d9eebb2955672",
        ROOT / "ntwin32/secure_transport/sspi_native.def":
        "d31e87e33f0b51bb175265e0f05a073749e1785d3d4d2cb34713ae7dd59566a7",
    }
    closure = [source, Path(__file__).resolve(), production, table, table_header,
               base_guard, headers / "windows.h", *abi_references]
    before = snapshot(closure)
    if before[str(base_guard.relative_to(ROOT))]["sha256"] != BASE_GUARD_SHA256:
        raise SystemExit("unchanged guarded-runner provenance source changed")
    for frozen, digest in ((source, FROZEN_FIXTURE_SHA256),
                           (headers / "windows.h", FROZEN_SHIM_SHA256)):
        if before[str(frozen.relative_to(ROOT))]["sha256"] != digest:
            raise SystemExit("reviewed frozen SSPI fixture or shim changed")
    if len(EXPECTED_RED_TAGS) != 423 or len(EXPECTED_ALL_TAGS) != EXPECTED_CHECKS:
        raise SystemExit("invalid independent stdout/tag contract")
    for reference, digest in abi_references.items():
        if before[str(reference.relative_to(ROOT))]["sha256"] != digest:
            raise SystemExit("noncompiled provider ABI reference changed")
    if args.phase == "red" and (
            before[str(production.relative_to(ROOT))]["sha256"] != UNCHANGED_RED_PRODUCTION_SHA256
            or before[str(table.relative_to(ROOT))]["sha256"] != UNCHANGED_RED_TABLE_SHA256):
        raise SystemExit("RED requires the exact unchanged production native.c and table.c")
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
    receipt = {"schema": "native-sspi-production-bridge-host-v1", "phase": args.phase,
               "result": "NOT_COMPLETED", "source_inputs": before,
               "source_hashes": {key: info["sha256"] for key, info in before.items()},
               "available_before_bytes": available, "output_limit_bytes": LIMIT,
               "reserve_bytes": RESERVE, "output_root": str(output), "commands": [],
               "native_execution_verified": False, "windows98_integration_verified": False,
               "network_execution_verified": False, "os_tls_provider_verified": False,
               "application_compatibility_verified": False,
               "scope": "complete production native.c/table.c TU; host-only Win32 loader/RPM/heap/lock boundaries and fixed SSPI32 v1 prefix oracle",
               "actual_windows_dll_abi_verified": False, "os_registration_verified": False,
               "kernel64_backend_verified": False, "credential_execution_verified": False,
               "concurrent_join_verified": False, "real_provider_dll_execution_verified": False,
               "reported_hosted_checkout_sha": os.environ.get("GITHUB_SHA"),
               "hosted_checkout_independently_verified_by_runner": False,
               "self_loaded_runner_binding_verified": False,
               "noncompiled_abi_reference_inputs": {
                   str(path.relative_to(ROOT)): before[str(path.relative_to(ROOT))]
                   for path in abi_references},
               "abi_reference_compiled_or_executed": False,
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
               "expected_checks": EXPECTED_CHECKS, "expected_red_tags": sorted(EXPECTED_RED_TAGS),
               "standard_header_closure": {}, "standard_header_inputs_before": {},
               "standard_header_inputs_after": {}}
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
           "TMPDIR": str(output), "TMP": str(output), "TEMP": str(output),
           "PYTHONDONTWRITEBYTECODE": "1", "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
           "UBSAN_OPTIONS": "halt_on_error=1"}
    recipes = [("host", "gcc", ["-O1"])]
    if args.phase == "green":
        recipes.append(("sanitizer", "clang", ["-O1", "-fsanitize=address,undefined",
                                             "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]))

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
        for kind, compiler, flags in recipes:
            exe = output / ("native-sspi-" + kind)
            common = [compilers[compiler]["path"], "-std=c11", "-g0", "-Wall", "-Wextra", "-Werror",
                      "-fno-pie", "-ffunction-sections", "-fdata-sections",
                      "-I", str(headers), *flags]
            depfile = output / (kind + ".includes")
            discovered = run([*common, "-M", "-MT", "native_sspi_proof", "-MF", str(depfile), str(source)],
                             kind + "-dependencies")
            if discovered.returncode or discovered.stdout or discovered.stderr:
                raise RuntimeError("actual compiler dependency discovery failed or emitted diagnostics")
            included, manifest = dependencies(depfile, "native_sspi_proof")
            if not set((source, production, table, table_header, headers / "windows.h")) <= set(included):
                raise RuntimeError("whole native/table TU and host Win32 shim absent from actual include closure")
            if set(abi_references) & set(included):
                raise RuntimeError("noncompiled provider ABI references unexpectedly entered the compiled TU")
            includes_before = snapshot(included, guard=guard)
            receipt["standard_header_closure"][kind] = manifest
            receipt["standard_header_inputs_before"][kind] = includes_before
            compile_depfile = output / (kind + "-compile.includes")
            command = [*common, "-no-pie", "-MD", "-MT", "native_sspi_proof", "-MF", str(compile_depfile),
                       str(source), "-Wl,--gc-sections", "-o", str(exe)]
            compiled = run(command, kind + "-compile")
            if compiled.returncode:
                raise RuntimeError("compiler failure is NOT expected RED: " + compiled.stderr[:2048].decode(errors="replace"))
            if compiled.stdout or compiled.stderr:
                raise RuntimeError("compiler diagnostics are not a clean assertion proof")
            compiled_includes, compile_manifest = dependencies(compile_depfile, "native_sspi_proof")
            if compiled_includes != included or snapshot(included, guard=guard) != includes_before:
                raise RuntimeError("actual compiler include closure changed before fixture execution")
            receipt["standard_header_closure"][kind]["compile_manifest"] = compile_manifest
            artifact = hash_regular(exe, maximum=LIMIT, guard=guard)
            tested = run([str(exe)], kind + "-run")
            results[kind] = {**classify_test(tested, args.phase), "executable": {"path": str(exe), **artifact}}
            if hash_regular(exe, maximum=LIMIT, guard=guard) != artifact:
                raise RuntimeError("actual fixture executable changed during proof")
            includes_after = snapshot(included, guard=guard)
            receipt["standard_header_inputs_after"][kind] = includes_after
            if includes_before != includes_after:
                raise RuntimeError("actual compiler header/source closure changed during fixture execution")
        if args.phase == "green" and results["host"]["completed_checks"] != results["sanitizer"]["completed_checks"]:
            raise RuntimeError("actual HOST/SAN assertion counts differ")
        receipt["test_results"] = results
        after = snapshot(closure, guard=guard)
        receipt["source_inputs_after"] = after
        if before != after:
            raise RuntimeError("frozen source closure changed during proof")
        for info in compilers.values():
            if hash_regular(Path(info["path"]), maximum=TOOL_INPUT_LIMIT, guard=guard) != {"sha256": info["sha256"], "identity": info["identity"]}:
                raise RuntimeError("actual resolved compiler changed during proof")
        receipt["provenance_limits"]["actual_M_and_MD_include_closures_hashed"] = True
        guard.check(RECEIPT_LIMIT)
        receipt["result"] = "RED_REAL_PROSPECTIVE_NATIVE_SSPI_OMISSION_ASSERTIONS" if args.phase == "red" else "PASS_HOST_AND_SAN"
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
