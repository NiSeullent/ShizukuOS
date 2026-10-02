#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded complete-production-TU WinHTTP URL omission proof; no Windows/network proof.

Compile/harness/resource failures cannot establish expected RED. All compiler
temporaries, binaries, captures and the self-inclusive receipt share one new
8 MiB root, admitted above the 20 GiB floor. No /dev/shm resource exception.
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
RECEIPT_LIMIT = 128 * 1024
PENDING = CAPTURE_LIMIT + RECEIPT_LIMIT + 64 * 1024
BASE_GUARD_SHA256 = "8b7d3c6d3d5bacdebc54412dbe9bb8b744d5c3df4701556b787ca9bab98a97db"
UNCHANGED_RED_PRODUCTION_SHA256 = "0036c09a67593ca10bff5a0cbfbe7d458d9dcc21ea99bd8d69191815a4a7f33b"
EXPECTED_CHECKS = 110
EXPECTED_RED_TAGS = {
    *(f"omitted copy {name} {property}" for name in
      ("query", "fragment", "query-fragment", "empty-query-fragment")
      for property in ("full length", "full payload")),
    *(f"omitted borrow {name} full length" for name in
      ("query", "fragment", "query-fragment", "empty-query-fragment")),
    *(f"omitted capacity {name} {property}" for name in
      ("prefix-only", "missing-terminator") for property in
      ("rejected", "insufficient buffer", "full requirement", "destination preserved")),
    "omitted exact capacity full length",
    "omitted exact capacity full payload",
    "omitted explicit copy full length",
    "omitted explicit copy full payload",
    "omitted explicit borrow full length",
}


def identity(info):
    return (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def hash_regular(path, *, maximum=None):
    """Hash only the named regular inode and reject changes during the read."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or (maximum is not None and before.st_size > maximum):
            raise RuntimeError("unbounded or nonregular source/tool input")
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        after = os.fstat(fd)
        if identity(before) != identity(after) or identity(after) != identity(path.stat(follow_symlinks=False)):
            raise RuntimeError("input identity changed while hashing")
        return {"sha256": digest.hexdigest(), "identity": list(identity(after))}
    finally:
        os.close(fd)


def snapshot(paths):
    return {str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path):
            hash_regular(path, maximum=2 * 1024 * 1024) for path in paths}


def dependencies(path, target):
    """Parse actual compiler -M output, including all standard/system headers."""
    pinned = hash_regular(path, maximum=64 * 1024)
    raw = path.read_bytes()
    if hash_regular(path, maximum=64 * 1024) != pinned:
        raise RuntimeError("compiler dependency manifest changed during read")
    text = raw.decode("utf-8", errors="strict").replace("\\\n", "")
    prefix = target + ":"
    if not text.startswith(prefix):
        raise RuntimeError("unexpected actual compiler dependency target")
    names = shlex.split(text[len(prefix):], posix=True)
    if not names or len(names) > 256:
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
    """Measured live enforcement; observed failures remain latched."""
    def __init__(self, output):
        self.output = output
        info = output.lstat()
        self.root_identity = (info.st_dev, info.st_ino)
        self.failure = None
        self.minimum_free = shutil.disk_usage(ROOT).free
        self.peak = 0

    def count(self):
        safe_components(self.output)
        root = self.output.lstat()
        if not stat.S_ISDIR(root.st_mode) or (root.st_dev, root.st_ino) != self.root_identity:
            raise RuntimeError("owned proof root identity changed")
        # Normal compiler temporary creation/unlink may race a directory
        # sample. Retry only that membership/ENOENT churn, never type, hardlink,
        # floor or cap violations. Every observed partial sum is bounded too.
        for _ in range(4):
            free = shutil.disk_usage(ROOT).free
            self.minimum_free = min(self.minimum_free, free)
            if free < RESERVE:
                raise RuntimeError("20 GiB reserve crossed during temporary sample")
            names = sorted(self.output.iterdir())
            total = 0
            try:
                for path in names:
                    info = path.lstat()
                    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                        raise RuntimeError("unexpected proof output type or hardlink")
                    total += info.st_size
                    self.peak = max(self.peak, total)
                    if total > LIMIT:
                        raise RuntimeError("combined proof files exceeded 8 MiB")
            except FileNotFoundError:
                continue
            if names == sorted(self.output.iterdir()):
                return total
        raise RuntimeError("compiler output directory sample did not stabilize")

    def check(self, extra=0):
        try:
            free = shutil.disk_usage(ROOT).free
            self.minimum_free = min(self.minimum_free, free)
            if free < RESERVE:
                raise RuntimeError(f"20 GiB reserve crossed: available={free}")
            if self.count() + extra > LIMIT:
                raise RuntimeError("combined proof files plus pending write exceeded 8 MiB")
            if self.failure:
                raise RuntimeError(self.failure)
        except (OSError, RuntimeError) as error:
            self.failure = self.failure or str(error)
            raise

    def write(self, path, data):
        if path.parent != self.output:
            raise RuntimeError("write escaped the owned proof root")
        self.check(len(data))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
        finally:
            os.close(fd)
        self.check()


def classify_test(completed, phase):
    stdout = completed.stdout.decode("ascii", errors="strict").strip()
    stderr = completed.stderr.decode("ascii", errors="strict")
    if "FIXTURE_ERROR:" in stderr or "AddressSanitizer" in stderr or "runtime error:" in stderr:
        raise RuntimeError("fixture/sanitizer failure is not a production assertion verdict")
    if phase == "red":
        summary = re.fullmatch(r"FAIL: ([1-9][0-9]*) of ([1-9][0-9]*) WinHTTP URL omission checks", stdout)
        tags = []
        for line in stderr.splitlines():
            match = re.fullmatch(r"ASSERT: (.+)", line)
            if not match or match[1] not in EXPECTED_RED_TAGS:
                raise RuntimeError("RED contained an unexpected assertion/infrastructure failure")
            tags.append(match[1])
        if (completed.returncode != 1 or not summary or int(summary[1]) != len(tags)
                or int(summary[2]) != EXPECTED_CHECKS
                or len(tags) != len(set(tags)) or set(tags) != EXPECTED_RED_TAGS):
            raise RuntimeError("RED did not execute all exact known omission defects and passing controls")
        return {"completed_checks": int(summary[2]), "failed_checks": int(summary[1]), "assertion_tags": tags}
    summary = re.fullmatch(r"PASS: ([1-9][0-9]*) WinHTTP URL omission checks", stdout)
    if completed.returncode or stderr or not summary or int(summary[1]) != EXPECTED_CHECKS:
        raise RuntimeError("actual HOST/SAN proof did not finish cleanly")
    return {"completed_checks": int(summary[1]), "failed_checks": 0}


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
    base = guard.count()
    data = encoded(base)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
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
                replacement = encoded(guard.count(), len(data))
            except (OSError, RuntimeError):
                # Unsafe scope/accounting cannot produce a complete proof.
                # Shrink this prospective receipt to an explicit invalid FAIL
                # so no readable PASS/expected-RED survives final guard failure.
                replacement = (json.dumps({"result": "FAIL", "receipt_accounting_verified": False,
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
    allowed = ROOT / "build" / "winhttp-url-6970"
    if not output.is_absolute() or output.parent != allowed or output.exists():
        raise SystemExit("output must be one NEW absolute direct child of build/winhttp-url-6970")
    safe_components(output)
    if ROOT != ROOT.resolve():
        raise SystemExit("source root must be canonical")
    source = ROOT / "shizukudos/tests/test_winhttp_crackurl_6970.c"
    headers = ROOT / "shizukudos/tests/host/winhttp_url_6970/include"
    production = ROOT / "shizukudos/win64/dlls/winhttp/winhttp.c"
    base_guard = ROOT / "shizukudos/tests/test_sched_deadlines_k32.py"
    closure = [source, Path(__file__).resolve(), production, base_guard,
               headers / "windows.h", headers / "winhttp.h"]
    before = snapshot(closure)
    if before[str(base_guard.relative_to(ROOT))]["sha256"] != BASE_GUARD_SHA256:
        raise SystemExit("unchanged guarded-runner provenance source changed")
    if args.phase == "red" and before[str(production.relative_to(ROOT))]["sha256"] != UNCHANGED_RED_PRODUCTION_SHA256:
        raise SystemExit("RED requires the exact unchanged production WinHTTP TU")
    try:
        available = admission()        # no proof directory or compiler before admission
    except RuntimeError as error:
        print(json.dumps({"result": "BLOCKED_NOT_RUN", "reason": str(error)}))
        return 3
    output.mkdir(parents=True, exist_ok=False)
    guard = Guard(output)
    receipt = {"schema": "winhttp-production-url-omission-host-v1", "phase": args.phase,
               "result": "NOT_COMPLETED", "source_inputs": before,
               "source_hashes": {key: info["sha256"] for key, info in before.items()},
               "available_before_bytes": available, "output_limit_bytes": LIMIT,
               "reserve_bytes": RESERVE, "output_root": str(output), "commands": [],
               "native_execution_verified": False, "windows98_integration_verified": False,
               "network_execution_verified": False, "os_tls_provider_verified": False,
               "application_compatibility_verified": False,
               "scope": "complete production WinHTTP TU with test-only UTF16/Win64 declarations; actual parser calls and last-error register only",
               "derived_guard_source_sha256": BASE_GUARD_SHA256,
               "expected_checks": EXPECTED_CHECKS, "expected_red_tags": sorted(EXPECTED_RED_TAGS),
               "standard_header_closure": {}, "standard_header_inputs_before": {},
               "standard_header_inputs_after": {}}
    env = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
           "TMPDIR": str(output), "TMP": str(output), "TEMP": str(output),
           "PYTHONDONTWRITEBYTECODE": "1", "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
           "UBSAN_OPTIONS": "halt_on_error=1"}
    recipes = [("host", "gcc", ["-O2"])]
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
        child = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True, preexec_fn=child_limits)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ, "stdout")
        selector.register(child.stderr, selectors.EVENT_READ, "stderr")
        chunks = {"stdout": bytearray(), "stderr": bytearray()}
        aborted = None
        group_kill = "NOT_REQUESTED"
        leader_exit_observed = False
        try:
            while True:
                # Keep an exited group leader waitable until its owned pipes
                # close or abort teardown completes. poll() would reap it and
                # release the PID/PGID before descendant termination.
                observed = os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                leader_exit_observed = bool(observed and observed.si_pid == child.pid)
                if leader_exit_observed and not selector.get_map():
                    break
                guard.check(PENDING)
                if time.monotonic() - start > 60:
                    raise RuntimeError("bounded compiler/fixture subprocess timeout")
                for key, _ in selector.select(0.05):
                    block = os.read(key.fileobj.fileno(), 16384)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        chunks[key.data].extend(block)
                        if sum(map(len, chunks.values())) > CAPTURE_LIMIT:
                            raise RuntimeError("bounded subprocess capture exceeded")
            guard.check(PENDING)
            child.wait(timeout=5)
        except BaseException as error:
            aborted = str(error)
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
                                        "elapsed_seconds": time.monotonic() - start})
        guard.write(output / (label + ".stdout"), bytes(chunks["stdout"]))
        guard.write(output / (label + ".stderr"), bytes(chunks["stderr"]))
        return subprocess.CompletedProcess(argv, child.returncode, bytes(chunks["stdout"]), bytes(chunks["stderr"]))

    try:
        compilers = {}
        for _, compiler, _ in recipes:
            found = shutil.which(compiler)
            if not found:
                raise RuntimeError("required actual compiler is unavailable")
            path = Path(found).resolve(strict=True)
            tool = hash_regular(path)
            version = run([str(path), "--version"], compiler + "-version")
            if version.returncode or not version.stdout.splitlines():
                raise RuntimeError("actual compiler version query failed")
            compilers[compiler] = {"path": str(path), **tool,
                                   "version": version.stdout.decode(errors="strict").splitlines()[0]}
        receipt["compilers"] = compilers
        results = {}
        for kind, compiler, flags in recipes:
            exe = output / ("winhttp-url-" + kind)
            common = [compilers[compiler]["path"], "-std=c11", "-g0", "-Wall", "-Wextra", "-Werror",
                      "-fshort-wchar", "-ffunction-sections", "-fdata-sections", "-I", str(headers), *flags]
            depfile = output / (kind + ".includes")
            discovered = run([*common, "-M", "-MT", "winhttp_url_proof", "-MF", str(depfile), str(source)],
                             kind + "-dependencies")
            if discovered.returncode or discovered.stdout or discovered.stderr:
                raise RuntimeError("actual compiler dependency discovery failed or emitted diagnostics")
            included, manifest = dependencies(depfile, "winhttp_url_proof")
            if not set((source, production, headers / "windows.h", headers / "winhttp.h")) <= set(included):
                raise RuntimeError("complete production TU and UTF16 declarations absent from actual include closure")
            includes_before = snapshot(included)
            receipt["standard_header_closure"][kind] = manifest
            receipt["standard_header_inputs_before"][kind] = includes_before
            compile_depfile = output / (kind + "-compile.includes")
            command = [*common, "-MD", "-MT", "winhttp_url_proof", "-MF", str(compile_depfile),
                       str(source), "-Wl,--gc-sections", "-o", str(exe)]
            compiled = run(command, kind + "-compile")
            if compiled.returncode:
                raise RuntimeError("compiler failure is NOT expected RED: " + compiled.stderr.decode(errors="replace"))
            if compiled.stdout or compiled.stderr:
                raise RuntimeError("compiler diagnostics are not a clean assertion proof")
            compiled_includes, compile_manifest = dependencies(compile_depfile, "winhttp_url_proof")
            if compiled_includes != included or snapshot(included) != includes_before:
                raise RuntimeError("actual compiler include closure changed before fixture execution")
            receipt["standard_header_closure"][kind]["compile_manifest"] = compile_manifest
            artifact = hash_regular(exe, maximum=LIMIT)
            tested = run([str(exe)], kind + "-run")
            results[kind] = {**classify_test(tested, args.phase), "executable": {"path": str(exe), **artifact}}
            if hash_regular(exe, maximum=LIMIT) != artifact:
                raise RuntimeError("actual fixture executable changed during proof")
            includes_after = snapshot(included)
            receipt["standard_header_inputs_after"][kind] = includes_after
            if includes_before != includes_after:
                raise RuntimeError("actual compiler header/source closure changed during fixture execution")
        if args.phase == "green" and results["host"]["completed_checks"] != results["sanitizer"]["completed_checks"]:
            raise RuntimeError("actual HOST/SAN assertion counts differ")
        receipt["test_results"] = results
        after = snapshot(closure)
        receipt["source_inputs_after"] = after
        if before != after:
            raise RuntimeError("frozen source closure changed during proof")
        for info in compilers.values():
            if hash_regular(Path(info["path"])) != {"sha256": info["sha256"], "identity": info["identity"]}:
                raise RuntimeError("actual resolved compiler changed during proof")
        guard.check(RECEIPT_LIMIT)
        receipt["result"] = "RED_REAL_WINHTTP_OMISSION_ASSERTIONS" if args.phase == "red" else "PASS_HOST_AND_SAN"
    except BaseException as error:
        receipt.update(result="FAIL", error=str(error))
        raise
    finally:
        write_receipt(output, receipt, guard)
    print(json.dumps({"result": receipt["result"], "receipt": str(output / "result.json")}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
