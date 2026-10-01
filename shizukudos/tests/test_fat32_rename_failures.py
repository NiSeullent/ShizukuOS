#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded HOST/SAN proof; real FAT32 fixtures exist only in process memory."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import resource
import re
import selectors
import shutil
import signal
import stat
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 8 * 1024 * 1024
RESERVE = 20 * 1024 * 1024 * 1024


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def admit():
    free = shutil.disk_usage(ROOT).free
    if free < RESERVE + LIMIT:
        raise SystemExit(f"BLOCKED: available={free}, required={RESERVE + LIMIT}")
    return free


class Guard:
    def __init__(self, output):
        self.output = output
        info = output.stat()
        self.identity = (info.st_dev, info.st_ino)
        self.failure = None
        self.minimum_free = shutil.disk_usage(ROOT).free

    def count(self):
        info = self.output.lstat()
        if not stat.S_ISDIR(info.st_mode) or (info.st_dev, info.st_ino) != self.identity:
            raise RuntimeError("owned output root identity changed")
        total = 0
        for path in self.output.iterdir():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise RuntimeError("unexpected output type or alias")
            total += info.st_size
        if total > LIMIT:
            raise RuntimeError("aggregate proof output exceeded 8MiB")
        return total

    def check(self, extra=0):
        try:
            free = shutil.disk_usage(ROOT).free
            self.minimum_free = min(self.minimum_free, free)
            if free < RESERVE:
                raise RuntimeError(f"reserve crossed: available={free}, required={RESERVE}")
            if self.count() + extra > LIMIT:
                raise RuntimeError("aggregate proof output including pending write exceeded 8MiB")
            if self.failure:
                raise RuntimeError(self.failure)
        except RuntimeError as error:
            self.failure = self.failure or str(error)
            raise

    def write(self, path, data):
        self.check(len(data))
        with path.open("xb") as stream:
            stream.write(data)
        self.check()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase", required=True, choices=("red", "green"))
    parser.add_argument("--output-root", required=True, type=Path)
    args = parser.parse_args()
    output = args.output_root.absolute()
    allowed = ROOT / "build" / "fat32-rename-6970"
    if output.parent != allowed or output.exists() or output.name in ("", ".", ".."):
        raise SystemExit("output must be a NEW direct child of build/fat32-rename-6970")
    if ROOT != ROOT.resolve() or any(p.is_symlink() for p in (ROOT, ROOT / "build", allowed, output)):
        raise SystemExit("symlinked output path refused")
    backend = ROOT / "shizukudos/kernel64/fat32.c"
    suites = [("fat32", ROOT / "shizukudos/tests/test_fat32_rename_failures.c", b"rollback preserves all durable sectors"),
              ("bridge", ROOT / "shizukudos/tests/test_disk_rename_quarantine.c", b"failed production commit must not publish fsnode metadata")]
    relative = ("kernel64/fat32.h", "kernel64/disk.c", "kernel64/fs.h", "kernel64/blk.h", "kernel64/blk_part.h",
                "kernel64/proc_internal.h", "kernel64/k64.h", "kernel64/ntsys.h", "kcommon/khc.h", "abi/shz_abi.h")
    closure = [backend, *(s[1] for s in suites), *(ROOT / "shizukudos" / x for x in relative), Path(__file__).resolve()]
    before = {str(p.relative_to(ROOT)): sha(p) for p in closure}
    receipt = {"phase": args.phase, "source_hashes": before, "available_before": admit(), "commands": [], "native_execution_verified": False}
    output.mkdir(parents=True, exist_ok=False)
    guard = Guard(output)
    env = dict(os.environ, TMPDIR="/dev/shm", PYTHONDONTWRITEBYTECODE="1", ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
    recipes = [("host", "gcc", ["-O2"])]
    if args.phase == "green":
        recipes.append(("sanitizer", "clang", ["-O1", "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer"]))
    def run(argv, label):
        admit()
        guard.check(320 * 1024)
        budget = LIMIT - guard.count() - 320 * 1024
        def child_limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (budget, budget))
        start = time.monotonic()
        child = subprocess.Popen(argv, cwd=ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True, preexec_fn=child_limits)
        selector = selectors.DefaultSelector()
        selector.register(child.stdout, selectors.EVENT_READ, "stdout")
        selector.register(child.stderr, selectors.EVENT_READ, "stderr")
        chunks = {"stdout": bytearray(), "stderr": bytearray()}
        aborted = None
        try:
            while selector.get_map() or child.poll() is None:
                guard.check(320 * 1024)
                if time.monotonic() - start > 300:
                    raise RuntimeError("bounded subprocess timeout")
                for key, _ in selector.select(0.05):
                    block = os.read(key.fileobj.fileno(), 16384)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        chunks[key.data].extend(block)
                        if sum(map(len, chunks.values())) > 256 * 1024:
                            raise RuntimeError("bounded process output exceeded")
            child.wait()
            guard.check(320 * 1024)
        except BaseException as error:
            aborted = str(error)
            if child.poll() is None:
                try:
                    os.killpg(child.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            child.wait()
            raise
        finally:
            selector.close()
            child.stdout.close()
            child.stderr.close()
            receipt["commands"].append({"argv": [str(x) for x in argv], "returncode": child.returncode,
                                        "aborted": aborted, "elapsed_seconds": time.monotonic() - start})
        guard.write(output / (label + ".stdout"), bytes(chunks["stdout"]))
        guard.write(output / (label + ".stderr"), bytes(chunks["stderr"]))
        return subprocess.CompletedProcess(argv, child.returncode, bytes(chunks["stdout"]), bytes(chunks["stderr"]))
    try:
        compilers = {}
        for _, compiler, _ in recipes:
            if compiler not in compilers:
                path = Path(shutil.which(compiler) or "").resolve(strict=True)
                if not path.is_file():
                    raise RuntimeError("compiler is not a resolved regular file")
                version = run([str(path), "--version"], compiler + "-version")
                if version.returncode:
                    raise RuntimeError("compiler version query failed")
                compilers[compiler] = {"path": str(path), "sha256": sha(path), "version": version.stdout.decode().splitlines()[0]}
        receipt["compilers"] = compilers
        for suite, source, red_message in suites:
            for kind, compiler, flags in recipes:
                name = suite + "-" + kind
                exe = output / name
                command = [compilers[compiler]["path"], "-std=c11", "-g0", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-fdata-sections",
                           *flags, str(source), str(backend), "-Wl,--gc-sections", "-o", str(exe)]
                compiled = run(command, name + "-compile")
                if compiled.returncode:
                    raise RuntimeError(compiled.stderr.decode(errors="replace"))
                tested = run([str(exe)], name + "-run")
                if args.phase == "red":
                    if tested.returncode != 1 or red_message not in tested.stderr:
                        raise RuntimeError("RED did not expose expected production failure: " + tested.stderr.decode(errors="replace"))
                    receipt["result"] = "EXPECTED_RED_REAL_BACKEND_AND_BRIDGE"
                else:
                    if tested.returncode or b"PASS:" not in tested.stdout:
                        raise RuntimeError(tested.stderr.decode(errors="replace"))
                    receipt[name] = tested.stdout.decode().strip()
                    receipt["result"] = "PASS_HOST_AND_SAN"
        if args.phase == "green":
            for suite, _, _ in suites:
                host = receipt[suite + "-host"]
                sanitized = receipt[suite + "-sanitizer"]
                if host != sanitized or not re.search(r"PASS: [1-9][0-9]* .*checks", host):
                    raise RuntimeError("HOST/SAN completed different or malformed assertion evidence")
        after = {str(p.relative_to(ROOT)): sha(p) for p in closure}
        if before != after:
            raise RuntimeError("source closure changed during proof")
        if any(sha(Path(info["path"])) != info["sha256"] for info in compilers.values()):
            raise RuntimeError("resolved compiler changed during proof")
        guard.check(64 * 1024)
    except BaseException as error:
        receipt["result"] = "FAIL"
        receipt["error"] = str(error)
        raise
    finally:
        receipt["minimum_observed_free_bytes"] = guard.minimum_free
        receipt["resource_failure"] = guard.failure
        if guard.failure:
            receipt["result"] = "FAIL"
        receipt["output_bytes_before_receipt"] = guard.count()
        receipt["final_output_bytes"] = receipt["output_bytes_before_receipt"]
        for _ in range(4):
            measured = receipt["output_bytes_before_receipt"] + len((json.dumps(receipt, indent=2) + "\n").encode())
            if receipt["final_output_bytes"] == measured:
                break
            receipt["final_output_bytes"] = measured
        data = (json.dumps(receipt, indent=2) + "\n").encode()
        if len(data) > 64 * 1024 or guard.count() + len(data) > LIMIT:
            raise RuntimeError("bounded final receipt cannot be written")
        # Preserve the bounded FAIL receipt after an externally crossed floor;
        # this is evidence recording only, never continued compilation or PASS.
        with (output / "result.json").open("xb") as stream:
            stream.write(data)
        final_bytes = guard.count()
        if final_bytes != receipt["final_output_bytes"]:
            raise RuntimeError("self-inclusive final receipt byte count disagrees")
        final_free = shutil.disk_usage(ROOT).free
        if final_free < RESERVE or guard.failure:
            receipt.update(result="FAIL", resource_failure=guard.failure or "reserve crossed at receipt completion",
                           final_output_bytes=final_bytes, final_available_bytes=final_free)
            replacement = (json.dumps(receipt, indent=2) + "\n").encode()
            if final_bytes - len(data) + len(replacement) > LIMIT:
                raise RuntimeError("final FAIL receipt exceeds aggregate bound")
            (output / "result.json").write_bytes(replacement)
            raise RuntimeError(receipt["resource_failure"])
    print(json.dumps({"result": receipt["result"], "receipt": str(output / "result.json")}))


if __name__ == "__main__":
    main()
