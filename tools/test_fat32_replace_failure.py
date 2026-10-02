#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run genuine FAT replacement-save RED/GREEN controls in a bounded own tree.

--source-root names a checkout containing the exact approved unpatched source.
Run --phase red first, then --phase green --red-sha256 <actual RED receipt>.
For an additive generation, --prior-build-dir and --prior-build-sha256 bind the
complete accepted earlier recipe. All specified generations share the 16MiB/90s cap.
--current-root instead checks actual integrated production source: the exact
patch is reversed only in the private snapshot to recover its pinned preimage.
No caller checkout, device, guest, service, package or global setting is changed.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import resource
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
BASE = {"shizukudos/kernel64/fat32.c": "dc3dc2fc1023fd3e64a7fe8a42134ee4de538c69f7f2c9a2767205db2528faee",
        "shizukudos/kernel64/fat32.h": "dc7c67603d0c250e7639717ca6656e425167be6ca6f3c4fdf899cb8fa5bcc053"}
ORIGINAL_TESTS = ("shizukudos/tests/test_fat32.c", "shizukudos/tests/test_fat32_batch.c",
                  "shizukudos/tests/test_fat32_host.py")
TEST = "shizukudos/tests/test_fat32_replace_failure.c"
PATCH = "patches/kernel64/fat32-safe-replace.patch"
RESERVE, BUDGET, RAM, RSS = 20 * 1024**3, 16 * 1024**2, 6 * 1024**3, 512 * 1024**2
FALSE = dict(native_execution=False, kernel_execution=False, crash_atomicity_verified=False,
             persistent_IO_rollback_guaranteed=False, full_Office_save_acceptance=False,
             cold_boot_profile_persistence_verified=False, MS_DOS_replacement_verified=False)


def need(ok, why):
    if not ok:
        raise ValueError(why)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum=16 * 1024**2):
    path = Path(path)
    need(path.is_absolute() and path.resolve(strict=True) == path, "noncanonical input")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        need(stat.S_ISREG(a.st_mode) and a.st_size <= maximum, "nonregular/unbounded input")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(maximum + 1)
        b = os.fstat(fd)
        need(len(data) == a.st_size and identity(a) == identity(b), "input changed during read")
        return data
    finally:
        os.close(fd)


def identity(s):
    return tuple(getattr(s, x) for x in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"))


def object_json(raw):
    def unique(rows):
        result = {}
        for k, v in rows:
            need(k not in result, "duplicate JSON key")
            result[k] = v
        return result
    result = json.loads(raw, object_pairs_hook=unique)
    need(isinstance(result, dict), "JSON object required")
    return result


def tree(directory):
    rows = {}
    for path in directory.rglob("*"):
        need(not path.is_symlink(), "output symlink")
        if path.is_file():
            data = read(path)
            rows[str(path.relative_to(directory))] = dict(bytes=len(data), sha256=sha(data))
    return rows


def own_bytes(directory):
    # Active owned compiler files are supposed to grow. Measure logical sizes
    # without the stable-file hash contract used for frozen input/closure.
    total = 0
    for p in directory.rglob("*"):
        try:
            s = p.lstat()
        except FileNotFoundError:
            continue  # sampled temporary-file creation/removal is not atomic
        need(stat.S_ISDIR(s.st_mode) or stat.S_ISREG(s.st_mode), "nonregular owned output")
        if stat.S_ISREG(s.st_mode): total += s.st_size
    return total


def ram():
    return next(int(x.split()[1]) * 1024 for x in Path("/proc/meminfo").read_text().splitlines()
                if x.startswith("MemAvailable:"))


def rss(group):
    total = 0
    for p in Path("/proc").glob("[0-9]*"):
        try:
            fields = (p / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group:
                total += next((int(x.split()[1]) * 1024 for x in (p / "status").read_text().splitlines()
                               if x.startswith("VmRSS:")), 0)
        except (OSError, IndexError, ValueError):
            continue
    return total


def stop(process):
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)


class Run:
    def __init__(self, out, previous_seconds=0, prior_dirs=()):
        self.out, self.seconds, self.prior_dirs = out, previous_seconds, prior_dirs
        self.steps, self.samples, self.original = [], [], {}

    def total_bytes(self):
        return own_bytes(self.out) + sum(own_bytes(p) for p in self.prior_dirs)

    def guard(self, group=None):
        s = dict(free=shutil.disk_usage(ROOT).free, ram=ram(), output=self.total_bytes(), RSS=rss(group) if group else 0)
        self.samples.append(s)
        need(s["free"] >= RESERVE and s["ram"] >= RAM, "resource reserve breached")
        need(s["output"] <= BUDGET and s["RSS"] <= RSS, "owned output/RSS limit breached")

    def input(self, p, want=None):
        raw = read(p)
        if want: need(sha(raw) == want, "pinned input drift: " + str(p))
        self.original[str(p)] = sha(raw)
        return raw

    def write(self, p, data):
        self.guard()
        need(self.total_bytes() + len(data) <= BUDGET, "copy exceeds aggregate write budget")
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("xb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        need(read(p) == data, "copy readback mismatch")
        self.guard()

    def command(self, argv, title, expect=0, env=None, cwd=None):
        self.guard()
        timeout = min(60, 90 - self.seconds)
        need(timeout > 0, "aggregate command budget exhausted")
        row = dict(command=[str(x) for x in argv], title=title, timeout_seconds=timeout, expected_returncode=expect)
        self.steps.append(row)
        file_cap = max(1, BUDGET - self.total_bytes())
        row["individual_RLIMIT_FSIZE_bytes"] = file_cap
        def limits():
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_cap, file_cap))
            resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        started, p = time.monotonic(), None
        try:
            with (self.out / (title + ".stdout")).open("xb") as stdout, (self.out / (title + ".stderr")).open("xb") as stderr:
                settings = dict(os.environ, LC_ALL="C", LANG="C", PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(self.out))
                if env: settings.update(env)
                p = subprocess.Popen(row["command"], cwd=cwd or ROOT, env=settings, stdout=stdout, stderr=stderr,
                                     preexec_fn=limits, start_new_session=True)
                row["owned_group"] = p.pid
                while p.poll() is None:
                    self.guard(p.pid)
                    need(time.monotonic() - started <= timeout, "owned command timeout")
                    time.sleep(.05)
                row["returncode"] = p.wait()
        except BaseException as error:
            if p: stop(p)
            row["error"] = str(error)
            raise
        finally:
            row["seconds"] = time.monotonic() - started
            self.seconds += row["seconds"]
            row["logs"] = {}
            for name in ("stdout", "stderr"):
                q = self.out / (title + "." + name)
                if q.exists(): row["logs"][name] = dict(path=q.name, bytes=q.stat().st_size, sha256=sha(read(q)))
        self.guard()
        need(row["returncode"] == expect and self.seconds <= 90, "unexpected actual command result: " + title)
        return read(self.out / (title + ".stdout")), read(self.out / (title + ".stderr"))

    def verify_inputs(self):
        for p, expected in self.original.items(): need(sha(read(Path(p))) == expected, "late original drift: " + p)


def tool(name):
    found = shutil.which(name)
    need(found, "missing tool: " + name)
    return Path(found).resolve(strict=True)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    modes = p.add_mutually_exclusive_group(required=True)
    modes.add_argument("--source-root", type=Path)
    modes.add_argument("--current-root", type=Path)
    p.add_argument("--phase", choices=("red", "green", "current"), required=True)
    p.add_argument("--output-dir", type=Path, default=Path("build/fat32-replace-save-v1"))
    p.add_argument("--red-sha256")
    p.add_argument("--prior-build-dir", type=Path)
    p.add_argument("--prior-build-sha256")
    p.add_argument("--preserved-failure-dir", type=Path, action="append", default=[])
    p.add_argument("--preserved-failure-sha256", action="append", default=[])
    a = p.parse_args(); run = None
    try:
        source_root = a.source_root or a.current_root
        need(source_root.is_absolute() and source_root.resolve(strict=True) == source_root, "canonical caller source-root required")
        need((a.phase == "current") == (a.current_root is not None), "current phase requires actual --current-root")
        out = a.output_dir if a.output_dir.is_absolute() else ROOT / a.output_dir
        need(out.parent.resolve(strict=True) == out.parent and out.is_relative_to(ROOT / "build") and
             not out.is_symlink(), "fresh canonical own build output required")
        previous, previous_seconds, prior_dir, prior_rows = None, 0, None, None
        failures = []
        if a.phase == "green":
            need(a.red_sha256, "green requires exact preserved RED authority")
            if a.prior_build_dir:
                prior_dir = a.prior_build_dir if a.prior_build_dir.is_absolute() else ROOT / a.prior_build_dir
                need(prior_dir.resolve(strict=True) == prior_dir and prior_dir.is_relative_to(ROOT / "build") and
                     not out.exists() and not out.is_relative_to(prior_dir) and not prior_dir.is_relative_to(out),
                     "additive generation requires fresh separate output and canonical prior build")
                need(a.prior_build_sha256, "prior completed build needs explicit caller approval pin")
                authority = read(prior_dir / "result.json")
                need(sha(authority) == a.prior_build_sha256, "unapproved prior generation")
                accepted = object_json(authority)
                need(accepted["status"] == "REAL_HOST_REPLACEMENT_REGRESSION_PASS_KERNEL_PENDING", "prior build was not real host PASS")
                prior_rows = tree(prior_dir)
                check_rows = dict(prior_rows); del check_rows["result.json"]
                need(check_rows == accepted["outputs"], "accepted prior closure changed")
                previous_seconds = accepted["aggregate_seconds"]
                red_dir = prior_dir
            else:
                need(out.is_dir() and not a.prior_build_sha256, "green needs preserved RED directory")
                red_dir = out
            raw = read(red_dir / "red-result.json"); need(sha(raw) == a.red_sha256, "unapproved RED authority")
            previous = object_json(raw)
            need(previous["status"] == "EXPECTED_REAL_FAT_REPLACEMENT_RED", "not actual semantic RED")
            old_rows = tree(red_dir)
            for name, row in previous["outputs"].items(): need(old_rows.get(name) == row, "original RED member changed")
            if not prior_dir:
                del old_rows["red-result.json"]
                need(old_rows == previous["outputs"], "unexpected files in RED directory")
                previous_seconds = previous["aggregate_seconds"]
        else:
            need(not out.exists() and not a.prior_build_dir and not a.prior_build_sha256,
                 "preserve previous evidence; output must be fresh")
        need(len(a.preserved_failure_dir) == len(a.preserved_failure_sha256), "each preserved failure requires one approval pin")
        for supplied_dir, approved_hash in zip(a.preserved_failure_dir, a.preserved_failure_sha256):
            need(prior_dir, "preserved failure requires a completed prior build")
            failure_dir = supplied_dir if supplied_dir.is_absolute() else ROOT / supplied_dir
            need(failure_dir.resolve(strict=True) == failure_dir and failure_dir.is_relative_to(ROOT / "build") and
                 all(not failure_dir.is_relative_to(q) and not q.is_relative_to(failure_dir)
                     for q in (out, prior_dir, *(f[0] for f in failures))),
                 "failure generation must be a separate canonical own directory")
            failed_raw = read(failure_dir / "failed-green.json")
            need(sha(failed_raw) == approved_hash, "unapproved failed generation")
            failed = object_json(failed_raw)
            need(isinstance(failed.get("error"), str) and failed.get("native_execution") is False, "not a preserved host failure")
            previous_seconds += sum(step["seconds"] for step in failed["steps"])
            failures.append((failure_dir, tree(failure_dir), approved_hash))
        prior_dirs = tuple(q for q in (prior_dir, *(f[0] for f in failures)) if q)
        prior_bytes = sum(own_bytes(q) for q in prior_dirs)
        remaining = BUDGET - prior_bytes
        need(remaining > 0 and shutil.disk_usage(ROOT).free >= RESERVE + remaining and ram() >= RAM,
             "16MiB combined fresh admission failed")
        out.mkdir(exist_ok=True); run = Run(out, previous_seconds, prior_dirs)
        if prior_rows:
            for name, row in prior_rows.items(): run.input(prior_dir / name, row["sha256"])
        for failure_dir, failure_rows, _approved_hash in failures:
            for name, row in failure_rows.items(): run.input(failure_dir / name, row["sha256"])
        inputs = {}
        for n in tuple(BASE) + ORIGINAL_TESTS:
            inputs[n] = run.input(source_root / n, BASE.get(n) if a.phase != "current" else None)
        fixture = run.input(ROOT / TEST)
        own_tool = run.input(Path(__file__).resolve())
        if previous:
            for n, expected in previous["original_inputs"].items():
                # Prior own source is already pinned in its immutable snapshot.
                # A new test/controller epoch is measured independently above.
                if prior_dir and n in (str(ROOT / TEST), str(Path(__file__).resolve())):
                    continue
                run.input(Path(n), expected)
        epoch = "red" if a.phase == "red" else "green"
        for n, raw in inputs.items(): run.write(out / epoch / n, raw)
        run.write(out / epoch / TEST, fixture)
        run.write(out / epoch / "tools/test_fat32_replace_failure.py", own_tool)
        patch = None
        if a.phase != "red":
            patch = run.input(ROOT / PATCH); run.write(out / "fat32-safe-replace.patch", patch)
            if a.phase == "current":
                for n in BASE: run.write(out / "preimage" / n, inputs[n])
                run.command([tool("patch"), "--batch", "--fuzz=0", "--no-backup-if-mismatch", "-R", "-p1", "-i", out / "fat32-safe-replace.patch"],
                            "current-recover-preimage", cwd=out / "preimage")
                for n, expected in BASE.items(): need(sha(read(out / "preimage" / n)) == expected, "current code is not exact reviewed patch generation")
            else:
                run.command([tool("patch"), "--batch", "--fuzz=0", "--no-backup-if-mismatch", "-p1", "-i", out / "fat32-safe-replace.patch"],
                            "actual-apply-pinned-patch", cwd=out / "green")
        production = out / epoch / "shizukudos/kernel64/fat32.c"
        fixture_path = out / epoch / TEST
        gcc = tool("gcc"); clang = tool("clang")
        common = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror"]
        executable = out / (epoch + "-replace")
        run.command([gcc, *common, fixture_path, production, "-o", executable], epoch + "-compile")
        if a.phase == "red":
            stdout, stderr = run.command([executable, "--red"], "actual-red-runtime", expect=1)
            need(b"RECOVERABLE" in stdout and b"OLD_DESTINATION_SURVIVES_FAILED_REPLACE: missing after real remount" in stderr,
                 "RED failed for an unrelated reason")
            status = "EXPECTED_REAL_FAT_REPLACEMENT_RED"
        else:
            if prior_dir:
                # Revalidate the reusable latest fixture's data-loss RED too;
                # this is genuine original production, not reused acceptance.
                portable_red = out / "portable-current-fixture-red"
                run.command([gcc, *common, fixture_path, prior_dir / "red/shizukudos/kernel64/fat32.c",
                             "-o", portable_red], "portable-red-compile")
                redout, rederr = run.command([portable_red, "--red"], "portable-red-runtime", expect=1)
                need(b"RECOVERABLE" in redout and b"OLD_DESTINATION_SURVIVES_FAILED_REPLACE: missing after real remount" in rederr,
                     "latest portable fixture failed before the original real data-loss oracle")
            stdout, stderr = run.command([executable], "green-runtime")
            need(b"PASS_REAL_FAT_REPLACE:" in stdout and not stderr, "real remount/failure oracle did not pass")
            sanitized = out / "green-replace-sanitized"
            run.command([clang, *common, "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                         fixture_path, production, "-o", sanitized], "green-sanitize-compile")
            sanout, sanerr = run.command([sanitized], "green-sanitize-runtime",
                                        env=dict(ASAN_OPTIONS="detect_leaks=1:halt_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
            need(stdout == sanout and not sanerr, "normal/full sanitizer semantics differ")
            batch = out / "original-batch"
            run.command([gcc, *common, out / epoch / ORIGINAL_TESTS[1], production, "-o", batch], "original-batch-compile")
            run.command([batch], "original-batch-runtime")
            run.command([gcc, "-std=gnu11", *common[1:], "-D_FILE_OFFSET_BITS=64", out / epoch / ORIGINAL_TESTS[0],
                         production, "-o", out / "original-image-walker"], "original-image-walker-compile")
            kernel = out / "fat32-kernel.o"
            run.command([gcc, "-m64", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
                         "-fno-pic", "-fno-pie", "-mcmodel=kernel", "-mno-red-zone", "-mgeneral-regs-only", "-fno-stack-protector",
                         "-c", production, "-o", kernel], "kernel-flags-compile")
            unresolved, err = run.command([tool("nm"), "-u", kernel], "kernel-undefined-symbols")
            need(not unresolved and not err, "freestanding FAT object acquired runtime dependencies")
            status = "REAL_HOST_REPLACEMENT_REGRESSION_PASS_KERNEL_PENDING"
        run.verify_inputs(); run.guard()
        result = dict(schema="shizukuos.fat32-replacement-save.v1", status=status,
                      original_inputs=run.original, preimage_sha256=BASE, patch_sha256=sha(patch) if patch else None,
                      actual_production_sha256=sha(read(production)), prior_red_sha256=a.red_sha256,
                      red_mode_difference="--red skips only the additive failed-output sentinel assertion; actual I/O error, old destination bytes and fresh-remount oracles remain required. GREEN never skips the sentinel.",
                      prior_completed_build_sha256=a.prior_build_sha256,
                      prior_tree_preserved=(tree(prior_dir) == prior_rows) if prior_dir else None,
                      preserved_failures=[dict(path=str(d), receipt_sha256=h, tree_preserved=tree(d) == rows)
                                          for d, rows, h in failures],
                      steps=run.steps, aggregate_seconds=run.seconds, outputs=tree(out), **FALSE,
                      limits=dict(output_budget=BUDGET, reserve=RESERVE, RAM=RAM, own_RSS=RSS, individual_seconds=60, aggregate_seconds=90,
                                  sample_period_seconds=.05, transient_overshoot_possible=True,
                                  combined_generations_budget=True, prior_output_bytes=prior_bytes,
                                  admission_remaining_budget=remaining,
                                  before_receipt_sampled_high_water=max(s["output"] for s in run.samples),
                                  sampled_RSS_high_water=max(s["RSS"] for s in run.samples),
                                  minimum_sampled_free=min(s["free"] for s in run.samples)),
                      verification_limits="Byte-memory sector callbacks and real FAT routines; not crash/powerloss/storage-barrier proof. Persistent rollback failure must poison writes and report error. Original external mkfs/mtools/fsck image suite only snapshotted/compiled here, not executed within16MiB.")
        payload = (json.dumps(result, indent=2) + "\n").encode()
        final = out / ("red-result.json" if a.phase == "red" else "result.json")
        run.write(final, payload); run.verify_inputs()
        if prior_dir: need(tree(prior_dir) == prior_rows, "late prior generation drift")
        for failure_dir, failure_rows, _approved_hash in failures:
            need(tree(failure_dir) == failure_rows, "late preserved failure drift")
        print(json.dumps(dict(status=status, receipt=str(final), sha256=sha(payload), actual_output_bytes=own_bytes(out),
                             actual_combined_output_bytes=run.total_bytes(), **FALSE)))
        return 0
    except (Exception, KeyboardInterrupt) as error:
        result = dict(error=str(error), steps=run.steps if run else [], **FALSE)
        if run:
            raw = (json.dumps(result, indent=2) + "\n").encode()
            if run.total_bytes() + len(raw) <= BUDGET:
                path = run.out / ("failed-" + a.phase + ".json")
                with path.open("xb") as f: f.write(raw)
        print(json.dumps(result)); return 1


if __name__ == "__main__":
    raise SystemExit(main())
