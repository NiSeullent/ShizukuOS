#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded host-only RED/GREEN checks of exact native builder role-gate bytes.

Explicit production source and real producer schema receipt are read only.
The candidate unified patch applies strictly in memory. The host harness runs
only extracted production helpers and its input prefix with small synthetic
containers; it never executes builder main, compilers, VM, EFI or ISO tools.
RED must first preserve the actual original wrong-role admission; GREEN needs
its exact receipt. Each phase uses a fresh child under one owned 2 MiB parent.

This runner accepts only the original pinned preimage. For an already-patched
current source, the direct host harness supports explicit --source-sha256 with
before/after byte verification; see its docstring and retain external admission.
"""
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import signal
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
PREIMAGE = "c0d46b639de9ce49525c98f7d9de1bae9b5969386990299d8aa516b49c760690"
TARGET = "shizukudos/supervisor/native_win98/build.py"
RESERVE, BUDGET, MEMORY, RSS = 20 << 30, 2 << 20, 6 << 30, 256 << 20
FALSE = {"builder_main_executed": False, "VM_executed": False,
         "native_Windows98_verified": False, "MS_DOS_replaced": False,
         "modern_app_functionality_verified": False}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read(path, maximum=1 << 20):
    path = Path(path)
    require(path.is_absolute() and path.resolve(strict=True) == path,
            "canonical regular input required")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= maximum, "input geometry refused")
        data = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
    require(len(data) == before.st_size and all(getattr(before, name) == getattr(after, name)
            for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")), "input changed during read")
    return data


def file_hash(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            result.update(chunk)
    return result.hexdigest()


def members(path):
    result = {}
    if path.exists():
        for file in path.rglob("*"):
            require(not file.is_symlink(), "unexpected output alias")
            if file.is_file():
                result[str(file.relative_to(path))] = {"bytes": file.stat().st_size, "sha256": file_hash(file)}
    return result


def memory_available():
    return next(int(line.split()[1]) * 1024 for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:"))


def admission(base):
    free, memory = shutil.disk_usage(base.parent).free, memory_available()
    require(free >= RESERVE + BUDGET, "20 GiB retained disk floor plus 2 MiB budget required")
    require(memory >= MEMORY, "6 GiB available memory required")
    return {"free_bytes": free, "MemAvailable_bytes": memory}


def apply_exact(original, patch):
    rows, source = patch.splitlines(keepends=True), original.splitlines(keepends=True)
    require(rows[:2] == ["--- a/" + TARGET + "\n", "+++ b/" + TARGET + "\n"], "wrong patch target")
    output, pos, i = [], 0, 2
    while i < len(rows):
        header = re.fullmatch(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n", rows[i])
        require(header is not None, "invalid unified hunk")
        at, old_count, new_count = int(header[1]) - 1, int(header[2] or 1), int(header[4] or 1)
        require(pos <= at <= len(source), "overlapping/invalid hunk location")
        output.extend(source[pos:at]); pos = at; i += 1; old = new = 0
        while i < len(rows) and not rows[i].startswith("@@ "):
            row = rows[i]; require(row[:1] in (" ", "-", "+"), "invalid hunk row")
            if row[0] in " -":
                require(pos < len(source) and source[pos] == row[1:], "exact preimage/context mismatch")
                pos += 1; old += 1
            if row[0] in " +": output.append(row[1:]); new += 1
            i += 1
        require(old == old_count and new == new_count, "hunk line count mismatch")
    output.extend(source[pos:])
    return "".join(output)


def group_rss(group):
    total = 0
    for directory in Path("/proc").glob("[0-9]*"):
        try:
            fields = (directory / "stat").read_text().rsplit(")", 1)[1].split()
            if int(fields[2]) == group:
                total += next((int(line.split()[1]) * 1024 for line in (directory / "status").read_text().splitlines()
                               if line.startswith("VmRSS:")), 0)
        except (OSError, ValueError, IndexError):
            pass
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--production-source", type=Path, required=True)
    parser.add_argument("--production-preimage-sha256", required=True)
    parser.add_argument("--schema-receipt", type=Path, required=True)
    parser.add_argument("--schema-receipt-sha256", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--phase", choices=("red", "green"), required=True)
    parser.add_argument("--red-evidence", type=Path)
    parser.add_argument("--red-evidence-sha256")
    args = parser.parse_args()
    started = time.monotonic()
    require(args.production_preimage_sha256 == PREIMAGE, "unapproved production preimage")
    source_path = args.production_source.absolute()
    schema_path = args.schema_receipt.absolute()
    original, schema_bytes = read(source_path), read(schema_path)
    require(sha(original) == PREIMAGE, "production source differs from the pinned preimage")
    require(sha(schema_bytes) == args.schema_receipt_sha256, "explicit producer schema receipt pin mismatch")
    schema = json.loads(schema_bytes)
    roles = schema.get("kernels") if isinstance(schema, dict) else None
    require(isinstance(roles, dict), "actual producer receipt lacks kernels map")
    actual_roles = {}
    for name in ("kernel64", "kernel64-standalone"):
        role = roles.get(name)
        require(isinstance(role, dict) and isinstance(role.get("sha256"), str) and
                re.fullmatch("[0-9a-f]{64}", role["sha256"]) is not None and
                type(role.get("bytes")) is int and role["bytes"] > 0, "actual producer role schema differs")
        actual_roles[name] = {key: role[key] for key in ("sha256", "bytes")}
    test = ROOT / "tests/test_native_win98_kernel64_role.py"
    runner = Path(__file__).resolve()
    patch = ROOT / "patches/supervisor/native-win98-kernel64-role.patch"
    paths = [source_path, schema_path, test, runner, patch]
    inputs = {str(p): sha(read(p)) for p in paths}
    patched = apply_exact(original.decode(), read(patch).decode())
    ast.parse(patched)
    out = args.output_dir.absolute()
    require(out.resolve() == out and ROOT / "build" in out.parents and not out.exists(), "fresh canonical owned build output required")
    base = out.parent
    ownership = {"kind": "native-win98-kernel64-role", "production_preimage_sha256": PREIMAGE}
    marker = base / "ownership.json"
    old = members(base)
    if base.exists():
        require(marker.is_file() and json.loads(read(marker)) == ownership, "unexpected output parent owner")
    else:
        require(args.phase == "red" and base.parent.is_dir(), "RED needs a fresh parent under existing build/")
    prior_elapsed = 0
    red_pin = None
    if args.phase == "green":
        require(args.red_evidence and args.red_evidence_sha256, "GREEN requires explicit actual RED receipt and SHA")
        red_path = args.red_evidence.absolute()
        require(base in red_path.parents, "RED must belong to the same 2 MiB parent")
        red_bytes = read(red_path); red_pin = sha(red_bytes)
        require(red_pin == args.red_evidence_sha256, "RED evidence differs")
        red = json.loads(red_bytes)
        require(red.get("passed") is True and red.get("phase") == "red" and
                red.get("original_wrong_role_admitted") is True and red.get("source_before") == inputs,
                "closed genuine production RED with unchanged sources required")
        prior_elapsed = red["elapsed_seconds"]
    else:
        require(not args.red_evidence and not args.red_evidence_sha256, "RED does not consume previous evidence")
    before = admission(base)
    require(sum(n["bytes"] for n in old.values()) + len(schema_bytes) + 256 * 1024 < BUDGET, "2 MiB aggregate output admission failed")
    interpreter = Path(sys.executable).resolve(strict=True)
    interpreter_pin = file_hash(interpreter)
    base.mkdir(exist_ok=True)
    if not marker.exists(): marker.write_text(json.dumps(ownership, indent=2) + "\n")
    out.mkdir()
    record = {"schema": 1, "phase": args.phase, "passed": False, **FALSE,
              "production_preimage_sha256": PREIMAGE, "patched_source_sha256": sha(patched.encode()),
              "source_before": inputs, "resources": {"retained_disk_floor_bytes": RESERVE,
              "aggregate_output_budget_bytes": BUDGET, "memory_floor_bytes": MEMORY,
              "RSS_limit_bytes": RSS, "command_wall_limit_seconds": 60, "aggregate_seconds_limit": 90,
              "admission_before": before}, "steps": [], "red_evidence_sha256": red_pin,
              "actual_producer_schema_roles": actual_roles,
              "fixture_scope": "small synthetic byte fixtures; actual producer schema is read/pinned only",
              "interpreter": {"path": str(interpreter), "sha256": interpreter_pin}}
    try:
        selected = original.decode() if args.phase == "red" else patched
        snapshot = out / "production-selected.py"; snapshot.write_text(selected)
        (out / "production-original.py").write_bytes(original)
        (out / "candidate.patch").write_bytes(read(patch))
        (out / "test-source.py").write_bytes(read(test))
        (out / "runner-source.py").write_bytes(read(runner))
        (out / "actual-producer-receipt.json").write_bytes(schema_bytes)
        for label, optimized in (("red", False),) if args.phase == "red" else (("normal", False), ("optimized", True)):
            sampled = admission(base)
            command = [str(interpreter), "-B"] + (["-O"] if optimized else []) + [str(out / "test-source.py"),
                       "--source", str(snapshot), "--source-sha256", sha(selected.encode()),
                       "--fixture-root", str(out / (label + "-fixtures")), "--phase", args.phase]
            env = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C", "TZ": "UTC",
                   "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0"}
            step = {"command": command, "environment": env, "admission_before": sampled}
            record["steps"].append(step)
            stdout, stderr = out / (label + ".stdout.log"), out / (label + ".stderr.log")
            def limits():
                resource.setrlimit(resource.RLIMIT_AS, (RSS, RSS))
                resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
                resource.setrlimit(resource.RLIMIT_FSIZE, (BUDGET, BUDGET))
            command_start = time.monotonic(); peak = 0
            with stdout.open("xb") as sout, stderr.open("xb") as serr:
                child = subprocess.Popen(command, stdout=sout, stderr=serr, env=env,
                                         start_new_session=True, preexec_fn=limits)
                try:
                    while child.poll() is None:
                        peak = max(peak, group_rss(child.pid))
                        require(peak <= RSS, "owned command RSS exceeded 256 MiB")
                        require(time.monotonic() - command_start <= 60, "owned command exceeded 60 seconds")
                        require(prior_elapsed + time.monotonic() - started <= 90, "aggregate phase runtime exceeded 90 seconds")
                        require(sum(n["bytes"] for n in members(base).values()) < BUDGET - 32768, "aggregate output budget exceeded")
                        time.sleep(0.025)
                    code = child.wait()
                finally:
                    if child.poll() is None:
                        os.killpg(child.pid, signal.SIGKILL); child.wait()
                    step.update(exit_code=child.returncode,
                                elapsed_seconds=round(time.monotonic() - command_start, 6),
                                peak_group_RSS_bytes=peak,
                                stdout={"path": stdout.name, "bytes": stdout.stat().st_size, "sha256": file_hash(stdout)},
                                stderr={"path": stderr.name, "bytes": stderr.stat().st_size, "sha256": file_hash(stderr)})
            step.update(exit_code=code, elapsed_seconds=round(time.monotonic() - command_start, 6), peak_group_RSS_bytes=peak,
                        stdout={"path": stdout.name, "bytes": stdout.stat().st_size, "sha256": file_hash(stdout)},
                        stderr={"path": stderr.name, "bytes": stderr.stat().st_size, "sha256": file_hash(stderr)})
            textout, texterr = stdout.read_text(), stderr.read_text()
            if args.phase == "red":
                require(code == 1 and "ORIGINAL_WRONG_ROLE_ADMITTED " in textout and
                        "FAILED (failures=1)" in texterr and "errors=" not in texterr,
                        "RED did not reproduce genuine wrong-role admission")
                record["original_wrong_role_admitted"] = True
            else:
                require(code == 0 and re.search(r"Ran 19 tests", texterr) and texterr.rstrip().endswith("OK"), "host role controls failed")
        late = {str(p): sha(read(p)) for p in paths}
        require(late == inputs and file_hash(interpreter) == interpreter_pin, "live source/producer/interpreter drift")
        require(all(members(base).get(name) == value for name, value in old.items()), "historical evidence changed")
        record.update(passed=True, source_after=late, historical_before_after_match=True,
                      selected_source_sha256=file_hash(snapshot), selected_source_exact_match=True,
                      outputs=members(out), resources_after=admission(base))
    except BaseException as error:
        record["error"] = str(error)
        raise
    finally:
        record["elapsed_seconds"] = round(time.monotonic() - started, 6)
        record["prior_elapsed_seconds"] = prior_elapsed
        total = sum(n["bytes"] for n in members(base).values())
        encoded = (json.dumps(record, indent=2) + "\n").encode()
        require(total + len(encoded) <= BUDGET, "result cannot fit owned 2 MiB parent")
        (out / "result.json").write_bytes(encoded)
    print(json.dumps({"passed": record["passed"], "phase": args.phase,
                      "receipt": str(out / "result.json"), "sha256": file_hash(out / "result.json"), **FALSE}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
