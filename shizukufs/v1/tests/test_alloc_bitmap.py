#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded production bitmap differential, freestanding closure and CPU check.

No filesystem images, VM, private inputs, network access or source edits. Every
invocation requires a new output directory and preserves failed command output.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time


BASELINE = "d612d9f36854c9c6bd2a2a8bd895e99e762fbca7"
ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / "shizukufs/v1/libsfs/sfs_alloc.c"
FIXTURE = Path(__file__).with_suffix(".c")
LIB = SOURCE.parent
HOST_FLAGS = ["-std=c11", "-march=x86-64", "-Wall", "-Wextra", "-Werror", "-Wshadow",
              "-Wstrict-prototypes", "-Wvla", "-ffunction-sections", "-fdata-sections"]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def kernel_flags() -> list[str]:
    # Parse the literal; importing kbuild would execute repository bootstrap code.
    tree = ast.parse((ROOT / "shizukudos/kbuild.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "K64_FLAGS" for t in node.targets):
            result = ast.literal_eval(node.value)
            if not isinstance(result, list) or not all(isinstance(v, str) for v in result):
                raise ValueError("K64_FLAGS is not a literal string list")
            return result
    raise ValueError("actual K64_FLAGS missing")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=False)
    os.chmod(out, 0o700)
    receipt: dict = {"scope": "production bitmap helper host correctness and CPU cost only",
                     "baseline_commit": BASELINE, "inputs_before": {}, "commands": [],
                     "pass": False}
    pins = [SOURCE, FIXTURE, Path(__file__).resolve(), Path(__file__).with_suffix(".md"), ROOT / "shizukudos/kbuild.py",
            *sorted(LIB.glob("*.h"))]
    receipt["inputs_before"] = {str(p.relative_to(ROOT)): sha(p) for p in pins}

    def save() -> None:
        p = out / "receipt.json"
        p.write_text(json.dumps(receipt, indent=2) + "\n")
        os.chmod(p, 0o600)

    def command(name: str, argv: list[str], timeout: int = 180) -> str:
        item: dict = {"name": name, "argv": argv}
        receipt["commands"].append(item)
        started = time.monotonic()
        try:
            p = subprocess.run(argv, cwd=ROOT, capture_output=True, text=True,
                               timeout=timeout, env={**os.environ,
                                                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                                                    "UBSAN_OPTIONS": "halt_on_error=1"})
            stdout, stderr, rc = p.stdout, p.stderr, p.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            if isinstance(stdout, bytes): stdout = stdout.decode(errors="replace")
            if isinstance(stderr, bytes): stderr = stderr.decode(errors="replace")
            rc = None
            item["timed_out"] = True
        item.update(returncode=rc, elapsed_seconds=time.monotonic() - started)
        (out / f"{name}.stdout").write_text(stdout)
        (out / f"{name}.stderr").write_text(stderr)
        save()
        print(f"{name}: {'PASS' if rc == 0 else 'FAIL'} ({item['elapsed_seconds']:.3f}s)", flush=True)
        if rc != 0: raise RuntimeError(f"{name} failed; preserved under {out}")
        return stdout

    try:
        for tool in ("gcc", "clang", "nm", "objdump", "git"):
            if not shutil.which(tool): raise RuntimeError(f"missing tool: {tool}")
            command(f"version-{tool}", [tool, "--version"], 10)
        baseline_source = out / "baseline_sfs_alloc.c"
        baseline_source.write_text(command("baseline-source", [
            "git", "show", f"{BASELINE}:shizukufs/v1/libsfs/sfs_alloc.c"], 10))
        receipt["baseline_source_sha256"] = sha(baseline_source)
        for label, source in (("baseline", baseline_source), ("candidate", SOURCE)):
            command(f"compile-{label}", ["gcc", *HOST_FLAGS, "-O2", "-I", str(LIB),
                    f'-DSFS_ALLOC_SOURCE="{source}"', str(FIXTURE), "-Wl,--gc-sections",
                    "-o", str(out / label)])
        command("compile-candidate-clang-sanitized", ["clang", *HOST_FLAGS, "-O1", "-g",
                "-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-fno-omit-frame-pointer",
                str(FIXTURE), "-Wl,--gc-sections", "-o", str(out / "candidate-sanitized")])
        baseline_check = command("check-baseline", [str(out / "baseline")])
        candidate_check = command("check-candidate", [str(out / "candidate")])
        sanitized_check = command("check-candidate-sanitized", [str(out / "candidate-sanitized")])
        if not (baseline_check == candidate_check == sanitized_check):
            raise RuntimeError("case counts/digests differ between actual sources/compilers")
        receipt["correctness"] = candidate_check.strip()
        flags = kernel_flags()
        receipt["actual_K64_FLAGS"] = flags
        undefined: dict[str, list[str]] = {}
        for label, source in (("baseline", baseline_source), ("candidate", SOURCE)):
            obj = out / f"{label}-k64.o"
            command(f"compile-{label}-k64", ["gcc", *flags, "-I", str(LIB),
                    "-c", str(source), "-o", str(obj)])
            undefined[label] = command(f"undefined-{label}-k64", ["nm", "-u", str(obj)]).splitlines()
        if undefined["baseline"] != undefined["candidate"]:
            raise RuntimeError("freestanding candidate changes undefined-symbol closure")
        receipt["freestanding_undefined_symbols_unchanged"] = True
        asm = command("disassemble-candidate-k64", ["objdump", "-d", str(out / "candidate-k64.o")])
        if re.search(r"\b(?:popcnt|tzcnt|lzcnt)[bwlq]?\b", asm):
            raise RuntimeError("candidate requires instructions beyond baseline x86-64")
        benchmarks = {}
        # Reverse the order once; CPU-clock time avoids descheduling accounting.
        for round_no, order in enumerate((("baseline", "candidate"), ("candidate", "baseline"))):
            for label in order:
                report = json.loads(command(f"benchmark-{label}-{round_no}",
                                            [str(out / label), "--benchmark"]))
                benchmarks[f"{label}-{round_no}"] = report
        comparisons = []
        for round_no in range(2):
            old, new = benchmarks[f"baseline-{round_no}"], benchmarks[f"candidate-{round_no}"]
            if old["checksum"] != new["checksum"]: raise RuntimeError("benchmark count checksum differs")
            for report in (old, new):
                floor = report["timer_pair_median_cpu_ns"]
                if floor <= 0: raise RuntimeError("invalid measured CPU timer floor")
                if min(r["median_cpu_ns"] / floor for r in report["rows"]) < 20:
                    raise RuntimeError("benchmark sample is too close to measured timer floor")
            for a, b in zip(old["rows"], new["rows"], strict=True):
                key = (a["from"], a["bits"], a["pattern"])
                if key != (b["from"], b["bits"], b["pattern"]): raise RuntimeError("benchmark rows differ")
                if a["row_checksum"] != b["row_checksum"] or a["expected_row_checksum"] != b["expected_row_checksum"]:
                    raise RuntimeError("per-case benchmark count checksums differ")
                comparisons.append({"round": round_no, "from": key[0], "bits": key[1], "pattern": key[2],
                                    "row_checksum": a["row_checksum"],
                                    "expected_row_checksum": a["expected_row_checksum"],
                                    "baseline_median_cpu_ns": a["median_cpu_ns"],
                                    "candidate_median_cpu_ns": b["median_cpu_ns"],
                                    "ratio_baseline_over_candidate": a["median_cpu_ns"] / b["median_cpu_ns"]})
        receipt["timer_floor_margins"] = {label: min(r["median_cpu_ns"] / report["timer_pair_median_cpu_ns"]
                                                   for r in report["rows"])
                                         for label, report in benchmarks.items()}
        receipt["benchmark_comparisons"] = comparisons
        large = [r for r in comparisons if r["bits"] >= 512]
        receipt["large_run_ratio_range"] = [min(r["ratio_baseline_over_candidate"] for r in large),
                                             max(r["ratio_baseline_over_candidate"] for r in large)]
        if min(r["ratio_baseline_over_candidate"] for r in large) <= 1:
            raise RuntimeError("no consistent measured improvement for tested large runs")
        receipt["inputs_after"] = {str(p.relative_to(ROOT)): sha(p) for p in pins}
        if receipt["inputs_after"] != receipt["inputs_before"]: raise RuntimeError("source changed during validation")
        receipt["pass"] = True
    except Exception as exc:
        receipt["failure"] = str(exc)
        print(str(exc), file=sys.stderr)
    finally:
        save()
    print(f"receipt: {out / 'receipt.json'}", flush=True)
    return 0 if receipt["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
