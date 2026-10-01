#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exact-production CoWait and MsgWait host checks; all output stays ignored."""
import argparse
import hashlib
import json
import re
import resource
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
TESTS = Path(__file__).resolve().parent


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--baseline-user32", type=Path)
    parser.add_argument("--baseline-co-wait", type=Path)
    args = parser.parse_args()
    if args.baseline_user32 and args.baseline_co_wait:
        raise SystemExit("choose one concrete counterfactual per run")
    out = args.output.resolve()
    if not out.is_relative_to(ROOT / "build"):
        raise SystemExit("output must stay within this worktree's ignored build directory")
    out.mkdir(parents=True, exist_ok=False)
    current_user32 = ROOT / "shizukudos/win64/dlls/user32/user32_core.c"
    user32 = args.baseline_user32.resolve() if args.baseline_user32 else current_user32
    paths = [ROOT / "shizukudos/win64/dlls/ole32/co_wait.c",
             TESTS / "cowait_host_contract.h", TESTS / "test_co_wait_host.c",
             TESTS / "test_msg_wait_host.c", Path(__file__).resolve(), user32]
    if args.baseline_co_wait:
        paths.append(args.baseline_co_wait.resolve())
    before = {str(p): digest(p.read_bytes()) for p in paths}
    raw = user32.read_bytes()
    # The next public function declaration is an unambiguous source boundary;
    # no modified surrogate implementation or copied algorithm is compiled.
    match = re.search(rb"(?m)^DLLAPI DWORD WINAPI MsgWaitForMultipleObjectsEx\([^;{}]+\{\n.*?^}\n",
                      raw, re.DOTALL)
    if not match:
        raise SystemExit("cannot find complete exact production MsgWait definition")
    consumed = match.group(0)
    (out / "production_msg_wait.h").write_bytes(consumed)
    results = []
    for compiler, extra in [("gcc", []), ("clang", ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])]:
        for name in ("test_co_wait_host", "test_msg_wait_host"):
            binary = out / f"{name}-{compiler}"
            command = [compiler, "-std=c11", "-D_GNU_SOURCE", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                       *extra, "-I", str(out), str(TESTS / f"{name}.c"), "-o", str(binary)]
            if args.baseline_co_wait and name == "test_co_wait_host":
                command.insert(1, '-DSHZ_COWAIT_SOURCE="' + str(args.baseline_co_wait.resolve()) + '"')
            build = subprocess.run(command, text=True, capture_output=True)
            if build.returncode:
                raise SystemExit(build.stdout + build.stderr)
            run = subprocess.run([str(binary)], text=True, capture_output=True,
                                 preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_CORE, (0, 0)))
            result = {"compiler": compiler, "fixture": name, "command": command,
                      "exit_code": run.returncode, "stdout": run.stdout, "stderr": run.stderr,
                      "binary_sha256": digest(binary.read_bytes())}
            results.append(result)
            print(run.stdout or run.stderr, end="", flush=True)
    after = {str(p): digest(p.read_bytes()) for p in paths}
    stable = before == after
    expected_failure = bool(args.baseline_user32)
    co_results = [r for r in results if r["fixture"] == "test_co_wait_host"]
    passes = all((r["exit_code"] != 0 and
                  "CoWaitForMultipleHandles(8,1000,1,handles,&output.index)==S_OK" in r["stderr"]
                  if args.baseline_co_wait else r["exit_code"] == 0) for r in co_results)
    msg_results = [r for r in results if r["fixture"] == "test_msg_wait_host"]
    passes = passes and all((r["exit_code"] != 0 and
                            "==WAIT_OBJECT_0&&wait_calls==1&&got_timeout==0" in r["stderr"]
                            if expected_failure else r["exit_code"] == 0)
                            for r in msg_results)
    receipt = {"status": "PASS" if passes and stable else "FAIL", "sources_stable": stable,
               "source_sha256": before, "msg_wait_function_sha256": digest(consumed),
               "baseline_counterfactual": expected_failure or bool(args.baseline_co_wait), "results": results,
               "scope": "exact production source with injected host outcomes; no guest/publisher evidence"}
    (out / "host-result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return 0 if passes and stable else 1


if __name__ == "__main__":
    raise SystemExit(main())
