#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run unchanged memory assertions against a frozen canonical source epoch.

Only host commands run. The existing 4409 C/Python fixture stays unchanged.
Captured canonical owned-group handling supplies 30s work plus 2s cleanup;
actual -MM outputs seal consumed local headers before each compilation.
External compiler support, system headers and libraries remain unsealed.
Each command inherits a per-file soft RLIMIT_FSIZE; aggregate leaf checks run
before/after commands and include the final adapter receipt before writing.
This is not a hard aggregate allocation quota or a bound on captured stdout RAM.
"""
from pathlib import Path
import hashlib

if "__captured_adapter_bytes__" not in globals():
    _entry = Path(__file__).resolve()
    _body = _entry.read_bytes()
    exec(compile(_body, str(_entry), "exec"), {
        "__name__": __name__, "__file__": str(_entry),
        "__captured_adapter_bytes__": _body,
    })
    raise SystemExit(0)

import argparse
import ast
import ctypes
import json
import os
import resource
import shlex
import shutil
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
ORIGINAL = ROOT / "shizukudos/tests/test_nt_memory_queries.py"
FIXTURE = ROOT / "shizukudos/tests/test_nt_memory_queries.c"
OWNER = ROOT / "shizukudos/tests/test_k32_memory_concurrency.py"
OWNER_SHA = "adcf9a70767541d6fdeb47146bce72f3e3e349a05595d539091d2a7627e2fe4f"
ORIGINAL_SHA = "9aa4268ce7383fbb12d3e704f10a620601181b023e0b5c40db3e0b7f1ad3a277"
FIXTURE_SHA = "5a3f71fd9a92cdf9ea037047eaaf1cb09446aa03693ab9bf91f2faa48c294b3f"
LIMIT = 64 << 20


def digest(data):
    return hashlib.sha256(data).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--compile-units", action="store_true")
    args = parser.parse_args()
    out = args.out.resolve()
    if (not out.is_relative_to(ROOT / "build") or out.exists() or
            any(p.is_symlink() for p in (args.out, *args.out.parents))):
        parser.error("fresh local ignored output required")
    driver = Path(__file__).resolve()
    buffers = {driver: __captured_adapter_bytes__, ORIGINAL: ORIGINAL.read_bytes(),
               FIXTURE: FIXTURE.read_bytes(), OWNER: OWNER.read_bytes()}
    assert driver.read_bytes() == buffers[driver]
    assert digest(buffers[ORIGINAL]) == ORIGINAL_SHA
    assert digest(buffers[FIXTURE]) == FIXTURE_SHA
    assert digest(buffers[OWNER]) == OWNER_SHA
    # Execute the exact captured definitions, without invoking its entry point.
    ns = {"__name__": "captured_unchanged_memory_fixture", "__file__": str(ORIGINAL)}
    exec(compile(buffers[ORIGINAL], str(ORIGINAL), "exec"), ns)
    owner_tree = ast.parse(buffers[OWNER], filename=str(OWNER))
    functions = [n for n in owner_tree.body if isinstance(n, ast.FunctionDef)
                 and n.name in ("group_members", "run_owned")]
    assert {n.name for n in functions} == {"group_members", "run_owned"}
    owner_ns = {"Path": Path, "ctypes": ctypes, "os": os, "signal": signal,
                "subprocess": subprocess, "time": time, "CLEANUP_SECONDS": 2.0}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(OWNER), "exec"), owner_ns)
    ns["FILES"] += ["tests/test_nt_memory_queries_canonical.py", "tests/test_k32_memory_concurrency.py"]
    paths = [ROOT / "shizukudos" / p for p in ns["FILES"]]
    paths += sorted((ROOT / "shizukudos").rglob("*.h")) + ns["SDKS"]
    source_pins = {p: file_sha(p) for p in dict.fromkeys(paths)}
    tools = {Path(shutil.which(n)).resolve(): None for n in
             ("gcc", "clang", "x86_64-w64-mingw32-gcc")}
    tools[Path(sys.executable).resolve()] = None
    tools = {p: file_sha(p) for p in tools}
    assert all(file_sha(p) == digest(b) for p, b in buffers.items())
    receipt = {"status": "FAIL", "scope": __doc__, "base_requested":
               "660194da44fe40df88ac67151a7aab79213353d7",
               "unchanged_fixture_sha256": FIXTURE_SHA,
               "unchanged_original_producer_sha256": ORIGINAL_SHA,
               "captured_owned_helper_sha256": OWNER_SHA,
               "driver_sha256": digest(buffers[driver]),
               "source_sha256_before": {str(p): h for p, h in source_pins.items()},
               "tool_sha256_before": {str(p): h for p, h in tools.items()},
               "owned_commands": [], "observed_dependencies": [],
               "generated_before_first_use": {}, "output_limit_bytes": LIMIT,
               "work_timeout_seconds": 30, "cleanup_timeout_seconds": 2,
               "native_windows98_verified": False, "guest_executed": False,
               "ap_executed": False, "external_toolchain_closure_sealed": False}
    generated = {}

    def logical_bytes():
        return sum(p.stat().st_size for p in out.rglob("*") if p.is_file()) if out.exists() else 0

    def stable():
        assert all(file_sha(p) == h for p, h in source_pins.items()), "source drift"
        assert all(file_sha(p) == h for p, h in tools.items()), "tool drift"
        assert all(file_sha(p) == h for p, h in generated.items()), "generated input drift"
        assert logical_bytes() < LIMIT, "aggregate output budget exhausted"

    def capture_generated():
        for p in out.rglob("*"):
            if p.is_file() and p.suffix in (".inc", ".h", ".d"):
                value = file_sha(p)
                assert p not in generated or generated[p] == value
                generated[p] = value
                receipt["generated_before_first_use"][str(p.relative_to(out))] = value

    def own(argv, label):
        stable()
        remaining = LIMIT - logical_bytes()
        assert remaining > (1 << 20), "retain room for terminal evidence"
        old_limit = resource.getrlimit(resource.RLIMIT_FSIZE)
        # Inherited per-file bound plus before/after aggregate checks. Compiler
        # internal transient files are not independently sealed or enumerated.
        finite_limits = [v for v in old_limit if v != resource.RLIM_INFINITY]
        child_limit = min([remaining - (1 << 20), *finite_limits])
        resource.setrlimit(resource.RLIMIT_FSIZE, (child_limit, old_limit[1]))
        try:
            raw = owner_ns["run_owned"](list(map(str, argv)), timeout=30)
        finally:
            resource.setrlimit(resource.RLIMIT_FSIZE, old_limit)
        receipt["owned_commands"].append({"name": label, **raw})
        (out / (label + ".owned.json")).write_text(json.dumps(raw, indent=2) + "\n")
        stable()
        return raw

    def admitted(raw):
        return (raw["exit_code"] == raw["parent_exit_code"] == 0 and
                not raw["timed_out"] and raw["infrastructure_error"] is None and
                raw["cleanup"]["passed"] and raw["cleanup"]["direct_reaped"] and
                raw["cleanup"]["group_empty"] and raw["cleanup"]["drain_complete"])

    def adapted_run(argv, **_unused):
        argv = list(map(str, argv))
        name = "command-%02d" % len(receipt["owned_commands"])
        if any(p.endswith(".c") for p in argv) and "-o" in argv:
            capture_generated()
            before_dep = {p: file_sha(p) for p in out.rglob("*") if p.is_file()}
            dep = out / (name + ".d")
            cut = argv.index("-o")
            dep_argv = argv[:cut] + argv[cut + 2:]
            dep_argv = [p for p in dep_argv if p != "-c"] + ["-MM", "-MF", str(dep)]
            row = own(dep_argv, name + "-dependencies")
            if not admitted(row):
                raise RuntimeError("actual dependency discovery refused")
            body = dep.read_text().replace("\\\n", " ").partition(":")[2]
            observed = {}
            for value in shlex.split(body):
                path = Path(value).resolve()
                assert path in before_dep, "compiler dependency outside presealed frozen/generated inputs"
                assert file_sha(path) == before_dep[path], "dependency drift"
                observed[str(path)] = before_dep[path]
            assert observed, "empty actual compiler dependency rule"
            receipt["observed_dependencies"].append({"command": dep_argv,
                "dependency_sha256": file_sha(dep), "inputs_sha256": observed})
            capture_generated()
        raw = own(argv, name)
        cleanup = raw["cleanup"]
        return {"returncode": raw["parent_exit_code"], "stdout": raw["stdout"],
                "stderr": raw["stderr"], "timed_out": raw["timed_out"],
                "interrupted": bool(raw["infrastructure_error"] and
                                    "KeyboardInterrupt" in raw["infrastructure_error"]),
                "execution_error": raw["infrastructure_error"] is not None,
                "cleanup_failed": not cleanup["passed"],
                "leader_reaped": cleanup["direct_reaped"],
                "owned_group": cleanup["owned_pgid"],
                "owned_group_live_members": cleanup.get("remaining_group_pids", []),
                "group_term_attempted": "TERM" in cleanup["signals"],
                "group_kill_attempted": any(v.startswith("KILL") for v in cleanup["signals"]),
                "admitted": admitted(raw), "canonical_owned_capture": raw}

    ns["run_owned"] = adapted_run
    original_extract = ns["extract"]

    def extract(*argv):
        result = original_extract(*argv)
        capture_generated()
        stable()
        return result

    ns["extract"] = extract
    try:
        original_rc = ns["main"]()
        original_result = json.loads((out / "result.json").read_bytes())
        receipt.update(original_returncode=original_rc,
                       original_result_sha256=file_sha(out / "result.json"),
                       original_status=original_result["status"],
                       original_records=original_result["records"],
                       selected_body_sha256=original_result["selected_body_sha256"])
        stable()
        all_reaped = all(r["cleanup"]["passed"] and not r["timed_out"] and
                         r["infrastructure_error"] is None for r in receipt["owned_commands"])
        receipt["status"] = "PASS" if original_rc == 0 and all_reaped else "FAIL"
    except (Exception, KeyboardInterrupt) as error:
        receipt["error"] = type(error).__name__ + ": " + str(error)
    finally:
        # Final evidence must survive a dependency/setup/compile refusal too.
        # Capture every readable pin instead of abandoning later pins on the
        # first missing file. A capture error always refuses PASS.
        final_errors = []
        def after_map(pins, kind):
            observed = {}
            for p in pins:
                try:
                    observed[str(p)] = file_sha(p)
                except (OSError, KeyboardInterrupt) as error:
                    final_errors.append(kind + " " + str(p) + ": " +
                                        type(error).__name__ + ": " + str(error))
            return observed
        receipt["source_sha256_after"] = after_map(source_pins, "source")
        receipt["tool_sha256_after"] = after_map(tools, "tool")
        generated_after = after_map(generated, "generated")
        receipt["sources_stable"] = receipt["source_sha256_before"] == receipt["source_sha256_after"]
        receipt["tools_stable"] = receipt["tool_sha256_before"] == receipt["tool_sha256_after"]
        receipt["generated_inputs_stable"] = generated_after == {str(p): h for p, h in generated.items()}
        receipt["artifacts_sha256"] = {}
        receipt["artifacts_complete_except_this_receipt"] = False
        receipt["artifact_inventory_excludes"] = ["canonical-adapter-result.json"]
        receipt["inherited_per_file_soft_rlimit_fsize"] = True
        receipt["hard_aggregate_allocation_quota"] = False
        receipt["stdout_ram_bounded"] = False
        terminal = out / "canonical-adapter-result.json"
        other_bytes = 0
        leaf_bytes_complete = True
        inventory_error_start = len(final_errors)
        try:
            leaves = sorted(p for p in out.rglob("*") if p.is_file() and p != terminal) if out.exists() else []
            # The original result.json is an artifact. Only this adapter's
            # separately caller-hashed receipt is excluded from its own map.
            for p in leaves:
                try:
                    other_bytes += p.stat().st_size
                except (OSError, KeyboardInterrupt) as error:
                    leaf_bytes_complete = False
                    final_errors.append("leaf size " + str(p) + ": " +
                                        type(error).__name__ + ": " + str(error))
                try:
                    receipt["artifacts_sha256"][str(p.relative_to(out))] = file_sha(p)
                except (OSError, KeyboardInterrupt) as error:
                    final_errors.append("artifact " + str(p) + ": " +
                                        type(error).__name__ + ": " + str(error))
            actual = {str(p.relative_to(out)) for p in out.rglob("*") if p.is_file() and p != terminal} if out.exists() else set()
            receipt["artifact_inventory"] = sorted(actual)
            receipt["artifacts_complete_except_this_receipt"] = (
                actual == set(receipt["artifacts_sha256"]) and len(final_errors) == inventory_error_start)
        except (OSError, KeyboardInterrupt) as error:
            leaf_bytes_complete = False
            final_errors.append("inventory: " + type(error).__name__ + ": " + str(error))
        receipt["finalization_errors"] = final_errors
        if (final_errors or not receipt["sources_stable"] or not receipt["tools_stable"] or
                not receipt["generated_inputs_stable"] or not receipt["artifacts_complete_except_this_receipt"]):
            receipt["status"] = "FAIL"
        receipt["output_leaf_bytes_excluding_adapter_receipt"] = other_bytes
        receipt["output_leaf_bytes_complete"] = leaf_bytes_complete
        receipt["terminal_receipt_bytes"] = 0
        receipt["output_logical_bytes"] = other_bytes
        receipt["terminal_written"] = False

        def encoded_receipt():
            # The two decimal size fields change the JSON length themselves.
            # Stabilize their exact UTF-8 counts before admitting any write.
            for _ in range(32):
                data = (json.dumps(receipt, indent=2) + "\n").encode("utf-8")
                total = other_bytes + len(data)
                if (receipt["terminal_receipt_bytes"] == len(data) and
                        receipt["output_logical_bytes"] == total):
                    return data
                receipt["terminal_receipt_bytes"] = len(data)
                receipt["output_logical_bytes"] = total
            raise RuntimeError("terminal receipt size did not converge")

        if out.exists():
            try:
                receipt["terminal_written"] = True
                data = encoded_receipt()
                if not leaf_bytes_complete or receipt["output_logical_bytes"] > LIMIT:
                    receipt["status"] = "FAIL"
                    receipt["terminal_written"] = False
                    receipt["terminal_write_refused"] = (
                        "leaf size evidence incomplete" if not leaf_bytes_complete else
                        "complete receipt plus existing leaves exceeds 64 MiB")
                    # Keep the completed evidence in memory for the refusal
                    # summary; never exceed the leaf budget to persist it.
                    receipt["proposed_terminal_receipt_bytes"] = len(data)
                    receipt["proposed_output_logical_bytes"] = other_bytes + len(data)
                    receipt["terminal_receipt_bytes"] = 0
                    receipt["output_logical_bytes"] = logical_bytes()
                else:
                    terminal.write_bytes(data)
                    assert logical_bytes() == receipt["output_logical_bytes"] <= LIMIT, "terminal aggregate output budget"
            except (Exception, KeyboardInterrupt) as error:
                receipt["status"] = "FAIL"
                receipt["terminal_written"] = False
                receipt["terminal_write_error"] = type(error).__name__ + ": " + str(error)
                # A post-write refusal must not leave an admitted PASS receipt.
                # Attempt only a bounded FAIL rewrite; never erase artifacts or
                # exceed the observed budget to preserve this diagnostic.
                try:
                    other_bytes = sum(p.stat().st_size for p in out.rglob("*") if p.is_file() and p != terminal)
                    receipt["output_leaf_bytes_excluding_adapter_receipt"] = other_bytes
                    receipt["terminal_written"] = True
                    data = encoded_receipt()
                    if other_bytes + len(data) <= LIMIT:
                        terminal.write_bytes(data)
                    else:
                        receipt["terminal_written"] = False
                        receipt["terminal_write_refused"] = "FAIL receipt plus existing leaves exceeds 64 MiB"
                    receipt["output_logical_bytes"] = logical_bytes()
                except (Exception, KeyboardInterrupt) as final_error:
                    receipt["terminal_written"] = False
                    receipt["terminal_write_error"] += "; FAIL rewrite: " + type(final_error).__name__ + ": " + str(final_error)
        else:
            receipt["status"] = "FAIL"
            receipt["terminal_write_refused"] = "original producer created no output leaf"
    print(json.dumps({k: receipt.get(k) for k in
                     ("status", "original_status", "original_returncode", "error", "output_logical_bytes",
                      "terminal_written", "terminal_write_refused", "terminal_write_error", "finalization_errors")}))
    return 0 if receipt["status"] == "PASS" and receipt["terminal_written"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
