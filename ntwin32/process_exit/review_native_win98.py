#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Interpret frozen real Win98 exit logs; never launch, edit or access a VM disk."""
import argparse
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_SHA = "729b3a6d9ca02dc7bed789a01a5c69a5ba0fe395309e1de1235948be162dca32"
MODES = ["--main-import", "--main-native", "--worker-import", "--worker-native",
         "--unregistered", "--terminated", "--dynamic-unload"]
NAMES = ["PXMI.LOG", "PXMN.LOG", "PXWI.LOG", "PXWN.LOG", "PXUN.LOG", "PXTM.LOG", "PXDYN.LOG"]


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for data in iter(lambda: stream.read(1024 ** 2), b""):
            h.update(data)
    return h.hexdigest()


def require(good, reason):
    if not good:
        raise ValueError(reason)


def lines(raw):
    require(0 < len(raw) <= 32768 and raw.endswith(b"\r\n"), "bounded complete CRLF report required")
    result = raw.decode("ascii").split("\r\n")[:-1]
    require(all("\r" not in x and "\n" not in x and "\x00" not in x for x in result), "exact ASCII report lines required")
    require(not any(x.startswith("FAIL ") or "REPORT_FLUSH_FAILED=" in x or "OBSERVER_IO_FAILED=" in x for x in result), "native check/report failure preserved")
    return result


def one(report, key):
    values = [x[len(key) + 1:] for x in report if x.startswith(key + "=")]
    require(len(values) == 1, "one exact field required: " + key)
    return values[0]


def number(report, key):
    value = one(report, key)
    require(re.fullmatch(r"[0-9A-F]{8}", value) is not None, "exact hexadecimal field required: " + key)
    return int(value, 16)


def count(report, text, expected=1):
    require(report.count(text) == expected, "exact observation count differs: " + text)


def child_report(raw, mode):
    report = lines(raw)
    count(report, "SCOPE=OWNED_NATIVE_EXIT_NOTIFICATION_NOT_APPLICATION_ACCEPTANCE")
    count(report, "APPLICATION_EXECUTED=0")
    require(one(report, "MODE") == mode, "child mode differs")
    for label in ("actual original native Win98 4.10.2222", "actual original kernel ExitProcess export",
                  "native EXE validated and manager process lifetime pin acquired", "repeated initialize retains same instance",
                  "stack context refused", "native DLL callback refused", "native EXE data address refused as callback",
                  "native EXE code address refused as writable context", "rollback callback unpublished", "stale rollback token refused"):
        count(report, "PASS " + label)
    require(number(report, "KERNEL_EXPORT_EXITPROCESS_ADDRESS") != 0, "actual original export absent")
    observation = {"mode": mode, "application_success": False,
                   "native_original_resolver_used": number(report, "KERNELEX_ORIGINAL_EXPORT_RESOLVER_USED")}
    if mode == "--dynamic-unload":
        count(report, "STATUS=ACTUAL_DYNAMIC_UNLOAD_CONTROL_PASS")
        count(report, "PASS actual DLL_PROCESS_DETACH has NULL reserved")
        require(number(report, "ACTUAL_DYNAMIC_DETACH_REASON") == 0 and number(report, "ACTUAL_DYNAMIC_DETACH_RESERVED_NONNULL") == 0, "actual dynamic detach distinction differs")
        require(not any(x.startswith("CALLBACK=") for x in report), "dynamic unload invoked callbacks")
        count(report, "NATIVE_DEPENDENCY_DETACH=A REASON=0 RESERVED_NONNULL=1")
        require(not any(x.startswith("NATIVE_DEPENDENCY_DETACH=B") for x in report), "unloaded control unexpectedly has dependency B")
        return observation
    if mode == "--unregistered":
        count(report, "STATUS=UNREGISTERED_BEFORE_EXIT")
        require(not any(x.startswith("CALLBACK=") for x in report), "unregistered callback was invoked")
    else:
        require(number(report, "VICTIM_CREATE_HANDLE") != 0 and number(report, "VICTIM_CREATE_THREAD_ID") != 0 and number(report, "VICTIM_CREATE_ERROR") == 0, "actual victim CreateThread fields differ")
        if mode.startswith("--worker"):
            require(number(report, "CALLER_CREATE_HANDLE") != 0 and number(report, "CALLER_CREATE_THREAD_ID") != 0 and number(report, "CALLER_CREATE_ERROR") == 0, "actual caller CreateThread fields differ")
        if mode == "--terminated":
            count(report, "READY_FOR_TERMINATE=1")
            require(not any(x.startswith("CALLBACK=") or x.startswith("NATIVE_DEPENDENCY_DETACH=") for x in report), "TerminateProcess control dispatched detach")
            return observation
        count(report, "READY_FOR_NATIVE_EXIT=1")
        count(report, "STATUS=SCOPED_NATIVE_EXIT_NOTIFICATION_PASS")
        count(report, "CALLBACK=B")
        count(report, "CALLBACK=A")
        require(not any(x.startswith("CALLBACK=REMOVED") for x in report), "removed callback invoked")
        b, a = report.index("CALLBACK=B"), report.index("CALLBACK=A")
        require(b < a and number(report, "FAILURES") == 0, "reverse order/native failures differ")
        require(number(report, "CHECKS") == sum(x.startswith("PASS ") for x in report), "actual native check count differs")
        observed = []
        for block in (report[b:a], report[a:]):
            for label in ("actual DLL process detach reason and nonNULL reserved", "other worker terminated before notification",
                          "other worker TLS marker was published", "caller worker TLS marker was published"):
                count(block, "PASS " + label)
            stopped = number(block, "OTHER_WORKER_EXIT_AT_DETACH")
            require(stopped != 259, "victim still active at callback")
            thread, caller = number(block, "DETACH_THREAD_ID"), number(block, "INITIATING_CALLER_THREAD_ID")
            marker, expected = number(block, "DETACH_TLS_MARKER"), number(block, "INITIATING_CALLER_TLS_MARKER")
            require(expected == (0x22222222 if mode.startswith("--worker") else 0x11111111), "caller TLS observation marker differs")
            require(number(block, "DETACH_RUNS_ON_INITIATING_CALLER") == int(thread == caller), "thread identity observation inconsistent")
            require(number(block, "INITIATING_CALLER_TLS_SURVIVED") == int(thread == caller and marker == expected), "TLS observation inconsistent")
            observed.append({"detach_thread_id": thread, "caller_thread_id": caller, "detach_tls": marker,
                             "caller_tls_survived": thread == caller and marker == expected, "victim_exit_at_detach": stopped,
                             "dependency_A_already_detached": number(block, "NATIVE_DEP_A_ALREADY_DETACHED"),
                             "dependency_B_already_detached": number(block, "NATIVE_DEP_B_ALREADY_DETACHED")})
        observation["callbacks"] = observed
    for dependency in "AB":
        count(report, "NATIVE_DEPENDENCY_DETACH=" + dependency + " REASON=0 RESERVED_NONNULL=1")
    return observation


def suite_report(raw):
    report = lines(raw)
    require([x[11:] for x in report if x.startswith("PROBE_MODE=")] == MODES, "exact seven suite modes required")
    starts = [i for i, x in enumerate(report) if x.startswith("PROBE_MODE=")]
    observations = []
    for index, start in enumerate(starts):
        block = report[start:starts[index + 1] if index < 6 else len(report)]
        require(number(block, "OWNED_CHILD_PID") != 0 and number(block, "ACTUAL_WAIT") == 0, "actual child wait/PID differs")
        code = number(block, "ACTUAL_EXIT")
        require(code == (74 if index == 5 else 73), "actual child OS exit differs")
        require(one(block, "STATUS_CHILD") == "SCOPED_PASS", "native child verdict failed")
        require(not any("ERROR=" in x or "WATCHDOG" in x or "UNCONFIRMED" in x for x in block), "native guard/error/closure failure preserved")
        observations.append({"mode": MODES[index], "actual_child_wait": 0, "actual_child_os_exit": code})
    require(number(report, "ACTUAL_SCOPED_PASS_MODES") == 7 and number(report, "FAILURES") == 0, "suite counts differ")
    count(report, "STATUS=SCOPED_NATIVE_EXIT_NOTIFICATION_SUITE_PASS")
    return observations


def review(run):
    run = run.resolve(strict=True)
    require(run.is_relative_to(ROOT / "build"), "private captured run required")
    result_path = run / "result.json"
    result = json.loads(result_path.read_text())
    require(result.get("qemu_exit_code") == 0 and result.get("originals_unchanged") is True and result.get("prepared_source_unchanged") is True, "quiescent real run and unchanged originals required")
    files = result["guest_files"]
    require(files["manifest_sha256"] == MANIFEST_SHA and files["immutable_sources_unchanged"] is True and files["output_baseline"] == "all absent before private injection", "exact fresh frozen fixture required")
    manifest_path = Path(files["manifest"])
    require(sha(manifest_path) == MANIFEST_SHA, "selected frozen fixture changed")
    for path, pin in files["immutable_sources"].items():
        require(sha(path) == pin, "held fixture source changed")
    manifest = json.loads(manifest_path.read_text())
    for item in manifest["inputs"]:
        require(sha(item["source"]) == item["sha256"], "prepared fixture changed")
        actual = run / ("prepared-guest-" + item["guest"].rsplit("\\", 1)[1])
        require(actual.stat().st_size == item["bytes"] and sha(actual) == item["sha256"], "actual guest input readback changed")
    captured = {}
    for item in files["readback"]:
        name = item["guest"].rsplit("\\", 1)[1]
        path = Path(item["path"])
        require(name not in captured and path == run / ("guest-output-" + name) and item["status"] == "captured" and item["freshness"] == "new-in-owned-run", "exact fresh captured output required")
        require(path.stat().st_size == item["bytes"] and sha(path) == item["sha256"], "actual raw report hash differs")
        captured[name] = path.read_bytes()
    require(set(captured) == set(NAMES + ["PXSUIT.LOG"]), "exact eight fresh outputs required")
    return {"status": "PASS_BOUNDED_NATIVE_EXIT_NOTIFICATION", "fixture_sha256": MANIFEST_SHA,
            "run_receipt": {"path": str(result_path), "sha256": sha(result_path)},
            "children": [child_report(captured[name], mode) for name, mode in zip(NAMES, MODES)],
            "actual_child_exits": suite_report(captured["PXSUIT.LOG"]),
            "suite_own_os_exit_observed": False, "application_success": False,
            "production_loader_integration_accepted": False,
            "limits": ["Caller thread/TLS and dependency order are observations; no general NT ordering contract is inferred.",
                       "Suite own actual OS exit and final report-close status need an independent observer.",
                       "Only default-mode owned native EXE/static callbacks are tested; modern WINXP app mode and mapped application graph remain pending."]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", required=True, type=Path)
    args = parser.parse_args()
    try:
        outcome = review(args.run)
    except (OSError, ValueError, KeyError, TypeError, UnicodeError) as error:
        outcome = {"status": "FAIL_NATIVE_EVIDENCE_NOT_ESTABLISHED", "error": str(error),
                   "application_success": False, "production_loader_integration_accepted": False}
    print(json.dumps(outcome, indent=2))
    return 0 if outcome["status"] == "PASS_BOUNDED_NATIVE_EXIT_NOTIFICATION" else 1


if __name__ == "__main__":
    raise SystemExit(main())
