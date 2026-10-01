#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only verification of frozen, stopped Win98 MSHTML component evidence.

Caller-approved build/harness hashes establish source provenance. GUI input and
paint are pending unless a separately trusted manual review binds actual QEMU
action records and reviewed captures. No VM, screenshot inference or web claim.
"""
from pathlib import Path
import argparse
import hashlib
import json
import math
import os
import re
import stat

PREFIX = "C:\\GOPLAB\\"
INPUTS = {"M98AUTPR.EXE", "M98QJS.DLL", "M98AURUN.EXE"}
OUTPUTS = {"AUT13.LOG", "AURUN.LOG", "AUOUT.LOG"}
RECEIPTS = {"automation-build.json", "runtime-build.json", "observer-build.json"}
AUTOMATION_SOURCES = {
    "src/m98_trident_automation.h", "src/m98_trident_automation.cpp",
    "src/m98_trident_automation_HANDOFF.md", "src/m98_trident_script.h",
    "tests/m98_trident_automation_host.cpp", "tests/m98_trident_automation_mock.h",
    "tests/m98_trident_automation_guest.cpp", "tools/build_trident_automation.py",
    "platform/freestanding/memory.c", "platform/freestanding/memory.h",
    "benchmarks/win98se-ko-oem-native-exports-v1.json"}
OBSERVER_SOURCES = {"tests/m98_trident_guest_runner.c", "tests/m98_trident_guest_runner_mock.c",
    "tests/m98_tls13_guest_runner_mock.h", "tools/build_trident_guest_runner.py",
    "benchmarks/win98se-ko-oem-native-exports-v1.json"}
RUNTIME_SOURCES = {"src/m98_trident_script.h", "src/m98_trident_script.c",
    "src/m98_trident_script_win32.c", "src/m98_trident_script.def",
    "src/m98_trident_script_port.h", "src/m98_trident_script_port.c", "src/m98_trident_script_fp.c",
    "src/m98_trident_script_HANDOFF.md", "tests/m98_trident_script_host.c",
    "tests/m98_trident_script_guest.c", "tests/m98_trident_script_platform_host.c",
    "tests/m98_trident_script_port_host.c", "tests/m98_trident_script_win32_mock.c",
    "tests/m98_trident_script_win32_mock.h", "tests/m98_trident_script_sanitizer_fault.c",
    "tests/trident_es2026_selected.js",
    "tests/trident_numeric_selected.js", "tools/build_trident_script.py",
    "benchmarks/win98se-ko-oem-native-exports-v1.json"}
RUNTIME_EXPORTS = {"m98_script_open", "m98_script_bind_root", "m98_script_eval",
    "m98_script_invoke", "m98_script_invoke_this", "m98_script_jobs",
    "m98_script_release_result", "m98_script_info", "m98_script_close"}
CHECKS = {
    "NATIVE_WIN98_SE", "KOREAN_ACP949", "EXACT_ADJACENT_RUNTIME", "VISIBLE_NATIVE_HOST",
    "ACTUAL_SYSTEM_MSHTML_MODULE", "HTML_SAFEARRAY", "REAL_INTERPRETER_OPEN",
    "GENUINE_DOCUMENT_ROOT_BIND", "MODERN_SYNTAX_EXECUTED", "REAL_PROMISE_JOBS",
    "PROMISE_RESULT_STATE", "INDEPENDENT_TYPED_MSHTML_PROMISE_TEXT",
    "NONEMPTY_ACTUAL_INPUT_MATCHES_JS_THIS_VALUE", "UI_THREAD_KEYUP_OBSERVED",
    "QUEUED_JS_INPUT_CALLBACK", "UI_EVENT_COMPLETED", "REAL_INTERPRETER_CLOSE",
    "CLIENT_SITE_REFS_RELEASED", "RUNTIME_MODULE_RELEASE"}
HRESULTS = {
    "COM_STA_INITIALIZE", "ACTUAL_MSHTML_CREATE", "MSHTML_OLE_OBJECT", "MSHTML_CLIENT_SITE",
    "MSHTML_PERSIST_INIT_INTERFACE", "MSHTML_INIT_NEW", "GENUINE_VIEW_INPLACE_ACTIVATE",
    "GENUINE_DOCUMENT_WRITE", "GENUINE_DOCUMENT_CLOSE", "INDEPENDENT_DOCUMENT3_INTERFACE",
    "AUTOMATION_OPEN", "ACTUAL_DOCUMENT_CANONICAL_ATTACH", "SCRIPT_HOST_TABLE",
    "INDEPENDENT_TYPED_INPUT_VALUE_AND_FULL_STATUS", "AUTOMATION_CLOSE_BEFORE_SCRIPT",
    "VIEW_UI_DEACTIVATE", "VIEW_HIDE", "VIEW_CLOSE", "VIEW_DETACH_SITE",
    "MSHTML_OLE_CLOSE", "MSHTML_DETACH_SITE"}
FIXED = {"PROFILE": "genuine-mshtml-direct-host-v1",
    "EXE_MODULE": PREFIX + "M98AUTPR.EXE", "RUNTIME_MODULE": PREFIX + "M98QJS.DLL",
    "ADAPTER": "statically embedded actual adapter source; not a DOM double",
    "BROWSER_INTEGRATION": "not tested; no global script selection/registration",
    "OS_PLATFORM": "1", "OS_MAJOR": "4", "OS_MINOR": "10", "OS_BUILD_LOW": "2222", "ACP": "949",
    "REAL_INPUT_PENDING": "Click genuine MSHTML input and type; no input/event synthesis exists in fixture",
    "EXTERNAL_INPUT_REVIEW_REQUIRED": "WM_KEYUP and COM event observations alone do not prove physical or QEMU GUI input",
    "VISUAL_REVIEW_REQUIRED": "Korean mutation must be visibly reviewed in genuine MSHTML; log is not pixel proof",
    "FAILURES": "0", "STATUS": "PASS_COMPONENT_ONLY", "SYSTEM_WEB_STANDARDS": "not certified",
    "HTML5_LAYOUT_WASM": "not implemented by this adapter"}


class EvidenceError(ValueError):
    pass


def need(condition, reason):
    if not condition:
        raise EvidenceError(reason)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(value, name):
    need(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), f"invalid {name} SHA256 pin")
    return value


def read(path, limit=4 << 20):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, f"noncanonical/symlink evidence: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= limit,
             f"unbounded/nonregular evidence: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        need(len(data) == before.st_size and all(getattr(before, k) == getattr(after, k) for k in fields),
             f"evidence changed while reading: {path}")
        return data
    finally:
        os.close(fd)


def unique(items):
    result = {}
    for key, value in items:
        need(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def receipt(path, expected, limit=1 << 20):
    data = read(path, limit)
    need(sha(data) == pin(expected, "receipt"), f"frozen receipt changed: {path}")
    value = json.loads(data, object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("nonfinite JSON number")))
    need(isinstance(value, dict), "receipt must be a JSON object")
    return value


def local(value, parent):
    need(isinstance(value, str), "evidence path must be a string")
    path = Path(value)
    need(path.is_absolute() and path.parent == parent and path.name not in {"", ".", ".."},
         f"evidence escapes its exact owned directory: {path}")
    return path


def records(items, names, key="guest"):
    need(isinstance(items, list) and len(items) == len(names), "record count differs from approved scope")
    result = {}
    for row in items:
        need(isinstance(row, dict) and isinstance(row.get(key), str), "malformed evidence record")
        name = row[key]
        need(name in names and name not in result, "unexpected/duplicate evidence record")
        result[name] = row
    need(set(result) == names, "incomplete approved evidence set")
    return result


def uint(value, title, positive=False):
    need(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,9}", value), f"invalid {title}")
    number = int(value)
    need(number <= 0xffffffff and (number > 0 or not positive), f"out-of-range {title}")
    return number


def pairs(raw, allow_events=False):
    need(raw and len(raw) <= 65536 and raw.endswith(b"\r\n"), "empty/large/partial native log")
    try:
        lines = raw[:-2].decode("ascii").split("\r\n")
    except UnicodeError as error:
        raise EvidenceError("native success log is not ASCII") from error
    result, events = {}, 0
    for line in lines:
        need("=" in line and "\r" not in line and "\n" not in line and len(line) <= 512,
             "malformed native log line")
        key, value = line.split("=", 1)
        if allow_events and key == "EVENT_EXECUTED_OUTSIDE_COM":
            need(value == "PASS", "queued event failed")
            events += 1
        else:
            need(key and key not in result, f"duplicate native log key: {key}")
            result[key] = value
    return result, events


def component(raw):
    fields, events = pairs(raw, True)
    counts = {"OBSERVED_UI_KEYUPS", "EXECUTED_QUEUED_CALLBACKS"}
    need(set(fields) == set(FIXED) | CHECKS | HRESULTS | counts | {"MSHTML_MODULE"},
         "native component log is stale/partial or has unexpected diagnostics")
    need(all(fields[k] == v for k, v in FIXED.items()) and all(fields[k] == "PASS" for k in CHECKS),
         "native MSHTML/JS/Promise/input-value/teardown component checks failed")
    for key in HRESULTS:
        need(re.fullmatch(r"[0-9a-f]{8}", fields[key]) and int(fields[key], 16) < 0x80000000,
             f"native HRESULT failure: {key}")
    need(re.fullmatch(r"[A-Za-z]:\\[A-Za-z0-9 _-]{1,64}\\SYSTEM\\MSHTML\.DLL", fields["MSHTML_MODULE"], re.I),
         "native system MSHTML path is malformed")
    keyups = uint(fields["OBSERVED_UI_KEYUPS"], "UI key-up count", True)
    callbacks = uint(fields["EXECUTED_QUEUED_CALLBACKS"], "queued callback count", True)
    need(events == callbacks, "queued callback evidence is partial or duplicated")
    return {"ui_keyups": keyups, "queued_callbacks": callbacks,
            "mshtml_module": fields["MSHTML_MODULE"]}


def observer(raw, nonce):
    fields, _ = pairs(raw)
    expected = {"scope": "actual-win98-trident-owned-child-observer", "nonce": nonce,
        "profile": "genuine-mshtml-direct-host", "WIN98_IDENTIFIED": "1", "os.major": "4",
        "os.minor": "10", "os.build-low": "2222", "os.platform": "1",
        "child.path": PREFIX + "M98AUTPR.EXE", "child.stdout": PREFIX + "AUOUT.LOG",
        "child.created": "1", "child.create-error": "0", "child.wait": "0", "child.exit-query": "1",
        "child.exit-query-error": "0", "child.exit-code": "0", "child.stdout-flushed": "1",
        "child.handles-closed": "1", "child.success": "1", "supervisor.requested-exit-code": "0"}
    need(set(fields) == set(expected) | {"child.pid"} and all(fields[k] == v for k, v in expected.items()),
         "observer lacks actual owned child exit zero and complete flush/close")
    return uint(fields["child.pid"], "actual child PID", True)


def sources(build, expected, directory, merged):
    hashes = build.get("source_sha256")
    need(isinstance(hashes, dict) and 1 <= len(hashes) <= 128, "build source pin set missing/unbounded")
    need(set(hashes) == expected, "build source profile differs from approved component")
    for name, digest in hashes.items():
        need(isinstance(name, str) and re.fullmatch(r"[A-Za-z0-9_./-]{1,200}", name) and
             not Path(name).is_absolute() and all(part not in {"", ".", ".."} for part in name.split("/")),
             "build source path escapes approved snapshot")
        pin(digest, "source")
        need(name not in merged or merged[name] == digest, "conflicting source generations across components")
        merged[name] = digest
        path = directory / name
        need(sha(read(path, 8 << 20)) == digest, f"frozen source snapshot changed: {name}")


def prepared_sources(runtime, directory):
    """Never read the original absolute build paths named by the receipt."""
    hashes = runtime.get("prepared_sha256")
    need(isinstance(hashes, dict) and 1 <= len(hashes) <= 128,
         "approved interpreter prepared source pins missing/unbounded")
    result, roots = {}, set()
    for original, digest in hashes.items():
        need(isinstance(original, str) and original.startswith("/") and original.count("/prepared/") == 1,
             "unsupported interpreter prepared source path")
        root, name = original.split("/prepared/", 1)
        need(re.fullmatch(r"(?:quickjs|math)/[A-Za-z0-9_./-]{1,180}", name) and
             all(part not in {"", ".", ".."} for part in name.split("/")) and name not in result,
             "prepared source path escapes approved snapshot")
        roots.add(root)
        pin(digest, "interpreter prepared source")
        need(sha(read(directory / name, 8 << 20)) == digest, f"frozen interpreter source changed: {name}")
        result[name] = digest
    need(len(roots) == 1 and "quickjs/quickjs.c" in result and
         any(name.startswith("math/src/math/") for name in result),
         "interpreter prepared sources lack one coherent real-engine/math generation")
    return result


def build_logs(build, directory):
    steps = build.get("steps")
    need(isinstance(steps, list) and 1 <= len(steps) <= 256,
         "approved successful build-step evidence missing/unbounded")
    result = {}
    for step in steps:
        need(isinstance(step, dict) and type(step.get("returncode")) is int and step["returncode"] == 0,
             "approved build contains an unsuccessful/unchecked step")
        original = step.get("log")
        need(isinstance(original, str) and Path(original).is_absolute(), "unsupported build-step log path")
        name = Path(original).name
        need(re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.(?:txt|log)", name) and name not in result,
             "ambiguous/unsafe build-step log filename")
        digest = pin(step.get("sha256"), "build-step log")
        need(sha(read(directory / name, 8 << 20)) == digest, f"frozen build-step log changed: {name}")
        result[name] = digest
    return result


def artifact(build, name, row, stack_commit):
    artifacts = build.get("artifacts")
    need(isinstance(artifacts, dict) and isinstance(artifacts.get(name), dict), "missing approved build artifact")
    item = artifacts[name]
    count = item.get("size", item.get("bytes"))
    need(type(count) is int and count == row["bytes"] and item.get("sha256") == row["sha256"] and
         item.get("pe98_gate") == "pass", "staged artifact differs from approved PE build")
    need(type(item.get("stack_reserve")) is int and item["stack_reserve"] == 2097152 and
         type(item.get("stack_commit")) is int and item["stack_commit"] >= stack_commit and
         item["stack_commit"] <= item["stack_reserve"], "approved native stack bound is missing")
    return item


def runtime_instructions(item):
    gate = item.get("i486_instructions")
    need(isinstance(gate, dict) and set(gate) == {"instructions_decoded", "post_i486_families"} and
         type(gate.get("instructions_decoded")) is int and 0 < gate["instructions_decoded"] <= 1048576 and
         gate.get("post_i486_families") == "absent", "approved runtime instruction gate evidence missing")
    return gate["instructions_decoded"]


def visual_review(path, expected_sha, run, run_sha, manifest_sha, inputs, captures):
    review = receipt(path, expected_sha, 65536)
    need(review.get("schema") == "win98modern.trident-automation-input-visual-review.v1" and
         review.get("harness_result_sha256") == run_sha and review.get("manifest_sha256") == manifest_sha,
         "trusted input/paint review binds another run")
    need(review.get("input_sha256") == {name: row["sha256"] for name, row in inputs.items()},
         "trusted review binds different component binaries")
    need(review.get("genuine_mshtml_paint_verified") is True and review.get("qemu_gui_input_verified") is True,
         "trusted observed paint and GUI input review missing")
    need(review.get("standard_browser_integration_verified") is False and review.get("full_web_standards_verified") is False and
         review.get("modern_apps_verified") is False and
         all(review.get(key, False) is False for key in ("modern_css_verified", "webgpu_verified", "webgl_verified")),
         "trusted review exceeds component scope")
    actions = run.get("gui_interaction", {}).get("actions")
    need(isinstance(actions, list) and 1 <= len(actions) <= 128, "actual QEMU action records missing/unbounded")
    last_sequence = 0
    for item in actions:
        need(isinstance(item, dict) and type(item.get("sequence")) is int and
             item["sequence"] == last_sequence + 1, "QEMU action sequence is malformed/ambiguous/incomplete")
        last_sequence = item["sequence"]
    action_bytes = json.dumps(actions, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode()
    need(review.get("gui_actions_sha256") == sha(action_bytes), "trusted action review changed")
    sequence = review.get("input_action_sequence")
    need(type(sequence) is int and sequence > 0, "trusted input action identity missing")
    selected = [a for a in actions if a["sequence"] == sequence]
    need(len(selected) == 1, "input action is absent or ambiguous")
    action = selected[0]
    need(isinstance(action.get("typed"), str) and 0 < len(action["typed"]) <= 256 and
         all(32 <= ord(c) <= 126 for c in action["typed"]) and
         action.get("status") == "sent; application effect requires screenshot/readback verification",
         "unsupported/unconfirmed QEMU input action format; use component-only verification")
    need(action["typed"] == review.get("reviewed_typed_input"), "manual review describes different sent input")
    need(isinstance(review.get("manual_review"), str) and 0 < len(review["manual_review"].strip()) <= 4096,
         "manual input/paint review description missing")
    frames = review.get("frames")
    need(isinstance(frames, dict) and set(frames) == {"focused_input", "korean_after_input"},
         "reviewed focused-input and resulting Korean frames required")
    result, times, hashes = {}, [], set()
    for role in ("focused_input", "korean_after_input"):
        frame = frames[role]
        need(isinstance(frame, dict), "malformed frame review")
        capture_path = local(frame.get("path"), Path(run["source_snapshot"]).parent)
        need(capture_path.suffix.lower() == ".png", "reviewed capture is not a PNG artifact")
        digest = sha(read(capture_path, 16 << 20))
        need(digest == pin(frame.get("sha256"), "reviewed frame") and digest not in hashes,
             "reviewed frame changed or identical frames reused")
        hashes.add(digest)
        matching = [c for c in captures if isinstance(c, dict) and c.get("screenshot") == str(capture_path)]
        need(len(matching) == 1 and matching[0].get("sha256") == digest and
             matching[0].get("screenshot_status") == "captured" and matching[0].get("seconds") == frame.get("seconds"),
             "reviewed frame does not match an actual harness capture")
        seconds = frame.get("seconds")
        need(type(seconds) in {int, float} and math.isfinite(seconds) and seconds >= 0,
             "invalid reviewed capture time")
        description = frame.get("visual_review")
        need(isinstance(description, str) and 0 < len(description.strip()) <= 4096, "painted-content review missing")
        times.append(seconds)
        result[role] = {"path": str(capture_path), "sha256": digest, "manual_review": description}
    action_time = action.get("seconds")
    need(type(action_time) in {int, float} and math.isfinite(action_time) and times[0] <= action_time < times[1],
         "reviewed frames do not bracket actual sent input")
    return {"trusted_review_sha256": expected_sha, "gui_actions_sha256": sha(action_bytes),
            "input_action_sequence": sequence, "frames": result,
            "trust": "caller-approved manual action/effect/paint review; no automatic pixel/input assertion"}


def verify(run_path, run_sha, manifest_path, manifest_sha, harness_sha, build_pins,
           review_path=None, review_sha=None):
    run_path, manifest_path = Path(run_path).absolute(), Path(manifest_path).absolute()
    run_dir, stage = run_path.parent, manifest_path.parent
    run = receipt(run_path, run_sha, 16 << 20)
    manifest = receipt(manifest_path, manifest_sha, 65536)
    need(type(manifest.get("schema")) is int and manifest["schema"] == 1 and
         manifest.get("kind") == "isolated-guest-file-inputs", "unsupported frozen manifest schema/kind")
    nonce = manifest.get("nonce")
    need(isinstance(nonce, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", nonce),
         "empty/unbounded native trial nonce")
    need(manifest.get("command") == PREFIX + "M98AURUN.EXE" and manifest.get("network_required") is False,
         "manifest is not the offline Automation observer")
    need(isinstance(manifest.get("outputs"), list) and len(manifest["outputs"]) == 3 and
         set(manifest["outputs"]) == {PREFIX + name for name in OUTPUTS}, "unexpected native output plan")
    inputs_by_guest = records(manifest.get("inputs"), {PREFIX + name for name in INPUTS})
    inputs = {}
    for guest, row in inputs_by_guest.items():
        name = guest[len(PREFIX):]
        path = local(row.get("source"), stage)
        need(path.name == name, "staged input filename differs from guest destination")
        data = read(path)
        need(type(row.get("bytes")) is int and row["bytes"] == len(data) and 0 < len(data) <= 1048576 and
             sha(data) == pin(row.get("sha256"), "guest input"), "frozen staged input changed")
        inputs[name] = row
    need(isinstance(build_pins, dict) and set(build_pins) == RECEIPTS, "three caller-approved build hashes required")
    receipt_rows = records(manifest.get("source_receipts"), {str(stage / n) for n in RECEIPTS}, "path")
    builds, merged = {}, {}
    pinned_logs = {}
    for name in sorted(RECEIPTS):
        row = receipt_rows[str(stage / name)]
        need(row.get("sha256") == pin(build_pins[name], name), "manifest uses unapproved build receipt")
        builds[name] = receipt(local(row["path"], stage), build_pins[name])
        need(builds[name].get("passed") is True, "approved build is failed")
        if name != "runtime-build.json":
            need(type(builds[name].get("schema")) is int and builds[name]["schema"] == 1,
                 "unsupported component build schema")
        role = name.removesuffix("-build.json")
        pinned_logs[role] = build_logs(builds[name], stage / "build-logs" / role)
    automation, runtime, observed = (builds[n] for n in ("automation-build.json", "runtime-build.json", "observer-build.json"))
    need(automation.get("kind") == "genuine-mshtml-automation-component-build" and
         observed.get("kind") == "win98-trident-owned-child-observer-build" and observed.get("nonce") == nonce,
         "approved component/observer build identity differs")
    need(runtime.get("profile") == "bounded-local-trident-quickjs-v1",
         "unsupported approved runtime build profile")
    sources(automation, AUTOMATION_SOURCES, stage / "source", merged)
    sources(observed, OBSERVER_SOURCES, stage / "source", merged)
    sources(runtime, RUNTIME_SOURCES, stage / "source", merged)
    prepared = prepared_sources(runtime, stage / "runtime-prepared")
    need(sha(read(stage / "runtime-selected.h", 65536)) ==
         pin(runtime.get("embedded_fixture_header_sha256"), "runtime generated selected fixture header"),
         "frozen runtime generated selected fixture header changed")
    fixture = artifact(automation, "M98AUTPR.EXE", inputs["M98AUTPR.EXE"], 524288)
    observer_gate = artifact(observed, "M98AURUN.EXE", inputs["M98AURUN.EXE"], 65536)
    runtime_gate = artifact(runtime, "M98QJS.DLL", inputs["M98QJS.DLL"], 524288)
    need(fixture.get("adapter") == "statically embedded" and observer_gate.get("i486_instruction_gate") == "pass",
         "approved native fixture/observer gate differs")
    need(isinstance(runtime_gate.get("exports"), list) and len(runtime_gate["exports"]) == 9 and
         set(runtime_gate["exports"]) == RUNTIME_EXPORTS, "runtime lacks exact nine invoke_this ABI exports")
    runtime_instructions(runtime_gate)
    profile = observed.get("profiles", {}).get("automation")
    need(isinstance(profile, dict) and all(profile.get(k) == v for k, v in {
        "self": PREFIX + "M98AURUN.EXE", "supervisor_log": PREFIX + "AURUN.LOG",
        "child_stdout": PREFIX + "AUOUT.LOG", "child": PREFIX + "M98AUTPR.EXE", "child_log": PREFIX + "AUT13.LOG",
        "child_timeout_ms": 240000, "reap_timeout_ms": 5000}.items()), "observer child/path/deadline profile differs")
    need(run.get("profile") == "actual-win98-uefi-csmwrap" and run.get("status") in {"PASS", "NEEDS-VISUAL-REVIEW"} and
         not run.get("runtime_failure") and not run.get("error"), "native harness failed")
    need(run.get("originals_unchanged") is True and run.get("prepared_source_unchanged") is True and
         type(run.get("qemu_exit_code")) is int and run["qemu_exit_code"] == 0 and run.get("manual_finish_requested") is True,
         "owned native run is not normally stopped/preserved")
    source = local(run.get("source_snapshot"), run_dir)
    need(source.name == "runner-source.py" and sha(read(source)) == pin(harness_sha, "harness") == run.get("source_sha256"),
         "approved harness source snapshot differs")
    hardware = run.get("hardware", {})
    need(hardware.get("run_name") == run_dir.name and hardware.get("network") == "none" and
         hardware.get("accel") == "kvm" and type(hardware.get("memory")) is int and hardware["memory"] == 128 and
         type(hardware.get("smp")) is int and hardware["smp"] == 2 and
         type(hardware.get("reserve_gib")) is int and hardware["reserve_gib"] == 20 and hardware.get("manual_gui") is True and
         hardware.get("firmware_gop") is True and run.get("firmware_gop_opt_in") is True,
         "native cold GOP/offline hardware profile differs")
    need(run.get("prepared_reuse", {}).get("method", "").startswith("verified private sparse post-run disk copy; cold hardware"),
         "verified private cold clone profile missing")
    files = run.get("guest_files", {})
    need(files.get("manifest") == str(manifest_path) and files.get("manifest_sha256") == manifest_sha and
         files.get("immutable_sources_unchanged") is True and files.get("output_baseline") == "all absent before private injection",
         "native staging differs, is stale, or changed")
    immutable = {str(manifest_path): manifest_sha} | {r["source"]: r["sha256"] for r in inputs.values()} | {
        r["path"]: r["sha256"] for r in receipt_rows.values()}
    need(files.get("immutable_sources") == immutable and files.get("outputs") == manifest["outputs"],
         "native immutable input/receipt/output set differs")
    copied = records(files.get("inputs"), set(inputs_by_guest))
    for guest, row in copied.items():
        original = inputs_by_guest[guest]
        need(all(row.get(k) == original[k] for k in ("guest", "source", "bytes", "sha256")) and
             row.get("private_copy_sha256") == original["sha256"] and
             sha(read(run_dir / ("prepared-guest-" + guest[len(PREFIX):]))) == original["sha256"],
             "private prepared guest input differs")
    readback = records(files.get("readback"), {PREFIX + n for n in OUTPUTS})
    logs = {}
    for guest, row in readback.items():
        name = guest[len(PREFIX):]
        path = local(row.get("path"), run_dir)
        need(path.name == "guest-output-" + name, "different stopped collector output path")
        data = read(path, 65536)
        need(row.get("status") == "captured" and row.get("freshness") == "new-in-owned-run" and
             type(row.get("bytes")) is int and row["bytes"] == len(data) and row.get("sha256") == sha(data),
             "missing/stale/changed native readback")
        logs[name] = data
    need(logs["AUOUT.LOG"] == b"", "unexpected inherited stdout diagnostics from GUI fixture")
    pid = observer(logs["AURUN.LOG"], nonce)
    observed_component = component(logs["AUT13.LOG"])
    need((review_path is None) == (review_sha is None), "review path and caller hash must be supplied together")
    reviewed = None
    if review_path is not None:
        reviewed = visual_review(Path(review_path).absolute(), pin(review_sha, "trusted review"), run,
                                 run_sha, manifest_sha, inputs, run.get("captures", []))
    return {"schema": "win98modern.trident-automation-native-component.v1", "passed": True,
        "scope": "actual MSHTML/modern JS component, typed DOM/Promise/event/teardown and owned child completion",
        "nonce": nonce, "harness_result_sha256": run_sha, "manifest_sha256": manifest_sha,
        "harness_source_sha256": harness_sha, "approved_build_sha256": build_pins,
        "source_sha256": merged, "runtime_prepared_sha256": prepared, "build_log_sha256": pinned_logs,
        "input_sha256": {n: r["sha256"] for n, r in inputs.items()},
        "log_sha256": {n: sha(data) for n, data in logs.items()},
        "actual_owned_child": {"pid": pid, "exit_code": 0, "stdout_flushed": True, "handles_closed": True},
        "supervisor_requested_exit_code": 0, "actual_supervisor_exit_verified": False,
        "native_component_execution_verified": True, "native_observations": observed_component,
        "real_gui_input_verified": reviewed is not None, "genuine_mshtml_paint_verified": reviewed is not None,
        "trusted_input_paint_review": reviewed, "visual_content_automatically_asserted": False,
        "source_semantics_trust": "caller-approved frozen builds/harness; verifier binds bytes, not production semantics",
        "standard_browser_navigation_verified": False, "full_html5_verified": False,
        "webassembly_verified": False, "es2026_conformance_verified": False, "modern_css_verified": False,
        "webgpu_verified": False, "webgl_verified": False, "modern_apps_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-result", required=True, type=Path)
    parser.add_argument("--run-result-sha256", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--harness-sha256", required=True)
    for role in ("automation", "runtime", "observer"):
        parser.add_argument(f"--{role}-build-sha256", required=True)
    parser.add_argument("--trusted-input-visual-review", type=Path)
    parser.add_argument("--trusted-input-visual-review-sha256")
    args = parser.parse_args()
    try:
        result = verify(args.run_result, args.run_result_sha256, args.manifest, args.manifest_sha256,
            args.harness_sha256, {f"{role}-build.json": getattr(args, f"{role}_build_sha256")
                for role in ("automation", "runtime", "observer")},
            args.trusted_input_visual_review, args.trusted_input_visual_review_sha256)
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps({"passed": False, "native_component_execution_verified": False,
            "real_gui_input_verified": False, "genuine_mshtml_paint_verified": False, "error": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
