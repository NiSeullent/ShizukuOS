#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only acceptance of fresh, stopped Win98 numeric WAMR component evidence."""
import argparse
import json
from pathlib import Path

from wasm_native_log import PREFIX, component, observer
from wasm_native_stage_evidence import BOOT_BUILD, OUTPUTS, PROFILE, check_stage, read
from verify_trident_automation_native import (EvidenceError, need, receipt,
    records, local, pin, sha)


def verify(run_path, run_sha, manifest_path, manifest_sha, harness_sha, build_pins, provenance_sha):
    run_path, manifest_path = Path(run_path).absolute(), Path(manifest_path).absolute()
    run_dir = run_path.parent
    need(run_path.name == "result.json" and run_dir.parent == BOOT_BUILD / "shizukudos/csm" and
         run_dir.name.startswith("run-win98-gop-wasm-numeric-5abe-native-"),
         "canonical dedicated owned numeric run required")
    builds, inputs, host_raw, merged, checked = check_stage(manifest_path, manifest_sha, build_pins, provenance_sha)
    manifest = receipt(manifest_path, manifest_sha, 65536)
    run = receipt(run_path, run_sha, 16 << 20)
    need(run.get("profile") == "actual-win98-uefi-csmwrap" and
         run.get("status") in {"PASS", "NEEDS-VISUAL-REVIEW"} and
         not run.get("runtime_failure") and not run.get("error"), "actual native harness failed")
    need(run.get("originals_unchanged") is True and run.get("prepared_source_unchanged") is True and
         type(run.get("qemu_exit_code")) is int and run["qemu_exit_code"] == 0 and
         run.get("manual_finish_requested") is True, "private native run not normally stopped/preserved")
    snapshot = local(run.get("source_snapshot"), run_dir)
    need(snapshot.name == "runner-source.py" and sha(read(snapshot, 16 << 20)) ==
         pin(harness_sha, "harness") == run.get("source_sha256"), "approved harness bytes differ")
    native_checked = {str(snapshot): (harness_sha, 16 << 20)}
    hardware = run.get("hardware", {})
    need(hardware.get("run_name") == run_dir.name and hardware.get("network") == "none" and
         hardware.get("accel") == "kvm" and type(hardware.get("memory")) is int and hardware["memory"] == 128 and
         type(hardware.get("smp")) is int and hardware["smp"] == 2 and
         type(hardware.get("reserve_gib")) is int and hardware["reserve_gib"] == 20 and
         hardware.get("manual_gui") is True and hardware.get("firmware_gop") is True and
         run.get("firmware_gop_opt_in") is True and
         run.get("prepared_reuse", {}).get("method", "").startswith(
             "verified private sparse post-run disk copy; cold hardware"), "wrong cold/offline GOP hardware")
    files = run.get("guest_files", {})
    immutable = {str(manifest_path): manifest_sha} | {r["source"]: r["sha256"] for r in inputs.values()} | {
        r["path"]: r["sha256"] for r in manifest["source_receipts"]}
    need(files.get("manifest") == str(manifest_path) and files.get("manifest_sha256") == manifest_sha and
         files.get("immutable_sources_unchanged") is True and files.get("immutable_sources") == immutable and
         files.get("output_baseline") == "all absent before private injection" and
         files.get("outputs") == manifest["outputs"], "native staging stale or changed")
    copied = records(files.get("inputs"), {PREFIX + n for n in inputs})
    for guest, row in copied.items():
        original = inputs[guest[len(PREFIX):]]
        prepared = run_dir / ("prepared-guest-" + guest[len(PREFIX):])
        need(all(row.get(k) == original[k] for k in ("guest", "source", "bytes", "sha256")) and
             row.get("private_copy_sha256") == original["sha256"] and
             sha(read(prepared, 1 << 20)) == original["sha256"],
             "actual prepared guest PE changed")
        native_checked[str(prepared)] = (original["sha256"], 1 << 20)
    readback = records(files.get("readback"), {PREFIX + n for n in OUTPUTS})
    logs = {}
    for guest, row in readback.items():
        name = guest[len(PREFIX):]
        path = local(row.get("path"), run_dir)
        data = read(path, 65536)
        need(path.name == "guest-output-" + name and row.get("status") == "captured" and
             row.get("freshness") == "new-in-owned-run" and type(row.get("bytes")) is int and
             row["bytes"] == len(data) and row.get("sha256") == sha(data), "missing/stale/changed actual readback")
        logs[name] = data
        native_checked[str(path)] = (sha(data), 65536)
    need(logs["WAOUT.LOG"] == b"", "unexpected GUI numeric stdout diagnostic")
    pid = observer(logs["WARUN.LOG"], manifest["nonce"])
    measured = component(logs["WA13.LOG"], manifest["nonce"], host_raw)
    # Do not accept a source/provenance change during potentially slow readback.
    _, final_inputs, final_host, final_sources, final_checked = check_stage(manifest_path, manifest_sha, build_pins, provenance_sha)
    need((inputs, host_raw, merged, checked) == (final_inputs, final_host, final_sources, final_checked),
         "stage generation drift during native acceptance")
    for path, (expected, limit) in native_checked.items():
        need(sha(read(Path(path), limit)) == expected,
             "native file drift during final stage replay: " + path)
    need(sha(read(run_path, 16 << 20)) == run_sha, "harness receipt drift during acceptance")
    return dict(schema="win98modern.wamr-native-numeric-component.v1", passed=True,
        harness_result_sha256=run_sha, manifest_sha256=manifest_sha, harness_source_sha256=harness_sha,
        stage_provenance_sha256=provenance_sha,
        approved_build_sha256=build_pins, source_sha256=merged, checked_stage_sha256=checked,
        checked_native_file_sha256={p: h for p, (h, _) in native_checked.items()},
        input_sha256={n: r["sha256"] for n, r in inputs.items()},
        log_sha256={n: sha(raw) for n, raw in logs.items()}, observations=measured,
        actual_owned_child=dict(pid=pid, exit_code=0, stdout_flushed=True, handles_closed=True),
        actual_supervisor_exit_verified=False, supervisor_requested_exit_code=0,
        native_numeric_component_execution_verified=True, native_paint_verified=False,
        full_modern_wasm_verified=False, browser_webassembly_verified=False,
        standard_browser_navigation_verified=False, full_html5_verified=False,
        full_javascript_verified=False, full_css_verified=False, webgpu_verified=False,
        webgl_verified=False, modern_apps_verified=False, user_objective_complete=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run-result", "manifest"):
        parser.add_argument("--" + name, required=True, type=Path)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--harness-sha256", required=True)
    parser.add_argument("--stage-provenance-sha256", required=True)
    for name in ("runtime", "probe", "observer"):
        parser.add_argument("--" + name + "-build-sha256", required=True)
    args = parser.parse_args()
    try:
        result = verify(args.run_result, args.run_result_sha256, args.manifest, args.manifest_sha256,
            args.harness_sha256, {name + "-build.json": getattr(args, name + "_build_sha256")
                for name in ("runtime", "probe", "observer")}, args.stage_provenance_sha256)
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps(dict(passed=False, native_numeric_component_execution_verified=False,
                              actual_supervisor_exit_verified=False, error=str(error))))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
