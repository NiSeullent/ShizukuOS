#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read-only frozen genuine-MSHTML CSS component acceptance; no full CSS claim."""
import argparse
import hashlib
import json
import math
from pathlib import Path

from build_css_mshtml_fixture import SOURCES as FIXTURE_SOURCES
from build_css_mshtml_runner import SOURCES as OBSERVER_SOURCES
from css_mshtml_native_log import PREFIX, component, observer
from stage_css_mshtml_native import PROFILE
from verify_trident_automation_native import (EvidenceError, need, read, receipt, records,
    sources, build_logs, artifact, local, pin, sha)

INPUTS = {"M98CSS.DLL", "CSS13PR.EXE", "M98CSR.EXE"}
OUTPUTS = {"CSS13.LOG", "CSRUN.LOG", "CSOUT.LOG"}
RECEIPTS = {"core-build.json", "fixture-build.json", "observer-build.json"}
BOOT_BUILD = Path("/root/Win98-Modern-boot/build")


def verify(run_path, run_sha, manifest_path, manifest_sha, harness_sha, build_pins,
           review_path=None, review_sha=None):
    run_path, manifest_path = Path(run_path).absolute(), Path(manifest_path).absolute()
    run_dir, stage = run_path.parent, manifest_path.parent
    need(stage.parent == BOOT_BUILD, "canonical boot stage required")
    run = receipt(run_path, run_sha, 16 << 20)
    manifest = receipt(manifest_path, manifest_sha, 65536)
    need(type(manifest.get("schema")) is int and manifest["schema"] == 1 and
         manifest.get("kind") == "isolated-guest-file-inputs" and
         manifest.get("command") == PROFILE["self"] and manifest.get("network_required") is False,
         "wrong offline CSS native manifest")
    nonce = manifest.get("nonce")
    need(isinstance(nonce, str) and 1 <= len(nonce) <= 64 and
         all(c.isascii() and (c.isalnum() or c in "_-") for c in nonce), "invalid observer nonce")
    need(isinstance(manifest.get("outputs"), list) and len(manifest["outputs"]) == 3 and
         set(manifest["outputs"]) == {PREFIX + n for n in OUTPUTS}, "exact output plan required")
    inputs_by_guest = records(manifest.get("inputs"), {PREFIX + n for n in INPUTS})
    inputs = {}
    for guest, row in inputs_by_guest.items():
        name = guest[len(PREFIX):]
        path = local(row.get("source"), stage)
        data = read(path)
        need(path.name == name and type(row.get("bytes")) is int and
             row["bytes"] == len(data) and 0 < len(data) <= 1048576 and
             sha(data) == pin(row.get("sha256"), "input"), "staged input changed")
        inputs[name] = row
    need(isinstance(build_pins, dict) and set(build_pins) == RECEIPTS,
         "three explicit caller-approved receipt hashes required")
    receipt_rows = records(manifest.get("source_receipts"), {str(stage / n) for n in RECEIPTS}, "path")
    builds, merged, logs = {}, {}, {}
    for name in RECEIPTS:
        row = receipt_rows[str(stage / name)]
        need(row.get("sha256") == pin(build_pins[name], name), "unapproved build receipt")
        build = receipt(stage / name, build_pins[name], 16 << 20)
        need(type(build.get("schema")) is int and build["schema"] == 1 and
             build.get("passed") is True and build.get("native_execution") is False and
             build.get("vm_operations") is False, "wrong build-only receipt")
        role = name.removesuffix("-build.json")
        logs[role] = build_logs(build, stage / "build-logs" / role)
        expected = set(FIXTURE_SOURCES) if role == "fixture" else (
            set(OBSERVER_SOURCES) if role == "observer" else set(build["source_sha256"]))
        sources(build, expected, stage / "source", merged)
        for filename, item in build["artifacts"].items():
            need(Path(filename).name == filename, "canonical artifact member required")
            data = read(stage / "build-artifacts" / role / filename)
            need(type(item.get("size", item.get("bytes"))) is int and
                 len(data) == item.get("size", item.get("bytes")) and sha(data) == item["sha256"],
                 "original frozen build artifact changed")
        builds[name] = build
    core, fixture, observed = (builds[n] for n in ("core-build.json", "fixture-build.json", "observer-build.json"))
    need(core.get("kind") == "current-css-token-and-variable-core-build" and
         core.get("profile") == "current-css-variables-active-fallback-core-v1" and
         fixture.get("kind") == "genuine-mshtml-css-variable-consumer-build" and
         fixture.get("core_receipt_sha256") == build_pins["core-build.json"] and
         fixture.get("core_source_sha256") == core["source_sha256"] and
         observed.get("kind") == "win98-css-owned-child-observer-build" and observed.get("nonce") == nonce,
         "CSS component source generations differ")
    need(all(core.get(k) is False for k in ("foreign_script_execution", "mshtml_style_integration",
        "native_paint", "browser_wpt_pass", "full_modern_css", "full_browser", "wasm", "webgpu",
        "webgl", "modern_apps")) and all(fixture.get(k) is False for k in (
        "native_mshtml_styles", "native_geometry", "native_paint", "actual_child_exit", "full_css",
        "browser_wpt", "full_browser", "wasm", "webgpu", "webgl", "modern_apps")) and
        all(observed.get(k) is False for k in ("native_mshtml_styles", "native_geometry", "native_paint",
        "actual_child_exit", "full_css", "browser_wpt", "webgpu", "webgl", "full_web_standards")),
        "approved builds must retain component-only scope")
    need(all(observed.get("profiles", {}).get("css", {}).get(k) == v for k, v in PROFILE.items()),
         "observer child/path/deadline differs")
    for name, digest in core["generated_sha256"].items():
        need(Path(name).name == name and sha(read(stage / "core-generated" / name)) == digest,
             "frozen generated core changed")
    for role, name, commit in (("core-build.json", "M98CSS.DLL", 524288),
                              ("fixture-build.json", "CSS13PR.EXE", 524288),
                              ("observer-build.json", "M98CSR.EXE", 65536)):
        item = artifact(builds[role], name, inputs[name], commit)
        corrected = (fixture if name == "M98CSS.DLL" else builds[role])["artifacts"][name]
        machine = corrected.get("i486_instructions", {})
        need(corrected.get("sha256") == inputs[name]["sha256"] and
             machine.get("artifact_sha256") == inputs[name]["sha256"] and
             machine.get("parser") == "horizontal-lines-explicit-i486-x87-allowlist-v1" and
             type(machine.get("instructions_decoded")) is int and machine["instructions_decoded"] > 100 and
             machine.get("post_i486_families") == "absent" and machine.get("executable_sections") and
             all(type(s.get("bytes")) is int and s["bytes"] > 0 and s.get("decoded_bytes") == s["bytes"]
                 for s in machine["executable_sections"].values()), "complete corrected i486 gate missing")
    need(run.get("profile") == "actual-win98-uefi-csmwrap" and
         run.get("status") in {"PASS", "NEEDS-VISUAL-REVIEW"} and
         not run.get("runtime_failure") and not run.get("error"), "native harness failed")
    need(run.get("originals_unchanged") is True and run.get("prepared_source_unchanged") is True and
         type(run.get("qemu_exit_code")) is int and run["qemu_exit_code"] == 0 and
         run.get("manual_finish_requested") is True, "owned native run not normally stopped/preserved")
    snapshot = local(run.get("source_snapshot"), run_dir)
    need(snapshot.name == "runner-source.py" and sha(read(snapshot)) ==
         pin(harness_sha, "harness") == run.get("source_sha256"), "approved actual harness source differs")
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
        r["path"]: r["sha256"] for r in receipt_rows.values()}
    need(files.get("manifest") == str(manifest_path) and files.get("manifest_sha256") == manifest_sha and
         files.get("immutable_sources_unchanged") is True and files.get("immutable_sources") == immutable and
         files.get("output_baseline") == "all absent before private injection" and
         files.get("outputs") == manifest["outputs"], "native staging stale or changed")
    copied = records(files.get("inputs"), set(inputs_by_guest))
    for guest, row in copied.items():
        original = inputs_by_guest[guest]
        need(all(row.get(k) == original[k] for k in ("guest", "source", "bytes", "sha256")) and
             row.get("private_copy_sha256") == original["sha256"] and
             sha(read(run_dir / ("prepared-guest-" + guest[len(PREFIX):]))) == original["sha256"],
             "actual prepared guest PE changed")
    readback = records(files.get("readback"), {PREFIX + n for n in OUTPUTS})
    native_logs = {}
    for guest, row in readback.items():
        name = guest[len(PREFIX):]
        path = local(row.get("path"), run_dir)
        data = read(path, 65536)
        need(path.name == "guest-output-" + name and row.get("status") == "captured" and
             row.get("freshness") == "new-in-owned-run" and type(row.get("bytes")) is int and
             row["bytes"] == len(data) and row.get("sha256") == sha(data), "missing/stale/changed actual readback")
        native_logs[name] = data
    need(native_logs["CSOUT.LOG"] == b"", "unexpected GUI fixture stdout diagnostic")
    pid = observer(native_logs["CSRUN.LOG"], nonce)
    measurements = component(native_logs["CSS13.LOG"])
    need((review_path is None) == (review_sha is None), "visual review path/hash must be paired")
    reviewed = None
    if review_path is not None:
        review = receipt(Path(review_path).absolute(), review_sha, 65536)
        need(review.get("schema") == "win98modern.css-mshtml-paint-review.v1" and
             review.get("harness_result_sha256") == run_sha and review.get("manifest_sha256") == manifest_sha and
             review.get("input_sha256") == {n: r["sha256"] for n, r in inputs.items()} and
             review.get("genuine_mshtml_paint_verified") is True and review.get("full_modern_css_verified") is False,
             "trusted paint review binds different scope/run/input")
        frames = review.get("frames")
        need(isinstance(frames, dict) and set(frames) == {"initial_gray", "modified_colors_korean"},
             "both reviewed initial/modified states required")
        times, hashes = [], set()
        for role in ("initial_gray", "modified_colors_korean"):
            frame = frames[role]
            path = local(frame.get("path"), run_dir)
            digest = sha(read(path, 16 << 20))
            need(path.suffix.lower() == ".png" and digest == pin(frame.get("sha256"), "frame") and
                 digest not in hashes and isinstance(frame.get("visual_review"), str) and
                 0 < len(frame["visual_review"].strip()) <= 4096, "missing/duplicate/changed manual frame review")
            hashes.add(digest)
            seconds = frame.get("seconds")
            need(type(seconds) in {int, float} and math.isfinite(seconds) and seconds >= 0,
                 "invalid frame timestamp")
            matches = [c for c in run.get("captures", []) if c.get("screenshot") == str(path)]
            need(len(matches) == 1 and matches[0].get("sha256") == digest and
                 matches[0].get("screenshot_status") == "captured" and matches[0].get("seconds") == seconds,
                 "reviewed frame is not actual harness capture")
            times.append(seconds)
        need(times[0] < times[1], "reviewed CSS state order differs")
        reviewed = dict(trusted_review_sha256=review_sha, frames=frames,
                        trust="caller-approved manual painted state review; no automatic pixel inference")
    return dict(schema="win98modern.css-mshtml-native-component.v1", passed=True,
        harness_result_sha256=run_sha, manifest_sha256=manifest_sha, harness_source_sha256=harness_sha,
        approved_build_sha256=build_pins, source_sha256=merged, build_log_sha256=logs,
        input_sha256={n: r["sha256"] for n, r in inputs.items()},
        log_sha256={n: sha(d) for n, d in native_logs.items()},
        actual_owned_child=dict(pid=pid, exit_code=0, stdout_flushed=True, handles_closed=True),
        actual_supervisor_exit_verified=False, supervisor_requested_exit_code=0,
        native_component_execution_verified=True, native_styles_verified=True, native_geometry_verified=True,
        native_paint_verified=reviewed is not None, trusted_visual_review=reviewed,
        observations=measurements, visual_content_automatically_asserted=False,
        full_modern_css_verified=False, browser_wpt_verified=False, standard_browser_navigation_verified=False,
        full_html5_verified=False, full_javascript_verified=False, webassembly_verified=False,
        webgpu_verified=False, webgl_verified=False, modern_apps_verified=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("run-result", "manifest"):
        parser.add_argument("--" + name, required=True, type=Path)
        parser.add_argument("--" + name + "-sha256", required=True)
    parser.add_argument("--harness-sha256", required=True)
    for name in ("core", "fixture", "observer"):
        parser.add_argument("--" + name + "-build-sha256", required=True)
    parser.add_argument("--trusted-visual-review", type=Path)
    parser.add_argument("--trusted-visual-review-sha256")
    args = parser.parse_args()
    try:
        result = verify(args.run_result, args.run_result_sha256, args.manifest, args.manifest_sha256,
            args.harness_sha256, {name + "-build.json": getattr(args, name + "_build_sha256")
                for name in ("core", "fixture", "observer")},
            args.trusted_visual_review, args.trusted_visual_review_sha256)
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps(dict(passed=False, native_component_execution_verified=False,
                              native_paint_verified=False, error=str(error))))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
