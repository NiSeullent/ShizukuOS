#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Read only: verify pinned stopped-guest theme evidence and a trusted visual review.

This never operates a VM, reads a live guest disk or decides what PNG pixels show.
The caller must pin a separately trusted manual visual review receipt.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import stat

INPUTS = {"M98THEME.DLL", "M98THPRO.EXE", "M98THSTA.EXE", "M98THRUN.EXE"}
OUTPUTS = {"THRUN.LOG", "THPRO.LOG", "THSTA.LOG"}
SOURCE_RECEIPTS = {"theme-source-receipt.json", "supervisor-source-receipt.json"}
PASS_LINE = "PASS: native GDI theme, colors, margins, font, text, handles and visible comparison"

class EvidenceError(ValueError):
    pass

def need(condition, reason):
    if not condition:
        raise EvidenceError(reason)

def sha(data):
    return hashlib.sha256(data).hexdigest()

def pin(value, name):
    need(isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value), f"invalid {name} SHA256 pin")
    return value

def read(path, maximum=16 * 1024 * 1024):
    path = Path(path).absolute()
    need(path.resolve(strict=True) == path, f"symlink or noncanonical evidence path: {path}")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= maximum, f"unbounded/nonregular evidence: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        need(all(getattr(before, k) == getattr(after, k) for k in fields) and len(data) == before.st_size,
             f"evidence changed while reading: {path}")
        return data
    finally:
        os.close(fd)

def object_from(data):
    def pairs(items):
        out = {}
        for key, value in items:
            need(key not in out, f"duplicate JSON key: {key}")
            out[key] = value
        return out
    value = json.loads(data, object_pairs_hook=pairs)
    need(isinstance(value, dict), "receipt must be a JSON object")
    return value

def local(path, directory):
    path = Path(path)
    need(path.is_absolute() and path.parent == directory and path.name not in {"", ".", ".."},
         f"evidence path is outside its owned directory: {path}")
    return path

def log_pairs(lines, title):
    out = {}
    for line in lines:
        need("=" in line, f"non-key line in {title}")
        key, value = line.split("=", 1)
        need(key not in out, f"duplicate log key in {title}: {key}")
        out[key] = value
    return out

def child_logs(run_log, nonce):
    try:
        lines = run_log.decode("ascii").splitlines()
    except UnicodeError as error:
        raise EvidenceError("supervisor log is not ASCII") from error
    need(lines and all(line for line in lines), "empty supervisor log line")
    boundaries = [i for i, line in enumerate(lines) if line.startswith("child.path=")]
    need(len(boundaries) == 2, "both complete child blocks are required")
    pre = log_pairs(lines[:boundaries[0]], "supervisor preamble")
    expected = {"scope": "actual-win98-theme-owned-child-supervisor", "nonce": nonce,
                "WIN98_IDENTIFIED": "1", "os.major": "4", "os.minor": "10",
                "os.build-low": "2222", "os.platform": "1"}
    need(pre == expected, "supervisor OS/nonce identity differs")
    need(lines[-1] == "supervisor.requested-exit-code=0", "supervisor requested completion missing/nonzero")
    blocks = [lines[boundaries[0]:boundaries[1]], lines[boundaries[1]:-1]]
    children = []
    for block, name, stdout in zip(blocks, ("M98THPRO.EXE", "M98THSTA.EXE"), ("THPRO.LOG", "THSTA.LOG")):
        fields = log_pairs(block, name)
        expected = {"child.path": "C:\\GOPLAB\\" + name, "child.stdout": "C:\\GOPLAB\\" + stdout,
                    "child.created": "1", "child.create-error": "0", "child.wait": "0",
                    "child.exit-query": "1", "child.exit-query-error": "0", "child.exit-code": "0",
                    "child.stdout-flushed": "1", "child.handles-closed": "1", "child.success": "1"}
        need(set(fields) == set(expected) | {"child.pid"}, f"partial/extra child fields: {name}")
        need(all(fields[k] == v for k, v in expected.items()), f"native child did not fully succeed: {name}")
        pid = fields["child.pid"]
        need(re.fullmatch(r"[1-9][0-9]*", pid) and int(pid) <= 0xffffffff, f"invalid native child PID: {name}")
        children.append({"path": expected["child.path"], "pid": int(pid), "actual_exit": 0,
                         "stdout_flushed": True, "handles_closed": True})
    return children

def verify(run, manifest_path, manifest_sha, runner_sha, review_path, review_sha):
    run = Path(run).absolute()
    need(run.resolve(strict=True) == run and run.is_dir(), "noncanonical owned run directory")
    manifest_path = Path(manifest_path).absolute()
    review_path = Path(review_path).absolute()
    manifest_bytes = read(manifest_path, 65536)
    review_bytes = read(review_path, 65536)
    need(sha(manifest_bytes) == pin(manifest_sha, "manifest"), "frozen manifest changed")
    need(sha(review_bytes) == pin(review_sha, "manual review"), "trusted manual review changed")
    manifest = object_from(manifest_bytes)
    review = object_from(review_bytes)
    need(type(manifest.get("schema")) is int and manifest["schema"] == 1 and
         manifest.get("kind") == "isolated-guest-file-inputs", "unsupported frozen manifest schema/kind")
    nonce = manifest.get("nonce")
    need(isinstance(nonce, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", nonce),
         "manifest nonce must be nonempty bounded ASCII identity")
    result_bytes = read(run / "result.json")
    result = object_from(result_bytes)
    need(review.get("schema") == "win98modern.theme-native-visual-review.v1", "unsupported trusted review schema")
    need(review.get("harness_result_sha256") == sha(result_bytes), "manual review binds a different run result")
    need(review.get("frozen_manifest_sha256") == manifest_sha, "manual review binds a different manifest")
    need(review.get("native_component_visual_verified") is True and review.get("originals_unchanged") is True,
         "trusted manual painted-frame review is absent")
    need(review.get("system_theme_verified") is False and review.get("application_functionality_verified") is False,
         "manual review exceeds component scope")
    need(result.get("profile") == "actual-win98-uefi-csmwrap", "different runtime profile")
    need(result.get("status") in {"NEEDS-VISUAL-REVIEW", "PASS"} and
         not result.get("runtime_failure") and not result.get("error"), "native harness failed")
    need(result.get("originals_unchanged") is True and result.get("prepared_source_unchanged") is True,
         "protected/native source immutability not established")
    need(type(result.get("qemu_exit_code")) is int and result["qemu_exit_code"] == 0 and result.get("manual_finish_requested") is True,
         "owned VM has no normal stopped-run completion")
    source = local(result.get("source_snapshot", ""), run)
    need(sha(read(source, 1024 * 1024)) == pin(runner_sha, "runner") == result.get("source_sha256"), "native runner source differs")
    hardware = result.get("hardware", {})
    need(hardware.get("run_name") == run.name and hardware.get("network") == "none" and
         hardware.get("reserve_gib") == 20 and hardware.get("accel") == "kvm" and
         hardware.get("memory") == 128 and hardware.get("smp") == 2 and hardware.get("manual_gui") is True,
         "different native cold-trial hardware/guard")
    need(hardware.get("firmware_gop") is True and result.get("firmware_gop_opt_in") is True,
         "explicit native GOP trial profile missing")
    need(result.get("prepared_reuse", {}).get("method", "").startswith("verified private sparse post-run disk copy; cold hardware"),
         "verified fresh cold clone is absent")
    guest = result.get("guest_files", {})
    need(guest.get("manifest") == str(manifest_path) and guest.get("manifest_sha256") == manifest_sha,
         "native run uses a different manifest")
    need(guest.get("immutable_sources_unchanged") is True and guest.get("output_baseline") == "all absent before private injection",
         "guest outputs are stale or inputs changed")
    frozen_inputs = {}
    for row in manifest.get("inputs", []):
        path = local(row["source"], manifest_path.parent)
        need(path.name in INPUTS and path.name not in frozen_inputs and row.get("guest") == "C:\\GOPLAB\\" + path.name,
             "unexpected/duplicate frozen theme input")
        data = read(path, 1024 * 1024)
        need(len(data) == row.get("bytes") and sha(data) == pin(row.get("sha256"), "input"), f"frozen input changed: {path.name}")
        frozen_inputs[path.name] = row
    need(set(frozen_inputs) == INPUTS, "four current theme inputs required")
    frozen_receipts = {}
    for row in manifest.get("source_receipts", []):
        path = local(row["path"], manifest_path.parent)
        need(path.name in SOURCE_RECEIPTS and str(path) not in frozen_receipts,
             "unexpected/duplicate approved source receipt")
        data = read(path, 1024 * 1024)
        object_from(data)
        need(sha(data) == pin(row.get("sha256"), "source receipt"), "approved source receipt changed")
        frozen_receipts[str(path)] = row["sha256"]
    need({Path(path).name for path in frozen_receipts} == SOURCE_RECEIPTS,
         "both current approved source receipts required")
    immutable = {str(manifest_path): manifest_sha}
    immutable.update({row["source"]: row["sha256"] for row in frozen_inputs.values()})
    immutable.update(frozen_receipts)
    need(guest.get("immutable_sources") == immutable, "native immutable source set/hash differs from approved manifest")
    observed = {}
    for row in guest.get("inputs", []):
        path = Path(row.get("source", ""))
        need(path.name in INPUTS and path.name not in observed, "unexpected/duplicate guest input")
        expected = frozen_inputs[path.name]
        need(all(row.get(k) == expected[k] for k in ("source", "guest", "bytes", "sha256")) and
             row.get("private_copy_sha256") == expected["sha256"], "guest copied different theme bytes")
        need(sha(read(run / ("prepared-guest-" + path.name), 1024 * 1024)) == expected["sha256"], "private prepared input differs")
        observed[path.name] = row
    need(set(observed) == INPUTS, "current private input copy evidence missing")
    need(len(manifest.get("outputs", [])) == 3 and set(manifest["outputs"]) == {"C:\\GOPLAB\\" + n for n in OUTPUTS}, "different theme output plan")
    need(guest.get("outputs") == manifest["outputs"], "native guest output plan differs from approved manifest")
    logs = {}
    for row in guest.get("readback", []):
        name = row.get("guest", "").split("\\")[-1]
        need(name in OUTPUTS and name not in logs, "unexpected/duplicate readback")
        need(row.get("guest") == "C:\\GOPLAB\\" + name, "readback is from a different guest path")
        path = local(row.get("path", ""), run)
        need(path.name == "guest-output-" + name, "different stopped native collector path")
        data = read(path, 65536)
        need(row.get("status") == "captured" and row.get("freshness") == "new-in-owned-run" and data and
             row.get("bytes") == len(data) and row.get("sha256") == sha(data), f"empty/stale/incomplete native log: {name}")
        logs[name] = data
    need(set(logs) == OUTPUTS, "three fresh stopped-guest logs required")
    children = child_logs(logs["THRUN.LOG"], manifest.get("nonce"))
    for name, mode in (("THPRO.LOG", "direct-dll"), ("THSTA.LOG", "static-import")):
        need(logs[name].decode("ascii").splitlines() == ["WIN98_IDENTIFIED=1", "PROBE_MODE=" + mode, "ACP=949", PASS_LINE],
             f"current native probe/ACP/full PASS missing: {name}")
    frames = review.get("frames", {})
    need(set(frames) == {"direct-dll", "static-import"}, "two trusted painted mode reviews required")
    captures = result.get("captures", [])
    frame_evidence = {}; seen_frames = set(); seen_digests = set()
    for mode, frame in frames.items():
        path = local(frame.get("path", ""), run)
        need(str(path) not in seen_frames, "the same frame cannot establish both modes")
        seen_frames.add(str(path))
        description = frame.get("visual_review")
        need(path.suffix.lower() == ".png" and isinstance(description, str) and 0 < len(description.strip()) <= 4096,
             "manual painted-frame description missing")
        digest = sha(read(path))
        need(digest not in seen_digests, "identical frame bytes cannot establish both modes")
        seen_digests.add(digest)
        need(digest == pin(frame.get("sha256"), "frame"), "reviewed PNG changed")
        matched = [c for c in captures if c.get("screenshot") == str(path)]
        need(len(matched) == 1 and matched[0].get("sha256") == digest and
             matched[0].get("screenshot_status") == "captured" and matched[0].get("seconds") == frame.get("seconds"),
             "manual frame does not match actual native capture")
        frame_evidence[mode] = {"path": str(path), "sha256": digest, "visual_review": frame["visual_review"]}
    return {"schema": "win98modern.theme-native-completion.v1", "passed": True,
            "scope": "current opt-in native theme direct/static API and trusted visible comparison",
            "run": str(run), "harness_result_sha256": sha(result_bytes), "manifest_sha256": manifest_sha,
            "trusted_visual_review_sha256": review_sha, "production_dll_sha256": frozen_inputs["M98THEME.DLL"]["sha256"],
            "input_sha256": {n: row["sha256"] for n, row in frozen_inputs.items()},
            "source_receipt_sha256": frozen_receipts,
            "input_semantics_trust": "externally approved manifest/source receipts; no automatic production classification",
            "log_sha256": {n: sha(data) for n, data in logs.items()}, "actual_children": children,
            "supervisor_requested_exit": 0, "supervisor_actual_exit": "not_observed",
            "trusted_manual_frames": frame_evidence, "system_theme_verified": False,
            "application_functionality_verified": False, "visual_content_automatically_asserted": False}

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--run", type=Path, required=True)
    p.add_argument("--manifest", type=Path, required=True)
    p.add_argument("--manifest-sha256", required=True)
    p.add_argument("--runner-sha256", required=True)
    p.add_argument("--visual-review", type=Path, required=True)
    p.add_argument("--visual-review-sha256", required=True)
    args = p.parse_args()
    try:
        result = verify(args.run, args.manifest, args.manifest_sha256, args.runner_sha256,
                        args.visual_review, args.visual_review_sha256)
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
        print(json.dumps({"passed": False, "error": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
