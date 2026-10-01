#!/usr/bin/env python3
"""Export bounded capabilities from retained receipts without executing project code.

Only the requested output is written. Receipt and artifact hashes establish
identity of retained evidence; they do not repeat a guest test or inspect pixels.
The latest run remains authoritative even when incomplete, malformed or failed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


STAMP = re.compile(r"(\d{8}T\d{6})")
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
BUILD_RECEIPTS = {
    "loader": "build/shizukudos/supervisor/build-result.json",
    "kernel": "build/shizukudos/kernels-build-result.json",
    "runtime": "build/shizukudos/win64/build-result.json",
}


class EvidenceError(ValueError):
    """Evidence cannot support the claimed result."""


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _load_bound(path):
    before = path.stat()
    raw = path.read_bytes()
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise EvidenceError(f"receipt changed while reading: {path}")
    data = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(EvidenceError(f"invalid JSON number: {value}")))
    if not isinstance(data, dict):
        raise EvidenceError("receipt must be a JSON object")
    return data, hashlib.sha256(raw).hexdigest()


def _load(path):
    return _load_bound(path)[0]


def _sha(path):
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise EvidenceError(f"file changed while reading: {path}")
    return digest.hexdigest()


def _time(value):
    if not isinstance(value, str):
        return None
    try:
        stamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return stamp.replace(tzinfo=timezone.utc).timestamp() if stamp.tzinfo is None else stamp.timestamp()
    except ValueError:
        return None


def _run_order(path):
    match = STAMP.search(path.parent.name)
    if match:
        try:
            return (datetime.strptime(match[1], "%Y%m%dT%H%M%S").replace(tzinfo=timezone.utc).timestamp(), str(path))
        except ValueError:
            pass
    try:
        timestamp = _time(_load(path).get("utc"))
        if timestamp is not None:
            return (timestamp, str(path))
    except (OSError, ValueError):
        pass
    # A started run with no result must not revive a completed older PASS.
    return (path.stat().st_mtime if path.exists() else path.parent.stat().st_mtime, str(path))


def _select(root, group):
    if group in ("gop_qa", "shipped_desktop_iso"):
        directory = root / "build" / ("gop-provenance" if group == "gop_qa" else "desktop-harness-iso")
        candidates = [p / "result.json" for p in directory.iterdir() if p.is_dir() and STAMP.search(p.name)] if directory.is_dir() else []
    else:
        directory = root / "build/shizukudos/csm"
        candidates = []
        if directory.is_dir():
            for run in directory.glob("run-win98-uefi-*"):
                is_driver = "-native-vxd-" in run.name
                if run.is_dir() and is_driver == (group == "native_win98_driver"):
                    candidates.append(run / "result.json")
    return max(candidates, key=_run_order) if candidates else None


def _path(root, value, relative_to=None):
    if not isinstance(value, str) or not value:
        raise EvidenceError("artifact path is missing")
    path = Path(value)
    path = path.resolve() if path.is_absolute() else ((relative_to or root) / path).resolve()
    if not path.is_relative_to(root):
        raise EvidenceError(f"artifact path leaves selected root: {value}")
    return path


def _artifact(root, entry, value, expected, label, relative_to=None):
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise EvidenceError(f"{label}: missing or invalid SHA-256")
    path = _path(root, value, relative_to)
    actual = _sha(path)
    item = {"label": label, "path": str(path), "sha256": actual, "matches": actual == expected.lower()}
    entry["artifacts"].append(item)
    if not item["matches"]:
        raise EvidenceError(f"{label}: retained artifact hash mismatch")
    return path


def _checks(items):
    if not isinstance(items, list) or not items:
        raise EvidenceError("nonempty check records are required")
    if any(not isinstance(item, dict) or item.get("status") not in ("PASS", "FAIL") or not isinstance(item.get("check"), str) for item in items):
        raise EvidenceError("invalid check record")
    passed = sum(item["status"] == "PASS" for item in items)
    return {"checks": len(items), "passed": passed, "failed": len(items) - passed}


def _all_pass(items):
    counts = _checks(items)
    if counts["failed"]:
        raise EvidenceError("receipt contains failing checks despite claimed PASS")
    return counts


def _freshness(root, receipts):
    sources, missing, mismatches = {}, [], []
    for kind in BUILD_RECEIPTS:
        record = receipts.get(kind)
        mapping = record.get("sources_sha256") if isinstance(record, dict) else None
        if not isinstance(mapping, dict) or not mapping:
            missing.append(kind)
            continue
        for name, expected in mapping.items():
            if name in sources and sources[name] != expected:
                mismatches.append(f"conflicting source digest: {name}")
            sources[name] = expected
    for name, expected in sources.items():
        try:
            if not isinstance(expected, str) or not SHA256.fullmatch(expected) or _sha(_path(root, name)) != expected.lower():
                mismatches.append(name)
        except (OSError, ValueError):
            mismatches.append(name)
    return {"state": "mismatch" if mismatches else "unavailable" if missing else "matched",
            "files": len(sources), "missing_receipts": missing, "mismatches": sorted(set(mismatches))}


def _gop(root, entry, record, path):
    entry["counts"] = _all_pass(record.get("checks"))
    entry["counts"].update({"apps_run": record.get("apps_run"), "apps_pass": record.get("apps_pass")})
    if type(record.get("apps_run")) is not int or record["apps_run"] != 85 or record.get("apps_pass") != 85 or record.get("apps_failed") != []:
        raise EvidenceError("GOP receipt must record all 85 internal QA apps passing")
    guest_path = _artifact(root, entry, record.get("guest_result"), record.get("guest_result_sha256"), "GOP guest receipt")
    guest, guest_digest = _load_bound(guest_path)
    if guest_digest != record["guest_result_sha256"].lower():
        raise EvidenceError("GOP guest receipt changed before parsing")
    if guest.get("test") != "shizukudos/tests/run_k64_gop.py":
        raise EvidenceError("GOP receipt belongs to a different runner")
    counts = _all_pass(guest.get("checks"))
    if guest.get("status") != "PASS" or record.get("guest_check_count") != counts["checks"] or record.get("guest_check_results") != {"PASS": counts["passed"], "FAIL": 0}:
        raise EvidenceError("GOP summary disagrees with retained guest checks")
    entry["counts"]["guest_checks"] = counts["checks"]
    entry["source_identity"] = guest.get("git")
    _artifact(root, entry, record.get("serial"), record.get("serial_sha256"), "GOP serial log")
    shots = record.get("screenshots")
    if not isinstance(shots, dict) or len(shots) < 2:
        raise EvidenceError("GOP framebuffer and status screenshot evidence is required")
    for label, shot in shots.items():
        if not isinstance(shot, dict):
            raise EvidenceError("invalid GOP screenshot record")
        _artifact(root, entry, shot.get("path"), shot.get("sha256"), label)
    inputs_path = path.parent / "inputs.json"
    if inputs_path.is_file():
        inputs, digest = _load_bound(inputs_path)
        entry["artifacts"].append({"label": "GOP source receipts", "path": str(inputs_path), "sha256": digest})
        receipts = inputs.get("source_receipts", {})
        entry["source_freshness"] = _freshness(root, receipts if isinstance(receipts, dict) else {})
        entry["build_source_identities"] = {key: value.get("git") for key, value in receipts.items() if isinstance(value, dict)} if isinstance(receipts, dict) else {}
    entry["remaining_issue"] = record.get("remaining_issue")


def _desktop(root, entry, record, path):
    if record.get("test") != "shizukudos/tests/run_k64_desktop.py":
        raise EvidenceError("desktop receipt belongs to a different runner")
    entry["counts"] = _all_pass(record.get("checks"))
    boots = record.get("boots")
    if not isinstance(boots, list) or len(boots) != 2 or {boot.get("boot") for boot in boots if isinstance(boot, dict)} != {1, 2}:
        raise EvidenceError("two independently recorded cold boots are required")
    entry["counts"]["boots"] = 2
    entry["counts"]["boot_checks"] = []
    names = {item["check"] for item in record["checks"]}
    for boot in boots:
        if boot.get("status") != "PASS" or boot.get("boot_medium") != "shipped-iso-cd" or boot.get("qemu_exit_code") != 1:
            raise EvidenceError("desktop boot did not pass on the shipped ISO with intentional QEMU exit")
        entry["counts"]["boot_checks"].append(_all_pass(boot.get("checks"))["checks"])
        for suffix in ("disk bytes equal exact host-selected text", "FAT32 volume consistent after guest writes"):
            if f"boot-{boot['boot']}: {suffix}" not in names:
                raise EvidenceError("independent disk readback and consistency checks are required")
        shots = boot.get("screenshots")
        if not isinstance(shots, list) or not shots:
            raise EvidenceError("desktop guest screenshots are missing")
        for shot in shots:
            if not isinstance(shot, dict):
                raise EvidenceError("invalid desktop screenshot record")
            _artifact(root, entry, shot.get("path"), shot.get("sha256"), f"boot-{boot['boot']} {shot.get('label', 'screenshot')}")
    expected = record.get("expected_file", {})
    if not isinstance(expected, dict) or type(expected.get("bytes")) is not int or expected["bytes"] <= 0 or not isinstance(expected.get("sha256"), str) or not SHA256.fullmatch(expected["sha256"]):
        raise EvidenceError("exact persisted-file identity is missing")
    entry["persisted_file"] = expected
    iso = record.get("iso")
    if not isinstance(iso, dict) or not isinstance(iso.get("receipt"), dict):
        raise EvidenceError("shipped ISO evidence is missing")
    _artifact(root, entry, iso.get("frozen"), iso.get("sha256"), "frozen shipped desktop ISO")
    _artifact(root, entry, iso["receipt"].get("path"), iso["receipt"].get("sha256"), "desktop ISO builder receipt")
    identities = record.get("inputs", {}).get("receipts", {})
    receipts, changed = {}, []
    for kind, name in BUILD_RECEIPTS.items():
        # These mutable build receipts are a current-source check, not frozen
        # guest evidence. A legitimate rebuild cannot revoke the retained run.
        receipt_path = _path(root, name)
        expected = identities.get(kind)
        if not isinstance(expected, str) or not SHA256.fullmatch(expected) or not receipt_path.is_file():
            continue
        digest = _sha(receipt_path)
        entry["artifacts"].append({"label": f"current desktop {kind} build receipt", "path": str(receipt_path),
                                   "sha256": digest, "expected_sha256": expected, "matches": digest == expected.lower()})
        if digest != expected.lower():
            changed.append(f"live {kind} build receipt differs from tested receipt")
            continue
        current, parsed_digest = _load_bound(receipt_path)
        if parsed_digest != expected.lower():
            changed.append(f"live {kind} build receipt changed during reading")
            continue
        receipts[kind] = current
    entry["source_freshness"] = _freshness(root, receipts)
    if changed:
        entry["source_freshness"]["state"] = "mismatch"
        entry["source_freshness"]["mismatches"].extend(changed)
    entry["build_source_identities"] = {kind: value.get("git") for kind, value in receipts.items()}


def _native_gui(root, entry, record, path):
    review_path = path.parent / "visual-review.json"
    if not review_path.is_file():
        raise EvidenceError("native Windows 98 GUI requires a separate retained visual review")
    review, digest = _load_bound(review_path)
    entry["artifacts"].append({"label": "native Windows 98 visual review", "path": str(review_path), "sha256": digest})
    if review.get("receipt_sha256") != entry["receipt"]["sha256"] or review.get("functional_gui_verdict") != "PASS":
        raise EvidenceError("latest native GUI visual review does not bind a functional PASS to this receipt")
    readback = review.get("exact_host_readback", {})
    if not isinstance(readback, dict) or readback.get("status") != "PASS" or readback.get("baseline_file_present") is not False or readback.get("freshness") != "new-in-owned-run":
        raise EvidenceError("fresh native Windows 98 saved-file readback is not established")
    saved = _artifact(root, entry, readback.get("path"), readback.get("sha256"), "native Windows 98 saved file")
    if type(readback.get("bytes")) is not int or saved.stat().st_size != readback["bytes"]:
        raise EvidenceError("native Windows 98 saved-file byte count differs")
    captures = record.get("captures", [])
    by_name = {Path(item.get("screenshot", "")).name: item for item in captures if isinstance(item, dict)}
    screenshots = review.get("screenshots")
    if not isinstance(screenshots, list) or not screenshots:
        raise EvidenceError("reviewed native Windows 98 screenshots are missing")
    for name in screenshots:
        capture = by_name.get(name, {})
        _artifact(root, entry, capture.get("screenshot"), capture.get("sha256"), f"native Windows 98 {name}")
    entry["state"] = "verified_pass"
    entry["scope"] = "Microsoft Windows 98 GUI interaction and fresh Notepad save in one private guest run"
    entry["counts"] = {"checks": 0, "passed": 0, "failed": 0, "reviewed_screenshots": len(screenshots)}
    entry["remaining_issue"] = {"cold_saved_file_persistence": review.get("cold_saved_file_persistence"), "full_project_drivers": review.get("full_project_drivers")}


def _native_driver(root, entry, record, path):
    trial = record.get("native_trial")
    if not isinstance(trial, dict):
        raise EvidenceError("native driver trial evidence is missing")
    entry["native_trial"] = {key: trial.get(key) for key in ("variant", "scope", "validation_status", "dos_exit", "result_code", "windows98_version_confirmed", "candidate_identity_matches", "raw_register_results")}
    logs = trial.get("readback")
    if not isinstance(logs, list) or not logs:
        raise EvidenceError("fresh native driver readback is missing")
    for item in logs:
        if not isinstance(item, dict) or item.get("freshness") != "new-in-owned-run":
            raise EvidenceError("native driver readback is not fresh")
        _artifact(root, entry, item.get("path"), item.get("sha256"), "native driver raw log")
    if trial.get("validation_status") == "FAIL" or record.get("status") == "FAIL":
        entry["state"] = "verified_fail"
        entry["reasons"].append("Latest native Windows 98 driver fixture failed; host fixture tests do not establish loader acceptance.")
    elif trial.get("validation_status") == "PASS" and trial.get("windows98_version_confirmed") is True and trial.get("candidate_identity_matches") is True and trial.get("dos_exit") == 0 and trial.get("result_code") == 0:
        # A passing diagnostic fixture still cannot establish production drivers.
        entry["state"] = "verified_pass"
        entry["scope"] = "native Windows 98 diagnostic VxD fixture only; production driver support unverified"
    else:
        raise EvidenceError("native driver fixture acceptance remains unverified")


def _evidence(root, group):
    entry = {"state": "unverified", "receipt": None, "source_identity": None,
             "source_freshness": {"state": "unavailable", "files": 0, "missing_receipts": [], "mismatches": []},
             "counts": {"checks": 0, "passed": 0, "failed": 0}, "reasons": [], "artifacts": []}
    path = _select(root, group)
    if path is None:
        entry["reasons"].append("No retained run receipt was found.")
        return entry
    entry["receipt"] = {"path": str(path), "sha256": None, "timestamp": None}
    if not path.is_file():
        entry["reasons"].append("Latest run has no completed result.json; an older result was not substituted.")
        return entry
    try:
        record, entry["receipt"]["sha256"] = _load_bound(path)
        entry["receipt"]["timestamp"] = record.get("utc")
        entry["recorded_status"] = record.get("status")
        entry["source_identity"] = record.get("git") or {key: record.get(key) for key in ("source_snapshot", "source_sha256", "boot_path") if record.get(key) is not None} or None
        if group.startswith("native_win98_") and record.get("profile") != "actual-win98-uefi-csmwrap":
            raise EvidenceError("native Windows 98 evidence requires the actual-win98-uefi-csmwrap profile")
        if group == "native_win98_driver":
            _native_driver(root, entry, record, path)
        elif group == "native_win98_gui":
            if record.get("status") == "FAIL":
                entry["state"] = "verified_fail"
                entry["reasons"].append(record.get("interaction_failure") or "Latest native Windows 98 run failed.")
            else:
                _native_gui(root, entry, record, path)
        elif record.get("status") == "FAIL":
            entry["state"] = "verified_fail"
            entry["counts"] = _checks(record["checks"]) if record.get("checks") else entry["counts"]
            entry["reasons"].append("Latest retained run failed; an older PASS was not substituted.")
        elif record.get("status") != "PASS":
            entry["reasons"].append("Latest run does not record a completed PASS.")
        else:
            (_gop if group == "gop_qa" else _desktop)(root, entry, record, path)
            entry["state"] = "verified_pass"
        if _sha(path) != entry["receipt"]["sha256"]:
            raise EvidenceError("receipt changed while exporting")
    except FileNotFoundError as exc:
        entry["state"] = "unverified"
        entry["reasons"].append(f"Required retained file is missing: {exc.filename}")
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as exc:
        entry["state"] = "error"
        entry["reasons"].append(str(exc))
    return entry


def build_status(root: Path) -> dict:
    """Read retained receipts and return JSON-ready evidence; write nothing."""
    root = Path(root).resolve()
    if not root.is_dir():
        raise EvidenceError(f"selected root is not a directory: {root}")
    evidence = {group: _evidence(root, group) for group in ("gop_qa", "shipped_desktop_iso", "native_win98_gui", "native_win98_driver")}
    current = lambda group: evidence[group]["state"] == "verified_pass" and evidence[group]["source_freshness"]["state"] == "matched"
    return {"schema_version": 1, "generated_utc": datetime.now(timezone.utc).isoformat(), "root": str(root),
            "selection_policy": "Latest run directory/receipt timestamp, never latest PASS; incomplete or corrupt latest evidence remains authoritative.",
            "evidence": evidence,
            "capabilities": {"gop_qa_85_apps": current("gop_qa"), "shipped_desktop_persistence": current("shipped_desktop_iso"),
                             "native_windows98_gui": evidence["native_win98_gui"]["state"] == "verified_pass",
                             "native_windows98_driver": False, "modern_app_compatibility": False, "gpu_acceleration": False},
            "limitations": ["85 internal T_* QA applications are not the required modern application corpus.",
                            "ShizukuDOS desktop and Microsoft Windows 98 GUI are separate execution paths.",
                            "GOP framebuffer display does not prove hardware GPU acceleration.",
                            "Native VxD diagnostic fixtures do not establish production driver support.",
                            "Exporter verifies retained file hashes and receipt claims; it executes no guests, scripts or image analysis."]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="repository whose retained build receipts are read")
    parser.add_argument("--output", type=Path, required=True, help="explicit output JSON path (the only file written)")
    args = parser.parse_args(argv)
    try:
        report = build_status(args.root)
        # The caller creates the output directory; no implicit directory writes.
        args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except (OSError, ValueError) as exc:
        print(f"preview evidence export failed: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
