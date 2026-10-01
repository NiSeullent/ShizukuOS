#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify frozen build bytes against externally captured Win98 theme evidence.

This reader does not run a guest or establish that readback happened after the
guest stopped. The caller supplies that lifecycle evidence and the actual exit
code from its outer process observer. Log contracts do not prove visible pixels.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import ntpath
from pathlib import Path
import re
import sys
from typing import Any


MAX_METADATA_BYTES = 1024 * 1024
ARTIFACTS = ("M98THEME.DLL", "NTTHGUI.EXE", "NTTHRUN.EXE")
OBSERVER_FIELDS = frozenset({
    "NTTHOBS_LOG_VERSION", "BEGIN_NONCE", "RUN_NONCE", "OS_PLATFORM", "OS_MAJOR", "OS_MINOR",
    "OS_BUILD_LOW", "WIN98_IDENTIFIED", "CHILD_PATH", "CHILD_CREATED", "CHILD_CREATE_ERROR",
    "CHILD_PID", "CHILD_WAIT", "CHILD_WAIT_ERROR", "CHILD_EXIT_QUERY", "CHILD_EXIT_QUERY_ERROR",
    "CHILD_EXIT_CODE", "CHILD_REAPED", "THREAD_CLOSED", "PROCESS_CLOSED", "TERMINATION_ATTEMPTED",
    "CLEANUP", "RESULT",
})
FINAL_FIELDS = frozenset({
    "RUN_NONCE", "WIN98_IDENTIFIED", "OS_PLATFORM", "OS_MAJOR", "OS_MINOR",
    "CLASSIC_PAINTS", "MODERN_PAINTS", "SWITCHES", "DLL_LOCAL",
    "PROVIDER_PATH", "CLEANUP", "RESULT",
})
LOG_FIELDS = FINAL_FIELDS | frozenset({"NTTHGUI_LOG_VERSION", "BEGIN_NONCE"})
ERROR_MARKER = re.compile(
    r"(?<![A-Z0-9])(?:FAIL(?:URE|ED)?|FAIL_STAGE|ERROR(?:S)?|LOGERROR(?:S)?|LOG_ERROR(?:S)?)(?![A-Z0-9])",
    re.IGNORECASE,
)


class VerificationError(ValueError):
    """Evidence is incomplete, contradictory, stale or not the frozen build."""


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(message)


def _hash_file(path: Path) -> tuple[str, int]:
    _require(path.is_file(), f"missing regular file: {path}")
    before = path.stat()
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    after = path.stat()
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    _require(identity(before) == identity(after) and size == after.st_size,
             f"file changed during verification: {path}")
    return digest.hexdigest(), size


def _read_metadata(path: Path) -> bytes:
    _require(path.is_file(), f"missing evidence file: {path}")
    with path.open("rb") as source:
        data = source.read(MAX_METADATA_BYTES + 1)
    _require(0 < len(data) <= MAX_METADATA_BYTES, f"empty or oversized evidence file: {path}")
    return data


def _unique_json(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result, f"duplicate build receipt key: {key}")
        result[key] = value
    return result


def _win_path(value: str) -> str:
    _require(isinstance(value, str) and bool(value), "provider path must be nonempty")
    _require(not any(ord(char) < 32 for char in value), "provider path contains control characters")
    drive, tail = ntpath.splitdrive(value)
    _require(re.fullmatch(r"[A-Za-z]:", drive) is not None and tail.startswith(("\\", "/")),
             "provider path must be an absolute Windows drive path")
    return ntpath.normcase(ntpath.normpath(value))


def parse_log(data: bytes, expected_nonce: str, expected_provider_path: str) -> dict[str, Any]:
    """Check the producer's final contract, retaining no visibility inference."""
    _require(re.fullmatch(r"[0-9a-f]{32}", expected_nonce) is not None,
             "expected nonce must contain exactly 32 lowercase hexadecimal digits")
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError("theme log is not ASCII") from error
    _require(not any(ord(char) < 32 and char not in "\r\n\t" for char in text),
             "theme log contains control characters")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    _require(bool(lines), "theme log is empty")
    _require(lines[-1] == "RESULT=PASS", "last nonempty log line must be RESULT=PASS")
    _require(ERROR_MARKER.search(text) is None, "theme log contains a failure or error marker")
    fields: dict[str, str] = {}
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        _require(key.upper() not in LOG_FIELDS or key == key.upper(),
                 f"noncanonical theme log field: {key}")
        if key in LOG_FIELDS:
            _require(key not in fields, f"duplicate theme log field: {key}")
            fields[key] = value
    _require(LOG_FIELDS <= fields.keys(),
             "missing theme log fields: " + ", ".join(sorted(LOG_FIELDS - fields.keys())))
    _require(fields["NTTHGUI_LOG_VERSION"] == "1", "unsupported theme log version")
    _require(fields["RUN_NONCE"] == expected_nonce, "theme log nonce does not match this run")
    _require(fields["BEGIN_NONCE"] == expected_nonce, "initial theme log nonce does not match this run")
    for key, value in {"WIN98_IDENTIFIED": "1", "OS_PLATFORM": "1", "OS_MAJOR": "4",
                       "OS_MINOR": "10", "DLL_LOCAL": "1", "CLEANUP": "PASS",
                       "RESULT": "PASS"}.items():
        _require(fields[key] == value, f"invalid theme log field: {key}")
    counts: dict[str, int] = {}
    for key, minimum in (("CLASSIC_PAINTS", 1), ("MODERN_PAINTS", 1), ("SWITCHES", 2)):
        value = fields[key]
        _require(re.fullmatch(r"[0-9]{1,10}", value) is not None, f"invalid decimal count: {key}")
        counts[key] = int(value)
        _require(minimum <= counts[key] <= 0xffffffff, f"out-of-range theme count: {key}")
    expected_path = _win_path(expected_provider_path)
    _require(ntpath.basename(expected_path) == "m98theme.dll", "expected provider must name M98THEME.DLL")
    _require(_win_path(fields["PROVIDER_PATH"]) == expected_path, "loaded provider path differs from expected local DLL")
    return {"nonce": expected_nonce, "provider_path": fields["PROVIDER_PATH"], "counts": counts,
            "os": {"platform": 1, "major": 4, "minor": 10}}


def _source_freshness(receipt: dict[str, Any]) -> dict[str, Any]:
    """A source change does not rewrite which bytes were executed in the guest."""
    hashes = receipt.get("source_hashes")
    root_value = receipt.get("source_root")
    if not isinstance(hashes, dict) or not hashes or not isinstance(root_value, str):
        return {"checked": False, "matches": None, "mismatches": []}
    root = Path(root_value)
    if not root.is_absolute():
        return {"checked": False, "matches": None, "mismatches": ["invalid source_root"]}
    root = root.resolve()
    mismatches = []
    for relative, expected_hash in hashes.items():
        try:
            _require(isinstance(relative, str) and isinstance(expected_hash, str), "invalid source hash entry")
            _require(re.fullmatch(r"[0-9a-f]{64}", expected_hash) is not None, "invalid source digest")
            path = (root / relative).resolve()
            _require(not Path(relative).is_absolute() and path.is_relative_to(root), "source path escapes source_root")
            actual_hash, _ = _hash_file(path)
            _require(actual_hash == expected_hash, "source hash mismatch")
        except (VerificationError, OSError) as error:
            mismatches.append({"path": relative, "reason": str(error)})
    return {"checked": True, "matches": not mismatches, "mismatches": mismatches}


def parse_observer_log(data: bytes, expected_nonce: str, provider_path: str) -> dict[str, Any]:
    """Require a normal owned-process wait and its actual full DWORD exit."""
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise VerificationError("observer log is not ASCII") from error
    _require(not any(ord(char) < 32 and char not in "\r\n\t" for char in text),
             "observer log contains control characters")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    _require(bool(lines) and lines[-1] == "RESULT=PASS", "observer log has no final PASS")
    fields: dict[str, str] = {}
    for line in lines:
        _require("=" in line, "malformed observer log line")
        key, value = (part.strip() for part in line.split("=", 1))
        _require(not re.search(r"(?:^|_)(?:FAIL|FAILED|FAILURE|FAIL_STAGE)(?:_|$)", key, re.IGNORECASE),
                 "observer log contains a failure stage")
        if key.upper() in OBSERVER_FIELDS:
            _require(key == key.upper() and key not in fields, f"duplicate or noncanonical observer field: {key}")
            fields[key] = value
        elif re.search(r"(?:^|_)(?:ERROR|LOGERROR)(?:_|$)", key, re.IGNORECASE):
            _require(value == "0", "observer log contains an error")
    _require(OBSERVER_FIELDS <= fields.keys(), "missing observer log fields: " +
             ", ".join(sorted(OBSERVER_FIELDS - fields.keys())))
    for key in ("BEGIN_NONCE", "RUN_NONCE"):
        _require(fields[key] == expected_nonce, f"observer {key} nonce mismatch")
    success_values = {
        "NTTHOBS_LOG_VERSION": "1", "OS_PLATFORM": "1", "OS_MAJOR": "4", "OS_MINOR": "10",
        "OS_BUILD_LOW": "2222", "WIN98_IDENTIFIED": "1", "CHILD_CREATED": "1",
        "CHILD_CREATE_ERROR": "0", "CHILD_WAIT": "0", "CHILD_WAIT_ERROR": "0",
        "CHILD_EXIT_QUERY": "1", "CHILD_EXIT_QUERY_ERROR": "0", "CHILD_EXIT_CODE": "0",
        "CHILD_REAPED": "1", "THREAD_CLOSED": "1", "PROCESS_CLOSED": "1",
        "TERMINATION_ATTEMPTED": "0", "CLEANUP": "PASS", "RESULT": "PASS",
    }
    for key, expected in success_values.items():
        _require(fields[key] == expected, f"invalid observer field: {key}")
    pid = fields["CHILD_PID"]
    _require(re.fullmatch(r"[0-9]{1,10}", pid) is not None and 0 < int(pid) <= 0xffffffff,
             "invalid observer child PID")
    child_path = ntpath.join(ntpath.dirname(_win_path(provider_path)), "NTTHGUI.EXE")
    _require(_win_path(fields["CHILD_PATH"]) == _win_path(child_path), "observer launched another child path")
    return {"child_path": fields["CHILD_PATH"], "child_pid": int(pid), "child_exit_code": 0,
            "os_build_low": 2222, "normal_wait_verified": True,
            "actual_supervisor_exit_verified": False, "supervisor_log_close_verified": False}


def verify_native_evidence(*, build_receipt: Path, build_receipt_sha256: str,
                           log: Path, nonce: str, exit_code: int, provider_path: str,
                           guest_dll: Path, guest_probe: Path, observer_log: Path,
                           guest_observer: Path) -> dict[str, Any]:
    """Read only; require independent readbacks and an actual outer exit result."""
    _require(type(exit_code) is int and exit_code == 0, "external native probe exit code must be exactly zero")
    _require(re.fullmatch(r"[0-9a-f]{64}", build_receipt_sha256) is not None,
             "frozen build receipt SHA-256 must be lowercase hexadecimal")
    receipt_data = _read_metadata(build_receipt)
    _require(hashlib.sha256(receipt_data).hexdigest() == build_receipt_sha256,
             "build receipt differs from its frozen digest")
    try:
        receipt = json.loads(receipt_data, object_pairs_hook=_unique_json)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError("invalid build receipt JSON") from error
    _require(isinstance(receipt, dict), "build receipt must be a JSON object")
    _require(type(receipt.get("schema")) is int and receipt["schema"] == 1,
             "unsupported build receipt schema")
    _require(receipt.get("status") == "PASS", "build receipt has no PASS status")
    _require(receipt.get("native_win98") == "not_tested", "build receipt must describe static evidence only")
    artifacts = receipt.get("artifacts")
    _require(isinstance(artifacts, dict), "build receipt has no artifact mapping")
    verified_artifacts: dict[str, Any] = {}
    for name, readback in zip(ARTIFACTS, (guest_dll, guest_probe, guest_observer)):
        entry = artifacts.get(name)
        _require(isinstance(entry, dict), f"missing frozen build artifact: {name}")
        pe_gate = entry.get("pe98_gate")
        _require(isinstance(pe_gate, dict) and pe_gate.get("status") == "PASS",
                 f"missing or failed native PE gate: {name}")
        path_value, expected_hash, expected_bytes = entry.get("path"), entry.get("sha256"), entry.get("bytes")
        _require(isinstance(path_value, str) and Path(path_value).is_absolute(), f"build path must be absolute: {name}")
        _require(isinstance(expected_hash, str) and re.fullmatch(r"[0-9a-f]{64}", expected_hash) is not None,
                 f"invalid build artifact SHA-256: {name}")
        _require(type(expected_bytes) is int and expected_bytes > 0, f"invalid build artifact size: {name}")
        built = Path(path_value)
        built_hash, built_bytes = _hash_file(built)
        guest_hash, guest_bytes = _hash_file(readback)
        _require(not built.samefile(readback), f"guest readback is the original build file: {name}")
        _require((built_hash, built_bytes) == (expected_hash, expected_bytes), f"original build artifact changed: {name}")
        _require((guest_hash, guest_bytes) == (expected_hash, expected_bytes), f"guest readback artifact changed: {name}")
        verified_artifacts[name] = {"sha256": expected_hash, "bytes": expected_bytes,
                                    "built_path": str(built.resolve()), "readback_path": str(readback.resolve())}
    log_data = _read_metadata(log)
    parsed = parse_log(log_data, nonce, provider_path)
    observer_data = _read_metadata(observer_log)
    observed = parse_observer_log(observer_data, nonce, provider_path)
    return {
        "schema": 1, "status": "PASS", "run_nonce": nonce,
        "gdi_contracts_verified": True, "native_visibility_verified": False,
        "visual_review_required": True, "os_wide_automatic_theme_verified": False,
        "system_theme_installed": False, "persistence_verified": False,
        "application_functionality_verified": False,
        "external_exit_code": exit_code, "os": parsed["os"],
        "observer_child_exit_verified": True, "observer": observed,
        "observer_log": {"path": str(observer_log.resolve()),
                         "sha256": hashlib.sha256(observer_data).hexdigest(), "bytes": len(observer_data)},
        "provider_path": parsed["provider_path"], "counts": parsed["counts"],
        "build_receipt": {"path": str(build_receipt.resolve()), "sha256": build_receipt_sha256},
        "artifacts": verified_artifacts,
        "log": {"path": str(log.resolve()), "sha256": hashlib.sha256(log_data).hexdigest(), "bytes": len(log_data)},
        "source_freshness": _source_freshness(receipt),
        "scope": "Caller-supplied outer exit and stopped-guest readbacks; log contracts do not verify visible pixels or guest lifecycle.",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--build-receipt-sha256", required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--exit-code", type=int, required=True,
                        help="Actual exit code observed externally after native probe termination")
    parser.add_argument("--provider-path", required=True,
                        help="Expected absolute DLL path inside the disposable guest")
    parser.add_argument("--guest-dll", type=Path, required=True,
                        help="Independent M98THEME.DLL readback after guest stop")
    parser.add_argument("--guest-probe", type=Path, required=True,
                        help="Independent NTTHGUI.EXE readback after guest stop")
    parser.add_argument("--observer-log", type=Path, required=True,
                        help="Independent THOBS.LOG with the observer's actual child exit")
    parser.add_argument("--guest-observer", type=Path, required=True,
                        help="Independent NTTHRUN.EXE readback after guest stop")
    args = parser.parse_args(argv)
    try:
        result = verify_native_evidence(**vars(args))
    except (VerificationError, OSError) as error:
        print(json.dumps({"schema": 1, "status": "FAIL", "reason": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
