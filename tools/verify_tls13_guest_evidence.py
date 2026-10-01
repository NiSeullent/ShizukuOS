#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify frozen native DLL interop readbacks; never infer OS/app TLS support.

The VM harness's diagnostic status alone does not attest to an application.
This verifier joins its fresh file readbacks to the frozen staging receipt and
to both native logs, including the supervisor's actual owned-child exit code.
It does not observe the supervisor's own exit after its final file close.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

ROOT = Path(__file__).resolve().parents[1]
HEX = re.compile(r"[0-9a-f]{64}\Z")
PREFIX = "C:\\GOPLAB\\"
CHECKS = (
    "WIN98_IDENTIFIED", "LOAD_BOTH_DLLS_AND_9_13_EXPORTS", "FIXTURES_LOADED",
    "NATIVE_CRYPTOAPI_CSPRNG", "NATIVE_UTC_VALID", "INDEPENDENT_SERVER_PSA_NATIVE_INIT",
    "ENTROPY_ZERO_REJECTED", "ENTROPY_MINUS1_REJECTED", "ENTROPY_TWO_REJECTED",
    "LATE_ENTROPY_FAILURE_DENIED", "PAIR_CREATE", "TLS13_HANDSHAKE_BOTH_DLLS",
    "AUTHENTICATED_BIDIRECTIONAL_PAYLOAD", "BOUNDED_PARTIAL_IO_WANT_RETRIES",
    "AUTHENTICATED_CLOSE_NOTIFY", "WRITE_AFTER_CLOSE_DENIED",
    "WRONG_HOST_REJECTED_WITHOUT_PLAINTEXT", "UNTRUSTED_CA_REJECTED_WITHOUT_PLAINTEXT",
    "LATEST_CLIENT_TAMPERED_CIPHERTEXT_NO_PLAINTEXT", "SERVER_RUNTIME_SHUTDOWN",
    "CRYPTOAPI_PROVIDER_RELEASED", "SERVER_DLL_UNLOADED", "CLIENT_DLL_UNLOADED",
    "CRYPTOAPI_DLL_UNLOADED",
)
INPUT_NAMES = frozenset(("TLSDLL.EXE", "M98TLS13.DLL", "M98TLS.DLL", "CA.PEM",
                         "SRV.PEM", "SRV.KEY", "BADCA.PEM", "T13RUN.EXE"))
OUTPUT_NAMES = frozenset(("TLSDLL.LOG", "T13RUN.LOG", "TLSOUT.LOG"))
SOURCE_NAMES = frozenset((
    "tests/m98_tls13_guest_interop.c", "tools/build_tls13_guest_interop.py",
    "tests/m98_tls13_interop_controller.c", "tests/m98_tls13_guest_runner.c",
    "tests/m98_tls13_guest_runner_mock.c", "tests/m98_tls13_guest_runner_mock.h",
    "src/m98_tls13.h", "benchmarks/win98se-ko-oem-native-exports-v1.json",
))
CLIENT_EXPORTS = frozenset(("m98_tls_create", "m98_tls_handshake", "m98_tls_write", "m98_tls_read",
                            "m98_tls_shutdown", "m98_tls_backend_error", "m98_tls_verify_flags",
                            "m98_tls_is_established", "m98_tls_free"))
SERVER_EXPORTS = frozenset(("ntwst_runtime_init", "ntwst_runtime_fini", "ntwst_native_runtime_init",
                            "ntwst_native_runtime_fini", "ntwst_create", "ntwst_destroy",
                            "ntwst_handshake", "ntwst_write", "ntwst_read", "ntwst_close_notify",
                            "ntwst_version", "ntwst_verify_flags", "ntwst_engine_error"))


class EvidenceError(ValueError):
    """A missing, ambiguous, stale, failed or mismatched evidence item."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise EvidenceError(message)


def frozen_bytes(path: Path, expected: str, limit: int = 1 << 20) -> bytes:
    require(isinstance(expected, str) and bool(HEX.fullmatch(expected)),
            "expected SHA256 is malformed")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_size <= limit,
                f"not a bounded regular evidence file: {path}")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        require(len(data) == before.st_size and
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns),
                f"evidence changed while reading: {path}")
    finally:
        os.close(fd)
    require(hashlib.sha256(data).hexdigest() == expected,
            f"evidence SHA256 mismatch: {path}")
    return data


def unique_pairs(items: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in items:
        require(key not in result, f"duplicate JSON key: {key}")
        result[key] = value
    return result


def json_file(path: Path, expected: str) -> dict:
    require(isinstance(expected, str) and bool(HEX.fullmatch(expected)), "JSON receipt lacks a frozen SHA256")
    result = json.loads(frozen_bytes(path, expected), object_pairs_hook=unique_pairs)
    require(isinstance(result, dict), "evidence JSON must be an object")
    return result


def contained(path: str, parent: Path) -> Path:
    require(isinstance(path, str), "evidence path must be a string")
    value = Path(path)
    require(value.is_absolute() and not value.is_symlink(), "evidence path must be absolute and regular")
    resolved = value.resolve(strict=True)
    require(resolved.is_relative_to(parent.resolve(strict=True)), "evidence path escapes its owned directory")
    return resolved


def records(items: object, expected_guests: set[str]) -> dict[str, dict]:
    require(isinstance(items, list), "evidence records must be a list")
    result = {}
    for entry in items:
        require(isinstance(entry, dict) and isinstance(entry.get("guest"), str), "bad guest record")
        require(entry["guest"] not in result, "duplicate guest record")
        result[entry["guest"]] = entry
    require(set(result) == expected_guests, "guest record set differs from frozen scope")
    return result


def log_pairs(raw: bytes) -> dict[str, str]:
    require(len(raw) <= 65536 and raw.endswith(b"\r\n"), "native log is empty, large or incomplete")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise EvidenceError("native log is not ASCII") from error
    result = {}
    for line in text[:-2].split("\r\n"):
        require("\r" not in line and "\n" not in line and "=" in line and len(line) <= 512,
                "malformed native log line")
        key, value = line.split("=", 1)
        require(key and key not in result, "duplicate or empty native log key")
        result[key] = value
    return result


def verify(run_path: Path, run_sha: str, manifest_path: Path, manifest_sha: str,
           source_root: Path = ROOT) -> dict:
    run_path, manifest_path = run_path.absolute(), manifest_path.absolute()
    manifest = json_file(manifest_path, manifest_sha)
    run = json_file(run_path, run_sha)
    require(type(manifest.get("schema")) is int and manifest["schema"] == 1 and
            manifest.get("kind") == "isolated-guest-file-inputs",
            "unsupported staging manifest")
    require(isinstance(manifest.get("nonce"), str) and
            bool(re.fullmatch(r"[A-Za-z0-9_-]{8,96}", manifest["nonce"])), "invalid frozen nonce")
    require(manifest.get("command") == PREFIX + "T13RUN.EXE" and
            manifest.get("network_required") is False, "manifest is not the offline TLS supervisor")
    require(manifest.get("outputs") == [PREFIX + "TLSDLL.LOG", PREFIX + "T13RUN.LOG", PREFIX + "TLSOUT.LOG"],
            "unexpected output scope")
    inputs = records(manifest.get("inputs"), {PREFIX + name for name in INPUT_NAMES})
    receipts = manifest.get("source_receipts")
    require(isinstance(receipts, list) and len(receipts) == 1 and isinstance(receipts[0], dict),
            "expected exactly one frozen interop build receipt")
    receipt_path = contained(receipts[0]["path"], manifest_path.parent)
    build = json_file(receipt_path, receipts[0]["sha256"])
    require(build.get("schema") == "win98modern.latest-tls-dll-interop.v1" and
            build.get("status") == "PASS" and build.get("nonce") == manifest["nonce"],
            "build receipt identity mismatch")
    artifacts = build.get("artifacts")
    require(isinstance(artifacts, dict) and set(artifacts) == INPUT_NAMES, "build artifact set mismatch")
    source_hashes = build.get("source_sha256")
    require(isinstance(source_hashes, dict) and set(source_hashes) == SOURCE_NAMES,
            "missing or unexpected frozen source profile")
    for name, sha in source_hashes.items():
        require(isinstance(name, str) and not Path(name).is_absolute() and ".." not in Path(name).parts,
                "source hash path escapes the project")
        # The pinned OEM export inventory is larger than a guest input; its
        # source audit has a separate bounded limit from the 1 MiB staging cap.
        frozen_bytes(contained(str(source_root.absolute() / name), source_root), sha, 4 << 20)
    for guest, entry in inputs.items():
        data = frozen_bytes(contained(entry["source"], manifest_path.parent), entry["sha256"])
        name = guest.rsplit("\\", 1)[1]
        require(type(entry.get("bytes")) is int and entry["bytes"] == len(data) and
                artifacts[name].get("bytes") == len(data) and artifacts[name].get("sha256") == entry["sha256"],
                "manifest input differs from build receipt")
    client = json_file(manifest_path.parent / "client-build.json", build.get("client_receipt_sha256"))
    server = json_file(manifest_path.parent / "server-build.json", build.get("server_receipt_sha256"))
    client_sha, server_sha = inputs[PREFIX + "M98TLS13.DLL"]["sha256"], inputs[PREFIX + "M98TLS.DLL"]["sha256"]
    require(client.get("profile") == "pe32" and client.get("dependency", {}).get("version") == "4.2.0" and
            client.get("dependency", {}).get("tf_psa_crypto_version") == "1.2.0" and
            any(isinstance(item, dict) and item.get("sha256") == client_sha and
                Path(item.get("path", "")).name == "M98TLS13.dll" for item in client.get("artifacts", [])),
            "client is not the frozen latest Mbed TLS 4.2.0/TF-PSA-Crypto 1.2.0 DLL")
    require(server.get("status") == "PASS" and server.get("target") == "win98-x86" and
            server.get("upstream", {}).get("version") == "3.6.7" and
            server.get("source_sha256", {}).get("transport.h") ==
            "7f3f364ab97fd58d94c03f80432a94b99c0ad28b71b48bc4d0ee4920e3191cda" and
            server.get("native_library", {}).get("sha256") == server_sha and
            server.get("native_library", {}).get("bytes") == inputs[PREFIX + "M98TLS.DLL"]["bytes"],
            "server is not the frozen independent native LTS DLL/ABI")
    for key, sha, exports in (("client_gate", client_sha, CLIENT_EXPORTS),
                              ("server_gate", server_sha, SERVER_EXPORTS)):
        gate = build.get(key, {})
        require(gate.get("pe32_oem_gate") == "PASS" and gate.get("sha256") == sha and
                isinstance(gate.get("exports"), list) and len(gate["exports"]) == len(exports) and
                set(gate["exports"]) == exports,
                "frozen DLL OEM import/export gate mismatch")
    for key, name in (("probe_gate", "TLSDLL.EXE"), ("runner_gate", "T13RUN.EXE")):
        gate = build.get(key, {})
        require(gate.get("pe32_oem_gate") == "PASS" and
                gate.get("sha256") == inputs[PREFIX + name]["sha256"] and
                gate.get("bytes") == inputs[PREFIX + name]["bytes"] and
                type(gate.get("stack_reserve")) is int and gate["stack_reserve"] >= 2097152 and
                type(gate.get("stack_commit")) is int and gate["stack_commit"] >= 65536 and
                gate["stack_commit"] <= gate["stack_reserve"],
                "probe/supervisor lacks frozen PE32 identity or committed stack bounds")
    require(run.get("profile") == "actual-win98-uefi-csmwrap" and
            run.get("status") == "NEEDS-VISUAL-REVIEW" and
            run.get("originals_unchanged") is True and type(run.get("qemu_exit_code")) is int and
            run["qemu_exit_code"] == 0 and
            run.get("guest_status", {}).get("running") is True and not run.get("runtime_failure") and
            not run.get("error"), "native VM did not finish with preserved originals")
    require(not run.get("prepared_reuse") or run.get("prepared_source_unchanged") is True,
            "prepared VM source changed")
    require(run.get("hardware", {}).get("network") == "none", "unexpected guest networking")
    harness_source = contained(run.get("source_snapshot"), run_path.parent)
    require(harness_source.name == "runner-source.py", "missing owned harness source snapshot")
    frozen_bytes(harness_source, run.get("source_sha256"))
    files = run.get("guest_files", {})
    require(files.get("manifest") == str(manifest_path) and files.get("manifest_sha256") == manifest_sha and
            files.get("immutable_sources_unchanged") is True and
            files.get("output_baseline") == "all absent before private injection",
            "staging identity/freshness was not preserved by the VM harness")
    expected_sources = {str(manifest_path): manifest_sha, str(receipt_path): receipts[0]["sha256"]}
    expected_sources.update({item["source"]: item["sha256"] for item in inputs.values()})
    require(files.get("immutable_sources") == expected_sources,
            "harness did not freeze the entire approved staging scope")
    copied = records(files.get("inputs"), set(inputs))
    for guest, entry in inputs.items():
        copy = copied[guest]
        require(all(copy.get(key) == entry.get(key) for key in ("source", "sha256", "bytes")) and
                copy.get("private_copy_sha256") == entry["sha256"], "guest input copy identity mismatch")
    require(files.get("outputs") == manifest["outputs"], "harness output scope mismatch")
    captures = records(files.get("readback"), {PREFIX + name for name in OUTPUT_NAMES})
    logs, captured = {}, {}
    for guest, entry in captures.items():
        require(entry.get("status") == "captured" and entry.get("freshness") == "new-in-owned-run",
                "guest output is missing or inherited")
        path = contained(entry["path"], run_path.parent)
        require(path.name == "guest-output-" + guest.rsplit("\\", 1)[1], "unexpected output filename")
        raw = frozen_bytes(path, entry["sha256"], 65536)
        require(type(entry.get("bytes")) is int and entry["bytes"] == len(raw), "output byte count mismatch")
        logs[guest.rsplit("\\", 1)[1]] = raw
        captured[guest] = {"path": str(path), "sha256": entry["sha256"], "bytes": len(raw)}
    require(logs["TLSOUT.LOG"] == b"", "unexpected child standard output")
    supervisor = log_pairs(logs["T13RUN.LOG"])
    expected = {
        "scope": "actual-win98-tls-owned-child-supervisor", "nonce": manifest["nonce"],
        "WIN98_IDENTIFIED": "1", "os.major": "4", "os.minor": "10", "os.build-low": "2222",
        "os.platform": "1", "child.path": PREFIX + "TLSDLL.EXE", "child.stdout": PREFIX + "TLSOUT.LOG",
        "child.created": "1", "child.create-error": "0", "child.wait": "0",
        "child.exit-query": "1", "child.exit-query-error": "0", "child.exit-code": "0",
        "child.stdout-flushed": "1", "child.handles-closed": "1", "child.success": "1",
        "supervisor.requested-exit-code": "0",
    }
    require(set(supervisor) == set(expected) | {"child.pid"} and
            all(supervisor[key] == value for key, value in expected.items()),
            "supervisor did not observe successful child completion on Win98 SE")
    require(bool(re.fullmatch(r"[1-9][0-9]{0,9}", supervisor["child.pid"])) and
            int(supervisor["child.pid"]) <= 0xFFFFFFFF, "invalid actual child PID")
    native = log_pairs(logs["TLSDLL.LOG"])
    expected = {name: "PASS" for name in CHECKS}
    expected.update({"NONCE": manifest["nonce"], "CLIENT_SHA256": inputs[PREFIX + "M98TLS13.DLL"]["sha256"],
                     "SERVER_SHA256": inputs[PREFIX + "M98TLS.DLL"]["sha256"],
                     "SCOPE": "Native DLL interoperability; offline queues; no OS networking",
                     "CLIENT_PATH": PREFIX + "M98TLS13.DLL", "SERVER_PATH": PREFIX + "M98TLS.DLL",
                     "CHECKS": str(len(CHECKS)), "FAILURES": "0", "FINAL": "PASS", "REQUESTED_EXIT": "0",
                     "POSITIVE_CLIENT_STATUS": "0", "POSITIVE_SERVER_STATUS": "0",
                     "POSITIVE_CLIENT_ESTABLISHED": "1", "POSITIVE_CLIENT_BACKEND_ERROR": "0",
                     "POSITIVE_SERVER_BACKEND_ERROR": "0", "POSITIVE_CLIENT_VERIFY_FLAGS": "0",
                     "POSITIVE_SERVER_VERSION": "TLSv1.3",
                     "CLIENT_CERTIFICATE_AUTHENTICATION": "not-requested"})
    require(set(native) == set(expected) | {"UNIX_TIME", "POSITIVE_SERVER_VERIFY_FLAGS"} and
            all(native[key] == value for key, value in expected.items()),
            "native probe lacks complete successful DLL/crypto/TLS/rejection/cleanup checks")
    # No client certificate is requested. This result is informational, not
    # mutual authentication. SKIP_VERIFY or an absent-peer sentinel is valid.
    require(bool(re.fullmatch(r"[0-9]{1,10}", native["POSITIVE_SERVER_VERIFY_FLAGS"])) and
            int(native["POSITIVE_SERVER_VERIFY_FLAGS"]) <= 0xFFFFFFFF,
            "invalid informational server verification flags")
    require(bool(re.fullmatch(r"[0-9]{10}", native["UNIX_TIME"])) and
            1577836800 <= int(native["UNIX_TIME"]) < 2051222400, "invalid native UTC evidence")
    return {"schema": "win98modern.latest-tls-native-readback.v1", "status": "PASS",
            "scope": "Native latest-client/LTS-server DLL interoperability using offline memory queues",
            "nonce": manifest["nonce"], "native_guest_verified": True, "native_checks": len(CHECKS),
            "actual_owned_child_exit_code": 0, "actual_supervisor_exit_verified": False,
            "client_certificate_authentication_verified": False,
            "server_reported_peer_verify_flags": int(native["POSITIVE_SERVER_VERIFY_FLAGS"]),
            "supervisor_requested_exit_code": 0, "system_tls_verified": False,
            "network_transport_verified": False, "application_functionality_verified": False,
            "os": {"platform": "Win32 Windows", "major": 4, "minor": 10, "build_low": 2222},
            "unix_time": int(native["UNIX_TIME"]), "manifest_sha256": manifest_sha,
            "build_receipt_sha256": receipts[0]["sha256"], "harness_result_sha256": run_sha,
            "harness_source_sha256": run["source_sha256"],
            "client_sha256": native["CLIENT_SHA256"], "server_sha256": native["SERVER_SHA256"],
            "source_sha256": source_hashes, "outputs": captured}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-result", type=Path, required=True)
    parser.add_argument("--run-result-sha256", required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    try:
        result = verify(args.run_result, args.run_result_sha256, args.manifest, args.manifest_sha256)
    except (EvidenceError, OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(json.dumps({"status": "FAIL", "native_guest_verified": False, "error": str(error)}))
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
