#!/usr/bin/env python3
"""Review a stopped native prerequisite log without claiming execution proof."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

CHECKS = (
    "exact-target", "startup", "version-1-1", "listener-created",
    "listener-nonblocking", "bind-loopback", "listener-address", "listen",
    "accept-empty-wouldblock", "empty-select-timeout", "client-created",
    "client-nonblocking", "connect-started", "connect-write-ready",
    "connect-so-error-zero", "listener-read-ready", "accept-completed",
    "accepted-nonblocking", "accepted-peer-owned", "client-peer-owned",
    "listener-close", "recv-empty-wouldblock", "accepted-empty-select-timeout",
    "send-client", "recv-server", "client-payload-equal", "send-server",
    "recv-client", "server-payload-equal", "client-send-shutdown",
    "send-after-shutdown-error", "server-eof-ready", "server-eof-zero",
    "halfclose-server-send", "halfclose-client-recv", "halfclose-byte-equal",
    "server-send-shutdown", "client-eof-ready", "client-eof-zero",
    "client-close", "accepted-close", "closed-socket-error", "winsock-cleanup",
    "unmatched-cleanup-error",
)
METADATA = (
    "scope", "nonce", "source.version", "steam.application-executed", "os.platform",
    "os.major", "os.minor", "os.build-low", "winsock.version", "winsock.high-version",
    "loopback.server-port", "connect.result", "connect.error", "roundtrip.bytes-each-direction",
    "resources.cleaned", "prerequisite.checks-completed", "steam.application-passed", "exit",
)


def review(data: bytes, nonce: str) -> dict:
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,80}", nonce):
        raise ValueError("a 16-to-80-character fresh trial nonce is required")
    if not data or len(data) > 64 * 1024:
        raise ValueError("log is empty or exceeds 64 KiB")
    if not data.endswith(b"\r\n"):
        raise ValueError("log has no complete closed final checkpoint")
    try:
        lines = data.decode("ascii").split("\r\n")[:-1]
    except UnicodeDecodeError as error:
        raise ValueError("native checkpoint log is not ASCII") from error
    expected = set(METADATA) | {f"check.{name}" for name in CHECKS} | {
        f"error.{name}" for name in CHECKS}
    fields = {}
    for line in lines:
        if line.count("=") != 1:
            raise ValueError("malformed checkpoint")
        key, value = line.split("=", 1)
        if key not in expected or key in fields:
            raise ValueError(f"unexpected or duplicate checkpoint: {key}")
        fields[key] = value
    if set(fields) != expected:
        raise ValueError("missing required native checkpoints")
    if fields["scope"] != "steam-native-win98-loopback-prerequisite" or fields["nonce"] != nonce:
        raise ValueError("log belongs to a different scope or trial nonce")
    if lines[-1] != "exit=0":
        raise ValueError("missing final success checkpoint")
    integer_fields = set(fields) - {"scope", "nonce"}
    if any(not re.fullmatch(r"0|-?[1-9][0-9]{0,9}", fields[key]) for key in integer_fields):
        raise ValueError("noncanonical or oversized numeric checkpoint")
    values = {key: int(fields[key]) for key in integer_fields}
    fixed = {"source.version": 1, "os.platform": 1, "os.major": 4, "os.minor": 10,
             "os.build-low": 2222, "winsock.version": 257, "resources.cleaned": 1,
             "prerequisite.checks-completed": 1, "steam.application-executed": 0,
             "steam.application-passed": 0, "exit": 0}
    if any(values[key] != value for key, value in fixed.items()):
        raise ValueError("target, cleanup, completion or explicit application boundary failed")
    if any(values[f"check.{name}"] != 1 for name in CHECKS):
        raise ValueError("native prerequisite contains a failed check")
    if not 1 <= values["loopback.server-port"] <= 65535 or not 1 <= values["winsock.high-version"] <= 65535:
        raise ValueError("invalid native port or Winsock version metadata")
    if values["roundtrip.bytes-each-direction"] != len(nonce) + 11:
        raise ValueError("nonce-bearing binary payload length mismatch")
    connect = values["connect.result"], values["connect.error"]
    if connect not in ((0, 0), (-1, 10035)):
        raise ValueError("nonblocking connect outcome is inconsistent")
    expected_errors = {"accept-empty-wouldblock": 10035, "recv-empty-wouldblock": 10035,
                       "connect-started": connect[1], "send-after-shutdown-error": 10058,
                       "closed-socket-error": 10038, "unmatched-cleanup-error": 10093}
    if any(values[f"error.{name}"] != expected_errors.get(name, 0) for name in CHECKS):
        raise ValueError("recorded socket error transition is inconsistent")
    return {"schema": "steam.win9x-socket-prerequisite-log-review.v1",
            "log_sha256": hashlib.sha256(data).hexdigest(), "log_size_bytes": len(data),
            "nonce": nonce, "complete_consistent_prerequisite_log": True,
            "check_count": len(CHECKS), "metadata_origin": "self-reported stopped guest log",
            "actual_executable_and_os_provenance_verified": False,
            "actual_process_exit_after_crt_verified": False, "native_probe_execution_verified": False,
            "steam_application_executed": False, "steam_application_passed": False,
            "remaining_evidence": ["receipt-bound staged executable and unchanged genuine dependencies",
                                   "actual Win98 SE IO.SYS/GOP guest and process observations",
                                   "owned process exit after CRT teardown"]}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--output", type=Path, help="new review file; existing files are refused")
    args = parser.parse_args()
    try:
        with args.log.open("rb") as stream:
            data = stream.read(64 * 1024 + 1)
        result = review(data, args.nonce)
        text = json.dumps(result, indent=2) + "\n"
        if args.output:
            with args.output.open("x", encoding="utf-8") as stream:
                stream.write(text)
        print(text, end="")
        return 0
    except (OSError, ValueError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
