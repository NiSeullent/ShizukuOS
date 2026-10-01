#!/usr/bin/env python3
"""Combine digest-bound independent GUI fixtures without running a guest.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
Requires private filesystem COW copies. Total inputs remain bounded to64MiB.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build"
GUEST = re.compile(r"C:\\GOPLAB\\[A-Z0-9]{1,8}\.[A-Z0-9]{1,3}")


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 ** 2), b""):
            result.update(block)
    return result.hexdigest()


def bound(path: Path, expected: str, limit: int) -> Path:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("A bounded regular file is required: " + str(path))
    path = path.resolve()
    if not path.is_relative_to(BUILD) or digest(path) != expected:
        raise ValueError("Frozen build path or digest mismatch: " + str(path))
    return path


def create(fixtures: list[list[str]], output: Path) -> dict:
    if not 1 <= len(fixtures) <= 2 or output.exists() or output.is_symlink():
        raise ValueError("Select at most2 independent fixtures and a new output directory")
    if not output.resolve().is_relative_to(BUILD):
        raise ValueError("Combined fixtures must remain in private build storage")
    files, outputs, receipts, lanes = {}, [], {}, []
    total = 0
    for selected, expected in fixtures:
        manifest = bound(Path(selected), expected, 256 * 1024)
        data = json.loads(manifest.read_text())
        if (data.get("schema") != 1 or data.get("kind") != "isolated-guest-file-inputs"
                or not data.get("requires_absent_guest_paths") or not data.get("requires_nic_absent")
                or not 1 <= len(data["inputs"]) <= 8 or len(data["outputs"]) > 8):
            raise ValueError("An independent fresh offline GUI fixture is required")
        receipts[str(manifest)] = expected
        for item in data["source_receipts"]:
            receipt = bound(Path(item["path"]), item["sha256"], 1024 ** 2)
            if str(receipt) in receipts and receipts[str(receipt)] != item["sha256"]:
                raise ValueError("Conflicting source receipt digests")
            receipts[str(receipt)] = item["sha256"]
        for item in data["inputs"]:
            guest = item["guest"]
            if not GUEST.fullmatch(guest) or guest in files:
                raise ValueError("Input scope or collision")
            source = bound(Path(item["source"]), item["sha256"], 64 * 1024 ** 2)
            if not source.is_relative_to(manifest.parent) or source.stat().st_size != item["bytes"]:
                raise ValueError("Input escaped its frozen fixture or changed length")
            total += item["bytes"]
            files[guest] = dict(item, source=str(source))
        for guest in data["outputs"]:
            if not GUEST.fullmatch(guest) or guest in outputs:
                raise ValueError("Output scope or collision")
            outputs.append(guest)
        lanes.append({"manifest": str(manifest), "sha256": expected, "nonce": data["nonce"],
                      "command": data["command"], "acceptance": data["acceptance"],
                      "source_provenance": data.get("probe_provenance"),
                      "protocol_component_acceptance": data.get("protocol_component_acceptance"),
                      "expected_absent_engine_result": data.get("expected_absent_engine_result")})
    if total > 64 * 1024 ** 2 or len(files) > 8 or len(outputs) > 8 or set(files) & set(outputs):
        raise ValueError("Combined input/output or64MiB total bound exceeded")
    output.mkdir(parents=True, mode=0o700)
    inputs = []
    for guest, item in files.items():
        source = Path(item["source"])
        destination = output / guest.rsplit("\\", 1)[1]
        subprocess.run(["cp", "--reflink=always", "--sparse=auto", "--", str(source), str(destination)], check=True)
        if destination.stat().st_ino == source.stat().st_ino or destination.stat().st_nlink != 1:
            raise ValueError("The frozen input must have a distinct private inode")
        bound(destination, item["sha256"], 64 * 1024 ** 2)
        bound(source, item["sha256"], 64 * 1024 ** 2)
        inputs.append(dict(item, source=str(destination.resolve())))
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                "outputs": outputs, "source_receipts": [{"path": path, "sha256": value} for path, value in receipts.items()],
                "backups": ["C:\\WINDOWS\\SYSTEM.DAT", "C:\\WINDOWS\\USER.DAT"],
                "requires_absent_guest_paths": True, "requires_nic_absent": True,
                "required_guest_input_limit_bytes": 64 * 1024 ** 2,
                "total_input_bytes": total, "lanes": lanes,
                "acceptance_limit": "Separate native component verdicts. No JSC/provider/TLS/page-rendering pass is implied."}
    path = output / "guest-files.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return {"manifest": str(path.resolve()), "sha256": digest(path), "inputs": len(inputs),
            "outputs": len(outputs), "total_input_bytes": total, "lanes": lanes}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixture", nargs=2, action="append", required=True, metavar=("PATH", "SHA256"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(create(args.fixture, args.output), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
