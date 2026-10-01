#!/usr/bin/env python3
"""Freeze digest-bound Win98/IE5 memory diagnostics for a new isolated clone.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
Creates local bounded inputs only; never launches a guest or changes its files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded_read(path: Path, limit: int = 1024 ** 2) -> bytes:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("input must be a bounded regular file: " + str(path))
    return path.read_bytes()


def create(probe: Path, probe_receipt: Path, bundle: Path, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("output exists; choose a new private fixture directory")
    native = bounded_read(probe)
    raw_receipt = bounded_read(probe_receipt)
    receipt = json.loads(raw_receipt)
    if (receipt.get("schema") != "iewebkit-win9x-core-memory-native-v1"
            or not receipt.get("static_gate_passed")
            or digest(native) != receipt.get("binary", {}).get("sha256")):
        raise ValueError("memory probe is not bound to its successful native build receipt")
    hashes = {"source": receipt["source"]["sha256"],
              "header": receipt["header"]["sha256"],
              "binary": digest(native), "receipt": digest(raw_receipt)}
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()):
        raise ValueError("source/header/binary/receipt require exact SHA-256 values")
    for name in ("source", "header"):
        if digest(bounded_read(Path(receipt[name]["path"]))) != hashes[name]:
            raise ValueError("memory " + name + " changed since its build receipt")
    if digest(bounded_read(Path(receipt["source_pin"]["path"]))) != receipt["source_pin"]["sha256"]:
        raise ValueError("memory source pin changed since its build receipt")
    target_receipt = bundle.parent / "build.json"
    raw_target_receipt = bounded_read(target_receipt)
    target_report = json.loads(raw_target_receipt)
    target = bounded_read(bundle / "IETARGET.EXE")
    required_target = {"os": "win98se", "os_version": "4.10.2222", "ie": "5.0",
                       "ie_version": "5.00.2614.3500", "arch": "x86", "mode": "classic"}
    if (target_report.get("schema") != "win98modern.iewebkit-build.v1"
            or not target_report.get("static_gate_passed")
            or target_report.get("target") != required_target
            or digest(target) != target_report["artifacts"]["IETARGET.EXE"]["sha256"]):
        raise ValueError("IETARGET is not bound to the exact Win98SE/IE5 host build")
    nonce = "83bd-memory-" + uuid.uuid4().hex
    command = "MEM9X.EXE C:\\GOPLAB\\MEM9X.LOG " + nonce + " C:\\GOPLAB\\MEMPROV.TXT"
    lines = ["@echo off", "cd \\GOPLAB", "IETARGET.EXE " + nonce,
             "if errorlevel 4 goto failed", "if errorlevel 3 goto targetok",
             "if errorlevel 1 goto failed", ":targetok", command, "if errorlevel 1 goto failed",
             "echo " + nonce + ">C:\\GOPLAB\\MEMDONE.TXT", "exit",
             ":failed", "echo failed-" + nonce + ">C:\\GOPLAB\\MEMFAIL.TXT", "exit"]
    files = {"IETARGET.EXE": target, "MEM9X.EXE": native,
             "MEMPROV.TXT": ("\r\n".join(hashes.values()) + "\r\n").encode("ascii"),
             "RUNMEM.BAT": ("\r\n".join(lines) + "\r\n").encode("ascii")}
    output.mkdir(parents=True, mode=0o700)
    inputs = []
    for name, data in files.items():
        path = output / name
        path.write_bytes(data)
        inputs.append({"source": str(path.resolve()), "guest": "C:\\GOPLAB\\" + name,
                       "bytes": len(data), "sha256": digest(data)})
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                "outputs": ["C:\\GOPLAB\\" + name for name in
                            ("IETARGET.LOG", "MEM9X.LOG", "MEMDONE.TXT", "MEMFAIL.TXT")],
                "source_receipts": [
                    {"path": str(target_receipt.resolve()), "sha256": digest(raw_target_receipt)},
                    {"path": str(probe_receipt.resolve()), "sha256": hashes["receipt"]}],
                "backups": [], "nonce": nonce, "probe_sha256": hashes["binary"],
                "probe_provenance": hashes, "target": required_target,
                "command": "C:\\COMMAND.COM /C C:\\GOPLAB\\RUNMEM.BAT",
                "requires_absent_guest_paths": True,
                "acceptance": "Fresh IETARGET target_matched=1/nonce and expected provider status; MEM9X nonce/provenance/exit=0; matching MEMDONE nonce; MEMFAIL absent. IETARGET exits 0 or expected provider-missing 3 are diagnostic only.",
                "acceptance_limit": "Shared Win9x memory API/accounting/policy probe; no WTF timer lifecycle, JSC/provider/rendering pass."}
    raw_manifest = (json.dumps(manifest, indent=2) + "\n").encode()
    path = output / "guest-files.json"
    path.write_bytes(raw_manifest)
    return {"manifest": str(path.resolve()), "sha256": digest(raw_manifest), "nonce": nonce,
            "command": manifest["command"], "probe_sha256": hashes["binary"]}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", type=Path, required=True)
    parser.add_argument("--probe-receipt", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(create(args.probe, args.probe_receipt, args.bundle, args.output), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
