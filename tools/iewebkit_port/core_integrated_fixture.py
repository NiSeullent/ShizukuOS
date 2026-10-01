#!/usr/bin/env python3
"""Freeze independent GUI IE/memory checks for one private IO.SYS/GOP boot.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
Creates bounded local files only; never starts or changes a guest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys

GUEST = re.compile(r"C:\\GOPLAB\\[A-Z0-9]{1,8}\.[A-Z0-9]{1,3}")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read(path: Path, expected: str) -> bytes:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1024 ** 2:
        raise ValueError("A bounded regular input is required: " + str(path))
    data = path.read_bytes()
    if digest(data) != expected:
        raise ValueError("Frozen input digest mismatch: " + str(path))
    return data


def create(ie_path: Path, ie_sha: str, memory_path: Path, memory_sha: str, output: Path) -> dict:
    ie = json.loads(read(ie_path, ie_sha))
    memory = json.loads(read(memory_path, memory_sha))
    if (ie.get("schema") != 1 or ie.get("kind") != "isolated-guest-file-inputs"
            or len(ie.get("inputs", [])) != 4 or len(ie.get("outputs", [])) != 5
            or not ie.get("requires_nic_absent") or not ie.get("requires_absent_guest_paths")
            or not re.fullmatch(r"83bd-ie-[0-9a-f]{32}", str(ie.get("nonce", "")))):
        raise ValueError("An exact independent fresh IE activation fixture is required")
    if (memory.get("schema") != "iewebkit-win9x-memory-gui-v1"
            or not memory.get("binary", {}).get("static_gate_passed")
            or memory["binary"]["pe"]["subsystem"] != 2):
        raise ValueError("The GUI memory probe must pass its native import gate")
    if output.exists() or output.is_symlink():
        raise ValueError("Preserve existing fixtures; choose a new private directory")
    files = {}
    for item in ie["inputs"]:
        if not GUEST.fullmatch(item["guest"]) or item["guest"] in files:
            raise ValueError("IE input path collision or scope error")
        path = Path(item["source"])
        if not path.resolve().is_relative_to(ie_path.parent.resolve()):
            raise ValueError("IE frozen input escaped its fixture directory")
        data = read(path, item["sha256"])
        if len(data) != item["bytes"]:
            raise ValueError("IE frozen input length mismatch")
        files[item["guest"]] = data
    for item in memory["inputs"].values():
        read(Path(item["path"]), item["sha256"])
    for item in ie["source_receipts"]:
        read(Path(item["path"]), item["sha256"])
    binary = memory["binary"]
    files["C:\\GOPLAB\\MEM9XG.EXE"] = read(Path(binary["path"]), binary["sha256"])
    provenance = {"source": memory["inputs"]["original_source"]["sha256"],
                  "header": memory["inputs"]["original_header"]["sha256"],
                  "binary": binary["sha256"], "receipt": memory_sha}
    files["C:\\GOPLAB\\MEMPROV.TXT"] = ("\r\n".join(provenance.values()) + "\r\n").encode("ascii")
    outputs = list(ie["outputs"]) + ["C:\\GOPLAB\\MEM9X.LOG"]
    if (len(files) > 8 or len(outputs) > 8 or len(set(outputs)) != len(outputs)
            or any(not GUEST.fullmatch(name) for name in outputs) or set(files) & set(outputs)):
        raise ValueError("Integrated input/output paths exceed fresh bounded scope")
    output.mkdir(parents=True, mode=0o700)
    inputs = []
    for guest, data in files.items():
        path = output / guest.rsplit("\\", 1)[1]
        path.write_bytes(data)
        inputs.append({"source": str(path.resolve()), "guest": guest,
                       "bytes": len(data), "sha256": digest(data)})
    manifest = dict(ie)
    manifest.update(inputs=inputs, outputs=outputs,
                    backups=["C:\\WINDOWS\\SYSTEM.DAT", "C:\\WINDOWS\\USER.DAT"],
                    source_receipts=ie["source_receipts"] + [
                        {"path": str(ie_path.resolve()), "sha256": ie_sha},
                        {"path": str(memory_path.resolve()), "sha256": memory_sha}],
                    memory_provenance=provenance,
                    commands={"memory": "C:\\GOPLAB\\MEM9XG.EXE " + ie["nonce"],
                              "ie": ie["command"]},
                    integrated_scope="Original IO.SYS/GOP boot, independent shared memory and actual IE handoff/cleanup diagnostics",
                    full_engine_or_renderer=False)
    path = output / "guest-files.json"
    raw = (json.dumps(manifest, indent=2) + "\n").encode()
    path.write_bytes(raw)
    return {"manifest": str(path.resolve()), "sha256": digest(raw), "nonce": ie["nonce"],
            "commands": manifest["commands"], "inputs": len(inputs), "outputs": len(outputs)}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ie-manifest", type=Path, required=True)
    parser.add_argument("--ie-sha256", required=True)
    parser.add_argument("--memory-receipt", type=Path, required=True)
    parser.add_argument("--memory-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(create(args.ie_manifest, args.ie_sha256, args.memory_receipt,
                                args.memory_sha256, args.output), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
