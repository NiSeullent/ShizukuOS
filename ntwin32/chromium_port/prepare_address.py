#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze the three exact compile-gated address controls for an owned VM clone."""
import argparse
import datetime
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
NAMES = {"M98ADDR.DLL", "CHADDR.EXE", "CHASUIT.EXE"}


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(path):
    return {"path": str(path.resolve()), "sha256": sha(path)}


def prepare(receipt, pin, out):
    receipt = receipt.resolve(strict=True)
    if not receipt.is_relative_to(ROOT / "build") or sha(receipt) != pin:
        raise ValueError("pinned repository-local producer receipt required")
    built = json.loads(receipt.read_text())
    if (built.get("schema") != "win98modern.chromium-address-core.v1" or built.get("status") != "PASS"
            or set(built.get("artifacts", {})) != NAMES or built.get("native_executed") is not False
            or built.get("application_executed") is not False):
        raise ValueError("exact successful compile-only three-artifact receipt required")
    for name, digest in built["sources"].items():
        current = (ROOT / name).resolve(strict=True)
        frozen = (receipt.parent / "frozen" / name).resolve(strict=True)
        if (not current.is_relative_to(ROOT) or not frozen.is_relative_to(receipt.parent / "frozen")
                or sha(current) != digest or sha(frozen) != digest):
            raise ValueError("current or frozen corresponding source changed")
    for compiler in built["compilers"].values():
        if sha(Path(compiler["path"])) != compiler["sha256"]:
            raise ValueError("actual compiler changed")
    original = built["original_target"]
    target = Path(original["path"]).resolve(strict=True)
    if (not target.is_relative_to(ROOT / "build") or target.stat().st_size != original["bytes"]
            or sha(target) != original["sha256"]
            or original["sha256"] != "7335c4494009b24842f5a2f501afb136c6b30bb473a9731a48147ce69865d823"):
        raise ValueError("original target changed or has no exact candidate hash")
    files = []
    for name in sorted(NAMES):
        item = built["artifacts"][name]
        path = Path(item["path"]).resolve(strict=True)
        if (path != receipt.parent / name or path.stat().st_size != item["bytes"]
                or not 0 < item["bytes"] < 1024**2 or sha(path) != item["sha256"]
                or item.get("native_import_gate") != "PASS" or item.get("native_executed") is not False):
            raise ValueError("exact frozen classic Win98 native import-gated artifact required")
        files.append((name, path, item))
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        raise ValueError("fresh isolated repository build output required")
    # No output is made before every dependency and exact source binding passes.
    out.mkdir(parents=True)
    inputs = []
    for name, path, item in files:
        target = out / name
        shutil.copyfile(path, target)
        if sha(target) != item["sha256"]:
            raise ValueError("artifact changed during freezing")
        inputs.append({"source": str(target), "guest": "C:\\VXDLAB\\" + name,
                       "bytes": item["bytes"], "sha256": item["sha256"]})
    tool = out / "prepare_address.py"
    shutil.copyfile(Path(__file__), tool)
    prepared = {"schema": "win98modern.chromium-address-probe-preparation.v1", "status": "PREPARED",
                "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "native_executed": False, "application_executed": False,
                "producer": record(receipt), "tool": record(tool), "inputs": inputs,
                "native_acceptance": ["Fresh CHADDR.LOG reports all native event/thread/timeout controls successful.",
                                      "Fresh CHASUIT.LOG reports actual child wait success and exit zero without timeout/termination.",
                                      "The suite's own OS exit needs independent observation before claiming it."],
                "effects": ["Only this private DLL and two VXDLAB executables are staged on a new private clone.",
                            "The native suite creates, waits and closes one owned child.",
                            "The probe privately loads the owned address DLL, uses real events, joins three native workers and unloads after explicit cleanup.",
                            "Two fresh private VXDLAB reports are created; registry/system providers/drivers/app files are not changed."],
                "scope": "Native address-wait/API-contract substrate controls only; Chromium, Legcord, Office and Steam execution unproved."}
    path = out / "preparation.json"
    path.write_text(json.dumps(prepared, indent=2) + "\n")
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                "outputs": ["C:\\VXDLAB\\CHADDR.LOG", "C:\\VXDLAB\\CHASUIT.LOG"], "backups": [],
                "source_receipts": [record(receipt), record(path)], "command": "C:\\VXDLAB\\CHASUIT.EXE",
                "scope": prepared["scope"]}
    target = out / "manifest.json"
    target.write_text(json.dumps(manifest, indent=2) + "\n")
    return {"status": "PREPARED", "manifest": str(target), "sha256": sha(target),
            "input_count": len(inputs), "input_bytes": sum(item["bytes"] for item in inputs)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", required=True, type=Path)
    parser.add_argument("--build-sha", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.build_receipt, args.build_sha, args.out.resolve()), indent=2))


if __name__ == "__main__":
    main()
