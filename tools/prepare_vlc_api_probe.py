#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze seven native API controls for the unchanged private guest-file guard."""
from __future__ import annotations
import argparse
import datetime
import hashlib
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {"M98VLC.DLL", "M98LOC.DLL", "M98CTX.DLL", "VLCAPI.EXE", "VLCLOC.EXE", "VLCCTX.EXE", "VLCSUITE.EXE"}
OUTPUTS = ["VLCAPI.LOG", "VLCLOC.LOG", "VLCCTX.LOG", "VLCSUITE.LOG", "VLCFILE.DAT"]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(path):
    return {"path": str(path.resolve()), "sha256": digest(path)}


def prepare(build_receipt, expected_sha, out):
    build_receipt = build_receipt.resolve(strict=True)
    if digest(build_receipt) != expected_sha:
        raise ValueError("selected producer receipt changed")
    document = json.loads(build_receipt.read_text())
    if (document.get("schema") != "win98modern.vlc-prerequisite-build.v1" or
            document.get("status") != "PASS" or set(document.get("artifacts", {})) != EXPECTED or
            document.get("native_execution") is not False or document.get("application_success") is not False):
        raise ValueError("successful exact seven-artifact compile-only receipt required")
    if not build_receipt.is_relative_to(ROOT / "build"):
        raise ValueError("repository-local producer receipt required")
    source_records = {}
    for name, pin in document["sources"].items():
        current = ROOT / name
        frozen = build_receipt.parent / "frozen" / name
        if not current.resolve().is_relative_to(ROOT) or digest(current) != pin or digest(frozen) != pin:
            raise ValueError("current/frozen build source differs")
        source_records[str(frozen)] = pin
    exports = document["native_exports"]
    if digest(Path(exports["path"])) != exports["sha256"]:
        raise ValueError("native OEM receipt changed")
    compiler = document["compiler"]
    if digest(Path(compiler["path"])) != compiler["sha256"]:
        raise ValueError("actual compiler changed")
    files = []
    for name in sorted(EXPECTED):
        artifact = document["artifacts"][name]
        path = Path(artifact["path"]).resolve(strict=True)
        if (path != build_receipt.parent / name or path.stat().st_size != artifact["bytes"] or
                not 0 < artifact["bytes"] <= 1024**2 or digest(path) != artifact["sha256"] or
                artifact.get("native_import_gate") != "PASS" or artifact.get("native_execution") is not False):
            raise ValueError("exact source-bound native import-gated artifact required")
        files.append((name, path, artifact))
    if sum(item[2]["bytes"] for item in files) > 1024**2:
        raise ValueError("bounded diagnostic total exceeded")
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        raise ValueError("new isolated repository output required")
    out.mkdir(parents=True)
    inputs = []
    for name, path, artifact in files:
        target = out / name
        shutil.copyfile(path, target)
        if digest(target) != artifact["sha256"]:
            raise ValueError("artifact changed while freezing")
        inputs.append({"source": str(target), "guest": "C:\\VXDLAB\\" + name,
                       "bytes": target.stat().st_size, "sha256": digest(target)})
    # This source is build-local frozen too; the guest runner has no reason to
    # execute it and sees only immutable byte identities via the JSON receipt.
    frozen_tool = out / "prepare_vlc_api_probe.py"
    shutil.copyfile(Path(__file__), frozen_tool)
    receipt = {"schema": "win98modern.vlc-native-probe-preparation.v1",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "status": "PREPARED",
               "native_execution": False, "application_success": False,
               "build_receipt": record(build_receipt), "native_exports": exports,
               "frozen_sources": source_records, "tool": record(frozen_tool),
               "input_count": len(inputs), "input_bytes": sum(i["bytes"] for i in inputs),
               "guest_command": "C:\\VXDLAB\\VLCSUITE.EXE",
               "native_acceptance": ["All three fresh probe logs report every expected control successful.",
                                     "Suite reports three actual child zero exits with no timeout/termination/error.",
                                     "Independent guest-file readback equals 13 bytes: VLC seek test.",
                                     "Owned temporary VLCFONT.TTF is absent after native removal/deletion."],
               "effects": ["Only seven listed VXDLAB DLL/EXE inputs are staged on a new owned clone.",
                           "Native tests create five listed private reports/data outputs.",
                           "Compat test temporarily copies system Arial into VXDLAB/VLCFONT.TTF, adds/removes that owned copy, then deletes it.",
                           "Suite creates/waits three owned child processes; timeout/nonzero remains failure, forced termination never success."],
               "limits": ["No existing Core, registry configuration, system driver or NPP provider is changed.",
                          "Successful controls are native API evidence only; VLC application launch/playback remains a separate gate.",
                          "NT LFH/heap termination and private/memory-font features remain explicitly unsupported."]}
    preparation = out / "preparation.json"
    preparation.write_text(json.dumps(receipt, indent=2) + "\n")
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                "outputs": ["C:\\VXDLAB\\" + name for name in OUTPUTS], "backups": [],
                "source_receipts": [record(build_receipt), record(preparation)],
                "command": receipt["guest_command"],
                "transient_files": [{"guest": "C:\\VXDLAB\\VLCFONT.TTF", "source": "C:\\WINDOWS\\FONTS\\ARIAL.TTF",
                                     "created_by": "native CopyFileA fail-if-exists", "expected_after_run": "absent"}],
                "scope": "Native OEM-backed VLC prerequisite API controls only; no actual VLC application acceptance."}
    path = out / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    return {"status": "PREPARED", "files": len(inputs), "bytes": receipt["input_bytes"],
            "manifest": str(path), "sha256": digest(path)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-receipt", type=Path, required=True)
    parser.add_argument("--build-sha", required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(prepare(args.build_receipt, args.build_sha, args.out.resolve()), indent=2))


if __name__ == "__main__":
    main()
