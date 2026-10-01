#!/usr/bin/env python3
"""Freeze a new four-input GUI IE5 diagnostic package; starts no guest.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import sys
import uuid

ROOT = Path(__file__).resolve().parents[2]
TARGET = {"os": "win98se", "os_version": "4.10.2222", "ie": "5.0",
          "ie_version": "5.00.2614.3500", "arch": "x86", "mode": "classic"}


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def bounded(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= 1024 ** 2:
        raise ValueError("input must be a bounded regular file: " + str(path))
    return path.read_bytes()


def create(build: Path, output: Path) -> dict:
    if output.exists() or output.is_symlink():
        raise ValueError("output exists; choose a new private fixture directory")
    permitted = ROOT / "build/iewebkit-core-83bd"
    if not output.resolve().is_relative_to(permitted.resolve()):
        raise ValueError("output must be a private child of the core build area")
    if shutil.disk_usage(permitted).free < 20 * 1024 ** 3 + 3 * 1024 ** 2:
        raise ValueError("host free space is below the 20 GiB floor plus the fixture budget")
    receipt_path = build / "build.json"
    receipt_raw = bounded(receipt_path)
    receipt = json.loads(receipt_raw)
    if (receipt.get("schema") != "iewebkit-win98-ie5-activation-build-v1" or receipt.get("target") != TARGET
            or not receipt.get("static_gate_passed") or receipt.get("full_engine")
            or receipt.get("rendering_verified") or receipt.get("tls_verified")):
        raise ValueError("a successful exact-target diagnostic GUI build receipt is required")
    source = receipt["source"]
    if digest(bounded(Path(source["path"]))) != source["sha256"]:
        raise ValueError("IE GUI source changed after compilation")
    host = receipt["host_receipt"]
    host_raw = bounded(Path(host["path"]))
    host_receipt = json.loads(host_raw)
    if (digest(host_raw) != host["sha256"] or host_receipt.get("target") != TARGET
            or not host_receipt.get("diagnostic_handoff_included") or not host_receipt.get("static_gate_passed")
            or host_receipt.get("source_sha256") != receipt["host_source_sha256"]):
        raise ValueError("selected diagnostic host receipt changed")
    files = {}
    for name in ("IEACT.EXE", "IEWKHOST.DLL", "NAVBHO.DLL"):
        entry = receipt["artifacts"][name]
        data = bounded(build / "bundle" / name)
        if digest(data) != entry["sha256"] or not entry["static_gate_passed"]:
            raise ValueError("native artifact changed after compilation: " + name)
        if name == "IEACT.EXE" and entry["pe"]["subsystem"] != 2:
            raise ValueError("IE activation must be a GUI PE")
        if name.endswith(".DLL") and digest(data) != host_receipt["artifacts"][name]["sha256"]:
            raise ValueError("native DLL does not match its host snapshot receipt")
        files[name] = data
    hashes = {"source": source["sha256"], "binary": digest(files["IEACT.EXE"]),
              "host": digest(files["IEWKHOST.DLL"]), "bho": digest(files["NAVBHO.DLL"]),
              "host-receipt": host["sha256"], "receipt": digest(receipt_raw)}
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()):
        raise ValueError("provenance values must be exact SHA-256 digests")
    files["IEPROV.TXT"] = ("\r\n".join(hashes.values()) + "\r\n").encode("ascii")
    nonce = "83bd-ie-" + uuid.uuid4().hex
    command = "C:\\GOPLAB\\IEACT.EXE " + nonce + " C:\\GOPLAB\\IEPROV.TXT"
    output.mkdir(parents=True, mode=0o700)
    inputs = []
    for name, data in files.items():
        path = output / name
        path.write_bytes(data)
        inputs.append({"source": str(path.resolve()), "guest": "C:\\GOPLAB\\" + name,
                       "bytes": len(data), "sha256": digest(data)})
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": inputs,
                "outputs": ["C:\\GOPLAB\\" + name for name in
                            ("IEACT.LOG", "IENAV.LOG", "IEWIZ.BAK", "IEDONE.TXT", "IEFAIL.TXT")],
                "backups": [], "source_receipts": [
                    {"path": str(receipt_path.resolve()), "sha256": digest(receipt_raw)},
                    {"path": host["path"], "sha256": host["sha256"]}],
                "target": TARGET, "nonce": nonce, "probe_sha256": hashes["binary"],
                "probe_provenance": hashes, "command": command,
                "requires_absent_guest_paths": True, "requires_nic_absent": True,
                "guest_preconditions": ["All declared input and output paths absent before injection.",
                    "No preexisting iexplore.exe process; do not start another IE concurrently.",
                    "Both diagnostic CLSID keys, their own MIME mapping and BHO list key absent.",
                    "C:\\ZUKUQA\\IENAV.LOG absent; C:\\GOPLAB\\iewebkit-engine.dll absent.",
                    "Completed registry data at most 256 bytes, and HKCU Software\\Microsoft parent exists."],
                "guest_side_effects": [
                    "Bounded fresh file logs and one completion or failure marker in C:\\GOPLAB.",
                    "Exact Completed presence/type/raw bytes saved to IEWIZ.BAK before temporary REG_DWORD 1.",
                    "DllRegisterServer creates only the diagnostic DocObject CLSID/MIME and BHO CLSID/list keys.",
                    "Owned fresh C:\\ZUKUQA\\IENAV.LOG and directory if absent; copied to GOPLAB then removed after owned IE exit.",
                    "CoCreateInstance CLSID_InternetExplorer LOCAL_SERVER; visible new IWebBrowser2 navigation to HTTPS reserved.invalid with nonce.",
                    "Quit only the created browser, require its HWND and process to exit before unregistering and exact Completed restoration.",
                    "No engine provider, HTTP associations, synthetic page drawing or guest NIC is added."],
                "acceptance": "Fresh nonce and six provenance rows; target_matched=1; registration HRESULTs S_OK; owned unique IE HWND/PID; BHO attach/arm and DocObject Load/remote_https/show/engine_missing trace; owned exit; private registration keys absent; wizard before/after presence/type/data.hex equal; cleanup.verified=1 and exit=0; matching IEDONE; IEFAIL absent.",
                "acceptance_limit": "Actual IE5 activation/interception and cleanup diagnostic only. Provider, JavaScript execution, TLS, page rendering and full engine remain unverified.",
                "watchdog_limit": "COM calls are synchronous. A guest watchdog must treat an unfinished log, hung call or deferred cleanup as failure and discard the private clone.",
                "wizard_mapping_source": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gppref/3fb5c89d-d9c2-41e2-9749-f5cac492121e"}
    raw = (json.dumps(manifest, indent=2) + "\n").encode()
    path = output / "guest-files.json"
    path.write_bytes(raw)
    return {"manifest": str(path.resolve()), "sha256": digest(raw), "nonce": nonce, "command": command,
            "inputs": len(inputs), "outputs": len(manifest["outputs"]), "probe_sha256": hashes["binary"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(create(args.build, args.output), indent=2))
        return 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
