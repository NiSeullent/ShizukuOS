#!/usr/bin/env python3
"""Freeze new private GUI IE5 protocol telemetry; starts no guest.

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
    if (receipt.get("schema") != "iewebkit-win98-ie5-protocol-build-v1" or receipt.get("target") != TARGET
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
            or host_receipt.get("source_sha256") != receipt["original_host_source_sha256"]):
        raise ValueError("selected diagnostic host receipt changed")
    for name in ("source_origin", "builder", "builder_dependency", "patch", "pin"):
        entry = receipt[name]
        if digest(bounded(Path(entry["path"]))) != entry["sha256"]:
            raise ValueError("build input changed: " + name)
    pin = json.loads(bounded(Path(receipt["pin"]["path"])))
    if (pin.get("schema") != "iewebkit-win98-ie5-protocol-source-pin-v1"
            or pin["patch"]["sha256"] != receipt["patch"]["sha256"]
            or pin["original_host_receipt"]["sha256"] != host["sha256"]
            or not receipt.get("unchanged_DocObject_DLL") or not receipt.get("DocObject_Load_acceptance_preserved")):
        raise ValueError("telemetry source pins or unchanged DocObject binding failed")
    private = Path(receipt["private_host_source"])
    for relative, expected in receipt["private_host_source_sha256"].items():
        if digest(bounded(private / relative)) != expected:
            raise ValueError("private patched host snapshot changed: " + relative)
    for relative, expected in pin["source"].items():
        if (receipt["original_host_source_sha256"][relative] != expected["before_sha256"]
                or receipt["private_host_source_sha256"][relative] != expected["after_sha256"]):
            raise ValueError("before/after source hash mismatch")
    files = {}
    for name in ("IEACT.EXE", "IEWKHOST.DLL", "NAVBHO.DLL"):
        entry = receipt["artifacts"][name]
        data = bounded(build / "bundle" / name)
        if digest(data) != entry["sha256"] or not entry["static_gate_passed"]:
            raise ValueError("native artifact changed after compilation: " + name)
        if name == "IEACT.EXE" and entry["pe"]["subsystem"] != 2:
            raise ValueError("IE activation must be a GUI PE")
        if name == "IEWKHOST.DLL" and digest(data) != host_receipt["artifacts"][name]["sha256"]:
            raise ValueError("native DLL does not match its host snapshot receipt")
        files[name] = data
    hashes = {"source": source["sha256"], "binary": digest(files["IEACT.EXE"]),
              "host": digest(files["IEWKHOST.DLL"]), "bho": digest(files["NAVBHO.DLL"]),
              "host-receipt": host["sha256"], "patch": receipt["patch"]["sha256"],
              "pin": receipt["pin"]["sha256"], "receipt": digest(receipt_raw)}
    if any(not re.fullmatch(r"[0-9a-f]{64}", value) for value in hashes.values()):
        raise ValueError("provenance values must be exact SHA-256 digests")
    files["IEPROV.TXT"] = ("\r\n".join(hashes.values()) + "\r\n").encode("ascii")
    nonce = "83bd-protocol-" + uuid.uuid4().hex
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
                            ("IEACT.LOG", "IENAV.LOG", "IEWIZ.BAK", "IEDONE.TXT", "IEFAIL.TXT", "IPROTO.TXT")],
                "backups": [], "source_receipts": [
                    {"path": str(receipt_path.resolve()), "sha256": digest(receipt_raw)},
                    {"path": host["path"], "sha256": host["sha256"]},
                    {"path": receipt["patch"]["path"], "sha256": receipt["patch"]["sha256"]},
                    {"path": receipt["pin"]["path"], "sha256": receipt["pin"]["sha256"]}],
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
                "acceptance": "Unchanged overall DocObject criterion: fresh nonce and eight provenance rows; target_matched=1; registration S_OK; unique owned IE HWND/PID; BHO attach/arm and Document.Load/remote_https/show/engine_missing; owned exit and exact cleanup; exit=0; matching IEDONE; IEFAIL absent.",
                "protocol_component_acceptance": "Independently inspect the returned IENAV trace: one per-Start ID must carry the exact fresh URL and nonce, attached same-thread exact pending match, no PI_PARSE_URL, actual successful GetBindInfo GET/zero body/TYMED_NULL, eligible=1/delegated=0, pending 1-to-0 before sink callbacks, actual CLSID report HRESULT and final return/aborted state. IEACT must report protocol.ingress.verified=1; matching IPROTO must exist only after owned shutdown and cleanup.verified=1, exact wizard restoration and absent diagnostic keys. Eight provenance rows and every returned log/marker must bind to the manifest. Report callback errors remain errors.",
                "expected_absent_engine_result": "The unchanged DocObject can fail Show before Load. IE exit=29 and matching IEFAIL are then the required preserved overall failure, even if the separate protocol ingress component is verified. Missing Document.Load/remote_https means DocObject URL ingress remains unverified. A protocol component marker does not turn exit29 into an overall pass.",
                "acceptance_limit": "Actual IE5 protocol ingress component and cleanup diagnostic only; unchanged DocObject Load acceptance is independent. Provider, JavaScript execution, TLS, page rendering and full engine remain unverified.",
                "source_patch": receipt["patch"], "source_pin": receipt["pin"],
                "DocObject_Load_acceptance_preserved": True, "protocol_ingress_verified": False,
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
