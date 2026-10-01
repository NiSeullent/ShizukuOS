#!/usr/bin/env python3
"""Freeze two genuine compiled socket diagnostics; start no VM or process."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import sys
import uuid

import steam_win9x_socket_probe_build as base

PROBE_BUILD = base.ROOT / "build/steam-socket-prerequisite-83bd/pe-v1"
PROBE_RECEIPT_SHA = "7e4710467f54f27b6096888c9ebaea0d483e18364b504690bad0afd687799849"
PROBE_BINARY_SHA = "9eeae77105b2474b51f8e95915a8f2df90d5c90fb0ede55ea3cd36989ba042ea"
IO_SHA = "1df17834b5c7744a3af92c20e4edaa8e0fdb78eca6da7a01db3538d59b2d1430"


def freeze(observer_build: Path, output: Path) -> dict:
    observer_build = observer_build.resolve()
    output = output.absolute()
    if output.exists() or output.is_symlink() or output.resolve() != output:
        raise ValueError("preserve old fixtures; select a new private nonsymlink output")
    if not output.is_relative_to(base.ROOT / "build"):
        raise ValueError("fixture output must remain below the checkout's build directory")
    if shutil.disk_usage(base.ROOT).free < base.START_FREE:
        raise ValueError("preserve the unchanged 20 GiB floor and tiny-output margin")
    probe_receipt_path = PROBE_BUILD / "receipt.json"
    if base.file_record(probe_receipt_path)["sha256"] != PROBE_RECEIPT_SHA:
        raise ValueError("the original successful probe receipt changed")
    if base.file_record(PROBE_BUILD / "SPROB.EXE")["sha256"] != PROBE_BINARY_SHA:
        raise ValueError("the original genuine probe binary changed")
    origins = {}
    builds = []
    for label, folder, schema, name in (
        ("probe", PROBE_BUILD, "steam.win9x-socket-prerequisite-build.v1", "SPROB.EXE"),
        ("observer", observer_build, "steam.win9x-socket-owned-observer-build.v1", "SPWAIT.EXE"),
    ):
        receipt_path = folder / "receipt.json"
        receipt = json.loads(receipt_path.read_text())
        if (receipt.get("schema") != schema or not receipt.get("source_and_static_gate_passed") or
            not receipt.get("inputs_unchanged_after_build") or receipt.get("compiler_exit") != 0 or
            receipt.get("steam_application_passed") is not False):
            raise ValueError("actual successful source/import build receipt is required")
        binary_record = receipt["pe_audit"]["binary"]
        binary = folder / name
        if base.file_record(binary) != binary_record:
            raise ValueError("compiled diagnostic differs from its exact receipt")
        source_records = receipt["source_inputs"]
        records = [*source_records, receipt["actual_header_inventory"], receipt["build_log"],
                   base.file_record(receipt_path), binary_record]
        if base.file_record(Path(receipt["compiler"]["path"]))["sha256"] != receipt["compiler"]["sha256"]:
            raise ValueError("actual compiler provenance changed")
        # Validate the actual transitive headers again; their frozen inventory is
        # copied below. The complete implicit static archive closure is unverified.
        headers = json.loads(Path(receipt["actual_header_inventory"]["path"]).read_text())
        if len(headers) != receipt["actual_header_count"]:
            raise ValueError("actual header inventory count changed")
        for row in headers:
            if base.file_record(Path(row["path"])) != row:
                raise ValueError("actual header input changed since compilation")
        for index, row in enumerate(records):
            original = Path(row["path"])
            if base.file_record(original) != row:
                raise ValueError("actual source/build/header input changed")
            key = str(original)
            if key not in origins:
                if original == binary:
                    destination = output / name
                else:
                    destination = output / "receipts" / f"{label}-{index:02d}-{original.name}"
                origins[key] = {"record": row, "destination": destination, "data": original.read_bytes()}
        builds.append({"label": label, "name": name, "binary": binary, "receipt": receipt_path})
    total = sum(len(value["data"]) for value in origins.values())
    if total > base.OUTPUT_CAP - 64 * 1024:
        raise ValueError("bounded frozen fixture exceeds its 8 MiB allowance")
    output.mkdir(parents=True, mode=0o700)
    (output / "receipts").mkdir()
    input_rows, receipts, bindings = [], [], []
    for original, value in origins.items():
        row, destination = value["record"], value["destination"]
        destination.write_bytes(value["data"])
        if base.file_record(Path(original)) != row or base.file_record(destination)["sha256"] != row["sha256"]:
            raise ValueError("origin or frozen copy changed while freezing")
        bindings.append({"origin": original, "frozen": str(destination), "sha256": row["sha256"]})
        if destination.parent == output:
            input_rows.append({"source": str(destination), "guest": "C:\\GOPLAB\\" + destination.name,
                               "bytes": len(value["data"]), "sha256": row["sha256"]})
        else:
            receipts.append({"path": str(destination), "sha256": row["sha256"]})
    if {row["guest"] for row in input_rows} != {r"C:\GOPLAB\SPROB.EXE", r"C:\GOPLAB\SPWAIT.EXE"}:
        raise ValueError("fixture must contain exactly the two native diagnostic inputs")
    nonce = "83bd-steam-socket-" + uuid.uuid4().hex
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": input_rows,
                "outputs": [r"C:\GOPLAB\SPROB.LOG", r"C:\GOPLAB\SPWAIT.LOG"], "backups": [],
                "source_receipts": receipts, "source_receipt_origins": bindings, "nonce": nonce,
                "command": r"C:\GOPLAB\SPWAIT.EXE " + nonce, "probe_sha256": PROBE_BINARY_SHA,
                "requires_absent_guest_paths": True, "requires_nic_absent": True,
                "required_guest_input_limit_bytes": 1024**2,
                "target": {"os": "win98se", "os_version": "4.10.2222", "arch": "x86",
                           "boot": "actual IO.SYS UEFI/GOP native Windows 98",
                           "original_io_sys_sha256": IO_SHA}, "post_crt_exit_required": True,
                "native_observer_executed": False, "native_probe_execution_verified": False,
                "actual_socket_semantics_verified": False, "steam_application_executed": False,
                "steam_application_passed": False,
                "acceptance": "Require actual IO.SYS/GOP process/module provenance, never-reused bound nonce, all genuine "
                              "SPROB checks plus cleaned resources, and SPWAIT owned child signaled/query/zero post-CRT exit. "
                              "Log text alone does not prove native execution; socket prerequisite never proves Steam.",
                "capability_limits": {"network": "only real IPv4 loopback; no guest NIC or remote endpoint",
                                      "provider": "genuine 32-bit Win98 WSOCK32 prerequisite; no Win64 provider equivalence",
                                      "implicit_static_archive_closure": "not independently frozen by these small build receipts"}}
    manifest_path = output / "guest-files.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    if base.output_size(output) > base.OUTPUT_CAP or shutil.disk_usage(output).free < base.FLOOR:
        raise ValueError("post-freeze output/reserve gate failed; preserve retained evidence")
    return {"manifest": str(manifest_path), "sha256": base.file_record(manifest_path)["sha256"],
            "nonce": nonce, "command": manifest["command"], "input_count": len(input_rows),
            "source_receipt_count": len(receipts), "output_size_bytes": base.output_size(output),
            "native_probe_execution_verified": False, "steam_application_passed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observer-build", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        print(json.dumps(freeze(args.observer_build, args.output), indent=2))
        return 0
    except (OSError, ValueError, KeyError) as error:
        print(str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
