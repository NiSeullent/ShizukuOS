#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Rehash an existing stopped loader trial and compare its actual Signal runtime."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import re

ROOT = Path(__file__).resolve().parents[3]


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(block)
    return checksum.hexdigest()


def load(path):
    return json.loads(Path(path).read_text())


def require(value, reason):
    if not value:
        raise ValueError(reason)


def bound(path):
    path = Path(path).resolve(strict=True)
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": digest(path)}


def normalized(command, image):
    return [item.replace(image, "<app-image>")
            .replace(str(ROOT / "build/lp64-run-v1"), "<run>")
            .replace(str(ROOT / "build/modern-required-apps-6970/signal-memory-themed-1024-run-v1"), "<run>")
            for item in command]


def audit(out):
    spec = importlib.util.spec_from_file_location("stopped_loader_trial", ROOT / "tools/win64_memory_loader_probe_trial.py")
    trial = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(trial)
    require(not out.exists() and out.parent.resolve().is_relative_to(ROOT / "build"), "new owned build output required")
    preparation = ROOT / "build/lp64-prep-v1/prepared.json"
    prepared, overlay = trial.verified_preparation(preparation)
    run = ROOT / "build/lp64-run-v1"
    receipt = load(run / "loader-diagnostic.json")
    serial = (run / "serial.log").read_text()
    evidence = trial.parse_evidence(serial, prepared["nonce"], prepared["candidate_bytes"])
    require(evidence == receipt["evidence"] and evidence["status"] == "PASS", "reparsed diagnostic differs")
    require(receipt["original_and_sealed_inputs_preserved"], "original receipt preservation failed")
    signal = ROOT / "build/modern-required-apps-6970/signal-memory-themed-1024-run-v1"
    ls, ss = load(run / "runtime-seal.json"), load(signal / "runtime-seal.json")
    inputs = {}
    for key in ("boot_stub", "kernel", "qemu", "win64_initrd"):
        rows = [ls["sealed_runtime_input_hashes"][key], ss["sealed_runtime_input_hashes"][key]]
        actual = [bound(row["path"]) for row in rows]
        require(all(row["bytes"] == actual[i]["bytes"] and row["sha256"] == actual[i]["sha256"]
                    and bound(row["source_path"])["sha256"] == row["sha256"] for i, row in enumerate(rows)),
                "sealed/source runtime changed")
        require(actual[0]["sha256"] == actual[1]["sha256"], "Signal/probe runtime differs")
        inputs[key] = {"identical": True, "actual": actual}
    fw = {}
    require(set(ls["sealed_firmware"]["files"]) == set(ss["sealed_firmware"]["files"]), "firmware member set differs")
    for name, row in ls["sealed_firmware"]["files"].items():
        peer = ss["sealed_firmware"]["files"][name]
        actual = [bound(row["path"]), bound(peer["path"])]
        require(all(item["sha256"] == row["sha256"] and item["bytes"] == row["bytes"] for item in actual)
                and peer["sha256"] == row["sha256"] and bound(row["source_path"])["sha256"] == row["sha256"], "firmware changed/differs")
        fw[name] = {"identical": True, "sha256": row["sha256"], "bytes": row["bytes"]}
    require(ls["runtime_source_hashes"] == ss["runtime_source_hashes"], "peer source bindings differ")
    for name, checksum in ls["runtime_source_hashes"].items():
        require(digest(Path(prepared["runtime_worktree"]) / name) == checksum, "peer source changed")
    require(trial.handoff.sealed_firmware_preserved(ls["sealed_firmware"])
            and trial.handoff.sealed_firmware_preserved(ss["sealed_firmware"]), "firmware directory changed")
    lr, sr = load(run / "result.json"), load(signal / "result.json")
    lc = receipt["resource_guard"]["actual_qemu_command"]
    sc = sr["actual_qemu_command"]
    require(normalized(lc, prepared["image"]["path"]) == normalized(sc, sr["image"]), "machine flags differ after run/image path normalization")
    guard = receipt["resource_guard"]
    require(guard["termination_reason"] is None and guard["reserve_bytes"] == 20 * 1024**3
            and guard["minimum_free_bytes"] >= guard["reserve_bytes"]
            and guard["write_budget_bytes"] == 256 * 1024**2 and guard["peak_written_bytes"] <= guard["write_budget_bytes"]
            and guard["stderr_budget_bytes"] == 16 * 1024**2, "resource guards failed")
    require((run / "serial.log").stat().st_size + (run / "qemu-host-output.log").stat().st_size <= guard["stderr_budget_bytes"], "own output exceeds bound")
    require(any(row["target"] == "/dev/kvm" for row in guard["kvm_fd_evidence"])
            and any("kvm-vm" in row["target"] for row in guard["kvm_fd_evidence"]), "genuine owned KVM descriptors missing")
    require(all(not (Path("/proc") / str(row["pid"])).exists() for row in guard["kvm_fd_evidence"]), "owned QEMU still running")
    require(receipt["host_qemu_return_code"] == 1 and lr["exit_code"] == 0 and lr["faulted"] == 0
            and re.fullmatch(r"K64 autorun: result exited exit=0 faulted=0 reaped=0 after \d+ ms", lr["autorun_result"]),
            "host ISA exit/process exit semantics differ")
    archive = Path(ls["sealed_runtime_input_hashes"]["win64_initrd"]["path"]).read_bytes()
    members = trial.theme.parse_archive(archive)
    actual_candidate = [raw for name, raw in members if name.upper().endswith("\\SYS64\\KERNELBASE.DLL")]
    require(len(members) == 143 and len(actual_candidate) == 1
            and hashlib.sha256(actual_candidate[0]).hexdigest() == prepared["candidate_sha256"], "actual archive candidate differs")
    require(trial.common.pe_gate(Path(prepared["executable"]["path"]), archive) == prepared["pe_gate"], "actual executable import gate differs")
    signal_serial = (signal / "serial.log").read_text()
    require("kernelbase.dll: DLL not found" in signal_serial and sr["qemu_timed_out"] and sr["exit_code"] is None, "retained Signal outcome differs")
    report = {"schema": 1, "stage": "stopped-loader-order-trial-preservation-and-runtime-comparison", "status": "PASS",
        "audit_recipe": bound(__file__), "probe_receipt": bound(run / "loader-diagnostic.json"), "probe_serial": bound(run / "serial.log"),
        "preparation": bound(preparation), "signal_receipt": bound(signal / "extension-runtime-result.json"),
        "signal_serial": bound(signal / "serial.log"), "preserved_inputs": trial.preserved_inputs(),
        "actual_runtime_inputs": inputs, "identical_firmware": fw, "runtime_source_hashes": ls["runtime_source_hashes"],
        "loader_probe_source_hashes": prepared["source_hashes"], "probe_actual_command": lc, "signal_actual_command": sc,
        "machine_flags_identical_after_private_path_normalization": True, "ram_mib": 1024,
        "application_payload_command_line_tree_image_child_timeout_differ": True,
        "diagnostic": evidence, "resource_guard": guard, "own_qemu_pid_absent": True,
        "host_qemu_return_code": 1, "host_exit_semantics": "isa-debug-exit guest value zero encodes host return code 1; actual child exit is separately zero",
        "interpretation": "The exact missing fibers contract followed by SYSTEM32 ExW/ExA and plain/absolute KERNELBASE loads before file inspection succeeds in this isolated child. This sequence does not reproduce the retained Signal load failure; application context remains unresolved.",
        "signal_app_functionality_verified": False, "native_windows98_execution_verified": False, "full_modern_memory_api_verified": False}
    require(len(json.dumps(report)) < 48 * 1024, "audit output exceeds bound")
    out.mkdir()
    trial.handoff.write_json(out / "audit.json", report)
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        result = audit(args.out.resolve())
        print(json.dumps({"status": result["status"], "output": str(args.out / "audit.json")}))
    except Exception as error:
        print(json.dumps({"status": "FAIL", "error": str(error)}))
        raise SystemExit(1)
