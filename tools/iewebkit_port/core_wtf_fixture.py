#!/usr/bin/env python3
"""Freeze the real-WTF GUI caller and its exact static/source receipts.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
No guest is started and no native execution is claimed.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import uuid
import shutil

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError("Preserve the existing frozen guest inputs")
    receipt_path = args.native / "WTFNAT.receipt.json"
    receipt = json.loads(receipt_path.read_text())
    binary = args.native / "WTFNAT.EXE"
    if (not receipt.get("link_provenance_passed")
        or not receipt["binary"].get("provenance_gate_passed")
        or not receipt["binary"]["static_gate_passed"]
        or digest(binary) != receipt["binary"]["sha256"]
        or receipt["binary"]["absent_from_media_export_baseline"]
        or digest(Path(receipt["source"])) != receipt["source_sha256"]
        or receipt["binary"]["pe"]["subsystem"] != 2):
        raise ValueError("Use a GUI PE with its exact passing whole-linked-import receipt")
    diagnostic = bool(receipt.get("diagnostic_scope"))
    if diagnostic and not receipt.get("abort_wrapper_audit", {}).get("passed"):
        raise ValueError("The diagnostic caller requires actual COFF abort routing disassembly")
    runtime = receipt["runtime"]
    from core_build import runtime_link_input
    runtime_object, current_runtime = runtime_link_input(Path(runtime["receipt"]).parent)
    if current_runtime != runtime:
        raise ValueError("Paired genuine runtime source/components changed after the passing link")
    if digest(Path(runtime["receipt"])) != runtime["receipt_sha256"] or digest(runtime_object) != runtime["object_sha256"]:
        raise ValueError("Private genuine GCC runtime changed after the passing link")
    for row in receipt["immutable_link_inputs"]:
        if digest(Path(row["path"])) != row["sha256"]:
            raise ValueError("An actual source/runtime/compiler link input changed before fixture freezing")
    if shutil.disk_usage(args.native).free < 20 * 1024**3 + 4 * 1024**2:
        raise ValueError("Preserve the 20 GiB hard floor plus a bounded frozen-receipt margin")
    args.output.mkdir(parents=True)
    frozen = args.output / "WTFNAT.EXE"
    subprocess.run(["cp", "--reflink=always", "--sparse=auto", str(binary), str(frozen)], check=True)
    if frozen.stat().st_ino == binary.stat().st_ino or digest(frozen) != receipt["binary"]["sha256"]:
        raise ValueError("Require a distinct, byte-exact private COW input copy")
    nonce = "83bd-wtf-" + uuid.uuid4().hex
    command = "C:\\GOPLAB\\WTFNAT.EXE C:\\GOPLAB\\WTFNAT.LOG " + nonce
    assert len(command) <= 126
    source_inputs = [receipt_path, Path(runtime["receipt"]), HERE / "core_runtime_pin.json",
                     HERE / "core_optional_api_pin.json", HERE / "core_statistics_pin.json",
                     HERE / "core_memory_pin.json", HERE / "source-pin.json", HERE / "core_profile.json",
                     HERE / "core_allocator_pin.json", HERE / "core_runtime_link_pin.json",
                     HERE / "core_runtime_link.cmake", HERE / "core_wtf_native.cpp",
                     HERE / "core_runtime_build.py", HERE / "core_build.py",
                     HERE / "runtime/gcc-15.1.1-atexit_thread.cc", HERE / "runtime/gcc-15.1.1-emutls.c",
                     HERE / "patches/core-gcc-15.1.1-win9x-thread-atexit.patch",
                     HERE / "patches/core-gcc-15.1.1-win9x-emutls.patch",
                     HERE / "patches/core-win9x-allocator-tls-and-crypto.patch"]
    if diagnostic:
        source_inputs += [Path(receipt["source"]), HERE / "src/core_Win9xDiagnosticLog.h"]
        source_inputs += [Path(row["log"]) for row in receipt["abort_wrapper_audit"]["symbols"]]
    runtime_pin = json.loads((HERE / "core_runtime_pin.json").read_text())
    source_inputs.append(Path(runtime_pin["companion"]["extraction_receipt"]["path"]))
    snapshots = receipt["thin_archive_snapshots"]
    if len(snapshots["pre"]) != 2 or len(snapshots["post"]) != 2:
        raise ValueError("Require complete WTF/allocator and bmalloc pre/post member snapshots")
    for snapshot in snapshots["pre"] + snapshots["post"]:
        path = Path(snapshot["receipt"])
        if digest(path) != snapshot["sha256"]:
            raise ValueError("Genuine linked member snapshot changed after the passing link")
        source_inputs.append(path)
    receipts_dir = args.output / "receipts"
    receipts_dir.mkdir()
    frozen_receipts = []
    origins = []
    for source_input in source_inputs:
        copy = receipts_dir / source_input.name
        if copy.exists():
            raise ValueError("Distinct frozen receipt origins must have distinct filenames")
        copy.write_bytes(source_input.read_bytes())
        frozen_receipts.append({"path": str(copy.resolve()), "sha256": digest(copy)})
        origins.append({"origin": str(source_input.resolve()), "frozen": str(copy.resolve()), "sha256": digest(copy)})
    for row in receipt["immutable_link_inputs"]:
        if digest(Path(row["path"])) != row["sha256"]:
            raise ValueError("Actual inputs changed during frozen source/receipt copying")
    manifest = {"schema": 1, "kind": "isolated-guest-file-inputs",
        "inputs": [{"source": str(frozen.resolve()), "guest": "C:\\GOPLAB\\WTFNAT.EXE",
                    "bytes": frozen.stat().st_size, "sha256": digest(frozen)}],
        "outputs": ["C:\\GOPLAB\\WTFNAT.LOG"] + (["C:\\GOPLAB\\WTFABRT.LOG"] if diagnostic else []), "backups": [],
        "source_receipts": frozen_receipts, "source_receipt_origins": origins,
        "nonce": nonce, "probe_sha256": digest(frozen), "command": command,
        "requires_absent_guest_paths": True, "requires_nic_absent": True,
        "required_guest_input_limit_bytes": 64 * 1024 * 1024,
        "target": {"os": "win98se", "os_version": "4.10.2222", "arch": "x86"},
        "acceptance": "Exact frozen PE/receipts, freshnonce, os.exact-target=1, wtf.initialize=1, realmainRunLoop current,96crossworkerdispatches, timerfired/no deadline, ownedworkerjoined, realWTFworkercontext, liveC++TLScleanup/destructor-time64cellgrowth/newdestructorchain, publicmemorymonitorstopped andexit=0. Require external ownedprocess observer for actualpostCRTzeroexit; callerlog alone does not prove process teardown.",
        "capability_limits": {"engine": "ActualWTF+allocator+ICU+GCCruntimecaller only; noJSCexecution/provider/rendering", "diagnostic_stack_trace": "NativeRTLstackcapture unavailable returns0frames", "signals": "C_LOOP/JIT_OFF/WASM_OFF requiresnonoVEhandlers; requestingunavailableAPI aborts", "dll_tls_lifetime": "MainEXEprocesslifetime covered; separateDLLrefcountvalidation remainsunverified"},
        "log_scope": "Beforeengineinitialization logs exactOS/freshnonce andCryptAcquireContextW/A realresult+last-error, so native API stub/earlyabort remains visible."
    }
    if diagnostic:
        manifest["diagnostic_scope"] = receipt["diagnostic_scope"]
        manifest["log_scope"] = ("Every main checkpoint closes its actual Win32 handle after WriteFile/FlushFileBuffers. "
            "Unique before/after fields localize the last reached stage. A GNU-routed direct COFF _abort records "
            "fresh nonce, exact return PC, process image base and main/worker phases to separately closed WTFABRT.LOG "
            "before calling the unchanged real CRT abort. Other system-DLL abort paths are not intercepted; an absent "
            "abort file is not success. External observer still establishes actual process termination.")
    path = args.output / "guest-files.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"manifest": str(path), "sha256": digest(path), "nonce": nonce,
                      "input_bytes": frozen.stat().st_size, "command": command}))


if __name__ == "__main__":
    main()
