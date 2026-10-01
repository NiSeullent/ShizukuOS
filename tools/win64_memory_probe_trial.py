#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded real AMD64 loader/memory diagnostic using a sealed private overlay.

Preserves source, runtime, firmware, and image; never edits the stable bridge,
handoff, extension overlay, peer kernel, native Win98, or another guest control.
"""
from __future__ import annotations
import argparse
import importlib.util
from pathlib import Path
import re
import subprocess
import sys
import uuid

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "ntwddm/win64/memory_probe/probe.c"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


extension = load("private_memory_probe_extension", ROOT / "tools/runtime_extension_overlay.py")
common = load("private_memory_probe_common", ROOT / "tools/win64_theme_probe_trial.py")
handoff = extension.handoff
theme = extension.theme
require = common.require
digest = common.digest
EXE = "MEMORYP64.EXE"
VOLUME = "memprobe"
APP = "private_memory_probe"
WAIT_SOURCES = common.WAIT_SOURCES
FALSE_FLAGS = {"windows98_execution_verified": False, "os_wide_theme_verified": False,
               "app_functionality_verified": False, "full_modern_memory_api_verified": False}
MANDATORY_MEMORY = (
    "real_virtualalloc2_allocates", "allocation_bytes_zeroed", "allocation_real_bytes_writable", "allocation_query_ownership",
    "allocation_placeholder_refused", "allocation_extension_untouched", "unsupported_allocation_keeps_owner_bytes",
    "allocation_conflict_propagated", "failed_reservation_keeps_bytes", "real_process_rights_not_bypassed",
    "reservation_commit_same_base", "committed_reservation_zeroed", "real_pagefile_mapping_handle",
    "real_mapview3_writable", "pagefile_view_zeroed", "same_section_views_coherent", "copy_view_private_write",
    "mapping_unaligned_offset_refused", "mapping_placeholder_refused", "mapping_extension_untouched",
    "mapping_owner_size_failure_propagated", "mapping_bad_handle_failure_propagated", "unmap_interior_address_refused",
    "unmap_placeholder_preservation_refused", "unmap_private_allocation_refused", "failed_unmap_preserves_owners",
    "close_mapping_handle_before_views", "views_outlive_mapping_handle", "release_copy_view", "release_second_view",
    "release_first_view_preserves_error", "released_view_no_longer_owned", "double_unmap_refused",
    "close_real_process_handle", "release_reserved_allocation", "release_private_allocation",
)


def sources():
    paths = (SOURCE, Path(__file__).resolve(), ROOT / "tools/runtime_extension_overlay.py",
             ROOT / "tools/win64_theme_probe_trial.py", ROOT / "tools/required_theme_runtime.py",
             ROOT / "tools/required_app_runtime_handoff.py", ROOT / "tools/signal_desktop_corpus.py",
             ROOT / "tools/modern_app_inventory.py", ROOT / "LICENSE")
    return {str(path.relative_to(ROOT)): digest(path) for path in paths}


def prepare(overlay_path, out, nonce):
    require(common.nonce_ok(nonce), "fresh lowercase 32-digit nonce required")
    receipt = extension.verified(overlay_path)
    out = theme.owned_new_directory(out)
    original = sources()
    productivity, peer_hashes = handoff.load_peer(Path(receipt["runtime_worktree"]))
    require(peer_hashes == receipt["runtime_source_hashes"], "peer helper changed")
    wait_hashes = {name: digest(Path(receipt["runtime_worktree"]) / name) for name in WAIT_SOURCES}
    archive = theme.inventory.read_regular(Path(receipt["archive"]["path"]))
    require(len(theme.parse_archive(archive)) == 143, "expected prepared 143-member Modern+memory archive")
    handoff.check_space(out.parent, 300 * 1024**2 + handoff.METADATA_MARGIN)
    out.mkdir()
    for relative, checksum in original.items():
        target = out / "sources" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(theme.inventory.read_regular(ROOT / relative))
        require(digest(target) == checksum, "source changed while freezing")
        target.chmod(0o400)
    for relative, checksum in wait_hashes.items():
        target = out / "sources/runtime-wait" / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(theme.inventory.read_regular(Path(receipt["runtime_worktree"]) / relative))
        require(digest(target) == checksum, "wait source changed while freezing")
        target.chmod(0o400)
    header = out / "trial_nonce.h"
    candidate_bytes = (overlay_path.parent / "KERNELBASE.DLL").stat().st_size
    header.write_text('#define TRIAL_NONCE "' + nonce + '"\n#define CANDIDATE_BYTES ' + str(candidate_bytes) + 'ull\n')
    header.chmod(0o400)
    tree = out / "tree"; tree.mkdir()
    executable = tree / EXE
    compiler = Path(subprocess.check_output(["which", "x86_64-w64-mingw32-gcc"], text=True).strip()).resolve(strict=True)
    command = [str(compiler), "-std=c99", "-Os", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin",
               "-fno-stack-protector", "-mno-stack-arg-probe", "-nostdlib", "-I", str(out), str(out / "sources" / SOURCE.relative_to(ROOT)),
               "-Wl,--no-insert-timestamp,--entry,MemoryProbeEntry,--subsystem,console,--nxcompat,--dynamicbase",
               "-Wl,--image-base,0x140000000", "-o", str(executable), "-lkernel32"]
    built = subprocess.run(command, capture_output=True, text=True, timeout=60)
    (out / "compiler.log").write_text(built.stdout + built.stderr)
    require(built.returncode == 0, "probe compilation failed; see compiler.log")
    gate = common.pe_gate(executable, archive)
    require(all(row["module"].upper() == "KERNEL32.DLL" for row in gate["imports"]), "probe requires only the genuine Kernel32")
    image = out / "memory-probe.img"
    productivity.runner.build_image(image, tree, VOLUME)
    control = f"image=D:\\{VOLUME}\\{EXE}\r\ncmdline={EXE} \r\ncwd=D:\\{VOLUME}\r\ntimeout=30\r\n".encode("ascii")
    productivity.runner.put_file(image, control, "K64RUN.TXT", out)
    image.chmod(0o400)
    require(sources() == original and extension.verified(overlay_path) == receipt, "preparation inputs changed")
    result = {"schema": 1, "stage": "private-amd64-memory-probe", "status": "PREPARED", "nonce": nonce,
              "overlay_receipt": {"path": str(overlay_path.resolve()), "sha256": digest(overlay_path)},
              "candidate_sha256": digest(overlay_path.parent / "KERNELBASE.DLL"),
              "candidate_bytes": candidate_bytes,
              "runtime_worktree": receipt["runtime_worktree"], "runtime_source_hashes": peer_hashes,
              "runtime_wait_source_hashes": wait_hashes, "kernel_reaped_field_semantics": "raw proc_wait: 0 success, -1 failure; final grammar required",
              "source_hashes": original, "compiler": {"path": str(compiler), "sha256": digest(compiler), "command": command},
              "nonce_header": {"path": str(header), "sha256": digest(header)},
              "executable": {"path": str(executable), "bytes": executable.stat().st_size, "sha256": digest(executable)},
              "image": {"path": str(image), "bytes": image.stat().st_size, "sha256": digest(image)}, "tree": str(tree),
              "control": control.decode("ascii"), "pe_gate": gate, "payload_executed": False, "network_attached": False, **FALSE_FLAGS}
    handoff.write_json(out / "prepared.json", result)
    return result


def verified_preparation(path):
    receipt = handoff.read_json(path)
    require(receipt.get("schema") == 1 and receipt.get("stage") == "private-amd64-memory-probe" and receipt.get("status") == "PREPARED"
            and common.nonce_ok(receipt.get("nonce", "")), "invalid preparation")
    directory = path.parent.resolve(strict=True)
    require(directory.is_relative_to((ROOT / "build").resolve(strict=True)), "preparation must be in owned build")
    require(receipt["source_hashes"] == sources(), "probe/helper source changed")
    for relative, checksum in receipt["source_hashes"].items():
        require(digest(directory / "sources" / relative) == checksum, "frozen source changed")
    require(set(receipt["runtime_wait_source_hashes"]) == set(WAIT_SOURCES), "wait source bindings missing")
    for relative, checksum in receipt["runtime_wait_source_hashes"].items():
        require(digest(directory / "sources/runtime-wait" / relative) == checksum and
                digest(Path(receipt["runtime_worktree"]) / relative) == checksum, "runtime wait source changed")
    opath = Path(receipt["overlay_receipt"]["path"])
    require(digest(opath) == receipt["overlay_receipt"]["sha256"], "overlay receipt changed")
    runtime = extension.verified(opath)
    require(runtime["runtime_worktree"] == receipt["runtime_worktree"] and runtime["runtime_source_hashes"] == receipt["runtime_source_hashes"],
            "runtime differs from preparation")
    require(digest(opath.parent / "KERNELBASE.DLL") == receipt["candidate_sha256"], "candidate changed")
    for key in ("image", "executable", "nonce_header"):
        row = receipt[key]; input_path = Path(row["path"])
        require(input_path.resolve(strict=True).is_relative_to(directory) and digest(input_path) == row["sha256"], "prepared input changed")
        if "bytes" in row: require(input_path.stat().st_size == row["bytes"], "prepared size changed")
    require(Path(receipt["tree"]).resolve(strict=True) == directory / "tree", "prepared tree changed")
    return receipt, runtime


def parse_evidence(serial, nonce, candidate_bytes=69609):
    require(common.nonce_ok(nonce), "invalid nonce")
    starts = list(re.finditer(r"^K64 autorun: starting ([^\r\n]+)", serial, re.M))
    require(len(starts) == 1 and starts[0].group(1).startswith(f"D:\\{VOLUME}\\{EXE} (cwd D:\\{VOLUME}, timeout 30 s)"), "exact autorun required")
    tail = serial[starts[0].start():]
    pids = re.findall(r"^K64 autorun: started pid (\d+)\r?$", tail, re.M)
    require(len(pids) == 1, "unique child PID required")
    pid = pids[0]
    app = re.findall(r"^\[(?:win64|user) " + re.escape(EXE) + r" pid " + pid + r"\] (MP64[^\r\n]*)\r?$", tail, re.M)
    require(app.count("MP64 BEGIN " + nonce) == 1, "unique fresh BEGIN required")
    endings = [line for line in app if line.startswith("MP64 FINAL ")]
    require(len(endings) == 1 and endings[0] in ("MP64 FINAL PASS " + nonce, "MP64 FINAL FAIL " + nonce), "unique fresh FINAL required")
    totals = [re.fullmatch(r"MP64 COUNTS checks=(\d+) failures=(\d+)", line) for line in app if line.startswith("MP64 COUNTS")]
    require(len(totals) == 1 and totals[0], "unique assertion totals required")
    checks, failures = map(int, totals[0].groups())
    passed = [line[10:] for line in app if line.startswith("MP64 PASS ")]
    failed = [line[10:] for line in app if line.startswith("MP64 FAIL ")]
    require(checks >= 8 and checks == len(passed) + len(failed) and failures == len(failed), "assertion totals mismatch")
    require(endings[0] == "MP64 FINAL " + ("FAIL " if failures else "PASS ") + nonce, "FINAL differs from assertions")
    results = re.findall(r"^K64 autorun: result (\S+) exit=([0-9a-f]+) faulted=(\d) reaped=(-?\d+) after \d+ ms\r?$", tail, re.M)
    all_results = re.findall(r"^K64 autorun: result [^\r\n]*", tail, re.M)
    expected_exit = "1" if failures else "0"
    require(len(all_results) == 1 and results == [("exited", expected_exit, "0", "0")], "external exit/status/proc_wait mismatch")
    require(not re.search(r"K64 EXCEPTION|K64: process .* killed|unhandled exception", tail), "process fault")
    values = {}
    for line in app:
        if line.startswith("MP64 VALUE "):
            match = re.fullmatch(r"MP64 VALUE (\w+) value=([0-9a-f]{16}) error=(\d+)", line)
            require(match is not None and match[1] not in values, "malformed/duplicate diagnostic value")
            values[match[1]] = {"value": int(match[2], 16), "value_hex": match[2], "last_error": int(match[3])}
    require(all(key in values for key in ("attributes_a", "attributes_w", "file_open", "load_lower_basename", "load_upper_basename", "load_absolute")),
            "live namespace/loader diagnostics missing")
    for key in ("load_lower_basename", "load_upper_basename", "load_absolute"):
        check_name = "kernelbase_" + key
        require((check_name in passed) == bool(values[key]["value"]), "load handle and assertion differ")
    for suffix in ("a", "w"):
        require(("kernelbase_file_attributes_" + suffix in passed) == (values["attributes_" + suffix]["value"] != 0xffffffff),
                "attribute value and assertion differ")
    if values["file_open"]["value"]:
        require(all(key in values for key in ("file_size", "file_read_bytes", "file_mz")), "live candidate content diagnostics absent")
        require(("kernelbase_live_file_exact_size" in passed) == (values["file_size"]["value"] == candidate_bytes), "live size assertion differs")
        require(("kernelbase_live_file_mz_header" in passed) == (values["file_read_bytes"]["value"] == 64 and values["file_mz"]["value"] == 0x5a4d),
                "live MZ assertion differs")
    memory_ok = False
    if app.count("MP64 MEMORY BEGIN") == 1 and app.count("MP64 MEMORY DONE") == 1:
        beginning, end = app.index("MP64 MEMORY BEGIN"), app.index("MP64 MEMORY DONE")
        require(beginning < end, "memory scope out of order")
        memory_scope = app[beginning + 1:end]
        memory_ok = (all("MP64 PASS " + name in memory_scope for name in MANDATORY_MEMORY)
                     and not any(line.startswith("MP64 FAIL ") for line in memory_scope))
    loader_ok = all(name in passed for name in ("kernelbase_file_attributes_a", "kernelbase_file_attributes_w",
                    "kernelbase_load_lower_basename", "kernelbase_load_upper_basename", "kernelbase_load_absolute", "genuine_kernel32_forwarder"))
    api_names = ("VirtualAlloc2", "MapViewOfFile3", "UnmapViewOfFile2", "GetCurrentProcessId")
    if memory_ok:
        require(all(name in values and values[name]["value"] and name in passed for name in api_names), "memory ran without dynamic API pointers")
    return {"status": "PASS" if not failures and memory_ok and loader_ok else "FAIL", "nonce": nonce, "pid": int(pid),
            "assertions": checks, "failures": failures, "failed_assertions": failed, "values": values,
            "module_paths": [line for line in app if line.startswith("MP64 PATH ")],
            "normal_exit_code": int(expected_exit, 16), "proc_wait_return_code": 0, "kernel_child_reaped": True,
            "loader_basename_and_absolute_verified": loader_ok, "basic_memory_subset_verified": memory_ok}


class ProbeGuard(handoff.GuardedSubprocess):
    def written_bytes(self, pid):
        written, output = super().written_bytes(pid)
        serial = self.out / "serial.log"
        serial_bytes = serial.stat().st_size if serial.exists() else 0
        observed = self.record.setdefault("kvm_fd_evidence", [])
        try:
            for descriptor in (Path("/proc") / str(pid) / "fd").iterdir():
                try: target = str(descriptor.readlink())
                except OSError: continue
                if target == "/dev/kvm" or "kvm-vm" in target or "kvm-vcpu" in target:
                    row = {"pid": pid, "fd": descriptor.name, "target": target}
                    if row not in observed: observed.append(row)
        except OSError:
            pass
        return written, output + serial_bytes


def run_trial(prepared, out, qemu, firmware_dirs, timeout=60):
    require(qemu.is_absolute() and 10 <= timeout <= 180, "absolute QEMU/bounded timeout required")
    receipt, runtime = verified_preparation(prepared)
    preparation_hash = digest(prepared)
    out = theme.owned_new_directory(out)
    productivity, hashes = handoff.load_peer(Path(receipt["runtime_worktree"]))
    require(hashes == receipt["runtime_source_hashes"], "runtime helper changed")
    runner = productivity.runner
    inputs = {"boot_stub": runner.K64S / "boot.elf", "kernel": runner.K64S / "KERNEL64S.BIN",
              "win64_initrd": Path(runtime["archive"]["path"]), "qemu": qemu}
    before = {key: {"path": str(path.resolve()), "sha256": digest(path)} for key, path in inputs.items()}
    firmware = handoff.firmware_manifest(firmware_dirs)
    handoff.check_space(out.parent, sum(path.stat().st_size for path in inputs.values()) + firmware["bytes"] + handoff.RUN_WRITE_BUDGET)
    out.mkdir()
    sealed = handoff.seal_runtime_inputs(inputs, out / "runtime-inputs")
    require(all(sealed[key]["sha256"] == row["sha256"] for key, row in before.items()), "input changed while sealing")
    sealed_firmware = handoff.seal_firmware(firmware, out / "runtime-firmware")
    handoff.write_json(out / "runtime-seal.json", {"schema": 1, "stage": "sealed-memory-diagnostic-runtime",
        "probe_preparation_sha256": preparation_hash, "extension_overlay_sha256": receipt["overlay_receipt"]["sha256"],
        "runtime_source_hashes": hashes, "sealed_runtime_input_hashes": sealed, "sealed_firmware": sealed_firmware})
    guard = ProbeGuard(Path(sealed["qemu"]["path"]), out, sealed_firmware)
    app = {"dir": VOLUME, "exe": EXE, "args": "", "expect": "MP64 FINAL PASS " + receipt["nonce"]}
    require(APP not in runner.APPS, "application key already owned")
    saved = runner.K64S, runner.WIN64, runner.subprocess, runner.build_image, runner.put_file, sys.argv
    runner.K64S = runner.WIN64 = out / "runtime-inputs"; runner.subprocess = guard; runner.APPS[APP] = app
    image = Path(receipt["image"]["path"])

    def image_builder(selected, tree, volume, over=None):
        require(Path(selected).resolve() == image.resolve() and Path(tree).resolve() == Path(receipt["tree"]).resolve()
                and volume == VOLUME and not over, "runner attempted another image")
        return [(EXE, receipt["executable"]["bytes"])]

    def control_writer(selected, data, name, folder):
        require(Path(selected).resolve() == image.resolve() and name == "K64RUN.TXT" and data.decode("ascii") == receipt["control"],
                "runner attempted another control")

    runner.build_image = image_builder; runner.put_file = control_writer
    sys.argv = [str(Path(runner.__file__)), "--app", APP, "--tree", receipt["tree"], "--image", str(image), "--out", str(out),
                "--qemu", sealed["qemu"]["path"], "--accel", "kvm", "--memory", "1024", "--timeout", str(timeout), "--guest-timeout", "30"]
    runner_code, error = 2, None
    try: runner_code = runner.main()
    except Exception as failure: error = str(failure)
    finally:
        runner.K64S, runner.WIN64, runner.subprocess, runner.build_image, runner.put_file, sys.argv = saved
        runner.APPS.pop(APP, None); guard.close()
    serial = (out / "serial.log").read_text(errors="replace") if (out / "serial.log").exists() else ""
    evidence = {"status": "FAIL", "basic_memory_subset_verified": False}
    try:
        require(error is None, error or "runtime execution failed")
        evidence = parse_evidence(serial, receipt["nonce"], receipt["candidate_bytes"])
    except Exception as failure: evidence["error"] = str(failure)
    preserved = False
    try:
        require(digest(prepared) == preparation_hash and verified_preparation(prepared)[0] == receipt, "preparation changed")
        require(all(digest(Path(row["path"])) == row["sha256"] and digest(Path(row["source_path"])) == row["sha256"]
                    for row in sealed.values()), "original/sealed runtime changed")
        require(handoff.sealed_firmware_preserved(sealed_firmware) and handoff.firmware_sources_preserved(firmware), "firmware changed")
        preserved = True
    except Exception as failure: error = (error + "; " if error else "") + str(failure)
    kvm = bool(guard.record.get("kvm_fd_evidence"))
    guarded = not guard.record["termination_reason"] and kvm
    ok = evidence["status"] == "PASS" and runner_code == 0 and preserved and guarded
    result = {"schema": 1, "stage": "standalone-kernel64-loader-and-basic-memory-diagnostic", "status": "PASS" if ok else "FAIL",
        "probe_nonce": receipt["nonce"], "probe_preparation": {"path": str(prepared.resolve()), "sha256": preparation_hash},
        "candidate_sha256": receipt["candidate_sha256"], "guest_os": "ShizukuDOS Kernel64 standalone",
        "original_runner_return_code": runner_code, "evidence": evidence, "resource_guard": guard.record,
        "hardware_virtualization_fd_verified": kvm, "host_qemu_return_code": guard.child.returncode if guard.child else None,
        "original_and_sealed_inputs_preserved": preserved, "error": error, "network_attached": False,
        "peer_sources_modified": False, "installation": "not_performed",
        "basic_memory_subset_verified": evidence["basic_memory_subset_verified"] and preserved and guarded, **FALSE_FLAGS}
    handoff.write_json(out / "memory-diagnostic.json", result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="stage", required=True)
    prep = commands.add_parser("prepare")
    prep.add_argument("--overlay", type=Path, required=True); prep.add_argument("--out", type=Path, required=True)
    prep.add_argument("--nonce", default=None)
    run = commands.add_parser("run")
    for flag in ("prepared", "out", "qemu"): run.add_argument("--" + flag, type=Path, required=True)
    run.add_argument("--firmware-dir", type=Path, action="append", required=True); run.add_argument("--timeout", type=int, default=60)
    args = parser.parse_args(argv)
    try:
        result = prepare(args.overlay, args.out, args.nonce or uuid.uuid4().hex) if args.stage == "prepare" else run_trial(
            args.prepared, args.out, args.qemu, args.firmware_dir, args.timeout)
    except Exception as error:
        print(handoff.json.dumps({"status": "FAIL", "error": str(error)})); return 2
    print(handoff.json.dumps({key: result[key] for key in ("status", "stage")}))
    return 0 if result["status"] in ("PREPARED", "PASS") else 1


if __name__ == "__main__":
    raise SystemExit(main())
