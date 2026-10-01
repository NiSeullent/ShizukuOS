#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot an isolated actual Windows 98 clone through the IO.SYS UEFI entry port.

All remaining arguments are passed to csm/test_win98_uefi.py. The source archive
and its installed Windows snapshot remain immutable. A QEMU/GDB hardware
breakpoint at original MSLOAD's resume address records the real execution point,
then detaches so the native Windows boot can continue. No network is enabled.
"""
import argparse
import hashlib
import importlib.util
import json
import re
import shutil
import struct
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
AUDITED_IO_SHA256 = "1df17834b5c7744a3af92c20e4edaa8e0fdb78eca6da7a01db3538d59b2d1430"
sys.path.insert(0, str(HERE))
from prepare import create_capsule


def aggregate_exit_code(entry_passed, runner_exit_code, native_status):
    """Preserve the requested native checks alongside the separate entry proof."""
    if runner_exit_code:
        return runner_exit_code
    return 0 if entry_passed and native_status in ("PASS", "NEEDS-VISUAL-REVIEW") else 1


def private_reflink_runner(source):
    """Require a private COW inode; keep content gates and the full dirty reserve."""
    substitutions = (
        (b"RESERVE + allocated + DIRTY_BUDGET", b"RESERVE + 4 * 1024 ** 2 + DIRTY_BUDGET"),
        (b'command(["cp", "--reflink=never", "--sparse=always", "--", source, disk], timeout=300)',
         b'command(["cp", "--reflink=always", "--sparse=auto", "--", source, disk], timeout=300)'),
        (b'initial_raw_allocation = disk.stat().st_blocks * 512',
         b'initial_raw_allocation = disk.stat().st_blocks * 512\n        result["sparse_budget"]["cow_baseline"] = _iosys_cow_capture(disk)'),
        (b'if disk.stat().st_blocks * 512 - initial_raw_allocation > DIRTY_BUDGET:',
         b'if _iosys_cow_growth(disk, result, monitor) > DIRTY_BUDGET:'),
        (b'                    monitor.call("quit")\n            finally:',
         b'                    monitor.call("quit")\n            except BaseException as error:\n                result["private_owned_abort"] = str(error)\n                if child.poll() is None:\n                    child.kill()\n                    child.wait(timeout=5)\n                raise\n            finally:'),
        (b'raise RuntimeError("Owned guest exceeded the 256 MiB dirty allocation budget")',
         b'raise RuntimeError(f"Owned guest exceeded the {DIRTY_BUDGET // 1024 ** 2} MiB dirty allocation budget")'),
    )
    for previous, replacement in substitutions:
        if source.count(previous) != 1:
            raise ValueError("Native copy contract changed; private reflink adaptation rejected")
        source = source.replace(previous, replacement)
    return source


def quiescent_cow_observation(disk, monitor, cow, baseline, quota, reserve):
    """Pause only the owned VM; never resume an uncertain or over-budget writer."""
    started = time.monotonic()
    before = monitor.call("query-status")
    if before.get("running") is not True or before.get("status") != "running":
        raise RuntimeError("COW sampling requires an already running owned VM")
    # QEMU vm_stop pauses CPUs and drains/flushes block devices. Still require
    # two identical FIEMAP maps; a paused CPU alone is not allocation evidence.
    monitor.call("stop")
    paused = monitor.call("query-status")
    if paused.get("running") is not False or paused.get("status") != "paused":
        raise RuntimeError("Owned VM did not reach the required paused state")
    observation = cow.observe_allocations(disk)
    growth = cow.net_exclusive_growth_bytes(baseline, observation)
    if growth > quota:
        raise RuntimeError(f"Owned guest exceeded the {quota // 1024 ** 2} MiB dirty allocation budget")
    if shutil.disk_usage(disk.parent).free < reserve:
        raise RuntimeError("Disk free space reached the selected reserve floor while the owned VM was paused")
    if time.monotonic() - started > 5:
        raise RuntimeError("Quiescent COW observation exceeded its five-second bound")
    # On any failure above, leave the writer paused for the immediate owned
    # process abort. Do not put cont in a finally block.
    monitor.call("cont")
    resumed = monitor.call("query-status")
    if resumed.get("running") is not True or resumed.get("status") != "running":
        raise RuntimeError("Owned VM did not resume after a verified COW observation")
    return observation, growth, time.monotonic() - started


def private_native_limits(source, guest_file_mib, dirty_mib):
    """Select explicit bounded private inputs and a stricter allocation quota."""
    substitutions = []
    if guest_file_mib == 64:
        substitutions += [
            (b'if (not path.is_relative_to(manifest.parent) or not guest_re.fullmatch(item["guest"]) or\n                not 0 < item["bytes"] <= 1024 ** 2',
             b'if (not path.is_relative_to(manifest.parent) or not guest_re.fullmatch(item["guest"]) or\n                not 0 < item["bytes"] <= 64 * 1024 ** 2'),
            (b'if not 1 <= len(inputs) <= 8 or len({item["guest"] for item in inputs}) != len(inputs):',
             b'if not 1 <= len(inputs) <= 8 or len({item["guest"] for item in inputs}) != len(inputs) or sum(item["bytes"] for item in inputs) > 64 * 1024 ** 2:'),
        ]
    if dirty_mib == 128:
        substitutions.append((b'DIRTY_BUDGET = 256 * 1024 ** 2', b'DIRTY_BUDGET = 128 * 1024 ** 2'))
    for previous, replacement in substitutions:
        if source.count(previous) != 1:
            raise ValueError("Native resource contract changed; private limit adaptation rejected")
        source = source.replace(previous, replacement)
    return source


def main():
    wrapper_source = Path(__file__).read_bytes()
    wrapper_sha256 = hashlib.sha256(wrapper_source).hexdigest()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--io-sha256", required=True)
    parser.add_argument("--reflink-source", action="store_true",
                        help="Require a private filesystem COW clone; retain reserve and hash gates")
    parser.add_argument("--max-guest-file-mib", type=int, choices=(1, 64), default=1,
                        help="Opt in to at most 64 MiB total digest-bound private guest inputs")
    parser.add_argument("--dirty-budget-mib", type=int, choices=(128, 256), default=256,
                        help="Reserved allocation headroom; 128 MiB requires the COW allocation guard")
    parser.add_argument("--reserve-gib", type=int, default=20,
                        help="Independent filesystem free-space floor, 20..64 GiB")
    args, remaining = parser.parse_known_args()
    if not 20 <= args.reserve_gib <= 64:
        parser.error("The IO.SYS native workflow requires a free-space floor of 20..64 GiB")
    remaining += ["--reserve-gib", str(args.reserve_gib)]
    if args.io_sha256.lower() != AUDITED_IO_SHA256:
        parser.error("Native entry ABI is audited only for the pinned Windows 98 SE IO.SYS")
    if "--native-bios-control" in remaining or "--firmware-gop" not in remaining:
        parser.error("The IO.SYS port requires --firmware-gop and a UEFI run")
    gdb = shutil.which("gdb")
    if not gdb:
        parser.error("gdb is required for independent original-MSLOAD resume evidence")
    native_source = (HERE.parent / "csm/test_win98_uefi.py").read_bytes()
    native_origin_digest = hashlib.sha256(native_source).hexdigest()
    if args.dirty_budget_mib == 128 and not args.reflink_source:
        parser.error("The stricter128MiB quota requires --reflink-source and FIEMAP accounting")
    if args.max_guest_file_mib == 64 and not any(item == "--guest-files-manifest" or item.startswith("--guest-files-manifest=") for item in remaining):
        parser.error("Large private input selection requires a digest-bound guest manifest")
    if args.reflink_source:
        if not any(item == "--resume-owned-run" or item.startswith("--resume-owned-run=") for item in remaining):
            parser.error("Private reflink reuse requires an explicitly selected retained owned run")
        native_source = private_reflink_runner(native_source)
    native_source = private_native_limits(native_source, args.max_guest_file_mib, args.dirty_budget_mib)
    native_digest = hashlib.sha256(native_source).hexdigest()
    cache = HERE.parents[1] / "build/shizukudos/iosys-uefi-port/runner-cache" / native_digest / "shizukudos"
    frozen_runner = cache / "csm/test_win98_uefi.py"
    frozen_runner.parent.mkdir(parents=True, exist_ok=True)
    if frozen_runner.exists():
        if frozen_runner.read_bytes() != native_source:
            raise RuntimeError("Frozen native runner does not match its source digest")
    else:
        with frozen_runner.open("xb") as stream:
            stream.write(native_source)
    tools_link = cache / "tools"
    if not tools_link.exists():
        tools_link.symlink_to(HERE.parent / "tools", target_is_directory=True)
    elif tools_link.resolve() != (HERE.parent / "tools").resolve():
        raise RuntimeError("Frozen runner tools path differs from the selected repository")
    module_spec = importlib.util.spec_from_file_location("iosys_native_runner", frozen_runner)
    runner = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(runner)
    cow = None
    cow_digest = None
    if args.reflink_source:
        cow_source = (HERE / "cow_accounting.py").read_bytes()
        cow_digest = hashlib.sha256(cow_source).hexdigest()
        cow_path = cache / ("cow_accounting_" + cow_digest + ".py")
        if cow_path.exists():
            if cow_path.read_bytes() != cow_source:
                raise RuntimeError("Frozen COW accounting helper digest mismatch")
        else:
            with cow_path.open("xb") as stream:
                stream.write(cow_source)
        cow_spec = importlib.util.spec_from_file_location("iosys_cow_" + cow_digest, cow_path)
        cow = importlib.util.module_from_spec(cow_spec)
        sys.modules[cow_spec.name] = cow
        cow_spec.loader.exec_module(cow)
    runner.CSM = runner.BUILD / "iosys-uefi-port/runs"
    if not any(item == "--csm-dir" or item.startswith("--csm-dir=") for item in remaining):
        remaining += ["--csm-dir", str(runner.BUILD / "iosys-uefi-port/firmware")]
    runner.INI += "iosys_boot=true\r\n"
    original_add = runner.add_uefi_files
    original_launch = runner.qemu.launch
    original_reuse = runner.reuse_prepared
    state = {}

    def capture_cow(disk):
        observation = cow.observe_allocations(disk)
        state["cow_baseline"] = observation
        return observation.to_dict()

    def cow_growth(disk, result, monitor):
        observation, growth, elapsed = quiescent_cow_observation(
            disk, monitor, cow, state["cow_baseline"], runner.DIRTY_BUDGET, runner.RESERVE)
        result["sparse_budget"].update(cow_latest=observation.to_dict(),
                                      cow_net_exclusive_growth_bytes=growth,
                                      cow_peak_net_exclusive_growth_bytes=max(0, growth, result["sparse_budget"].get("cow_peak_net_exclusive_growth_bytes", 0)),
                                      cow_quiescent_samples=result["sparse_budget"].get("cow_quiescent_samples", 0) + 1,
                                      cow_maximum_sampling_seconds=max(elapsed, result["sparse_budget"].get("cow_maximum_sampling_seconds", 0)))
        return growth

    if args.reflink_source:
        runner._iosys_cow_capture = capture_cow
        runner._iosys_cow_growth = cow_growth

    def reuse_prepared(run, *positional, **keywords):
        # Accept the other session's explicitly selected, receipt-bound cold
        # CSM trial through the existing copy/hash gates. Only the output clone
        # is booted; the earlier run's raw image is never opened for writing.
        source = run.resolve(strict=True)
        previous = runner.CSM
        shared_csm = (runner.BUILD / "csm").resolve()
        if source.is_relative_to(shared_csm):
            runner.CSM = shared_csm
        try:
            partition, receipt = original_reuse(run, *positional, **keywords)
            if args.reflink_source:
                disk = positional[1]
                original = source / "windows-uefi.raw"
                if disk.stat().st_ino == original.stat().st_ino or disk.stat().st_nlink != 1:
                    raise RuntimeError("COW clone must have its own private inode")
                receipt["method"] = "verified private filesystem COW clone; cold hardware, new VARS, no CPU/RAM state"
                receipt["copy_mode"] = "cp --reflink=always; unsupported filesystems fail closed"
                receipt["copy_metadata_budget_bytes"] = 4 * 1024 ** 2
            return partition, receipt
        finally:
            runner.CSM = previous

    def add_uefi_files(disk, run_dir, efi, firmware_gop=False):
        receipt = json.loads((efi.parent / "build-result.json").read_text())
        if receipt.get("iosys_uefi", {}).get("compiled_support") is not True:
            raise RuntimeError("Firmware receipt lacks the opt-in IO.SYS entry port")
        partition = original_add(disk, run_dir, efi, firmware_gop)
        capsule, report = create_capsule(disk.read_bytes(), args.io_sha256)
        if report["partition"]["start_lba"] != partition["start_lba"]:
            raise RuntimeError("Native runner and capsule selected different FAT32 partitions")
        target = run_dir / "IOSYS.BIN"
        with target.open("xb") as stream:
            stream.write(capsule)
        runner.shzlib.write_json(run_dir / "iosys-capsule.json", report)
        with (run_dir / "iosys-wrapper-source.py").open("xb") as stream:
            stream.write(wrapper_source)
        spec = f"{disk}@@{partition['start_lba'] * 512}"
        runner.command(["mcopy", "-o", "-i", spec, target, "::EFI/BOOT/IOSYS.BIN"])
        readback = subprocess.run(["mtype", "-i", spec, "::EFI/BOOT/IOSYS.BIN"],
                                  check=True, capture_output=True).stdout
        if readback != capsule:
            raise RuntimeError("Private capsule injection differs from the validated source")
        # Revalidate the actual installed IO.SYS after the FAT directory writes.
        after, _ = create_capsule(disk.read_bytes(), args.io_sha256)
        if after != capsule:
            raise RuntimeError("Capsule injection changed IO.SYS or its boot contract")
        state.update(run_dir=run_dir, capsule=report, capsule_bytes=capsule)
        partition.update(uefi_disk_sha256=runner.sha256_file(disk),
                         iosys_capsule_sha256=hashlib.sha256(capsule).hexdigest(),
                         iosys_boot_opt_in=True)
        return partition

    def launch(command, workdir, timeout_note=None):
        probe = workdir / "native-entry"
        probe.mkdir()
        # The runner already creates a short private QMP socket directory.
        qmp_arg = command[command.index("-qmp") + 1]
        socket_path = Path(qmp_arg.removeprefix("unix:").split(",")[0]).parent / "gdb.sock"
        argv = [*command, "-S", "-gdb", f"unix:{socket_path},server=on,wait=off"]
        child = original_launch(argv, workdir, timeout_note)
        try:
            return capture_resume(child, probe, socket_path, qmp_arg, argv)
        except BaseException:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait()
            raise

    def capture_resume(child, probe, socket_path, qmp_arg, argv):
        deadline = time.monotonic() + 10
        while not socket_path.exists():
            if child.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Owned QEMU did not create its private GDB socket")
            time.sleep(0.05)
        gdb_commands = ["set pagination off", "set confirm off", "set remotetimeout 20",
                        f"target remote {socket_path}", "hbreak *0x908", "continue",
                        'printf "IO98_RESUME cs=%lx ip=%lx ss=%lx sp=%lx bp=%lx si=%lx di=%lx ds=%lx es=%lx bx=%lx cx=%lx flags=%lx\\n", $cs, $rip, $ss, $rsp, $rbp, $rsi, $rdi, $ds, $es, $rbx, $rcx, $eflags',
                        "info registers rax rbx rcx rdx rsi rdi rbp rsp rip eflags cs ss ds es fs gs cr0 cr3 cr4",
                        "dump binary memory entry.bin 0x900 0x920",
                        "dump binary memory handover.bin 0x6800 0x68a0",
                        "dump binary memory stack-bpb.bin 0x7bf0 0x7e00",
                        "dump binary memory int1e.bin 0x78 0x7c",
                        "detach"]
        script = probe / "capture.gdb"
        script.write_text("\n".join(gdb_commands) + "\n")
        log = (probe / "gdb.log").open("wb")
        debugger = subprocess.Popen([gdb, "-q", "-nx", "-batch", "-x", script],
                                    cwd=probe, stdout=log, stderr=subprocess.STDOUT)
        log.close()
        state.update(debugger=debugger, command=argv, probe=probe)
        try:
            debugger.wait(timeout=45)
        except subprocess.TimeoutExpired:
            debugger.kill()
            debugger.wait()
            state["gdb_timeout"] = True
        # Return only after the probe has detached. The existing runner treats
        # a paused VM as failure, so -S and the breakpoint must stay private
        # to this launch phase. A failed probe still retains boot diagnostics.
        monitor = runner.qemu.QMP(Path(qmp_arg.removeprefix("unix:").split(",")[0]))
        try:
            monitor.call("cont")
        finally:
            monitor.close()
        return child

    runner.add_uefi_files = add_uefi_files
    runner.qemu.launch = launch
    runner.reuse_prepared = reuse_prepared
    original_argv = sys.argv
    try:
        sys.argv = [str(HERE.parent / "csm/test_win98_uefi.py"), *remaining]
        runner_status = runner.main()
    finally:
        sys.argv = original_argv
        runner.qemu.launch = original_launch
        debugger = state.get("debugger")
        if debugger:
            try:
                debugger.wait(timeout=10)
            except subprocess.TimeoutExpired:
                debugger.kill()
                debugger.wait()
    if not state.get("run_dir"):
        return runner_status or 1
    run_dir = state["run_dir"]
    native_result_bytes = (run_dir / "result.json").read_bytes()
    native = json.loads(native_result_bytes)
    final_cow = None
    if args.reflink_source and state.get("cow_baseline") and (run_dir / "windows-uefi.raw").exists():
        try:
            observation = cow.observe_allocations(run_dir / "windows-uefi.raw")
            final_cow = {"status": "PASS" if cow.net_exclusive_growth_bytes(state["cow_baseline"], observation) <= runner.DIRTY_BUDGET else "FAIL",
                         "observation": observation.to_dict(),
                         "net_exclusive_growth_bytes": cow.net_exclusive_growth_bytes(state["cow_baseline"], observation),
                         "scope": "quiescent current exclusive data extent growth; metadata/staging and cumulative writes excluded"}
        except cow.AccountingError as error:
            final_cow = {"status": "FAIL", "error": str(error)}
    serial = (run_dir / "serial.log").read_text(errors="replace") if (run_dir / "serial.log").exists() else ""
    probe = state.get("probe", run_dir / "native-entry")
    text = (probe / "gdb.log").read_text(errors="replace") if (probe / "gdb.log").exists() else ""
    match = re.search(r"IO98_RESUME ([^\n]+)", text)
    registers = {key: int(value, 16) for key, value in re.findall(r"(\w+)=([0-9a-f]+)", match.group(1))} if match else {}
    descriptor = (probe / "handover.bin").read_bytes() if (probe / "handover.bin").exists() else b""
    entry = (probe / "entry.bin").read_bytes() if (probe / "entry.bin").exists() else b""
    stack = (probe / "stack-bpb.bin").read_bytes() if (probe / "stack-bpb.bin").exists() else b""
    int1e = (probe / "int1e.bin").read_bytes() if (probe / "int1e.bin").exists() else b""
    wanted = dict(state["capsule"]["entry"])
    wanted["ip"] = 0x208
    saved_vbr = bytearray(state["capsule_bytes"][128:640])
    saved_vbr[2] = state["capsule_bytes"][121]
    checks = {
        "gdb_capture_completed": state.get("debugger") is not None and
                                 state["debugger"].returncode == 0 and not state.get("gdb_timeout"),
        "entry_consumed_gop_serial": "IO98:GOP-CONSUMED" in serial,
        "original_msload_resume_registers": all(registers.get(key) == wanted[key] for key in
                                                ("cs", "ip", "ss", "sp", "bp", "si", "di", "ds", "es", "bx", "cx")) and
                                             registers.get("flags", 0) & 0x600 == 0x200,
        "entry_redirects_to_hook": len(entry) == 32 and entry[0] == 0xE9 and
                                  0x903 + struct.unpack_from("<h", entry, 1)[0] == 0x6000 and entry[3:8] == b"\x90" * 5,
        "gop_descriptor_at_resume": len(descriptor) == 160 and descriptor[:8] == b"SHZGOP1\0" and
                                    descriptor[8:16] == struct.pack("<HHI", 1, 0, 96) and
                                    sum(struct.unpack_from("<24I", descriptor)) & 0xffffffff == 0,
        "original_vbr_stack_context": len(stack) == 528 and struct.unpack_from("<I", stack, 12)[0] ==
                                      state["capsule"]["fat32"]["first_data_absolute_lba"] and
                                      stack[16:] == saved_vbr and stack[:4] == struct.pack("<HH", 0x78, 0) and
                                      stack[8:12] == b"\xff" * 4 and len(int1e) == 4 and stack[4:8] == int1e,
        "original_archive_unchanged": native.get("originals_unchanged") is True,
        "emulator_healthy": native.get("qemu_exit_code") == 0 and not native.get("runtime_failure"),
        "gop_consumed_marker": len(descriptor) == 160 and descriptor[128:136] == b"IO98GOP1" and
                               struct.unpack_from("<I", descriptor, 136)[0] == 1 and
                               descriptor[140:144] == descriptor[16:20] and
                               descriptor[144:152] == descriptor[24:32] and
                               descriptor[152:160] == descriptor[48:56],
    }
    try:
        post_run_capsule, _ = create_capsule((run_dir / "windows-uefi.raw").read_bytes(), args.io_sha256)
        checks["original_io_file_unchanged"] = post_run_capsule == state["capsule_bytes"]
    except (OSError, ValueError) as error:
        checks["original_io_file_unchanged"] = False
        state["post_run_io_error"] = str(error)
    proof = {"profile": "actual-win98-iosys-uefi-entry-port", "status": "PASS" if all(checks.values()) else "FAIL",
             "checks": checks, "resume_registers": registers, "capsule": state["capsule"],
             "native_result": str(run_dir / "result.json"), "command": state.get("command"),
             "native_result_sha256": hashlib.sha256(native_result_bytes).hexdigest(),
             "native_runner_exit_code": runner_status, "native_result_status": native.get("status"),
             "native_runner_origin_sha256": native_origin_digest,
             "native_runner_executed_sha256": native_digest,
             "private_reflink_source": args.reflink_source,
             "cow_accounting_helper_sha256": cow_digest,
             "cow_allocation_review": final_cow,
             "private_guest_input_limit_mib": args.max_guest_file_mib,
             "private_dirty_allocation_quota_mib": args.dirty_budget_mib,
             "source_sha256": wrapper_sha256,
             "boot_path": "OVMF -> CSMWrap -> IO.SYS entry GOP hook -> original Microsoft MSLOAD",
             "scope": "Entry/resume proof with subsequent SeaBIOS services; complete Windows GUI requires separate acceptance",
             "native_windows_gui": native.get("gui_verdict", "not-established")}
    runner.shzlib.write_json(run_dir / "iosys-entry-result.json", proof)
    allocation_passed = not args.reflink_source or final_cow is not None and final_cow["status"] == "PASS"
    exit_code = aggregate_exit_code(proof["status"] == "PASS" and allocation_passed, runner_status, native.get("status"))
    print(json.dumps({"io_entry": proof["status"], "checks": checks,
                      "native_result_status": native.get("status"), "exit_code": exit_code,
                      "result": str(run_dir / "iosys-entry-result.json")}, indent=2))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
