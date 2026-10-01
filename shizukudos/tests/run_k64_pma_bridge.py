#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Exercise PMA event requests on the real Kernel64 service thread and IPC rings.

This isolated standalone guest does not execute Windows 98, VMM or a VxD.
It preserves the existing Win64 loopback acceptance checks as a regression gate.
The existing GUI fixtures require the same Bochs VBE adapter used by the GUI
runner. This component check does not establish UEFI GOP or product boot support.
The GUI input fixture's optional host-input phases have no QMP driver here;
its existing software assertions remain active, but this is not PS/2 evidence.
"""
import argparse
import hashlib
import json
import re
import sys
import time
from pathlib import Path

import run_k64_standalone as baseline

qemu, shzlib = baseline.qemu, baseline.shzlib
ROOT = Path(__file__).resolve().parents[2]
BUILD = ROOT / "build" / "shizukudos"
sys.path.insert(0, str(ROOT / "shizukudos"))
import kbuild  # noqa: E402 -- source inventory only; never executes a build


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pma_checks(serial):
    records = re.findall(r"^K64 PMA bridge (PASS|FAIL): (.+)$", serial, re.M)
    names = {name for status, name in records if status == "PASS"}
    required = ("query negotiation", "auto-reset deferred wait", "manual-reset broadcast",
                "timeout", "cancellation", "stale generation", "duplicate request",
                "thread cleanup", "process cleanup", "full-ring completion retention", "domain restart",
                "corrupt-ring quarantine", "process cleanup after thread exit", "invalid-ring metadata quarantine",
                "mixed W64 backpressure deadline", "shutdown cancels waits and stops admission")
    checks = [baseline.check("PMA: " + name, name in names) for name in required]
    summary = re.findall(r"^K64 PMA bridge: (\d+) passed, (\d+) failed$", serial, re.M)
    checks.append(baseline.check("PMA guest assertions all passed", len(summary) == 1 and
                  int(summary[0][0]) >= len(required) and int(summary[0][1]) == 0 and
                  not any(status == "FAIL" for status, _ in records), str(summary)))
    return checks


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--memory", default="256")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "pma-bridge-run"))
    ap.add_argument("--serial", type=Path, help="evaluate an existing log; this does not run a guest")
    args = ap.parse_args()
    if not 1 <= args.timeout <= 600:
        ap.error("timeout must be in 1..600 seconds")
    if args.serial:
        checks = pma_checks(args.serial.read_text(errors="replace"))
        for item in checks:
            print(f"[{item['status']}] {item['check']}")
        return int(any(item["status"] != "PASS" for item in checks))
    out = Path(args.out)
    if out.exists():
        ap.error("choose a fresh output directory to preserve earlier guest receipts")
    stub = BUILD / "kernel64s" / "boot.elf"
    kernel = BUILD / "kernel64s" / "KERNEL64S.BIN"
    initrd = BUILD / "win64" / "WIN64.IMG"
    for path in (stub, kernel, initrd):
        if not path.is_file():
            raise SystemExit(f"missing guest input: {path}")
    sources = [ROOT / p for p in ("shizukudos/kernel64/subsys64.c", "shizukudos/abi/shz_vmm_pma.h",
               "shizukudos/pma_bridge/service.h", "shizukudos/kernel64/sched.c", "shizukudos/abi/shz_ipc.h")]
    inputs = {str(p.relative_to(ROOT)): digest(p) for p in (*sources, stub, kernel, initrd)}
    runner_paths = tuple(Path(p).resolve() for p in
                         (__file__, baseline.__file__, qemu.__file__, shzlib.__file__, kbuild.__file__))
    runner_inputs = {str(p.relative_to(ROOT)): digest(p) for p in runner_paths}
    receipt_path = BUILD / "kernels-build-result.json"
    receipt = json.loads(receipt_path.read_text())
    built_sources = receipt.get("sources_sha256", {})
    current_sources = kbuild.source_hashes()
    if not built_sources or any(built_sources.get(str(p.relative_to(ROOT))) != digest(p) for p in sources):
        raise SystemExit("guest build receipt does not match current PMA sources; rebuild kernels")
    if current_sources != built_sources:
        raise SystemExit("guest build receipt does not match the complete current kernel source set")
    if receipt["kernels"]["kernel64-standalone"]["sha256"] != digest(kernel):
        raise SystemExit("guest kernel does not match its build receipt")
    if receipt["kernels"]["kernel64-standalone"]["stub_sha256"] != digest(stub):
        raise SystemExit("guest boot stub does not match its build receipt")
    out.mkdir(parents=True)
    serial_path = out / "serial.log"
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    command = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory,
               "-nodefaults", "-vga", "std", "-display", "none", "-nic", "none", "-kernel", str(stub),
               "-initrd", f"{kernel},{initrd}", "-serial", f"file:{serial_path}",
               "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    started = time.monotonic()
    rc, output, timed_out = qemu.run_bounded(command, args.timeout)
    serial = serial_path.read_text(errors="replace") if serial_path.is_file() else ""
    evidence, exit_code = baseline.parse(serial)
    checks = baseline.evaluate(serial, evidence, exit_code, rc, memory=args.memory) + pma_checks(serial)
    checks.append(baseline.check("bounded isolated guest finished", not timed_out and rc == 1,
                                f"qemu_rc={rc}, expected=1, timed_out={timed_out}, timeout={args.timeout}s"))
    checks.append(baseline.check("sources and guest inputs unchanged during execution",
                  all(inputs[str(p.relative_to(ROOT))] == digest(p) for p in (*sources, stub, kernel, initrd)) and
                  kbuild.source_hashes() == current_sources))
    checks.append(baseline.check("runner and evaluator helpers unchanged during execution",
                  all(runner_inputs[str(p.relative_to(ROOT))] == digest(p) for p in runner_paths)))
    status = "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL"
    shzlib.write_json(out / "result.json", {"status": status, "profile": "Kernel64 standalone threaded IPC loopback + Bochs VBE fixture adapter",
        "scope": "Real Kernel64 scheduler/service/rings. No Windows 98, VMM, VxD, Supervisor or SMP execution.",
        "checks": checks, "inputs_sha256": inputs, "build_sources_sha256": built_sources,
        "runner_inputs_sha256": runner_inputs,
        "current_sources_sha256": current_sources,
        "command": command, "qemu_rc": rc,
        "qemu_output": output[-2000:], "seconds": round(time.monotonic() - started, 2),
        "utc": shzlib.utc_now(), "git": shzlib.git_state()})
    for item in checks:
        print(f"[{item['status']}] {item['check']} {item['detail']}")
    print(status)
    if status != "PASS":
        print(serial[-4000:])
    return int(status != "PASS")


if __name__ == "__main__":
    sys.exit(main())
