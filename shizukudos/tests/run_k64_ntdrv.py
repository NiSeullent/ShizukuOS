#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot Kernel64 WITHOUT the Supervisor under QEMU with QEMU's 'edu' PCI device attached, mount the
driver-store initrd (WIN64_NTDRV.IMG) and verify the NT driver host end to end:

  stub (Multiboot) -> Kernel64 (SHZ_STANDALONE) -> self-tests -> ntdrv_selftest():
    - loads the unmodified ECHO.SYS / DPCTIMER.SYS / PCIEDU.SYS, calls each DriverEntry,
      drives an IOCTL through the real IRP stack, a pended IRP completed from a timer DPC,
      and the edu PCI driver (BAR map + register read + IoConnectInterrupt + raised IRQ);
  then the Win64 app harness runs \\SHZ\\TESTS\\T_NTDRV.EXE, which reaches a loaded driver from
  user mode (NtLoadDriver -> NtCreateFile("\\??\\ShzEcho") -> NtDeviceIoControlFile).

This is a bring-up/test profile (no Supervisor, no VMX). Results come from guest-computed
evidence and the serial log, never asserted by the harness.
"""
import argparse
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"


def check(name, ok, detail=""):
    return {"check": name, "status": "PASS" if ok else "FAIL", "detail": detail}


def parse(serial):
    ev, exit_code = {}, None
    for m in re.finditer(r"^SHZ-EV ([0-9a-f]+) ([0-9a-f]+)$", serial, re.M):
        ev[int(m.group(1), 16)] = int(m.group(2), 16)
    m = re.search(r"^SHZ-EXIT:([0-9a-f]+)$", serial, re.M)
    if m:
        exit_code = int(m.group(1), 16)
    return ev, exit_code


def evaluate(serial, ev):
    e = lambda s: ev.get(s, 0)  # noqa: E731
    c = []
    c.append(check("driver host reported providers and loaded 3 drivers", e(13) == 3, f"loaded={e(13)}"))
    c.append(check("echo IOCTL round-tripped through the IRP stack (10 bytes)",
                   (e(14) >> 32) == 1 and (e(14) & 0xffffffff) == 10, f"slot14={e(14):#x}"))
    c.append(check("DPC/timer/thread driver + pended IRP completed from a timer DPC",
                   (e(15) & 0xffffffff) == 1, f"slot15={e(15):#x}"))
    c.append(check("edu PCI driver found the device and read identification 0x010000ed",
                   (e(26) >> 32) == 1 and e(25) == 0x010000ed, f"found={e(26) >> 32} ident={e(25):#x}"))
    c.append(check("hosted driver recorded as the edu function's owner (pci_claim ntdrv:shzpci)",
                   bool(re.search(r"K64 ntdrv: shzpci owns PCI [0-9a-f]+:[0-9a-f]+\.[0-9a-f]+ \(1234:11e8\)", serial))))
    c.append(check("edu interrupt connected over IoConnectInterrupt and the ISR fired",
                   (e(26) & 0xffffffff) >= 1, f"isr={e(26) & 0xffffffff}"))
    c.append(check("kernel driver-host self-test overall PASS", (e(27) >> 32) == 1, f"slot27={e(27):#x}"))
    c.append(check("provider export surface >= 180 (ntoskrnl+hal)", (e(27) & 0xffffffff) >= 180,
                   f"providers={e(27) & 0xffffffff}"))
    c.append(check("user-mode app reached a driver (NtLoadDriver + NtDeviceIoControlFile)",
                   "t_ntdrv: PASS" in serial, "t_ntdrv: FAIL" if "t_ntdrv: FAIL" in serial else ""))
    c.append(check("DriverEntry ran for the echo driver", "ShzEcho: DriverEntry" in serial))
    return c


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--memory", default="256")
    ap.add_argument("--out", default=str(K64S / "ntdrv-run"))
    args = ap.parse_args()
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64_NTDRV.IMG"
    for f in (stub, kernel, initrd):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults",
           "-display", "none", "-kernel", str(stub), "-initrd", f"{kernel},{initrd}",
           "-device", "edu", "-serial", f"file:{serial_path}",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        proc.wait(timeout=args.timeout)
        timed_out = False
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    qemu_out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    ev, exit_code = parse(serial)
    checks = evaluate(serial, ev)
    if timed_out:
        checks.insert(0, check("run finished before the timeout", False, f"{args.timeout}s, accel={accel}"))
    status = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    record = {"profile": "kernel64-standalone + edu PCI (NT driver host, no Supervisor, no VMX)", "accel": accel,
              "status": status, "checks": checks, "exit_code": exit_code, "seconds": round(time.time() - started, 1),
              "evidence": {str(k): hex(v) for k, v in sorted(ev.items())}, "command": cmd,
              "qemu_output": qemu_out[-1500:], "serial_tail": serial[-6000:], "utc": shzlib.utc_now(),
              "git": shzlib.git_state()}
    shzlib.write_json(out / "result.json", record)
    for x in checks:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    print(status)
    if status != "PASS":
        print("---- serial tail ----\n" + serial[-4000:])
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
