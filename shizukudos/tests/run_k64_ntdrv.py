#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot Kernel64 WITHOUT the Supervisor under QEMU with QEMU's 'edu' PCI device attached, mount the
driver-store initrd (WIN64_NTDRV.IMG) and verify the NT driver host end to end:

  stub (Multiboot) -> Kernel64 (SHZ_STANDALONE) -> self-tests -> ntdrv_selftest():
    - loads the unmodified ECHO.SYS / DPCTIMER.SYS / PCIEDU.SYS / APITEST.SYS, calls each DriverEntry,
      drives an IOCTL through the real IRP stack, a pended IRP completed from a timer DPC,
      the edu PCI driver (BAR map + register read + IoConnectInterrupt + raised IRQ), and the
      export-surface driver whose DriverEntry checks the second export batch (registry query
      tables, device interfaces, StartIo/cancel, remove locks, power IRPs, PDO properties, DMA,
      partition tables, ...) and fails to load if any check fails;
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
    c.append(check("driver host reported providers and loaded 4 drivers", e(13) == 4, f"loaded={e(13)}"))
    api_fail = re.findall(r"^\[drv\] apitest: FAIL (.*)$", serial, re.M)
    api_pass = len(re.findall(r"^\[drv\] apitest: PASS ", serial, re.M))
    c.append(check("export-surface driver (APITEST.SYS): no FAIL line, >= 60 PASS lines",
                   not api_fail and api_pass >= 60, f"pass={api_pass} fail={len(api_fail)}" + (": " + "; ".join(api_fail[:5]) if api_fail else "")))
    m = re.search(r"^K64 ntdrv-test: apitest (\d+) passed, (\d+) failed$", serial, re.M)
    c.append(check("apitest IOCTL reported the driver's own counts (>= 60 passed, 0 failed)",
                   bool(m) and int(m.group(1)) >= 60 and int(m.group(2)) == 0, m.group(0) if m else "no count line"))
    c.append(check("driver re-initialization routine ran after DriverEntry",
                   "apitest: PASS IoRegisterDriverReinitialization" in serial))
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
    c.append(check("provider export surface >= 500 (ntoskrnl+hal)", (e(27) & 0xffffffff) >= 500,
                   f"providers={e(27) & 0xffffffff}"))
    c.append(check("user-mode app reached a driver (NtLoadDriver + NtDeviceIoControlFile)",
                   "t_ntdrv: PASS" in serial, "t_ntdrv: FAIL" if "t_ntdrv: FAIL" in serial else ""))
    c.append(check("DriverEntry ran for the echo driver", "ShzEcho: DriverEntry" in serial))
    return c


def evaluate_kmdf(serial):
    c = []
    c.append(check("KMDF image mounted (WdfLdr present)", "kmdf: KMDF image present" in serial))
    for client in ("cdrom", "hdaudbus"):
        m = re.search(rf"^K64 ntdrv-test: kmdf: client {client} load status=([0-9a-f]+) started=(\d)$", serial, re.M)
        c.append(check(f"KMDF client {client}.sys: FxDriverEntry -> WdfVersionBind -> WdfDriverCreate, DriverEntry returned success",
                       bool(m) and int(m.group(1), 16) == 0 and m.group(2) == "1", m.group(0) if m else "no result line"))
    for client in ("cdrom", "hdaudbus"):
        m = re.search(rf"^K64 ntdrv-test: kmdf: client {client} WdfDriverCreate effect: AddDevice=(\w+) DriverUnload=(\w+) framework dispatch in (\d+) major functions$", serial, re.M)
        c.append(check(f"{client}.sys: WdfDriverCreate took effect (framework AddDevice/DriverUnload/dispatch installed on the DRIVER_OBJECT)",
                       bool(m) and m.group(1) == "set" and m.group(2) == "set" and int(m.group(3)) >= 3, m.group(0) if m else "no effect line"))
    c.append(check("WdfLdr and Wdf01000 both loaded (the library through ZwLoadDriver from WdfLdr)",
                   "kmdf: framework loaded=1 loader loaded=1" in serial))
    return c


CORPUS_LOADED_MIN = 22         # measured: 22 of 23 (uniata returns STATUS_DEVICE_DOES_NOT_EXIST: no ATA controller in the VM)


def evaluate_corpus(serial):
    m = re.search(r"K64 ntdrv-test: corpus: (\d+) of (\d+) drivers loaded", serial, re.M)
    loaded, total = (int(m.group(1)), int(m.group(2))) if m else (0, 0)
    rows = re.findall(r"K64 ntdrv-test: corpus (\S+) status=([0-9a-f]+) started=(\d)", serial, re.M)
    ok = [n for n, st, s in rows if int(st, 16) == 0 and s == "1"]
    bad = [f"{n}={st}" for n, st, s in rows if not (int(st, 16) == 0 and s == "1")]
    return [check("corpus: every driver in the store was attempted and the total line printed", bool(m) and total == len(rows) and total > 0,
                  f"{loaded} of {total} loaded"),
            check(f"corpus: at least {CORPUS_LOADED_MIN} drivers load", loaded >= CORPUS_LOADED_MIN,
                  f"loaded: {', '.join(ok)}; not loaded: {', '.join(bad)}")]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--memory", default="256")
    ap.add_argument("--out", default=str(K64S / "ntdrv-run"))
    ap.add_argument("--corpus", action="store_true",
                    help="mount WIN64_CORPUS.IMG (win64/ntdrv/kmdf_image.py --all: every built corpus driver) and report how many load")
    ap.add_argument("--kmdf", action="store_true",
                    help="mount WIN64_KMDF.IMG (win64/ntdrv/kmdf_image.py: the test drivers + the corpus's WdfLdr/Wdf01000/cdrom/hdaudbus) "
                         "and require the KMDF client drivers to bind to the framework")
    args = ap.parse_args()
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / ("WIN64_CORPUS.IMG" if args.corpus else "WIN64_KMDF.IMG" if args.kmdf else "WIN64_NTDRV.IMG")
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
    if args.kmdf or args.corpus:
        checks += evaluate_kmdf(serial)
    if args.corpus:
        checks += evaluate_corpus(serial)
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
