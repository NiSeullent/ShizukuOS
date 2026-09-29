#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot Kernel32 (i486 Protected Mode kernel) WITHOUT the Supervisor under QEMU and check its guest-generated results.

Profile: QEMU -kernel (Multiboot stub, kernel64/standalone/boot_pm.asm) -> Kernel32 built with SHZ_STANDALONE
(hypercalls served in-kernel over COM1/PIT/RTC). Exercises Kernel32's own paging, scheduler, sync objects, demand paging
and ring-3 fault containment. Does NOT exercise the Supervisor/VMX or the Kernel32<->Kernel64 IPC.
"""
import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
sys.path.insert(0, str(HERE))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from run_k64_standalone import check, parse  # noqa: E402
from shzlib import BUILD  # noqa: E402

K32S = BUILD / "kernel32s"


def evaluate(serial, ev, exit_code, qemu_rc):
    e = lambda s: ev.get(s, 0)  # noqa: E731
    c = [check("Kernel32 reached the end of its self-tests and exited 0", exit_code == 0 and e(29) == 0x4b333221,
               f"exit={exit_code} marker={e(29):#x} qemu_rc={qemu_rc}")]
    c.append(check("no Kernel32 self-test reported FAIL", "K32 test FAIL" not in serial and e(28) == 0,
                   "; ".join(__import__("re").findall(r"K32 test FAIL: (.*)", serial)) or f"failures={e(28)}"))
    c.append(check("CR0 has PE|WP|PG, CR3 page aligned", e(0) & 0x80010001 == 0x80010001 and e(1) & 0xfff == 0 and e(1) != 0,
                   f"cr0={e(0):#x} cr3={e(1):#x}"))
    c.append(check("timer preempted CPU-bound threads (>=10 switches)", e(2) >= 10, str(e(2))))
    c.append(check("mutex counter 20000, heap sum 10000, 16 demand-paged pages", e(3) == 20000 and e(4) == 10000 and e(5) == 16,
                   f"{e(3)} {e(4)} {e(5)}"))
    c.append(check("ring-3 exit code 42, #GP and #PF contained", e(6) == 42 and e(7) == 0x8000000d and e(8) == 0x8000000e,
                   f"{e(6)} {e(7):#x} {e(8):#x}"))
    c.append(check("ring-3 computed 500500 and saw pid 1", e(17) == 500500 and e(16) == 1, f"{e(17)} {e(16)}"))
    c.append(check("no physical pages leaked", 12 in ev and e(12) == 0, str(e(12))))
    c.append(check("timed wait(30 ms) and sleep(50 ms) on the tick clock", 28000 <= e(13) <= 150000 and 45000 <= e(14) <= 300000,
                   f"{e(13)} us, {e(14)} us"))
    return c


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--out", default=str(K32S / "run"))
    args = ap.parse_args()
    stub, kernel = K32S / "boot.elf", K32S / "KERNEL32S.BIN"
    for f in (stub, kernel):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/kbuild.py first")
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", "128", "-nodefaults", "-display", "none",
           "-kernel", str(stub), "-initrd", str(kernel), "-serial", f"file:{serial_path}",
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
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    ev, exit_code = parse(serial)
    checks = evaluate(serial, ev, exit_code, proc.returncode)
    if timed_out:
        checks.insert(0, check("run finished before the timeout", False, f"{args.timeout}s, accel={accel}"))
    status = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    shzlib.write_json(out / "result.json", {"profile": "kernel32-standalone (no Supervisor, no VMX)", "accel": accel,
                                            "status": status, "checks": checks, "seconds": round(time.time() - started, 1),
                                            "evidence": {str(k): hex(v) for k, v in sorted(ev.items())}, "command": cmd,
                                            "serial_tail": serial[-4000:], "utc": shzlib.utc_now(), "git": shzlib.git_state()})
    for x in checks:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    print(status)
    if status != "PASS":
        print("---- serial tail ----\n" + serial[-3000:])
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
