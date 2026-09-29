#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot Kernel64 WITHOUT the Supervisor under QEMU (TCG or KVM) and check its guest-generated results.

Profile: QEMU -kernel (Multiboot stub) -> Kernel64 (SHZ_STANDALONE: hypercalls served in-kernel over COM1/PIT/RTC)
-> self-tests, then the Win64 apps from WIN64.IMG. This exercises Kernel64, the PE32+ loader and the user-mode
ntdll/kernel32 for real. It does NOT exercise the Supervisor, VMX, EPT or multi-domain IPC (those need Intel VMX
in L1 and are covered by supervisor/test_qemu.py on a VMX host).
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


def memory_mib(arg):
    """QEMU -m argument -> MiB (plain number = MiB; suffixes M/G accepted)."""
    a = str(arg).strip().lower()
    if a.endswith("g"):
        return int(float(a[:-1]) * 1024)
    if a.endswith("m"):
        return int(a[:-1])
    return int(a)


def evaluate(serial, ev, exit_code, qemu_rc, memory=None):
    e = lambda s: ev.get(s, 0)  # noqa: E731
    c = [check("Kernel64 reached the end of its self-tests and exited 0", exit_code == 0 and e(29) == 0x4b363421,
               f"exit={exit_code} marker={e(29):#x} qemu_rc={qemu_rc}")]
    if memory is not None:
        # The stub uses the RAM below 4 GiB. QEMU pc puts all of -m there below 3.5 GiB; from 3.5 GiB on it splits
        # at 3 GiB (gigabyte alignment) and the rest lies above 4 GiB, which is not used (no E820 walk).
        mib = memory_mib(memory)
        want = mib if mib < 3584 else 3072
        got = e(10) & 0xffffffff                      # multiboot mem_upper excludes the first MiB, rounded down to 2 MiB
        c.append(check(f"Kernel64 manages {want} MiB of RAM and read back the top page through its direct map",
                       want - 2 <= got <= want and e(10) >> 32 & 1 == 1 and (e(10) >> 33) * 4096 > (want - 64) * 1048576,
                       f"slot10={e(10):#x}: {e(10) & 0xffffffff} MiB, probe={e(10) >> 32 & 1}, free pages={e(10) >> 33}"))
    c.append(check("no Kernel64 self-test reported FAIL", "K64 test FAIL" not in serial and e(28) == 0,
                   "; ".join(re.findall(r"K64 test FAIL: (.*)", serial)) or f"failures={e(28)}"))
    c.append(check("CR0 has PE|WP|PG and CR3 is page aligned", e(0) & 0x80010001 == 0x80010001 and e(1) & 0xfff == 0 and e(1) != 0,
                   f"cr0={e(0):#x} cr3={e(1):#x}"))
    c.append(check("timer preempted CPU-bound threads (>=10 switches)", e(2) >= 10, str(e(2))))
    c.append(check("mutex counter 20000, heap sum, 16 demand pages", e(3) == 20000 and e(4) == 10000 and e(5) == 16,
                   f"{e(3)} {e(4)} {e(5)}"))
    c.append(check("two SSE ring-3 processes exited 42/42", e(6) == 0x2a002a, hex(e(6))))
    c.append(check("ring-3 faults contained (privileged insn, kernel write, freed memory)",
                   e(7) & 0xffffffff == 0xc0000096 and e(8) & 0xffffffff == 0xc0000005 and e(9) & 0xffffffff == 0xc0000005,
                   f"{e(7) & 0xffffffff:#x} {e(8) & 0xffffffff:#x} {e(9) & 0xffffffff:#x}"))
    c.append(check("ring-3 process used 0x200000000 (8 GiB) and read its pattern back", e(16) == 0x200000000 and
                   e(17) == 0x1122334455667788, f"{e(16):#x} {e(17):#x}"))
    c.append(check("no pages leaked by the five flat processes", 12 in ev and e(12) == 0, str(e(12))))
    # Win64
    res = e(30)
    c.append(check("Win64: WIN64.IMG mounted (ntdll, kernel32, test app)", e(23) >= 3, f"files={e(23)}"))
    c.append(check("Win64: T_HELLO.EXE ran twice, exit code 7, no fault",
                   res & 0xffffffff == 7 and not res >> 32 & 1 and bool(res >> 33 & 1) and bool(res >> 34 & 1), f"slot30={res:#x}"))
    c.append(check("Win64: image base 0x140000000, PROCESSOR_ARCHITECTURE=AMD64, argc=2",
                   e(19) == 0x140000000 and e(20) == 1 and e(21) == 2, f"{e(19):#x} {e(20)} {e(21)}"))
    c.append(check("Win64: second process returned every physical page", res != 0 and e(22) == 0, f"delta={e(22)}"))
    c.append(check("Win64 console output reached the serial console", "hello from Win64 PE32+" in serial))
    return c


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--memory", default="256")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "run"))
    args = ap.parse_args()
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    for f in (stub, kernel, initrd):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-display", "none",
           "-kernel", str(stub), "-initrd", f"{kernel},{initrd}", "-serial", f"file:{serial_path}",
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
    checks = evaluate(serial, ev, exit_code, proc.returncode, memory=args.memory)
    if timed_out:
        checks.insert(0, check("run finished before the timeout", False, f"{args.timeout}s, accel={accel}"))
    status = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    record = {"profile": "kernel64-standalone (no Supervisor, no VMX)", "accel": accel, "status": status, "checks": checks,
              "seconds": round(time.time() - started, 1), "evidence": {str(k): hex(v) for k, v in sorted(ev.items())},
              "command": cmd, "qemu_output": qemu_out[-1500:], "serial_tail": serial[-4000:], "utc": shzlib.utc_now(),
              "git": shzlib.git_state()}
    shzlib.write_json(out / "result.json", record)
    for x in checks:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    print(status)
    if status != "PASS":
        print("---- serial tail ----\n" + serial[-3000:])
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
