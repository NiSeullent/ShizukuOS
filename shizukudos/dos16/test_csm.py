#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""CSM/Legacy-BIOS profile test: FreeDOS DOS16 on a real BIOS in actual Real Mode.

QEMU's SeaBIOS plays the role of the legacy firmware, so this validates the DOS16
runtime (kernel, shell, COM/MZ execution, file I/O) and the conformance programs.
It says nothing about the Shizuku Supervisor or UEFI paths.
"""
import argparse
import re
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import qemu  # noqa: E402
import shzlib  # noqa: E402
import verify  # noqa: E402
from shzlib import BUILD, sha256_file  # noqa: E402


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    parser.add_argument("--timeout", type=int, default=90)
    args = parser.parse_args()

    out = BUILD / "dos16"
    image = out / "shizukudos-dos16-hd32.img"
    if not image.exists():
        raise SystemExit("Run shizukudos/dos16/build.py first")
    run_dir = out / "run-csm"
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)
    disk = run_dir / "disk.img"
    shutil.copy2(image, disk)
    serial = run_dir / "serial.log"
    with tempfile.TemporaryDirectory(prefix="shz-qmp-") as tmp:
        sock = Path(tmp) / "qmp.sock"
        command = [args.qemu, "-name", "shz-dos16-csm", "-machine", "pc", "-accel", args.accel,
                   "-cpu", "host" if args.accel == "kvm" else "qemu64", "-m", "64",
                   "-display", "none", "-monitor", "none", "-vga", "std",
                   "-qmp", f"unix:{sock},server=on,wait=off", "-serial", f"file:{serial}",
                   "-drive", f"file={disk},format=raw,if=ide,cache=writethrough",
                   "-boot", "c", "-net", "none", "-no-reboot"]
        proc = qemu.launch(command, run_dir)
        record = {"profile": "csm-real-mode-dos16", "boot_path": "SeaBIOS (legacy BIOS) -> real mode",
                  "host_mode": "n/a (firmware is the platform)", "guest_mode": "real mode (16-bit)",
                  "kernel_instance": "dos16-freedos", "command": command}
        qmp = None
        try:
            qmp = qemu.QMP(sock)
            seen = qemu.wait_for(serial, "SHZ-EXIT:0", args.timeout)
            regs = qemu.cpu_state(qmp)
            record["independent_cpu_state"] = regs
            screen = qemu.decode_text_page(qemu.read_guest_memory(qmp, 0xB8000, 4000, run_dir / "b8000.bin"))
            (run_dir / "screen.txt").write_text("\n".join(screen) + "\n")
            qmp.call("quit")
        finally:
            if qmp:
                qmp.close()
            try:
                proc.wait(timeout=15)
            except Exception:
                proc.kill()
        record["qemu_exit_code"] = proc.returncode
    checks, text = verify.verify_disk(disk)
    checks += verify.verify_screen(screen)
    cr0 = re.search(r"CR0=([0-9a-fA-F]{8})", regs)
    checks.append(verify._check("independent CR0.PE=0 (accelerator state)", bool(cr0) and not int(cr0.group(1), 16) & 1,
                                cr0.group(0) if cr0 else "missing"))
    checks.append(verify._check("guest requested end through COM1 marker", seen))
    status = verify.overall(checks)
    record.update({"status": status, "checks": checks, "result_txt": text,
                   "image_sha256": sha256_file(image), "disk_after_sha256": sha256_file(disk),
                   "git": shzlib.git_state(), "qemu": qemu.qemu_version(args.qemu), "utc": shzlib.utc_now(),
                   "screen": screen})
    shzlib.write_json(run_dir / "result.json", record)
    for c in checks:
        print(f"  [{c['status']}] {c['check']}  {c['detail']}")
    print(status)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
