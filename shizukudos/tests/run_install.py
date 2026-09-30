#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""End-to-end installer test: build the payload, boot the installer with a blank target disk, install unattended,
verify the installed disk ON THE HOST, then boot the installed disk a second time.

1. Build (--build): kbuild.py, win64/build.py (SHZSETUP.EXE), install/mkpayload.py --answer install/tests/install-test.ini.
2. Install boot, QEMU TCG (no Supervisor, no VMX): Multiboot stub -> KERNEL64S.BIN + INSTALL.IMG, kernel command line
   `shz.setup=auto`. Target: a 512 MiB RAM block device (QEMU ivshmem-plain at PCI 00:05.0) whose memory is the host file
   target.img (memory-backend-file, share=on); a 256 MiB decoy at 00:06.0 must stay zero. Kernel64 runs its self-tests,
   then SHZSETUP.EXE, which selects the target by serial, installs, verifies, and requests shutdown.
   The RAM block device is the interim target until the AHCI/NVMe drivers (storage track) are merged.
3. Host verification of target.img (install/tests/verify_disk.py: GPT + CRCs, MBR boot code, ESP byte-identical and
   per file via mtools, e2fsck -fn on p2, SHA-256 of every manifest file via debugfs, empty FAT32 p3).
4. Second boot from the installed disk image:
   - UEFI (OVMF, disk on virtio-blk): the firmware must start \\EFI\\BOOT\\BOOTX64.EFI from the installed ESP. Whether that
     loader then starts Kernel64 (BOOT.INI mode = kernel64) depends on agent C2's boot manager: BLOCKED until it is in
     the tree (detected by the loader's own strings), after that Kernel64 must reach its self-test summary.
   - Legacy BIOS (SeaBIOS): the protective MBR's code (install/gptmbr.asm) must find the legacy-bootable ESP and run its
     boot sector, which is syslinux 6.04 installed into esp.img by install/mkpayload.py (agent C3): SYSLINUX on COM1,
     then its menu's default entry (mboot.c32 \\SHZDOS\\K64STUB.ELF --- KERNEL64S.BIN --- WIN64.IMG) must bring Kernel64
     to its self-test summary and SHZ-EXIT:0. An ESP without syslinux (mkpayload --no-bios-boot) stays BLOCKED.
Every cell is PASS / FAIL / BLOCKED; result.json in build/shizukudos/install/vm-test/.
"""
import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHZ = HERE.parent
sys.path.insert(0, str(SHZ / "tools"))
sys.path.insert(0, str(SHZ / "install" / "tests"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD  # noqa: E402
import verify_disk  # noqa: E402

INSTALL = BUILD / "install"
OUT = INSTALL / "vm-test"
K64S = BUILD / "kernel64s"
ANSWER = SHZ / "install" / "tests" / "install-test.ini"
TARGET_MIB, DECOY_MIB = 512, 256
cells = []


def cell(name, status, detail=""):
    cells.append({"check": name, "status": status, "detail": str(detail)[:900]})
    print(f"  [{status}] {name}  {detail if status != 'PASS' else ''}", flush=True)


def check(name, ok, detail=""):
    cell(name, "PASS" if ok else "FAIL", detail)
    return ok


def build():
    for script, extra in (("kbuild.py", []), ("win64/build.py", []), ("install/mkpayload.py", ["--answer", str(ANSWER)])):
        print(f"== {script}", flush=True)
        subprocess.run([sys.executable, str(SHZ / script), *extra], check=True, timeout=3600, stdout=subprocess.DEVNULL)


def blank(path, mib):
    path.unlink(missing_ok=True)
    with open(path, "wb") as f:
        f.truncate(mib << 20)


def all_zero(path):
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            if chunk.count(0) != len(chunk):
                return False
    return True


def strip_ansi(data):
    return re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", data.decode(errors="replace")).replace("\r", "")


def run_vm(cmd, serial, timeout, stop_marker=None):
    started = time.time()
    proc = subprocess.Popen([str(x) for x in cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timed_out = False
    try:
        while proc.poll() is None:
            if time.time() - started > timeout:
                timed_out = True
                break
            if stop_marker and serial.exists() and stop_marker(strip_ansi(serial.read_bytes())):
                break
            time.sleep(0.5)
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    return proc.returncode, timed_out, round(time.time() - started, 1), out


def install_boot(args):
    target, decoy, serial = OUT / "target.img", OUT / "decoy.img", OUT / "install-serial.log"
    blank(target, TARGET_MIB)
    blank(decoy, DECOY_MIB)
    serial.unlink(missing_ok=True)
    cmd = [args.qemu, "-machine", "pc", "-accel", "tcg", "-cpu", "max", "-m", "256", "-nodefaults", "-display", "none",
           "-kernel", K64S / "boot.elf", "-initrd", f"{K64S / 'KERNEL64S.BIN'},{INSTALL / 'INSTALL.IMG'}",
           "-append", "shz.setup=auto",
           "-object", f"memory-backend-file,id=tgt,size={TARGET_MIB}M,mem-path={target},share=on",
           "-device", "ivshmem-plain,memdev=tgt,addr=05",
           "-object", f"memory-backend-file,id=dcy,size={DECOY_MIB}M,mem-path={decoy},share=on",
           "-device", "ivshmem-plain,memdev=dcy,addr=06",
           "-serial", f"file:{serial}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    rc, timed_out, secs, out = run_vm(cmd, serial, args.timeout)
    text = strip_ansi(serial.read_bytes()) if serial.exists() else ""
    (OUT / "install-qemu.txt").write_text(" ".join(str(c) for c in cmd) + "\n" + out)
    print(f"   install boot: {secs} s, qemu rc {rc}, timed out {timed_out}", flush=True)
    m = re.search(r"K64 setup: SHZSETUP\.EXE exit=(-?\d+) faulted=(\d+)", text)
    exit_m = re.search(r"SHZ-EXIT:([0-9a-f]+)", text)
    check("install boot: Multiboot stub passed the command line (shz.setup=auto) to Kernel64",
          "shz.setup=auto" in text or "K64 setup: shz.setup=auto" in text, text[:300])
    check("install boot: RAM block devices ram0 (serial IVSHMEM-00:05.0) and ram1 registered",
          "serial IVSHMEM-00:05.0" in text and "ram1 = ivshmem" in text,
          [l for l in text.splitlines() if "blk_ram" in l])
    check("install boot: SHZSETUP.EXE ran unattended after the self-tests and printed SETUP-RESULT: OK",
          "SETUP-RESULT: OK" in text and "SETUP-RESULT: FAIL" not in text, [l for l in text.splitlines() if "SETUP-RESULT" in l or "ERROR" in l])
    check("install boot: SHZSETUP.EXE exit code 0, no fault", bool(m) and m.group(1) == "0" and m.group(2) == "0",
          m.group(0) if m else "no exit line")
    check("install boot: the target was chosen by the answer file's serial selector",
          "target: [0] ram0" in text or re.search(r"target: \[\d+\] ram0, 512 MiB, serial 'IVSHMEM-00:05.0'", text) is not None,
          [l for l in text.splitlines() if "target:" in l])
    check("install boot: Kernel64 self-tests before setup: 0 failures", "done, 0 self-test failure(s)" in text,
          [l for l in text.splitlines() if "self-test failure" in l or "FAIL" in l][:8])
    check("install boot: shutdown requested and the VM powered off (SHZ-EXIT:0, no timeout)",
          "power request shutdown" in text and bool(exit_m) and exit_m.group(1) == "0" and not timed_out,
          (exit_m.group(0) if exit_m else "no SHZ-EXIT", timed_out))
    check("install boot: decoy RAM disk (00:06.0) untouched", all_zero(decoy))
    decoy.unlink()
    return target, text


def uefi_second_boot(args, target):
    code, vars_src = Path(qemu.DEFAULT_OVMF_CODE), Path(qemu.DEFAULT_OVMF_VARS)
    if not code.exists() or not vars_src.exists():
        cell("second boot UEFI: firmware starts the installed ESP's BOOTX64.EFI", "BLOCKED", "OVMF not installed")
        return
    loader = (BUILD / "supervisor" / "BOOTX64.EFI").read_bytes()
    direct = "Kernel64 direct boot".encode("utf-16-le") in loader or b"Kernel64 direct boot" in loader
    work = OUT / "uefi"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    vars_copy = work / "OVMF_VARS.fd"
    shutil.copyfile(vars_src, vars_copy)
    disk = work / "disk.img"
    shutil.copyfile(target, disk)
    serial = work / "serial.log"
    cmd = [args.qemu, "-machine", "q35", "-accel", "tcg", "-cpu", "max", "-m", "512",
           # OVMF keeps QEMU's default S3 (on): its ACPI NVS at 8 MiB is a firmware hole that the boot manager hands to
           # Kernel64 (kernel64/standalone/memholes.h), which fences it off in its heap
           "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={code}",
           "-drive", f"if=pflash,format=raw,unit=1,file={vars_copy}",
           "-drive", f"file={disk},format=raw,if=virtio", "-vga", "std", "-display", "none", "-nic", "none",
           "-serial", f"file:{serial}", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    banner = "Supervisor loader (UEFI x64)"

    def done(t):
        return banner in t and ("REFUSED" in t or "SHZ-EXIT" in t or "Handing over" in t or "self-test failure" in t)
    rc, timed_out, secs, out = run_vm(cmd, serial, 900 if direct else 300, done)
    text = strip_ansi(serial.read_bytes()) if serial.exists() else ""
    (work / "qemu.txt").write_text(" ".join(str(c) for c in cmd) + "\n" + out)
    print(f"   UEFI second boot: {secs} s", flush=True)
    seen = [l.strip() for l in text.splitlines() if "Shizuku" in l or "REFUSED" in l or "Kernel64" in l or "BOOT.INI" in l][:12]
    check("second boot UEFI: OVMF found the installed GPT ESP and started \\EFI\\BOOT\\BOOTX64.EFI", banner in text, seen or text[-400:])
    if not direct:
        cell("second boot UEFI: Kernel64 starts from the installed disk (BOOT.INI mode = kernel64)", "BLOCKED",
             "the loader in this tree has no Kernel64 direct boot (agent C2's boot manager is not merged); it "
             "started the Supervisor path, which needs Intel VMX: " + "; ".join(l for l in seen if "REFUSED" in l)[:300])
    else:
        check("second boot UEFI: Kernel64 starts from the installed disk and finishes its self-tests",
              "done, 0 self-test failure(s)" in text, seen or text[-600:])
    disk.unlink()


def bios_second_boot(args, target):
    work = OUT / "bios"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    disk = work / "disk.img"
    shutil.copyfile(target, disk)
    esp_syslinux = b'"bios_boot": "syslinux' in (INSTALL / "payload" / "manifest.json").read_bytes()
    sock_dir = Path(tempfile.mkdtemp(prefix="shzinst-"))    # AF_UNIX paths are limited to 108 bytes
    serial, qmp_path = work / "serial.log", sock_dir / "qmp.sock"
    cmd = [args.qemu, "-machine", "pc", "-accel", "tcg", "-cpu", "max", "-m", "256", "-nodefaults", "-vga", "std",
           "-display", "none", "-drive", f"file={disk},format=raw,if=ide", "-serial", f"file:{serial}",
           "-qmp", f"unix:{qmp_path},server=on,wait=off", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
           "-no-reboot"]
    proc = subprocess.Popen([str(c) for c in cmd], stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT)
    screen = []
    try:
        ok = qemu.wait_for(serial, "->VBR", 120) or qemu.wait_for(serial, "FAIL:", 1)
        if esp_syslinux:
            qemu.wait_for(serial, "SHZ-EXIT:", 900)          # syslinux menu (5 s) -> Kernel64 self-tests
        else:
            time.sleep(4)                                    # let the ESP boot sector print its message
        if proc.poll() is None:
            try:
                q = qemu.QMP(qmp_path)
                screen = qemu.decode_text_page(qemu.read_guest_memory(q, 0xB8000, 4000, work / "vga.bin"))
                q.close()
            except Exception as exc:                         # evidence below says what was (not) seen
                screen = [f"(VGA text memory not read: {exc})"]
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(sock_dir, ignore_errors=True)
    text = strip_ansi(serial.read_bytes()) if serial.exists() else ""
    (work / "screen.txt").write_text("\n".join(screen) + "\n")
    check("second boot BIOS: SeaBIOS ran the protective MBR's code, which found the legacy-bootable ESP (COM1: SHZ-MBR ->VBR)",
          ok and "SHZ-MBR ->VBR" in text, text.strip()[-200:])
    if not esp_syslinux:
        vbr_msg = any("not a bootable disk" in l for l in screen)
        check("second boot BIOS: the ESP's own boot sector ran from p1 (its message is in VGA text memory)", vbr_msg,
              [l for l in screen if l.strip()][:6])
        cell("second boot BIOS: Kernel64 starts from the installed disk", "BLOCKED",
             "the payload was built with --no-bios-boot: the ESP boot sector is mkfs.fat's non-system stub")
    else:
        exit_m = re.search(r"SHZ-EXIT:([0-9a-f]+)", text)
        check("second boot BIOS: the ESP's syslinux boot sector loaded ldlinux.sys from p1 (SYSLINUX 6.04 on COM1)",
              "SYSLINUX 6.04" in text, [l for l in text.splitlines() if "SYSLINUX" in l or "SHZ-MBR" in l][:4])
        check("second boot BIOS: the installed syslinux.cfg's default entry started the Kernel64 Multiboot stub",
              "SHZ-STUB: kernel" in text, [l for l in text.splitlines() if "SHZ-STUB" in l][:4])
        check("second boot BIOS: Kernel64 starts from the installed disk and finishes its self-tests (SHZ-EXIT:0)",
              "done, 0 self-test failure(s)" in text and bool(exit_m) and exit_m.group(1) == "0",
              [l for l in text.splitlines() if "self-test failure" in l or "SHZ-EXIT" in l][:4] or text[-400:])
    disk.unlink()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--build", action="store_true", help="rebuild kernels, Win64 runtime and the payload first")
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--timeout", type=int, default=2400, help="install boot timeout, seconds")
    ap.add_argument("--keep", action="store_true", help="keep target.img")
    args = ap.parse_args()
    started = time.time()
    if args.build:
        build()
    need = [K64S / "boot.elf", K64S / "KERNEL64S.BIN", INSTALL / "INSTALL.IMG", INSTALL / "esp.img"]
    missing = [str(p) for p in need if not p.exists()]
    if missing:
        raise SystemExit("missing " + ", ".join(missing) + " (run with --build)")
    if b"IVSHMEM-00:05.0" not in (INSTALL / "shzsetup.ini").read_bytes():
        raise SystemExit("INSTALL.IMG was not built with install/tests/install-test.ini (run with --build)")
    shutil.rmtree(OUT, ignore_errors=True)
    OUT.mkdir(parents=True)
    stubs = (BUILD / "win64" / "nt_stubs.S").read_text()
    nums = {n: int(v) for n, v in re.findall(r"^(NtShzSetup\w+):\n\s+movq %rcx, %r10\n\s+movl \$(\d+), %eax", stubs, re.M)}
    check("ntdll stubs: installer syscalls NtShzSetup* are 0xb0-0xb4 (installer range; 0xe0-0xef is the NT driver host's)",
          sorted(nums.values()) == list(range(0xb0, 0xb5)), {k: hex(v) for k, v in nums.items()})
    target, text = install_boot(args)
    rep = verify_disk.verify(target, INSTALL, want_win98=True)
    for r in rep.rows:
        check("host verify: " + r["check"], r["status"] == "PASS", r["detail"])
    if rep.parts:
        uefi_second_boot(args, target)
        bios_second_boot(args, target)
    else:
        cell("second boot", "FAIL", "no partition table on the target")
    if not args.keep:
        target.unlink()
    failed = [c for c in cells if c["status"] == "FAIL"]
    blocked = [c for c in cells if c["status"] == "BLOCKED"]
    status = "FAIL" if failed else ("PASS_WITH_BLOCKED" if blocked else "PASS")
    shzlib.write_json(OUT / "result.json", {
        "profile": "installer: Kernel64 standalone (QEMU TCG, no Supervisor/VMX), ivshmem RAM disk target",
        "status": status, "cells": cells, "seconds": round(time.time() - started, 1), "qemu": qemu.qemu_version(args.qemu),
        "serial_tail": text[-6000:], "utc": shzlib.utc_now(), "git": shzlib.git_state()})
    print(f"{status}: {sum(c['status'] == 'PASS' for c in cells)} PASS, {len(failed)} FAIL, {len(blocked)} BLOCKED")
    if failed:
        print("---- install serial tail ----\n" + text[-3000:])
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
