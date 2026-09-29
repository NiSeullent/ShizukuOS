#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot matrix of the Windows 98 Shizuku Second Edition media in QEMU.

Cells: {SeaBIOS, OVMF} x {ISO as CD, ISO as hard disk (the USB-stick case: the
same bytes written raw), raw disk image}. In every cell each boot-menu entry is
booted in its own QEMU run (one QEMU at a time), selected over COM1 (the menu's
letter + Enter), and judged only from host-side evidence:

  kernel64  COM1 log parsed by shizukudos/tests/run_k64_standalone.py (parse +
            evaluate: SHZ-EXIT:0, no self-test FAIL, every self-test check, the
            T_HELLO checks) and, in addition, every other T_*.EXE listed in the
            win64 build receipt's WIN64.IMG archive reported
            "K64 win64 app: <name> exit=0 faulted=0" (tests.c runs them all).
  dos16     SHZ-EXIT:0 on COM1, then guest memory over QMP: memdisk's mBFT
            table (ACPI-style checksum) in conventional memory gives the
            address and size of the live RAM disk; those bytes are carved out
            and judged by shizukudos/dos16/verify.py (RESULT.TXT, T_COM.OUT,
            T_EXE.OUT byte-exact) plus the DOS16 banner in the text page.
  shzdos01  the ShizukuDOS 0.1 prompt "A:\\>" on COM1, then DIR lists
            NTW32.DLL, NTWRAP9X.VXD and NTWGPROB.EXE and the prompt returns.
  install   one row: boot the medium's Install entry (I) with a blank 512 MiB disk
            on AHCI port 0 (the medium on port 1), SHZSETUP installs unattended and
            powers off; the written disk is checked on the host by agent I1's
            shizukudos/install/tests/verify_disk.py against the payload the medium
            ships; then the installed disk alone boots on OVMF (S3 on: boot manager,
            BOOT.INI mode = kernel64 -> Kernel64 direct) and on SeaBIOS (GPT
            protective MBR -> the ESP's syslinux -> mboot.c32 -> Kernel64); both must
            finish Kernel64's self-tests with SHZ-EXIT:0.
  k64direct OVMF only: key K at the UEFI boot manager menu (not the legacy menu).
            Kernel64 direct boot, no CSM: the same Kernel64 evidence as above
            through shizukudos/supervisor/test_bootmgr.py's k64_checks (loader
            RAM == kernel RAM, ABI 1.1 UEFI-direct boot info, GOP handover, the
            firmware holes the loader handed over == the holes Kernel64 applied,
            CSMWrap never ran), plus OVMF's S3 ACPI NVS at 8 MiB fenced off.

Each run also checks the boot path from the COM1 log: legacy BIOS runs show the
isolinux/syslinux banner with no UEFI firmware in the command line; OVMF runs
show, in order, BDS starting the medium, the Shizuku loader, BOOT.INI read
(mode=auto, menu_timeout=5), the boot manager menu, then either no key -> auto
-> CSM legacy boot -> CSMWrap's boot device -> the isolinux/syslinux banner, or
key K -> Kernel64 direct. The UEFI Shell must never start (no startup.nsh path).
OVMF runs keep QEMU's default S3 setting (on), so OVMF reserves ACPI NVS at 8 MiB.

Hardware for every run: q35, TCG, -cpu max, 2 vCPUs (CSMWrap keeps one), 512
MiB, AHCI port 0 (CD read-only; disks with snapshot=on so the images are never
written), isa-debug-exit (Kernel64 ends the VM). Evidence per run under
build/shizuku-se-matrix/<run>/<firmware>-<medium>-<entry>/ (serial.log,
result.json); matrix.json and matrix.md summarise the run.
QEMU is a development tool; nothing here is a claim about real hardware.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "shizukudos" / "tools"))
sys.path.insert(0, str(ROOT / "shizukudos" / "tests"))
sys.path.insert(0, str(ROOT / "shizukudos" / "dos16"))
sys.path.insert(0, str(ROOT / "shizukudos" / "supervisor"))
sys.path.insert(0, str(ROOT / "shizukudos" / "install" / "tests"))
sys.path.insert(0, str(ROOT / "tools"))
import qemu as qemu_tools  # noqa: E402
import run_k64_standalone as k64check  # noqa: E402
import shzlib  # noqa: E402
import verify as dos16verify  # noqa: E402

BUILD = ROOT / "build"
DEFAULT_ISO = BUILD / "windows98-shizuku-second-edition.iso"
DEFAULT_DISK = BUILD / "windows98-shizuku-second-edition-disk.img"
OUT = BUILD / "shizuku-se-matrix"
WIN64_RECEIPT = BUILD / "shizukudos" / "win64" / "build-result.json"
FIRMWARES = ("seabios", "ovmf")
MEDIA = ("iso-cd", "iso-hdd", "disk", "iso-usb")  # iso-usb (xHCI mass storage) is optional, not in the default set
ENTRIES = ("kernel64", "dos16", "shzdos01", "k64direct", "install")  # install: only on media built with SHZSETUP
INSTALL_TARGET_MIB = 512
UEFI_ONLY = {"k64direct"}
UEFI_MENU = b"Shizuku boot manager menu: press a key"
MEDIUM_TEXT = {"iso-cd": "ISO as CD", "iso-hdd": "ISO as hard disk (USB-stick image)", "disk": "raw disk image",
               "iso-usb": "ISO as USB mass storage (xHCI)"}
MENU_READY = b"Automatic boot in"
ANSI = re.compile(r"\x1b\[[0-9;?=]*[A-Za-z]|\x1b[()][A-Z0-9]|[\x0e\x0f]")


def check(name: str, ok: bool, detail: str = "") -> dict:
    return {"check": name, "status": "PASS" if ok else "FAIL", "detail": detail}


def clean(data: bytes) -> str:
    return ANSI.sub("", data.decode("latin-1")).replace("\r", "")


def host_load() -> str:
    try:
        return " ".join(f"{x:.2f}" for x in os.getloadavg())
    except OSError:
        return "?"


# ---------------------------------------------------------------------------- QEMU run

class Serial:
    """COM1 as a QEMU socket chardev: a reader thread keeps the guest from ever blocking on a full socket."""

    def __init__(self, path: Path):
        deadline = time.time() + 30
        while True:
            try:
                self.sock = socket.socket(socket.AF_UNIX)
                self.sock.connect(str(path))
                break
            except OSError:
                self.sock.close()
                if time.time() > deadline:
                    raise
                time.sleep(0.1)
        self.buf = bytearray()
        self.lock = threading.Lock()
        self.closed = False
        self.thread = threading.Thread(target=self._reader, daemon=True)
        self.thread.start()

    def _reader(self) -> None:
        while True:
            try:
                data = self.sock.recv(65536)
            except OSError:
                break
            if not data:
                break
            with self.lock:
                self.buf += data
        self.closed = True

    def data(self) -> bytes:
        with self.lock:
            return bytes(self.buf)

    def send(self, text: bytes) -> None:
        self.sock.sendall(text)

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def wait_for(serial: Serial, proc: subprocess.Popen, predicate, timeout: float, start: int = 0):
    """Poll until predicate(text since `start`) returns a truthy value, the VM ends, or the time runs out."""
    deadline = time.time() + timeout
    while True:
        found = predicate(serial.data()[start:])
        if found:
            return found
        if proc.poll() is not None or time.time() > deadline:
            time.sleep(0.5)  # the reader thread may still hold the last bytes
            return predicate(serial.data()[start:])
        time.sleep(0.2)


def qemu_command(args, firmware: str, medium: str, image: Path, run_dir: Path, sock_dir: Path) -> list[str]:
    cmd = [args.qemu, "-name", f"shz-se-{firmware}-{medium}", "-machine", "q35", "-accel", "tcg", "-cpu", "max",
           "-smp", str(args.smp), "-m", str(args.memory), "-display", "none", "-vga", "std", "-net", "none",
           "-no-reboot", "-monitor", "none",
           "-chardev", f"socket,id=com1,path={sock_dir / 'com1.sock'},server=on,wait=off,logfile={run_dir / 'serial.log'}",
           "-serial", "chardev:com1",
           "-qmp", f"unix:{sock_dir / 'qmp.sock'},server=on,wait=off",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    if firmware == "ovmf":
        vars_copy = run_dir / "OVMF_VARS.fd"
        shutil.copyfile(args.ovmf_vars, vars_copy)
        cmd += ["-drive", f"if=pflash,unit=0,format=raw,readonly=on,file={args.ovmf_code}",
                "-drive", f"if=pflash,unit=1,format=raw,file={vars_copy}"]
    if medium == "iso-cd":
        cmd += ["-drive", f"file={image},format=raw,if=none,id=boot,readonly=on,media=cdrom",
                "-device", "ide-cd,drive=boot,bus=ide.0,bootindex=1"]
    elif medium == "iso-usb":
        cmd += ["-device", "qemu-xhci,id=xhci", "-drive", f"file={image},format=raw,if=none,id=boot,snapshot=on",
                "-device", "usb-storage,bus=xhci.0,drive=boot,bootindex=1"]
    else:
        cmd += ["-drive", f"file={image},format=raw,if=none,id=boot,snapshot=on",
                "-device", "ide-hd,drive=boot,bus=ide.0,bootindex=1"]
    return cmd


# ---------------------------------------------------------------------------- evidence

def expected_win64_apps() -> list[str]:
    receipt = json.loads(WIN64_RECEIPT.read_text())
    names = [f.split("\\")[-1] for f in receipt["archive"]["files"] if f.upper().startswith("\\SHZ\\TESTS\\T_")
             and f.upper().endswith(".EXE")]
    return sorted(names)


def judge_kernel64(raw: bytes, qemu_rc) -> list[dict]:
    text = raw.decode("latin-1").replace("\r", "")
    ev, exit_code = k64check.parse(text)
    checks = [dict(c, check=f"run_k64_standalone: {c['check']}") for c in k64check.evaluate(text, ev, exit_code, qemu_rc)]
    apps = {m.group(1): (int(m.group(2)), int(m.group(3)))
            for m in re.finditer(r"K64 win64 app: (\S+) exit=(-?\d+) faulted=(\d+)", text)}
    expected = [name for name in expected_win64_apps() if name.upper() != "T_HELLO.EXE"]
    missing = [name for name in expected if name not in apps]
    failed = [f"{name} exit={apps[name][0]} faulted={apps[name][1]}" for name in expected
              if name in apps and apps[name] != (0, 0)]
    checks.append(check(f"every other T_*.EXE of WIN64.IMG ran and exited 0 without a fault ({len(expected)} apps)",
                        not missing and not failed and bool(expected),
                        f"{len(apps)} reported" + (f"; missing {missing}" if missing else "")
                        + (f"; failed {failed}" if failed else "")))
    holes = re.search(r"K64: (\d+) firmware memory hole\(s\): (\d+) page\(s\) kept out of the page allocator, "
                      r"(\d+) KiB of the heap fenced off", text)
    stub_holes = len(re.findall(r"SHZ-STUB: firmware hole", text))
    checks.append(check("memory map: holes reported by the Multiboot stub == holes applied by Kernel64",
                        (int(holes.group(1)) if holes else 0) == stub_holes,
                        f"stub {stub_holes}, kernel {holes.group(0) if holes else 'none'}"))
    return checks


def judge_k64direct(raw: bytes, qemu_rc) -> list[dict]:
    """Kernel64 direct boot: C2's k64_checks (shizukudos/supervisor/test_bootmgr.py) on this run's COM1 log."""
    import test_bootmgr  # noqa: E402  (shizukudos/supervisor; imported only for these cells)
    text = raw.decode("latin-1").replace("\r", "")
    apps = expected_win64_apps()
    checks = [dict(c, check=c["check"].replace("[k64direct] ", "test_bootmgr.k64_checks: "))
              for c in test_bootmgr.k64_checks("k64direct", text, qemu_rc, {"cmdline": "", "holes": True}, apps)]
    checks.append(check("OVMF S3 ACPI NVS at 8 MiB is a firmware hole fenced off in Kernel64's heap (not RAM)",
                        bool(re.search(r"firmware hole 0x0000000000800000 size 0x[0-9a-f]+ \(occupied by "
                                       r"EfiACPIMemoryNVS[^\n]*: fenced off in Kernel64's heap", text))))
    return checks


def find_mbft(low: bytes):
    """memdisk's mBFT in conventional memory: 'mBFT' signature, ACPI checksum over `length` bytes."""
    pos = low.find(b"mBFT")
    while pos >= 0:
        length = struct.unpack_from("<I", low, pos + 4)[0] if pos + 8 <= len(low) else 0
        if 52 <= length <= 256 and pos + length <= len(low) and sum(low[pos:pos + length]) & 0xFF == 0:
            diskbuf, disksize = struct.unpack_from("<II", low, pos + 44)
            return {"address": pos, "length": length, "diskbuf": diskbuf, "sectors": disksize,
                    "version": f"{low[pos + 43]}.{low[pos + 42]:02d}"}
        pos = low.find(b"mBFT", pos + 1)
    return None


def judge_dos16(qmp, run_dir: Path, pristine: bytes, keep: bool) -> tuple[list[dict], dict]:
    checks, info = [], {}
    low = qemu_tools.read_guest_memory(qmp, 0, 0xA0000, run_dir / "low.bin")
    mbft = find_mbft(low)
    checks.append(check("memdisk mBFT found in conventional memory (checksum valid)", bool(mbft), str(mbft)))
    if not mbft:
        return checks, info  # low.bin stays as evidence
    (run_dir / "low.bin").unlink(missing_ok=True)
    size = mbft["sectors"] * 512
    checks.append(check("RAM disk size == the DOS16 image on the medium", size == len(pristine),
                        f"{size} vs {len(pristine)}"))
    disk = run_dir / "ramdisk.img"
    data = qemu_tools.read_guest_memory(qmp, mbft["diskbuf"], size, disk)
    info["mbft"] = mbft
    info["ramdisk_sha256"] = shzlib.sha256_bytes(data)
    checks.append(check("RAM disk sector 0 == the image's MBR (it is the DOS16 disk)", data[:512] == pristine[:512]))
    checks.append(check("RAM disk differs from the pristine image (the guest wrote its results)", data != pristine))
    more, text = dos16verify.verify_disk(disk)
    checks += [dict(c, check=f"dos16/verify.py: {c['check']}") for c in more]
    info["result_txt"] = text
    screen = qemu_tools.decode_text_page(qemu_tools.read_guest_memory(qmp, 0xB8000, 4000, run_dir / "b8000.bin"))
    (run_dir / "b8000.bin").unlink(missing_ok=True)
    (run_dir / "screen.txt").write_text("\n".join(screen) + "\n")
    checks += [dict(c, check=f"dos16/verify.py: {c['check']}") for c in dos16verify.verify_screen(screen)]
    if not keep:
        disk.unlink(missing_ok=True)
    return checks, info


def stutter(literal: str) -> str:
    """Regex for a literal whose characters may be repeated. CSMWrap's boot CPU and its BIOS-proxy AP both write
    COM1 while it starts, and its log then shows doubled characters ('BIOS proxy reaady', 'Boot deevice'); the
    matched text is kept in the check detail, so such garbling stays visible in the evidence."""
    return "".join(re.escape(ch) + "+" for ch in literal)


def boot_path_checks(firmware: str, medium: str, entry: str, text: str, command: list[str]) -> list[dict]:
    banner = "SYSLINUX 6.04" if medium == "disk" else "ISOLINUX 6.04"
    if firmware == "seabios":
        return [check("legacy BIOS: QEMU's SeaBIOS (no UEFI flash in the command line)",
                      not any("pflash" in c for c in command)),
                check(f"legacy BIOS: {banner} started from the medium", banner in text)]
    steps = [("OVMF BDS starts the medium's UEFI boot option",
              r"BdsDxe: starting Boot\w+ \"UEFI (QEMU (DVD-ROM|HARDDISK)|QEMU QEMU USB HARDDRIVE)"),
             ("\\EFI\\BOOT\\BOOTX64.EFI = the Shizuku loader started", r"Supervisor loader \(UEFI x64\)"),
             ("boot manager read \\EFI\\SHIZUKU\\BOOT.INI: mode=auto, menu_timeout=5",
              r"Boot manager: \\EFI\\SHIZUKU\\BOOT\.INI mode=auto, csm_path=\\EFI\\SHIZUKU\\CSMWRAP\.EFI, "
              r"auto_kernel64=no, menu_timeout=5"),
             ("boot manager menu shown", r"Shizuku boot manager menu: press a key within 5 seconds")]
    if entry == "k64direct":
        steps += [("key K typed on COM1 chose Kernel64 direct", r"Boot manager menu: key 'K': mode=kernel64 for this boot"),
                  ("Kernel64 direct boot started, no CSM", r"Kernel64 direct boot \(mode=kernel64\)"),
                  ("loader exited boot services and handed over the firmware holes",
                   r"ExitBootServices done \(0x[0-9a-f]+ call\(s\)\); Kernel64 RAM \[0, 0x[0-9a-f]+\); "
                   r"0x[0-9a-f]+ firmware hole\(s\) handed over at 0x6000")]
    else:
        steps += [("no key: BOOT.INI policy followed", r"Boot manager menu: no key within 5 seconds; BOOT.INI mode=auto\."),
                  ("no usable virtualization backend under TCG", r"Supervisor profile not available: "),
                  ("boot manager chose the CSM legacy boot",
                   r"CSM legacy boot \(mode=auto, no usable virtualization backend\)"),
                  ("CSMWrap BIOS proxy on a reserved AP", stutter("BIOS proxy ready (AP ") + r"\d+\)+"),
                  ("CSMWrap boot device = the controller of the medium",
                   stutter("bootdev: Boot device: PCI ") + (r"[0-9a-f]{2}:[0-9a-f]{2}\.\d" if medium == "iso-usb"
                                                            else stutter("00:1f.2"))),
                  (f"SeaBIOS CSM legacy-booted the medium: {banner}", stutter(banner))]
    out, pos = [check("UEFI: OVMF in pflash", any("pflash" in c for c in command)),
                check("the UEFI Shell never started (no startup.nsh path)",
                      "EFI Internal Shell" not in text and "startup.nsh" not in text.lower())], 0
    for name, rx in steps:
        m = re.compile(rx).search(text, pos)
        out.append(check(f"UEFI path (in order): {name}", bool(m), m.group(0)[:100] if m else "missing / out of order"))
        if m:
            pos = m.end()
    return out


# ---------------------------------------------------------------------------- one run

def run_entry(args, firmware: str, medium: str, image: Path, entry: str, run_dir: Path, ctx: dict) -> dict:
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)
    record = {"firmware": firmware, "medium": medium, "entry": entry, "image": str(image), "utc": shzlib.utc_now(),
              "host_load_at_start": host_load()}
    checks: list[dict] = []
    key = ctx["keys"].get(entry, "")  # k64direct uses the UEFI menu key K instead
    with tempfile.TemporaryDirectory(prefix="shz-se-mx-") as tmp:
        sock_dir = Path(tmp)
        command = qemu_command(args, firmware, medium, image, run_dir, sock_dir)
        record["command"] = command
        started = time.time()
        proc = subprocess.Popen(command, stdout=open(run_dir / "qemu.out", "wb"), stderr=subprocess.STDOUT)
        serial = qmp = None
        try:
            serial = Serial(sock_dir / "com1.sock")
            qmp = qemu_tools.QMP(sock_dir / "qmp.sock", timeout=30)
            if entry == "k64direct":
                menu = wait_for(serial, proc, lambda d: UEFI_MENU in d, args.menu_timeout)
                record["menu_seconds"] = round(time.time() - started, 1)
                checks.append(check("UEFI boot manager menu reached (console mirrored on COM1)", bool(menu),
                                    f"{record['menu_seconds']} s"))
                if menu:
                    mark = len(serial.data())
                    serial.send(b"k")
                    done = wait_for(serial, proc, lambda d: re.search(rb"(?m)^SHZ-EXIT:([0-9a-f]+)\r?$", d),
                                    args.timeout, mark)
                    try:
                        proc.wait(timeout=30)  # isa-debug-exit ends the VM right after SHZ-EXIT
                    except subprocess.TimeoutExpired:
                        pass
                    record["seconds"] = round(time.time() - started, 1)
                    checks.append(check("Kernel64 printed SHZ-EXIT", bool(done),
                                        done.group(0).decode().strip() if done else "none"))
                    checks += judge_k64direct(serial.data()[mark:], proc.returncode)
                menu = None                                   # the legacy menu is not used by this entry
            else:
                menu = wait_for(serial, proc, lambda d: MENU_READY in d, args.menu_timeout)
                record["menu_seconds"] = round(time.time() - started, 1)
                checks.append(check("boot menu reached (menu.c32 on COM1)", bool(menu), f"{record['menu_seconds']} s"))
            if menu:
                time.sleep(1.0)
                mark = len(serial.data())
                serial.send(key.encode())
                time.sleep(0.5)
                serial.send(b"\r")
                loads = ctx["loads"][medium][entry]
                started_entry = wait_for(serial, proc, lambda d: all(
                    re.search(rb"Loading " + re.escape(x.encode()) + rb"\.\.\. ?ok", d) for x in loads), 300, mark)
                checks.append(check(f"menu entry {entry!r} selected over COM1: loaded {', '.join(loads)}",
                                    bool(started_entry)))
                if entry == "kernel64":
                    done = wait_for(serial, proc, lambda d: re.search(rb"(?m)^SHZ-EXIT:([0-9a-f]+)\r?$", d),
                                    args.timeout, mark)
                    try:
                        proc.wait(timeout=30)  # isa-debug-exit ends the VM right after SHZ-EXIT
                    except subprocess.TimeoutExpired:
                        pass
                    record["seconds"] = round(time.time() - started, 1)
                    checks.append(check("Kernel64 printed SHZ-EXIT", bool(done),
                                        done.group(0).decode().strip() if done else "none"))
                    checks += judge_kernel64(serial.data()[mark:], proc.returncode)
                elif entry == "dos16":
                    done = wait_for(serial, proc, lambda d: re.search(rb"(?m)^SHZ-EXIT:(\d+)\r?$", d),
                                    args.timeout, mark)
                    record["seconds"] = round(time.time() - started, 1)
                    checks.append(check("DOS16 AUTOEXEC reached SHZEXIT: SHZ-EXIT:0 on COM1",
                                        bool(done) and done.group(1) == b"0",
                                        done.group(0).decode().strip() if done else "none"))
                    if done and proc.poll() is None:
                        more, info = judge_dos16(qmp, run_dir, ctx["dos16_image"], args.keep_ramdisk)
                        checks += more
                        record["dos16"] = info
                else:
                    prompt = wait_for(serial, proc, lambda d: b"A:\\>" in d, args.timeout, mark)
                    checks.append(check("ShizukuDOS 0.1 prompt A:\\> on COM1", bool(prompt)))
                    if prompt:
                        mark2 = len(serial.data())
                        serial.send(b"DIR\r")
                        names = (b"NTW32   .DLL", b"NTWRAP9X.VXD", b"NTWGPROB.EXE")
                        listed = wait_for(serial, proc, lambda d: all(n in d for n in names) and d.rstrip().endswith(
                            b"A:\\>"), 120, mark2)
                        checks.append(check("DIR lists NTW32.DLL, NTWRAP9X.VXD, NTWGPROB.EXE and the prompt returns",
                                            bool(listed)))
                    record["seconds"] = round(time.time() - started, 1)
        except Exception as exc:  # a harness failure is a FAIL of this run, recorded, never a PASS
            checks.append(check("harness", False, f"{type(exc).__name__}: {exc}"))
        finally:
            if qmp:
                try:
                    qmp.call("quit")
                except Exception:
                    pass
                qmp.close()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            if serial:
                serial.close()
        record["qemu_exit_code"] = proc.returncode
    log = run_dir / "serial.log"
    text = clean(log.read_bytes()) if log.exists() else ""
    checks = boot_path_checks(firmware, medium, entry, text, record["command"]) + checks
    record["checks"] = checks
    record["status"] = "PASS" if checks and all(c["status"] == "PASS" for c in checks) else "FAIL"
    (run_dir / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


# ---------------------------------------------------------------------------- install row

def boot_qemu(args, firmware: str, drives: list[tuple[str, Path, bool, int]], run_dir: Path, sock_dir: Path) -> list[str]:
    """QEMU for the install row: drives = [(kind 'cd'|'hd', image, writable, bootindex or 0)], AHCI ports 0.. in order."""
    cmd = [args.qemu, "-name", f"shz-se-install-{firmware}", "-machine", "q35", "-accel", "tcg", "-cpu", "max",
           "-smp", str(args.smp), "-m", str(args.memory), "-display", "none", "-vga", "std", "-net", "none",
           "-no-reboot", "-monitor", "none",
           "-chardev", f"socket,id=com1,path={sock_dir / 'com1.sock'},server=on,wait=off,logfile={run_dir / 'serial.log'}",
           "-serial", "chardev:com1", "-qmp", f"unix:{sock_dir / 'qmp.sock'},server=on,wait=off",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]
    if firmware == "ovmf":
        vars_copy = run_dir / "OVMF_VARS.fd"
        shutil.copyfile(args.ovmf_vars, vars_copy)
        cmd += ["-drive", f"if=pflash,unit=0,format=raw,readonly=on,file={args.ovmf_code}",
                "-drive", f"if=pflash,unit=1,format=raw,file={vars_copy}"]
    for port, (kind, image, writable, bootindex) in enumerate(drives):
        opts = f"file={image},format=raw,if=none,id=d{port}" + (",readonly=on,media=cdrom" if kind == "cd" else
                                                                   ("" if writable else ",snapshot=on"))
        dev = f"{'ide-cd' if kind == 'cd' else 'ide-hd'},drive=d{port},bus=ide.{port}" + (
            f",bootindex={bootindex}" if bootindex else "")
        cmd += ["-drive", opts, "-device", dev]
    return cmd


def one_boot(args, firmware, drives, run_dir: Path, action, timeout: int) -> tuple[bytes, int | None, list[str]]:
    """One QEMU run: `action(serial, proc)` drives it; returns the COM1 bytes, QEMU's exit code and the command."""
    run_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="shz-se-in-") as tmp:
        sock_dir = Path(tmp)
        cmd = boot_qemu(args, firmware, drives, run_dir, sock_dir)
        proc = subprocess.Popen(cmd, stdout=open(run_dir / "qemu.out", "wb"), stderr=subprocess.STDOUT)
        serial = qmp = None
        try:
            serial = Serial(sock_dir / "com1.sock")
            qmp = qemu_tools.QMP(sock_dir / "qmp.sock", timeout=30)
            action(serial, proc)
            wait_for(serial, proc, lambda d: re.search(rb"(?m)^SHZ-EXIT:[0-9a-f]+\r?$", d), timeout)
            try:
                proc.wait(timeout=30)                    # Kernel64 ends the VM through isa-debug-exit
            except subprocess.TimeoutExpired:
                pass
        finally:
            if qmp:
                try:
                    qmp.call("quit")
                except Exception:
                    pass
                qmp.close()
            try:
                proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
            data = serial.data() if serial else b""
            if serial:
                serial.close()
    return data, proc.returncode, cmd


def k64_finished(text: str) -> tuple[bool, str]:
    exit_m = re.search(r"(?m)^SHZ-EXIT:([0-9a-f]+)$", text)
    fails = [l for l in text.splitlines() if l.startswith("K64 test FAIL")]
    ok = "done, 0 self-test failure(s)" in text and bool(exit_m) and exit_m.group(1) == "0" and not fails
    return ok, (exit_m.group(0) if exit_m else "no SHZ-EXIT") + (f"; {fails[:3]}" if fails else "")


def run_install_row(args, firmware: str, medium: str, image: Path, run_dir: Path, ctx: dict) -> dict:
    import verify_disk  # noqa: E402  (agent I1: shizukudos/install/tests/verify_disk.py)
    shutil.rmtree(run_dir, ignore_errors=True)
    run_dir.mkdir(parents=True)
    record = {"firmware": firmware, "medium": medium, "entry": "install", "image": str(image), "utc": shzlib.utc_now(),
              "host_load_at_start": host_load(), "phases": {}}
    checks: list[dict] = []
    started = time.time()
    target = run_dir / "target.img"
    with open(target, "wb") as fh:
        fh.truncate(INSTALL_TARGET_MIB << 20)
    setup = ctx["setup"][medium]
    medium_kind = "cd" if medium == "iso-cd" else "hd"
    medium_before = shzlib.sha256_file(image)
    try:
        # A. install: blank disk on AHCI port 0, the medium on port 1 (boot device)
        def press_install(serial, proc):
            menu = wait_for(serial, proc, lambda d: MENU_READY in d, args.menu_timeout)
            checks.append(check("install: legacy boot menu reached", bool(menu)))
            if not menu:
                return
            time.sleep(1.0)
            mark = len(serial.data())
            serial.send(ctx["keys"]["setup"].encode())
            time.sleep(0.5)
            serial.send(b"\r")
            loaded = wait_for(serial, proc, lambda d: re.search(rb"Loading /SHZ/SETUP/INSTALL\.IMG\.\.\. ?ok", d), 300, mark)
            checks.append(check("install: Install entry loaded /SHZ/SETUP/INSTALL.IMG (mboot.c32, shz.setup=auto)",
                                bool(loaded)))
        raw, rc, cmd = one_boot(args, firmware, [("hd", target, True, 0), (medium_kind, image, False, 1)],
                                run_dir / "1-install", press_install, args.install_timeout)
        text = clean(raw)
        record["phases"]["install"] = {"command": cmd, "qemu_exit_code": rc, "seconds": round(time.time() - started, 1)}
        checks += [dict(c, check=f"install boot path: {c['check']}") for c in boot_path_checks(firmware, medium, "install",
                                                                                              text, cmd)]
        m = re.search(r"K64 setup: SHZSETUP\.EXE exit=(-?\d+) faulted=(\d+)", text)
        tgt = re.search(r"target: \[\d+\] (\S+), (\d+) MiB", text)
        checks += [
            check("install: Kernel64 got shz.setup=auto and started SHZSETUP.EXE", "K64 setup: shz.setup=auto" in text),
            check("install: SHZSETUP chose the blank 512 MiB AHCI disk (answer file Select=first)",
                  bool(tgt) and tgt.group(1).startswith("ahci") and tgt.group(2) == str(INSTALL_TARGET_MIB),
                  tgt.group(0) if tgt else [l for l in text.splitlines() if "target" in l.lower()][:4]),
            check("install: SETUP-RESULT: OK", "SETUP-RESULT: OK" in text and "SETUP-RESULT: FAIL" not in text,
                  [l for l in text.splitlines() if "SETUP-RESULT" in l or "ERROR" in l][:6]),
            check("install: SHZSETUP.EXE exit 0, no fault", bool(m) and m.group(1) == "0" and m.group(2) == "0",
                  m.group(0) if m else "no exit line"),
            check("install: shutdown requested, VM powered off with SHZ-EXIT:0",
                  "power request shutdown" in text and bool(re.search(r"(?m)^SHZ-EXIT:0$", text)), f"qemu rc {rc}"),
            check("install: the medium was not written (sha256 before == after the install boot)",
                  shzlib.sha256_file(image) == medium_before, medium_before[:16]),
        ]
        # B. host verification of the written disk against the payload this medium ships
        rep = verify_disk.verify(target, setup["directory"], want_win98=False)
        checks += [dict(r, check=f"host verify_disk.py: {r['check']}") for r in rep.rows]
        # C. UEFI boot of the installed disk alone (OVMF, S3 on)
        raw, rc, cmd = one_boot(args, "ovmf", [("hd", target, False, 1)], run_dir / "2-uefi", lambda s, p: None,
                                args.timeout)
        text = clean(raw)
        record["phases"]["uefi"] = {"command": cmd, "qemu_exit_code": rc}
        lh = re.search(r"0x([0-9a-f]+) firmware hole\(s\) handed over at 0x6000", text)
        kh = re.search(r"K64: (\d+) firmware memory hole\(s\)", text)
        ok, detail = k64_finished(text)
        checks += [
            check("installed disk, UEFI: OVMF started the installed ESP's \\EFI\\BOOT\\BOOTX64.EFI",
                  bool(re.search(r"BdsDxe: starting Boot\w+ \"UEFI QEMU HARDDISK", text)) and
                  "Supervisor loader (UEFI x64)" in text),
            check("installed disk, UEFI: its BOOT.INI mode=kernel64 -> Kernel64 direct boot",
                  "BOOT.INI mode=kernel64" in text and "Kernel64 direct boot (mode=kernel64)" in text),
            check("installed disk, UEFI: firmware holes handed over == applied (S3 NVS at 8 MiB fenced off)",
                  bool(lh) and (int(kh.group(1)) if kh else 0) == int(lh.group(1), 16) and
                  "firmware hole 0x0000000000800000" in text, (lh.group(0) if lh else "none", kh.group(0) if kh else "none")),
            check("installed disk, UEFI: Kernel64 finished its self-tests, 0 failures, SHZ-EXIT:0", ok, detail),
            check("installed disk, UEFI: the UEFI Shell never started", "EFI Internal Shell" not in text),
        ]
        # D. legacy BIOS boot of the installed disk alone (SeaBIOS)
        raw, rc, cmd = one_boot(args, "seabios", [("hd", target, False, 1)], run_dir / "3-bios", lambda s, p: None,
                                args.timeout)
        text = clean(raw)
        record["phases"]["bios"] = {"command": cmd, "qemu_exit_code": rc}
        ok, detail = k64_finished(text)
        checks += [
            check("installed disk, BIOS: GPT protective MBR code found the legacy-bootable ESP (SHZ-MBR ->VBR)",
                  "SHZ-MBR ->VBR" in text),
            check("installed disk, BIOS: the ESP's syslinux loaded (SYSLINUX 6.04 on COM1)", "SYSLINUX 6.04" in text),
            check("installed disk, BIOS: its syslinux.cfg default entry started the Kernel64 Multiboot stub",
                  "SHZ-STUB: kernel" in text),
            check("installed disk, BIOS: Kernel64 finished its self-tests, 0 failures, SHZ-EXIT:0", ok, detail),
        ]
    except Exception as exc:  # a harness failure is a FAIL of this row, recorded, never a PASS
        checks.append(check("harness", False, f"{type(exc).__name__}: {exc}"))
    finally:
        record["target_sha256"] = shzlib.sha256_file(target) if target.exists() else None
        if not args.keep_ramdisk:
            target.unlink(missing_ok=True)
    record["seconds"] = round(time.time() - started, 1)
    record["checks"] = checks
    record["status"] = "PASS" if checks and all(c["status"] == "PASS" for c in checks) else "FAIL"
    (run_dir / "result.json").write_text(json.dumps(record, indent=2) + "\n")
    return record


# ---------------------------------------------------------------------------- main

def media_context(iso: Path, disk: Path) -> dict:
    ctx = {}
    for name, path in (("iso", iso), ("disk", disk)):
        receipt = path.with_suffix(".json")
        if not path.is_file() or not receipt.is_file():
            raise SystemExit(f"{path} or its receipt {receipt} is missing: build it first "
                             f"(tools/build_shizuku_se_{'iso' if name == 'iso' else 'disk'}.py)")
        data = json.loads(receipt.read_text())
        digest = shzlib.sha256_file(path)
        if data["sha256"] != digest:
            raise SystemExit(f"{path} does not match its receipt {receipt}")
        ctx[name] = {"path": str(path), "sha256": digest, "bytes": path.stat().st_size, "receipt": data}
    ctx["keys"] = ctx["iso"]["receipt"]["menu"]["keys"]
    ctx["loads"] = {}
    for medium, key in (("iso-cd", "iso"), ("iso-hdd", "iso"), ("iso-usb", "iso"), ("disk", "disk")):
        menu = ctx[key]["receipt"]["menu"]
        k64 = [f"{menu['k64_dir']}/KERNEL64S.BIN", f"{menu['k64_dir']}/WIN64.IMG"]
        ctx["loads"][medium] = {"kernel64": k64, "dos16": [menu["dos16"]], "shzdos01": [menu["shzdos01"]]}
        ctx.setdefault("setup_entry", {})[medium] = menu.get("setup_entry", False)
        info = ctx[key]["receipt"].get("setup", {})
        ctx.setdefault("setup", {})[medium] = {"directory": ROOT / info["directory"]} if info.get("present") else None
    # The DOS16 image the menu boots, as built (the same bytes are on the ISO and, as \SHZDOS\DISK.IMG, on the disk).
    dos16 = next(i for i in ctx["iso"]["receipt"]["inputs"] if i["name"].endswith("DISK.IMG"))
    ctx["dos16_image"] = (ROOT / dos16["path"]).read_bytes()
    if shzlib.sha256_bytes(ctx["dos16_image"]) != dos16["sha256"]:
        raise SystemExit("the DOS16 image in build/ changed since the ISO was built; rebuild the media")
    return ctx


def write_summary(out: Path, runs: list[dict], ctx: dict, args) -> dict:
    cells = []
    for firmware in args.firmware:
        for medium in args.media:
            mine = [r for r in runs if r["firmware"] == firmware and r["medium"] == medium]
            status = "PASS" if mine and all(r["status"] == "PASS" for r in mine) else "FAIL"
            cells.append({"firmware": firmware, "medium": medium, "status": status,
                          "entries": {r["entry"]: {"status": r["status"], "seconds": r.get("seconds"),
                                                   "failed": [c["check"] for c in r["checks"] if c["status"] != "PASS"]}
                                      for r in mine}})
    summary = {"utc": shzlib.utc_now(), "git": shzlib.git_state(), "qemu": qemu_tools.qemu_version(args.qemu),
               "ovmf_code_sha256": shzlib.sha256_file(args.ovmf_code), "hardware": {
                   "machine": "q35", "accel": "tcg", "cpu": "max", "smp": args.smp, "memory_mib": args.memory},
               "media": {k: {x: ctx[k][x] for x in ("path", "sha256", "bytes")} for k in ("iso", "disk")},
               "s3": "QEMU default (on) for OVMF", "cells": cells,
               "verdict": "PASS" if cells and all(c["status"] == "PASS" for c in cells) else "FAIL"}
    (out / "matrix.json").write_text(json.dumps(summary, indent=2) + "\n")
    columns = [e for e in ENTRIES if any(r["entry"] == e for r in runs)]
    lines = [f"# Shizuku SE boot matrix {summary['utc']}", "",
             f"ISO sha256 `{ctx['iso']['sha256']}`, disk sha256 `{ctx['disk']['sha256']}`; QEMU TCG q35, -cpu max, "
             f"{args.smp} vCPUs, {args.memory} MiB.", "",
             "| firmware | medium | " + " | ".join(columns) + " | cell |",
             "|---|---|" + "---|" * len(columns) + "---|"]
    for c in cells:
        row = [c["firmware"], MEDIUM_TEXT[c["medium"]]]
        for e in columns:
            info = c["entries"].get(e)
            row.append(f"{info['status']} ({info['seconds']} s)" if info else
                       ("n/a" if e in UEFI_ONLY and c["firmware"] != "ovmf" else "not run"))
        row.append(c["status"])
        lines.append("| " + " | ".join(row) + " |")
    (out / "matrix.md").write_text("\n".join(lines) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iso", type=Path, default=DEFAULT_ISO)
    ap.add_argument("--disk", type=Path, default=DEFAULT_DISK)
    ap.add_argument("--firmware", nargs="+", choices=FIRMWARES, default=list(FIRMWARES))
    ap.add_argument("--media", nargs="+", choices=MEDIA, default=list(MEDIA[:3]))
    ap.add_argument("--entries", nargs="+", choices=ENTRIES, default=list(ENTRIES),
                    help="menu entries to boot (k64direct only on OVMF; install only on --install-media)")
    ap.add_argument("--install-media", nargs="+", choices=MEDIA, default=["iso-cd"],
                    help="media whose Install entry the install row boots (each: install + host check + 2 boots)")
    ap.add_argument("--install-timeout", type=int, default=2400)
    ap.add_argument("--run-name", default=None, help="evidence directory under build/shizuku-se-matrix")
    ap.add_argument("--qemu", default=shutil.which("qemu-system-x86_64") or qemu_tools.DEFAULT_QEMU)
    ap.add_argument("--ovmf-code", default=qemu_tools.DEFAULT_OVMF_CODE)
    ap.add_argument("--ovmf-vars", default=qemu_tools.DEFAULT_OVMF_VARS)
    ap.add_argument("--smp", type=int, default=2)
    ap.add_argument("--memory", type=int, default=512)
    ap.add_argument("--menu-timeout", type=int, default=600)
    ap.add_argument("--timeout", type=int, default=1200, help="seconds per entry after it was selected")
    ap.add_argument("--keep-ramdisk", action="store_true")
    args = ap.parse_args(argv)
    ctx = media_context(args.iso.resolve(), args.disk.resolve())
    run_name = args.run_name or "run-" + time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    out = OUT / run_name
    out.mkdir(parents=True, exist_ok=True)
    images = {"iso-cd": args.iso.resolve(), "iso-hdd": args.iso.resolve(), "iso-usb": args.iso.resolve(),
              "disk": args.disk.resolve()}
    runs = []
    for firmware in args.firmware:
        for medium in args.media:
            for entry in args.entries:
                if entry in UEFI_ONLY and firmware != "ovmf":
                    continue
                if entry == "install" and (medium not in args.install_media or not ctx["setup_entry"][medium]):
                    continue
                name = f"{firmware}-{medium}-{entry}"
                print(f"[{time.strftime('%H:%M:%S')}] {name} (load {host_load()})", flush=True)
                if entry == "install":
                    record = run_install_row(args, firmware, medium, images[medium], out / name, ctx)
                else:
                    record = run_entry(args, firmware, medium, images[medium], entry, out / name, ctx)
                runs.append(record)
                bad = [c for c in record["checks"] if c["status"] != "PASS"]
                print(f"    {record['status']} in {record.get('seconds', '?')} s"
                      + "".join(f"\n      FAIL {c['check']}: {c['detail'][:160]}" for c in bad), flush=True)
    for key, path in (("iso", args.iso), ("disk", args.disk)):
        if shzlib.sha256_file(path.resolve()) != ctx[key]["sha256"]:
            raise SystemExit(f"{path} changed during the matrix run")
    summary = write_summary(out, runs, ctx, args)
    print((out / "matrix.md").read_text())
    print(f"verdict {summary['verdict']} -> {out / 'matrix.json'}")
    return 0 if summary["verdict"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
