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

Each run also checks the boot path from the COM1 log: legacy BIOS runs show the
isolinux/syslinux banner with no UEFI firmware in the command line; OVMF runs
show, in order, BDS starting the medium, the Shizuku loader, CSMWrap's boot
device and the isolinux/syslinux banner. While the loader has no boot manager
(C2's work not merged), OVMF runs go loader (refuses: no VMX under TCG) ->
UEFI Shell -> \\STARTUP.NSH -> CSMWrap, and those cells are marked INTERIM.

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
ENTRIES = ("kernel64", "dos16", "shzdos01", "setup")  # setup: only on media built with SHZSETUP
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
    holes = re.search(r"K64: (\d+) firmware memory hole\(s\), (\d+) page\(s\)", text)
    stub_holes = len(re.findall(r"SHZ-STUB: firmware hole", text))
    checks.append(check("memory map: holes reported by the stub == holes applied by Kernel64",
                        (int(holes.group(1)) if holes else 0) == stub_holes,
                        f"stub {stub_holes}, kernel {holes.group(0) if holes else 'none'}"))
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


def boot_path_checks(firmware: str, medium: str, text: str, command: list[str], loader_interim: bool) -> list[dict]:
    banner = "SYSLINUX 6.04" if medium == "disk" else "ISOLINUX 6.04"
    if firmware == "seabios":
        return [check("legacy BIOS: QEMU's SeaBIOS (no UEFI flash in the command line)",
                      not any("pflash" in c for c in command)),
                check(f"legacy BIOS: {banner} started from the medium", banner in text)]
    steps = [("OVMF BDS starts the medium's UEFI boot option",
              r"BdsDxe: starting Boot\w+ \"UEFI (QEMU (DVD-ROM|HARDDISK)|QEMU QEMU USB HARDDRIVE)"),
             ("\\EFI\\BOOT\\BOOTX64.EFI = the Shizuku loader started", r"Supervisor loader \(UEFI x64\)")]
    if loader_interim:
        steps += [("Shizuku loader ran and refused (no VMX under TCG; interim loader without boot manager)",
                   r"REFUSED: "),
                  ("UEFI Shell ran \\STARTUP.NSH, which started CSMWRAP.EFI", r"SHZ-SE: starting fs\d+:\\EFI\\SHIZUKU")]
    else:
        steps += [("Shizuku loader boot manager chose CSMWrap", r"Boot manager: .*mode=")]
    steps += [("CSMWrap BIOS proxy on a reserved AP", stutter("BIOS proxy ready (AP ") + r"\d+\)+"),
              ("CSMWrap boot device = the controller of the medium",
               stutter("bootdev: Boot device: PCI ") + (r"[0-9a-f]{2}:[0-9a-f]{2}\.\d" if medium == "iso-usb"
                                                        else stutter("00:1f.2"))),
              (f"SeaBIOS CSM legacy-booted the medium: {banner}", stutter(banner))]
    out, pos = [check("UEFI: OVMF in pflash", any("pflash" in c for c in command))], 0
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
    key = ctx["keys"][entry]
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
                if entry in ("kernel64", "setup"):
                    if entry == "setup":
                        record["note"] = ("Install entry: Kernel64 with shz.setup=auto on the Multiboot command line; "
                                          "what SHZSETUP itself must show is defined by its own work (agent I1)")
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
    checks = boot_path_checks(firmware, medium, text, record["command"], ctx["loader_interim"]) + checks
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
    loader = next(i for i in ctx["iso"]["receipt"]["inputs"] if "BOOTX64" in i["name"])
    ctx["loader_interim"] = loader["interim"]
    ctx["keys"] = ctx["iso"]["receipt"]["menu"]["keys"]
    ctx["loads"] = {}
    for medium, key in (("iso-cd", "iso"), ("iso-hdd", "iso"), ("iso-usb", "iso"), ("disk", "disk")):
        menu = ctx[key]["receipt"]["menu"]
        k64 = [f"{menu['k64_dir']}/KERNEL64S.BIN", f"{menu['k64_dir']}/WIN64.IMG"]
        ctx["loads"][medium] = {"kernel64": k64, "setup": k64, "dos16": [menu["dos16"]], "shzdos01": [menu["shzdos01"]]}
        ctx.setdefault("setup_entry", {})[medium] = menu.get("setup_entry", False)
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
                          "interim": firmware == "ovmf" and ctx["loader_interim"],
                          "entries": {r["entry"]: {"status": r["status"], "seconds": r.get("seconds"),
                                                   "failed": [c["check"] for c in r["checks"] if c["status"] != "PASS"]}
                                      for r in mine}})
    summary = {"utc": shzlib.utc_now(), "git": shzlib.git_state(), "qemu": qemu_tools.qemu_version(args.qemu),
               "ovmf_code_sha256": shzlib.sha256_file(args.ovmf_code), "hardware": {
                   "machine": "q35", "accel": "tcg", "cpu": "max", "smp": args.smp, "memory_mib": args.memory},
               "media": {k: {x: ctx[k][x] for x in ("path", "sha256", "bytes")} for k in ("iso", "disk")},
               "loader_interim": ctx["loader_interim"], "cells": cells,
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
            row.append(f"{info['status']} ({info['seconds']} s)" if info else "not run")
        row.append(c["status"] + (" (interim: shell startup.nsh -> CSMWrap)" if c["interim"] else ""))
        lines.append("| " + " | ".join(row) + " |")
    (out / "matrix.md").write_text("\n".join(lines) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iso", type=Path, default=DEFAULT_ISO)
    ap.add_argument("--disk", type=Path, default=DEFAULT_DISK)
    ap.add_argument("--firmware", nargs="+", choices=FIRMWARES, default=list(FIRMWARES))
    ap.add_argument("--media", nargs="+", choices=MEDIA, default=list(MEDIA[:3]))
    ap.add_argument("--entries", nargs="+", choices=ENTRIES, default=list(ENTRIES[:3]),
                    help="menu entries to boot; 'setup' is added automatically when the medium has it")
    ap.add_argument("--no-setup", action="store_true", help="do not add the Install entry automatically")
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
            for entry in args.entries + (["setup"] if ctx["setup_entry"][medium] and "setup" not in args.entries
                                         and not args.no_setup else []):
                if entry == "setup" and not ctx["setup_entry"][medium]:
                    print(f"    {firmware}-{medium}-setup: this medium has no Install entry (no SHZSETUP); not run")
                    continue
                name = f"{firmware}-{medium}-{entry}"
                print(f"[{time.strftime('%H:%M:%S')}] {name} (load {host_load()})", flush=True)
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
