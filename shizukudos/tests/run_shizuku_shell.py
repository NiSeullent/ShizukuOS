#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Bounded actual UEFI/GOP acceptance of the native Korean ShizukuOS shell.

Reuses the existing private disk/firmware helpers. This is a development VM,
not ISO installation, hardware acceleration or modern-application acceptance.
All interactions go through QEMU's PS/2 keyboard/mouse; screenshots are raw
guest captures. The guest AA fixture checks real Win32 DIB pixels separately.
"""
import argparse
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

import run_k64_desktop as base

READY = re.compile(r"SHZ-SHELL READY hwnd=([0-9a-f]+) width=(\d+) height=(\d+) scale=(\d+) lang=(\w+) cfg=(-?\d+)")
FAILURES = re.compile(r"SHZ-SHELL (?:ERROR|FAIL)\b|SHZ-AA FAIL\b|K64 desktop: result (?:start|wait|network-init)-failed|"
                      r"K64(?: EXCEPTION|: process .* killed)|(?:^|\n).*PANIC\b")


class ShellGuest(base.Guest):
    def __init__(self, *args):
        super().__init__(*args)
        self.scale = 100
        self.w = self.h = 0
        self.pointer = [0, 0]

    def healthy(self, allow_exit=False):
        text = self.serial()
        hit = FAILURES.search(text)
        if hit:
            raise base.EvidenceError(f"guest failure: {hit.group(0)}; {text[-1800:]}")
        if not allow_exit and self.proc.poll() is not None:
            raise base.EvidenceError("guest exited before requested shutdown")
        if time.monotonic() >= self.deadline:
            raise base.EvidenceError("guest reached original total deadline")
        return text

    def move(self, x, y, reset=False):
        self.healthy()
        if reset:
            # No assumed initial cursor position. Repeated bounded real PS/2
            # packets clamp at the guest's top-left display edge.
            for _ in range((max(self.w, self.h) + 99) // 100 + 4):
                self.qmp.call("input-send-event", {"events": [
                    {"type": "rel", "data": {"axis": "x", "value": -100}},
                    {"type": "rel", "data": {"axis": "y", "value": -100}}]})
                time.sleep(0.055)
            self.pointer = [0, 0]
        dx, dy = x - self.pointer[0], y - self.pointer[1]
        while dx or dy:
            sx, sy = max(-80, min(80, dx)), max(-80, min(80, dy))
            self.qmp.call("input-send-event", {"events": [
                {"type": "rel", "data": {"axis": "x", "value": sx}},
                {"type": "rel", "data": {"axis": "y", "value": sy}}]})
            dx -= sx
            dy -= sy
            time.sleep(0.055)
        self.pointer = [x, y]
        time.sleep(0.15)

    def click(self, x, y, double=False, reset=True):
        self.move(x, y, reset)
        for i in range(2 if double else 1):
            self.qmp.call("input-send-event", {"events": [{"type": "btn", "data": {"down": True, "button": "left"}}]})
            time.sleep(0.06)
            self.qmp.call("input-send-event", {"events": [{"type": "btn", "data": {"down": False, "button": "left"}}]})
            time.sleep(0.08 if double and i == 0 else 0.25)

    def screenshot(self, label, diagnostic=False):
        if not diagnostic:
            self.healthy()
        time.sleep(0.3)
        ppm = self.run_dir / f"{label}.ppm"
        self.qmp.call("stop")
        try:
            self.qmp.call("screendump", {"filename": str(ppm)})
        finally:
            self.qmp.call("cont")
        img = base.gui.Image(ppm)
        base.check(self.checks, f"{label}: actual screen dimensions", (img.w, img.h) == (self.w, self.h))
        # Shape and text evidence is inspected from raw captures. Dimensions
        # alone do not establish Korean glyphs or AA.
        base.gui.save_png(ppm)
        png = ppm.with_suffix(".png")
        self.shots.append({"label": label, "path": str(png), "sha256": base.sha(png)})

    def type_command(self, command):
        qcodes = {" ": "spc", "\\": "backslash", "/": "slash", ".": "dot", "_": "minus", ":": "semicolon"}
        for c in command:
            if c in (":", "_"):
                self.keys("shift", qcodes[c])
            else:
                self.keys(qcodes.get(c, c.lower()))

    def run(self, command):
        self.click(45 * self.scale // 100, 145 * self.scale // 100, double=True)
        time.sleep(0.3)
        # Opening the real Run window starts a fresh command entry.
        self.type_command(command)
        start = len(self.serial())
        self.keys("ret")
        hit = self.wait(re.compile(r"SHZ-SHELL LAUNCH pid=(\d+)"), start)
        return int(hit.group(1)), start


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=base.qemu.DEFAULT_QEMU)
    ap.add_argument("--firmware-code", default=base.qemu.DEFAULT_OVMF_CODE)
    ap.add_argument("--firmware-vars", default=base.qemu.DEFAULT_OVMF_VARS)
    ap.add_argument("--accel", choices=("tcg", "kvm"), default="kvm")
    ap.add_argument("--memory", type=int, default=768)
    ap.add_argument("--timeout", type=int, default=360)
    ap.add_argument("--step-timeout", type=int, default=45)
    ap.add_argument("--observe-seconds", type=int, default=3)
    ap.add_argument("--out", type=Path, default=base.REPO / "build/shizuku-shell-vm")
    args = ap.parse_args(argv)
    if min(args.timeout, args.step_timeout, args.observe_seconds) < 1 or args.memory < 256:
        ap.error("positive deadlines and at least 256 MiB required")
    args.boot_iso = None
    args.iso_receipt = None
    missing = base.prerequisites(args)
    args.out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%S-"), dir=args.out))
    record = {"status": "FAIL", "scope": "native Korean shell UEFI/GOP, actual Win64 GDI AA and process lifecycle",
              "utc": base.shzlib.utc_now(), "work": str(work), "checks": [], "screenshots": [],
              "ISO_install_verified": False, "modern_apps_verified": False, "hardware_acceleration_verified": False}
    if missing:
        record.update(status="BLOCKED", missing=missing)
        base.shzlib.write_json(work / "result.json", record)
        print(json.dumps(record))
        return 2
    checks = record["checks"]
    proc = q = guest = None
    try:
        record["inputs"] = base.verify_inputs(checks)
        files = {f.upper() for f in record["inputs"]["runtime_archive_files"]}
        base.check(checks, "current archive contains new shell and AA fixture",
                   {r"\SHZ\SYS64\SHIZUKU_SHELL.EXE", r"\SHZ\TESTS\T_GUI_ANTIALIAS.EXE"} <= files)
        boot, data = base.build_disks(work)
        variables = work / "OVMF_VARS.fd"
        shutil.copyfile(args.firmware_vars, variables)
        with tempfile.TemporaryDirectory(prefix="shzshell-") as sockets:
            command = base.command_for(args, work, Path(sockets) / "qmp.sock", boot, data, variables)
            record["command"] = command
            with (work / "qemu.log").open("wb") as log:
                proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
                q = base.qemu.QMP(Path(sockets) / "qmp.sock", timeout=min(30, args.step_timeout))
                guest = ShellGuest(proc, q, work, args, checks)
                ready = guest.wait(READY)
                guest.w, guest.h, guest.scale = map(int, ready.group(2, 3, 4))
                text = guest.serial()
                base.check(checks, "current default native shell actually started", r"K64 desktop: starting C:\SHZ\SYS64\SHIZUKU_SHELL.EXE" in text)
                base.check(checks, "actual Korean default language", ready.group(5) == "ko", ready.group(0))
                base.check(checks, "actual UEFI GOP path", "ExitBootServices" in text and "K64 gfx: display backend UEFI GOP" in text)
                guest.observe(args.observe_seconds, "native shell remains running")
                guest.screenshot("korean-desktop")
                guest.click(40 * guest.scale // 100, guest.h - 18 * guest.scale // 100)
                time.sleep(0.5)
                guest.screenshot("start-menu")
                guest.click(guest.w - 24, 24)
                pid, offset = guest.run(r"c:\shz\tests\t_gui_antialias.exe")
                guest.wait("SHZ-AA SCENE READY", offset)
                base.check(checks, "guest GDI coverage/composition/clipping checks pass", "SHZ-AA RESULT failures=0" in guest.serial()[offset:])
                base.check(checks, "AA scene actually completed EndPaint", "SHZ-AA PAINT count=" in guest.serial()[offset:])
                guest.screenshot("aa-actual-app")
                guest.wait(re.compile(r"SHZ-SHELL EXIT pid=" + str(pid) + r" code=0\b"), offset)
                base.check(checks, "AA fixture exited and shell reaped real process", True, f"pid={pid}")
                pid, offset = guest.run(r"c:\shz\tests\t_hello.exe")
                guest.wait(re.compile(r"SHZ-SHELL EXIT pid=" + str(pid) + r" code=7\b"), offset)
                base.check(checks, "real PE64 child documented exit code", "hello from Win64 PE32+" in guest.serial()[offset:], f"pid={pid}, exit=7")
                guest.observe(args.observe_seconds, "shell survives two actual child lifecycles")
                guest.screenshot("desktop-after-apps")
                record["status"] = "PASS"
    except (base.EvidenceError, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        record["error"] = str(exc)
        if guest and proc and proc.poll() is None:
            try:
                guest.screenshot("failure", diagnostic=True)
            except Exception as shot_error:
                record["screenshot_error"] = str(shot_error)
    finally:
        if q:
            try:
                q.call("quit")
            except (RuntimeError, OSError):
                pass
            q.close()
        if proc:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        record["owned_VM_reaped"] = bool(proc and proc.poll() is not None)
        if guest:
            record["screenshots"] = guest.shots
            record["serial_tail"] = guest.serial()[-12000:]
        base.shzlib.write_json(work / "result.json", record)
    print(json.dumps({"status": record["status"], "result": str(work / "result.json"), "error": record.get("error")}))
    return 0 if record["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
