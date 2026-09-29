#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot Kernel64 WITHOUT the Supervisor under QEMU with a Bochs VBE display (`-vga std`) and verify the Win32 GUI stack
by looking at the pixels QEMU actually shows.

Profile: same standalone image as run_k64_standalone.py (QEMU -kernel stub -> Kernel64 -> WIN64.IMG apps), plus a display
device and a QMP socket. The GUI test programs (win64/tests/t_gui_*.c) draw a known scene, print
`GUI-READY: <scene>` on the serial console and keep the scene on screen for a couple of seconds. On each marker this
runner pauses the VM (QMP `stop`, so the scene cannot change under us), takes a QMP `screendump` (PPM) and compares it with
what the HOST computes for that scene from the test's documented drawing: expected colours and positions are written down
in this file, never read back from the guest or from the implementation under test. Then it resumes the VM.

It also requires every T_GUI_* program to exit 0 without a fault and to print no FAIL: line. It does not test the
Supervisor path (there is no display there) and says nothing about real hardware.
"""
import argparse
import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
W, H = 1024, 768
DESKTOP = (0x00, 0x80, 0x80)


# ---------------------------------------------------------------- PPM access
class Image:
    def __init__(self, path):
        raw = Path(path).read_bytes()
        m = re.match(rb"P6\s+(\d+)\s+(\d+)\s+(\d+)\s", raw)
        if not m:
            raise ValueError("not a P6 PPM")
        self.w, self.h = int(m.group(1)), int(m.group(2))
        self.data = raw[m.end():]
        if len(self.data) != self.w * self.h * 3:
            raise ValueError(f"PPM payload {len(self.data)} != {self.w}x{self.h}x3")

    def px(self, x, y):
        o = (y * self.w + x) * 3
        return tuple(self.data[o:o + 3])

    def row(self, y, x0, x1):
        return self.data[(y * self.w + x0) * 3:(y * self.w + x1) * 3]

    def rect_is(self, x0, y0, x1, y1, rgb):
        """Every pixel of [x0,x1)x[y0,y1) has colour rgb. Returns None or a description of the first mismatch."""
        want = bytes(rgb) * (x1 - x0)
        for y in range(y0, y1):
            got = self.row(y, x0, x1)
            if got != want:
                for x in range(x0, x1):
                    if self.px(x, y) != tuple(rgb):
                        return f"({x},{y}) is {self.px(x, y)}, expected {tuple(rgb)}"
        return None


class Report:
    def __init__(self):
        self.items = []

    def check(self, name, ok, detail=""):
        self.items.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})
        return ok

    def rect(self, img, name, x0, y0, x1, y1, rgb):
        bad = img.rect_is(x0, y0, x1, y1, rgb)
        return self.check(name, bad is None, bad or f"[{x0},{x1})x[{y0},{y1}) all {tuple(rgb)}")


# ---------------------------------------------------------------- scene: kernel test pattern (T_GUI_FB)
def expected_pattern():
    """Bars/ramp/markers as documented in kernel64/gfx_fb.c gfx_fb_test_pattern, computed here independently."""
    bars = [(255, 255, 255), (255, 255, 0), (0, 255, 255), (0, 255, 0), (255, 0, 255), (255, 0, 0), (0, 0, 255),
            (128, 128, 128)]
    top = b"".join(bytes(bars[x * 8 // W]) for x in range(W))
    bottom = b"".join(bytes([x * 255 // (W - 1)] * 3) for x in range(W))
    rows = [bytearray(top) for _ in range(H // 2)] + [bytearray(bottom) for _ in range(H - H // 2)]
    for y in range(4):
        for k in range(4):
            rows[y][k * 3:k * 3 + 3] = bytes((255, 0, 0))
            rows[y][(W - 4 + k) * 3:(W - 3 + k) * 3] = bytes((0, 255, 0))
            rows[H - 4 + y][k * 3:k * 3 + 3] = bytes((0, 0, 255))
            rows[H - 4 + y][(W - 4 + k) * 3:(W - 3 + k) * 3] = bytes((255, 255, 0))
    return b"".join(bytes(r) for r in rows)


def verify_fb(img, rep):
    rep.check("fb: screendump is 1024x768", (img.w, img.h) == (W, H), f"{img.w}x{img.h}")
    if (img.w, img.h) != (W, H):
        return
    exp = expected_pattern()
    ok = img.data == exp
    detail = "all 786432 pixels identical to the host-computed pattern"
    if not ok:
        for i in range(0, len(exp), 3):
            if img.data[i:i + 3] != exp[i:i + 3]:
                p = i // 3
                detail = f"first mismatch at ({p % W},{p // W}): got {tuple(img.data[i:i + 3])} want {tuple(exp[i:i + 3])}"
                break
    rep.check("fb: kernel test pattern (8 bars, grey ramp, 4 corner markers) is pixel-exact on screen", ok, detail)
    rep.check("fb: corner colours (orientation and R/G/B byte order)",
              img.px(0, 0) == (255, 0, 0) and img.px(W - 1, 0) == (0, 255, 0) and img.px(0, H - 1) == (0, 0, 255) and
              img.px(W - 1, H - 1) == (255, 255, 0),
              f"{img.px(0, 0)} {img.px(W - 1, 0)} {img.px(0, H - 1)} {img.px(W - 1, H - 1)}")


SCENES = {"fb": verify_fb}


# ---------------------------------------------------------------- harness
def parse_serial(serial):
    exit_code = None
    m = re.search(r"^SHZ-EXIT:([0-9a-f]+)$", serial, re.M)
    if m:
        exit_code = int(m.group(1), 16)
    return exit_code


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=240)
    ap.add_argument("--memory", default="256")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "gui-run"))
    ap.add_argument("--keep-shots", action="store_true", help="keep the screendump of every scene (PPM)")
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
    sockdir = Path(tempfile.mkdtemp(prefix="shzgui"))     # AF_UNIX paths are limited to ~100 bytes: keep the socket somewhere short
    sock = sockdir / "qmp.sock"
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-vga", "std",
           "-display", "none", "-kernel", str(stub), "-initrd", f"{kernel},{initrd}", "-serial", f"file:{serial_path}",
           "-qmp", f"unix:{sock},server=on,wait=off", "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot"]
    rep = Report()
    started = time.time()
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    seen, timed_out = set(), False
    try:
        q = qemu.QMP(sock, timeout=15)
        consumed = 0
        while True:
            if proc.poll() is not None:
                break
            if time.time() - started > args.timeout:
                timed_out = True
                break
            text = serial_path.read_text(errors="replace") if serial_path.exists() else ""
            hit = None
            for m in re.finditer(r"GUI-READY: (\S+)", text):
                if m.end() > consumed:
                    hit = m
                    break
            if not hit:
                time.sleep(0.02)
                continue
            consumed = hit.end()
            scene = hit.group(1)
            shot = out / f"shot-{scene}.ppm"
            shot.unlink(missing_ok=True)
            q.call("stop")                              # freeze the guest: the scene cannot change while we look
            try:
                q.call("screendump", {"filename": str(shot)})
            finally:
                q.call("cont")
            seen.add(scene)
            try:
                img = Image(shot)
            except (ValueError, OSError) as e:
                rep.check(f"{scene}: screendump readable", False, str(e))
                continue
            fn = SCENES.get(scene)
            if fn is None:
                rep.check(f"{scene}: known scene", False, "no host-side expectation for this scene")
            else:
                fn(img, rep)
            if not args.keep_shots:
                shot.unlink(missing_ok=True)
    except (RuntimeError, OSError, ValueError) as e:
        rep.check("QMP session", False, str(e))
    finally:
        try:
            proc.wait(timeout=30 if not timed_out else 1)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
    shutil.rmtree(sockdir, ignore_errors=True)
    qemu_out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    exit_code = parse_serial(serial)
    if timed_out:
        rep.check("run finished before the timeout", False, f"{args.timeout}s, accel={accel}")
    rep.check("Kernel64 finished all self-tests and exited 0", exit_code == 0 and "K64 test FAIL" not in serial,
              f"exit={exit_code}")
    apps = re.findall(r"K64 win64 app: (T_GUI_\S+\.EXE) exit=(-?\d+) faulted=(\d)", serial)
    for name, code, faulted in apps:
        rep.check(f"{name} exits 0 without a fault", code == "0" and faulted == "0", f"exit={code} faulted={faulted}")
    rep.check("at least one GUI test program ran", len(apps) > 0, f"{len(apps)} program(s)")
    fails = re.findall(r"\] (FAIL: .*)", serial)
    rep.check("no GUI program printed FAIL:", not fails, "; ".join(fails[:5]))
    skips = re.findall(r"\] (SKIP: .*)", serial)
    rep.check("no GUI program skipped (the display is present)", not skips, "; ".join(skips[:5]))
    for scene in sorted(SCENES):
        rep.check(f"scene {scene} was shown and verified", scene in seen)
    status = "PASS" if all(x["status"] == "PASS" for x in rep.items) else "FAIL"
    record = {"profile": "kernel64-standalone + bochs vga (no Supervisor, no VMX)", "accel": accel, "status": status,
              "checks": rep.items, "seconds": round(time.time() - started, 1), "command": cmd, "qemu_output": qemu_out[-1500:],
              "serial_tail": serial[-4000:], "utc": shzlib.utc_now(), "git": shzlib.git_state()}
    shzlib.write_json(out / "result.json", record)
    for x in rep.items:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    print(status)
    if status != "PASS":
        print("---- serial tail ----\n" + serial[-3000:])
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
