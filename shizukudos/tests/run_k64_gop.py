#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""UEFI GOP display backend (kernel64/gfx_gop.c): Kernel64 started directly by the Shizuku boot manager on OVMF
(BOOT.INI mode=kernel64, the path of shizukudos/supervisor/test_bootmgr.py's kernel64 case, S3 off through
`-global ICH9-LPC.disable_s3=1`) draws the Win32 GUI on the framebuffer the firmware left on screen, in the firmware's mode.

Displays (one QEMU at a time, TCG):
  std    q35 -vga std: OVMF's QemuVideoDxe drives the Bochs VBE adapter in its own GOP mode. After a UEFI boot the kernel
         must not reprogram the adapter (the BGA backend declines) and draws through the GOP backend into BAR 0; the status
         screen lists PCI 1234:1111 as bound to "gfx_fb (UEFI GOP)".
  ramfb  q35 -vga none -device ramfb: no PCI display exists; OVMF's QemuRamfbDxe framebuffer lives in firmware-reserved RAM
         and the GOP backend is the only way anything reaches the screen; no display function is claimed.
Per display it checks, from what QEMU shows (QMP screendump) and what the guest printed:
  - the loader's GOP mode line, k64_boot_framebuffer()'s line and the kernel's "display backend UEFI GOP, WxHx32" agree;
  - T_GUI_FB: the kernel test pattern, computed HERE for the GOP mode, equals the screendump pixel for pixel;
  - T_GUI_STATUS: the screendump has the GOP mode's size, everything outside the status window is the desktop colour,
    its frame and caption are drawn; every DLL this build produced was loaded in the guest; the PCI binding as above;
  - T_GUI_INPUT: PS/2 keyboard, mouse and wheel input driven through QMP arrives as the expected messages (the same
    expectations as run_k64_gui.py);
  - every T_*.EXE in WIN64.IMG exits 0 without a fault, no FAIL line, Kernel64 exits 0.
Before booting anything, a host test compiles kernel64/gfx_pixfmt.h (the row conversion the GOP backend uses) with the
host C compiler and checks the byte order of both GOP layouts (BGRX copied, RGBX with red and blue swapped): QEMU's GOP
is always BGRX, so the RGBX path is only exercised there. This says nothing about real hardware beyond what OVMF does.

Inputs: BOOTX64.EFI from shizukudos/supervisor/build.py, KERNEL64S.BIN from shizukudos/kbuild.py, WIN64.IMG from
shizukudos/win64/build.py, OVMF (qemu.DEFAULT_OVMF_CODE/VARS). The boot disk is built here: MBR + one FAT16 partition
holding \\EFI\\BOOT\\BOOTX64.EFI, \\EFI\\SHIZUKU\\BOOT.INI (mode = kernel64), \\SHZDOS\\KERNEL64S.BIN and \\SHZDOS\\WIN64.IMG.
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
sys.path.insert(0, str(HERE))
import fatimg  # noqa: E402
import qemu  # noqa: E402
import run_k64_gui as gui  # noqa: E402  (image access, scene expectations and input driving are reused unchanged)
import run_k64_standalone  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, SHZ, sha256_file  # noqa: E402

OUT = BUILD / "kernel64s" / "gop-run"
LOADER = BUILD / "supervisor" / "BOOTX64.EFI"
K64S = BUILD / "kernel64s" / "KERNEL64S.BIN"
WIN64 = BUILD / "win64" / "WIN64.IMG"
WIN64_RECEIPT = BUILD / "win64" / "build-result.json"
BOOT_INI = b"; Shizuku boot manager: start the standalone Long Mode kernel directly\r\nmode = kernel64\r\n"
DISPLAYS = {"std": ["-vga", "std"], "ramfb": ["-vga", "none", "-device", "ramfb"]}
STATUS_RECT = (8, 8, 1016, 760)                                     # T_GUI_STATUS: CreateWindowExW(8, 8, 1008, 752)


# ---------------------------------------------------------------- host test of the pixel conversion
PIXFMT_DRIVER = r"""
#include <stdint.h>
#include <stdio.h>
#include "gfx_pixfmt.h"
int main(void)
{
    static const uint32_t src[5] = { 0x00112233u, 0x00ff0000u, 0x0000ff00u, 0x000000ffu, 0xff445566u };
    uint32_t dst[5];
    int rgbx, i;
    for (rgbx = 0; rgbx < 2; ++rgbx) {
        const unsigned char *b = (const unsigned char *)dst;
        gfx_row_convert(dst, src, 5, rgbx);
        printf("%s", rgbx ? "RGBX" : "BGRX");
        for (i = 0; i < 20; ++i) printf(" %02x", b[i]);
        printf("\n");
    }
    return 0;
}
"""


def pixfmt_host_test(work, rep):
    """compile gfx_pixfmt.h on the host and compare the bytes it writes with the two GOP layouts defined HERE"""
    src = work / "pixfmt_test.c"
    exe = work / "pixfmt_test"
    src.write_text(PIXFMT_DRIVER)
    cc = shutil.which("cc") or shutil.which("gcc")
    r = subprocess.run([cc, "-std=c99", "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(SHZ / "kernel64"), str(src), "-o", str(exe)],
                       capture_output=True, text=True)
    if not rep.check("host: kernel64/gfx_pixfmt.h compiles with the host C compiler", r.returncode == 0, r.stderr[-400:]):
        return
    out = subprocess.run([str(exe)], capture_output=True, text=True).stdout.split("\n")
    pixels = [(0x11, 0x22, 0x33), (0xff, 0, 0), (0, 0xff, 0), (0, 0, 0xff), (0x44, 0x55, 0x66)]      # (R, G, B) of src[]
    want = {"BGRX": " ".join(f"{b:02x} {g:02x} {r:02x} 00" for r, g, b in pixels),                  # GOP PixelBlueGreenRedReserved
            "RGBX": " ".join(f"{r:02x} {g:02x} {b:02x} 00" for r, g, b in pixels)}                  # GOP PixelRedGreenBlueReserved
    got = {ln.split(" ", 1)[0]: ln.split(" ", 1)[1] for ln in out if " " in ln}
    for fmt in ("BGRX", "RGBX"):
        rep.check(f"host: back-buffer rows converted to GOP {fmt} put the bytes {fmt[0]},{fmt[1]},{fmt[2]},X in memory "
                  "(reserved byte 0)", got.get(fmt) == want[fmt], f"got {got.get(fmt)} want {want[fmt]}")


# ---------------------------------------------------------------- boot disk
def build_disk(work):
    mbr = bytearray(512)
    mbr[510:512] = b"\x55\xaa"                                      # no boot code: OVMF reads the partition table only
    (work / "mbr.bin").write_bytes(bytes(mbr))
    disk = work / "gop-disk.img"
    size = max(64, -(-(LOADER.stat().st_size + K64S.stat().st_size + WIN64.stat().st_size) * 5 // 4 // (1 << 20)) + 16)
    spec = fatimg.make_hdd(disk, work / "mbr.bin", size_mib=size, label="SHZGOP", serial=0x53475031)
    (work / "BOOT.INI").write_bytes(BOOT_INI)
    fatimg.make_dirs(spec, ["EFI", "EFI/BOOT", "EFI/SHIZUKU", "SHZDOS"])
    shutil.copyfile(LOADER, work / "BOOTX64.EFI")
    shutil.copyfile(K64S, work / "KERNEL64S.BIN")
    shutil.copyfile(WIN64, work / "WIN64.IMG")
    fatimg.copy_in(spec, [(work / "BOOTX64.EFI", "EFI/BOOT/BOOTX64.EFI"), (work / "BOOT.INI", "EFI/SHIZUKU/BOOT.INI"),
                          (work / "KERNEL64S.BIN", "SHZDOS/KERNEL64S.BIN"), (work / "WIN64.IMG", "SHZDOS/WIN64.IMG")])
    return disk


# ---------------------------------------------------------------- one boot
def verify_status_gop(img, rep, w, h, tag):
    """the status window's frame and caption; a mode smaller than the 1008x752 window shows it clipped at the screen edge"""
    l, t, r, b = STATUS_RECT
    gui.W, gui.H = w, h                                             # the reused helpers read the screen size from here
    gui.check_outside_is_desktop(img, rep, f"{tag} status", [(l, t, min(r, w), min(b, h))])
    if r <= w and b <= h:
        gui.frame_checks(img, rep, f"{tag} status", l, t, r, b, True, "Shizuku Win64 runtime status")
        return
    ok = img.px(l, t) == (192, 192, 192) and img.px(l + 1, t + 1) == (255, 255, 255) and img.px(l + 2, t + 2) == gui.FACE
    rep.check(f"{tag} status: top-left corner of the bevelled frame (the window is larger than the {w}x{h} screen: clipped)", ok,
              f"{img.px(l, t)} {img.px(l + 1, t + 1)} {img.px(l + 2, t + 2)}")
    canvas, wrong = {}, None
    gui.paint_text(canvas, l + 8, t + 5, "Shizuku Win64 runtime status", (255, 255, 255))
    for y in range(t + 4, t + 22):
        for x in range(l + 4, min(r - 4, w)):
            want = canvas.get((x, y), gui.NAVY)
            if img.px(x, y) != want:
                wrong = f"({x},{y}) is {img.px(x, y)}, want {want}"
                break
        if wrong:
            break
    rep.check(f"{tag} status: active caption bar with the title, up to the right edge of the screen", wrong is None, wrong or "")


def run_display(name, args, disk, work, apps, built_dlls):
    rep = gui.Report()
    run_dir = work / name
    run_dir.mkdir()
    serial_path = run_dir / "serial.log"
    variables = run_dir / "OVMF_VARS.fd"
    shutil.copyfile(args.firmware_vars, variables)
    shutil.copyfile(disk, run_dir / "disk.img")
    sockdir = Path(tempfile.mkdtemp(prefix="shzgop"))
    sock = sockdir / "qmp.sock"
    cmd = [args.qemu, "-name", f"shz-gop-{name}", "-machine", "q35", "-accel", "tcg", "-cpu", "qemu64,vendor=GenuineIntel",
           "-smp", "2", "-m", "256", "-global", "ICH9-LPC.disable_s3=1", "-display", "none", *DISPLAYS[name],
           "-net", "none", "-no-reboot",
           "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={args.firmware_code}",
           "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
           "-drive", f"file={run_dir / 'disk.img'},format=raw,if=none,id=hd0,cache=writethrough",
           "-device", "ide-hd,drive=hd0,bus=ide.0,bootindex=1",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
           "-serial", f"file:{serial_path}", "-qmp", f"unix:{sock},server=on,wait=off"]
    started = time.time()
    proc = subprocess.Popen([str(c) for c in cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    seen, parked, driven, timed_out, mode = set(), None, [], False, None
    try:
        q = qemu.QMP(sock, timeout=30)
        consumed = 0
        while proc.poll() is None:
            if time.time() - started > args.timeout:
                timed_out = True
                break
            text = serial_path.read_text(errors="replace") if serial_path.exists() else ""
            if mode is None:
                m = re.search(r"K64 gfx: display backend (.+?), (\d+)x(\d+)x32", text)
                if m:
                    mode = (m.group(1), int(m.group(2)), int(m.group(3)))
            hit = None
            for m in re.finditer(r"(GUI-READY|INPUT-WAIT|INPUT-PARKED): (\S+)[^\n]*\n", text):
                if m.end() > consumed:
                    hit = m
                    break
            if not hit:
                time.sleep(0.05)
                continue
            consumed = hit.end()
            if hit.group(1) == "INPUT-WAIT":
                gui.drive_input(q, hit.group(2))
                driven.append(hit.group(2))
                continue
            if hit.group(1) == "INPUT-PARKED":
                parked = tuple(int(v) for v in re.findall(r"\d+", hit.group(0).split(":", 1)[1])[:2])
                continue
            scene = hit.group(2)
            if scene not in ("fb", "status"):
                continue                                          # the other scenes are laid out for 1024x768 (run_k64_gui.py)
            shot = run_dir / f"shot-{scene}.ppm"
            q.call("stop")
            try:
                q.call("screendump", {"filename": str(shot)})
            finally:
                q.call("cont")
            seen.add(scene)
            try:
                img = gui.Image(shot)
            except (ValueError, OSError) as e:
                rep.check(f"{name} {scene}: screendump readable", False, str(e))
                continue
            w, h = (mode[1], mode[2]) if mode else (0, 0)
            rep.check(f"{name} {scene}: the screen QEMU shows has the GOP mode's size {w}x{h}", (img.w, img.h) == (w, h),
                      f"screendump {img.w}x{img.h}")
            if (img.w, img.h) != (w, h):
                continue
            if parked and scene != "fb":
                px, py = parked
                rep.check(f"{name} {scene}: the parked pointer's hot-spot pixel ({px},{py}) is black", img.px(px, py) == (0, 0, 0),
                          f"{img.px(px, py)}")
                d = bytearray(img.data)
                o = (py * img.w + px) * 3
                d[o:o + 3] = bytes(gui.DESKTOP)
                img.data = bytes(d)
            if scene == "fb":
                gui.W, gui.H = w, h
                exp = gui.expected_pattern()
                bad = next((i // 3 for i in range(0, len(exp), 3) if img.data[i:i + 3] != exp[i:i + 3]), None) if img.data != exp else None
                rep.check(f"{name} fb: the kernel test pattern computed here for {w}x{h} equals the screendump pixel for pixel",
                          bad is None, "" if bad is None else f"first difference at ({bad % w},{bad // w}): "
                          f"{img.px(bad % w, bad // w)} want {tuple(exp[bad * 3:bad * 3 + 3])}")
            else:
                verify_status_gop(img, rep, w, h, name)
            if args.png:
                gui.save_png(shot)
            if not args.keep_shots:
                shot.unlink(missing_ok=True)
    except (RuntimeError, OSError, ValueError) as e:
        rep.check(f"{name}: QMP session", False, str(e))
    finally:
        try:
            proc.wait(timeout=30 if not timed_out else 1)
        except subprocess.TimeoutExpired:
            proc.kill()                                             # only the QEMU this runner started
            proc.wait()
        shutil.rmtree(sockdir, ignore_errors=True)
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    if timed_out:
        rep.check(f"{name}: run finished before the timeout", False, f"{args.timeout}s")
    ev, code = run_k64_standalone.parse(serial)
    rep.check(f"{name}: Kernel64 finished its self-tests and exited 0 (isa-debug-exit)", code == 0 and proc.returncode == 1,
              f"SHZ-EXIT={code} qemu rc={proc.returncode}")
    lg = re.search(r"GOP (\d+)x(\d+) (BGRX|RGBX) at 0x([0-9a-f]+)\.", serial)
    kg = re.search(r"K64 gfx: UEFI GOP framebuffer (\d+)x(\d+), pitch (\d+), (BGRX|RGBX), at ([0-9a-f]+)", serial)
    rep.check(f"{name}: the GOP backend took the mode the loader read from GOP (size, layout, address)",
              bool(lg and kg) and lg.group(1, 2, 3) == kg.group(1, 2, 4) and int(lg.group(4), 16) == int(kg.group(5), 16),
              (kg.group(0) if kg else "kernel line missing") + " / " + (lg.group(0) if lg else "loader line missing"))
    rep.check(f"{name}: display backend is UEFI GOP in the firmware's mode", bool(mode and kg) and mode[0] == "UEFI GOP" and
              (mode[1], mode[2]) == (int(kg.group(1)), int(kg.group(2))), f"{mode}")
    if name == "std":
        rep.check(f"{name}: the Bochs VBE backend declined (the firmware's display is left as it is)",
                  "Bochs VBE present, but the UEFI boot framebuffer is the active display" in serial and "K64 gfx: BGA " not in serial)
        pci = re.findall(r"STATUS-PCI: \S+ 1234:1111 class 03\S* irq \d+ driver=(.*)", serial)
        rep.check(f"{name}: status: PCI 1234:1111 (whose BAR 0 holds the framebuffer) is bound to gfx_fb (UEFI GOP)",
                  pci == ["gfx_fb (UEFI GOP)"], "; ".join(pci) or "not listed")
    else:
        pci = re.findall(r"STATUS-PCI: \S+ \S+ class 03\S* irq \d+ driver=(.*)", serial)
        rep.check(f"{name}: no PCI display function exists and none is claimed; the framebuffer is firmware RAM",
                  not pci and "lies in no PCI display BAR" in serial, "; ".join(pci))
    for scene in ("fb", "status"):
        rep.check(f"{name}: scene {scene} was shown and verified", scene in seen)
    loaded = {m.group(1).lower(): m.group(2) == "1" and m.group(3) == "1"
              for m in re.finditer(r"STATUS-DLL: (\S+) loaded=(\d) exports=\d+ resolved=(\d)", serial)}
    missing = [d for d in built_dlls if not loaded.get(d, False)]
    rep.check(f"{name}: status: every system DLL this build produced ({len(built_dlls)}) was loaded in the guest", not missing,
              ", ".join(missing[:8]))
    ran = re.findall(r"^K64 win64 app: (\S+) exit=(-?\d+) faulted=(\d+)", serial, re.M)
    bad = [f"{n} exit={e} faulted={f}" for n, e, f in ran if e != "0" or f != "0"]
    expected = [a for a in apps if a != "T_HELLO.EXE"]
    rep.check(f"{name}: every T_*.EXE in WIN64.IMG ran and exited 0 without a fault",
              sorted(n for n, _, _ in ran) == expected and not bad, f"{len(ran)}/{len(expected)} ran; {bad[:3]}")
    fails = re.findall(r"\] (FAIL: .*)", serial)
    rep.check(f"{name}: no program printed FAIL:", not fails, "; ".join(fails[:5]))
    skips = re.findall(r"\[win64 (T_GUI_\S+) pid \d+\] (SKIP: .*)", serial)
    rep.check(f"{name}: no GUI program skipped (the display is present)", not skips, "; ".join(f"{a}: {b}" for a, b in skips[:5]))
    rep.check(f"{name}: the input program asked for keyboard, mouse and wheel input and got it", driven == ["keys", "mouse", "wheel"],
              f"{driven}")
    before = len(rep.items)
    gui.verify_input_echo(serial, rep)
    for item in rep.items[before:]:
        item["check"] = f"{name}: {item['check']}"
    return rep.items, {"display": name, "command": [str(c) for c in cmd], "seconds": round(time.time() - started, 1),
                       "mode": mode, "serial_tail": serial[-3000:], "gfx_lines": re.findall(r"^K64 gfx: .*$", serial, re.M)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qemu", default=shutil.which("qemu-system-x86_64") or qemu.DEFAULT_QEMU)
    ap.add_argument("--firmware-code", default=qemu.DEFAULT_OVMF_CODE)
    ap.add_argument("--firmware-vars", default=qemu.DEFAULT_OVMF_VARS)
    ap.add_argument("--display", action="append", choices=tuple(DISPLAYS), help="run only these displays (repeatable)")
    ap.add_argument("--timeout", type=int, default=900, help="per-boot limit in seconds (TCG)")
    ap.add_argument("--keep-shots", action="store_true")
    ap.add_argument("--png", action="store_true")
    args = ap.parse_args()
    for path, hint in ((LOADER, "shizukudos/supervisor/build.py"), (K64S, "shizukudos/kbuild.py"), (WIN64, "shizukudos/win64/build.py"),
                       (Path(args.firmware_code), "OVMF"), (Path(args.firmware_vars), "OVMF")):
        if not path.exists():
            raise SystemExit(f"missing {path}: {hint}")
    receipt = json.loads(WIN64_RECEIPT.read_text())
    if receipt["archive"]["sha256"] != sha256_file(WIN64):
        raise SystemExit("WIN64.IMG does not match shizukudos/win64 build-result.json")
    files = receipt["archive"]["files"]
    apps = sorted(f.rsplit("\\", 1)[1] for f in files if re.fullmatch(r"\\SHZ\\TESTS\\T_[A-Z0-9_]+\.EXE", f))
    built_dlls = sorted(f.rsplit("\\", 1)[-1].lower() for f in files
                        if f.upper().startswith("\\SHZ\\SYS64\\") and f.upper().endswith(".DLL"))   # SYS64 also holds programs
    OUT.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%S-"), dir=OUT))
    host = gui.Report()
    pixfmt_host_test(work, host)
    checks = list(host.items)
    runs = []
    disk = build_disk(work)
    for name in args.display or list(DISPLAYS):
        c, rec = run_display(name, args, disk, work, apps, built_dlls)
        rec["status"] = "PASS" if all(x["status"] == "PASS" for x in c) else "FAIL"
        runs.append(rec)
        checks += c
        print(f"[{rec['status']}] display {name}: {rec['mode']} in {rec['seconds']} s")
    status = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    record = {"test": "shizukudos/tests/run_k64_gop.py", "status": status, "checks": checks, "runs": runs,
              "inputs": {"BOOTX64.EFI": sha256_file(LOADER), "KERNEL64S.BIN": sha256_file(K64S), "WIN64.IMG": sha256_file(WIN64),
                         "OVMF_CODE": str(args.firmware_code)},
              "qemu": qemu.qemu_version(args.qemu), "utc": shzlib.utc_now(), "git": shzlib.git_state(), "work": str(work)}
    shzlib.write_json(OUT / "result.json", record)
    for x in checks:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    print(status)
    (work / "gop-disk.img").unlink(missing_ok=True)
    for r in runs:
        (work / r["display"] / "disk.img").unlink(missing_ok=True)
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
