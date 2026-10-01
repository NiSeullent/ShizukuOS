#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Milestone R1 of the ShizukuDOS "Shizuku" WebKit port: render a local HTML+CSS page to a bitmap in the guest and
compare it with a host-rendered reference.

Guest: T_WK_RENDER.EXE (port/programs/TWkRender.cpp, built by port/build_port.py --target T_WK_RENDER) with
libc++.dll/libunwind.dll and the page (port/tests/data/r1.html) on D:\\WK; WKRUN.EXE runs
`T_WK_RENDER.EXE r1.html r1.bmp 800 600` under standalone Kernel64 (QEMU; TCG here) and the BMP is copied back out of the
disk image. Host reference: the same file rendered by headless Chromium (Playwright's, pre-installed) at 800x600 with a
private fontconfig that holds only the pinned Noto Sans the guest's \\SHZ\\FONTS has.

Comparison (both RGB): the fraction of pixels whose largest channel difference exceeds 48 (anti-aliasing and glyph
positioning differ between the engines; layout, colours and box geometry must not), the mean absolute difference, and
per-region checks of solid colours the page defines. PASS needs: the guest program exited 0, printed its timing line and
the title the page's script sets ("R1 5050": JavaScriptCore ran), the BMP decodes, differing pixels <= 5 %, and every
solid-colour probe within 24 of the expected colour. Outputs in build/shizukudos/win64/webkit/run_r1/: guest.png,
reference.png, diff.png, result.json; with --screenshot also docs/shizukudos10/screenshots/webkit-r1.png.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
PORT = HERE.parent
sys.path.insert(0, str(PORT.parent / "deps"))
sys.path.insert(0, str(HERE))
import build_deps as deps  # noqa: E402
import wkguest  # noqa: E402
import shzlib  # noqa: E402
from shzlib import REPO, run  # noqa: E402

OUT = deps.w1.OUT / "run_r1"
EXE = deps.w1.OUT / "shizuku" / "bin" / "T_WK_RENDER.exe"
PAGE = HERE / "data" / "r1.html"
CHROMIUM = Path("/opt/pw-browsers/chromium_headless_shell-1194/chrome-linux/headless_shell")
NOTO = REPO / "build" / "upstream" / "noto-fonts" / "ofl" / "notosans" / "NotoSans[wdth,wght].ttf"
W, H = 800, 600
# (name, x, y, expected RGB): solid areas of r1.html (box interiors, the float, the table header)
PROBES = [("red box", 76, 100, (211, 47, 47)), ("green box", 208, 100, (56, 142, 60)),
          ("blue box", 340, 100, (25, 118, 210)), ("page background", 700, 560, (255, 255, 255))]


def host_reference(dest):
    fonts = OUT / "host-fonts"
    fonts.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(NOTO, fonts / "NotoSans.ttf")
    conf = OUT / "fonts.conf"
    conf.write_text(f"""<?xml version="1.0"?>
<!DOCTYPE fontconfig SYSTEM "fonts.dtd">
<fontconfig><dir>{fonts}</dir><cachedir>{OUT / 'fc-cache'}</cachedir></fontconfig>
""")
    env = dict(os.environ, FONTCONFIG_FILE=str(conf))
    run([CHROMIUM, "--no-sandbox", f"--screenshot={dest}", f"--window-size={W},{H}", "--hide-scrollbars",
         "--force-device-scale-factor=1", "--disable-lcd-text", "--font-render-hinting=none", PAGE.as_uri()],
        env=env, timeout=300, capture=True)
    return dest


def compare(guest_png, ref_png, diff_png):
    from PIL import Image, ImageChops
    g = Image.open(guest_png).convert("RGB")
    r = Image.open(ref_png).convert("RGB")
    if g.size != r.size:
        return {"size_mismatch": [g.size, r.size]}
    diff = ImageChops.difference(g, r)
    px = diff.getdata()
    big = sum(1 for p in px if max(p) > 48)
    mean = sum(sum(p) for p in px) / (3 * g.size[0] * g.size[1])
    diff.point(lambda v: min(255, v * 4)).save(diff_png)
    probes = []
    for name, x, y, want in PROBES:
        got = g.getpixel((x, y))
        probes.append({"name": name, "xy": [x, y], "want": want, "guest": got, "reference": r.getpixel((x, y)),
                       "ok": max(abs(a - b) for a, b in zip(got, want)) <= 24})
    return {"differing_fraction": big / (g.size[0] * g.size[1]), "mean_abs_diff": round(mean, 3), "probes": probes}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--memory", default="1024")
    ap.add_argument("--timeout", type=int, default=3600)
    ap.add_argument("--screenshot", action="store_true", help="also write docs/shizukudos10/screenshots/webkit-r1.png")
    a = ap.parse_args()
    from PIL import Image
    OUT.mkdir(parents=True, exist_ok=True)
    if not EXE.exists():
        raise SystemExit(f"missing {EXE}: run port/build_port.py --target T_WK_RENDER")
    import importcheck
    wkrun = deps.w1.OUT / "WKRUN.EXE"
    run([*deps.CC, "-O2", "-Wall", "-Wextra", "-Werror", HERE / "wkrun.c", "-o", wkrun], env=deps.env())
    page = OUT / "r1.html"
    shutil.copyfile(PAGE, page)
    files = [wkrun, EXE, *deps.runtime_dlls(), page]
    report, _ = importcheck.check([str(f) for f in files if f.suffix.lower() in (".exe", ".dll")])
    misses = [f"{img}: {m}" for img, r in report.items() for m in r["missing"]]
    image = OUT / "r1.img"
    wkguest.make_image(image, files, f"r1|{a.timeout - 300}|T_WK_RENDER.exe r1.html r1.bmp {W} {H}\r\n")
    wkguest.autorun(image, a.timeout - 120)
    serial_path = OUT / "serial.log"
    secs, timed_out, _, cmd, accel = wkguest.run_qemu(image, serial_path, memory=a.memory, timeout=a.timeout,
                                                     display="vga", snapshot=False)
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    res = wkguest.parse_serial(serial)
    line = next((l for l in res["lines"] if "T_WK_RENDER init_ms=" in l), None)
    timing = dict(re.findall(r"(\w+)=([\d.]+)", line)) if line else {}
    title = re.search(r'title="([^"]*)"', line).group(1) if line else None
    bmp = wkguest.get_file(image, "WK/r1.bmp", OUT / "guest.bmp")
    checks = {"guest_exit_0": res["results"].get("r1", {}).get("exit") == 0, "timing_line": bool(line),
              "title_from_script": title == "R1 5050", "bmp_written": bool(bmp), "imports_resolve": not misses}
    cmpres = {}
    if bmp:
        Image.open(bmp).convert("RGB").save(OUT / "guest.png")
        host_reference(OUT / "reference.png")
        cmpres = compare(OUT / "guest.png", OUT / "reference.png", OUT / "diff.png")
        checks["pixels_within_tolerance"] = cmpres.get("differing_fraction", 1) <= 0.05
        checks["solid_colour_probes"] = all(p["ok"] for p in cmpres.get("probes", []))
    ok = all(checks.values()) and not timed_out
    record = {"status": "PASS" if ok else "FAIL", "checks": checks, "compare": cmpres, "timing_ms": timing,
              "title": title, "accel": accel, "qemu_seconds": secs, "qemu_timed_out": timed_out, "memory_mib": a.memory,
              "exe_bytes": EXE.stat().st_size, "import_misses": misses, "command": cmd, "loader": res["loader"],
              "exceptions": [e for e in res["exceptions"] if not re.search(r"process (fault|wild|high) \(pid", e)],
              "unsupported": res["unsupported"][:40], "guest_lines": res["lines"][-80:], "utc": shzlib.utc_now(),
              "git": shzlib.git_state()}
    shzlib.write_json(OUT / "result.json", record)
    if a.screenshot and bmp:
        shots = REPO / "docs" / "shizukudos10" / "screenshots"
        shots.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(OUT / "guest.png", shots / "webkit-r1.png")
    for k, v in checks.items():
        print(f"  [{'PASS' if v else 'FAIL'}] {k}")
    print(f"  timing: {timing}  compare: { {k: v for k, v in cmpres.items() if k != 'probes'} }")
    for l in record["loader"][:5] + record["exceptions"][:5]:
        print(f"  [guest] {l}")
    print(f"{record['status']} ({secs} s, accel={accel}); result: {OUT / 'result.json'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
