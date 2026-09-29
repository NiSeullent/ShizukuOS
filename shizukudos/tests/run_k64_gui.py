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


# ---------------------------------------------------------------- the built-in font (the same public-domain data file the
# guest is built from; used only as the SPECIFICATION of what a glyph looks like, never to read anything back)
def load_font():
    text = (HERE.parent / "supervisor" / "src" / "font8x8_basic.h").read_text()
    rows = re.findall(r"\{\s*((?:0x[0-9A-Fa-f]{2},?\s*){8})\}", text)
    font = [[int(x, 16) for x in re.findall(r"0x[0-9A-Fa-f]{2}", r)] for r in rows]
    assert len(font) == 128, len(font)
    return font


FONT = load_font()


def glyph_on(ch, x, y):
    """pixel (x,y) of the 8x16 cell of ASCII `ch`: each 8x8 row doubled, bit 0 = leftmost pixel"""
    return (FONT[ord(ch) & 0x7f][y >> 1] >> x) & 1


def paint_text(canvas, x0, y0, text, color):
    """canvas: dict (x,y) -> rgb overrides in screen coordinates; draws `text` with foreground pixels only"""
    for i, ch in enumerate(text):
        for y in range(16):
            for x in range(8):
                if glyph_on(ch, x, y):
                    canvas[(x0 + 8 * i + x, y0 + y)] = color


FACE = (192, 192, 192)
NAVY = (0, 0, 128)
GRAY = (128, 128, 128)


def check_outside_is_desktop(img, rep, name, windows):
    """every pixel outside all the given window rectangles [(l,t,r,b)] is the desktop colour"""
    bad = None
    dt = bytes(DESKTOP)
    for y in range(H):
        spans, x = [], 0
        for (l, t, r, b) in sorted(w for w in windows if w[1] <= y < w[3]):
            if l > x:
                spans.append((x, l))
            x = max(x, r)
        if x < W:
            spans.append((x, W))
        for (a, b2) in spans:
            if img.row(y, a, b2) != dt * (b2 - a):
                bad = f"row {y} x[{a},{b2}) is not desktop coloured"
                break
        if bad:
            break
    rep.check(f"{name}: everything outside the windows is the desktop colour", bad is None, bad or "")


def frame_checks(img, rep, name, l, t, r, b, active, title):
    """the classic thick-frame overlapped window frame drawn by the kernel compositor (documented in gfx_wm.c draw_nc)"""
    cap = NAVY if active else GRAY
    ok = (img.px(l, t) == (192, 192, 192) and img.px(l + 1, t + 1) == (255, 255, 255) and img.px(r - 1, b - 1) == (0, 0, 0) and
          img.px(r - 2, b - 2) == (128, 128, 128) and img.px(l + 2, t + 2) == FACE and img.px(l + 3, t + 3) == FACE)
    rep.check(f"{name}: 4-pixel bevelled sizing frame (corner pixels)", ok,
              f"{img.px(l, t)} {img.px(l + 1, t + 1)} {img.px(r - 1, b - 1)} {img.px(r - 2, b - 2)}")
    canvas = {}
    tcol = (255, 255, 255) if active else (192, 192, 192)
    paint_text(canvas, l + 4 + 4, t + 4 + 1, title, tcol)
    wrong = None
    for y in range(t + 4, t + 4 + 18):
        for x in range(l + 4, r - 4):
            want = canvas.get((x, y), cap)
            if img.px(x, y) != want:
                wrong = f"({x},{y}) is {img.px(x, y)}, want {want}"
                break
        if wrong:
            break
    rep.check(f"{name}: {'active' if active else 'inactive'} caption bar {cap} with the title text in the 8x16 font", wrong is None, wrong or "")
    rep.rect(img, f"{name}: 1-pixel face line below the caption", l + 4, t + 4 + 18, r - 4, t + 4 + 19, FACE)


def verify_window(img, rep):
    L, T, R, B = 100, 80, 500, 380
    cx, cy = L + 4, T + 4 + 19
    check_outside_is_desktop(img, rep, "window", [(L, T, R, B)])
    frame_checks(img, rep, "window", L, T, R, B, True, "Shizuku Test")
    expect = {}
    for y in range(273):
        for x in range(392):
            expect[(x, y)] = (255, 255, 255)
    for y in range(20, 80):
        for x in range(20, 120):
            expect[(x, y)] = (255, 0, 0)
        for x in range(150, 250):
            expect[(x, y)] = (0, 0, 255)
    for x in range(20, 120):
        expect[(x, 200)] = (0, 160, 0)
    for y in range(200, 260):
        for x in range(300, 380):
            border = x < 302 or x >= 378 or y < 202 or y >= 258
            expect[(x, y)] = (64, 64, 64) if border else (200, 200, 200)
    text = {}
    paint_text(text, 20, 100, "Hello GUI", (0, 0, 0))
    expect.update(text)
    wrong = None
    for y in range(273):
        for x in range(392):
            if img.px(cx + x, cy + y) != expect[(x, y)]:
                wrong = f"client ({x},{y}) is {img.px(cx + x, cy + y)}, want {expect[(x, y)]}"
                break
        if wrong:
            break
    rep.check("window: the 392x273 client area matches the painted scene pixel for pixel (bg, 2 rects, line, text, pen+brush box)", wrong is None,
              wrong or "all 106,896 client pixels identical")


# ---------------------------------------------------------------- a small model of the screen for whole-screen comparisons
class Screen:
    def __init__(self):
        self.rows = [bytearray(bytes(DESKTOP) * W) for _ in range(H)]
        self.clip = (0, 0, W, H)

    def fill(self, l, t, r, b, rgb):
        cl, ct, cr, cb = self.clip
        l, t, r, b = max(l, 0, cl), max(t, 0, ct), min(r, W, cr), min(b, H, cb)
        if r <= l or b <= t:
            return
        span = bytes(rgb) * (r - l)
        for y in range(t, b):
            self.rows[y][l * 3:r * 3] = span

    def put(self, x, y, rgb):
        if self.clip[0] <= x < self.clip[2] and self.clip[1] <= y < self.clip[3] and 0 <= x < W and 0 <= y < H:
            self.rows[y][x * 3:x * 3 + 3] = bytes(rgb)

    def ring(self, l, t, r, b, tl, br):
        self.fill(l, t, r, t + 1, tl)
        self.fill(l, t, l + 1, b, tl)
        self.fill(l, b - 1, r, b, br)
        self.fill(r - 1, t, r, b, br)

    def window(self, l, t, r, b, active, title, client_rgb):
        """A WS_OVERLAPPEDWINDOW (4-pixel sizing frame, 19-pixel caption) as documented in kernel64/gfx_wm.c draw_nc."""
        self.fill(l, t, r, b, FACE)
        self.ring(l, t, r, b, (192, 192, 192), (0, 0, 0))
        self.ring(l + 1, t + 1, r - 1, b - 1, (255, 255, 255), (128, 128, 128))
        self.fill(l + 4, t + 4, r - 4, t + 4 + 18, NAVY if active else GRAY)
        canvas = {}
        paint_text(canvas, l + 8, t + 5, title, (255, 255, 255) if active else (192, 192, 192))
        for (x, y), c in canvas.items():
            if l + 4 <= x < r - 4 and t + 4 <= y < t + 22:
                self.put(x, y, c)
        self.fill(l + 4, t + 23, r - 4, b - 4, client_rgb)

    def data(self):
        return b"".join(bytes(r) for r in self.rows)


def compare_screen(img, rep, name, scr):
    if (img.w, img.h) != (W, H):
        rep.check(f"{name}: screendump is 1024x768", False, f"{img.w}x{img.h}")
        return
    exp = scr.data()
    if img.data == exp:
        rep.check(name, True, "all 786432 pixels identical to the host-computed screen")
        return
    bad, first = 0, None
    for y in range(H):
        a, b = img.row(y, 0, W), exp[y * W * 3:(y + 1) * W * 3]
        if a != b:
            for x in range(W):
                if a[x * 3:x * 3 + 3] != b[x * 3:x * 3 + 3]:
                    bad += 1
                    if first is None:
                        first = f"first mismatch ({x},{y}) got {tuple(a[x * 3:x * 3 + 3])} want {tuple(b[x * 3:x * 3 + 3])}"
    rep.check(name, False, f"{bad} pixels differ; {first}")


RED, BLUE = (255, 0, 0), (0, 0, 255)


def verify_z1(img, rep):
    s = Screen()
    s.window(100, 100, 400, 300, False, "Window A", RED)
    s.window(220, 160, 520, 360, True, "Window B", BLUE)
    compare_screen(img, rep, "z1: B (blue, active) stacked above A (red, inactive): whole screen matches", s)


def verify_z2(img, rep):
    s = Screen()
    s.window(220, 160, 520, 360, False, "Window B", BLUE)
    s.window(100, 100, 400, 300, True, "Window A", RED)
    compare_screen(img, rep, "z2: after BringWindowToTop(A) A (red, active) is above B (blue, inactive): whole screen matches", s)


def verify_z3(img, rep):
    s = Screen()
    s.window(100, 100, 400, 300, True, "Window A", RED)
    compare_screen(img, rep, "z3: B hidden, only A on the desktop: whole screen matches", s)


def verify_z4(img, rep):
    s = Screen()
    s.window(300, 300, 600, 500, True, "Window A", RED)
    compare_screen(img, rep, "z4: A moved to (300,300), the vacated area is desktop again: whole screen matches", s)


def poly_fill_pixels(pts):
    """even-odd fill of an integer polygon: pixel (x,y) belongs to it when the pixel CENTRE (x+.5, y+.5) is inside; exact
    arithmetic; a horizontal edge never counts, an edge counts for the rows y in [min(y1,y2), max(y1,y2))"""
    from fractions import Fraction as Fr
    import math
    out = []
    ys = [p[1] for p in pts]
    for y in range(min(ys), max(ys)):
        xs = []
        for i in range(len(pts)):
            (x1, y1), (x2, y2) = pts[i], pts[(i + 1) % len(pts)]
            if y1 == y2 or not (min(y1, y2) <= y < max(y1, y2)):
                continue
            xs.append(x1 + Fr(2 * y + 1 - 2 * y1, 2) * Fr(x2 - x1, y2 - y1))
        xs.sort()
        for a, b in zip(xs[0::2], xs[1::2]):
            for x in range(math.ceil(a - Fr(1, 2)), math.ceil(b - Fr(1, 2))):
                out.append((x, y))
    return out


def verify_gdi(img, rep):
    OX, OY = 100, 100
    s = Screen()
    s.fill(OX, OY, OX + 500, OY + 360, (255, 255, 255))

    def P(x, y, c):
        s.put(OX + x, OY + y, c)

    def R(l, t, r, b, c):
        s.fill(OX + l, OY + t, OX + r, OY + b, c)
    for y in range(64):                                                      # A
        for x in range(256):
            P(10 + x, 10 + y, (x, 255 - x, 128))
    for y in range(32):                                                      # B
        for x in range(128):
            sx = x * 256 // 128
            P(10 + x, 90 + y, (sx, 255 - sx, 128))
    for y in range(32):                                                      # C
        for x in range(32):
            P(300 + x, 10 + y, (60 * (x * 4 // 32), 60 * (y * 4 // 32), 200))
    for v in range(8):                                                       # D
        for u in range(8):
            P(300 + u, 60 + v, (32 * u, 32 * v, 32 * (u ^ v)))
    R(10, 140, 10 + 6 * 16, 140 + 32, (255, 255, 192))                       # E: "Scale2", scale 2, opaque
    for i, ch in enumerate("Scale2"):
        for y in range(32):
            for x in range(16):
                if glyph_on(ch, x // 2, y // 2):
                    P(10 + 16 * i + x, 140 + y, (0, 0, 0))
    for i, ch in enumerate("Bold"):                                          # E: bold = the glyph OR'ed with itself shifted 1 px right
        for y in range(16):
            for x in range(8):
                if glyph_on(ch, x, y) or (x > 0 and glyph_on(ch, x - 1, y)):
                    P(10 + 8 * i + x, 180 + y, (0, 0, 0))
    R(200, 150, 300, 250, (200, 0, 0))                                       # F: the L-shaped clip
    R(200, 250, 400, 300, (200, 0, 0))

    def stripe(yy):
        return (0, 0, 255) if ((yy - 240) // 10) % 2 == 0 else (255, 255, 0)
    for y in range(230, 300):                                                # G: stripes scrolled up by 10, bottom 10 rows untouched
        R(10, y, 110, y + 1, stripe(y + 10 if y < 290 else y))
    R(10, 320, 110, 321, (0, 255, 255))                                      # H
    P(10, 330, (0, 255, 255))
    P(110, 330, (0, 255, 255))
    for (x, y) in poly_fill_pixels([(420, 20), (485, 20), (452, 73)]):       # I
        P(x, y, (255, 128, 0))
    R(450, 300, 470, 320, (255, 0, 255))                                     # K
    s.fill(5, 5, 25, 25, (128, 255, 0))                                      # L (on the desktop)
    # J: the ellipse is checked by its properties below; make the expected screen equal to the real one inside its box
    el, et, er, eb = OX + 420, OY + 100, OX + 480, OY + 160
    for y in range(et, eb):
        s.rows[y][el * 3:er * 3] = img.row(y, el, er)
    compare_screen(img, rep, "gdi: whole screen (BitBlt/StretchBlt/StretchDIBits/SetDIBitsToDevice/scaled+bold text/clip region/scroll/XOR "
                             "line/polygon/GetDC boxes/desktop DC) matches the host model outside the ellipse box", s)
    fillc, inside = (0, 200, 255), 0
    rows = []
    for y in range(et, eb):
        row = [img.px(x, y) == fillc for x in range(el, er)]
        rows.append(row)
        inside += sum(row)
    sym_x = all(r == r[::-1] for r in rows)
    sym_y = rows == rows[::-1]
    area = 3.14159265 * 30 * 30
    rep.check("gdi: ellipse is mirror symmetric, centre filled, corners untouched, area within 2% of pi*a*b",
              sym_x and sym_y and rows[30][30] and not rows[0][0] and not rows[59][59] and abs(inside - area) < 0.02 * area,
              f"sym_x={sym_x} sym_y={sym_y} pixels={inside} ideal={area:.0f}")


def child_window(s, ox, oy, rect, kind, color, boxes):
    """a child of the parent at screen client origin (ox,oy), clipped to the parent's client area; kind: 'border' (WS_BORDER),
    'edge' (WS_EX_CLIENTEDGE) or 'plain'. Non-client drawing as documented in kernel64/gfx_wm.c draw_nc."""
    l, t, r, b = rect
    L, T, R, B = ox + l, oy + t, ox + r, oy + b
    s.fill(L, T, R, B, FACE)
    if kind == "border":
        s.ring(L, T, R, B, (0, 0, 0), (0, 0, 0))
        inset = 1
    elif kind == "edge":
        s.ring(L, T, R, B, (128, 128, 128), (255, 255, 255))
        s.ring(L + 1, T + 1, R - 1, B - 1, (64, 64, 64), (192, 192, 192))
        inset = 2
    else:
        inset = 0
    s.fill(L + inset, T + inset, R - inset, B - inset, color)
    for (x0, y0, x1, y1) in boxes:
        s.fill(L + inset + x0, T + inset + y0, L + inset + x1, T + inset + y1, (255, 255, 255))


def child_scene(order):
    """order: list of (name, rect in parent client coordinates), bottom to top"""
    s = Screen()
    s.window(100, 100, 500, 400, True, "Parent", FACE)
    ox, oy = 104, 123
    s.clip = (ox, oy, ox + 392, oy + 273)
    spec = {"C1": ("border", (255, 0, 0), [(5, 5, 15, 15)]), "C2": ("edge", (0, 0, 255), [(5, 5, 15, 15)]),
            "C3": ("plain", (0, 160, 0), [(5, 5, 15, 15), (80, 80, 95, 95)])}
    for name, rect in order:
        kind, color, boxes = spec[name]
        child_window(s, ox, oy, rect, kind, color, boxes)
    return s


C1R, C2R, C3R = (20, 20, 170, 120), (100, 60, 250, 160), (330, 200, 430, 300)


def verify_c1(img, rep):
    compare_screen(img, rep, "c1: parent with C1 (bordered), C2 (client edge) above it and C3 clipped by the parent: whole screen matches",
                   child_scene([("C1", C1R), ("C2", C2R), ("C3", C3R)]))


def verify_c2(img, rep):
    compare_screen(img, rep, "c2: BringWindowToTop(C1) puts C1 above C2: whole screen matches",
                   child_scene([("C2", C2R), ("C3", C3R), ("C1", C1R)]))


def verify_c3(img, rep):
    compare_screen(img, rep, "c3: C2 hidden, C3 moved so its second box is half clipped: whole screen matches",
                   child_scene([("C3", (300, 150, 400, 250)), ("C1", C1R)]))


def verify_c4(img, rep):
    compare_screen(img, rep, "c4: C1 grown to 200x140, the old content kept and the new strips erased: whole screen matches",
                   child_scene([("C3", (300, 150, 400, 250)), ("C1", (20, 20, 220, 160))]))


def verify_orphan1(img, rep):
    s = Screen()
    s.window(560, 380, 800, 540, True, "Orphan", (0, 128, 0))
    compare_screen(img, rep, "orphan1: the window of another process is composited (whole screen matches)", s)


def verify_orphan2(img, rep):
    compare_screen(img, rep, "orphan2: after its process died the kernel removed the window: bare desktop (whole screen matches)", Screen())


def verify_status(img, rep):
    """T_GUI_STATUS: the frame of its full-screen window; its content (one row per loaded DLL) is checked through the
    STATUS-DLL serial lines against the DLLs this build produced, the screendump is kept as the visible record."""
    L, T, R, B = 8, 8, 1016, 760
    check_outside_is_desktop(img, rep, "status", [(L, T, R, B)])
    frame_checks(img, rep, "status", L, T, R, B, True, "Shizuku Win64 runtime status")


SCENES = {"fb": verify_fb, "status": verify_status, "window": verify_window, "z1": verify_z1, "z2": verify_z2, "z3": verify_z3, "z4": verify_z4,
          "orphan1": verify_orphan1, "orphan2": verify_orphan2, "gdi": verify_gdi,
          "c1": verify_c1, "c2": verify_c2, "c3": verify_c3, "c4": verify_c4}


# ---------------------------------------------------------------- harness
def save_png(ppm):
    try:
        from PIL import Image as PILImage
    except ImportError:
        return
    PILImage.open(ppm).save(ppm.with_suffix(".png"))



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
    ap.add_argument("--png", action="store_true", help="also write every screendump as PNG next to result.json (needs Pillow)")
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
            if args.png:
                save_png(shot)
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
    # only the GUI programs must not skip: this boot has no NIC, so the network tests skip by design
    skips = re.findall(r"\[win64 T_GUI_\S+ pid \d+\] (SKIP: .*)", serial)
    rep.check("no GUI program skipped (the display is present)", not skips, "; ".join(skips[:5]))
    loaded = {m.group(1).lower(): m.group(2) == "1" and m.group(3) == "1"
              for m in re.finditer(r"STATUS-DLL: (\S+) loaded=(\d) exports=\d+ resolved=(\d)", serial)}
    built = json.loads((WIN64 / "build-result.json").read_text())["archive"]["files"]
    for dll in sorted(f.rsplit("\\", 1)[-1].lower() for f in built if f.upper().startswith("\\SHZ\\SYS64\\")):
        rep.check(f"status: {dll} was loaded in the guest and its first export resolved", loaded.get(dll, False),
                  "reported" if dll in loaded else "not reported by T_GUI_STATUS")
    pci = re.findall(r"STATUS-PCI: \S+ 1234:1111 class 03\S* irq \d+ driver=(.*)", serial)
    rep.check("status: the Bochs VBE display (PCI 1234:1111) is listed as bound to the gfx_fb kernel driver",
              any(d.startswith("gfx_fb") for d in pci), "; ".join(pci) or "not listed")
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
