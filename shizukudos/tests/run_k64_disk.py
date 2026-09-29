#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot standalone Kernel64 under QEMU with a FAT32 disk on AHCI and verify the disk path from the host side.

Profile: the same standalone profile as run_k64_standalone.py (QEMU -kernel stub, no Supervisor, TCG or KVM) plus
`-device ahci` + `ide-hd` carrying a raw FAT32 image built here with mkfs.vfat --invariant and mtools (deterministic
timestamps). Kernel64 drives the disk through the original AHCI core (drivers/ahci_native: READ/WRITE DMA EXT, FLUSH
CACHE EXT) and mounts the volume read/write as D:\\ (kernel64/blk.c, ahci_blk.c, fat32.c, disk.c). Everything the
guest reports (sector-0 CRC, directory listing, file CRCs, written-file CRCs) is recomputed or checked independently
here from the image and its source files; after QEMU exits the image itself is checked: fsck.fat -n must find it
clean and mtools must read the guest-written files back with exactly the expected bytes.

Lazily mapped images: two large DLLs of known content (tests/k64_lazy_dll.py: BIGLAZY.DLL, a 320 MiB blob at its
preferred base, and BIGRELOC.DLL, relocated because its preferred base is the executable's) are loaded by T_LAZY.EXE
with LoadLibraryW from D:\\LAZY in a guest with 256 MiB of RAM; the host recomputes every page hash the guest
reports and checks the resident-page counts (NtQueryVirtualMemory working-set query), the free-memory deltas and the
kernel's own per-module statistics.

--chromium DIR additionally boots a second time with DIR (a Chromium chrome-win tree, read-only) copied into a FAT32
image outside the repository as D:\\chrome-win; T_CHROME.EXE calls LoadLibraryW(chrome.dll) and
CreateProcessW(chrome.exe) and the kernel's first loader failure line for each is recorded (not a pass criterion).

All checks of run_k64_standalone.py must still pass in this configuration (same self-tests, same Win64 apps).
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD, run  # noqa: E402
import run_k64_standalone as base  # noqa: E402
import k64_lazy_dll  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
FIXED_EPOCH = 1785283200          # 2026-07-29 00:00:00 UTC (tools/fatimg.py convention)
SCRATCH = Path("/tmp/claude-0/-home-user-Win98-Modern/31f1e8e6-646b-5a42-ab0f-36694df325e9/scratchpad")


def mtools_env():
    env = dict(os.environ)
    env["MTOOLS_SKIP_CHECK"] = "1"
    env["TZ"] = "UTC"
    env["SOURCE_DATE_EPOCH"] = str(FIXED_EPOCH)
    return env


def crc32_file(path):
    c = 0
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            c = zlib.crc32(chunk, c)
    return c & 0xffffffff


def make_image(image, size_mib, spc, files, dirs):
    """Superfloppy FAT32 (no MBR): mkfs.vfat --invariant, then mtools copies with fixed mtimes.
    files: list of (host_path, "DIR/NAME" inside the volume); dirs: list of "DIR" to create first."""
    image = Path(image)
    image.unlink(missing_ok=True)
    with open(image, "wb") as fh:
        fh.truncate(size_mib * 1024 * 1024)
    run(["mkfs.vfat", "-F", "32", "-s", str(spc), "-n", "SHZDISK", "--invariant", str(image)], capture=True)
    env = mtools_env()
    for d in dirs:
        run(["mmd", "-i", str(image), f"::{d}"], env=env, capture=True)
    for host, name in files:
        os.utime(host, (FIXED_EPOCH, FIXED_EPOCH))
        run(["mcopy", "-m", "-i", str(image), str(host), f"::{name}"], env=env, capture=True)


def pattern(seed, n):
    out = bytearray()
    x = seed & 0xffffffff
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0xffffffff
        out += x.to_bytes(4, "little")
    return bytes(out[:n])


FIXED_FILETIME = (FIXED_EPOCH + 11644473600) * 10_000_000


def disk_checks(serial, ev, manifest, image_path):
    """T_DISK.EXE lines (DISK-DIR/CRC/RANGE/NESTED) against the files packed into the image."""
    e = lambda s: ev.get(s, 0)  # noqa: E731
    c = []
    tests = {rel[len("TESTS/"):]: data for rel, data in manifest.items() if rel.startswith("TESTS/") and "/" not in rel[len("TESTS/"):]}
    tests["Sub Directory"] = None
    got_dir = {m.group(1): (int(m.group(2)), int(m.group(3), 16), int(m.group(4), 16))
               for m in re.finditer(r"^\[win64 T_DISK\.EXE pid \d+\] DISK-DIR (.+?) (\d+) ([0-9a-f]+) ([0-9a-f]{16})$", serial, re.M)}
    got_crc = {m.group(1): (int(m.group(2)), int(m.group(3), 16))
               for m in re.finditer(r"^\[win64 T_DISK\.EXE pid \d+\] DISK-CRC (.+?) (\d+) ([0-9a-f]+)$", serial, re.M)}
    got_range = {m.group(1).rsplit("\\", 1)[-1]: (int(m.group(2)), int(m.group(3)), int(m.group(4), 16))
                 for m in re.finditer(r"^\[win64 T_DISK\.EXE pid \d+\] DISK-RANGE (.+?) (\d+) (\d+) ([0-9a-f]+)$", serial, re.M)}
    c.append(base.check("FAT32: D:\\TESTS listing has exactly the packed entries (LFN names, case preserved)",
                        set(got_dir) == set(tests), f"guest={sorted(got_dir)} host={sorted(tests)}"))
    bad = []
    for name, data in tests.items():
        g = got_dir.get(name)
        if not g:
            continue
        if data is None:
            if not g[1] & 0x10:
                bad.append(f"{name}: not a directory ({g[1]:#x})")
            continue
        if g[0] != len(data):
            bad.append(f"{name}: size {g[0]} != {len(data)}")
        if g[1] & 0x10:
            bad.append(f"{name}: directory bit set")
        if g[2] != FIXED_FILETIME:
            bad.append(f"{name}: mtime {g[2]:#x} != {FIXED_FILETIME:#x}")
    c.append(base.check("FAT32: sizes, attributes and fixed mtimes match", not bad, "; ".join(bad)))
    bad = []
    for name, data in tests.items():
        if data is None:
            continue
        g = got_crc.get(name)
        if not g:
            bad.append(f"{name}: no CRC line")
        elif g != (len(data), zlib.crc32(data) & 0xffffffff):
            bad.append(f"{name}: guest {g[0]}/{g[1]:#x} host {len(data)}/{zlib.crc32(data) & 0xffffffff:#x}")
        r = got_range.get(name)
        if len(data) > 8192:
            off = max(len(data) // 2 - 1234, 1)
            want = zlib.crc32(data[off:off + 3000]) & 0xffffffff
            if not r or r != (off, min(3000, len(data) - off), want):
                bad.append(f"{name}: range read {r} != ({off}, 3000, {want:#x})")
    c.append(base.check("FAT32: every file's CRC-32 read by the guest matches the host, sequential and random-offset",
                        not bad, "; ".join(bad) or f"{len(got_crc)} files, {sum(len(d) for d in tests.values() if d)} bytes"))
    nested = manifest["TESTS/Sub Directory/nested file.txt"]
    m = re.search(r"DISK-NESTED (\d+) ([0-9a-f]+)", serial)
    c.append(base.check("FAT32: nested LFN path D:\\TESTS\\Sub Directory\\nested file.txt read back",
                        bool(m) and (int(m.group(1)), int(m.group(2), 16)) == (len(nested), zlib.crc32(nested) & 0xffffffff),
                        m.group(0) if m else "no DISK-NESTED line"))
    xor = 0
    for data in tests.values():
        if data is not None:
            xor ^= zlib.crc32(data) & 0xffffffff
    c.append(base.check("FAT32: evidence slot 18 = (files hashed << 32 | xor of CRCs)",
                        e(18) == (sum(1 for d in tests.values() if d is not None) << 32) | xor, f"{e(18):#x}"))
    queries = {}
    for m in re.finditer(r"^\[win64 T_DISK\.EXE pid \d+\] DISK-QUERY (\d+) (\S+) (.*)\|(.*)$", serial, re.M):
        queries.setdefault((int(m.group(1)), m.group(2)), []).append((m.group(3), m.group(4)))
    listing = run(["mdir", "-i", str(image_path), "::TESTS"], env=mtools_env(), capture=True).stdout
    aliases = {}
    for line in listing.splitlines():                  # "ALONGM~1 DAT     12293 2026-07-29   0:00  A Long Mixed-Case File Name.dat"
        mm = re.match(r"^(\S+)\s+(\S{1,3})?\s+(?:<DIR>|\d+)\s+\S+\s+\S+\s+(.+)$", line)
        if mm:
            aliases[mm.group(3).strip()] = mm.group(1) + ("." + mm.group(2) if mm.group(2) else "")
    want = {(12, "*.bin"): sorted((n, "") for n in tests if n.endswith(".bin")),
            (1, "A*.DAT"): [("A Long Mixed-Case File Name.dat", "")],
            (3, "*"): sorted((n, aliases.get(n, "")) for n in tests)}
    got = {k: sorted(v) for k, v in queries.items()}
    bad = [f"{k}: guest {got.get(k)} host {v}" for k, v in want.items() if got.get(k) != v]
    if (3, "nomatch*.zzz") in got:
        bad.append(f"nomatch returned {got[(3, 'nomatch*.zzz')]}")
    c.append(base.check("NtQueryDirectoryFile: kernel-side patterns, classes 1/3/12 (FileName @64/@94/@12), ShortName = mtools alias",
                        not bad and len(aliases) >= 2, "; ".join(bad) or f"aliases {aliases}"))
    c.append(base.check("T_DISK.EXE did not SKIP (D: was mounted)", "SKIP:" not in "".join(
        l for l in serial.splitlines() if "T_DISK.EXE" in l) and "t_disk:" in serial))
    m = re.search(r"K64 disk: D: = (\S+), FAT32 \"(\w*)\" id ([0-9a-f]+), (\d+) clusters of (\d+) bytes", serial)
    c.append(base.check("Kernel64 mounted the FAT32 volume as D: (label SHZDISK, 4 KiB clusters)",
                        bool(m) and m.group(2) == "SHZDISK" and m.group(5) == "4096", m.group(0) if m else "no mount line"))
    return c


WRITE_ORIG = {"WRITE/existing file.bin": pattern(41, 20000), "WRITE/TRUNC.BIN": pattern(42, 50000)}


def expected_writes():
    """What T_DISK.EXE's write_tests() leaves on D: (volume path -> bytes)."""
    existing = bytearray(WRITE_ORIG["WRITE/existing file.bin"])
    existing[5000:8000] = pattern(32, 3000)
    existing += pattern(33, 1000)
    return {"OUT/Guest Written File.bin": pattern(31, 300000),
            "OUT/Sub Dir/small.txt": b"written by T_DISK.EXE inside a new directory\r\n",
            "WRITE/existing file.bin": bytes(existing),
            "WRITE/TRUNC.BIN": WRITE_ORIG["WRITE/TRUNC.BIN"][:777]}


def write_checks(serial, image, out):
    """Guest read-back lines, then the image after QEMU exited: fsck.fat -n and mtools read-back."""
    c = []
    want = expected_writes()
    got = {m.group(1).replace("D:\\", "").replace("\\", "/"): (int(m.group(2)), int(m.group(3), 16))
           for m in re.finditer(r"^\[win64 T_DISK\.EXE pid \d+\] DISK-WRITE (.+?) (\d+) ([0-9a-f]+)$", serial, re.M)}
    bad = [f"{k}: guest {got.get(k)} host {(len(v), zlib.crc32(v) & 0xffffffff)}" for k, v in want.items()
           if got.get(k) != (len(v), zlib.crc32(v) & 0xffffffff)]
    c.append(base.check("FAT32 write: the guest read back what it wrote (create, odd-chunk write, overwrite, append, truncate)",
                        not bad, "; ".join(bad) or f"{len(got)} files"))
    fsck = subprocess.run(["fsck.fat", "-n", "-v", str(image)], capture_output=True, text=True)
    (out / "fsck.txt").write_text(fsck.stdout + fsck.stderr)
    problems = [l for l in fsck.stdout.splitlines() if not l.startswith("Checking") and any(
        k in l.lower() for k in ("wrong", "lost", "invalid", "differ", "bad ", "orphan", "reclaim", "unused",
                                 "free cluster summary", "has no", "starts with", "contains"))]
    summary = [l for l in fsck.stdout.splitlines() if " files, " in l]
    c.append(base.check("FAT32 write: fsck.fat -n finds the image clean after the guest's writes",
                        fsck.returncode == 0 and not problems, f"rc={fsck.returncode} {problems or summary}"))
    tmp = out / "readback.bin"
    bad = []
    for rel, data in want.items():
        tmp.unlink(missing_ok=True)
        r = subprocess.run(["mcopy", "-n", "-i", str(image), f"::{rel}", str(tmp)], env=mtools_env(), capture_output=True)
        if r.returncode or tmp.read_bytes() != data:
            bad.append(f"{rel}: rc={r.returncode} {tmp.stat().st_size if tmp.exists() else 0} bytes")
    c.append(base.check("FAT32 write: mtools reads every guest-written file back from the image, byte for byte",
                        not bad, "; ".join(bad) or ", ".join(f"{k} {len(v)}" for k, v in want.items())))
    listing = run(["mdir", "-i", str(image), "::OUT"], env=mtools_env(), capture=True).stdout
    (out / "mdir-out.txt").write_text(listing)
    c.append(base.check("FAT32 write: long names and generated 8.3 aliases in D:\\OUT (mdir)",
                        "Guest Written File.bin" in listing and "GUESTW~1 BIN" in " ".join(listing.split()) and "Sub Dir" in listing,
                        " | ".join(l.strip() for l in listing.splitlines() if "~" in l)))
    m = [x for x in re.finditer(r"K64 disk: flush (\S+): rc (-?\d+); (\S+): (\d+) sectors read, (\d+) written, (\d+) cache flush"
                                r"\(es\); D: (\d+) write\(s\), (\d+) create\(s\), (\d+) sector writes", serial)]
    last = m[-1] if m else None
    c.append(base.check("AHCI write path: WRITE DMA EXT sectors and FLUSH CACHE EXT commands completed (kernel counters)",
                        bool(last) and last.group(2) == "0" and int(last.group(5)) > 600 and int(last.group(6)) >= 2 and
                        int(last.group(7)) >= 5 and int(last.group(8)) == 4, last.group(0) if last else "no flush line"))
    return c


def lazy_checks(serial):
    """T_LAZY.EXE lines and the kernel's lazy-mapping lines."""
    c = []
    loads = {m.group(1): m for m in re.finditer(
        r"LAZY-LOAD (\S+) base ([0-9a-f]+) preferred ([0-9a-f]+) image_pages (\d+) resident (-?\d+) avail_delta_kib (-?\d+)", serial)}
    touch = {m.group(1): m for m in re.finditer(
        r"LAZY-TOUCH (\S+) touches (\d+) blob_first_page (\d+) blob_pages (\d+) resident (-?\d+) avail_delta_kib (-?\d+)", serial)}
    hashes = [(m.group(1), int(m.group(2)), int(m.group(3), 16)) for m in re.finditer(r"LAZY-HASH (\S+) (\d+) ([0-9a-f]+)", serial)]
    relocs = {m.group(1): int(m.group(2)) for m in re.finditer(r"LAZY-RELOC (\S+) (-?\d+)", serial)}
    bad = [f"{n} page {pg}: guest {h:#x} host {k64_lazy_dll.page_hash(pg):#x}" for n, pg, h in hashes if k64_lazy_dll.page_hash(pg) != h]
    c.append(base.check("lazy images: every page hash the guest computed through the mapped DLLs matches the host",
                        len(hashes) == 96 and not bad, "; ".join(bad[:4]) or f"{len(hashes)} pages"))
    big, rel = loads.get("BIGLAZY.DLL"), loads.get("BIGRELOC.DLL")
    tb, tr = touch.get("BIGLAZY.DLL"), touch.get("BIGRELOC.DLL")
    ok = bool(big and tb) and int(big.group(2), 16) == 0x7fe000000000 and int(big.group(4)) > 81000 and \
        int(big.group(5)) <= 8 and int(tb.group(5)) - int(big.group(5)) <= 64 + 8 and int(tb.group(6)) < 4096
    c.append(base.check("lazy images: BIGLAZY.DLL (320 MiB, 256 MiB guest) at its preferred base; <= 8 pages resident after "
                        "LoadLibrary, +<= 72 after touching 64 blob pages, < 4 MiB of RAM used",
                        ok, (big.group(0) + " | " + tb.group(0)) if big and tb else "missing LAZY lines"))
    ok = bool(rel and tr) and int(rel.group(2), 16) != 0x140000000 and int(tr.group(5)) - int(rel.group(5)) <= 32 + 8 and \
        relocs.get("BIGRELOC.DLL") == 1256 and relocs.get("BIGLAZY.DLL") == 1256
    c.append(base.check("lazy images: BIGRELOC.DLL relocated page by page (256 DIR64 fixups + one straddling a page edge)",
                        ok, (rel.group(0) + " | " + tr.group(0) + f" | relocs {relocs}") if rel and tr else "missing LAZY lines"))
    k_map = re.search(r"K64 ldr: bigreloc\.dll mapped lazily from \S+ at ([0-9a-f]+) \(preferred 140000000, relocated per page\)", serial)
    k_end = {m.group(1): m for m in re.finditer(r"K64 ldr: (big\w+\.dll) \(pid \d+\): (\d+) of (\d+) image pages were made resident "
                                                r"\((\d+) bytes read, (\d+) relocated pages, (\d+) fixups\)", serial)}
    kb, kr = k_end.get("biglazy.dll"), k_end.get("bigreloc.dll")
    ok = bool(k_map and kb and kr) and int(kb.group(2)) <= 64 + 16 and int(kr.group(5)) >= 2 and int(kr.group(6)) >= 257
    c.append(base.check("lazy images: kernel statistics (pages made resident, relocated pages, fixups) agree",
                        ok, " | ".join(x.group(0) for x in (k_map, kb, kr) if x) or "missing kernel lines"))
    c.append(base.check("T_LAZY.EXE ran on the disk image (no SKIP)", "t_lazy:" in serial and
                        not any("SKIP" in l for l in serial.splitlines() if "T_LAZY.EXE" in l)))
    return c


def build_chromium_image(tree, image):
    """FAT32 image holding `tree` as \\chrome-win (outside the repository); rebuilt only when the tree listing changes."""
    tree = Path(tree)
    listing = sorted((str(p.relative_to(tree)), p.stat().st_size) for p in tree.rglob("*") if p.is_file())
    key = hashlib.sha256(json.dumps(listing).encode()).hexdigest()
    stamp = Path(str(image) + ".json")
    if image.exists() and stamp.exists() and json.loads(stamp.read_text()).get("key") == key:
        return listing
    total = sum(s for _, s in listing)
    size_mib = (total * 11 // 10 >> 20) + 128
    image.unlink(missing_ok=True)
    with open(image, "wb") as fh:
        fh.truncate(size_mib << 20)
    run(["mkfs.vfat", "-F", "32", "-s", "8", "-n", "CHROMIUM", "--invariant", str(image)], capture=True)
    run(["mcopy", "-s", "-m", "-i", str(image), str(tree), "::chrome-win"], env=mtools_env(), capture=True)
    stamp.write_text(json.dumps({"key": key, "files": len(listing), "bytes": total}))
    return listing


def run_qemu(args, accel, image, serial_path, memory, snapshot):
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", memory, "-nodefaults", "-display", "none",
           "-kernel", str(stub), "-initrd", f"{kernel},{initrd}", "-serial", f"file:{serial_path}",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot",
           "-device", "ahci,id=ahci0", "-drive", f"if=none,id=d0,file={image},format=raw{',snapshot=on' if snapshot else ''}",
           "-device", "ide-hd,drive=d0,bus=ahci0.0"]
    serial_path.unlink(missing_ok=True)
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
    return cmd, proc.returncode, timed_out, qemu_out, serial


def chromium_probe(args, accel, out):
    """Boots with the Chromium tree as D: and extracts the kernel's first loader failure for chrome.dll and chrome.exe."""
    tree = Path(args.chromium)
    if not (tree / "chrome.dll").exists():
        return {"status": "SKIP", "reason": f"no {tree / 'chrome.dll'}"}
    image = Path(args.chromium_image)
    image.parent.mkdir(parents=True, exist_ok=True)
    started = time.time()
    listing = build_chromium_image(tree, image)
    built = round(time.time() - started, 1)
    cmd, rc, timed_out, qemu_out, serial = run_qemu(args, accel, image, out / "serial-chromium.log", args.chromium_memory, True)
    lines = serial.splitlines()
    rec = {"image": str(image), "files": len(listing), "bytes": sum(s for _, s in listing), "image_build_s": built,
           "timed_out": timed_out, "command": cmd}
    try:
        i_dll_start = next(i for i, l in enumerate(lines) if "chrome.dll mapped lazily" in l)
    except StopIteration:
        i_dll_start = next((i for i, l in enumerate(lines) if "T_CHROME.EXE" in l), 0)
    i_dll_end = next((i for i, l in enumerate(lines) if "CHROME-DLL" in l), len(lines))
    i_exe_end = next((i for i, l in enumerate(lines) if "CHROME-EXE" in l), len(lines))
    # the loader's one-line diagnostic ("K64 ldr: X not loaded: <image> needs <dll>!<fn>: <reason>") and older forms
    fail_re = re.compile(r"K64 ldr: .*(not loaded|imports|rejected|failed|cannot|lacks)|K64: process .*killed|unhandled exception")
    dll_lines = [l for l in lines[i_dll_start:i_dll_end] if l.startswith("K64 ldr") or l.startswith("K64:")]
    exe_lines = [l for l in lines[i_dll_end:i_exe_end] if l.startswith("K64 ldr") or l.startswith("K64:")]
    rec["chrome_dll_result"] = lines[i_dll_end] if i_dll_end < len(lines) else None
    rec["chrome_exe_result"] = lines[i_exe_end] if i_exe_end < len(lines) else None
    rec["chrome_dll_first_failure"] = next((l for l in dll_lines if fail_re.search(l)), None)
    rec["chrome_exe_first_failure"] = next((l for l in exe_lines if fail_re.search(l)), None)
    rec["chrome_dll_loader_lines"] = dll_lines[:40]
    rec["chrome_exe_loader_lines"] = exe_lines[:40]
    rec["lazy_lines"] = [l for l in lines if "mapped lazily" in l or "image pages were made resident" in l][:20]
    rec["status"] = "RECORDED" if rec["chrome_dll_result"] and rec["chrome_exe_result"] else "INCOMPLETE"
    return rec


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=600)
    ap.add_argument("--memory", default="256", help="guest RAM; 256 MiB is smaller than the 320 MiB test DLL")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "run_disk"))
    ap.add_argument("--chromium", default="", help="chrome-win tree (read-only) for the Chromium probe run; empty: no probe")
    ap.add_argument("--chromium-image", default=str(SCRATCH / "k64-chromium-fat32.img"),
                    help="where the Chromium FAT32 image is built (outside the repository)")
    ap.add_argument("--chromium-memory", default="2048")
    args = ap.parse_args()
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    for f in (stub, kernel, initrd):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
    for tool in ("mkfs.vfat", "mcopy", "mmd"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)

    # ---- disk content -------------------------------------------------------------------------------------------
    src = out / "src"
    src.mkdir(exist_ok=True)
    files, dirs, manifest = [], ["TESTS", "TESTS/Sub Directory"], {}

    def add(rel, data):
        host = src / rel.replace("/", "__").replace(" ", "_")
        host.write_bytes(data)
        files.append((host, rel))
        manifest[rel] = data

    add("TESTS/hello.txt", b"hello from the FAT32 volume\r\n")
    add("TESTS/empty.txt", b"")
    add("TESTS/pattern_1m.bin", pattern(11, (1 << 20) + 17))
    add("TESTS/A Long Mixed-Case File Name.dat", pattern(12, 4096 * 3 + 5))
    add("TESTS/big_4m.bin", pattern(13, (4 << 20) + 13))
    add("TESTS/Sub Directory/nested file.txt", b"nested content on D:\r\n")
    dirs.append("WRITE")
    for rel, data in WRITE_ORIG.items():
        add(rel, data)
    dirs.append("LAZY")
    for name, path in k64_lazy_dll.build(BUILD / "lazy-dll").items():
        files.append((path, f"LAZY/{name}"))
    image = out / "disk.img"
    make_image(image, 640, 8, files, dirs)
    fsck0 = subprocess.run(["fsck.fat", "-n", str(image)], capture_output=True, text=True)
    image_sha256 = hashlib.sha256(image.read_bytes()).hexdigest()       # deterministic: same inputs, same image
    sector0 = image.read_bytes()[:512]
    expect_sectors = image.stat().st_size // 512
    expect_crc0 = zlib.crc32(sector0) & 0xffffffff
    listing = run(["mdir", "-i", str(image), "::TESTS"], env=mtools_env(), capture=True).stdout
    (out / "mdir.txt").write_text(listing)

    started = time.time()
    cmd, qemu_rc, timed_out, qemu_out, serial = run_qemu(args, accel, image, serial_path, args.memory, False)
    ev, exit_code = base.parse(serial)
    checks = base.evaluate(serial, ev, exit_code, qemu_rc, memory=args.memory)
    e = lambda s: ev.get(s, 0)  # noqa: E731
    checks.append(base.check("AHCI: guest read sector 0 (crc32 and sector count match the host image)",
                             e(13) == (expect_sectors << 32) | expect_crc0,
                             f"guest={e(13):#x} host=({expect_sectors} << 32 | {expect_crc0:#x})"))
    checks += disk_checks(serial, ev, manifest, image)
    checks.insert(len(checks), base.check("host: fsck.fat -n finds the freshly built image clean (baseline)", fsck0.returncode == 0,
                                          f"rc={fsck0.returncode}"))
    checks += write_checks(serial, image, out)
    checks += lazy_checks(serial)
    if timed_out:
        checks.insert(0, base.check("run finished before the timeout", False, f"{args.timeout}s, accel={accel}"))
    status = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    chromium = chromium_probe(args, accel, out) if args.chromium else {"status": "not requested"}
    record = {"profile": "kernel64-standalone + AHCI FAT32 disk (no Supervisor, no VMX)", "accel": accel, "status": status,
              "checks": checks, "seconds": round(time.time() - started, 1),
              "evidence": {str(k): hex(v) for k, v in sorted(ev.items())}, "command": cmd, "qemu_output": qemu_out[-1500:],
              "serial_tail": serial[-4000:], "image_sha256_before_boot": image_sha256,
              "image_sha256_after_boot": hashlib.sha256(image.read_bytes()).hexdigest(), "chromium_probe": chromium,
              "utc": shzlib.utc_now(), "git": shzlib.git_state()}
    shzlib.write_json(out / "result.json", record)
    for x in checks:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    print(f"  [INFO] image sha256 before boot {image_sha256}")
    if args.chromium:
        print(f"  [INFO] Chromium probe: {chromium.get('status')}")
        for k in ("chrome_dll_result", "chrome_dll_first_failure", "chrome_exe_result", "chrome_exe_first_failure"):
            if k in chromium:
                print(f"         {k}: {chromium[k]}")
    print(status)
    if status != "PASS":
        print("---- serial tail ----\n" + serial[-3000:])
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
