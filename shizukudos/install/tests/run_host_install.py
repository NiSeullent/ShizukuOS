#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host tests of the installer: the SHZSETUP core (win64/setup/*.c, the same sources SHZSETUP.EXE is built from) is
compiled for Linux with ASan/UBSan (install/tests/host_install.c supplies files, SHA-256 and disk images) and run
against disk image files. Each installed image is then checked by verify_disk.py with independent tools
(zlib/hashlib, mtools, fsck.fat, e2fsck, debugfs); util-linux partx/blkid also parse the result when present.
Also: the ShizukuFS writer alone on large volumes (sfsw_host.c), and refusal cases that must leave disks untouched.

Needs the payload: python3 shizukudos/install/mkpayload.py. Writes build/shizukudos/install/host-test/result.json.
"""
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHZ = HERE.parents[1]
sys.path.insert(0, str(SHZ / "tools"))
sys.path.insert(0, str(HERE))
import shzlib  # noqa: E402
from shzlib import BUILD  # noqa: E402
import verify_disk  # noqa: E402

INSTALL = BUILD / "install"
WORK = INSTALL / "host-test"
SETUP = SHZ / "win64" / "setup"
CORE = ["install.c", "sfsw.c", "gpt.c", "fat32fmt.c", "textparse.c"]
MIB = 1 << 20
rows = []


def row(name, ok, detail=""):
    rows.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": str(detail)[:800]})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}  {'' if ok else detail}", flush=True)
    return ok


def compile_tools():
    flags = ["-O1", "-g", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    host = WORK / "host_install"
    subprocess.run(["gcc", *flags, "-o", host, HERE / "host_install.c", *[SETUP / c for c in CORE]], check=True)
    sfsw = WORK / "sfsw_host"
    subprocess.run(["gcc", *flags, "-o", sfsw, HERE / "sfsw_host.c", SETUP / "sfsw.c"], check=True)
    return host, sfsw


def answer(path, **kv):
    sections = {"Setup": {"Schema": "1", "Confirm": "ERASE-TARGET", "Reboot": "shutdown"},
                "Target": {"Select": "first"}, "Layout": {}, "System": {"Hostname": "SHZHOST", "GuidSeed": "host-test"},
                "Drivers": {"Install": "all"}}
    for key, value in kv.items():
        sec, k = key.split("_", 1)
        if value is None:
            sections[sec].pop(k, None)
        else:
            sections[sec][k] = value
    text = "".join(f"[{s}]\n" + "".join(f"{k}={v}\n" for k, v in d.items()) for s, d in sections.items())
    path.write_text(text)
    return path


def blank(path, mib):
    path.unlink(missing_ok=True)
    with open(path, "wb") as f:
        f.truncate(mib * MIB)
    return path


def digest(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 22), b""):
            h.update(chunk)
    return h.hexdigest()


def install(host, ans, disks, payload=None):
    cmd = [str(host), "--answer", str(ans), "--payload", str(payload or INSTALL / "payload")]
    for d in disks:
        cmd += ["--disk", d]
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=1200)
    return p.returncode, p.stdout + p.stderr


def main():
    if not (INSTALL / "payload" / "manifest.json").exists():
        raise SystemExit("run shizukudos/install/mkpayload.py first")
    shutil.rmtree(WORK, ignore_errors=True)
    WORK.mkdir(parents=True)
    started = time.time()
    host, sfsw = compile_tools()

    # 1. full install: ESP + ShizukuFS + Win98 FAT32, selected by serial among two disks
    d1, d2 = blank(WORK / "disk-a.img", 512), blank(WORK / "disk-b.img", 600)
    before_b = digest(d2)
    rc, out = install(host, answer(WORK / "a1.ini", Target_Select="serial", Target_Serial="SERIAL-A", Layout_Win98MiB="64"),
                      [f"diskb={d2},SERIAL-B", f"diska={d1},SERIAL-A"])
    (WORK / "install-a.log").write_text(out)
    row("install (Select=serial, Win98MiB=64): SETUP-RESULT: OK, exit 0", rc == 0 and "SETUP-RESULT: OK" in out, out[-600:])
    row("the other disk is untouched", digest(d2) == before_b)
    rep = verify_disk.verify(d1, INSTALL, want_win98=True)
    for r in rep.rows:
        row("disk-a: " + r["check"], r["status"] == "PASS", r["detail"])
    if shutil.which("partx"):
        px = subprocess.run(["partx", "--show", "-o", "NR,START,END,NAME", str(d1)], capture_output=True, text=True)
        row("util-linux partx parses the GPT (3 partitions)", px.returncode == 0 and len(px.stdout.strip().splitlines()) == 4, px.stdout)
    if shutil.which("blkid"):
        types = []
        for p in rep.parts:
            b = subprocess.run(["blkid", "-p", "-o", "value", "-s", "TYPE", "-O", str(p["first"] * 512), str(d1)], capture_output=True, text=True)
            types.append(b.stdout.strip())
        row("util-linux blkid probes p1 vfat, p2 ext4, p3 vfat", types == ["vfat", "ext4", "vfat"], types)

    # 2. a disk with a partition table is refused without AllowNonEmpty and stays byte-identical
    before = digest(d1)
    rc, out = install(host, answer(WORK / "a2.ini"), [f"diska={d1},SERIAL-A"])
    row("non-empty disk refused without AllowNonEmpty (exit 1, disk unchanged)",
        rc == 1 and "already has a partition table" in out and digest(d1) == before, out[-300:])

    # 3. reinstall over it with AllowNonEmpty=yes, fixed SystemMiB, no drivers, by Select=size
    rc, out = install(host, answer(WORK / "a3.ini", Target_Select="size", Target_SizeMiB="512", Target_AllowNonEmpty="yes",
                                   Layout_SystemMiB="100", Drivers_Install="none", Layout_BiosBootCode="yes"),
                      [f"diskb={d2},SERIAL-B", f"diska={d1},SERIAL-A"])
    row("reinstall (Select=size, AllowNonEmpty=yes, SystemMiB=100, Drivers=none): OK", rc == 0 and "SETUP-RESULT: OK" in out, out[-600:])
    rep = verify_disk.verify(d1, INSTALL, want_win98=False, drivers="none")
    for r in rep.rows:
        row("disk-a reinstall: " + r["check"], r["status"] == "PASS", r["detail"])
    row("reinstall: p2 is 100 MiB", len(rep.parts) == 2 and (rep.parts[1]["last"] - rep.parts[1]["first"] + 1) * 512 == 100 * MIB,
        [(p["first"], p["last"]) for p in rep.parts])

    # 4. refusals that must not touch any disk
    d3 = blank(WORK / "disk-c.img", 512)
    cases = [
        ("Confirm missing", answer(WORK / "n1.ini", Setup_Confirm=None), "Confirm=ERASE-TARGET is required"),
        ("unknown selector", answer(WORK / "n2.ini", Target_Select="fastest"), "not a known selector"),
        ("no disk matches Serial", answer(WORK / "n3.ini", Target_Select="serial", Target_Serial="NOPE"), "no block device matches"),
        ("disk too small (Win98MiB=400 on 512 MiB)", answer(WORK / "n4.ini", Layout_Win98MiB="400"), "no block device matches"),
        ("bad hostname", answer(WORK / "n5.ini", System_Hostname="bad name!"), "Hostname="),
    ]
    for name, ans, expect in cases:
        before = digest(d3)
        rc, out = install(host, ans, [f"diskc={d3},SERIAL-C"])
        row(f"refused: {name} (exit 1, disk untouched)", rc == 1 and expect in out and digest(d3) == before, out[-300:])

    # 5. a corrupted payload is detected before the partition table is written
    bad = WORK / "payload-bad"
    shutil.copytree(INSTALL / "payload", bad)
    arc = bytearray((bad / "SYSTEM.ARC").read_bytes())
    arc[-100] ^= 0xFF                                      # inside the last file's data
    (bad / "SYSTEM.ARC").write_bytes(bytes(arc))
    blank(d3, 512)
    rc, out = install(host, answer(WORK / "n6.ini"), [f"diskc={d3},SERIAL-C"], payload=bad)
    with open(d3, "rb") as f:
        f.seek(512)
        no_gpt = f.read(8) != b"EFI PART"
    row("corrupted SYSTEM.ARC: FAIL on the manifest SHA-256, no partition table written",
        rc == 1 and "does not match its manifest sha256" in out and no_gpt, out[-300:])
    esp = bytearray((INSTALL / "payload" / "ESP.SIM").read_bytes())
    esp[-5] ^= 0x01
    (bad / "SYSTEM.ARC").write_bytes((INSTALL / "payload" / "SYSTEM.ARC").read_bytes())
    (bad / "ESP.SIM").write_bytes(bytes(esp))
    rc, out = install(host, answer(WORK / "n7.ini"), [f"diskc={d3},SERIAL-C"], payload=bad)
    row("corrupted ESP.SIM: FAIL on the ESP SHA-256", rc == 1 and "does not match the manifest" in out, out[-300:])

    # 6. the ShizukuFS writer alone on bigger volumes (multi-group, depth-1 extent tree), e2fsck -fn each
    tree = WORK / "tree"
    (tree / "big").mkdir(parents=True)
    (tree / "many").mkdir()
    (tree / "big" / "huge.bin").write_bytes(hashlib.sha256(b"x").digest() * (700 * MIB // 32 + 3))
    for i in range(700):
        (tree / "many" / f"entry_with_a_long_name_number_{i:04d}.txt").write_text(f"file {i}\n" * (i % 7))
    (tree / "empty.dat").write_bytes(b"")
    for size in (1300 * MIB, 1090519040):
        img = WORK / "sfsw.img"
        img.unlink(missing_ok=True)
        p = subprocess.run([str(sfsw), str(img), str(size), str(tree)], capture_output=True, text=True, timeout=1200)
        fsck = subprocess.run(["e2fsck", "-fn", str(img)], capture_output=True, text=True)
        row(f"sfsw: {size // MIB} MiB volume with a 700 MiB file and 700 entries in one directory: read-back + e2fsck -fn",
            p.returncode == 0 and "read-back OK" in p.stdout and fsck.returncode == 0,
            (p.stdout + p.stderr + fsck.stdout)[-400:])
        img.unlink()
    shutil.rmtree(tree)

    status = "PASS" if all(r["status"] == "PASS" for r in rows) else "FAIL"
    for img in WORK.glob("*.img"):
        img.unlink()
    shzlib.write_json(WORK / "result.json", {"status": status, "checks": rows, "seconds": round(time.time() - started, 1),
                                             "utc": shzlib.utc_now(), "git": shzlib.git_state()})
    print(f"{status}: {sum(r['status'] == 'PASS' for r in rows)}/{len(rows)} checks")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
