#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-side verification of a disk image written by SHZSETUP, independent of the installer's own checks.

Checks (each a PASS/FAIL row): protective MBR and its boot code (= payload GPTMBR.BIN), primary and backup GPT
(signature, header CRC32, entry-array CRC32, cross-references, identical entries), the partition entries (types,
alignment, legacy-BIOS-bootable ESP), p1 byte-identical to esp.img + fsck.fat + every ESP file via mtools, p2 e2fsck -fn +
every manifest file's SHA-256 through debugfs rdump + directories + generated files + install.log, optional p3 FAT32.
Tools used: Python (zlib.crc32, hashlib), mtools (mcopy), fsck.fat, e2fsck, debugfs. Nothing of the installer is reused.

  verify_disk.py DISK.IMG --payload build/shizukudos/install [--win98] [--json out.json]
"""
import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import uuid
import zlib
from pathlib import Path

ESP_TYPE = "c12a7328-f81f-11d2-ba4b-00a0c93ec93b"
LINUX_FS = "0fc63daf-8483-4772-8e79-3d69d8477de4"
MS_BASIC = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7"
SS = 512


class Report:
    def __init__(self):
        self.rows = []

    def check(self, name, ok, detail=""):
        self.rows.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": str(detail)[:600]})
        return ok

    def ok(self):
        return all(r["status"] == "PASS" for r in self.rows)


def guid(b):
    return str(uuid.UUID(bytes_le=bytes(b)))


def parse_header(sec):
    f = struct.unpack_from("<8sIII4xQQQQ16sQIII", sec, 0)
    names = ("sig", "rev", "hsize", "hcrc", "my", "alt", "first", "last", "disk", "array", "n", "esize", "acrc")
    return dict(zip(names, f))


def header_crc_ok(sec, hsize):
    raw = bytearray(sec[:hsize])
    raw[16:20] = b"\0\0\0\0"
    return zlib.crc32(bytes(raw)) & 0xffffffff


def read(f, lba, count):
    f.seek(lba * SS)
    return f.read(count * SS)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def extract(f, first, last, dest):
    with open(dest, "wb") as out:
        f.seek(first * SS)
        left = (last - first + 1) * SS
        while left:
            chunk = f.read(min(left, 1 << 22))
            out.write(chunk)
            left -= len(chunk)


def selected(package, drivers):
    """Mirror of the installer's [Drivers] Install= rule: base always; driver-<x> for all / listed names."""
    if package in (None, "base"):
        return True
    if not package.startswith("driver-") or drivers == "none":
        return False
    return drivers == "all" or package[7:] in [d.strip() for d in drivers.split(",")]


def verify(disk, payload_dir, want_win98=None, rep=None, drivers="all"):
    rep = rep or Report()
    payload_dir = Path(payload_dir)
    manifest = json.loads((payload_dir / "payload" / "manifest.json").read_text())
    sys_files = [e for e in manifest["system"]["files"] if selected(e.get("package"), drivers)]
    sys_dirs = [e for e in manifest["system"]["dirs"] if selected(e.get("package"), drivers)]
    unselected = [e["path"] for e in manifest["system"]["files"] + manifest["system"]["dirs"] if not selected(e.get("package"), drivers)]
    esp_img = (payload_dir / "esp.img").read_bytes()
    mbr_code = (payload_dir / "payload" / "GPTMBR.BIN").read_bytes()
    size = os.path.getsize(disk)
    sectors = size // SS
    work = Path(tempfile.mkdtemp(prefix="shzverify-"))
    parts = []
    try:
        with open(disk, "rb") as f:
            mbr = read(f, 0, 1)
            rep.check("MBR: 0x55AA signature", mbr[510:512] == b"\x55\xaa", mbr[510:512].hex())
            ee = [mbr[446 + 16 * i:462 + 16 * i] for i in range(4)]
            prot = [e for e in ee if e[4] == 0xEE]
            rep.check("MBR: protective 0xEE entry starting at LBA 1",
                      len(prot) == 1 and struct.unpack_from("<I", prot[0], 8)[0] == 1,
                      [e.hex() for e in ee if e[4]])
            rep.check("MBR: BIOS boot code = payload GPTMBR.BIN (440 bytes)", mbr[:440] == mbr_code,
                      f"sha256 {sha(mbr[:440])[:16]} vs {sha(mbr_code)[:16]}")
            prim = read(f, 1, 1)
            h = parse_header(prim)
            rep.check("GPT primary: 'EFI PART', revision 1.0, 92-byte header", h["sig"] == b"EFI PART" and h["rev"] == 0x10000 and h["hsize"] == 92)
            rep.check("GPT primary: header CRC32", header_crc_ok(prim, 92) == h["hcrc"], f"{h['hcrc']:#x}")
            arr = read(f, h["array"], (h["n"] * h["esize"] + SS - 1) // SS)[:h["n"] * h["esize"]]
            rep.check("GPT primary: entry array CRC32", zlib.crc32(arr) & 0xffffffff == h["acrc"], f"{h['acrc']:#x}")
            rep.check("GPT primary: my LBA 1, alternate = last LBA", h["my"] == 1 and h["alt"] == sectors - 1, (h["my"], h["alt"]))
            back = read(f, sectors - 1, 1)
            hb = parse_header(back)
            barr = read(f, hb["array"], (hb["n"] * hb["esize"] + SS - 1) // SS)[:hb["n"] * hb["esize"]]
            rep.check("GPT backup: header CRC32 and entry array CRC32",
                      hb["sig"] == b"EFI PART" and header_crc_ok(back, 92) == hb["hcrc"] and zlib.crc32(barr) & 0xffffffff == hb["acrc"])
            rep.check("GPT backup: my = last LBA, alternate = 1, array before it, same disk GUID and entries",
                      hb["my"] == sectors - 1 and hb["alt"] == 1 and hb["array"] + 32 == sectors - 1 and hb["disk"] == h["disk"]
                      and barr == arr)
            for i in range(h["n"]):
                e = arr[i * h["esize"]:(i + 1) * h["esize"]]
                if e[:16] == bytes(16):
                    continue
                first, last, attrs = struct.unpack_from("<QQQ", e, 32)
                name = e[56:128].decode("utf-16-le").rstrip("\0")
                parts.append({"type": guid(e[:16]), "guid": guid(e[16:32]), "first": first, "last": last, "attrs": attrs, "name": name})
            rep.check("GPT: partitions inside the usable range, 1 MiB aligned, not overlapping",
                      all(h["first"] <= p["first"] <= p["last"] <= h["last"] and p["first"] % 2048 == 0 for p in parts)
                      and all(a["last"] < b["first"] for a, b in zip(parts, parts[1:])),
                      [(p["first"], p["last"]) for p in parts])
            types = [p["type"] for p in parts]
            expect = [ESP_TYPE, LINUX_FS] + ([MS_BASIC] if want_win98 else [])
            rep.check("GPT: p1 ESP, p2 ShizukuFS (Linux filesystem data type)" + (", p3 basic data" if want_win98 else ""),
                      types == expect if want_win98 is not None else types[:2] == expect[:2], types)
            if not parts:
                return rep
            p1 = parts[0]
            rep.check("GPT: p1 has the legacy-BIOS-bootable attribute (bit 2)", bool(p1["attrs"] & 4), hex(p1["attrs"]))
            # ---- p1
            rep.check("p1 starts at the LBA recorded in esp.img's BPB (hidden sectors)",
                      p1["first"] == struct.unpack_from("<I", esp_img, 0x1C)[0] == manifest["esp"]["first_lba"], p1["first"])
            espf = work / "p1.img"
            extract(f, p1["first"], p1["last"], espf)
            data = espf.read_bytes()
            bm = manifest.get("boot_manifest")
            if bm:
                # SHZSETUP stamps install_generation [24,32) and install_id [72,88) of SHZBOOT.MAN in place on the target;
                # every other byte of p1 must equal esp.img, and the stamp must be a nonzero generation and id.
                off, go, io = bm["image_offset"], bm["stamp"]["generation_offset"], bm["stamp"]["install_id_offset"]
                stamped = bytearray(data)
                gen = int.from_bytes(data[off + go:off + go + 8], "little") if len(data) == len(esp_img) else 0
                inst = bytes(data[off + io:off + io + 16]) if len(data) == len(esp_img) else bytes(16)
                stamped[off + go:off + go + 8] = esp_img[off + go:off + go + 8]
                stamped[off + io:off + io + 16] = esp_img[off + io:off + io + 16]
                rep.check("p1 equals esp.img except the SHZBOOT.MAN stamp (generation, install_id)",
                          bytes(stamped) == esp_img and sha(bytes(stamped)) == manifest["esp"]["sha256"],
                          f"{len(data)} bytes")
                man = bytes(data[off:off + bm["bytes"]])
                rep.check("p1: SHZBOOT.MAN stamped (generation >= 1, install_id nonzero, entries_sha256 unchanged)",
                          gen >= 1 and any(inst) and sha(man[96:]) == bm["entries_sha256"] and man[40:72].hex() == bm["entries_sha256"],
                          f"generation {gen} install_id {inst.hex()}")
                rec = bytes(f_read(f, (p1["first"] - 1) * 512, 512))
                rep.check("install record SHZINSR1 carries the stamped generation and install_id",
                          rec[:8] == b"SHZINSR1" and int.from_bytes(rec[320:328], "little") == gen and rec[328:344] == inst,
                          rec[320:344].hex())
            else:
                rep.check("p1 is byte-identical to esp.img", data == esp_img and sha(data) == manifest["esp"]["sha256"],
                          f"{len(data)} bytes, sha256 {sha(data)[:16]}")
            fsck = subprocess.run(["fsck.fat", "-n", str(espf)], capture_output=True, text=True)
            rep.check("p1: fsck.fat -n", fsck.returncode == 0, (fsck.stdout + fsck.stderr).strip().splitlines()[-1:])
            env = dict(os.environ, MTOOLS_SKIP_CHECK="1")
            bad = []
            for ent in manifest["esp"]["files"]:
                if bm and ent["path"].upper() == bm["path"].upper():
                    continue                    # stamped on the target; checked above against the template
                dst = work / "esp-out"
                dst.unlink(missing_ok=True)
                r = subprocess.run(["mcopy", "-n", "-i", str(espf), f"::{ent['path']}", str(dst)], capture_output=True, env=env)
                if r.returncode or sha(dst.read_bytes()) != ent["sha256"]:
                    bad.append(ent["path"])
            rep.check(f"p1: all {len(manifest['esp']['files'])} ESP files read with mtools match the manifest SHA-256", not bad, bad)
            espf.unlink()
            # ---- p2
            if len(parts) > 1:
                p2 = parts[1]
                sysf = work / "p2.img"
                extract(f, p2["first"], p2["last"], sysf)
                e2 = subprocess.run(["e2fsck", "-fn", str(sysf)], capture_output=True, text=True)
                rep.check("p2: e2fsck -fn (ShizukuFS v1 = ext4 on-disk format) exit 0", e2.returncode == 0,
                          (e2.stdout + e2.stderr).strip().splitlines()[-1:])
                sb = sysf.open("rb").read(2048)[1024:]
                rep.check("p2: superblock magic 0xEF53, label " + manifest["system"]["label"],
                          sb[0x38:0x3a] == b"\x53\xef" and sb[0x78:0x88].rstrip(b"\0").decode() == manifest["system"]["label"])
                tree = work / "tree"
                tree.mkdir()
                dump = subprocess.run(["debugfs", "-R", f"rdump / {tree}", str(sysf)], capture_output=True, text=True)
                bad, missing = [], []
                for ent in sys_files:
                    p = tree / ent["path"].lstrip("/")
                    if not p.is_file():
                        missing.append(ent["path"])
                    elif sha(p.read_bytes()) != ent["sha256"] or p.stat().st_size != ent["bytes"]:
                        bad.append(ent["path"])
                n = len(sys_files)
                rep.check(f"p2: all {n} selected manifest files dumped with debugfs match their SHA-256", not bad and not missing,
                          {"mismatch": bad, "missing": missing, "debugfs_rc": dump.returncode})
                extra = [u for u in unselected if (tree / u.lstrip("/")).exists()]
                rep.check(f"p2: {len(unselected)} manifest entries of unselected driver packages are absent", not extra, extra)
                dirs_missing = [d["path"] for d in sys_dirs if not (tree / d["path"].lstrip("/")).is_dir()]
                rep.check("p2: every manifest directory exists (\\SHZ\\SYS64, \\SHZ\\DRIVERS, \\SHZ\\SETUP\\log, \\Users ...)",
                          not dirs_missing, dirs_missing)
                gen = {"SHZ/SYSTEM.INI": b"[System]", "SHZ/SETUP/shzsetup.ini": b"[Setup]", "SHZ/SETUP/manifest.json": None,
                       "SHZ/DRIVERS/CATALOG.INI": b"Schema=shizuku-driver-catalog/2"}
                gen_bad = [g for g, marker in gen.items() if not (tree / g).is_file() or (marker and marker not in (tree / g).read_bytes())]
                if (tree / "SHZ/SETUP/manifest.json").is_file() and (tree / "SHZ/SETUP/manifest.json").read_bytes() != \
                        (payload_dir / "payload" / "manifest.json").read_bytes():
                    gen_bad.append("manifest.json differs from the payload's")
                rep.check("p2: generated SYSTEM.INI, shzsetup.ini, manifest.json present", not gen_bad, gen_bad)
                log = tree / "SHZ/SETUP/log/install.log"
                text = log.read_text(errors="replace") if log.is_file() else ""
                rep.check("p2: \\SHZ\\SETUP\\log\\install.log ends with SETUP-RESULT: OK", text.rstrip().endswith("SETUP-RESULT: OK"),
                          text.strip().splitlines()[-1:] if text else "missing")
                sysf.unlink()
            # ---- p3
            if want_win98:
                if len(parts) > 2:
                    p3 = parts[2]
                    w98 = work / "p3.img"
                    extract(f, p3["first"], p3["last"], w98)
                    fsck = subprocess.run(["fsck.fat", "-n", str(w98)], capture_output=True, text=True)
                    bs = w98.open("rb").read(512)
                    rep.check("p3: empty FAT32 volume WIN98 passes fsck.fat -n, hidden sectors = partition start",
                              fsck.returncode == 0 and bs[0x52:0x5a] == b"FAT32   " and bs[0x47:0x52] == b"WIN98      "
                              and struct.unpack_from("<I", bs, 0x1c)[0] == p3["first"],
                              (fsck.stdout + fsck.stderr).strip().splitlines()[-1:])
                    listing = subprocess.run(["mdir", "-b", "-i", str(w98), "::/"], capture_output=True, text=True,
                                             env=dict(os.environ, MTOOLS_SKIP_CHECK="1"))
                    rep.check("p3: contains no files (Windows 98 is never bundled)", listing.stdout.strip() == "",
                              listing.stdout.strip()[:200])
                else:
                    rep.check("p3 present", False)
    finally:
        shutil.rmtree(work, ignore_errors=True)
    rep.parts = parts
    return rep


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("disk")
    ap.add_argument("--payload", required=True, help="build/shizukudos/install")
    ap.add_argument("--win98", action="store_true")
    ap.add_argument("--drivers", default="all", help="the answer file's [Drivers] Install= value")
    ap.add_argument("--json")
    a = ap.parse_args()
    rep = verify(a.disk, a.payload, a.win98, drivers=a.drivers)
    for r in rep.rows:
        print(f"  [{r['status']}] {r['check']}  {r['detail'] if r['status'] != 'PASS' else ''}")
    if a.json:
        Path(a.json).write_text(json.dumps(rep.rows, indent=1))
    print("PASS" if rep.ok() else "FAIL")
    return 0 if rep.ok() else 1


def f_read(f, offset, size):
    """Reads `size` bytes at `offset` of the open disk image `f` (install record check)."""
    pos = f.tell()
    f.seek(offset)
    out = f.read(size)
    f.seek(pos)
    return out

if __name__ == "__main__":
    sys.exit(main())
