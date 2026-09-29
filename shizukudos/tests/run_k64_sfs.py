#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Boot standalone Kernel64 under QEMU with a ShizukuFS (ext4-format) partition on AHCI and verify it from the host.

Disk: a partitioned image built here (MBR by default, --gpt for a GUID partition table): partition 1 is a small FAT32
volume (so Kernel64's FAT32 code takes D: and ShizukuFS must get the *next* letter, E:), partition 2 (MBR type 0x83
/ GPT Linux file system data 0FC63DAF-8483-4772-8E79-3D69D8477DE4) an ext4 file system made by `mkfs.ext4 -d` from a
tree of known content (default ext4 features: 64bit, extents, flex_bg, metadata_csum, huge_file, dir_nlink,
extra_isize, journal). Kernel64 probes every partition from disk_init() (kernel64/sfs_mount.c), mounts it through
libsfs (shizukufs/v1/libsfs) and records it in the mount table (kernel64/vfs_mounts.c).

T_SFS_RW.EXE (win64/tests/t_sfs_rw.c) then reads and hashes every packed file through kernel32/ntdll and writes,
renames, deletes and flushes. Checks: every guest-reported size/CRC equals the host's; after QEMU exits the ext4
partition is cut out of the disk image and `e2fsck -fn` must find it clean (the kernel's NtFlushBuffersFile and
shutdown sync leave it cleanly unmounted: no needs_recovery), `debugfs` must read every guest-written file back with
exactly the expected bytes, and every deleted/renamed-away name must be gone. All run_k64_standalone.py checks must
still pass (same self-tests, same Win64 apps; T_DISK/T_LAZY skip on this disk).
"""
import argparse
import hashlib
import os
import re
import shutil
import struct
import subprocess
import sys
import time
import uuid
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import qemu  # noqa: E402
import shzlib  # noqa: E402
from shzlib import BUILD  # noqa: E402
import run_k64_standalone as base  # noqa: E402

K64S = BUILD / "kernel64s"
WIN64 = BUILD / "win64"
MIB = 1 << 20
FAT_START, FAT_MIB = 1 * MIB, 40
EXT_START, EXT_MIB = 64 * MIB, 192
LINUX_FS_GUID = "0FC63DAF-8483-4772-8E79-3D69D8477DE4"
MS_BASIC_DATA_GUID = "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"


def pattern(seed, n):
    out = bytearray()
    x = seed & 0xffffffff
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0xffffffff
        out += x.to_bytes(4, "little")
    return bytes(out[:n])


def crc(data):
    return zlib.crc32(data) & 0xffffffff


def guid_bytes(s):
    return uuid.UUID(s).bytes_le


def write_mbr(img, parts, disk_sectors):
    mbr = bytearray(512)
    for i, (start, size, typ) in enumerate(parts):
        e = 446 + 16 * i
        mbr[e + 4] = typ
        mbr[e + 1:e + 4] = b"\xfe\xff\xff"
        mbr[e + 5:e + 8] = b"\xfe\xff\xff"
        struct.pack_into("<II", mbr, e + 8, start // 512, size // 512)
    mbr[510], mbr[511] = 0x55, 0xaa
    with open(img, "r+b") as f:
        f.write(mbr)


def write_gpt(img, parts, disk_sectors):
    """Protective MBR + primary and backup GPT (128 entries of 128 bytes)."""
    write_mbr(img, [(512, (min(disk_sectors, 0x100000000) - 1) * 512, 0xee)], disk_sectors)
    entries = bytearray(128 * 128)
    for i, (start, size, guid) in enumerate(parts):
        e = 128 * i
        entries[e:e + 16] = guid_bytes(guid)
        entries[e + 16:e + 32] = uuid.uuid4().bytes_le
        struct.pack_into("<QQQ", entries, e + 32, start // 512, (start + size) // 512 - 1, 0)
        name = ("part%d" % (i + 1)).encode("utf-16-le")
        entries[e + 56:e + 56 + len(name)] = name
    ecrc = crc(bytes(entries))
    disk_guid = uuid.uuid4().bytes_le

    def header(my_lba, alt_lba, entries_lba):
        h = bytearray(92)
        h[0:8] = b"EFI PART"
        struct.pack_into("<IIIIQQQQ", h, 8, 0x00010000, 92, 0, 0, my_lba, alt_lba, 34, disk_sectors - 34)
        h[56:72] = disk_guid
        struct.pack_into("<QIII", h, 72, entries_lba, 128, 128, ecrc)
        struct.pack_into("<I", h, 16, crc(bytes(h)))
        return bytes(h) + bytes(512 - 92)

    with open(img, "r+b") as f:
        f.seek(512)
        f.write(header(1, disk_sectors - 1, 2))
        f.write(entries)
        f.seek((disk_sectors - 33) * 512)
        f.write(entries)
        f.write(header(disk_sectors - 1, 1, disk_sectors - 33))


def build_disk(out, gpt):
    src = out / "sfs-src"
    shutil.rmtree(src, ignore_errors=True)
    t = src / "SFSTEST"
    (t / "Sub Dir").mkdir(parents=True)
    files = {
        "README.TXT": b"ShizukuFS test volume for T_SFS_RW.EXE (tests/run_k64_sfs.py)\n",
        "hello.txt": b"hello from the ext4 side\n",
        "empty.txt": b"",
        "pattern_1m.bin": pattern(11, MIB + 17),
        "big_5m.bin": pattern(13, 5 * MIB + 13),
        "modify.bin": pattern(30, 20000),
        "trunc.bin": pattern(32, 100000),
        "delete_me.bin": pattern(33, 50000),
        "move_me.txt": b"this file is moved by the guest\n",
        "Sub Dir/nested file.txt": b"nested content on ShizukuFS\n",
    }
    for name, data in files.items():
        (t / name).write_bytes(data)
    with open(t / "sparse_host.bin", "wb") as f:           # 32 MiB, one data block at 16 MiB
        f.seek(16 * MIB)
        f.write(pattern(40, 4096))
        f.truncate(32 * MIB)
    files["sparse_host.bin"] = bytes(16 * MIB) + pattern(40, 4096) + bytes(16 * MIB - 4096)
    os.symlink("hello.txt", t / "a symlink")                # not shown in the NT name space
    (t / ("n" * 140)).write_bytes(b"long name\n")          # longer than FS_NAME_MAX-1: skipped (logged)
    ext = out / "ext4.part"
    ext.unlink(missing_ok=True)
    shzlib.run(["mkfs.ext4", "-q", "-F", "-L", "SHZSFS", "-d", str(src), str(ext), f"{EXT_MIB}M"], capture=True)
    fsck0 = subprocess.run(["e2fsck", "-fn", str(ext)], capture_output=True, text=True)
    fat = out / "fat.part"
    fat.unlink(missing_ok=True)
    with open(fat, "wb") as f:
        f.truncate(FAT_MIB * MIB)
    shzlib.run(["mkfs.vfat", "-F", "32", "-n", "SHZFAT", "--invariant", str(fat)], capture=True)
    img = out / "disk.img"
    img.unlink(missing_ok=True)
    total = EXT_START + EXT_MIB * MIB + MIB
    with open(img, "wb") as f:
        f.truncate(total)
    for part, start in ((fat, FAT_START), (ext, EXT_START)):
        shzlib.run(["dd", f"if={part}", f"of={img}", "bs=1M", f"seek={start // MIB}", "conv=notrunc,sparse", "status=none"])
    if gpt:
        write_gpt(img, [(FAT_START, FAT_MIB * MIB, MS_BASIC_DATA_GUID), (EXT_START, EXT_MIB * MIB, LINUX_FS_GUID)], total // 512)
    else:
        write_mbr(img, [(FAT_START, FAT_MIB * MIB, 0x0c), (EXT_START, EXT_MIB * MIB, 0x83)], total // 512)
    return img, files, fsck0


def expected_writes(files):
    mod = bytearray(files["modify.bin"])
    mod[5000:5100] = b"\xab" * 100
    mod += pattern(31, 5000)
    return {
        "OUT/Sub Dir/renamed small.txt": b"written by T_SFS_RW.EXE on ShizukuFS\r\n",
        "OUT/victim.txt": pattern(21, 300000),
        "OUT/big_3m.bin": pattern(22, 3 * MIB),
        "OUT/sparse.bin": bytes(10 * MIB) + pattern(23, 4000),
        "SFSTEST/modify.bin": bytes(mod),
        "SFSTEST/trunc.bin": files["trunc.bin"][:777],
        "OUT/moved from root.txt": files["move_me.txt"],
    }


GONE = ["SFSTEST/delete_me.bin", "SFSTEST/move_me.txt", "OUT/small.txt", "OUT/pattern_300k.bin",
        "OUT/temp_delete_on_close.tmp", "OUT/empty dir"]


def run_qemu(args, accel, image, serial_path):
    stub, kernel, initrd = K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"
    cmd = [args.qemu, "-machine", "pc", "-accel", accel, "-cpu", "max", "-m", args.memory, "-nodefaults", "-display", "none",
           "-kernel", str(stub), "-initrd", f"{kernel},{initrd}", "-serial", f"file:{serial_path}",
           "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04", "-no-reboot",
           "-device", "ahci,id=ahci0", "-drive", f"if=none,id=d0,file={image},format=raw",
           "-device", "ide-hd,drive=d0,bus=ahci0.0"]
    proc = subprocess.Popen([str(c) for c in cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    timed_out = False
    try:
        proc.wait(timeout=args.timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        timed_out = True
    qemu_out = (proc.stdout.read() if proc.stdout else b"").decode(errors="replace")
    serial = serial_path.read_text(errors="replace") if serial_path.exists() else ""
    return cmd, proc.returncode, timed_out, qemu_out, serial


def guest_checks(serial, files, gpt):
    c = []
    tag = r"^\[win64 T_SFS_RW\.EXE pid \d+\] "
    lines = [l for l in serial.splitlines() if "T_SFS_RW.EXE" in l]
    c.append(base.check("T_SFS_RW.EXE found the ShizukuFS volume (no SKIP)", any("SFS-DRIVE" in l for l in lines) and
                        not any("SKIP:" in l for l in lines), "; ".join(lines[:2])))
    m = re.search(r"^K64 sfs: ([D-Z]): = (\S+) \(mbr type ([0-9a-f]+)([^)]*)\), ShizukuFS/ext4 \"([^\"]*)\".*?, (read/write|read-only)", serial, re.M)
    c.append(base.check("Kernel64 mounted the ext4 partition as ShizukuFS read/write on the next letter after FAT32 (E:)",
                        bool(m) and m.group(1) == "E" and m.group(2).endswith("p2") and m.group(6) == "read/write" and m.group(5) == "SHZSFS",
                        m.group(0) if m else "no 'K64 sfs: X: = ...' line"))
    if gpt:
        c.append(base.check("partition recognised through the GPT (Linux file system data GUID)", bool(m) and "GPT Linux data" in m.group(4),
                            m.group(0) if m else ""))
    else:
        c.append(base.check("partition recognised through the MBR (type 0x83)", bool(m) and m.group(3) == "83", m.group(0) if m else ""))
    m2 = re.search(r"^K64 disk: D: = (\S+), FAT32", serial, re.M)
    c.append(base.check("FAT32 partition kept D:", bool(m2) and m2.group(1).endswith("p1"), m2.group(0) if m2 else "no FAT32 mount line"))
    sk = re.search(r"^K64 sfs: E: root holds (\d+) entries shown \((\d+) skipped\)", serial, re.M)
    c.append(base.check("root enumeration: SFSTEST and lost+found shown", bool(sk) and int(sk.group(1)) == 2, sk.group(0) if sk else ""))
    got_dir = {mm.group(1): (int(mm.group(2)), int(mm.group(3), 16)) for mm in re.finditer(tag + r"SFS-DIR (.+?) (\d+) ([0-9a-f]+)$", serial, re.M)}
    got_crc = {mm.group(1): (int(mm.group(2)), int(mm.group(3), 16)) for mm in re.finditer(tag + r"SFS-CRC (.+?) (\d+) ([0-9a-f]+)$", serial, re.M)}
    top = {k: v for k, v in files.items() if "/" not in k}
    want_dir = set(top) | {"Sub Dir"}
    c.append(base.check("SFSTEST listing: every packed regular file and directory, symlink and 140-byte name hidden",
                        set(got_dir) == want_dir, f"guest={sorted(got_dir)} host={sorted(want_dir)}"))
    bad = [f"{n}: guest {got_crc.get(n)} host {(len(d), crc(d))}" for n, d in top.items() if got_crc.get(n) != (len(d), crc(d))]
    c.append(base.check("every packed file: guest size and CRC-32 equal the host's (incl. a 32 MiB sparse file)", not bad, "; ".join(bad[:5])))
    mm = re.search(tag + r"SFS-NESTED (\d+) ([0-9a-f]+)$", serial, re.M)
    d = files["Sub Dir/nested file.txt"]
    c.append(base.check("nested file through 'Sub Dir'", bool(mm) and (int(mm.group(1)), int(mm.group(2), 16)) == (len(d), crc(d)),
                        mm.group(0) if mm else ""))
    mm = re.search(tag + r"SFS-RANGE 777777 (\d+) ([0-9a-f]+)$", serial, re.M)
    d = files["pattern_1m.bin"][777777:777777 + 3000]
    c.append(base.check("random-offset read", bool(mm) and (int(mm.group(1)), int(mm.group(2), 16)) == (len(d), crc(d)),
                        mm.group(0) if mm else ""))
    mm = re.search(tag + r"SFS-MANY (\d+)$", serial, re.M)
    c.append(base.check("300 files created, 100 deleted, 200 listed", bool(mm) and mm.group(1) == "200", mm.group(0) if mm else ""))
    exp = expected_writes(files)
    got_w = {mm.group(1).replace("\\", "/"): (int(mm.group(2)), int(mm.group(3), 16))
             for mm in re.finditer(tag + r"SFS-WRITE (.+?) (\d+) ([0-9a-f]+)$", serial, re.M)}
    bad = [f"{n}: guest {got_w.get(n)} host {(len(v), crc(v))}" for n, v in exp.items() if got_w.get(n) != (len(v), crc(v))]
    c.append(base.check("guest read-back of every written file matches the host's expectation", not bad, "; ".join(bad[:5])))
    fails = [l for l in lines if "FAIL" in l]
    c.append(base.check("T_SFS_RW.EXE reported no FAIL", not fails and any("t_sfs_rw:" in l and " 0 failed" in l for l in lines),
                        "; ".join(fails[:5])))
    mm = re.search(r"^K64 vfs: shutdown E: \(shizukufs on (\S+)\): rc (-?\d+)$", serial, re.M)
    c.append(base.check("normal exit synced the volume (vfs_shutdown rc 0)", bool(mm) and mm.group(2) == "0", mm.group(0) if mm else ""))
    return c


def host_checks(image, files, out):
    c = []
    part = out / "ext4.after"
    shzlib.run(["dd", f"if={image}", f"of={part}", "bs=1M", f"skip={EXT_START // MIB}", f"count={EXT_MIB}", "status=none"])
    p = subprocess.run(["e2fsck", "-fn", str(part)], capture_output=True, text=True)
    problems = [l for l in (p.stdout + p.stderr).splitlines()
                if l and not l.startswith(("e2fsck ", "Pass ", str(part) + ":", "SHZSFS:"))]
    (out / "e2fsck.txt").write_text(p.stdout + p.stderr)
    c.append(base.check("host: e2fsck -fn finds the ext4 partition clean after the guest's writes", p.returncode == 0 and not problems,
                        f"rc={p.returncode} {problems[:6]}"))
    h = subprocess.run(["dumpe2fs", "-h", str(part)], capture_output=True, text=True).stdout
    feats = re.search(r"^Filesystem features:\s+(.*)$", h, re.M)
    state = re.search(r"^Filesystem state:\s+(.*)$", h, re.M)
    c.append(base.check("host: volume left cleanly unmounted (no needs_recovery, state clean)",
                        feats and "needs_recovery" not in feats.group(1) and state and state.group(1).strip() == "clean",
                        f"{state.group(1) if state else '?'} / {feats.group(1) if feats else '?'}"))
    bad = []
    for rel, want in expected_writes(files).items():
        dst = out / "dump.bin"
        dst.unlink(missing_ok=True)
        subprocess.run(["debugfs", "-R", f'dump "/{rel}" {dst}', str(part)], capture_output=True, text=True)
        got = dst.read_bytes() if dst.exists() else None
        if got != want:
            bad.append(f"{rel}: {'missing' if got is None else f'{len(got)} bytes crc {crc(got):x}'} want {len(want)} crc {crc(want):x}")
    c.append(base.check("host: debugfs reads every guest-written file back with the expected bytes", not bad, "; ".join(bad[:5])))
    still = []
    for rel in GONE:
        r = subprocess.run(["debugfs", "-R", f'stat "/{rel}"', str(part)], capture_output=True, text=True)
        if "File not found" not in r.stderr + r.stdout:
            still.append(rel)
    c.append(base.check("host: deleted / renamed-away names are gone on disk", not still, ", ".join(still)))
    r = subprocess.run(["debugfs", "-R", "ls -p /OUT/many", str(part)], capture_output=True, text=True).stdout
    names = [l.split("/")[5] for l in r.splitlines() if l.startswith("/") and l.count("/") >= 6 and l.split("/")[5] not in (".", "..")]
    want = {"file_with_a_long_name_%03u.txt" % i for i in range(300) if i % 3}
    c.append(base.check("host: OUT/many holds exactly the 200 surviving files", set(names) == want, f"{len(names)} entries"))
    r = subprocess.run(["debugfs", "-R", "htree /OUT/many", str(part)], capture_output=True, text=True).stdout
    c.append(base.check("host: OUT/many is an indexed (htree) directory built in the guest", "Root node dump" in r, r[:120].replace("\n", " ")))
    unchanged = {k: v for k, v in files.items() if k in ("hello.txt", "pattern_1m.bin", "big_5m.bin", "README.TXT")}
    bad = []
    for name, data in unchanged.items():
        dst = out / "dump.bin"
        dst.unlink(missing_ok=True)
        subprocess.run(["debugfs", "-R", f'dump "/SFSTEST/{name}" {dst}', str(part)], capture_output=True, text=True)
        if not dst.exists() or dst.read_bytes() != data:
            bad.append(name)
    c.append(base.check("host: untouched files unchanged", not bad, ", ".join(bad)))
    return c


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--accel", choices=("auto", "kvm", "tcg"), default="auto")
    ap.add_argument("--timeout", type=int, default=900)
    ap.add_argument("--memory", default="512")
    ap.add_argument("--gpt", action="store_true", help="GUID partition table instead of MBR")
    ap.add_argument("--out", default=str(BUILD / "kernel64s" / "run_sfs"))
    args = ap.parse_args()
    for f in (K64S / "boot.elf", K64S / "KERNEL64S.BIN", WIN64 / "WIN64.IMG"):
        if not f.exists():
            raise SystemExit(f"missing {f}: run shizukudos/kbuild.py and shizukudos/win64/build.py first")
    for tool in ("mkfs.ext4", "e2fsck", "debugfs", "dumpe2fs", "mkfs.vfat"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    accel = ("kvm" if Path("/dev/kvm").exists() else "tcg") if args.accel == "auto" else args.accel
    out = Path(args.out) / ("gpt" if args.gpt else "mbr")
    out.mkdir(parents=True, exist_ok=True)
    serial_path = out / "serial.log"
    serial_path.unlink(missing_ok=True)
    image, files, fsck0 = build_disk(out, args.gpt)
    started = time.time()
    cmd, qemu_rc, timed_out, qemu_out, serial = run_qemu(args, accel, image, serial_path)
    ev, exit_code = base.parse(serial)
    checks = base.evaluate(serial, ev, exit_code, qemu_rc, memory=args.memory)
    checks.append(base.check("host: e2fsck -fn finds the freshly made ext4 partition clean (baseline)", fsck0.returncode == 0,
                             f"rc={fsck0.returncode}"))
    checks += guest_checks(serial, files, args.gpt)
    checks += host_checks(image, files, out)
    if timed_out:
        checks.insert(0, base.check("run finished before the timeout", False, f"{args.timeout}s, accel={accel}"))
    status = "PASS" if all(x["status"] == "PASS" for x in checks) else "FAIL"
    record = {"profile": "kernel64-standalone + AHCI disk: FAT32 p1 + ShizukuFS/ext4 p2 (%s)" % ("GPT" if args.gpt else "MBR"),
              "accel": accel, "status": status, "checks": checks, "seconds": round(time.time() - started, 1),
              "command": [str(c) for c in cmd], "qemu_output": qemu_out[-1500:],
              "sfs_lines": [l for l in serial.splitlines() if l.startswith(("K64 sfs", "K64 vfs")) or "T_SFS_RW" in l][:400],
              "utc": shzlib.utc_now(), "git": shzlib.git_state()}
    shzlib.write_json(out / "result.json", record)
    for x in checks:
        print(f"  [{x['status']}] {x['check']}  {x['detail']}")
    print(status)
    if status != "PASS":
        print("---- serial tail ----\n" + serial[-3000:])
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
