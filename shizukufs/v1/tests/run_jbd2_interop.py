#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""jbd2 replay interoperability: journals written by e2fsprogs' own jbd2 code (debugfs journal_open/_write/_close)
are replayed by libsfs and by e2fsck, and the results must agree block for block.

Per variant (checksum v3 / v2 / none, 64bit and 32-bit volumes, 1 KiB and 4 KiB blocks) debugfs logs:
  T1  blocks A, B, C (C's data starts with the jbd2 magic, so the writer escapes it)
  T2  a revoke record for B (B must keep its pre-journal content)
  T3  block D
  T4  block E, written without a commit block (must not be replayed)
Then one copy is recovered with `e2fsck -fy`, another by mounting it read-write with libsfs (sfstool), and blocks
A..E must be identical in both and equal to the expected bytes; `e2fsck -fn` must pass on the libsfs-recovered copy.
"""
import os
import subprocess
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "build", "sfstool")
MAGIC = bytes.fromhex("c03b3998")

VARIANTS = [
    ("csum-v3-64bit-4k", ["-O", "64bit"], ["-c"], 4096),
    ("csum-v2-64bit-4k", ["-O", "64bit"], ["-c", "-v", "2"], 4096),
    ("no-csum-64bit-4k", ["-O", "64bit,^metadata_csum"], [], 4096),
    ("csum-v3-32bit-4k", ["-O", "^64bit"], ["-c"], 4096),
    ("no-csum-32bit-1k", ["-O", "^64bit,^metadata_csum", "-b", "1024"], [], 1024),
]


def blocks(img, bs, nums):
    out = {}
    with open(img, "rb") as f:
        for n in nums:
            f.seek(n * bs)
            out[n] = f.read(bs)
    return out


def main():
    tmp = tempfile.mkdtemp(prefix="sfsjbd2-", dir=os.environ.get("SFS_TMP"))
    fails = 0
    try:
        for name, mkfs_opts, jo_opts, bs in VARIANTS:
            img = os.path.join(tmp, "img")
            subprocess.run(["mkfs.ext4", "-q", "-F"] + mkfs_opts + [img, "64M"], check=True, capture_output=True)
            nblocks = (64 << 20) // bs
            A, B, C, D, E = nblocks - 40, nblocks - 39, nblocks - 38, nblocks - 30, nblocks - 20
            orig = blocks(img, bs, [A, B, C, D, E])
            d1 = os.path.join(tmp, "d1")
            payload = bytes([0x11]) * bs + bytes([0x22]) * bs + MAGIC + bytes([0x33]) * (bs - 4)
            open(d1, "wb").write(payload)
            d2 = os.path.join(tmp, "d2")
            open(d2, "wb").write(bytes([0x44]) * bs)
            d3 = os.path.join(tmp, "d3")
            open(d3, "wb").write(bytes([0x55]) * bs)
            cmds = "\n".join(["jo " + " ".join(jo_opts), "jw -b %d,%d,%d %s" % (A, B, C, d1), "jw -r %d" % B,
                              "jw -b %d %s" % (D, d2), "jw -b %d -c %s" % (E, d3), "jc", ""])
            cf = os.path.join(tmp, "cmds")
            open(cf, "w").write(cmds)
            p = subprocess.run(["debugfs", "-w", "-f", cf, img], capture_output=True, text=True)
            log = subprocess.run(["debugfs", "-R", "logdump", img], capture_output=True, text=True).stdout
            feats = [l for l in subprocess.run(["dumpe2fs", "-h", img], capture_output=True, text=True).stdout.splitlines()
                     if l.startswith("Journal features")]
            a = img + ".e2fsck"
            b = img + ".libsfs"
            shutil.copyfile(img, a)
            shutil.copyfile(img, b)
            r1 = subprocess.run(["e2fsck", "-fy", a], capture_output=True, text=True)
            r2 = subprocess.run([TOOL, b, "stats"], capture_output=True, text=True)
            r3 = subprocess.run(["e2fsck", "-fn", b], capture_output=True, text=True)
            ga, gb = blocks(a, bs, [A, B, C, D, E]), blocks(b, bs, [A, B, C, D, E])
            want = {A: payload[:bs], B: orig[B], C: payload[2 * bs:], D: bytes([0x44]) * bs, E: orig[E]}
            errs = []
            for k, lbl in ((A, "A"), (B, "B revoked"), (C, "C escaped"), (D, "D"), (E, "E uncommitted")):
                if ga[k] != want[k]:
                    errs.append("e2fsck result differs from expectation at %s" % lbl)
                if gb[k] != want[k]:
                    errs.append("libsfs result differs from expectation at %s" % lbl)
            if r2.returncode != 0:
                errs.append("libsfs mount/replay failed: " + r2.stderr[-400:])
            if r3.returncode != 0:
                errs.append("e2fsck -fn after libsfs replay rc %d: %s" % (r3.returncode, r3.stdout[-400:]))
            replayed = [l for l in r2.stdout.splitlines() if l.startswith("extent_cache_hits")]
            ok = not errs
            fails += not ok
            print("%-18s %s  %s; debugfs logged %d transactions; libsfs: %s" % (
                name, "PASS" if ok else "FAIL", feats[0].split(":", 1)[1].strip() if feats else "?",
                log.count("type 2 (commit block)"), replayed[0].split("replayed_tx")[1].strip() if replayed else r2.stderr[-200:]))
            for e in errs:
                print("    " + e)
            if p.returncode:
                print("    debugfs: " + p.stderr[-300:])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("jbd2 interop: %s" % ("PASS" if not fails else "FAIL (%d)" % fails))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
