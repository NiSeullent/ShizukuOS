#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""ShizukuFS v1 performance run: optimised libsfs vs. the naive baseline on the same fresh ext4 image.

Makes a sparse ext4 image with mkfs.ext4 (default features, 4 KiB blocks), runs build/sfsperf (O2, no sanitizers)
once optimised and once with -N (SFS_MOUNT_NAIVE), each on a fresh copy, and checks both results with e2fsck -fn.
The image lives in the host page cache: the numbers measure the file system code and its I/O pattern (request
count, bytes, flushes), not a disk. -F adds fdatasync(2) to every flush.
Usage: run_perf.py [--size-mib 1024] [--files 100000] [--fsync]
"""
import os
import re
import subprocess
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
PERF = os.path.join(HERE, "..", "build", "sfsperf")


def arg(name, default):
    return sys.argv[sys.argv.index(name) + 1] if name in sys.argv else default


def main():
    size = int(arg("--size-mib", "1024"))
    files = int(arg("--files", "100000"))
    fsync = "--fsync" in sys.argv
    tmp = tempfile.mkdtemp(prefix="sfsperf-", dir=os.environ.get("SFS_TMP"))
    rc = 0
    try:
        base = os.path.join(tmp, "base.img")
        img_mib = size + files * 8 // 1024 + 1024
        subprocess.run(["mkfs.ext4", "-q", "-F", base, "%dM" % img_mib], check=True)
        for mode in (["-N"], []):
            img = os.path.join(tmp, "img")
            subprocess.run(["cp", "--sparse=always", base, img], check=True)
            cmd = [PERF] + mode + (["-F"] if fsync else []) + ["-s", str(size), "-n", str(files), img]
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print(p.stdout, end="")
            if p.returncode:
                print(p.stderr[-2000:])
                rc = 1
            f = subprocess.run(["e2fsck", "-fn", img], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            print("  e2fsck -fn after the run: rc %d, %s" % (f.returncode, (re.findall(r"\d+/\d+ files.*", f.stdout) or ["?"])[0]))
            if f.returncode:
                print(f.stdout[-1500:])
                rc = 1
            os.unlink(img)
            print()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return rc


if __name__ == "__main__":
    sys.exit(main())
