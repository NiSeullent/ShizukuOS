#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Corrupted-metadata fuzzing of libsfs (build/sfsfuzz, ASan/UBSan) on two pristine volumes:

  clean    mkfs.ext4 -d of a small tree (htree directory, 2 MB file, symlinks) plus a libsfs-written fragmented
           file with a depth-1 extent tree -- exercises mount, walk, read and update paths;
  crashed  a volume whose writer crashed mid-workload (sfstool -K), so the journal needs replay -- exercises the
           jbd2 recovery path with corrupted descriptor/commit/revoke/data blocks.
The metadata block list comes from `e2image -r` (every block e2fsprogs considers metadata, journal included).
Each iteration corrupts 1-3 of those blocks and must end without a crash, sanitizer report, leak or hang.
Usage: run_fuzz.py [--iterations N] [--seed S]
"""
import os
import subprocess
import sys
import tempfile
import shutil

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "build", "sfstool")
FUZZ = os.path.join(HERE, "..", "build", "sfsfuzz")


def meta_blocks(img, out, bs=4096):
    raw = img + ".e2i"
    subprocess.run(["e2image", "-r", img, raw], check=True, capture_output=True)
    n = 0
    with open(raw, "rb") as f, open(out, "w") as o:
        i = 0
        while True:
            b = f.read(bs)
            if not b:
                break
            if any(b):
                o.write("%d\n" % i)
                n += 1
            i += 1
    os.unlink(raw)
    return n


def main():
    iters = int(sys.argv[sys.argv.index("--iterations") + 1]) if "--iterations" in sys.argv else 1500
    seed = int(sys.argv[sys.argv.index("--seed") + 1]) if "--seed" in sys.argv else 1
    tmp = tempfile.mkdtemp(prefix="sfsfuzz-", dir=os.environ.get("SFS_TMP"))
    rc = 0
    try:
        src = os.path.join(tmp, "src")
        os.makedirs(os.path.join(src, "a", "b"))
        os.makedirs(os.path.join(src, "big"))
        for i in range(300):
            open(os.path.join(src, "big", "file_%d" % i), "w").write("f%d\n" % i)
        open(os.path.join(src, "a", "b", "blob"), "wb").write(os.urandom(2000000))
        os.symlink("a/b/blob", os.path.join(src, "ln"))
        os.symlink("/q" * 40, os.path.join(src, "slow"))
        clean = os.path.join(tmp, "clean.img")
        subprocess.run(["mkfs.ext4", "-q", "-F", "-d", src, clean, "16M"], check=True, capture_output=True)
        batch = "".join("pattern /a/frag %d 100 %d\n" % (i * 20000, i) for i in range(4, 400))
        subprocess.run([TOOL, "-q", clean, "batch"], input=batch, text=True, check=True, capture_output=True)
        crashed = os.path.join(tmp, "crashed.img")
        subprocess.run(["mkfs.ext4", "-q", "-F", crashed, "64M"], check=True, capture_output=True)
        subprocess.run([TOOL, "-q", "-K", "2500", crashed, "crashload", os.path.join(tmp, "log"), "5", "0"], capture_output=True)
        for name, img in (("clean", clean), ("crashed", crashed)):
            lst = img + ".meta"
            n = meta_blocks(img, lst)
            p = subprocess.run([FUZZ, img, lst, str(iters), str(seed)], capture_output=True, text=True)
            last = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
            print("%-8s %s (%d metadata blocks): %s" % (name, "PASS" if p.returncode == 0 else "FAIL", n, last))
            if p.returncode != 0:
                print(p.stderr[-3000:])
                rc = 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("fuzz: %s" % ("PASS" if not rc else "FAIL"))
    return rc


if __name__ == "__main__":
    sys.exit(main())
