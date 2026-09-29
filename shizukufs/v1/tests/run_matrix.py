#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""ShizukuFS v1 bidirectional compatibility matrix against e2fsprogs.

For every feature set:
  1. Linux format -> ShizukuFS: a host tree (small/large/sparse >4 GiB/empty files, 255-byte and UTF-8 names,
     fast and slow symlinks, deep nesting, a directory big enough for an htree, post-2038 timestamps) is put
     into an image with `mkfs.ext4 -d`; libsfs (ASan/UBSan build) lists every entry and hashes every file; the
     result must equal the host tree (type, mode, size, SHA-256 / link target, mtime when inodes are large).
  2. ShizukuFS -> Linux format: libsfs applies a scripted mix of creates, overwrites, appends, sparse writes past
     4 GiB, truncates (shrink/extend), renames (in/between directories, over files, directories), unlinks, rmdirs,
     symlinks and a 6000-entry directory (htree growth, splits, deletions) to the image and to a host mirror;
     `e2fsck -fn` must report a clean volume (exit 0, no problem lines), `debugfs rdump` (e2fsprogs' own reader)
     must reproduce the mirror byte for byte, libsfs must read back the mirror, and debugfs must show the
     post-2038 timestamp written through libsfs.
  3. A second libsfs session deletes most of it again (tree release, htree shrink, block/inode frees) and e2fsck
     must stay clean.
Usage: run_matrix.py [--keep] [--only NAME]
"""
import hashlib
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "..", "build", "sfstool")

CONFIGS = [
    # name, mkfs options, image size, big sparse file (bytes), large inodes
    ("ext4-default", [], "96M", 5 << 30, True),
    ("1k-blocks", ["-b", "1024"], "64M", 5 << 30, True),
    ("2k-blocks", ["-b", "2048"], "64M", 0, True),
    ("no-metadata_csum", ["-O", "^metadata_csum"], "96M", 0, True),
    ("no-64bit", ["-O", "^64bit"], "96M", 0, True),
    ("64bit-huge_file", ["-O", "64bit,huge_file,^flex_bg"], "300M", 5 << 30, True),
    ("T-small-128b-inodes", ["-T", "small", "-I", "128"], "64M", 0, False),
    ("no-journal", ["-O", "^has_journal"], "96M", 0, True),
    ("no-dir_index", ["-O", "^dir_index"], "96M", 0, True),
    ("meta_bg", ["-O", "meta_bg,^resize_inode", "-b", "1024"], "64M", 0, True),
    ("multi-group-4k", ["-g", "8192"], "400M", 0, True),
]

# Read-only configurations: libsfs reads every file; writes must be refused (EROFS) and the image stay untouched.
RO_CONFIGS = [
    ("ext3-blockmap", ["-t", "ext3"], "96M", 5 << 30, True),
    ("ext2-blockmap", ["-t", "ext2"], "96M", 0, True),
    ("inline_data", ["-O", "inline_data"], "96M", 0, True),
]


def run(cmd, check=True, **kw):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kw)
    if check and p.returncode != 0:
        raise RuntimeError("%s failed (%d):\n%s\n%s" % (" ".join(cmd), p.returncode, p.stdout[-4000:], p.stderr[-4000:]))
    return p


ZERO = bytes(4096)


def sha(path):
    """Same fingerprint as sfstool: SHA-256 over (le64 offset || block) for each non-zero 4 KiB block, then le64
    size; data regions found with SEEK_DATA/SEEK_HOLE so multi-GiB sparse files cost nothing."""
    h = hashlib.sha256()
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        fd = f.fileno()
        pos = 0
        while pos < size:
            try:
                data = os.lseek(fd, pos, os.SEEK_DATA)
            except OSError:
                break
            try:
                hole = os.lseek(fd, data, os.SEEK_HOLE)
            except OSError:
                hole = size
            start = max(data - data % 4096, pos)
            f.seek(start)
            off = start
            while off < hole:
                blk = f.read(min(4096, size - off))
                if not blk:
                    break
                if blk != ZERO[: len(blk)]:
                    h.update(off.to_bytes(8, "little"))
                    h.update(blk)
                off += len(blk)
            pos = max(off, hole)
    h.update(size.to_bytes(8, "little"))
    return h.hexdigest()


def host_tree(root, times):
    out = {}
    for dp, dns, fns in os.walk(root, followlinks=False):
        for n in dns + fns:
            p = os.path.join(dp, n)
            rel = "/" + os.path.relpath(p, root)
            st = os.lstat(p)
            mode = "%04o" % (st.st_mode & 0o7777)
            if os.path.islink(p):
                t = os.readlink(p)
                out[rel] = ("l", mode, str(len(t.encode())), t)
            elif os.path.isdir(p):
                if n == "lost+found":
                    continue
                out[rel] = ("d", mode, "0", "-")
            else:
                v = sha(p)
                if times:
                    v += " @%d" % int(st.st_mtime)
                out[rel] = ("f", mode, str(st.st_size), v)
    return out


def sfs_tree(img, times, extra=()):
    cmd = [TOOL, "-q", "-r"] + (["-T"] if times else []) + list(extra) + [img, "tree"]
    p = run(cmd)
    out = {}
    for line in p.stdout.splitlines():
        parts = line.split(" ")
        kind, mode, size, links = parts[0], parts[1], parts[2], parts[3]
        if kind == "f" and times:
            val, path = parts[4] + " " + parts[5], " ".join(parts[6:])
        elif kind == "l":
            # target may contain spaces: size tells its length
            rest = " ".join(parts[4:])
            val, path = rest[: int(size)], rest[int(size) + 1:]
        else:
            val, path = parts[4], " ".join(parts[5:])
        if path == "/lost+found":
            continue
        out[path] = (kind, mode, size, val)
    return out


def compare(a, b, what):
    errs = []
    for k in sorted(set(a) | set(b)):
        if a.get(k) != b.get(k):
            errs.append("%s: %s: expected %s got %s" % (what, k, a.get(k), b.get(k)))
    return errs


def e2fsck_clean(img):
    p = run(["e2fsck", "-fn", img], check=False)
    lines = [l for l in p.stdout.splitlines() + p.stderr.splitlines()
             if l and not l.startswith(("e2fsck ", "Pass ", img + ":", os.path.basename(img) + ":"))]
    return p.returncode, lines, p.stdout


def rand_bytes(rng, n):
    return rng.randbytes(n) if hasattr(rng, "randbytes") else bytes(rng.getrandbits(8) for _ in range(n))


def build_source(src, rng, big_sparse, bs_small):
    os.makedirs(src)
    os.makedirs(os.path.join(src, "docs", "deep", "er", "still", "deeper"))
    with open(os.path.join(src, "docs", "hello.txt"), "w") as f:
        f.write("hello from the Linux side\n")
    with open(os.path.join(src, "empty"), "w"):
        pass
    for i, size in enumerate([1, 1023, 1024, 4095, 4096, 4097, 65536, 300001, 3 * 1024 * 1024 + 7]):
        with open(os.path.join(src, "docs", "deep", "blob%d.bin" % i), "wb") as f:
            f.write(rand_bytes(rng, size))
    with open(os.path.join(src, "docs", "deep", "er", "still", "deeper", "leaf.txt"), "w") as f:
        f.write("leaf\n" * 1000)
    long_name = "L" * 255
    with open(os.path.join(src, long_name), "w") as f:
        f.write("255-byte name\n")
    with open(os.path.join(src, "ユニコード-名前.txt"), "w", encoding="utf-8") as f:
        f.write("utf-8 name\n")
    os.symlink("docs/hello.txt", os.path.join(src, "fastlink"))
    os.symlink("/" + "/".join(["segment%02d" % i for i in range(12)]), os.path.join(src, "slowlink"))
    os.makedirs(os.path.join(src, "many"))
    for i in range(1500):
        with open(os.path.join(src, "many", "entry-%05d-%s" % (i, "x" * (i % 40))), "w") as f:
            f.write("%d\n" % i)
    if big_sparse:
        p = os.path.join(src, "sparse-big.img")
        with open(p, "wb") as f:
            f.seek(4096 * 3)
            f.write(b"head" * 1024)
            f.seek(big_sparse - 8192)
            f.write(b"tail" * 2048)
    # a post-2038 mtime (needs the extra epoch bits)
    future = os.path.join(src, "docs", "future.txt")
    with open(future, "w") as f:
        f.write("from the future\n")
    os.utime(future, (4102444800, 4102444800))   # 2100-01-01
    os.chmod(os.path.join(src, "docs", "hello.txt"), 0o640)


class Mirror:
    """Applies each operation to the host mirror and records the sfstool batch line."""

    def __init__(self, root, tmp, rng):
        self.root, self.tmp, self.rng, self.lines, self.n = root, tmp, rng, [], 0

    def hp(self, p):
        return os.path.join(self.root, p.lstrip("/"))

    def blob(self, data):
        self.n += 1
        p = os.path.join(self.tmp, "blob%06d" % self.n)
        with open(p, "wb") as f:
            f.write(data)
        return p

    def putat(self, path, off, data):
        b = self.blob(data)
        self.lines.append("putat %s %s %d" % (b, path, off))
        hp = self.hp(path)
        if not os.path.exists(hp):
            open(hp, "wb").close()
            os.chmod(hp, 0o644)
        with open(hp, "r+b") as f:
            f.seek(off)
            f.write(data)

    def mkdir(self, path):
        self.lines.append("mkdir " + path)
        os.mkdir(self.hp(path))
        os.chmod(self.hp(path), 0o755)

    def rm(self, path):
        self.lines.append("rm " + path)
        os.unlink(self.hp(path))

    def rmdir(self, path):
        self.lines.append("rmdir " + path)
        os.rmdir(self.hp(path))

    def mv(self, a, b):
        self.lines.append("mv %s %s" % (a, b))
        os.replace(self.hp(a), self.hp(b))

    def truncate(self, path, size):
        self.lines.append("truncate %s %d" % (path, size))
        os.truncate(self.hp(path), size)

    def symlink(self, target, path):
        self.lines.append("symlink %s %s" % (target, path))
        os.symlink(target, self.hp(path))

    def settime(self, path, t):
        self.lines.append("settime %s %d" % (path, t))
        os.utime(self.hp(path), (t, t))


def mutations(m, rng, big_sparse, bs):
    m.mkdir("/w")
    m.mkdir("/w/a")
    m.mkdir("/w/a/b")
    for i in range(40):
        m.putat("/w/a/small%02d" % i, 0, rand_bytes(rng, rng.choice([0, 1, 100, 4096, 5000, 12345])))
    m.putat("/w/large.bin", 0, rand_bytes(rng, 7 * 1024 * 1024 + 123))
    m.putat("/w/large.bin", 1000, rand_bytes(rng, 10000))            # overwrite, partial blocks
    m.putat("/w/large.bin", 7 * 1024 * 1024 + 123, rand_bytes(rng, 99999))   # append
    m.putat("/docs/deep/blob6.bin", 777, rand_bytes(rng, 3000))      # modify a Linux-created file
    m.putat("/docs/deep/blob8.bin", 3 * 1024 * 1024 + 7, rand_bytes(rng, 5000))  # append to Linux-created
    m.truncate("/docs/deep/blob7.bin", 1000)                          # shrink Linux-created
    m.truncate("/w/a/small03", 200000)                                # extend (sparse)
    m.truncate("/w/large.bin", 3 * 1024 * 1024 + 5)                   # shrink ours
    m.putat("/w/sparse4g", (4 << 30) + 12345, rand_bytes(rng, 70000))  # data beyond 4 GiB
    m.putat("/w/sparse4g", 5, b"start")
    m.mv("/w/a/small01", "/w/a/b/moved01")
    m.mv("/w/a/small02", "/w/a/small04")                              # over an existing file
    m.mv("/w/a/b", "/w/b-moved")                                      # directory to another parent
    m.mv("/docs/hello.txt", "/w/hello-moved.txt")                     # Linux file into our directory
    m.rm("/docs/deep/blob5.bin")                                      # free Linux-allocated extents
    m.rm("/docs/deep/blob8.bin")
    m.rm("/docs/deep/er/still/deeper/leaf.txt")
    m.rmdir("/docs/deep/er/still/deeper")
    m.symlink("../../docs", "/w/fast")
    m.symlink("/" + "z" * 150, "/w/slow")
    m.settime("/w/a/small05", 4133980800)                             # 2101-01-01, needs extra epoch
    m.mkdir("/w/huge")
    names = ["n%05d_%s" % (i, "q" * (i % 50)) for i in range(6000)]
    for i, n in enumerate(names):
        m.putat("/w/huge/" + n, 0, (b"%d\n" % i) * (i % 3))
    for i in range(0, 6000, 2):
        m.rm("/w/huge/" + names[i])
    for i in range(1, 6000, 10):
        m.mv("/w/huge/" + names[i], "/w/huge/R" + names[i])
    for i in range(0, 600):
        m.putat("/w/huge/again%04d" % i, 0, b"x" * (i % 7))
    for i in range(0, 1500, 3):
        m.rm("/many/entry-%05d-%s" % (i, "x" * (i % 40)))
    if big_sparse:
        m.putat("/sparse-big.img", big_sparse - 100000, rand_bytes(rng, 5000))
        m.truncate("/sparse-big.img", big_sparse - 50000)


def teardown(m):
    for dp, dns, fns in os.walk(m.hp("/w/huge"), topdown=False):
        for n in fns:
            m.rm("/w/huge/" + n)
    m.rmdir("/w/huge")
    m.rm("/w/large.bin")
    m.rm("/w/sparse4g")
    for n in sorted(os.listdir(m.hp("/many")))[::2]:
        m.rm("/many/" + n)


def debugfs_compare(img, mirror_root, tmp):
    out = os.path.join(tmp, "rdump")
    os.makedirs(out)
    # debugfs cannot skip one file in rdump; big sparse files are compared through stat instead
    p = run(["debugfs", "-R", "rdump / %s" % out, img], check=False)
    if p.returncode != 0:
        return ["debugfs rdump failed: " + p.stderr[-500:]]
    errs = []
    a = host_tree(mirror_root, False)
    b = host_tree(out, False)
    errs += compare(a, b, "debugfs-rdump")
    shutil.rmtree(out, ignore_errors=True)
    return errs


def debugfs_mtime(img, path):
    p = run(["debugfs", "-R", "stat %s" % path, img], check=False)
    for line in p.stdout.splitlines():
        if line.strip().startswith("mtime:"):
            return line.strip()
    return ""


def one_config(name, opts, size, big_sparse, large_inodes, keep):
    rng = random.Random(hash(name) & 0xFFFFFFFF)
    tmp = tempfile.mkdtemp(prefix="sfsmx-%s-" % name, dir=os.environ.get("SFS_TMP"))
    res = {"name": name, "errors": []}
    try:
        src = os.path.join(tmp, "src")
        build_source(src, rng, big_sparse, 1024)
        img = os.path.join(tmp, "img")
        run(["mkfs.ext4", "-q", "-F", "-d", src] + opts + [img, size])
        if large_inodes:
            # mke2fs -d (1.47.0) stores 32-bit times only; debugfs sets the post-2038 mtime with the epoch bits
            run(["debugfs", "-w", "-R", "sif /docs/future.txt mtime 21000101000000", img])
        # 1. Linux -> ShizukuFS
        t0 = time.time()
        exp = host_tree(src, large_inodes)
        got = sfs_tree(img, large_inodes)
        res["errors"] += compare(exp, got, "read")
        res["read_entries"] = len(got)
        res["read_s"] = round(time.time() - t0, 1)
        # 2. ShizukuFS -> Linux
        mirror = os.path.join(tmp, "mirror")
        run(["cp", "-a", "--sparse=always", src, mirror])
        m = Mirror(mirror, tmp, rng)
        mutations(m, rng, big_sparse, 1024)
        m.lines = [l for l in m.lines if l]
        batch = "\n".join(m.lines) + "\n"
        p = subprocess.run([TOOL, "-q", img, "batch"], input=batch, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode != 0:
            res["errors"].append("write batch failed: " + p.stderr[-2000:])
            return res
        res["ops"] = len(m.lines)
        rc, lines, full = e2fsck_clean(img)
        res["e2fsck_after_write"] = rc
        if rc != 0 or lines:
            res["errors"].append("e2fsck after writes rc=%d:\n%s" % (rc, "\n".join(lines[:40])))
        exp = host_tree(mirror, False)
        got = sfs_tree(img, False)
        res["errors"] += compare(exp, got, "readback")
        if not big_sparse:
            res["errors"] += debugfs_compare(img, mirror, tmp)
            res["debugfs_rdump"] = "compared"
        else:
            # debugfs stat for the >4 GiB files: sizes must agree
            for path in ("/w/sparse4g", "/sparse-big.img"):
                p = run(["debugfs", "-R", "stat %s" % path, img], check=False)
                want = os.path.getsize(m.hp(path))
                if ("Size: %d" % want) not in p.stdout:
                    res["errors"].append("debugfs size mismatch for %s (want %d)" % (path, want))
            # rdump everything else through a copy with the big files removed by libsfs
            img2 = img + ".nobig"
            run(["cp", "--sparse=always", img, img2])
            run([TOOL, "-q", img2, "rm", "/w/sparse4g"])
            run([TOOL, "-q", img2, "rm", "/sparse-big.img"])
            mirror2 = mirror + ".nobig"
            run(["cp", "-a", "--sparse=always", mirror, mirror2])
            os.unlink(os.path.join(mirror2, "w", "sparse4g"))
            os.unlink(os.path.join(mirror2, "sparse-big.img"))
            rc2, lines2, _ = e2fsck_clean(img2)
            if rc2 != 0 or lines2:
                res["errors"].append("e2fsck after deleting >4GiB files rc=%d: %s" % (rc2, lines2[:10]))
            res["errors"] += debugfs_compare(img2, mirror2, tmp)
            res["debugfs_rdump"] = "compared (>4 GiB files via stat)"
            os.unlink(img2)
            shutil.rmtree(mirror2, ignore_errors=True)
        if large_inodes:
            s = debugfs_mtime(img, "/w/a/small05")
            res["debugfs_mtime_2101"] = s
            if "2101" not in s:
                res["errors"].append("debugfs does not show the 2101 mtime: %r" % s)
        # 3. tear down in a second session
        m.lines = []
        teardown(m)
        p = subprocess.run([TOOL, "-q", img, "batch"], input="\n".join(m.lines) + "\n", text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if p.returncode != 0:
            res["errors"].append("teardown batch failed: " + p.stderr[-2000:])
            return res
        rc, lines, _ = e2fsck_clean(img)
        res["e2fsck_after_teardown"] = rc
        if rc != 0 or lines:
            res["errors"].append("e2fsck after teardown rc=%d:\n%s" % (rc, "\n".join(lines[:40])))
        res["errors"] += compare(host_tree(mirror, False), sfs_tree(img, False), "after-teardown")
        return res
    except Exception as e:  # noqa
        res["errors"].append("exception: %s" % e)
        return res
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)
        else:
            res["dir"] = tmp


def one_ro_config(name, opts, size, big_sparse, large_inodes, keep):
    rng = random.Random(hash(name) & 0xFFFFFFFF)
    tmp = tempfile.mkdtemp(prefix="sfsmx-%s-" % name, dir=os.environ.get("SFS_TMP"))
    res = {"name": name, "errors": []}
    try:
        src = os.path.join(tmp, "src")
        build_source(src, rng, big_sparse, 1024)
        img = os.path.join(tmp, "img")
        run(["mkfs.ext4", "-q", "-F", "-d", src] + opts + [img, size])
        if large_inodes:
            run(["debugfs", "-w", "-R", "sif /docs/future.txt mtime 21000101000000", img])
        before = hashlib.sha256(open(img, "rb").read()).hexdigest()
        exp = host_tree(src, large_inodes)
        got = sfs_tree(img, large_inodes, extra=())
        res["errors"] += compare(exp, got, "read")
        res["read_entries"] = len(got)
        p = subprocess.run([TOOL, "-q", img, "info"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        m = re.search(r"read_only (\d) ro_reason (0x[0-9a-f]+)", p.stdout)
        res["ro_reason"] = m.group(2) if m else "?"
        if not m or m.group(1) != "1":
            res["errors"].append("not mounted read-only: " + p.stdout)
        p = subprocess.run([TOOL, "-q", img, "mkdir", "/nope"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if p.returncode == 0 or "read-only" not in p.stderr:
            res["errors"].append("write not refused: rc %d %s" % (p.returncode, p.stderr))
        after = hashlib.sha256(open(img, "rb").read()).hexdigest()
        if before != after:
            res["errors"].append("image changed by a read-only mount")
        rc, lines, _ = e2fsck_clean(img)
        res["e2fsck_after_write"] = rc
        if rc != 0 or lines:
            res["errors"].append("e2fsck rc=%d %s" % (rc, lines[:10]))
        return res
    except Exception as e:  # noqa
        res["errors"].append("exception: %s" % e)
        return res
    finally:
        if not keep:
            shutil.rmtree(tmp, ignore_errors=True)


def main():
    keep = "--keep" in sys.argv
    only = sys.argv[sys.argv.index("--only") + 1] if "--only" in sys.argv else None
    if not os.path.exists(TOOL):
        print("build first: make -C %s build/sfstool" % os.path.join(HERE, ".."))
        return 2
    results = []
    for name, opts, size, big, large in CONFIGS:
        if only and name != only:
            continue
        t0 = time.time()
        r = one_config(name, opts, size, big, large, keep)
        r["seconds"] = round(time.time() - t0, 1)
        results.append(r)
        status = "PASS" if not r["errors"] else "FAIL"
        print("%-22s %s  read %s entries, %s ops, e2fsck -fn: %s/%s, %ss" % (
            name, status, r.get("read_entries"), r.get("ops"), r.get("e2fsck_after_write"), r.get("e2fsck_after_teardown"), r["seconds"]))
        for e in r["errors"][:15]:
            print("    " + e.replace("\n", "\n    "))
        sys.stdout.flush()
    for name, opts, size, big, large in RO_CONFIGS:
        if only and name != only:
            continue
        t0 = time.time()
        r = one_ro_config(name, opts, size, big, large, keep)
        r["seconds"] = round(time.time() - t0, 1)
        results.append(r)
        print("%-22s %s  read %s entries, read-only (reason %s), writes refused, image unchanged, e2fsck -fn: %s, %ss" % (
            name, "PASS" if not r["errors"] else "FAIL", r.get("read_entries"), r.get("ro_reason"), r.get("e2fsck_after_write"), r["seconds"]))
        for e in r["errors"][:15]:
            print("    " + e.replace("\n", "\n    "))
        sys.stdout.flush()
    bad = [r for r in results if r["errors"]]
    print("matrix: %d/%d configurations passed" % (len(results) - len(bad), len(results)))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
