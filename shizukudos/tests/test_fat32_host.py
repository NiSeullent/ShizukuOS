#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host unit test for kernel64/fat32.c (the FAT32 reader/writer behind Kernel64's D:\\).

Builds FAT32 images with mkfs.vfat + mtools (superfloppy and MBR-partitioned, 4 KiB and 32 KiB clusters), fills
them with long names, mixed case, subdirectories, an empty file, a file spanning many clusters and a deliberately
fragmented file (copy/delete/copy), then compiles tests/test_fat32.c against fat32.c (gcc, -Wall -Wextra -Werror,
plus an ASan/UBSan variant when clang is available) and checks every entry the reader enumerates: names, sizes,
attributes, mtimes (fixed epoch) and CRC-32 of the content read back through fat32_read. Then the same walker runs
a scripted write sequence (--write) on a copy of each image: long-name and 8.3 creates, a directory, chunked and
gapped writes, in-place overwrite, append, shrink/grow truncation, directory growth past one cluster, duplicate and
invalid names. The result is checked three ways: fsck.fat -n must find nothing, mtools must read back the expected
bytes of every file and list the generated LONGNA~N aliases, and the walker must enumerate the expected tree.
Nothing here touches a device or a VM.
"""
import json
import os
import shutil
import subprocess
import sys
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
from shzlib import BUILD, run  # noqa: E402

OUT = BUILD / "fat32-host"
FIXED_EPOCH = 1785283200          # 2026-07-29 00:00:00 UTC
FIXED_FILETIME = (FIXED_EPOCH + 11644473600) * 10_000_000


def env():
    e = dict(os.environ)
    e.update(MTOOLS_SKIP_CHECK="1", TZ="UTC", SOURCE_DATE_EPOCH=str(FIXED_EPOCH))
    return e


def pattern(seed, n):
    out = bytearray()
    x = seed & 0xffffffff
    while len(out) < n:
        x = (x * 1103515245 + 12345) & 0xffffffff
        out += x.to_bytes(4, "little")
    return bytes(out[:n])


def build_image(path, size_mib, spc, mbr):
    path.unlink(missing_ok=True)
    with open(path, "wb") as fh:
        fh.truncate(size_mib << 20)
    cmd = ["mkfs.vfat", "-F", "32", "-s", str(spc), "-n", "FATTEST", "--invariant"]
    if mbr:
        cmd += ["--mbr=y"]
    run(cmd + [str(path)], capture=True)


def fill(image, src):
    """Returns {volume path: (bytes, is_dir)} of what was written."""
    e = env()
    spec = str(image)
    files = {}

    def put(rel, data):
        host = src / rel.replace("/", "__")
        host.write_bytes(data)
        os.utime(host, (FIXED_EPOCH, FIXED_EPOCH))
        run(["mcopy", "-m", "-i", spec, str(host), f"::{rel}"], env=e, capture=True)
        files[rel] = data

    for d in ("SUB", "Long Directory Name", "SUB/nested_dir_x"):
        run(["mmd", "-i", spec, f"::{d}"], env=e, capture=True)
        files[d] = None
    put("HELLO.TXT", b"hello\r\n")
    put("lowercase.txt", b"lower")
    put("MixedCase.Dat", pattern(1, 777))
    put("a_rather_long_file_name_with_many_characters.bin", pattern(2, 4096 * 3 + 5))
    put("empty.txt", b"")
    put("SUB/inner.txt", pattern(3, 100000))
    put("SUB/nested_dir_x/deep file.txt", pattern(4, 4097))
    put("Long Directory Name/x.y.z", pattern(5, 512))
    put("multi_cluster_800k.bin", pattern(6, 800 * 1024 + 13))
    # two files of equal cluster counts; interleave() below rewrites their chains into alternating clusters
    put("frag_b.bin", pattern(8, 512 * 1024 + 100))
    put("frag_c.bin", pattern(9, 512 * 1024 + 100))
    interleave(image, b"FRAG_B  BIN", b"FRAG_C  BIN")
    return files


def interleave(image, short_a, short_b):
    """mtools always allocates contiguously, so fragmentation is made by hand: the data clusters of two equally long
    files are swapped pairwise (odd indices) and both FAT copies are rewritten so each chain alternates between the
    two original extents. File contents are unchanged; each chain now has as many runs as clusters."""
    import struct
    with open(image, "r+b") as fh:
        bs = fh.read(512)
        bps, spc, reserved, nfats = struct.unpack_from("<HBHB", bs, 11)
        fatsz, root = struct.unpack_from("<I", bs, 36)[0], struct.unpack_from("<I", bs, 44)[0]
        first_data = reserved + nfats * fatsz
        fat_off = reserved * bps
        fh.seek(fat_off)
        fat = bytearray(fh.read(fatsz * bps))
        ent = lambda c: struct.unpack_from("<I", fat, c * 4)[0] & 0x0fffffff  # noqa: E731

        def cluster_off(c):
            return (first_data + (c - 2) * spc) * bps

        def chain(first):
            out = []
            while first < 0x0ffffff8:
                out.append(first)
                first = ent(first)
            return out

        firsts = {}
        c = root
        while c < 0x0ffffff8:                         # root directory: find the two short entries
            fh.seek(cluster_off(c))
            data = fh.read(spc * bps)
            for i in range(0, len(data), 32):
                e = data[i:i + 32]
                if e[:11] in (short_a, short_b) and e[11] != 0x0f:
                    firsts[e[:11]] = (struct.unpack_from("<H", e, 20)[0] << 16) | struct.unpack_from("<H", e, 26)[0]
            c = ent(c)
        a, b = chain(firsts[short_a]), chain(firsts[short_b])
        assert len(a) == len(b) >= 2, (len(a), len(b))
        for i in range(1, len(a), 2):
            fh.seek(cluster_off(a[i])); da = fh.read(spc * bps)
            fh.seek(cluster_off(b[i])); db = fh.read(spc * bps)
            fh.seek(cluster_off(a[i])); fh.write(db)
            fh.seek(cluster_off(b[i])); fh.write(da)
            a[i], b[i] = b[i], a[i]
        for ch in (a, b):
            for i, c in enumerate(ch):
                nxt = ch[i + 1] if i + 1 < len(ch) else 0x0fffffff
                struct.pack_into("<I", fat, c * 4, (struct.unpack_from("<I", fat, c * 4)[0] & 0xf0000000) | nxt)
        for k in range(nfats):
            fh.seek(fat_off + k * fatsz * bps)
            fh.write(fat)


def compile_walker():
    OUT.mkdir(parents=True, exist_ok=True)
    exes = []
    src = [str(HERE / "test_fat32.c"), str(HERE.parent / "kernel64" / "fat32.c")]
    exe = OUT / "test_fat32"
    run(["gcc", "-std=gnu11", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-D_FILE_OFFSET_BITS=64", *src, "-o", exe])
    exes.append(exe)
    if shutil.which("clang"):
        exe2 = OUT / "test_fat32_asan"
        run(["clang", "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fsanitize=address,undefined",
             "-fno-sanitize-recover=all", "-D_FILE_OFFSET_BITS=64", *src, "-o", exe2])
        exes.append(exe2)
    # the kernel build flags (freestanding, -mcmodel=kernel, general registers only) must accept it too
    run(["gcc", "-m64", "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-ffreestanding", "-fno-builtin", "-fno-pic",
         "-fno-pie", "-mcmodel=kernel", "-mno-red-zone", "-mgeneral-regs-only", "-fno-stack-protector", "-c",
         str(HERE.parent / "kernel64" / "fat32.c"), "-o", OUT / "fat32-kernel.o"])
    undefined = run(["nm", "-u", OUT / "fat32-kernel.o"], capture=True).stdout.strip()
    assert not undefined, f"fat32.c needs runtime helpers when built freestanding: {undefined}"
    return exes


def dos_filetime(date, time):
    import calendar
    y, m, d = 1980 + (date >> 9), (date >> 5) & 15, date & 31
    hh, mm, ss = time >> 11, (time >> 5) & 63, (time & 31) * 2
    return (calendar.timegm((y, m, d, hh, mm, ss)) + 11644473600) * 10_000_000


def check_image(exe, image, expected, label, write=False, mtimes=None):
    r = subprocess.run([str(exe), str(image), *(["--write"] if write else [])], capture_output=True, text=True)
    lines = [json.loads(l) for l in r.stdout.splitlines() if l.strip()]
    assert r.returncode == 0, f"{label}: walker failed rc={r.returncode}\n{r.stdout[-2000:]}\n{r.stderr[-2000:]}"
    seen = {}
    for l in lines:
        if "path" in l:
            seen[l["path"]] = l
    problems = []
    for rel, data in expected.items():
        got = seen.get(rel)
        if not got:
            problems.append(f"missing {rel}")
            continue
        base = rel.rsplit("/", 1)[-1]
        if got["name"] != base:
            problems.append(f"{rel}: name {got['name']!r}")
        if data is None:
            if not got.get("dir"):
                problems.append(f"{rel}: not a directory")
            continue
        if got["size"] != len(data):
            problems.append(f"{rel}: size {got['size']} != {len(data)}")
        if got["crc32"] != zlib.crc32(data) & 0xffffffff:
            problems.append(f"{rel}: crc {got['crc32']:#x} != {zlib.crc32(data) & 0xffffffff:#x}")
        want_mtime = (mtimes or {}).get(rel, FIXED_FILETIME)
        if got["mtime"] != want_mtime:
            problems.append(f"{rel}: mtime {got['mtime']} != {want_mtime}")
        stem, _, ext = base.partition(".")
        needs_lfn = len(stem) > 8 or len(ext) > 3 or " " in base or base.count(".") > 1 or \
            (stem != stem.upper() and stem != stem.lower()) or (ext != ext.upper() and ext != ext.lower())
        if needs_lfn and not got["lfn"]:
            problems.append(f"{rel}: expected an LFN entry")
    extra = set(seen) - set(expected)
    if extra:
        problems.append(f"unexpected entries {sorted(extra)}")
    frag = seen.get("frag_c.bin")
    if frag and frag["runs"] != frag["clusters"]:
        problems.append(f"frag_c.bin should alternate clusters, runs={frag['runs']} clusters={frag['clusters']}")
    errors = [l for l in lines if "error" in l]
    if errors:
        problems.append(f"walker errors {errors}")
    done = [l for l in lines if "done" in l]
    assert done and done[0]["allocs"] == done[0]["frees"], f"{label}: allocation leak {done}"
    assert not problems, f"{label}:\n  " + "\n  ".join(problems)
    out = {"entries": len(seen), "sector_reads": done[0]["sector_reads"], "frag_runs": frag["runs"] if frag else None}
    w = [l for l in lines if l.get("write")]
    if write:
        assert w, f"{label}: no write summary"
        out.update(sector_writes=done[0]["sector_writes"], free_before=w[0]["free_before"], free_after=w[0]["free_after"])
    return out


def apply_write_script(expected):
    """Mirror of write_script() in tests/test_fat32.c: returns (expected tree, {path: mtime} of touched entries)."""
    exp = dict(expected)
    wt = dos_filetime(0x5c9d, 0x6000)
    touched = {}

    def put(rel, data):
        exp[rel] = data
        touched[rel] = wt

    put("Written By Kernel.txt", pattern(21, 10000))
    put("UPPER.TXT", b"short name\r\n")
    put("New Folder", None)
    put("New Folder/inner file.bin", pattern(24, 1000) + bytes(4000) + pattern(23, 3000))
    inner = bytearray(exp["SUB/inner.txt"])
    inner[4095:4095 + 5000] = pattern(22, 5000)
    put("SUB/inner.txt", bytes(inner))
    put("HELLO.TXT", exp["HELLO.TXT"] + b"appended\r\n")
    put("multi_cluster_800k.bin", exp["multi_cluster_800k.bin"][:5000])
    put("empty.txt", bytes(3000))
    put("big_written.bin", pattern(25, 300000))
    for i in range(50):
        put(f"Long Directory Name/file number {i:02d} with a long name.txt", f"content {i}\r\n".encode())
    put("longname1.txt", b"")
    put("longname2.txt", b"")
    return exp, touched


def check_written(exe, image, expected, label):
    """Runs the write script on `image`, then fsck.fat -n, mtools read-back and the walker."""
    exp, mtimes = apply_write_script(expected)
    result = check_image(exe, image, exp, label + "/write", write=True, mtimes=mtimes)
    fsck = subprocess.run(["fsck.fat", "-n", "-v", str(image)], capture_output=True, text=True)
    bad_words = [l for l in fsck.stdout.splitlines() if not l.startswith("Checking") and
                 any(k in l.lower() for k in ("wrong", "lost", "invalid", "differ", "bad ", "orphan", "reclaim", "unused",
                                              "free cluster summary", "has no", "starts with", "contains"))]
    assert fsck.returncode == 0 and not bad_words, f"{label}: fsck.fat -n rc={fsck.returncode}\n{fsck.stdout[-3000:]}{fsck.stderr[-1000:]}"
    e = env()
    tmp = OUT / "mtools-out.bin"
    mismatches = []
    for rel, data in exp.items():
        if data is None:
            continue
        tmp.unlink(missing_ok=True)
        r = subprocess.run(["mcopy", "-n", "-i", str(image), f"::{rel}", str(tmp)], env=e, capture_output=True, text=True)
        if r.returncode or tmp.read_bytes() != data:
            mismatches.append(rel)
    assert not mismatches, f"{label}: mtools read-back differs for {mismatches}"
    listing = run(["mdir", "-i", str(image), "::"], env=e, capture=True).stdout
    aliases = [a for a in ("LONGNA~1 TXT", "LONGNA~2 TXT", "WRITTE~1 TXT", "NEWFOL~1") if a not in " ".join(listing.split())]
    assert not aliases, f"{label}: aliases {aliases} missing from mdir:\n{listing}"
    result.update(fsck="clean", mtools_files=sum(1 for d in exp.values() if d is not None))
    return result


def main():
    for tool in ("mkfs.vfat", "mcopy", "mmd", "gcc"):
        if not shutil.which(tool):
            raise SystemExit(f"required tool missing: {tool}")
    exes = compile_walker()
    results = {}
    src = OUT / "src"
    src.mkdir(parents=True, exist_ok=True)
    for name, size_mib, spc, mbr in (("superfloppy-4k", 64, 8, False), ("mbr-32k", 128, 64, True), ("superfloppy-512b", 40, 1, False)):
        image = OUT / f"{name}.img"
        build_image(image, size_mib, spc, mbr)
        expected = fill(image, src)
        for exe in exes:
            results[f"{name}/{exe.name}"] = check_image(exe, image, expected, f"{name}/{exe.name}")
            print(f"PASS {name} {exe.name}: {results[f'{name}/{exe.name}']}")
        for exe in exes:
            copy = OUT / f"{name}-{exe.name}-written.img"
            shutil.copyfile(image, copy)
            results[f"{name}/{exe.name}/write"] = check_written(exe, copy, expected, f"{name}/{exe.name}")
            print(f"PASS {name} {exe.name} write: {results[f'{name}/{exe.name}/write']}")
            copy.unlink()
    (OUT / "result.json").write_text(json.dumps({"status": "PASS", "results": results}, indent=2) + "\n")
    print("PASS")


if __name__ == "__main__":
    main()
