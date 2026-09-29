#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host unit tests of the Kernel64 partition scanner (kernel64/blk_part.c) on synthetic MBR/EBR/GPT tables.

Compiles tests/test_blk_part.c + kernel64/blk_part.c with the host gcc under ASan/UBSan and runs it; then cross-checks
the C scanner against an independent Python GPT/MBR writer (the one run_k64_storage.py uses for the guest images) by
scanning images written by Python through a tiny C harness driven over stdin.
"""
import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import shzlib  # noqa: E402
from shzlib import BUILD, SHZ  # noqa: E402

CFLAGS = ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-DBLK_HOST_TEST", "-fsanitize=address,undefined",
          "-fno-sanitize-recover=all"]

SCAN_HARNESS = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "blk_part.h"
typedef struct { FILE *f; unsigned ss; unsigned long long sectors; } D;
static int rd(void *c, uint64_t lba, uint32_t n, void *buf) {
    D *d = c; if (fseeko(d->f, (off_t)(lba * d->ss), SEEK_SET)) return -1;
    return fread(buf, d->ss, n, d->f) == n ? 0 : -1; }
int main(int argc, char **argv) {
    D d; blk_part_t p[64]; uint32_t notes = 0; int n, i; void *scratch;
    if (argc < 3) return 2;
    d.f = fopen(argv[1], "rb"); d.ss = (unsigned)atoi(argv[2]);
    if (!d.f) return 2;
    fseeko(d.f, 0, SEEK_END); d.sectors = (unsigned long long)ftello(d.f) / d.ss;
    scratch = malloc(2 * d.ss);
    n = blk_part_scan(rd, &d, d.ss, d.sectors, scratch, p, 64, &notes);
    printf("{\"n\": %d, \"notes\": %u, \"parts\": [", n, notes);
    for (i = 0; i < n; ++i)
        printf("%s{\"index\": %u, \"start\": %llu, \"sectors\": %llu, \"scheme\": %u, \"type\": %u, \"flags\": %u, \"name\": \"%s\"}",
               i ? ", " : "", p[i].index, (unsigned long long)p[i].start, (unsigned long long)p[i].sectors, p[i].scheme, p[i].mbr_type, p[i].flags, p[i].name);
    printf("]}\n");
    free(scratch);
    return 0;
}
"""


def build(out):
    out.mkdir(parents=True, exist_ok=True)
    exe = out / "test_blk_part"
    shzlib.run(["gcc", *CFLAGS, "-I", SHZ / "kernel64", HERE / "test_blk_part.c", SHZ / "kernel64" / "blk_part.c", "-o", exe])
    harness = out / "scan_harness"
    (out / "scan_harness.c").write_text(SCAN_HARNESS)
    shzlib.run(["gcc", *CFLAGS, "-I", SHZ / "kernel64", out / "scan_harness.c", SHZ / "kernel64" / "blk_part.c", "-o", harness])
    return exe, harness


def python_cross_checks(harness, out):
    """Images written by the Python table writer (shared with the guest runner) scanned by the C code."""
    sys.path.insert(0, str(HERE))
    import blk_images  # noqa: E402
    results = []
    # GPT with 3 partitions, 512-byte sectors
    img = bytearray(64 << 20)
    parts = [(2048, 4096, "EFI"), (6144, 40000, "ShizukuFS"), (46144, 80000, "data")]
    blk_images.write_gpt(img, 512, parts)
    p = out / "py_gpt.img"
    p.write_bytes(img)
    r = json.loads(subprocess.run([harness, p, "512"], capture_output=True, text=True, check=True).stdout)
    ok = r["n"] == 3 and [(x["start"], x["sectors"], x["name"]) for x in r["parts"]] == [(s, n, nm) for s, n, nm in parts] and r["notes"] & 4
    results.append(("C scanner reads the Python-written GPT (3 partitions, names, primary header)", ok, json.dumps(r)))
    # same image, primary header corrupted by the Python side -> backup
    blk_images.corrupt_gpt_primary(img, 512)
    p = out / "py_gpt_badprimary.img"
    p.write_bytes(img)
    r = json.loads(subprocess.run([harness, p, "512"], capture_output=True, text=True, check=True).stdout)
    ok = r["n"] == 3 and r["notes"] & 64 and all(x["flags"] & 4 for x in r["parts"])
    results.append(("C scanner falls back to the Python-written backup GPT header", ok, json.dumps(r)))
    # MBR with 2 primaries + extended with 2 logicals
    img = bytearray(16 << 20)
    blk_images.write_mbr(img, [(2048, 4096, 0x0C, True), (6144, 4096, 0x83, False)], extended=(10240, 20000, [(63, 4000, 0x83), (63, 6000, 0x07)]))
    p = out / "py_mbr.img"
    p.write_bytes(img)
    r = json.loads(subprocess.run([harness, p, "512"], capture_output=True, text=True, check=True).stdout)
    ok = (r["n"] == 4 and (r["parts"][0]["start"], r["parts"][0]["sectors"], r["parts"][0]["type"]) == (2048, 4096, 0x0C)
          and r["parts"][0]["flags"] & 1 and r["parts"][2]["start"] == 10240 + 63 and r["parts"][2]["flags"] & 2
          and r["parts"][3]["start"] == 10240 + 4063 + 63 and r["parts"][3]["sectors"] == 6000)
    results.append(("C scanner reads the Python-written MBR + EBR chain (2 primaries, 2 logicals)", ok, json.dumps(r)))
    return results


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(BUILD / "blk_part_host"))
    args = ap.parse_args()
    out = Path(args.out)
    exe, harness = build(out)
    r = subprocess.run([exe], capture_output=True, text=True)
    print(r.stdout, end="")
    checks = [{"check": line[6:], "status": "PASS" if line.startswith("PASS:") else "FAIL"} for line in r.stdout.splitlines()
              if line.startswith(("PASS:", "FAIL:"))]
    if r.returncode != 0:
        checks.append({"check": "test_blk_part exit code 0 (sanitizers clean)", "status": "FAIL", "detail": r.stderr[-2000:]})
    for name, ok, detail in python_cross_checks(harness, out):
        checks.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": detail})
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    status = "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL"
    shzlib.write_json(out / "result.json", {"test": "blk_part_host", "status": status, "checks": checks, "utc": shzlib.utc_now(),
                                           "git": shzlib.git_state()})
    print(f"{status} ({len(checks)} checks)")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
