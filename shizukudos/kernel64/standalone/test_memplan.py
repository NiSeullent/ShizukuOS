#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host test of the standalone Kernel64 RAM plan (kernel64/standalone/memholes.h).

The same header is compiled twice, as the Multiboot stub uses it (gcc -m32, freestanding) and as the UEFI boot
manager and Kernel64 use it (64-bit), with -Wall -Wextra -Werror and, for the 64-bit build, ASan + UBSan. Each case
feeds a memory map (usable ranges, in any order) and checks ram, the holes, the heap bytes fenced off, the cut, or
the refusal. The OVMF case is the map observed under QEMU q35 + OVMF with S3 on: SEC/PEI scratch RAM at 8-9 MiB
reserved as ACPI NVS (0x800000+0x8000, 0x80b000+0x1000, 0x810000+0xf0000).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
MIB = 1 << 20
CAP = 0xE0000000          # boot32.c MAX_RAM (3.5 GiB)
MIN = 64 * MIB

HARNESS = r'''
#include <stdio.h>
#include <string.h>
#include "memholes.h"
int main(void)
{
    static shz_memplan_t p;
    static shz_memplan_result_t r;
    static volatile shz_memholes_t h;
    unsigned long long b, e, cap, min, ig, is;
    unsigned i;
    shz_memplan_init(&p);
    if (scanf("%llx %llx %llx %llx", &cap, &min, &ig, &is) != 4) return 2;
    while (scanf("%llx %llx", &b, &e) == 2) {
        if (e & 1ull) shz_memplan_remove(&p, b, e & ~1ull);      /* odd end: an unusable range, removed after */
        else shz_memplan_add(&p, b, e);
    }
    for (i = 1; i < p.n; ++i)
        if (p.end[i - 1] >= p.base[i]) { printf("{\"error\": \"runs not sorted/merged\"}\n"); return 3; }
    i = shz_memplan_solve(&p, cap, min, ig, is, &r);
    memset((void *)&h, 0, sizeof h);
    shz_memholes_write(&h, &r);
    printf("{\"ok\": %u, \"ram\": %llu, \"count\": %u, \"heap\": %llu, \"cut\": %llu, \"dropped\": %u, "
           "\"check_ok\": %d, \"why\": \"%s\", \"at\": %llu, \"holes\": [",
           i, (unsigned long long)r.ram, r.count, (unsigned long long)r.heap_hole_bytes, (unsigned long long)r.cut,
           p.dropped, h.check == shz_memholes_sum(&h), r.why ? r.why : "", (unsigned long long)r.at);
    for (i = 0; i < r.count; ++i)
        printf("%s[%llu, %llu]", i ? ", " : "", (unsigned long long)r.gpa[i], (unsigned long long)r.size[i]);
    printf("]}\n");
    return 0;
}
'''


def legacy(ram):
    return [(0, 0x9FC00), (MIB, ram)]


OVMF_S3 = [(0, 0xA0000), (MIB, 0x800000), (0x808000, 0x80B000), (0x80C000, 0x810000), (0x900000, 0x1F800000),
           (0x1F900000, 0x1FEE0000)]
OVMF_S3_HOLES = [(0x800000, 0x8000), (0x80B000, 0x1000), (0x810000, 0xF0000), (0x1F800000, 0x100000)]

CASES = [
    # name, runs, cap, initrd size, expectation
    ("legacy 512 MiB, no holes", legacy(0x1FFE0000), CAP, 0x200000,
     {"ok": 1, "ram": 0x1FE00000, "count": 0, "heap": 0}),
    ("legacy, runs given out of order and overlapping", [(0x4000000, 0x8000000), (MIB, 0x4800000), (0, 0x9FC00),
                                                         (0x7000000, 0x10000000)], CAP, 0,
     {"ok": 1, "ram": 0x10000000, "count": 0}),
    ("OVMF S3 (CSMWrap E820 / UEFI map): 8 MiB NVS fenced in the heap, top-of-RAM hole kept out", OVMF_S3, CAP,
     0x200000, {"ok": 1, "ram": 0x1FE00000, "holes": OVMF_S3_HOLES, "heap": 0x8000 + 0x1000 + 0xF0000}),
    ("capped at 256 MiB (loader K64_RAM_MAX)", OVMF_S3, 256 * MIB, 0x200000,
     {"ok": 1, "ram": 256 * MIB, "holes": OVMF_S3_HOLES[:3]}),
    ("hole in the kernel window is refused", [(0, 0x9F000), (MIB, 2 * MIB), (0x280000, 512 * MIB)], CAP, 0,
     {"ok": 0, "why": "kernel window", "at": 2 * MIB}),
    ("boot pages not RAM are refused", [(0x8000, 0x9F000), (MIB, 512 * MIB)], CAP, 0,
     {"ok": 0, "why": "boot pages"}),
    ("hole over the initrd is refused", legacy(33 * MIB) + [(34 * MIB, 512 * MIB)], CAP, 4 * MIB,
     {"ok": 0, "why": "initial RAM image", "at": 33 * MIB}),
    ("heap window mostly holes is refused", [(0, 0x9F000), (MIB, 4 * MIB), (14 * MIB, 512 * MIB)], CAP, 0,
     {"ok": 0, "why": "heap"}),
    ("more than 16 holes: RAM ends below the 17th", [(0, 0x9F000), (MIB, 100 * MIB)] +
     [(100 * MIB + k * MIB + 0x10000, 101 * MIB + k * MIB) for k in range(24)], CAP, 0,
     {"ok": 1, "count": 16, "cut": 116 * MIB, "ram": 116 * MIB}),
    ("top page in a gap: RAM lowered to the last usable 2 MiB boundary", [(0, 0x9F000), (MIB, 0x10000000),
                                                                          (0x10300000, 0x10380000)], CAP, 0,
     {"ok": 1, "ram": 0x10000000, "count": 0}),
    ("too little RAM is refused", legacy(40 * MIB), CAP, 0, {"ok": 0, "why": "too low"}),
    ("initrd above the end of RAM is refused", legacy(66 * MIB), CAP, 40 * MIB, {"ok": 0, "why": "does not fit"}),
    ("more than 64 separate runs: the highest are dropped, RAM ends below them", [(0, 0x9F000), (MIB, 80 * MIB)] +
     [(80 * MIB + k * 0x20000 + 0x1000, 80 * MIB + (k + 1) * 0x20000) for k in range(80)], CAP, 0,
     {"ok": 1, "dropped_min": 1, "count": 16}),
    ("an unusable range inside a usable one splits it (UEFI map with overlapping descriptors)", legacy(512 * MIB),
     CAP, 0, {"ok": 1, "holes": [(0x800000, 0x8000), (0x10000000, 0x1000)]},
     [(0x800000, 0x808000), (0x10000000, 0x10001000)]),
    ("unusable ranges trimming run edges and deleting a run", [(0, 0x9F000), (MIB, 0x900000), (0xA00000, 0xA10000),
                                                               (0xB00000, 512 * MIB)], CAP, 0,
     {"ok": 1, "holes": [(0x880000, 0x280000)]}, [(0x880000, 0x900000), (0xA00000, 0xA10000), (0xB00000, 0xB00000)]),
]


def build(tmp: Path, bits: int) -> Path:
    src = tmp / "t.c"
    src.write_text(HARNESS)
    exe = tmp / f"memplan{bits}"
    cmd = ["gcc", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-I", str(HERE), str(src), "-o", str(exe)]
    cmd += ["-m32"] if bits == 32 else ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
    subprocess.run(cmd, check=True)
    return exe


def run_case(exe: Path, runs, cap, isize, unusable=()):
    """runs: usable ranges; unusable: ranges removed afterwards (the harness marks them with an odd end)."""
    text = (f"{cap:x} {MIN:x} {32 * MIB:x} {isize:x}\n" + "".join(f"{b:x} {e:x}\n" for b, e in runs)
            + "".join(f"{b:x} {e | 1:x}\n" for b, e in unusable))
    out = subprocess.run([str(exe)], input=text, capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def judge(got: dict, want: dict) -> list[str]:
    bad = []
    for key, value in want.items():
        if key == "why":
            if value not in got["why"]:
                bad.append(f"why {got['why']!r} lacks {value!r}")
        elif key == "holes":
            if [tuple(h) for h in got["holes"]] != [tuple(h) for h in value]:
                bad.append(f"holes {[(hex(a), hex(s)) for a, s in got['holes']]}")
        elif key == "dropped_min":
            if got["dropped"] < value:
                bad.append(f"dropped {got['dropped']}")
        elif got[key] != value:
            bad.append(f"{key} {got[key]:#x} != {value:#x}")
    if got["ok"] and not got["check_ok"]:
        bad.append("memholes checksum")
    if got["ok"] and got["ram"] & 0x1FFFFF:
        bad.append("ram not 2 MiB aligned")
    return bad


def main() -> int:
    failures = 0
    with tempfile.TemporaryDirectory(prefix="shz-memplan-") as tmp:
        for bits in (32, 64):
            try:
                exe = build(Path(tmp), bits)
            except (subprocess.CalledProcessError, FileNotFoundError) as exc:
                print(f"[FAIL] build {bits}-bit harness: {exc}")
                failures += 1
                continue
            for name, runs, cap, isize, want, *rest in CASES:
                got = run_case(exe, runs, cap, isize, *rest)
                bad = judge(got, want)
                failures += bool(bad)
                print(f"[{'FAIL' if bad else 'PASS'}] {bits}-bit: {name}" + (f": {'; '.join(bad)}" if bad else ""))
    print("PASS" if not failures else f"FAIL ({failures})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
