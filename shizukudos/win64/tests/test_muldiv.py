#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compare production MulDiv arithmetic with exact Fraction nearest-distance oracle.

Microsoft: nearest integer; half integers away from zero; overflow/zero -> -1.
https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-muldiv
This host check executes the production helper under undefined-behavior sanitizer.
It does not establish guest import/export or desktop application functionality.
"""
import argparse
import ctypes
import itertools
import math
import random
import subprocess
import tempfile
from fractions import Fraction
from pathlib import Path

LOW = -(1 << 31)
HIGH = (1 << 31) - 1


def oracle(number, numerator, denominator):
    if denominator == 0:
        return -1
    value = Fraction(number * numerator, denominator)
    lower, upper = math.floor(value), math.ceil(value)
    lower_distance, upper_distance = value - lower, upper - value
    if lower_distance == upper_distance:
        result = lower if value < 0 else upper
    else:
        result = lower if lower_distance < upper_distance else upper
    return result if LOW <= result <= HIGH else -1


def validate(out):
    source_root = Path(__file__).resolve().parents[1]
    wrapper = out / "muldiv_wrapper.c"
    wrapper.write_text('#include "k32_muldiv.h"\nint actual(int a,int b,int c){return shz_muldiv(a,b,c); }\n')
    library = out / "muldiv_sanitized.so"
    subprocess.run(["gcc", "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fPIC", "-shared",
                    "-fsanitize=undefined", "-fsanitize-undefined-trap-on-error", "-I", str(source_root / "kernel32"),
                    str(wrapper), "-o", str(library)], check=True, timeout=60)
    loaded = ctypes.CDLL(str(library))
    actual = loaded.actual
    actual.argtypes = [ctypes.c_int] * 3
    actual.restype = ctypes.c_int
    boundaries = [LOW, LOW + 1, -65536, -32769, -32768, -3, -2, -1, 0, 1, 2, 3, 32767, 32768, 65535, HIGH - 1, HIGH]
    rng = random.Random(0x535445414d)
    random_cases = ((rng.randint(LOW, HIGH), rng.randint(LOW, HIGH), rng.randint(LOW, HIGH)) for _ in range(50000))
    count = 0
    for triple in itertools.chain(itertools.product(boundaries, repeat=3), random_cases):
        expected = oracle(*triple)
        observed = actual(*triple)
        if observed != expected:
            raise AssertionError(f"MulDiv{triple}: actual={observed}, exact rational oracle={expected}")
        count += 1
    print(f"MULDIV-HOST: {count} boundary/random exact-rational checks passed with undefined-behavior traps")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path)
    args = parser.parse_args()
    if args.build_dir:
        args.build_dir.mkdir(parents=True, exist_ok=True)
        validate(args.build_dir.resolve())
    else:
        with tempfile.TemporaryDirectory(prefix="shz-steam-muldiv-") as directory:
            validate(Path(directory))


if __name__ == "__main__":
    main()
