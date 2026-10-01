#!/usr/bin/env python3
"""Compile and run the INT 10h host test."""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SOURCES = [
    os.path.join(HERE, "test_int10.c"),
    os.path.join(HERE, "bios", "int10.c"),
    os.path.join(HERE, "video", "video.c"),
    os.path.join(HERE, "video", "cp437.c"),
]


def main():
    out_dir = tempfile.mkdtemp(prefix="csmwrap-int10-")
    binary = os.path.join(out_dir, "test_int10")
    cmd = [
        "gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-O2",
        "-I", HERE,
        *SOURCES,
        "-o", binary,
    ]
    print("compile:", " ".join(cmd), flush=True)
    subprocess.check_call(cmd)
    print("run:", binary, flush=True)
    subprocess.check_call([binary])
    return 0


if __name__ == "__main__":
    sys.exit(main())
