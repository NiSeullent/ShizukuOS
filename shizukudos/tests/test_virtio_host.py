#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host-side tests of the Kernel64 virtio / virtio-gpu / virgl code that need no guest:

  1. kernel64/virtq.c            split virtqueue ring model against a simulated device (kernel64/host/test_virtq.c)
  2. kernel64/virtio_gpu.h       virtio-gpu wire structures vs the host's <linux/virtio_gpu.h> (test_virtio_gpu_layout.c)
  3. win64/include/shzvirgl.h    virgl command-stream encoder decoded with the pinned virgl_protocol.h (test_virgl_enc.c)
  4. win64/include/shzvirgl.h    the same stream EXECUTED by the host's libvirglrenderer on the host's OpenGL driver, pixels
                                 read back and compared with a host-computed triangle (test_virgl_exec.c)

1-3 are compiled with -fsanitize=address,undefined and must pass. 4 needs libvirglrenderer.so.1 and an EGL driver that
works without a window system (Mesa llvmpipe is enough); when the host lacks them it is reported NOT RUN (exit 77), which
is not a pass. It is built without sanitizers because the GL driver it loads is not instrumented.
The pinned upstream headers are re-hashed first (third_party/virglrenderer-1.0.0/PINNED.txt).

None of this proves that a guest reaches the device: tests/run_k64_gui.py --display virtio (2D) and --display virtio-gl
(3D, needs QEMU with a GL display, i.e. a DRM render node) do that.
"""
import hashlib
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SHZ = HERE.parent
BUILD = SHZ.parent / "build" / "shizukudos" / "host-virtio"
K64 = SHZ / "kernel64"
PIN = SHZ / "third_party" / "virglrenderer-1.0.0"
INC = SHZ / "win64" / "include"
BASE = ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-fno-omit-frame-pointer"]
SAN = ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]


def run(cmd):
    print("+", " ".join(str(c) for c in cmd), flush=True)
    r = subprocess.run([str(c) for c in cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(r.stdout, end="")
    return r.returncode


def check_pins():
    table = (PIN / "PINNED.txt").read_text()
    ok = True
    for name, digest in re.findall(r"^(\S+)\s+([0-9a-f]{64})\s+virglrenderer-1\.0\.0/", table, re.M):
        got = hashlib.sha256((PIN / name).read_bytes()).hexdigest()
        if got != digest:
            print(f"pinned file {name}: sha256 {got} != {digest}")
            ok = False
    print(f"pinned virglrenderer headers: {'match' if ok else 'MISMATCH'}")
    return ok


def main():
    BUILD.mkdir(parents=True, exist_ok=True)
    results = {"pins": check_pins()}
    exe = BUILD / "test_virtq"
    results["virtq"] = not (run(["gcc", *BASE, *SAN, "-I", K64, K64 / "host" / "test_virtq.c", K64 / "virtq.c", "-o", exe]) or run([exe]))
    exe = BUILD / "test_virtio_gpu_layout"
    results["virtio-gpu layout"] = not (run(["gcc", *BASE, *SAN, "-I", K64, K64 / "host" / "test_virtio_gpu_layout.c", "-o", exe]) or
                                        run([exe]))
    exe = BUILD / "test_virgl_enc"
    results["virgl encoder"] = not (run(["gcc", *BASE, *SAN, "-I", PIN, "-I", INC, K64 / "host" / "test_virgl_enc.c", "-o", exe]) or
                                    run([exe]))
    exe = BUILD / "test_virgl_exec"
    rc = run(["gcc", *BASE, "-I", PIN, "-I", INC, K64 / "host" / "test_virgl_exec.c", "-o", exe, "-ldl", "-lm"])
    rc = rc or run([exe])
    results["virgl exec (host virglrenderer)"] = True if rc == 0 else ("NOT RUN" if rc == 77 else False)
    for k, v in results.items():
        print(f"  {k}: {'PASS' if v is True else v if v == 'NOT RUN' else 'FAIL'}")
    ok = all(v is True or v == "NOT RUN" for v in results.values())
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
