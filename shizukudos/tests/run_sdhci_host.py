#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Host unit tests of the Kernel64 SD/eMMC driver (kernel64/sdhci.c) against a register-level SDHCI 3.00 + card model.

Builds tests/test_sdhci.c with kernel64/sdhci.c (-DSDHCI_HOST_TEST, the real kernel headers) under ASan/UBSan and runs
it: an SD 1.x standard-capacity card (CMD8 unanswered), an SD 2.00 high-capacity card and an eMMC device in sector
mode (CMD1, host-assigned RCA, EXT_CSD SEC_COUNT, SWITCH bus width) - the eMMC path is not reachable under QEMU 8.2,
which has no eMMC model. Checks ADMA2 over physically discontiguous pages, PIO, Auto CMD12, byte vs block addressing,
retry after an injected data CRC error, failure after two, and the out-of-range error path.
"""
import argparse
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import shzlib  # noqa: E402
from shzlib import BUILD, SHZ  # noqa: E402

CFLAGS = ["-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function", "-DSDHCI_HOST_TEST",
          "-fsanitize=address,undefined", "-fno-sanitize-recover=all"]


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", default=str(BUILD / "sdhci_host"))
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    exe = out / "test_sdhci"
    shzlib.run(["gcc", *CFLAGS, "-I", SHZ / "kernel64", "-I", HERE, HERE / "test_sdhci.c", SHZ / "kernel64" / "sdhci.c", "-o", exe])
    r = subprocess.run([exe], capture_output=True, text=True)
    print(r.stdout, end="")
    checks = [{"check": line[6:], "status": "PASS" if line.startswith("PASS:") else "FAIL"} for line in r.stdout.splitlines()
              if line.startswith(("PASS:", "FAIL:"))]
    if r.returncode != 0 or not checks:
        checks.append({"check": "test_sdhci exit code 0 (sanitizers clean)", "status": "FAIL", "detail": r.stderr[-3000:]})
        print(r.stderr[-3000:])
    status = "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL"
    shzlib.write_json(out / "result.json", {"test": "sdhci_host", "status": status, "checks": checks, "utc": shzlib.utc_now(),
                                           "git": shzlib.git_state()})
    print(f"{status} ({len(checks)} checks)")
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
