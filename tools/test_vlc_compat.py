#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Run production VLC forwarding/error controls on the host, never in a VM."""
import argparse
import datetime
import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ("src/m98_vlc_compat.c", "src/m98_vlc_compat.h", "src/kex_abi.h",
           "tests/vlc_compat_host.c", "tests/vlc_compat_host/windows.h",
           "tools/test_vlc_compat.py")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("new isolated repository build output required")
    cc = shutil.which("clang")
    if not cc:
        parser.error("existing host Clang with sanitizer runtime required")
    frozen = {name: digest(ROOT / name) for name in SOURCES}
    out.mkdir(parents=True)
    for name in frozen:
        destination = out / "frozen" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
    command = [cc, "--no-default-config", "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
               "-I", str(ROOT / "tests/vlc_compat_host"),
               str(ROOT / "tests/vlc_compat_host.c"), str(ROOT / "src/m98_vlc_compat.c"),
               "-o", str(out / "controls")]
    receipt = {"schema": "win98modern.vlc-compat-host-controls.v1",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "status": "FAIL", "native_execution": False, "application_success": False,
               "sources": frozen, "compiler": {"path": cc, "sha256": digest(Path(cc))},
               "compile_command": command,
               "limitations": ["Mock native API results test the production forwarding/error path only.",
                               "Native OEM behavior and VLC GUI/playback remain separate guest gates."]}
    try:
        built = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out / "compile.log").write_text(built.stdout + built.stderr)
        receipt["compile_exit"] = built.returncode
        if built.returncode:
            raise ValueError("actual provider host compile failed")
        tested = subprocess.run([str(out / "controls")], capture_output=True, text=True, timeout=30)
        (out / "controls.log").write_text(tested.stdout + tested.stderr)
        receipt["test_exit"] = tested.returncode
        match = re.search(r"CHECKS=(\d+) FAILURES=(\d+)\n", tested.stdout)
        if tested.returncode or not match or int(match[2]):
            raise ValueError("actual provider controls failed")
        receipt["checks"] = int(match[1])
        if any(digest(ROOT / name) != pin for name, pin in frozen.items()):
            raise ValueError("source changed during host controls")
        receipt["binary_sha256"] = digest(out / "controls")
        receipt["status"] = "PASS"
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        receipt["error"] = str(exc)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "checks": receipt.get("checks"),
                      "receipt": str(out / "result.json"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
