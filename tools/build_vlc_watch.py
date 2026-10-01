#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build an OEM-only fixed-path VLC native process observer; no guest actions."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--native-exports", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        p.error("new isolated repository output required")
    native_document = json.loads(args.native_exports.read_text())
    if native_document.get("status") != "PASS":
        p.error("successful actual OEM export readback required")
    native = {}
    for item in native_document["modules"]:
        if sha(Path(item["path"])) != item["sha256"]:
            p.error("OEM readback changed")
        native[item["module"].upper()] = {s["name"] for s in item["exports"] if s["name"]}
    cc = shutil.which("i686-w64-mingw32-gcc")
    if not cc:
        p.error("existing cross compiler required")
    source_names = ("remote/guest/vlc_app_watch.c", "tools/build_vlc_watch.py",
                    "tools/build_vlc_prerequisites.py", "platform/freestanding/memory.c",
                    "platform/freestanding/memory.h")
    sources = {name: sha(ROOT / name) for name in source_names}
    out.mkdir(parents=True)
    for name in sources:
        dest = out / "frozen" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
        if sha(dest) != sources[name]:
            raise ValueError("observer source changed while freezing")
    command = [cc, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
               "-fno-builtin", "-nostdlib", "-Wl,--no-insert-timestamp", "-Wl,--entry,_entry@0",
               "-Wl,--subsystem,windows:4.10", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
               str(out / "frozen/remote/guest/vlc_app_watch.c"),
               str(out / "frozen/platform/freestanding/memory.c"),
               "-o", str(out / "VLCWATCH.EXE"), "-lkernel32", "-luser32"]
    receipt = {"schema": "win98modern.vlc-native-observer-build.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "native_execution": False,
               "sources": sources, "command": command,
               "native_exports": {"path": str(args.native_exports.resolve()), "sha256": sha(args.native_exports)},
               "compiler": {"path": cc, "sha256": sha(Path(cc))}}
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out / "build.log").write_text(result.stdout + result.stderr)
        receipt["compile_exit"] = result.returncode
        if result.returncode:
            raise ValueError("strict native observer compile failed")
        spec = importlib.util.spec_from_file_location("vlc_build", ROOT / "tools/build_vlc_prerequisites.py")
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        receipt["artifact"] = build.artifact(out / "VLCWATCH.EXE", native)
        if any(sha(ROOT / name) != pin for name, pin in sources.items()):
            raise ValueError("observer source changed during build")
        receipt["status"] = "PASS"
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        receipt["error"] = str(exc)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(out / "result.json"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
