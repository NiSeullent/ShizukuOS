#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build a fixed-path VLC KernelEx settings guard; never execute it in a guest."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import re
import shutil
import subprocess
from pathlib import Path
import pefile

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha", required=True)
    parser.add_argument("--native-exports", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    manifest = args.manifest.resolve(strict=True)
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("new isolated repository build output required")
    if sha(manifest) != args.manifest_sha:
        parser.error("frozen official VLC manifest changed")
    data = json.loads(manifest.read_text())
    paths, image_pins = [], {}
    for item in data["inputs"]:
        guest = item["guest"]
        if not guest.upper().startswith("C:\\VLCLAB\\VLC\\") or not guest.lower().endswith((".dll", ".exe")):
            continue
        if not re.fullmatch(r"C:\\VLCLAB\\VLC\\[A-Za-z0-9_\\.]+", guest) or ".." in guest or len(guest) > 240:
            parser.error("exact bounded VLC image paths required")
        path = Path(item["source"]).resolve(strict=True)
        if path.stat().st_size != item["bytes"] or sha(path) != item["sha256"]:
            parser.error("official VLC image changed")
        with pefile.PE(str(path)) as image:
            if (image.FILE_HEADER.Machine, image.OPTIONAL_HEADER.Magic) != (0x14c, 0x10b):
                parser.error("actual original PE32 x86 VLC image required")
        paths.append(guest.upper()); image_pins[str(path)] = item["sha256"]
    if len(paths) != 21 or len(set(paths)) != 21:
        parser.error("exact selected21 official VLC image paths required")
    cc = shutil.which("i686-w64-mingw32-gcc")
    if not cc:
        parser.error("existing cross compiler required")
    source_names = ("remote/guest/vlc_app_modes.c", "platform/freestanding/memory.c",
                    "platform/freestanding/memory.h", "tools/build_vlc_modes.py",
                    "tools/build_vlc_prerequisites.py")
    sources = {name: sha(ROOT / name) for name in source_names}
    native_document = json.loads(args.native_exports.read_text())
    if native_document.get("status") != "PASS":
        parser.error("actual native OEM export receipt required")
    native = {}
    for item in native_document["modules"]:
        if sha(Path(item["path"])) != item["sha256"]:
            parser.error("actual native OEM readback changed")
        native[item["module"].upper()] = {symbol["name"] for symbol in item["exports"] if symbol["name"]}
    out.mkdir(parents=True)
    for name in sources:
        target = out / "frozen" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
        if sha(target) != sources[name]: raise ValueError("source changed while freezing")
    header = out / "vlc_paths.h"
    header.write_text("/* Fixed official21 image paths; no wildcard. */\n#define MAX_VLC_PATHS 21\n"
                      "static const char *const vlc_paths[MAX_VLC_PATHS] = {\n" +
                      ",\n".join(json.dumps(path) for path in sorted(paths)) + "\n};\n")
    receipt = {"schema": "win98modern.vlc-app-modes-build.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "native_execution": False, "guest_registry_modified": False,
               "manifest": {"path": str(manifest), "sha256": args.manifest_sha},
               "sources": sources, "exact_guest_paths": sorted(paths), "official_images": image_pins,
               "generated_header_sha256": sha(header),
               "compiler": {"path": cc, "sha256": sha(Path(cc))},
               "native_exports": {"path": str(args.native_exports.resolve()), "sha256": sha(args.native_exports)}}
    command = [cc, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
               "-fno-builtin", "-nostdlib", "-Wl,--no-insert-timestamp",
               "-Wl,--entry,_entry@0", "-Wl,--subsystem,windows:4.10",
               "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-I", str(out),
               str(out / "frozen/remote/guest/vlc_app_modes.c"),
               str(out / "frozen/platform/freestanding/memory.c"),
               "-o", str(out / "VLCMODE.EXE"), "-lkernel32", "-ladvapi32"]
    receipt["command"] = command
    try:
        p = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out / "build.log").write_text(p.stdout + p.stderr)
        receipt["compile_exit"] = p.returncode
        if p.returncode: raise ValueError("strict native guard compile failed")
        spec = importlib.util.spec_from_file_location("vlc_build", ROOT / "tools/build_vlc_prerequisites.py")
        builder = importlib.util.module_from_spec(spec); spec.loader.exec_module(builder)
        receipt["artifact"] = builder.artifact(out / "VLCMODE.EXE", native)
        if any(sha(ROOT / name) != pin for name, pin in sources.items()) or sha(manifest) != args.manifest_sha:
            raise ValueError("guard source/manifest changed during build")
        receipt["status"] = "PASS"
    except (OSError, ValueError, subprocess.TimeoutExpired, pefile.PEFormatError) as exc:
        receipt["error"] = str(exc)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(out / "result.json"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
