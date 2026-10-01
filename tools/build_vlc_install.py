#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Compile fixed digest-bound VLC prerequisite installation; never run it."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OLD_SHA = "022289408799526d71661d2c9367b84030de5aadeb7fa5681466655b5acf30ec"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def checked(path, pin=None):
    path = path.resolve(strict=True)
    if not path.is_relative_to(ROOT / "build"):
        raise ValueError("isolated repository build input required")
    actual = digest(path)
    if pin and actual != pin:
        raise ValueError("frozen input changed: " + str(path))
    return {"path": str(path), "sha256": actual, "bytes": path.stat().st_size}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--core-current", required=True, type=Path)
    p.add_argument("--core-new", required=True, type=Path)
    p.add_argument("--core-receipt", required=True, type=Path)
    p.add_argument("--provider-build", required=True, type=Path)
    p.add_argument("--native-exports", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        p.error("new isolated repository output required")
    current = checked(args.core_current, OLD_SHA)
    core_document = json.loads(args.core_receipt.read_text())
    new = checked(args.core_new, core_document["output_sha256"])
    if (core_document.get("status") != "PASS" or
            core_document["input_sha256"] != OLD_SHA or
            Path(core_document["input"]).resolve() != args.core_current.resolve() or
            Path(core_document["output"]).resolve() != args.core_new.resolve() or
            core_document["added"]["libraries"] != ["m98vlc", "m98loc", "m98ctx"] or
            len(core_document["added"]["names"]) != 14 or
            core_document["added"]["ordinals"] or core_document["added"]["replaced"]):
        p.error("exact guarded14-route/3-provider additive CORE merge required")
    checked(Path(core_document["plan"]), core_document["plan_sha256"])
    spec = importlib.util.spec_from_file_location("vlc_build", ROOT / "tools/build_vlc_prerequisites.py")
    build = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(build)
    providers = json.loads(args.provider_build.read_text())
    if (providers.get("schema") != "win98modern.vlc-prerequisite-build.v1" or
            providers.get("status") != "PASS" or providers.get("native_execution") is not False):
        p.error("source-bound compile-only provider receipt required")
    pins = []
    for name in ("M98VLC.DLL", "M98LOC.DLL", "M98CTX.DLL"):
        item = providers["artifacts"][name]
        record = checked(Path(item["path"]), item["sha256"])
        if record["bytes"] != item["bytes"] or item["native_import_gate"] != "PASS":
            p.error("exact native import-gated DLL required")
        record["name"] = name
        pins.append(record)
    for name, pin in providers["sources"].items():
        if digest(ROOT / name) != pin or digest(args.provider_build.parent / "frozen" / name) != pin:
            p.error("current/frozen provider source changed")
    native_document = json.loads(args.native_exports.read_text())
    if native_document.get("status") != "PASS":
        p.error("successful actual OEM export readbacks required")
    native = {}
    for item in native_document["modules"]:
        checked(Path(item["path"]), item["sha256"])
        native[item["module"].upper()] = {s["name"] for s in item["exports"] if s["name"]}
    cc = shutil.which("i686-w64-mingw32-gcc")
    if not cc:
        p.error("existing cross compiler required")
    source_names = ("remote/guest/vlc_prereq_install.c", "tools/build_vlc_install.py",
                    "tools/build_vlc_prerequisites.py", "shizukufs/v1/tools/sha256.c",
                    "shizukufs/v1/tools/sha256.h", "platform/freestanding/memory.c",
                    "platform/freestanding/memory.h")
    sources = {name: digest(ROOT / name) for name in source_names}
    records = [current, new, checked(args.core_receipt), checked(args.provider_build),
               checked(args.native_exports)] + pins
    out.mkdir(parents=True)
    for name in sources:
        dest = out / "frozen" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
        if digest(dest) != sources[name]:
            raise ValueError("source changed while freezing")
    header = out / "vlc_install_pins.h"
    rows = []
    for item in pins:
        rows.append("{" + ",".join((json.dumps("C:\\VLCLAB\\PROVIDE\\" + item["name"]),
                                    json.dumps("C:\\WINDOWS\\KernelEx\\" + item["name"]),
                                    json.dumps(item["sha256"]), str(item["bytes"]))) + "}")
    header.write_text("/* Exact guarded merge and native-proven provider bytes. */\n" +
                      "#define CORE_DESTINATION \"C:\\\\WINDOWS\\\\KernelEx\\\\CORE.INI\"\n" +
                      "#define CORE_SOURCE \"C:\\\\VLCLAB\\\\CORE.NEW\"\n" +
                      "#define CORE_BACKUP \"C:\\\\VLCLAB\\\\CORE.BAK\"\n" +
                      "#define CORE_OLD_SHA " + json.dumps(OLD_SHA) + "\n" +
                      "#define CORE_NEW_SHA " + json.dumps(new["sha256"]) + "\n" +
                      "#define CORE_OLD_BYTES " + str(current["bytes"]) + "\n" +
                      "#define CORE_NEW_BYTES " + str(new["bytes"]) + "\n" +
                      "static const struct { const char *source, *destination, *sha256; DWORD bytes; } providers[3] = {\n" +
                      ",\n".join(rows) + "\n};\n")
    receipt = {"schema": "win98modern.vlc-prerequisite-installer-build.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "native_execution": False, "guest_modified": False, "sources": sources,
               "inputs": records, "generated_header_sha256": digest(header),
               "compiler": {"path": cc, "sha256": digest(Path(cc))}}
    command = [cc, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
               "-fno-builtin", "-nostdlib", "-Wl,--no-insert-timestamp", "-Wl,--entry,_entry@0",
               "-Wl,--subsystem,windows:4.10", "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
               "-I", str(out), "-I", str(out / "frozen/shizukufs/v1/tools"),
               str(out / "frozen/remote/guest/vlc_prereq_install.c"),
               str(out / "frozen/shizukufs/v1/tools/sha256.c"),
               str(out / "frozen/platform/freestanding/memory.c"),
               "-o", str(out / "VLCINST.EXE"), "-lkernel32"]
    receipt["command"] = command
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out / "build.log").write_text(result.stdout + result.stderr)
        receipt["compile_exit"] = result.returncode
        if result.returncode:
            raise ValueError("strict native prerequisite guard compile failed")
        receipt["artifact"] = build.artifact(out / "VLCINST.EXE", native)
        for item in records:
            if digest(Path(item["path"])) != item["sha256"]:
                raise ValueError("frozen input changed during build")
        if any(digest(ROOT / name) != pin for name, pin in sources.items()):
            raise ValueError("installer source changed during build")
        receipt["status"] = "PASS"
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        receipt["error"] = str(exc)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(out / "result.json"),
                      "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
