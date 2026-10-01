#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Prepare a guarded native copy of licensed SB16 source files; no install/VM."""
import argparse
import datetime
import hashlib
import importlib.util
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]
MEDIA_PIN = "343d22f52397a8a18ca1812dd431623d3f330ee35e5f5daec66edf5499e5d154"
PROBE_PIN = "b92aadc704dd86f242b71a4a05050dc81b725cde62605265fe3a116ac783c61d"
EXPORT_PIN = "2835302f7c4f45c69c21c1b7ab34f89445656781d25f10ed43c885d55dd753bf"


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(path, pin=None):
    path = path.resolve(strict=True)
    if not path.is_relative_to(ROOT / "build"):
        raise ValueError("isolated private input required")
    actual = sha(path)
    if pin and actual != pin:
        raise ValueError("pinned producer/asset changed")
    return {"path": str(path), "sha256": actual, "bytes": path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--driver-media", type=Path, required=True)
    parser.add_argument("--probe-result", type=Path, required=True)
    parser.add_argument("--native-exports", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("absent isolated build required")
    try:
        if shutil.disk_usage(ROOT).free <= 19 * 1024 ** 3:
            raise ValueError("19GiB audio build floor reached")
        inputs = [record(args.driver_media, MEDIA_PIN), record(args.probe_result, PROBE_PIN), record(args.native_exports, EXPORT_PIN)]
        media = json.loads(args.driver_media.read_text())
        probe = json.loads(args.probe_result.read_text())
        exports = json.loads(args.native_exports.read_text())
        if (media.get("status") != "PASS_LICENSED_LOCAL_DRIVER_COPYLIST_EXTRACT_ONLY" or media.get("driver_installed") is not False or
                probe.get("status") != "PASS_BUILD_AND_PCM_ONLY" or probe.get("native_executed") is not False or exports.get("status") != "PASS"):
            raise ValueError("exact compile/readback-only producers required")
        expected = set(media["copylist"]) | {"SB16AWE.INF"}
        if len(expected) != 13 or len(media["files"]) != 13:
            raise ValueError("exact licensed 12-driver/one-INF copy set required")
        members = []
        for item in media["files"]:
            path = Path(item["path"])
            if path.is_symlink() or path.parent.resolve() != args.driver_media.resolve().parent / "files" or path.name not in expected:
                raise ValueError("original confined file set required")
            checked = record(path, item["sha256"])
            if checked["bytes"] != item["bytes"]:
                raise ValueError("licensed source length changed")
            members.append(checked); inputs.append(checked)
        if {Path(item["path"]).name for item in members} != expected:
            raise ValueError("duplicate/missing original driver source")
        for name, pin in probe["sources"].items():
            if sha(ROOT / name) != pin or sha(args.probe_result.resolve().parent / "frozen" / name) != pin:
                raise ValueError("current/frozen compiled PCM source changed")
        cc = shutil.which("i686-w64-mingw32-gcc")
        if not cc or sha(Path(cc)) != probe["compiler"]["sha256"]:
            raise ValueError("same existing compiler required")
        source_names = ("tools/build_native_audio_stage.py", "tools/build_native_audio_probe.py", "remote/guest/native_audio_stage.c",
                        "shizukufs/v1/tools/sha256.c", "shizukufs/v1/tools/sha256.h", "platform/freestanding/memory.c", "platform/freestanding/memory.h")
        sources = {name: sha(ROOT / name) for name in source_names}
        spec = importlib.util.spec_from_file_location("audio_build", ROOT / "tools/build_native_audio_probe.py")
        helper = importlib.util.module_from_spec(spec); spec.loader.exec_module(helper)
        item = next(m for m in exports["modules"] if m["module"] == "KERNEL32.DLL")
        checked, k32 = helper.native_module(item); inputs.append(checked)
        for item in probe["artifacts"].values():
            checked = record(Path(item["path"]), item["sha256"])
            if checked["bytes"] != item["bytes"]:
                raise ValueError("compiled PCM artifact length changed")
            inputs.append(checked)
    except (OSError, KeyError, ValueError, StopIteration) as error:
        parser.error(str(error))
    out.mkdir(parents=True)
    for name, pin in sources.items():
        dest = out / "frozen" / name; dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
        if sha(dest) != pin: raise ValueError("source changed while freezing")
    packed = bytearray(); catalog = []
    for item in sorted(members, key=lambda i: Path(i["path"]).name.upper()):
        name = Path(item["path"]).name.upper()
        catalog.append(dict(item, guest="C:\\VXDLAB\\SBAUDIO\\" + name, offset=len(packed)))
        packed += Path(item["path"]).read_bytes()
    if len(packed) != 305153:
        raise ValueError("exact original local source byte budget required")
    bundle = out / "SBDRVS.BIN"; bundle.write_bytes(packed)
    header = out / "audio_stage_pins.h"
    header.write_text('/* Fixed original licensed local source set; no runtime path metadata. */\n'
                      '#define AUDIO_SOURCE_DIRECTORY "C:\\\\VXDLAB\\\\SBAUDIO"\n'
                      '#define AUDIO_BUNDLE_PATH "C:\\\\VXDLAB\\\\SBDRVS.BIN"\n'
                      '#define AUDIO_BUNDLE_SHA ' + json.dumps(sha(bundle)) + '\n'
                      '#define AUDIO_BUNDLE_BYTES ' + str(len(packed)) + '\n#define AUDIO_FILE_COUNT 13\n'
                      'static const struct { const char *path, *sha256; DWORD offset, bytes; } audio_files[AUDIO_FILE_COUNT] = {\n' +
                      ',\n'.join('{' + ','.join((json.dumps(i["guest"]), json.dumps(i["sha256"]), str(i["offset"]), str(i["bytes"]))) + '}' for i in catalog) + '\n};\n')
    command = [cc] + helper.COMMON + ["-I", str(out), "-I", str(out / "frozen/shizukufs/v1/tools"),
               str(out / "frozen/remote/guest/native_audio_stage.c"), str(out / "frozen/shizukufs/v1/tools/sha256.c"),
               str(out / "frozen/platform/freestanding/memory.c"), "-o", str(out / "AUDSTG.EXE"), "-lkernel32"]
    receipt = {"schema": "win98modern.native-audio-stage-build.v1", "status": "FAIL", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "native_executed": False, "driver_installed": False, "audio_playback_proven": False,
               "sources": sources, "inputs": inputs, "licensed_source_catalog": catalog,
               "bundle": record(bundle), "generated_header": record(header), "command": command,
               "compiler": probe["compiler"], "artifacts": {}}
    try:
        helper.check_space()
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out / "build.log").write_text(result.stdout + result.stderr)
        receipt["compile_exit"] = result.returncode
        if result.returncode:
            raise ValueError("strict OEM-only source stager compilation failed")
        receipt["artifacts"]["AUDSTG.EXE"] = helper.artifact(out / "AUDSTG.EXE", {"KERNEL32.DLL": k32})
        for name, item in probe["artifacts"].items():
            dest = out / name; shutil.copyfile(item["path"], dest)
            checked = record(dest, item["sha256"])
            receipt["artifacts"][name] = checked
        for name, pin in sources.items():
            if sha(ROOT / name) != pin or sha(out / "frozen" / name) != pin:
                raise ValueError("stage source changed during build")
        for item in inputs:
            checked = record(Path(item["path"]), item["sha256"])
            if checked["bytes"] != item["bytes"]: raise ValueError("stage producer changed")
        receipt["status"] = "PASS_PREPARATION_NOT_NATIVE_INSTALL"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        receipt["error"] = str(error)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt["status"] == "PASS_PREPARATION_NOT_NATIVE_INSTALL":
        manifest = {"schema": 1, "kind": "isolated-guest-file-inputs",
                    "inputs": [dict(source=item["path"], guest="C:\\VXDLAB\\" + name, bytes=item["bytes"], sha256=item["sha256"])
                               for name, item in receipt["artifacts"].items()] +
                              [{"source": str(bundle), "guest": "C:\\VXDLAB\\SBDRVS.BIN", "bytes": len(packed), "sha256": sha(bundle)}],
                    "outputs": ["C:\\VXDLAB\\AUDSTG.LOG", "C:\\VXDLAB\\AUDTONE.LOG", "C:\\VXDLAB\\AUDWATCH.LOG"],
                    "backups": ["C:\\WINDOWS\\SYSTEM.DAT", "C:\\WINDOWS\\USER.DAT", "C:\\WINDOWS\\SYSTEM.INI", "C:\\WINDOWS\\WIN.INI"],
                    "source_receipts": [{"path": str(out / "result.json"), "sha256": sha(out / "result.json")}],
                    "commands": ["C:\\VXDLAB\\AUDSTG.EXE", "MANUAL_NATIVE_HAVE_DISK_C:\\VXDLAB\\SBAUDIO_REQUIRED", "COLD_OWNED_REBOOT_REQUIRED", "C:\\VXDLAB\\AUDWATCH.EXE"],
                    "scope": "Exact original licensed SB16 source copy, separate clone-only native driver install, then actual WINMM/child/WAV proof"}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(out / "result.json"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS_PREPARATION_NOT_NATIVE_INSTALL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
