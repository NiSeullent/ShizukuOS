#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze/build one GUI-only diagnostic for the exact official VLC Qt module."""
import argparse
import datetime
import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pefile

ROOT = Path(__file__).resolve().parents[1]
TRIAL_PIN = "872106f97ac0f5e032ebb1ad13c6c18ac995d9a0d10762ef3d027bf1c8f8226f"
QT_PIN = "4365daa473571a837460c4c1fa1ea4b28407a980b823f8a2fecbf4d407cd4775"
CORE_PIN = "934b1652ddf63eaaa4c9418e61d105ec5d256f1e90596e0552d2bf160578907a"
PROVIDER_PINS = {
    "M98VLC.DLL": "fdac81d881f6781216a6bc77d42313eadeb9dd249a6e0dfc395aaa4efe2d9a1b",
    "M98LOC.DLL": "8c5e00fcb59979b4dc5db83bf287ded004661210d6efc9ad0ddb99a6cc9e5337",
    "M98CTX.DLL": "315fd4a37e5beecf8d99ad37e012126faa6adbbb6106fd7474c24a014b4d4a61",
}
CANDIDATES = {
    "GDI32.DLL": {"AddFontMemResourceEx", "AddFontResourceExW", "RemoveFontMemResourceEx", "RemoveFontResourceExW"},
    "KERNEL32.DLL": {"CheckRemoteDebuggerPresent", "GetConsoleWindow", "GetGeoInfoW", "GetNativeSystemInfo",
                     "GetUserDefaultUILanguage", "GetUserGeoID", "IsValidLanguageGroup", "SetFilePointerEx"},
    "USER32.DLL": {"RealGetWindowClassW"},
}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(path, pin=None):
    path = path.resolve(strict=True)
    if not path.is_relative_to(ROOT / "build"):
        raise ValueError("private repository build input required")
    actual = digest(path)
    if pin and actual != pin:
        raise ValueError("exact input SHA changed: " + str(path))
    return {"path": str(path), "sha256": actual, "bytes": path.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trial-manifest", required=True, type=Path)
    parser.add_argument("--native-exports", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("absent isolated output required")
    trial_record = record(args.trial_manifest, TRIAL_PIN)
    trial = json.loads(args.trial_manifest.read_text())
    if trial.get("staging_prefix") != "VLCLAB" or trial.get("outputs") != [] or len(trial["inputs"]) != 47:
        parser.error("exact corrected47-input VLC fixture required")
    inputs, pins = {}, [trial_record, record(args.native_exports)]
    protocol = ROOT / "build/app-prerequisites-20260930/sources/KernelEx-31cdfc3560fc116637ee8ed7be31b12f3aacf5d1"
    protocol_pins = [record(protocol / name) for name in ("common/kexcoresdk.h", "core/kexcoresdk.cpp", "core/SettingsDB.cpp", "core/resolver.cpp", "core/resolver.h",
                                                       "core/apiconfmgr.cpp", "core/apiconf.cpp", "core/apilib.cpp")]
    pins += protocol_pins
    for item in trial["inputs"]:
        source = Path(item["source"])
        if not source.resolve(strict=True).is_relative_to(args.trial_manifest.resolve().parent):
            parser.error("confined trial asset required")
        checked = record(source, item["sha256"])
        if checked["bytes"] != item["bytes"]:
            parser.error("trial byte count changed")
        inputs[item["guest"].replace("\\\\", "\\").upper()] = checked
        pins.append(checked)
    def asset(guest, pin=None):
        item = inputs[guest.upper()]
        if pin and item["sha256"] != pin:
            raise ValueError("wrong selected diagnostic asset")
        return item
    qt = asset(r"C:\VLCLAB\VLC\plugins\gui\libqt_plugin.dll", QT_PIN)
    core = asset(r"C:\VLCLAB\CORE.NEW", CORE_PIN)
    pe = pefile.PE(qt["path"])
    if pe.FILE_HEADER.Machine != 0x14c or pe.OPTIONAL_HEADER.Magic != 0x10b:
        parser.error("original Qt PE32 required")
    modules, imports, found_candidates = [], [], set()
    for descriptor in pe.DIRECTORY_ENTRY_IMPORT:
        name = descriptor.dll.decode("ascii").upper()
        path = r"C:\VLCLAB\VLC\libvlccore.dll" if name == "LIBVLCCORE.DLL" else name
        index = len(modules)
        modules.append({"name": name, "path": path})
        for item in descriptor.imports:
            if item.name is None:
                parser.error("unexpected Qt ordinal import")
            symbol = item.name.decode("ascii")
            candidate = symbol in CANDIDATES.get(name, ())
            imports.append({"module": index, "name": symbol, "candidate": int(candidate)})
            if candidate:
                found_candidates.add((name, symbol))
    pe.close()
    if len(modules) != 13 or len(imports) != 653 or len(found_candidates) != 13:
        parser.error("exact13-module/653-import/13-candidate diagnostic profile required")
    native_document = json.loads(args.native_exports.read_text())
    if native_document.get("status") != "PASS":
        parser.error("actual successful OEM export readback required")
    native = {}
    for item in native_document["modules"]:
        checked = record(Path(item["path"]), item["sha256"])
        if checked["bytes"] != item["bytes"]:
            parser.error("OEM readback length changed")
        pins.append(checked)
        native[item["module"].upper()] = {symbol["name"] for symbol in item["exports"] if symbol["name"]}
    compiler = shutil.which("i686-w64-mingw32-gcc")
    if not compiler:
        parser.error("existing cross compiler required")
    source_names = ("remote/guest/vlc_qt_load_probe.c", "tools/build_vlc_qt_probe.py", "tools/build_vlc_prerequisites.py",
                    "shizukufs/v1/tools/sha256.c", "shizukufs/v1/tools/sha256.h",
                    "platform/freestanding/memory.c", "platform/freestanding/memory.h")
    sources = {name: digest(ROOT / name) for name in source_names}
    guest_pins = [(r"C:\VLCLAB\VLC\plugins\gui\libqt_plugin.dll", qt),
                  (r"C:\WINDOWS\KernelEx\CORE.INI", core),
                  (r"C:\VLCLAB\VLC\libvlccore.dll", asset(r"C:\VLCLAB\VLC\libvlccore.dll"))]
    for name, pin in PROVIDER_PINS.items():
        guest_pins.append(("C:\\WINDOWS\\KernelEx\\" + name, asset("C:\\VLCLAB\\PROVIDE\\" + name, pin)))
    for item in pins:
        if digest(Path(item["path"])) != item["sha256"]:
            parser.error("input changed before output")
    out.mkdir(parents=True)
    for name, pin in sources.items():
        destination = out / "frozen" / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, destination)
        if digest(destination) != pin:
            raise ValueError("source changed while freezing")
    header = out / "vlc_qt_pins.h"
    header.write_text("/* Exact official inputs; diagnostic function pointers are never invoked. */\n" +
        '#define QT_TARGET "C:\\\\VLCLAB\\\\VLC\\\\plugins\\\\gui\\\\libqt_plugin.dll"\n' +
        "#define QT_PIN_COUNT " + str(len(guest_pins)) + "\n" +
        "static const struct { const char *path, *sha256; DWORD bytes; } qt_pins[QT_PIN_COUNT] = {\n" +
        ",\n".join("{" + ",".join((json.dumps(path), json.dumps(item["sha256"]), str(item["bytes"]))) + "}" for path, item in guest_pins) + "\n};\n" +
        "#define QT_MODULE_COUNT 13\nstatic const struct { const char *name, *path; } qt_modules[QT_MODULE_COUNT] = {\n" +
        ",\n".join("{" + json.dumps(item["name"]) + "," + json.dumps(item["path"]) + "}" for item in modules) + "\n};\n" +
        "#define QT_IMPORT_COUNT 653\nstruct qt_import { unsigned module; const char *name; int candidate; };\n" +
        "static const struct qt_import qt_imports[QT_IMPORT_COUNT] = {\n" +
        ",\n".join("{" + str(item["module"]) + "," + json.dumps(item["name"]) + "," + str(item["candidate"]) + "}" for item in imports) + "\n};\n")
    command = [compiler, "-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror", "-fno-builtin", "-nostdlib",
               "-Wl,--no-insert-timestamp", "-Wl,--entry,_entry@0", "-Wl,--subsystem,windows:4.10",
               "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat", "-I", str(out),
               "-I", str(out / "frozen/shizukufs/v1/tools"), str(out / "frozen/remote/guest/vlc_qt_load_probe.c"),
               str(out / "frozen/shizukufs/v1/tools/sha256.c"), str(out / "frozen/platform/freestanding/memory.c"),
               "-o", str(out / "QTLOAD.EXE"), "-lkernel32", "-ladvapi32"]
    receipt = {"schema": "win98modern.vlc-qt-diagnostic-build.v1", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
               "status": "FAIL", "native_execution": False, "application_success": False, "guest_modified": False,
               "sources": sources, "inputs": pins, "guest_input_pins": guest_pins, "imports": imports, "modules": modules,
               "candidate_imports": sorted(found_candidates), "generated_header_sha256": digest(header), "command": command,
               "original_kernel_ex_protocol_source": protocol_pins,
               "compiler": {"path": compiler, "sha256": digest(Path(compiler))},
               "guest_effects": ["Fresh VXDLAB QTBOOT.LOG/QTWORK.LOG only", "Guarded absent mode values for C:\\VXDLAB\\QTLOAD.EXE only",
                                 "Native LoadLibrary Qt and bounded45s child wait; termination is FAIL; no VLC/CORE/provider byte writes"]}
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        (out / "build.log").write_text(result.stdout + result.stderr)
        receipt["compile_exit"] = result.returncode
        if result.returncode:
            raise ValueError("strict Qt diagnostic compile failed")
        spec = importlib.util.spec_from_file_location("vlc_build", ROOT / "tools/build_vlc_prerequisites.py")
        build = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(build)
        receipt["artifact"] = build.artifact(out / "QTLOAD.EXE", native)
        for item in pins:
            if digest(Path(item["path"])) != item["sha256"]:
                raise ValueError("input changed during build")
        if any(digest(ROOT / name) != pin for name, pin in sources.items()):
            raise ValueError("diagnostic source changed during build")
        receipt["status"] = "PASS"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        receipt["error"] = str(error)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt["status"] == "PASS":
        manifest = {"schema": 1, "kind": "isolated-guest-file-inputs", "inputs": [{"source": str(out / "QTLOAD.EXE"), "guest": "C:\\VXDLAB\\QTLOAD.EXE",
                    "bytes": (out / "QTLOAD.EXE").stat().st_size, "sha256": digest(out / "QTLOAD.EXE")}],
                    "outputs": ["C:\\VXDLAB\\QTBOOT.LOG", "C:\\VXDLAB\\QTWORK.LOG"],
                    "backups": ["C:\\WINDOWS\\SYSTEM.DAT", "C:\\WINDOWS\\USER.DAT"],
                    "source_receipts": [{"path": str(out / "result.json"), "sha256": digest(out / "result.json")}],
                    "commands": ["C:\\VXDLAB\\QTLOAD.EXE"],
                    "scope": "Fixed original Qt resolver diagnostic; guarded new helper mode only; Core/providers/apps unchanged; no GUI/application success inferred"}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(out / "result.json"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
