#!/usr/bin/env python3
"""Compile original and ported RunLoopWin.cpp against actual pinned WTF headers.

Copyright (c) 2026 IEWebKit contributors. SPDX-License-Identifier: MIT
This focused Windows-event-loop profile is separate from JSCOnly's Generic
event-loop profile. No substitute WTF types or host Linux ICU libraries are used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

HERE = Path(__file__).resolve().parent


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--original", type=Path, required=True)
    parser.add_argument("--cc", default="i686-w64-mingw32-g++")
    args = parser.parse_args()
    work = args.work.resolve()
    pin = json.loads((HERE / "source-pin.json").read_text())
    source = work / "webkitgtk-2.54.0"
    patched = source / pin["upstream_file"]
    original = args.original.resolve()
    if digest(original) != pin["upstream_sha256"] or digest(patched) != pin["modified_sha256"]:
        raise ValueError("Original and modified engine translation units must match reviewed pins")
    output = work / "focused-runloop"
    output.mkdir(parents=True, exist_ok=True)
    original_copy = output / "RunLoopWin.original.cpp"
    shutil.copyfile(original, original_copy)
    icu_headers = work / "icu-work/icu/source/common"
    if not (icu_headers / "unicode/uversion.h").is_file():
        raise ValueError("Restore pinned ICU source headers before compiling the real engine file")
    flags = ["-std=c++23", "-Os", "-g0", "-march=pentium3", "-ffunction-sections",
             "-fdata-sections", "-fno-strict-aliasing", "-DBUILDING_WTF", "-DUNICODE", "-D_UNICODE",
             "-DWINVER=0x0410", "-D_WIN32_WINDOWS=0x0410", "-D_WIN32_WINNT=0x0400",
             "-DNTDDI_VERSION=0x04000000", "-DIEWEBKIT_WIN9X=1", "-DENABLE_JIT=0",
             "-DENABLE_C_LOOP=1", "-DENABLE_WEBASSEMBLY=0", "-DUSE_MIMALLOC=1",
             "-DUSE_SYSTEM_MALLOC=0", "-DU_STATIC_IMPLEMENTATION", "-DWTF_DEFAULT_EVENT_LOOP=1"]
    for include in [source / "Source/WTF", source / "Source/bmalloc", icu_headers]:
        flags.extend(["-I", str(include)])
    receipt = {"schema": "iewebkit-actual-runloop-object-v1", "source_commit": pin["upstream_commit"],
               "profile": "Win9x x86 Windows event loop, upstream default config headers",
               "real_WTF_headers": True, "linked_WTF_archive": False, "engine_provider": False,
               "guest_execution": "NOT-VERIFIED", "completed": False, "profiles": {}}
    profiles = [("original", original_copy, True), ("ported", patched, True),
                ("generic-layout-negative", patched, False)]
    for name, translation_unit, expected_success in profiles:
        obj = output / (name + ".obj")
        profile_flags = flags
        if not expected_success:
            # Reproduce the unmodified JSCOnly profile's real RunLoop layout.
            profile_flags = [flag for flag in flags if flag != "-DWTF_DEFAULT_EVENT_LOOP=1"]
            profile_flags += ["-DBUILDING_JSCONLY__", "-DWTF_DEFAULT_EVENT_LOOP=0", "-DUSE_GENERIC_EVENT_LOOP=1"]
        command = [args.cc, *profile_flags, "-c", str(translation_unit), "-o", str(obj)]
        result = subprocess.run(command, text=True, capture_output=True)
        log = output / (name + ".log")
        log.write_text(result.stdout + result.stderr)
        profile = {"argv": command, "returncode": result.returncode,
                   "expected_compile_success": expected_success,
                   "gate": "PASS" if (result.returncode == 0) == expected_success else "FAIL",
                   "translation_unit_sha256": digest(translation_unit), "log_sha256": digest(log)}
        receipt["profiles"][name] = profile
        if not result.returncode:
            symbols = subprocess.check_output(["i686-w64-mingw32-nm", "-u", str(obj)], text=True)
            (output / (name + ".undefined.txt")).write_text(symbols)
            profile.update({"object_sha256": digest(obj), "bytes": obj.stat().st_size,
                            "windows_imports": sorted(line.split()[-1] for line in symbols.splitlines()
                                                      if "__imp_" in line)})
        (output / "objects.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(name + ": " + profile["gate"] + " (compiler exit " + str(result.returncode) + ")")
    failed = any(p["gate"] != "PASS" for p in receipt["profiles"].values())
    receipt["completed"] = True
    receipt["gate"] = "FAIL" if failed else "PASS"
    (output / "objects.json").write_text(json.dumps(receipt, indent=2) + "\n")
    (output / "objects-verified.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
