#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Build two isolated GUI WINMM probes and test their actual PCM generator.

This does not install a driver, boot a VM, emit host sound, or establish native
playback. The prepared observer needs a separately verified native endpoint and
an independently analyzed QEMU WAV capture.
"""
import argparse
import datetime
import hashlib
import json
import shutil
import subprocess
from pathlib import Path

import numpy as np
import pefile

ROOT = Path(__file__).resolve().parents[1]
BUILD_FLOOR = 19 * 1024 ** 3
EXPORT_PIN = "2835302f7c4f45c69c21c1b7ab34f89445656781d25f10ed43c885d55dd753bf"
AUDIO_PIN = "ef849a92eaf40dc5c2199d4426b8dfea9280202361873aaeca6327155a33df9d"
WINMM_PIN = "2dd6ab7ebc50703f7b09b527b508450a354aea27912f2bf5e2a10072333004de"
SOURCES = ("tools/build_native_audio_probe.py", "remote/guest/native_audio_pcm.h",
           "remote/guest/native_audio_probe.c", "remote/guest/native_audio_watch.c",
           "platform/freestanding/memory.c", "platform/freestanding/memory.h")
COMMON = ["-std=c11", "-march=i486", "-Os", "-Wall", "-Wextra", "-Werror",
          "-fno-builtin", "-nostdlib", "-Wl,--no-insert-timestamp",
          "-Wl,--entry,_entry@0", "-Wl,--subsystem,windows:4.10",
          "-Wl,--disable-dynamicbase", "-Wl,--disable-nxcompat",
          "-Wl,--disable-tsaware"]


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 ** 2), b""):
            h.update(block)
    return h.hexdigest()


def record(path, pin=None):
    path = path.resolve(strict=True)
    if not path.is_relative_to(ROOT / "build") or not path.is_file():
        raise ValueError("isolated local receipt/readback required")
    actual = digest(path)
    if pin is not None and actual != pin:
        raise ValueError("pinned native input changed")
    return {"path": str(path), "bytes": path.stat().st_size, "sha256": actual}


def check_space():
    free = shutil.disk_usage(ROOT).free
    if free <= BUILD_FLOOR:
        raise ValueError("audio build paused: measured free space at/below 19 GiB")
    return free


def native_module(item):
    checked = record(Path(item["path"]), item["sha256"])
    if checked["bytes"] != item["bytes"]:
        raise ValueError("native module length changed")
    with pefile.PE(checked["path"]) as pe:
        actual = {s.name.decode("ascii") for s in pe.DIRECTORY_ENTRY_EXPORT.symbols if s.name}
    claimed = {s["name"] for s in item["exports"] if s["name"]}
    if claimed != actual:
        raise ValueError("native export inventory does not match readback PE")
    return checked, actual


def artifact(path, native):
    with pefile.PE(str(path)) as pe:
        o = pe.OPTIONAL_HEADER
        if (pe.FILE_HEADER.Machine, o.Magic, o.Subsystem,
                o.MajorSubsystemVersion, o.MinorSubsystemVersion,
                o.MajorOperatingSystemVersion, o.MinorOperatingSystemVersion) != (0x14c, 0x10b, 2, 4, 10, 4, 0):
            raise ValueError("i386 PE32 native GUI4.10/OS4.0 required")
        if o.DllCharacteristics & 0x140 or any(o.DATA_DIRECTORY[i].VirtualAddress for i in (9, 10, 13, 14)):
            raise ValueError("unexpected modern runtime/PE directories")
        imports = {}
        for module in getattr(pe, "DIRECTORY_ENTRY_IMPORT", ()):
            name = module.dll.decode("ascii").upper()
            if name not in ("KERNEL32.DLL", "WINMM.DLL"):
                raise ValueError("audio probe imports outside original KERNEL32/WINMM")
            imports[name] = []
            for symbol in module.imports:
                if symbol.name is None or symbol.name.decode("ascii") not in native[name]:
                    raise ValueError("import unavailable in licensed actual OEM readback")
                imports[name].append(symbol.name.decode("ascii"))
        return dict(record(path), imports=imports, native_import_gate="PASS", native_executed=False)


def pcm_test(out, cc, run):
    # Include the same frozen function compiled into AUDTONE, then independently
    # inspect the emitted samples. No waveOut mock substitutes for native proof.
    source = out / "pcm_host.c"
    source.write_text('#include <stdio.h>\n#include <stdlib.h>\n#include "native_audio_pcm.h"\n'
                      'int main(void) { int16_t guard[3]={123,456,789};\n'
                      'audio_pcm_fill(&guard[1],0); if(guard[0]!=123||guard[1]!=456||guard[2]!=789)return 2;\n'
                      'int16_t *p=malloc(AUDIO_FRAMES*sizeof(*p));if(!p)return 3;\n'
                      'audio_pcm_fill(p,AUDIO_FRAMES);size_t n=fwrite(p,sizeof(*p),AUDIO_FRAMES,stdout);\n'
                      'free(p);return n==AUDIO_FRAMES?0:4;}\n')
    command = [cc, "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
               "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
               "-fno-omit-frame-pointer", "-I",
               str(out / "frozen/remote/guest"), str(source), "-o", str(out / "pcm_host")]
    run(command)
    raw = out / "generated-pcm.raw"
    with raw.open("wb") as samples, (out / "pcm-host.log").open("wb") as errors:
        result = subprocess.run([str(out / "pcm_host")], stdout=samples, stderr=errors, timeout=30)
    if result.returncode or (out / "pcm-host.log").stat().st_size:
        raise ValueError("actual generator sanitized host execution failed")
    data = np.frombuffer(raw.read_bytes(), dtype="<i2").astype(np.float64)
    spectrum = np.abs(np.fft.rfft(data))
    peak = int(np.argmax(spectrum[1:])) + 1
    peak_hz = peak * 22050 / len(data)
    checks = {"exact_110250_frames": len(data) == 110250, "exact_220500_bytes": raw.stat().st_size == 220500,
              "exact_five_seconds": len(data) / 22050 == 5,
              "first_and_last_samples_zero": data[0] == 0 and data[-1] == 0,
              "contains_both_polarities": data.min() < -9000 and data.max() > 9000,
              "bounded_amplitude": max(abs(data.min()), abs(data.max())) <= 10000,
              "nonzero_rms": 6500 < np.sqrt(np.mean(data ** 2)) < 7200,
              "near_zero_dc": abs(data.mean()) < 2,
              "dominant_frequency_440_hz": abs(peak_hz - 440) < 0.21,
              "dominant_tone_exceeds_other_bins": spectrum[peak] > 10 * np.max(np.delete(spectrum, peak)),
              "asan_ubsan_actual_generator_exit_zero": result.returncode == 0,
              "no_sanitizer_runtime_diagnostics": (out / "pcm-host.log").stat().st_size == 0}
    checks = {name: bool(value) for name, value in checks.items()}
    if not all(checks.values()):
        raise ValueError("generated PCM signal contract failed: " + json.dumps(checks))
    return {"scope": "Actual generator only; no native WINMM/QEMU playback", "checks": checks,
            "sample_rate": 22050, "seconds": 5, "peak_hz": peak_hz, "rms": float(np.sqrt(np.mean(data ** 2))),
            "raw": record(raw), "host_command": command, "host_source": record(source),
            "host_binary": record(out / "pcm_host"), "host_runtime_log": record(out / "pcm-host.log"),
            "numpy_version": np.__version__}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-exports", required=True, type=Path)
    parser.add_argument("--audio-oem", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("absent private output required")
    try:
        free = check_space()
        inputs = [record(args.native_exports, EXPORT_PIN), record(args.audio_oem, AUDIO_PIN)]
        exports = json.loads(args.native_exports.read_text())
        audio = json.loads(args.audio_oem.read_text())
        if exports.get("status") != "PASS" or audio.get("guest_modified") is not False:
            raise ValueError("pinned native readback receipts required")
        native = {}
        selected = next(item for item in exports["modules"] if item["module"] == "KERNEL32.DLL")
        checked, native["KERNEL32.DLL"] = native_module(selected)
        inputs.append(checked)
        if audio["native_exports"]["sha256"] != WINMM_PIN:
            raise ValueError("exact licensed WINMM readback required")
        checked, native["WINMM.DLL"] = native_module(audio["native_exports"])
        inputs.append(checked)
        cc, host = shutil.which("i686-w64-mingw32-gcc"), shutil.which("clang")
        if not cc or not host:
            raise ValueError("existing MinGW and sanitized host compiler required")
        sources = {name: digest(ROOT / name) for name in SOURCES}
    except (OSError, ValueError, KeyError, StopIteration) as error:
        parser.error(str(error))
    out.mkdir(parents=True)
    for name, pin in sources.items():
        dest = out / "frozen" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
        if digest(dest) != pin:
            raise ValueError("source changed while freezing")
    receipt = {"schema": "win98modern.native-audio-probe-build.v1", "status": "FAIL",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "native_executed": False,
               "audio_playback_proven": False, "guest_modified": False, "sources": sources, "inputs": inputs,
               "compiler": {"path": cc, "sha256": digest(Path(cc))},
               "host_compiler": {"path": host, "sha256": digest(Path(host))},
               "free_before": free, "required_build_floor": BUILD_FLOOR, "steps": [], "artifacts": {}}
    def run(command):
        check_space()
        with (out / "build.log").open("a") as log:
            log.write(json.dumps(command) + "\n"); log.flush()
            result = subprocess.run(command, stdout=log, stderr=log, timeout=120)
        receipt["steps"].append({"command": command, "exit_code": result.returncode})
        if result.returncode:
            raise ValueError("strict compiler failed; immutable log retained")
    try:
        for output, source, libraries in (("AUDTONE.EXE", "native_audio_probe.c", ["kernel32", "winmm"]),
                                          ("AUDWATCH.EXE", "native_audio_watch.c", ["kernel32"])):
            run([cc] + COMMON + [str(out / "frozen/remote/guest" / source),
                str(out / "frozen/platform/freestanding/memory.c"), "-o", str(out / output)] +
                ["-l" + library for library in libraries])
            receipt["artifacts"][output] = artifact(out / output, native)
        receipt["pcm_generator"] = pcm_test(out, host, run)
        for name, pin in sources.items():
            if digest(ROOT / name) != pin or digest(out / "frozen" / name) != pin:
                raise ValueError("audio source changed during build")
        for item in inputs:
            record(Path(item["path"]), item["sha256"])
        receipt["free_after"] = check_space()
        receipt["status"] = "PASS_BUILD_AND_PCM_ONLY"
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        receipt["error"] = str(error)
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if receipt["status"] == "PASS_BUILD_AND_PCM_ONLY":
        manifest = {"schema": 1, "kind": "isolated-guest-file-inputs",
                    "inputs": [dict(source=item["path"], guest="C:\\VXDLAB\\" + name,
                                    bytes=item["bytes"], sha256=item["sha256"])
                               for name, item in receipt["artifacts"].items()],
                    "outputs": ["C:\\VXDLAB\\AUDTONE.LOG", "C:\\VXDLAB\\AUDWATCH.LOG"],
                    "backups": [], "source_receipts": [{"path": str(out / "result.json"),
                                                              "sha256": digest(out / "result.json")}],
                    "command": "C:\\VXDLAB\\AUDWATCH.EXE",
                    "scope": "Actual native waveOut device/tone child; driver and WAV-backend evidence separately required"}
        (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "result": str(out / "result.json"), "error": receipt.get("error")}))
    return 0 if receipt["status"] == "PASS_BUILD_AND_PCM_ONLY" else 1


if __name__ == "__main__":
    raise SystemExit(main())
