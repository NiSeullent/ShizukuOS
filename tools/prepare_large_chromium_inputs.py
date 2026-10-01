#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Stage one exact read-only Chromium structure fixture on a private FAT clone.

This separate policy grants no general large-file exception. The old GOPLAB /
VXDLAB and application stagers keep their original limits. No VM is started.
"""
import argparse
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
BUILD = ROOT / "build"
FIXTURE = BUILD / "chromium-large-native-probe-20261001T0036-v2"
MANIFEST_SHA = "498162fe9acc5ed110ceabcf8a163374ed4126afe98467fed4fc65110b209f01"
PRODUCER_SHA = "70b11508c6965ae2cf3b4dac591c2f70a9157dc99d52ce523e97e41e86212570"
HOST = BUILD / "chromium-large-image-budget-controls-20261001T0003-v3/result.json"
HOST_SHA = "ff1391d152f05ea5ee64b369ddf133f06505f7e48c8f6b7c4ebf596a456d6aa8"
CORE = BUILD / "chromium-large-image-20260930T2336/chrome.dll"
ASSETS = (
    (FIXTURE / "CHRLARGE.EXE", "C:\\CHRLAB\\CHRLARGE.EXE", 28680,
     "c2b14638467626aa1930321c8880d7fd5430cec813ad8f0f4086ac5a1d49ef1a"),
    (FIXTURE / "CHLWAIT.EXE", "C:\\CHRLAB\\CHLWAIT.EXE", 8951,
     "034fdb8f3a1a0e1f83471d6606f092892db622ae862553a3a9bbfd7b50dcad2c"),
    (CORE, "C:\\CHRLAB\\CHROME.DLL", 283207168,
     "f8decffdf2970597ffcab390f583cefeb3f97be697a2422b0a336a2697969158"),
)
OUTPUTS = ["C:\\CHRLAB\\CHRLARGE.LOG", "C:\\CHRLAB\\CHLWAIT.LOG"]
COMMANDS = ["C:\\CHRLAB\\CHLWAIT.EXE"]


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 ** 2), b""):
            digest.update(block)
    return digest.hexdigest()


def _exact_path(value, expected):
    path = Path(value)
    if not path.is_absolute() or path != expected or path.resolve(strict=True) != expected:
        raise ValueError("exact canonical private fixture source required")
    if not path.is_file() or not path.is_relative_to(BUILD):
        raise ValueError("private build file required")
    return path


def _policy(data):
    """Pure metadata validation; no FAT commands or file writes."""
    if (data.get("schema") != 1 or data.get("kind") != "isolated-guest-file-inputs" or
            data.get("staging_prefix") != "CHRLAB" or
            data.get("requires_exact_large_input_staging_policy") is not True or
            data.get("outputs") != OUTPUTS or data.get("backups") != [] or
            data.get("commands") != COMMANDS):
        raise ValueError("exact CHRLAB scope, fresh outputs and no backups required")
    inputs = data.get("inputs")
    if not isinstance(inputs, list) or len(inputs) != 3:
        raise ValueError("exact three Chromium fixture inputs required")
    for item, (path, guest, size, pin) in zip(inputs, ASSETS):
        if (not isinstance(item, dict) or item.get("source") != str(path) or
                item.get("guest") != guest or type(item.get("bytes")) is not int or
                item["bytes"] != size or item.get("sha256") != pin):
            raise ValueError("exact Chromium source, guest, length and hash required")
    receipts = data.get("source_receipts")
    expected = [{"path": str(FIXTURE / "result.json"), "sha256": PRODUCER_SHA},
                {"path": str(HOST), "sha256": HOST_SHA}]
    if receipts != expected:
        raise ValueError("exact two frozen source receipts required")


def validate(manifest, selected_sha):
    """Validate all frozen bytes before returning a staging plan."""
    manifest = _exact_path(manifest, FIXTURE / "manifest.json")
    if selected_sha != MANIFEST_SHA or sha256(manifest) != MANIFEST_SHA:
        raise ValueError("explicit exact Chromium v2 manifest hash required")
    data = json.loads(manifest.read_text())
    _policy(data)
    sources = {str(manifest): MANIFEST_SHA, str(Path(__file__).resolve()): sha256(__file__)}
    for item, (expected, _, size, pin) in zip(data["inputs"], ASSETS):
        path = _exact_path(item["source"], expected)
        if path.stat().st_size != size or sha256(path) != pin:
            raise ValueError("frozen Chromium asset bytes changed")
        sources[str(path)] = pin
    # Receipt validation is complete before any mtools mutation is possible.
    for item in data["source_receipts"]:
        path = _exact_path(item["path"], Path(item["path"]))
        if sha256(path) != item["sha256"]:
            raise ValueError("frozen Chromium source receipt changed")
        sources[str(path)] = item["sha256"]
    producer = json.loads((FIXTURE / "result.json").read_text())
    host = json.loads(HOST.read_text())
    if (producer.get("status") != "HOST_BUILD_PASS_NATIVE_PENDING" or
            producer.get("native_executed") is not False or producer.get("entry_points_called") != 0 or
            producer.get("application_functionality_verified") is not False or
            producer.get("runtime_admission_changed") is not False or host.get("status") != "PASS" or
            host.get("controls", {}).get("checks") != 55 or host.get("native_executed") is not False or
            host.get("entry_points_called") != 0 or host.get("runtime_admission_changed") is not False):
        raise ValueError("host-only exact structural build provenance required")
    return {"manifest": str(manifest), "manifest_sha256": selected_sha,
            "inputs": data["inputs"], "outputs": OUTPUTS.copy(), "backups": [],
            "commands": COMMANDS.copy(), "immutable_sources": sources,
            "scope": "exact original Chromium read-only structure fixture only; no application acceptance"}


def _run(argv):
    result = subprocess.run([str(x) for x in argv], capture_output=True, text=True, timeout=180)
    if result.returncode:
        raise RuntimeError(f"{argv[0]} failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def _absent(spec, path):
    # Distinguish an absent name from an unreadable/corrupt FAT volume by proving
    # the containing directory is readable and inspecting the exact name.
    result = subprocess.run(["mdir", "-i", spec, path], capture_output=True, text=True, timeout=30)
    if result.returncode == 0:
        return False
    diagnostic = result.stderr.lower()
    if "file \"" not in diagnostic or "not found" not in diagnostic:
        raise RuntimeError("FAT name absence could not be established: " + result.stderr.strip())
    return True


def _no_open_disk(disk):
    identity = disk.stat()
    for process in Path("/proc").iterdir():
        if not process.name.isdigit() or int(process.name) == os.getpid():
            continue
        try:
            descriptors = list((process / "fd").iterdir())
        except (FileNotFoundError, ProcessLookupError):
            continue
        for descriptor in descriptors:
            try:
                entry = descriptor.stat()
            except (FileNotFoundError, ProcessLookupError):
                continue
            if entry.st_dev == identity.st_dev and entry.st_ino == identity.st_ino:
                raise RuntimeError("private FAT disk is open in another process")


def _boot_hashes(disk, start_lba):
    with disk.open("rb") as stream:
        mbr = stream.read(512)
        stream.seek(start_lba * 512)
        boot = stream.read(512)
    if len(mbr) != 512 or len(boot) != 512:
        raise ValueError("complete private boot sectors required")
    return hashlib.sha256(mbr).hexdigest(), hashlib.sha256(boot).hexdigest()


def stage(disk, run_dir, partition, plan, command=_run):
    """Inject validated inputs on an offline disk inside its new owned run dir.

    The caller still owns resource/clone provenance guards. This helper refuses
    other-process disk handles and holds advisory locks throughout injection.
    Failure preserves the new clone for inspection; originals are never targets.
    """
    # Revalidate even if a caller supplies a fabricated/mutated plan dictionary.
    checked = validate(plan["manifest"], plan["manifest_sha256"])
    disk, run_dir = Path(disk), Path(run_dir)
    if (not run_dir.is_absolute() or run_dir.resolve(strict=True) != run_dir or
            not run_dir.is_dir() or not run_dir.is_relative_to(BUILD) or run_dir == BUILD or
            not disk.is_absolute() or disk.resolve(strict=True) != disk or
            not disk.is_file() or not disk.is_relative_to(run_dir) or disk in [a[0] for a in ASSETS]):
        raise ValueError("offline new private disk inside its own build run directory required")
    start = partition.get("start_lba")
    if type(start) is not int or start < 0 or start * 512 + 512 > disk.stat().st_size:
        raise ValueError("bounded partition offset required")
    before = _boot_hashes(disk, start)
    if before != (partition.get("mbr_sha256"), partition.get("boot_sector_sha256")):
        raise ValueError("exact original boot sector hashes required")
    readbacks = [run_dir / ("prepared-guest-" + a[1].rsplit("\\", 1)[1]) for a in ASSETS]
    if any(p.exists() for p in readbacks):
        raise ValueError("new absent host readback names required")
    _no_open_disk(disk)
    with contextlib.ExitStack() as stack:
        disk_hold = stack.enter_context(disk.open("r+b"))
        fcntl.flock(disk_hold, fcntl.LOCK_EX | fcntl.LOCK_NB)
        _no_open_disk(disk)
        for name in checked["immutable_sources"]:
            source = stack.enter_context(Path(name).open("rb"))
            fcntl.flock(source, fcntl.LOCK_SH | fcntl.LOCK_NB)
        if any(sha256(name) != pin for name, pin in checked["immutable_sources"].items()):
            raise ValueError("held Chromium source changed before injection")
        spec = f"{disk}@@{start * 512}"
        command(["mdir", "-i", spec, "::"])
        if not _absent(spec, "::CHRLAB"):
            raise ValueError("CHRLAB must be entirely absent on a new private clone")
        # Outputs and injected names are all below this proven absent directory.
        command(["mmd", "-i", spec, "::CHRLAB"])
        copied = []
        for item, target in zip(checked["inputs"], readbacks):
            guest = "::" + item["guest"][3:].replace("\\", "/")
            command(["mcopy", "-i", spec, item["source"], guest])
            command(["mcopy", "-i", spec, guest, target])
            if target.stat().st_size != item["bytes"] or sha256(target) != item["sha256"]:
                raise RuntimeError("exact private Chromium input readback differs")
            copied.append(item | {"private_copy_sha256": sha256(target)})
        for guest in OUTPUTS:
            if not _absent(spec, "::" + guest[3:].replace("\\", "/")):
                raise RuntimeError("output appeared during private staging")
        if _boot_hashes(disk, start) != before:
            raise RuntimeError("Chromium injection changed original boot sectors")
        if any(sha256(name) != pin for name, pin in checked["immutable_sources"].items()):
            raise RuntimeError("held Chromium source changed during injection")
    return checked | {"inputs": copied, "installed_gop_replacement": [],
                      "output_baseline": "CHRLAB and all outputs absent before injection",
                      "native_installed_and_rendered": "not-established",
                      "mbr_sha256": before[0], "boot_sector_sha256": before[1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha", required=True)
    args = parser.parse_args()
    print(json.dumps(validate(args.manifest, args.manifest_sha), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
