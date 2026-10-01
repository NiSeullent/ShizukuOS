#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Freeze an opt-in private QEMU command adapter; no VM starts during preparation.

The ordinary runner stays unchanged. This adapter accepts its exact no-network,
owned-clone Q35 command and records the actual upstream machine/binary command.
Baseline has no sound device. SB16 mode writes only a private WAV recording.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
QEMU_RECEIPT_PIN = "2b86bb435cfe6015594e29b3e17f92af9913a4a289f5c7366ea327a2862a96d8"


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 ** 2), b""):
            h.update(chunk)
    return h.hexdigest()


def record(path, pin=None):
    path = path.resolve(strict=True)
    value = digest(path)
    if pin and value != pin:
        raise ValueError("private pinned file changed: " + str(path))
    return {"path": str(path), "sha256": value, "bytes": path.stat().st_size}


def validate_arguments(argv, run, config):
    if len(argv) != 32:
        raise ValueError("exact approved ordinary runner command required")
    fixed = {0: "-name", 1: "shz-disposable-win98-uefi", 2: "-machine", 3: "q35,hpet=off",
             4: "-accel", 5: "kvm", 6: "-cpu", 7: "qemu64", 8: "-smp", 9: "2",
             10: "-m", 11: "128", 12: "-nodefaults", 13: "-nic", 14: "none",
             15: "-display", 16: "none", 17: "-device", 18: "VGA", 19: "-drive",
             21: "-drive", 23: "-drive", 25: "-device",
             26: "ide-hd,drive=win98,bus=ide.0,bootindex=1", 27: "-serial", 29: "-qmp", 31: "-no-reboot"}
    if any(argv[i] != expected for i, expected in fixed.items()):
        raise ValueError("unsupported machine/resource/device/host endpoint option")
    repository_root = Path(config["repository_root"])
    if repository_root != Path(config["build_receipt"]["path"]).parents[2]:
        raise ValueError("repository identity differs from pinned producer location")
    if not run.is_relative_to(repository_root / "build/shizukudos/csm") or not run.name.startswith("run-win98-gop-audio-"):
        raise ValueError("new isolated audio owned run directory required")
    if run.resolve() != run or any(c in str(run) for c in ",\n\r"):
        raise ValueError("literal owned run path required")
    expected = {20: "if=pflash,unit=0,format=raw,readonly=on,file=" + config["firmware_code"]["path"],
                22: "if=pflash,unit=1,format=raw,file=" + str(run / "OVMF_VARS.fd"),
                24: "file=" + str(run / "windows-uefi.raw") + ",format=raw,if=none,id=win98",
                28: "file:" + str(run / "serial.log")}
    if any(argv[i] != value for i, value in expected.items()):
        raise ValueError("firmware/backing/serial path exceeds isolated audio scope")
    for name in ("windows-uefi.raw", "OVMF_VARS.fd"):
        path = run / name
        if path.is_symlink() or path.resolve(strict=True).parent != run:
            raise ValueError("owned backing file must be literal, existing, nonsymlink")
    qmp = argv[30]
    match = re.fullmatch(r"unix:(/tmp/shz-win98-uefi-[A-Za-z0-9_-]+)/qmp\.sock,server=on,wait=off", qmp)
    if not match:
        raise ValueError("ordinary private QMP endpoint required")
    parent = Path(match.group(1))
    if (parent.is_symlink() or parent.resolve(strict=True) != parent or not parent.is_dir() or
            parent.stat().st_uid != os.getuid() or parent.stat().st_mode & 0o077):
        raise ValueError("QMP parent must be an existing private owned direct child of /tmp")
    endpoint = parent / "qmp.sock"
    if endpoint.exists() or endpoint.is_symlink():
        raise ValueError("fresh nonsymlink QMP output required")
    serial = run / "serial.log"
    if serial.exists() or serial.is_symlink():
        raise ValueError("fresh nonsymlink serial output required")
    result = list(argv)
    # This is an explicit machine change from the host RHEL q35 alias. A new
    # baseline comparison is required before adding the SB16 audio device.
    result[3] = "pc-q35-11.1,hpet=off"
    result += ["-L", config["bios_directory"]]
    if config["mode"] == "sb16":
        wav = run / "sb16-capture.wav"
        if wav.exists() or wav.is_symlink():
            raise ValueError("fresh private WAV output required")
        result += ["-audiodev", "wav,id=sb16audio,path=" + str(wav) + ",out.frequency=44100,out.channels=2",
                   "-device", "sb16,audiodev=sb16audio,iobase=0x220,irq=5,dma=1,dma16=5"]
    return [config["binary"]["path"]] + result


def launcher(config_path, config_pin):
    record(config_path, config_pin)
    config = json.loads(config_path.read_text())
    bios_directory = Path(config["bios_directory"])
    current_catalog = []
    for path in sorted(bios_directory.rglob("*")):
        if path.is_symlink():
            raise ValueError("private BIOS catalog acquired a symlink")
        if path.is_file():
            current_catalog.append(str(path.resolve()))
    if current_catalog != config["bios_catalog"]:
        raise ValueError("private BIOS catalog changed")
    for item in [config["binary"], config["build_receipt"], config["firmware_code"], config["source"]] + config["assets"]:
        actual = record(Path(item["path"]), item["sha256"])
        if actual["bytes"] != item["bytes"]:
            raise ValueError("private execution input length changed")
    if sys.argv[1:] == ["--version"]:
        os.execv(config["binary"]["path"], [config["binary"]["path"], "--version"])
    run = Path.cwd()
    command = validate_arguments(sys.argv[1:], run, config)
    if shutil.disk_usage(run).free < 17 * 1024 ** 3 + 512 * 1024 ** 2:
        raise ValueError("audio launch below strict 17GiB plus 512MiB headroom")
    proof = {"schema": "win98modern.private-audio-qemu-command.v1", "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
             "mode": config["mode"], "config": record(config_path), "command": command,
             "ordinary_runner_command": sys.argv[1:], "binary": config["binary"],
             "firmware_code": config["firmware_code"], "assets": config["assets"],
             "machine_changed_from_host_rhel_alias": True, "host_speakers_or_network_enabled": False,
             "native_audio_or_driver_acceptance": False}
    with (run / "audio-qemu-command.json").open("x") as stream:
        json.dump(proof, stream, indent=2); stream.write("\n"); stream.flush(); os.fsync(stream.fileno())
    os.execv(command[0], command)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu-receipt", required=True, type=Path)
    parser.add_argument("--firmware-code", required=True, type=Path)
    parser.add_argument("--mode", required=True, choices=("baseline", "sb16"))
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    out = args.out.resolve()
    if out.exists() or not out.is_relative_to(ROOT / "build"):
        parser.error("absent private adapter directory required")
    try:
        producer = record(args.qemu_receipt, QEMU_RECEIPT_PIN)
        build = json.loads(args.qemu_receipt.read_text())
        if build["status"] != "BUILD_AND_INVENTORY_VERIFIED" or build["guest_started"] is not False:
            raise ValueError("exact compile/inventory private QEMU producer required")
        binary = record(Path(build["binary"]["path"]), build["binary"]["sha256"])
        assets = [record(Path(item["path"]), item["sha256"]) for item in build["assets"]]
        bios_directory = Path(build["binary"]["path"]).parent.parent / "source-build/qemu-11.1.2/pc-bios"
        if not bios_directory.is_dir():
            raise ValueError("private firmware directory missing")
        # QEMU can also load auxiliary x86 ROMs such as kvmvapic.bin. Bind the
        # complete private search directory, including its catalog, rather than
        # assuming that the VGA ROM is its only additional firmware input.
        bios_assets = []
        for path in sorted(bios_directory.rglob("*")):
            if path.is_symlink():
                raise ValueError("private BIOS catalog must not contain symlinks")
            if path.is_file():
                bios_assets.append(record(path))
        assets += bios_assets
        source = record(Path(__file__))
        firmware = record(args.firmware_code)
        config = {"schema": "win98modern.private-audio-adapter.v1", "mode": args.mode,
                  "repository_root": str(ROOT),
                  "binary": binary, "build_receipt": producer, "assets": assets,
                  "firmware_code": firmware, "bios_directory": str(bios_directory),
                  "bios_catalog": [item["path"] for item in bios_assets], "source": source}
    except (OSError, KeyError, ValueError) as error:
        parser.error(str(error))
    out.mkdir(parents=True)
    frozen = out / "prepare_audio_qemu_adapter.py"
    shutil.copyfile(__file__, frozen)
    if digest(frozen) != source["sha256"]:
        raise ValueError("adapter source changed while freezing")
    config["source"] = record(frozen)
    config_path = out / "config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n")
    wrapper = out / "qemu-audio"
    wrapper.write_text('#!/usr/bin/python3\nimport hashlib,runpy\nfrom pathlib import Path\n'
                      'source=Path(__file__).parent/"prepare_audio_qemu_adapter.py"\n'
                      'if hashlib.sha256(source.read_bytes()).hexdigest()!=' + repr(source["sha256"]) + ':raise ValueError("frozen audio adapter source changed")\n'
                      'runpy.run_path(str(source))["launcher"](Path(__file__).parent/"config.json",' + repr(digest(config_path)) + ')\n')
    wrapper.chmod(0o700)
    receipt = {"schema": "win98modern.private-audio-adapter-preparation.v1", "status": "PREPARED_NOT_NATIVE_ACCEPTANCE",
               "utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "config": record(config_path),
               "launcher": record(wrapper), "source": record(frozen), "mode": args.mode,
               "native_executed": False, "effects": ["Only new owned run raw/VARS/serial/QMP files accepted",
               "Explicit upstream pc-q35-11.1 machine comparison; ordinary RHEL runner unchanged",
               "SB16 mode adds private WAV output only; no host speakers or network"]}
    (out / "result.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(json.dumps({"status": receipt["status"], "launcher": str(wrapper), "sha256": digest(out / "result.json")}))


if __name__ == "__main__":
    raise SystemExit(main())
