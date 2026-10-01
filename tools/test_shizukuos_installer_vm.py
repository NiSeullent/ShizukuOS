#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Production installer VM gate: cancel, exact-disk install, host audit, cold desktops.

Default validates explicit source/artifact pins only. --run starts four bounded,
owned disposable QEMU instances in sequence. It never attaches a host disk or
Windows media. Success proves the Shizuku component installer, not Windows 98,
MS-DOS replacement, native modern apps, drivers or acceleration.
"""
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import signal
import resource
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time
import threading

sys.dont_write_bytecode = True
MIB = 1 << 20
TARGET_BYTES = 512 * MIB
RETAIN_FREE = 17 << 30
RUN_BUDGET = 3 << 30
LOG_LIMIT = 128 * MIB             # combined stdout/stderr over the whole run
MAX_FRAME_BYTES = 1280 * 1024 * 3 + 64
METADATA_HEADROOM = 64 * MIB


def production_budget(readback_bytes):
    if not 0 <= readback_bytes <= 128 * MIB:
        raise ValueError("installer member readbacks exceed the bounded 128 MiB medium")
    screens = 10 * 2 * MAX_FRAME_BYTES
    retained = 3 * TARGET_BYTES + 128 * MIB + readback_bytes + screens + LOG_LIMIT + 12 * MIB + METADATA_HEADROOM
    audit = TARGET_BYTES + 128 * MIB + readback_bytes + screens + LOG_LIMIT + 12 * MIB + METADATA_HEADROOM + 2 * TARGET_BYTES
    # A malformed single frame cannot grow beyond the owned child's file-size
    # limit. It fails before another capture; previous valid rolling frames stay.
    peak = max(retained + TARGET_BYTES, audit)
    if peak > RUN_BUDGET: raise ValueError("proved installer phase budget exceeds 3 GiB")
    return {"retained_bytes": retained, "host_audit_temporary_bytes": 2 * TARGET_BYTES,
            "max_peak_bytes": peak, "run_budget_bytes": RUN_BUDGET, "retain_free_bytes": RETAIN_FREE}


def child_file_limit():
    resource.setrlimit(resource.RLIMIT_FSIZE, (TARGET_BYTES, TARGET_BYTES))


class PipeCapture:
    """Drain actual child pipes; never turn overflow into a passing receipt."""
    def __init__(self, proc, stdout_path, stderr_path, limit=LOG_LIMIT, budget=None, outputs=None, reserve=None):
        self.proc, self.error, self.reserve = proc, None, reserve
        self.budget = budget if budget is not None else {"used": 0, "limit": limit, "lock": threading.Lock()}
        self.outputs = outputs or [stdout_path.open("xb"), stderr_path.open("xb")]
        self.threads = []
        for pipe, output in zip((proc.stdout, proc.stderr), self.outputs):
            thread = threading.Thread(target=self.drain, args=(pipe, output), daemon=True)
            thread.start(); self.threads.append(thread)

    def drain(self, pipe, output):
        try:
            while True:
                chunk = os.read(pipe.fileno(), 65536)
                if not chunk: break
                with self.budget["lock"]:
                    remaining = self.budget["limit"] - self.budget["used"]
                    if self.reserve is not None:
                        try: space(self.reserve, len(chunk))
                        except ValueError as error: self.error = str(error); remaining = 0
                    keep = chunk[:max(0, remaining)]
                    if keep: output.write(keep); output.flush(); self.budget["used"] += len(keep)
                    if len(keep) != len(chunk) and self.error is None:
                        self.error = "actual child combined log cap exceeded; evidence incomplete, run must FAIL"
        except BaseException as error:
            self.error = "actual child pipe capture failed: " + str(error)
        finally:
            pipe.close()

    def finish(self):
        for thread in self.threads: thread.join(timeout=5)
        if any(thread.is_alive() for thread in self.threads):
            self.error = "owned child PIPE drain did not finish"
        for output in self.outputs: output.close()


def block_attestation(info, stats, drives):
    if not isinstance(info, list) or not isinstance(stats, list): raise ValueError("actual QMP block lists required")
    result = []
    for port, (disk, readonly, _) in enumerate(drives):
        device = "d" + str(port)
        found = [x for x in info if x.get("device") == device]
        counters = [x for x in stats if x.get("device") == device]
        if len(found) != 1 or len(counters) != 1: raise ValueError("missing/ambiguous actual QMP block device " + device)
        inserted = found[0].get("inserted", {}); image = inserted.get("image", {}); node = inserted.get("node-name")
        if not isinstance(node, str) or not node or counters[0].get("node-name") != node:
            raise ValueError("actual QMP block node identity mismatch")
        if inserted.get("file") != str(disk) or image.get("filename") != str(disk) or inserted.get("drv") != "raw" or image.get("format") != "raw" or inserted.get("ro") is not readonly or image.get("virtual-size") != disk.stat().st_size:
            raise ValueError("actual QMP raw file/size/readonly identity mismatch")
        values = counters[0].get("stats", {})
        if any(type(values.get(k)) is not int or values[k] < 0 for k in ("wr_bytes", "wr_operations")):
            raise ValueError("missing/malformed actual QMP write counters")
        result.append({"device": device, "node": node, "file": str(disk), "readonly": readonly,
                       "bytes": disk.stat().st_size, "wr_bytes": values["wr_bytes"], "wr_operations": values["wr_operations"]})
    return result


def write_contract(baseline, final, phase):
    if len(baseline) != len(final) or not baseline: raise ValueError("actual QMP baseline/final device coverage")
    for before, after in zip(baseline, final):
        if any(before.get(k) != after.get(k) for k in ("device", "node", "file", "readonly", "bytes")):
            raise ValueError("actual QMP block identity changed during guest run")
        if before["wr_bytes"] or before["wr_operations"]: raise ValueError("pre-instruction actual QMP write baseline must be zero")
        if after["wr_bytes"] < before["wr_bytes"] or after["wr_operations"] < before["wr_operations"]:
            raise ValueError("actual QMP counters decreased")
        writes = after["wr_bytes"] or after["wr_operations"]
        if after["readonly"] or phase == "cancel" or (phase == "install" and after["device"] == "d0"):
            if writes: raise ValueError("actual QMP unexpected disk writes: " + after["device"])
        elif phase == "install" and after["device"] == "d1":
            if not after["wr_bytes"] or not after["wr_operations"]: raise ValueError("actual selected target received no writes")
    if phase == "install" and {x["device"] for x in final if not x["readonly"]} != {"d0", "d1"}:
        raise ValueError("actual installer writable decoy/target coverage")


def path(value):
    raw = Path(value).expanduser().absolute()
    if any(p.is_symlink() for p in (raw, *raw.parents)):
        raise ValueError("symlinks and symlink parents are refused")
    result = raw.resolve()
    if any(result == p or p in result.parents for p in map(Path, ("/dev", "/proc", "/sys"))):
        raise ValueError("device/virtual filesystem inputs and outputs are refused")
    return result


def sha(p):
    p = path(p)
    descriptor = os.open(p, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode): raise ValueError("regular file required")
        h = hashlib.sha256()
        for block in iter(lambda: stream.read(MIB), b""): h.update(block)
        def identity(value):
            return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns
        if identity(before) != identity(os.fstat(stream.fileno())) or identity(before) != identity(p.stat()):
            raise ValueError("file changed while hashing")
    return h.hexdigest()


def json_file(p):
    if p.stat().st_size > 4 * MIB: raise ValueError("bounded receipt/manifest exceeds 4 MiB")
    return json.loads(p.read_text())


def pinned(entry):
    p = path(entry["path"])
    if not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) or p.stat().st_size != entry["bytes"] or sha(p) != entry["sha256"]:
        raise ValueError("stale or malformed file pin: " + p.name)
    return p


def qemu_runtime_files(qemu, data):
    if any(os.environ.get(k) for k in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT")):
        raise ValueError("unselected dynamic loader environment is refused")
    qemu, data = path(qemu), path(data)
    names = {"vgabios-stdvga.bin", "kvmvapic.bin"}
    if not data.is_dir() or {p.name for p in data.iterdir()} != names:
        raise ValueError("exact VGA/APIC ROM directory required")
    result = subprocess.run(["ldd", str(qemu)], capture_output=True, text=True, timeout=30)
    if result.returncode or "not found" in result.stdout or len(result.stdout) > MIB:
        raise ValueError("actual QEMU ELF dependency resolution failed")
    libraries = {Path(p).resolve() for p in re.findall(r"(/[^\s]+)\s+\(0x[0-9a-fA-F]+\)", result.stdout)}
    if not libraries: raise ValueError("actual QEMU ELF dependency closure absent")
    selected = libraries | {data / name for name in names}
    if len(selected) > 128: raise ValueError("bounded QEMU dependency closure exceeded")
    return {str(path(p)): {"path": str(path(p)), "bytes": p.stat().st_size, "sha256": sha(p)}
            for p in sorted(selected)}


def verify_qemu_runtime(qemu, data, expected):
    if qemu_runtime_files(qemu, data) != expected:
        raise ValueError("actual QEMU library/ROM runtime closure differs from capture")


def new_output(value, repo):
    out, repo = path(value), path(repo)
    if out.exists() or not out.parent.is_dir(): raise ValueError("new output with existing parent required")
    if repo in out.parents:
        if out.relative_to(repo).parts[0] != "build": raise ValueError("repository outputs must be ignored build/")
        if (repo / ".git").exists() and subprocess.run(["git", "-C", str(repo), "check-ignore", "-q", "--no-index", str(out)], timeout=10).returncode:
            raise ValueError("output is not git-ignored")
    if "," in str(out) or "\n" in str(out): raise ValueError("QEMU delimiter in output path")
    return out


def space(out, margin=0):
    if shutil.disk_usage(out.parent).free < RETAIN_FREE + margin:
        raise ValueError("17 GiB free reserve plus phase budget required")


def verify_sources(repo, pins, required=()):
    if not pins or not all(k in pins for k in required): raise ValueError("required current source absent from build receipt")
    for name, digest in pins.items():
        rel = Path(name)
        if rel.is_absolute() or ".." in rel.parts or sha(path(repo) / rel) != digest:
            raise ValueError("source differs from completed build receipt: " + name)


def archive(data):
    if data[:8] != b"SHZARC01" or len(data) < 16: raise ValueError("invalid bounded Shizuku archive")
    count, reserved = struct.unpack_from("<II", data, 8)
    end = 16 + count * 136
    if reserved or count > 10000 or end > len(data): raise ValueError("archive table extent")
    entries = {}
    for i in range(count):
        at = 16 + i * 136
        raw = data[at:at + 120]
        if b"\0" not in raw: raise ValueError("unterminated archive name")
        name = raw.split(b"\0", 1)[0].decode("ascii").upper()
        offset, size = struct.unpack_from("<QQ", data, at + 120)
        if not name.startswith("\\") or ".." in name.split("\\") or name in entries or offset < end or offset > len(data) or size > len(data) - offset:
            raise ValueError("archive member identity/range")
        entries[name] = data[offset:offset + size]
    return entries


def load_module(p, name):
    spec = importlib.util.spec_from_file_location(name, p)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_install_runtime(packed, original):
    prefixes = ("\\SHZ\\SYS64\\", "\\SHZ\\FONTS\\", "\\SHZ\\CERTS\\")
    runtime = {name: data for name, data in original.items()
               if name.startswith(prefixes) or name == "\\SHZ\\TESTS\\T_HELLO.EXE"}
    for name, data in runtime.items():
        if packed.get(name) != data:
            raise ValueError("INSTALL runtime differs from fresh WIN64.IMG: " + name)
    for name in packed:
        if name.startswith(prefixes) and name not in runtime:
            raise ValueError("INSTALL runtime contains an unbuilt member: " + name)


def validate_inputs(config):
    if config.get("schema") != "shizukuos-production-installer-vm/1": raise ValueError("input schema")
    if config.get("harness_sha256") != sha(Path(__file__)):
        raise ValueError("input capture belongs to another harness source revision")
    repo, payload = path(config["repo"]), path(config["payload_directory"])
    files = {k: pinned(v) for k, v in config["files"].items()}
    for key in ("loader", "kernel64s", "kernel32", "kernel64", "stub", "dos16", "install", "win64", "kernel_receipt", "runtime_receipt", "supervisor_receipt", "dos_receipt", "payload_receipt", "payload_manifest", "esp", "qemu", "ovmf_code", "ovmf_vars", "seabios"):
        if key not in files: raise ValueError("required explicit input: " + key)
    if files["ovmf_code"].stat().st_size + files["ovmf_vars"].stat().st_size != 4 * MIB:
        raise ValueError("exact supported 4 MiB OVMF flash pair required")
    if not os.access(files["qemu"], os.X_OK): raise ValueError("pinned QEMU is not executable")
    files["qemu_data"] = path(config["qemu_data_directory"])
    verify_qemu_runtime(files["qemu"], files["qemu_data"], config["qemu_runtime"])
    models = subprocess.run([str(files["qemu"]), "-device", "help"], capture_output=True, text=True, timeout=30)
    if models.returncode or any('name "' + name + '"' not in models.stdout for name in ("ich9-ahci", "nvme", "virtio-blk-pci", "VGA")):
        raise ValueError("explicit QEMU lacks the actual AHCI/NVMe/readonly virtio/VGA profile")
    kr = json_file(files["kernel_receipt"])
    wr = json_file(files["runtime_receipt"])
    sr = json_file(files["supervisor_receipt"])
    dr = json_file(files["dos_receipt"])
    pr = json_file(files["payload_receipt"])
    manifest = json_file(files["payload_manifest"])
    verify_sources(repo, kr["sources_sha256"], ["shizukudos/kernel64/main.c", "shizukudos/kernel64/setup_sys.c",
                   "shizukudos/kernel64/standalone/standalone64.c", "shizukudos/kcommon/standalone_dev.h"])
    verify_sources(repo, wr["sources_sha256"], ["shizukudos/win64/setup/interactive_ui.c", "shizukudos/win64/setup/interactive_choice.c", "shizukudos/win64/setup/setup_main.c", "shizukudos/win64/apps/shzdesk/main.c"])
    verify_sources(repo, sr["sources_sha256"], ["shizukudos/supervisor/loader/loader.c", "shizukudos/supervisor/loader/bootini.c"])
    verify_sources(repo, dr["user_boot"]["sources_sha256"], ["shizukudos/dos16/build.py", "shizukudos/dos16/user/SHZSTART.BAT"])
    verify_sources(repo, config["harness_dependencies_sha256"], ["shizukudos/tools/qemu.py", "shizukudos/install/tests/verify_disk.py", "shizukudos/install/mkpayload.py", "shizukudos/install/desktop_profile.py"])
    if kr["kernels"]["kernel64-standalone"]["sha256"] != sha(files["kernel64s"]) or wr["archive"]["sha256"] != sha(files["win64"]) or sr["artifacts"]["BOOTX64.EFI"]["sha256"] != sha(files["loader"]):
        raise ValueError("kernel/runtime/loader not from the completed source-bound builds")
    for key in ("kernel32", "kernel64"):
        if kr["kernels"][key]["sha256"] != sha(files[key]): raise ValueError("stale built " + key)
    if kr["kernels"]["kernel64-standalone"]["stub_sha256"] != sha(files["stub"]): raise ValueError("stale BIOS kernel stub")
    if dr["artifacts"]["dos10.img"]["sha256"] != sha(files["dos16"]) or sr["artifacts"]["disk.img (input)"]["sha256"] != sha(files["dos16"]):
        raise ValueError("stale DOS10 image or old Supervisor DOS profile")
    if manifest.get("boot_profile") != "desktop" or not pr.get("bios_boot"):
        raise ValueError("production desktop payload with actual BIOS boot code required")
    for name, ent in pr["outputs"].items():
        if Path(name).name != name or name in (".", ".."):
            raise ValueError("payload output name must be a flat member")
        p = payload / ("payload" if name in ("manifest.json", "ESP.SIM", "SYSTEM.ARC", "GPTMBR.BIN") else "") / name
        if p.stat().st_size != ent["bytes"] or sha(p) != ent["sha256"]:
            raise ValueError("payload receipt drift: " + name)
    if pr["outputs"]["INSTALL.IMG"]["sha256"] != sha(files["install"]) or pr["outputs"]["esp.img"]["sha256"] != sha(files["esp"]):
        raise ValueError("INSTALL archive/ESP is not the selected payload")
    for key, digest in pr["inputs"].items():
        if re.fullmatch(r"[0-9a-f]{64}", str(digest)) and (key not in files or sha(files[key]) != digest):
            raise ValueError("payload consumed an older component: " + key)
    if files["install"].stat().st_size > 64 * MIB: raise ValueError("INSTALL.IMG exceeds the actual loader limit")
    if files["win64"].stat().st_size > 128 * MIB: raise ValueError("bounded WIN64.IMG exceeds 128 MiB")
    packed = archive(files["install"].read_bytes())
    original = archive(files["win64"].read_bytes())
    setup = packed["\\SHZ\\SETUP\\SHZSETUP.EXE"]
    if hashlib.sha256(setup).hexdigest() != wr["setup"]["SHZSETUP.EXE"]:
        raise ValueError("INSTALL.IMG contains stale SHZSETUP.EXE")
    verify_install_runtime(packed, original)
    for name in ("manifest.json", "ESP.SIM", "SYSTEM.ARC", "GPTMBR.BIN"):
        if packed["\\SHZ\\SETUP\\PAYLOAD\\" + name.upper()] != (payload / "payload" / name).read_bytes():
            raise ValueError("guest payload differs from independent host audit payload")
    esp_members = {x["path"].upper(): x for x in manifest["esp"]["files"]}
    for key, name in (("loader", "/EFI/BOOT/BOOTX64.EFI"), ("kernel64s", "/SHZDOS/KERNEL64S.BIN")):
        if esp_members[name]["sha256"] != sha(files[key]): raise ValueError("installed ESP ships an older " + key)
    if "/SHZDOS/KERNEL64.INI" not in esp_members: raise ValueError("installed desktop boot policy absent")
    return repo, payload, files


def capture(args):
    repo, build, payload = path(args.repo), path(args.build), path(args.payload)
    locations = {"loader": build / "supervisor/BOOTX64.EFI", "kernel64s": build / "kernel64s/KERNEL64S.BIN",
                 "install": payload / "INSTALL.IMG", "win64": build / "win64/WIN64.IMG",
                 "kernel_receipt": build / "kernels-build-result.json", "runtime_receipt": build / "win64/build-result.json",
                 "dos_receipt": build / "dos16/build-result.json",
                 "supervisor_receipt": build / "supervisor/build-result.json", "payload_receipt": payload / "mkpayload-result.json",
                 "payload_manifest": payload / "payload/manifest.json", "esp": payload / "esp.img",
                 "kernel32": build / "kernel32/KERNEL32.BIN", "kernel64": build / "kernel64/KERNEL64.BIN",
                 "stub": build / "kernel64s/boot.elf", "dos16": build / "dos16/shizukudos-dos10.img",
                 "qemu": path(args.qemu), "ovmf_code": path(args.ovmf_code), "ovmf_vars": path(args.ovmf_vars), "seabios": path(args.seabios)}
    if (build / "csm/CSMWRAP.EFI").is_file(): locations["csmwrap"] = build / "csm/CSMWRAP.EFI"
    data = {"schema": "shizukuos-production-installer-vm/1", "repo": str(repo), "payload_directory": str(payload),
            "harness_sha256": sha(Path(__file__)),
            "qemu_data_directory": str(path(args.qemu_data)),
            "qemu_runtime": qemu_runtime_files(path(args.qemu), path(args.qemu_data)),
            "files": {k: {"path": str(path(p)), "bytes": p.stat().st_size, "sha256": sha(p)} for k, p in locations.items()},
            "harness_dependencies_sha256": {q: sha(repo / q) for q in ("shizukudos/tools/qemu.py", "shizukudos/install/tests/verify_disk.py", "shizukudos/install/mkpayload.py", "shizukudos/install/desktop_profile.py")}}
    validate_inputs(data)
    dest = path(args.capture_inputs)
    with dest.open("x") as stream: json.dump(data, stream, indent=2); stream.write("\n")
    print(json.dumps({"status": "PASS_CURRENT_INPUT_CAPTURE_NOT_RUN", "inputs": str(dest), "sha256": sha(dest)}))


def ordered(text, patterns):
    position = 0
    for pattern in patterns:
        match = re.search(pattern, text[position:])
        if not match: raise ValueError("missing or out-of-order production evidence: " + pattern)
        position += match.end()


def installation_trace(text, phase):
    common = [r"K64 setup: shz.setup=interactive, \d+ RAM block device\(s\); starting \\SHZ\\SETUP\\SHZSETUP.EXE\n", r"SHZ-SETUP UI ready candidates=2 writes=0\n",
              r"SHZ-SETUP UI review target=nvme0n1 sectors=1048576\n"]
    if "SETUP-RESULT: FAIL" in text or "K64 test FAIL" in text: raise ValueError("actual installer/kernel failure")
    if phase == "cancel":
        if "UI confirmed" in text or "SETUP-RESULT: OK" in text: raise ValueError("cancel path confirmed installation")
        ordered(text, common + [r"SETUP-RESULT: CANCELLED \(no disk writes\)\n", r"K64 setup: SHZSETUP\.EXE exit=0 faulted=0 reaped=0(?:\n|,)"])
    else:
        ordered(text, common + [r"SHZ-SETUP UI confirmed target=nvme0n1\n", r"SETUP-RESULT: OK\n",
                               r"K64 setup: SHZSETUP\.EXE exit=0 faulted=0 reaped=0[^\n]*power request shutdown\n", r"SHZ-EXIT:0\n"])


def desktop_trace(text, firmware):
    boot = [r"Supervisor loader \(UEFI x64\)", r"BOOT.INI mode=kernel64"] if firmware == "uefi" else [r"SHZ-MBR ->VBR", r"SYSLINUX 6\.04", r"SHZ-STUB: kernel"]
    ordered(text, boot + [r"K64 desktop: production profile \(self-tests not run\)", r"SHZ-DESKTOP READY width=\d+ height=\d+",
                         r"SHZ-DESKTOP EDITOR", r"SHZ-DESKTOP EXIT requested=1", r"K64 desktop: result exited exit=0 faulted=0 reaped=0",
                         r"K64 desktop: volume flush rc 0", r"SHZ-EXIT:0"])
    if "K64 desktop: result start-failed" in text or "SHZ-DESKTOP ERROR" in text or "EFI Internal Shell" in text:
        raise ValueError("actual production desktop failed")


def zero_sha(size):
    h = hashlib.sha256(); block = bytes(MIB)
    while size:
        chunk = block[:min(size, MIB)]; h.update(chunk); size -= len(chunk)
    return h.hexdigest()


def verify_unchanged_zero(p, expected, size=TARGET_BYTES):
    if p.stat().st_size != size or sha(p) != expected: raise ValueError("supposedly untouched disk changed")


def blank(p):
    with p.open("xb") as stream: stream.truncate(TARGET_BYTES)
    if p.stat().st_blocks: raise ValueError("owned blank disk must be sparse for the bounded production profile")


def ppm(p):
    if p.stat().st_size > MAX_FRAME_BYTES: raise ValueError("actual screenshot exceeds bounded production frame")
    raw = p.read_bytes()
    match = re.match(rb"P6\s+(\d+)\s+(\d+)\s+255\s", raw)
    if not match: raise ValueError("actual screenshot is not P6")
    w, h = map(int, match.groups()); pixels = raw[match.end():]
    if w < 640 or h < 480 or w > 1280 or h > 1024 or len(pixels) != w * h * 3:
        raise ValueError("screenshot extent/production display geometry")
    if len(set(zip(pixels[0::3], pixels[1::3], pixels[2::3]))) < 4:
        raise ValueError("blank/degenerate actual display")
    return hashlib.sha256(pixels).hexdigest()


class OwnedVM:
    def __init__(self, files, directory, firmware, drives, timeout, evidence=None, capture_budget=None, start_guest=True):
        self.directory, self.timeout, self.files = directory, timeout, files
        self.evidence, self.drives, self.capture_budget = evidence, drives, capture_budget
        self.capture = None
        self.start_guest = start_guest
        directory.mkdir(); self.serial = directory / "serial.log"; self.qmp = None; self.proc = None; self.pidfd = None
        self.sockdir = Path(tempfile.mkdtemp(prefix="shz-inst-qmp-"))
        sock = self.sockdir / "qmp.sock"; self.sock = sock
        self.command = [str(files["qemu"]), "-name", "shz-production-installer-owned", "-machine", "q35", "-accel", "kvm",
                        "-cpu", "qemu64", "-smp", "1", "-m", "512M", "-nodefaults", "-nic", "none", "-display", "none",
                        "-vga", "std", "-no-reboot", "-S", "-monitor", "none", "-serial", "stdio", "-qmp", f"unix:{sock},server=on,wait=off"]
        if "qemu_data" in files: self.command += ["-L", str(files["qemu_data"])]
        # The unchanged guest sa_exit prints after its filesystem flush, then
        # cli/hlt when no debug-exit device exists. Keep QMP alive for final I/O
        # counters; record owned QMP quit separately from an ISA exit status.
        if firmware == "uefi":
            variables = directory / "OVMF_VARS.fd"; shutil.copyfile(files["ovmf_vars"], variables)
            self.command += ["-drive", f"if=pflash,unit=0,format=raw,readonly=on,file={files['ovmf_code']}",
                             "-drive", f"if=pflash,unit=1,format=raw,file={variables}"]
        else: self.command += ["-bios", str(files["seabios"])]
        self.models = []
        for port, (disk, readonly, boot) in enumerate(drives):
            device = (f"virtio-blk-pci,drive=d{port}" if readonly else
                      f"nvme,drive=d{port},serial=SHZ-SETUP-TARGET" if port == 1 or len(drives) == 1 else
                      f"ide-hd,drive=d{port},bus=ide.{port}")
            self.models.append(device.split(",", 1)[0])
            self.command += ["-drive", f"if=none,id=d{port},format=raw,file={disk}" + (",readonly=on" if readonly else ""),
                             "-device", device + (",bootindex=1" if boot else "") + f",id=storage-d{port}"]
        if any("," in str(x) or "\n" in str(x) for x in [*files.values(), directory, self.sockdir]): raise ValueError("QEMU delimiter in path")

    def identity(self):
        raw = Path(f"/proc/{self.proc.pid}/stat").read_text()
        return raw[raw.rfind(")") + 2:].split()[19]

    def owner(self):
        if time.monotonic() - self.started >= self.timeout: raise TimeoutError("bounded owned VM phase deadline")
        if self.proc.poll() is not None: raise ValueError("owned VM exited before requested observation")
        if self.identity() != self.starttime or Path(f"/proc/{self.proc.pid}/cmdline").read_bytes().split(b"\0")[:-1] != [os.fsencode(x) for x in self.command]:
            raise ValueError("VM owner identity mismatch")
        if self.capture is not None and self.capture.error: raise ValueError(self.capture.error)
        space(self.directory)

    def __enter__(self):
        self.started = time.monotonic()
        try:
            self.err = (self.directory / "qemu.stderr").open("xb")
            self.serial_output = self.serial.open("xb")
            self.proc = subprocess.Popen(self.command, cwd=self.directory, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=child_file_limit)
            self.capture = PipeCapture(self.proc, self.serial, self.directory / "qemu.stderr", budget=self.capture_budget,
                                       outputs=[self.serial_output, self.err], reserve=self.directory)
            if self.evidence is not None:
                self.evidence["VM_executed"] = True
                self.evidence["actual_VM_count"] += 1
            self.pidfd = os.pidfd_open(self.proc.pid); self.starttime = self.identity()
            (self.directory / "command.json").write_text(json.dumps(self.command, indent=2) + "\n")
            # Allow exec to publish its actual argv before binding the QMP peer.
            until = time.monotonic() + 2
            while time.monotonic() < until:
                try: self.owner(); break
                except ValueError: time.sleep(.05)
            self.owner()
            self.qmp = QMP(self.sock, timeout=30)
            peer = struct.unpack("3i", self.qmp.socket.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))[0]
            if peer != self.proc.pid: raise ValueError("QMP peer is not the owned VM")
            status = self.qmp.call("query-status")
            if status.get("running") is not False or status.get("status") not in ("prelaunch", "paused"):
                raise ValueError("owned VM was not paused before its first guest instruction")
            self.frontends = self.frontend_snapshot()
            self.baseline = self.block_snapshot("pre-instruction")
            if any(row["wr_bytes"] or row["wr_operations"] for row in self.baseline):
                raise ValueError("actual initial block writes must be zero")
            if self.start_guest: self.qmp.call("cont")
            return self
        except BaseException:
            self.__exit__(None, None, None); raise

    def frontend_snapshot(self):
        objects = self.qmp.call("qom-list", {"path": "/machine/peripheral"})
        rows = []
        for index, model in enumerate(self.models):
            name = "storage-d" + str(index)
            found = [entry for entry in objects if entry.get("name") == name]
            if len(found) != 1 or found[0].get("type") != "child<" + model + ">":
                raise ValueError("actual storage frontend device/model mismatch")
            drive = self.qmp.call("qom-get", {"path": "/machine/peripheral/" + name, "property": "drive"})
            if drive != "d" + str(index): raise ValueError("actual storage frontend backend binding mismatch")
            rows.append({"id": name, "model": model, "drive": drive})
        (self.directory / "actual-frontends.json").write_text(json.dumps({"devices": rows, "pci": self.qmp.call("query-pci")}, indent=2) + "\n")
        return rows

    def text(self):
        raw = self.serial.read_bytes() if self.serial.exists() else b""
        return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", raw.decode(errors="replace")).replace("\r", "")

    def wait(self, expression, after=0):
        while time.monotonic() - self.started < self.timeout:
            text = self.text(); match = re.search(expression, text[after:])
            if match: return match
            if "SETUP-RESULT: FAIL" in text: raise ValueError("actual SETUP-RESULT failure")
            if self.proc.poll() is not None: raise ValueError("owned VM exited before marker " + expression)
            self.owner(); time.sleep(.1)
        raise TimeoutError("bounded VM marker timeout: " + expression)

    def key(self, qcode):
        self.owner()
        self.qmp.call("send-key", {"keys": [{"type": "qcode", "data": qcode}], "hold-time": 80})
        time.sleep(.15)

    def screenshot(self, name):
        # Wait for two actual identical frames; do not inspect cached browser frames.
        previous = None
        for i in range(20):
            self.owner(); time.sleep(.1)
            dest = self.directory / f"{name}-{i % 2}.ppm"
            self.qmp.call("stop")
            try: self.qmp.call("screendump", {"filename": str(dest)})
            finally: self.qmp.call("cont")
            digest = ppm(dest)
            if digest == previous: return dest, digest
            previous = digest
        raise ValueError("actual display never stabilized for " + name)

    def wait_exit(self):
        self.wait(r"(?:^|\n)SHZ-EXIT:0\n")
        self.owner(); self.qmp.call("stop")
        status = self.qmp.call("query-status")
        if status.get("running") is not False or status.get("status") != "paused":
            raise ValueError("owned post-exit observation is not paused")
        self.final_blocks = self.block_snapshot("after-guest-SHZ-EXIT-0")
        self.guest_shutdown_observed = True

    def block_snapshot(self, label):
        self.owner()
        info = self.qmp.call("query-block")
        stats = self.qmp.call("query-blockstats", {"query-nodes": False})
        rows = block_attestation(info, stats, self.drives)
        report = {"label": label, "query_block": info, "query_blockstats": stats, "attested": rows}
        data = json.dumps(report, indent=2) + "\n"
        if len(data.encode()) > MIB: raise ValueError("bounded actual QMP block report exceeds 1 MiB")
        (self.directory / (label + "-block-stats.json")).write_text(data)
        return rows

    def quit_observed_guest(self):
        if not getattr(self, "guest_shutdown_observed", False): raise ValueError("actual guest shutdown observation absent")
        self.owner(); self.qmp.call("quit")
        rc = self.proc.wait(timeout=min(30, max(1, self.timeout - (time.monotonic() - self.started))))
        self.capture.finish()
        if self.capture.error: raise ValueError(self.capture.error)
        if rc: raise ValueError("owned QMP quit failed: " + str(rc))
        (self.directory / "shutdown-observation.json").write_text(json.dumps({"guest_SHZ_EXIT": 0, "post_guest_io_snapshot": True,
                       "QMP_quit_exit_code": rc, "isa_debug_exit_device": False, "isa_debug_exit_status_claimed": False}) + "\n")

    def __exit__(self, *_):
        try:
            if self.proc is not None and self.proc.poll() is None:
                # The pidfd binds this Popen child even if exec/QMP/argv validation
                # failed. A validation failure must not leave our child running.
                if self.pidfd is not None: signal.pidfd_send_signal(self.pidfd, signal.SIGTERM)
                else: self.proc.terminate()  # unreaped direct Popen child, never a lookup PID
                try: self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    if self.pidfd is not None: signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
                    else: self.proc.kill()
                    self.proc.wait(timeout=5)
        finally:
            if self.qmp is not None: self.qmp.close()
            if self.pidfd is not None: os.close(self.pidfd)
            if self.capture is not None: self.capture.finish()
            if self.capture is not None and self.capture.error and self.evidence is not None:
                self.evidence.setdefault("capture_errors", []).append(self.capture.error)
            if hasattr(self, "err"): self.err.close()
            if hasattr(self, "serial_output"): self.serial_output.close()
            shutil.rmtree(self.sockdir)


def boot_medium(out, files):
    medium = out / "installer-esp.img"
    readback_bytes = sum(files[key].stat().st_size for key in ("loader", "kernel64s", "install")) + len(b"mode=install\r\nmenu_timeout=0\r\n")
    production_budget(readback_bytes)
    space(out, 128 * MIB + readback_bytes + METADATA_HEADROOM)
    with medium.open("xb") as stream: stream.truncate(128 * MIB)
    subprocess.run(["mkfs.vfat", "-F", "32", "-n", "SHZSETUP", medium], check=True, capture_output=True, timeout=60)
    for name in ("EFI", "EFI/BOOT", "EFI/SHIZUKU", "SHZDOS", "SHZ", "SHZ/SETUP"):
        subprocess.run(["mmd", "-i", medium, "::/" + name], check=True, capture_output=True, timeout=30)
    policy = out / "BOOT.INI"; policy.write_bytes(b"mode=install\r\nmenu_timeout=0\r\n")
    members = {"EFI/BOOT/BOOTX64.EFI": files["loader"], "EFI/SHIZUKU/BOOT.INI": policy,
               "SHZDOS/KERNEL64S.BIN": files["kernel64s"], "SHZ/SETUP/INSTALL.IMG": files["install"]}
    for name, source in members.items():
        subprocess.run(["mcopy", "-i", medium, source, "::/" + name], check=True, capture_output=True, timeout=120)
        readback = out / (name.replace("/", "_") + ".readback")
        subprocess.run(["mcopy", "-i", medium, "::/" + name, readback], check=True, capture_output=True, timeout=120)
        if sha(readback) != sha(source): raise ValueError("actual installer boot member byte drift")
    subprocess.run(["fsck.fat", "-n", medium], check=True, capture_output=True, timeout=60)
    return medium


def install_phase(files, work, medium, phase, timeout, zero, evidence=None, capture_budget=None):
    space(work, 2 * TARGET_BYTES + LOG_LIMIT + 6 * MAX_FRAME_BYTES + METADATA_HEADROOM)
    folder = work / phase; folder.mkdir()
    decoy, target = folder / "decoy.img", folder / "target.img"
    blank(decoy); blank(target)
    verify_unchanged_zero(decoy, zero); verify_unchanged_zero(target, zero)
    with OwnedVM(files, folder / "vm", "uefi", [(decoy, False, False), (target, False, False), (medium, True, True)], timeout, evidence, capture_budget) as vm:
        vm.wait(r"SHZ-SETUP UI ready candidates=2 writes=0\n")
        vm.key("down"); selected, baseline = vm.screenshot("selected-nvme0n1")
        vm.key("ret"); vm.wait(r"SHZ-SETUP UI review target=nvme0n1 sectors=1048576\n")
        review, review_hash = vm.screenshot("review-nvme0n1")
        if review_hash == baseline: raise ValueError("review did not change actual guest display")
        if phase == "cancel":
            vm.key("esc"); returned, returned_hash = vm.screenshot("escape-back-selection")
            if returned_hash != baseline: raise ValueError("Esc did not restore the actual selected-disk screen")
            vm.key("esc"); vm.wait(r"SETUP-RESULT: CANCELLED \(no disk writes\)")
            vm.wait(r"K64 setup: SHZSETUP\.EXE exit=0 faulted=0 reaped=0")
            vm.wait(r"SHZ-DESKTOP READY")
            vm.key("f10"); vm.wait(r"SHZ-EXIT:0"); vm.wait_exit()
        else:
            for key in "erase": vm.key(key)
            vm.key("ret"); vm.wait(r"SHZ-SETUP UI confirmed target=nvme0n1\n")
            vm.wait(r"SETUP-RESULT: OK")
            result, result_hash = vm.screenshot("installed-result")
            if result_hash in (baseline, review_hash): raise ValueError("no actual result screen")
            vm.key("s"); vm.wait(r"SHZ-EXIT:0"); vm.wait_exit()
        text = vm.text(); installation_trace(text, phase)
        write_contract(vm.baseline, vm.final_blocks, phase)
        verify_unchanged_zero(decoy, zero)
        if decoy.stat().st_blocks: raise ValueError("write-free actual decoy gained allocated data blocks")
        if phase == "cancel":
            verify_unchanged_zero(target, zero)
            if target.stat().st_blocks: raise ValueError("write-free actual cancelled target gained allocated data blocks")
        vm.quit_observed_guest()
    verify_unchanged_zero(decoy, zero)
    if phase == "cancel": verify_unchanged_zero(target, zero)
    elif sha(target) == zero: raise ValueError("confirmed target still blank")
    return target


def desktop_phase(files, work, installed, firmware, timeout, evidence=None, capture_budget=None):
    space(work, TARGET_BYTES + LOG_LIMIT + 4 * MAX_FRAME_BYTES + METADATA_HEADROOM)
    folder = work / ("installed-" + firmware); folder.mkdir()
    disk = folder / "disk.img"; shutil.copyfile(installed, disk)
    if sha(disk) != sha(installed): raise ValueError("installed cold-boot clone drift")
    with OwnedVM(files, folder / "vm", firmware, [(disk, False, True)], timeout, evidence, capture_budget) as vm:
        vm.wait(r"SHZ-DESKTOP READY width=\d+ height=\d+")
        before, baseline = vm.screenshot("desktop-ready")
        start = len(vm.text()); vm.key("f3"); vm.wait(r"SHZ-DESKTOP EDITOR", after=start)
        editor, editor_hash = vm.screenshot("editor-from-real-ps2-key")
        if editor_hash == baseline: raise ValueError("real keyboard input did not change installed desktop")
        vm.key("f10"); vm.wait(r"SHZ-EXIT:0"); vm.wait_exit()
        desktop_trace(vm.text(), firmware)
        write_contract(vm.baseline, vm.final_blocks, "desktop")
        vm.quit_observed_guest()


def host_audit(repo, payload, target, out, capture_budget=None):
    space(out, 2 * TARGET_BYTES + METADATA_HEADROOM)
    report = out / "host-disk-audit.json"
    command = [sys.executable, "-B", str(repo / "shizukudos/install/tests/verify_disk.py"), str(target),
               "--payload", str(payload), "--json", str(report)]
    temporary = out / "host-audit-tmp"; temporary.mkdir()
    environment = dict(os.environ, TMPDIR=str(temporary))
    capture = None
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, env=environment, preexec_fn=child_file_limit)
    try:
        capture = PipeCapture(child, out / "host-disk-audit.log", out / "host-disk-audit.stderr", budget=capture_budget, reserve=out)
        deadline = time.monotonic() + 300
        while child.poll() is None:
            if time.monotonic() >= deadline: raise TimeoutError("bounded independent disk audit deadline")
            if capture.error: raise ValueError(capture.error)
            space(out)
            total = 0
            for p in temporary.rglob("*"):
                try:
                    if p.is_symlink(): raise ValueError("independent audit temporary tree contains a symlink")
                    if p.is_file(): total += p.stat().st_size
                except FileNotFoundError: pass  # verifier removes its own finished extraction
            if total > 2 * TARGET_BYTES: raise ValueError("independent audit exceeds 512 MiB extraction plus 512 MiB dump budget")
            time.sleep(.05)
        rc = child.returncode
    except BaseException:
        if child.poll() is None:
            # This isolated process group contains only the verifier and the
            # filesystem tools it starts, never an existing VM or service.
            os.killpg(child.pid, signal.SIGTERM)
            try: child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL); child.wait(timeout=5)
        raise
    finally:
        if capture is not None: capture.finish()
        else:
            child.stdout.close(); child.stderr.close()
    if capture is not None and capture.error: raise ValueError(capture.error)
    rows = json_file(report) if report.exists() else []
    if rc or not rows or any(row.get("status") != "PASS" for row in rows):
        raise ValueError("independent verify_disk rejected the installed target")
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--capture-inputs", type=Path)
    for name in ("repo", "build", "payload", "qemu", "qemu-data", "ovmf-code", "ovmf-vars", "seabios", "inputs", "out"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--inputs-sha256")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--timeout", type=int, default=900, help="bounded seconds per owned VM")
    args = parser.parse_args()
    if args.capture_inputs:
        if args.run: parser.error("capture never launches a VM")
        if any(getattr(args, n) is None for n in ("repo", "build", "payload", "qemu", "qemu_data", "ovmf_code", "ovmf_vars", "seabios")):
            parser.error("capture needs explicit repo/build/payload/QEMU/firmware paths")
        capture(args); return 0
    if not args.inputs or not args.inputs_sha256: parser.error("explicit completed input manifest and SHA required")
    data = path(args.inputs)
    if sha(data) != args.inputs_sha256: raise ValueError("input manifest SHA differs")
    config = json_file(data); repo, payload, files = validate_inputs(config)
    if not args.run:
        print(json.dumps({"status": "PASS_CURRENT_PRODUCTION_INPUTS_VALIDATED_NOT_RUN", "VM_executed": False})); return 0
    if not args.out or not 30 <= args.timeout <= 3600: parser.error("--run needs a fresh --out and timeout30..3600")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"): raise ValueError("Linux/Python owned-process pidfd support required")
    for tool in ("mkfs.vfat", "mmd", "mcopy", "fsck.fat", "e2fsck", "debugfs"):
        if not shutil.which(tool): raise ValueError("required host verification tool missing: " + tool)
    readback_bytes = sum(files[key].stat().st_size for key in ("loader", "kernel64s", "install")) + len(b"mode=install\r\nmenu_timeout=0\r\n")
    budget_proof = production_budget(readback_bytes)
    out = new_output(args.out, repo); space(out, budget_proof["max_peak_bytes"]); out.mkdir(mode=0o700)
    capture_budget = {"used": 0, "limit": LOG_LIMIT, "lock": threading.Lock()}
    global QMP
    QMP = load_module(repo / "shizukudos/tools/qemu.py", "pinned_qemu_helper").QMP
    result = {"status": "FAIL_PARTIAL_VM_EVIDENCE_PRESERVED", "VM_executed": False, "actual_VM_count": 0,
              "phases": [], "input_manifest_sha256": args.inputs_sha256, "harness_sha256": sha(Path(__file__)),
              "harness_dependencies_sha256": config["harness_dependencies_sha256"],
              "resource_budget": budget_proof, "combined_actual_child_log_limit_bytes": LOG_LIMIT,
              "shutdown_profile": "unchanged guest SHZ-EXIT:0 after flush, paused final QMP I/O counters, owned QMP quit; no ISA-debug-exit status claim",
              "device_profile": "d0 AHCI decoy; d1 NVMe target (nvme0n1); d2 readonly virtio firmware boot medium; cold installed target stays NVMe",
              "Windows98_boot_verified": False, "MS_DOS_replaced": False, "native_modern_apps_verified": False}
    try:
        medium = boot_medium(out, files); medium_sha = sha(medium)
        zero = zero_sha(TARGET_BYTES)
        for phase in ("cancel", "install"):
            validate_inputs(config)
            target = install_phase(files, out, medium, phase, args.timeout, zero, result, capture_budget)
            result["phases"].append({"phase": phase, "status": "PASS", "target_sha256": sha(target), "decoy_sha256": zero,
                                    "actual_final_QMP_write_contract_verified": True})
        audit = host_audit(repo, payload, target, out, capture_budget)
        result["phases"].append({"phase": "host-independent-disk-verification", "status": "PASS", "checks": len(audit)})
        target_hash = sha(target)
        for firmware in ("uefi", "bios"):
            validate_inputs(config)
            desktop_phase(files, out, target, firmware, args.timeout, result, capture_budget)
            if sha(target) != target_hash: raise ValueError("original installed target changed during cold clone test")
            result["phases"].append({"phase": "installed-cold-" + firmware, "status": "PASS"})
        validate_inputs(config)
        if sha(medium) != medium_sha: raise ValueError("read-only installer medium changed")
        if result["actual_VM_count"] != 4: raise ValueError("four actual owned cold VM launches required")
        result.update(status="PASS_ACTUAL_PRODUCTION_INSTALLER_VM_COMPONENT_GATE", input_originals_before_after_match=True,
                      installed_target_sha256=target_hash, zero_disk_sha256=zero,
                      scope="Shizuku production component installer; genuine Windows98 DOS replacement/apps remain incomplete")
    except BaseException as error:
        result["error"] = str(error); raise
    finally:
        result["combined_actual_child_log_bytes_retained"] = capture_budget["used"]
        (out / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "result": str(out / "result.json")})); return 0


if __name__ == "__main__":
    raise SystemExit(main())
