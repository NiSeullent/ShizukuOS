#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""Verify two real UEFI cold boots of the persistent Shizuku desktop.

OVMF boots private LOADER/Kernel64/WIN64 copies with cmdline=shz.desktop,
or --boot-iso boots an unchanged shipped ISO using its own boot settings.
A writable FAT32 disk on AHCI port 0 becomes D: (ESP on port 1). Real PS/2
keys open Explorer, save/reopen host-selected editor text, launch T_HELLO,
then F10 exits intentionally. The host reads actual disk bytes with mcopy.
The second cold boot opens the same data disk, proving persisted content.
Actual QMP screenshots are kept as PNGs. No all-T suite, network, existing
VM, physical disk, host installation or global settings changes.

PASS covers these behaviors under QEMU, not Windows 98 Explorer or all
hardware/app compatibility. Missing inputs: BLOCKED/exit2. Stale artifacts,
missing evidence, faults and timeouts: FAIL/exit1. Outputs and disposable
writable disks live in unique directories under build/desktop-harness.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "tools"))
import fatimg  # noqa: E402
import qemu  # noqa: E402
import run_k64_gui as gui  # noqa: E402
import shzlib  # noqa: E402

REPO = HERE.parents[1]
BUILD = REPO / "build" / "shizukudos"
ARTIFACTS = {"BOOTX64.EFI": BUILD / "supervisor/BOOTX64.EFI",
             "KERNEL64S.BIN": BUILD / "kernel64s/KERNEL64S.BIN",
             "WIN64.IMG": BUILD / "win64/WIN64.IMG"}
RECEIPTS = {"loader": BUILD / "supervisor/build-result.json",
            "kernel": BUILD / "kernels-build-result.json",
            "runtime": BUILD / "win64/build-result.json"}
SHELL_PATH = r"\SHZ\SYS64\SHZDESK.EXE"
TEXT = "uefi desktop persistence\n"
EXPECTED = TEXT.encode("ascii")
SEED = b"Shizuku desktop writable volume\r\n"
FAILURES = re.compile(r"SHZ-DESKTOP (?:ERROR|FAIL)\b|K64 desktop: result (?:start|wait|network-init)-failed|"
                      r"K64(?: EXCEPTION|: process .* killed)|(?:^|\n).*PANIC\b")
PRODUCTION = "K64 desktop: production profile (self-tests not run)"
READY = re.compile(r"SHZ-DESKTOP READY width=(\d+) height=(\d+)")
OPENED = re.compile(r"SHZ-DESKTOP OPENED path=D:\\DESKTOP\.TXT bytes=(\d+)")
CONTENT = re.compile(r"SHZ-DESKTOP CONTENT ([^\r\n]*)")


class EvidenceError(RuntimeError):
    pass


def sha(path):
    return shzlib.sha256_file(path)


def check(items, name, ok, detail=""):
    items.append({"check": name, "status": "PASS" if ok else "FAIL", "detail": str(detail)})
    if not ok:
        raise EvidenceError(f"{name}: {detail}")


def content_line(data):
    return data.decode("ascii").replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")


def prerequisites(args):
    paths = [*ARTIFACTS.values(), *RECEIPTS.values(), Path(args.firmware_code), Path(args.firmware_vars)]
    if args.boot_iso:
        paths.append(args.boot_iso)
        if args.iso_receipt:
            paths.append(args.iso_receipt)
    missing = [str(p) for p in paths if not p.is_file()]
    missing += [f"tool {n}" for n in ("mformat", "mmd", "mcopy", "mkfs.vfat", "fsck.vfat") if not shutil.which(n)]
    if args.boot_iso and not shutil.which("xorriso"):
        missing.append("tool xorriso (inspect shipped ISO without modifying it)")
    if not (shutil.which(args.qemu) or (Path(args.qemu).is_file() and os.access(args.qemu, os.X_OK))):
        missing.append(f"QEMU {args.qemu}")
    try:
        from PIL import Image  # noqa: F401
    except ImportError:
        missing.append("Pillow (required for real guest PNG screenshots)")
    if args.accel == "kvm" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        missing.append("read/write access to /dev/kvm")
    return missing


def verify_inputs(items):
    receipts = {n: json.loads(p.read_text()) for n, p in RECEIPTS.items()}
    hashes = {n: sha(p) for n, p in ARTIFACTS.items()}
    expected = {"BOOTX64.EFI": receipts["loader"]["artifacts"]["BOOTX64.EFI"]["sha256"],
                "KERNEL64S.BIN": receipts["kernel"]["kernels"]["kernel64-standalone"]["sha256"],
                "WIN64.IMG": receipts["runtime"]["archive"]["sha256"]}
    for name in hashes:
        check(items, f"{name} matches its build receipt", hashes[name] == expected[name])
    for kind in ("loader", "kernel", "runtime"):
        sources = receipts[kind].get("sources_sha256", {})
        check(items, f"{kind} build records source hashes", bool(sources))
        stale = [n for n, digest in sources.items() if not (REPO / n).is_file() or sha(REPO / n) != digest]
        check(items, f"{kind} build matches current source", not stale, ", ".join(stale[:8]))
    files = receipts["runtime"]["archive"]["files"]
    check(items, "WIN64.IMG contains the production desktop", SHELL_PATH in [f.upper() for f in files])
    return {"artifacts": hashes, "receipts": {n: sha(p) for n, p in RECEIPTS.items()}, "runtime_archive_files": files}


def iso_uefi_lba(path):
    """Read the actual EFI El Torito entry without loading a whole ISO into RAM."""
    with path.open("rb") as stream:
        catalog_lba = None
        for sector in range(16, 128):
            stream.seek(sector * 2048)
            descriptor = stream.read(2048)
            if len(descriptor) != 2048 or descriptor[1:6] != b"CD001":
                raise EvidenceError("ISO volume descriptor is truncated or invalid")
            if descriptor[0] == 0 and descriptor[7:39].startswith(b"EL TORITO SPECIFICATION"):
                catalog_lba = struct.unpack_from("<I", descriptor, 0x47)[0]
                break
            if descriptor[0] == 255:
                break
        if catalog_lba is None:
            raise EvidenceError("ISO has no El Torito boot catalog")
        stream.seek(catalog_lba * 2048)
        catalog = stream.read(2048)
    if len(catalog) != 2048 or catalog[0] != 1 or catalog[30:32] != b"\x55\xaa":
        raise EvidenceError("ISO boot catalog validation entry is invalid")
    if sum(struct.unpack_from("<16H", catalog, 0)) & 0xFFFF:
        raise EvidenceError("ISO boot catalog checksum is invalid")
    entries = [(catalog[1], catalog[32:64])]
    pos = 64
    while pos + 32 <= len(catalog) and catalog[pos] in (0x90, 0x91):
        header = catalog[pos:pos + 32]
        count = struct.unpack_from("<H", header, 2)[0]
        if pos + 32 * (count + 1) > len(catalog):
            raise EvidenceError("ISO boot catalog section is truncated")
        entries += [(header[1], catalog[pos + 32 * (i + 1):pos + 32 * (i + 2)]) for i in range(count)]
        pos += 32 * (count + 1)
        if header[0] == 0x91:
            break
    efi = [raw for platform, raw in entries if platform == 0xEF]
    if len(efi) != 1 or efi[0][:2] != b"\x88\x00":
        raise EvidenceError("ISO needs exactly one bootable no-emulation UEFI entry")
    return struct.unpack_from("<I", efi[0], 8)[0]


def verify_shipped_config(boot_ini, kernel_ini, items):
    def values(data, key):
        return re.findall(r"^\s*" + re.escape(key) + r"\s*=\s*([^\r\n;#]*?)\s*(?:[;#].*)?$",
                          data.decode("ascii"), flags=re.MULTILINE | re.IGNORECASE)
    check(items, "shipped ISO selects Kernel64 without harness injection", values(boot_ini, "mode") == ["kernel64"])
    check(items, "shipped ISO selects the production desktop command", values(kernel_ini, "cmdline") == ["shz.desktop"])


def freeze_iso(args, work, inputs, items):
    proof = work / "iso-inputs"
    proof.mkdir()
    source_digest = sha(args.boot_iso)
    frozen = proof / "boot.iso"
    shutil.copyfile(args.boot_iso, frozen)
    frozen.chmod(0o444)
    check(items, "ISO frozen as an identical read-only private copy", sha(frozen) == source_digest)
    image = proof / "shipped-efiboot.img"
    subprocess.run(["xorriso", "-osirrox", "on", "-indev", str(frozen), "-extract",
                    "/ShizukuDOS10/efiboot.img", str(image)], check=True, capture_output=True, timeout=120)
    lba = iso_uefi_lba(frozen)
    with frozen.open("rb") as stream:
        stream.seek(lba * 2048)
        from_catalog = stream.read(image.stat().st_size)
    check(items, "extracted EFI payload is the actual firmware-selected El Torito image",
          hashlib.sha256(from_catalog).hexdigest() == sha(image))
    members = {"BOOTX64.EFI": "EFI/BOOT/BOOTX64.EFI", "KERNEL64S.BIN": "SHZDOS/KERNEL64S.BIN",
               "WIN64.IMG": "SHZDOS/WIN64.IMG", "BOOT.INI": "EFI/SHIZUKU/BOOT.INI",
               "KERNEL64.INI": "SHZDOS/KERNEL64.INI"}
    hashes = {}
    for name, member in members.items():
        destination = proof / name
        subprocess.run(["mcopy", "-n", "-i", str(image), "::/" + member, str(destination)],
                       env=fatimg._mtools_env(), check=True, capture_output=True, timeout=30)
        hashes[member] = sha(destination)
        if name in ARTIFACTS:
            check(items, f"shipped ISO {name} matches source-bound current build", sha(destination) == inputs["artifacts"][name])
    verify_shipped_config((proof / "BOOT.INI").read_bytes(), (proof / "KERNEL64.INI").read_bytes(), items)
    record = {"source": str(args.boot_iso), "frozen": str(frozen), "sha256": source_digest,
              "bytes": frozen.stat().st_size, "efi_lba": lba, "efi_members_sha256": hashes}
    receipt_path = args.iso_receipt or args.boot_iso.with_suffix(".json")
    if receipt_path.is_file():
        receipt = json.loads(receipt_path.read_text())
        check(items, "ISO matches its builder receipt", receipt["sha256"] == source_digest and receipt["bytes"] == record["bytes"])
        check(items, "ISO builder receipt describes production desktop media",
              receipt.get("boot_mode") == "kernel64" and receipt.get("boot_profile") == "desktop")
        for member, digest in hashes.items():
            check(items, f"ISO receipt binds shipped {member}", receipt["efi_members"][member]["sha256"] == digest)
        record["receipt"] = {"path": str(receipt_path), "sha256": sha(receipt_path), "recorded_iso": receipt["iso"]}
    else:
        record["receipt"] = None
    check(items, "source ISO unchanged while freezing and inspecting it", sha(args.boot_iso) == source_digest)
    return frozen, record


def build_disks(work, frozen_iso=None):
    """Only private copies receive timestamps or guest writes."""
    copies = work / "inputs"
    copies.mkdir()
    boot = frozen_iso
    if boot is None:
        for name, source in ARTIFACTS.items():
            shutil.copyfile(source, copies / name)
        (copies / "BOOT.INI").write_bytes(b"mode = kernel64\r\n")
        (copies / "KERNEL64.INI").write_bytes(b"cmdline = shz.desktop\r\n")
        mbr = bytearray(512)
        mbr[510:512] = b"\x55\xaa"
        (copies / "mbr.bin").write_bytes(mbr)
        total = sum((copies / name).stat().st_size for name in ARTIFACTS)
        size_mib = max(64, (total * 5 // 4 + (1 << 20) - 1) // (1 << 20) + 16)
        if size_mib > 480:
            raise EvidenceError(f"payload needs {size_mib} MiB; FAT16 fixture supports at most 480 MiB")
        boot = work / "boot-template.img"
        spec = fatimg.make_hdd(boot, copies / "mbr.bin", size_mib=size_mib, label="SHZDESK", serial=0x53445A31)
        fatimg.make_dirs(spec, ["EFI", "EFI/BOOT", "EFI/SHIZUKU", "SHZDOS"])
        fatimg.copy_in(spec, [(copies / "BOOTX64.EFI", "EFI/BOOT/BOOTX64.EFI"),
                              (copies / "BOOT.INI", "EFI/SHIZUKU/BOOT.INI"),
                              (copies / "KERNEL64.INI", "SHZDOS/KERNEL64.INI"),
                              (copies / "KERNEL64S.BIN", "SHZDOS/KERNEL64S.BIN"),
                              (copies / "WIN64.IMG", "SHZDOS/WIN64.IMG")])
    seed = copies / "README.TXT"
    seed.write_bytes(SEED)
    os.utime(seed, (fatimg.FIXED_EPOCH, fatimg.FIXED_EPOCH))
    base = work / "data-template.img"
    with base.open("wb") as stream:
        stream.truncate(64 << 20)
    subprocess.run(["mkfs.vfat", "-F", "32", "-s", "1", "-n", "SHZDATA", "--invariant", str(base)],
                   check=True, capture_output=True, timeout=30)
    subprocess.run(["mcopy", "-m", "-i", str(base), str(seed), "::README.TXT"],
                   env=fatimg._mtools_env(), check=True, capture_output=True, timeout=30)
    data = work / "data-working.img"
    shutil.copyfile(base, data)
    return boot, data


def command_for(args, run_dir, sock, boot, data, variables):
    iso = bool(getattr(args, "boot_iso", None))
    boot_drive = (f"file={boot},format=raw,if=none,id=boot,readonly=on,media=cdrom" if iso else
                  f"file={boot},format=raw,if=none,id=boot,cache=writethrough")
    return [str(x) for x in [args.qemu, "-name", "shz-persistent-desktop", "-machine", "q35", "-accel", args.accel,
        "-cpu", "max" if args.accel == "tcg" else "host", "-smp", "2", "-m", str(args.memory),
        "-global", "ICH9-LPC.disable_s3=1", "-display", "none", "-vga", "std", "-net", "none",
        "-no-reboot", "-monitor", "none",
        "-drive", f"if=pflash,format=raw,unit=0,readonly=on,file={args.firmware_code}",
        "-drive", f"if=pflash,format=raw,unit=1,file={variables}",
        "-drive", f"file={data},format=raw,if=none,id=data,cache=writethrough",
        "-device", "ide-hd,drive=data,bus=ide.0",
        "-drive", boot_drive,
        "-device", f"{'ide-cd' if iso else 'ide-hd'},drive=boot,bus=ide.1,bootindex=1",
        "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        "-serial", f"file:{run_dir / 'serial.log'}", "-qmp", f"unix:{sock},server=on,wait=off"]]


class Guest:
    def __init__(self, proc, qmp, run_dir, args, checks):
        self.proc, self.qmp, self.run_dir, self.args, self.checks = proc, qmp, run_dir, args, checks
        self.deadline = time.monotonic() + args.timeout
        self.shots = []

    def serial(self):
        path = self.run_dir / "serial.log"
        return path.read_text(errors="replace") if path.exists() else ""

    def healthy(self, allow_exit=False):
        text = self.serial()
        match = FAILURES.search(text)
        if match:
            raise EvidenceError(f"guest failure: {match.group(0)}")
        if not allow_exit and (self.proc.poll() is not None or "K64 desktop: result exited" in text or "SHZ-EXIT:" in text):
            raise EvidenceError("desktop ended before an explicit F10 request")
        if time.monotonic() > self.deadline:
            raise EvidenceError(f"guest exceeded {self.args.timeout}s total deadline")
        return text

    def wait(self, pattern, start=0, allow_exit=False):
        rx = re.compile(re.escape(pattern)) if isinstance(pattern, str) else pattern
        phase_deadline = min(self.deadline, time.monotonic() + self.args.step_timeout)
        while time.monotonic() < phase_deadline:
            text = self.healthy(allow_exit)
            hit = rx.search(text, start)
            if hit:
                return hit
            if self.proc.poll() is not None:
                break
            time.sleep(0.1)
        raise EvidenceError(f"missing marker {rx.pattern!r}; serial tail: {self.serial()[-500:]}")

    def keys(self, *qcodes):
        self.healthy()
        self.qmp.call("send-key", {"keys": [{"type": "qcode", "data": k} for k in qcodes], "hold-time": 80})
        time.sleep(0.2)

    def type_text(self, text):
        for char in text:
            self.keys("spc" if char == " " else "ret" if char == "\n" else char)

    def observe(self, seconds, label):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            self.healthy()
            time.sleep(0.1)
        state = self.qmp.call("query-status")
        check(self.checks, label, bool(state.get("running")), f"observed {seconds}s; QMP {state}")

    def screenshot(self, label):
        self.healthy()
        time.sleep(0.3)
        ppm = self.run_dir / f"{label}.ppm"
        self.qmp.call("stop")
        try:
            self.qmp.call("screendump", {"filename": str(ppm)})
        finally:
            self.qmp.call("cont")
        img = gui.Image(ppm)
        mode = READY.search(self.serial())
        check(self.checks, f"{label}: screenshot has reported desktop dimensions",
              bool(mode) and (img.w, img.h) == (int(mode.group(1)), int(mode.group(2))), f"{img.w}x{img.h}")
        check(self.checks, f"{label}: actual taskbar and desktop pixels match their UI contract",
              img.w >= 320 and img.h >= 200 and img.px(img.w - 8, img.h - 12) == (192, 192, 192)
              and img.px(img.w - 8, img.h - 60) == (0, 128, 128))
        gui.save_png(ppm)
        png = ppm.with_suffix(".png")
        check(self.checks, f"{label}: real guest PNG saved", png.is_file())
        self.shots.append({"label": label, "path": str(png), "sha256": sha(png)})

    def explorer(self, saved):
        start = len(self.serial())
        self.keys("f2")
        self.keys("d")
        self.wait(re.compile(r"SHZ-DESKTOP FILES path=D:\\ count=\d+"), start)
        filename, size = ("DESKTOP.TXT", len(EXPECTED)) if saved else ("README.TXT", len(SEED))
        self.wait(re.compile(r"SHZ-DESKTOP FILE name=" + re.escape(filename) + r" dir=0 bytes=" + str(size) + r"\b"), start)
        check(self.checks, "Explorer enumerated the independently prepared writable D: volume", True)
        self.screenshot("explorer-persisted" if saved else "explorer-initial")
        self.keys("esc")

    def reopen(self):
        start = len(self.serial())
        self.keys("ctrl", "o")
        hit = self.wait(OPENED, start)
        check(self.checks, "editor reopened the saved file with expected length", int(hit.group(1)) == len(EXPECTED), hit.group(0))
        line = self.wait(CONTENT, hit.end())
        check(self.checks, "editor read exact host-selected text back", line.group(1) == content_line(EXPECTED), line.group(0))

    def editor(self, create):
        start = len(self.serial())
        self.keys("f3")
        self.wait(r"SHZ-DESKTOP EDITOR path=D:\DESKTOP.TXT", start)
        if create:
            self.type_text(TEXT)
            start = len(self.serial())
            self.keys("ctrl", "s")
            self.wait(re.compile(r"SHZ-DESKTOP SAVED path=D:\\DESKTOP\.TXT bytes=" + str(len(EXPECTED)) + r" verified=1\b"), start)
            check(self.checks, "editor saved new nonempty text through real disk driver", True)
        self.reopen()
        self.screenshot("editor-saved" if create else "editor-cold-boot")
        self.keys("esc")

    def child(self):
        start = len(self.serial())
        self.keys("f4")
        hit = self.wait(re.compile(r"SHZ-DESKTOP LAUNCHED pid=(\d+) path=C:\\SHZ\\TESTS\\T_HELLO\.EXE"), start)
        pid = int(hit.group(1))
        self.wait(re.compile(r"SHZ-DESKTOP APP-EXIT pid=" + str(pid) + r" code=7\b"), hit.end())
        check(self.checks, "desktop launched/reaped real Win64 child with documented exit code", pid > 0, f"pid {pid}, exit 7")
        self.observe(self.args.observe_seconds, "desktop remains usable after its child exited")

    def exit(self):
        start = len(self.serial())
        self.keys("f10")
        self.wait("SHZ-DESKTOP EXIT requested=1", start, allow_exit=True)
        hit = self.wait(re.compile(r"K64 desktop: result exited exit=([0-9a-f]+) faulted=(\d+) reaped=(\d+)"), start, allow_exit=True)
        check(self.checks, "production shell exited cleanly only after F10",
              int(hit.group(1), 16) == 0 and hit.group(2) == "0", hit.group(0))
        self.wait("K64 desktop: volume flush rc 0", start, allow_exit=True)
        self.wait(re.compile(r"K64 vfs: shutdown D: .*: rc 0\b"), start, allow_exit=True)
        self.wait(re.compile(r"(?:^|\n)SHZ-EXIT:0\r?(?:\n|$)"), start, allow_exit=True)
        rc = self.proc.wait(timeout=max(1, min(30, self.deadline - time.monotonic())))
        check(self.checks, "Kernel64 flushed writable volume and intentionally stopped QEMU successfully", rc == 1, f"QEMU exit {rc}")


def run_boot(args, work, boot_template, data, number):
    run_dir = work / f"boot-{number}"
    run_dir.mkdir()
    variables = run_dir / "OVMF_VARS.fd"
    boot = boot_template if args.boot_iso else run_dir / "boot.img"
    if not args.boot_iso:
        shutil.copyfile(boot_template, boot)
    shutil.copyfile(args.firmware_vars, variables)
    checks = []
    record = {"boot": number, "checks": checks, "status": "FAIL", "data_disk": str(data),
              "boot_medium": "shipped-iso-cd" if args.boot_iso else "private-fixture-esp"}
    proc = q = guest = None
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="shzdesk-") as socket_dir:
            cmd = command_for(args, run_dir, Path(socket_dir) / "qmp.sock", boot, data, variables)
            record["command"] = cmd
            with (run_dir / "qemu.log").open("wb") as log:
                proc = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT)
                try:
                    q = qemu.QMP(Path(socket_dir) / "qmp.sock", timeout=min(30, args.step_timeout))
                    guest = Guest(proc, q, run_dir, args, checks)
                    guest.wait(PRODUCTION)
                    ready = guest.wait(READY)
                    text = guest.serial()
                    check(checks, "UEFI boot manager selected Kernel64 and exited firmware boot services",
                          "Kernel64 direct boot" in text and "ExitBootServices" in text and "CSM legacy boot:" not in text)
                    check(checks, "real UEFI GOP driver initialized before desktop",
                          "K64 gfx: UEFI GOP framebuffer" in text and "K64 gfx: display backend UEFI GOP" in text)
                    check(checks, "AHCI driver mounted writable FAT32 D: volume",
                          "K64 ahci:" in text and bool(re.search(r"K64 disk: D: = .*FAT32.*read/write", text)), text[-700:])
                    check(checks, "production boot did not execute all-T application suite", "K64 win64 app:" not in text)
                    check(checks, "desktop registered its actual GUI window as the system shell",
                          bool(re.search(r"SHZ-DESKTOP SHELL registered=1 hwnd=[0-9a-fA-F]+", text)))
                    check(checks, "production shell reached its own GUI readiness marker", True, ready.group(0))
                    guest.observe(args.observe_seconds, "desktop persists while idle instead of a timed test screen")
                    guest.screenshot("desktop-ready")
                    guest.explorer(number == 2)
                    guest.editor(number == 1)
                    guest.child()
                    guest.screenshot("desktop-after-app")
                    guest.exit()
                    check(checks, "production boot never ran the all-T suite", "K64 win64 app:" not in guest.serial())
                    record["status"] = "PASS"
                finally:
                    if q and proc and proc.poll() is None and record["status"] != "PASS":
                        try:
                            ppm = run_dir / "failure.ppm"
                            q.call("stop")
                            q.call("screendump", {"filename": str(ppm)})
                            gui.save_png(ppm)
                            record["failure_screenshot"] = str(ppm.with_suffix(".png"))
                        except (RuntimeError, OSError, ValueError) as exc:
                            record["failure_screenshot_error"] = str(exc)
                    if q:
                        q.close()
                    if proc and proc.poll() is None:
                        proc.kill()
                        proc.wait(timeout=10)
    except (EvidenceError, OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as exc:
        record["error"] = str(exc)
        checks.append({"check": "desktop acceptance sequence completed", "status": "FAIL", "detail": str(exc)})
    record.update({"seconds": round(time.monotonic() - started, 2), "qemu_exit_code": proc.returncode if proc else None,
                   "screenshots": guest.shots if guest else [], "serial_tail": guest.serial()[-6000:] if guest else ""})
    shzlib.write_json(run_dir / "result.json", record)
    return record


def verify_written_disk(data, work, label, items):
    destination = work / f"{label}-DESKTOP.TXT"
    got = subprocess.run(["mcopy", "-n", "-i", str(data), "::DESKTOP.TXT", str(destination)],
                         capture_output=True, env=fatimg._mtools_env(), timeout=30)
    check(items, f"{label}: host independently extracted guest-written file", got.returncode == 0,
          got.stderr.decode(errors="replace")[-400:])
    payload = destination.read_bytes()
    check(items, f"{label}: disk bytes equal exact host-selected text", payload == EXPECTED,
          f"{len(payload)} bytes; sha256={sha(destination)}")
    clean = subprocess.run(["fsck.vfat", "-n", str(data)], capture_output=True, text=True, timeout=30)
    (work / f"{label}-fsck.txt").write_text(clean.stdout + clean.stderr)
    check(items, f"{label}: FAT32 volume consistent after guest writes", clean.returncode == 0,
          (clean.stdout + clean.stderr)[-600:])
    seed = subprocess.run(["mcopy", "-n", "-i", str(data), "::README.TXT", "-"], capture_output=True,
                          env=fatimg._mtools_env(), timeout=30)
    check(items, f"{label}: prepared seed file unchanged", seed.returncode == 0 and seed.stdout == SEED)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--qemu", default=qemu.DEFAULT_QEMU)
    ap.add_argument("--firmware-code", default=qemu.DEFAULT_OVMF_CODE)
    ap.add_argument("--firmware-vars", default=qemu.DEFAULT_OVMF_VARS)
    ap.add_argument("--accel", choices=("tcg", "kvm"), default="tcg")
    ap.add_argument("--memory", type=int, default=512)
    ap.add_argument("--timeout", type=int, default=600, help="seconds per cold boot")
    ap.add_argument("--step-timeout", type=int, default=90)
    ap.add_argument("--observe-seconds", type=float, default=10, help="idle observation per desktop/child")
    ap.add_argument("--boot-iso", type=Path, help="boot a frozen copy of the actual shipped ISO; never replace its boot configuration")
    ap.add_argument("--iso-receipt", type=Path, help="builder receipt for --boot-iso (default: its .json sibling if present)")
    ap.add_argument("--out", type=Path, default=REPO / "build/desktop-harness")
    args = ap.parse_args(argv)
    if args.timeout < 1 or args.step_timeout < 1 or args.observe_seconds < 1 or args.memory < 128:
        ap.error("timeouts/observation must be positive; at least 128 MiB RAM required")
    if args.iso_receipt and not args.boot_iso:
        ap.error("--iso-receipt requires --boot-iso")
    if args.boot_iso:
        args.boot_iso = args.boot_iso.resolve()
    if args.iso_receipt:
        args.iso_receipt = args.iso_receipt.resolve()
    args.out = args.out.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix=time.strftime("%Y%m%dT%H%M%S-"), dir=args.out))
    result = {"test": str(Path(__file__).relative_to(REPO)), "utc": shzlib.utc_now(), "git": shzlib.git_state(),
              "status": "FAIL", "scope": "two QEMU UEFI boots; persistent own desktop/input/disk I/O/Win64 child",
              "accel": args.accel, "work": str(work), "checks": [], "boots": [],
              "expected_file": {"path": r"D:\DESKTOP.TXT", "bytes": len(EXPECTED),
                                "sha256": hashlib.sha256(EXPECTED).hexdigest()}}
    try:
        missing = prerequisites(args)
        if missing:
            result.update(status="BLOCKED", missing=missing)
        else:
            result["inputs"] = verify_inputs(result["checks"])
            frozen_iso = None
            if args.boot_iso:
                frozen_iso, result["iso"] = freeze_iso(args, work, result["inputs"], result["checks"])
            boot, data = build_disks(work, frozen_iso)
            result["data_disk"] = str(data)
            result["boot_disk_sha256"] = sha(boot)
            for number in (1, 2):
                record = run_boot(args, work, boot, data, number)
                result["boots"].append(record)
                if record["status"] != "PASS":
                    raise EvidenceError(f"cold boot {number} failed: {record.get('error', 'see checks')}")
                verify_written_disk(data, work, f"boot-{number}", result["checks"])
            check(result["checks"], "boot template remained unchanged", sha(boot) == result["boot_disk_sha256"])
            if args.boot_iso:
                check(result["checks"], "source shipped ISO unchanged after both cold boots", sha(args.boot_iso) == result["iso"]["sha256"])
                receipt = result["iso"]["receipt"]
                if receipt:
                    check(result["checks"], "ISO builder receipt unchanged after both cold boots", sha(Path(receipt["path"])) == receipt["sha256"])
            for name, path in ARTIFACTS.items():
                check(result["checks"], f"original {name} unchanged", sha(path) == result["inputs"]["artifacts"][name])
            for name, path in RECEIPTS.items():
                check(result["checks"], f"{name} receipt unchanged", sha(path) == result["inputs"]["receipts"][name])
            check(result["checks"], "all inputs still match their current sources at completion",
                  verify_inputs([]) == result["inputs"])
            result["status"] = "PASS"
    except (EvidenceError, OSError, RuntimeError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        result["error"] = str(exc)
        result["checks"].append({"check": "desktop verification finished", "status": "FAIL", "detail": str(exc)})
    shzlib.write_json(work / "result.json", result)
    shzlib.write_json(args.out / "result.json", result)
    print(f"desktop {result['status']}: {work / 'result.json'}", flush=True)
    for item in result["checks"]:
        if item["status"] != "PASS":
            print(f"  {item['status']} {item['check']}: {item['detail']}", flush=True)
    for item in result.get("missing", []):
        print(f"  BLOCKED: {item}", flush=True)
    return 0 if result["status"] == "PASS" else 2 if result["status"] == "BLOCKED" else 1


if __name__ == "__main__":
    sys.exit(main())
